// go: file archive/tar/common.go decls: sparseEntry.endOffset, validateSparseEntries, invertSparseEntries, alignSparseEntries, isHeaderOnlyType, headerError.Error, Header.allowedFormats, basicKeys, FileInfoHeader, headerFileInfo.Name, headerFileInfo.Size, headerFileInfo.ModTime, headerFileInfo.IsDir, headerFileInfo.Sys, headerFileInfo.Mode, headerFileInfo.String, Header.FileInfo
//
// common.go — Header, the type flags, the PAX keywords, the
// sentinel errors, sparse-entry validation and FileInfoHeader.
//
// goishlint:ignore GOISH021 tarinsecurepath, sysStat, fileState, basicKeys - `tarinsecurepath` is a `godebug` knob and goish has no godebug; `sysStat` is set by stat_unix.go, which is not among the files this port covers; `fileState` is the interface the regular and sparse readers/writers share, and this port stubs the sparse half; `basicKeys` is spelled as the predicate `basicKey`.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::convert::{int as toint, int64 as toint64, uint32 as touint32};
use crate::errors::{error, nil};
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io::fs;
use crate::strconv;
use crate::strings;
use crate::time::Time;
use crate::types::{byte, int};

use super::*;

// ─── Type flags ─────────────────────────────────────────────────────

/// Type '0' indicates a regular file.
pub const TypeReg: byte = b'0';

/// Deprecated: Use TypeReg instead.
pub const TypeRegA: byte = 0;

/// Hard link.
pub const TypeLink: byte = b'1';
/// Symbolic link.
pub const TypeSymlink: byte = b'2';
/// Character device node.
pub const TypeChar: byte = b'3';
/// Block device node.
pub const TypeBlock: byte = b'4';
/// Directory.
pub const TypeDir: byte = b'5';
/// FIFO node.
pub const TypeFifo: byte = b'6';

/// Type '7' is reserved.
pub const TypeCont: byte = b'7';

/// PAX extended header (local).
pub const TypeXHeader: byte = b'x';
/// PAX global extended header.
pub const TypeXGlobalHeader: byte = b'g';

/// GNU sparse file.
pub const TypeGNUSparse: byte = b'S';
/// GNU long name.
pub const TypeGNULongName: byte = b'L';
/// GNU long link.
pub const TypeGNULongLink: byte = b'K';

// ─── PAX keywords ────────────────────────────────────────────────────

/// Indicates that no PAX key is suitable.
pub(crate) const paxNone: &str = "";

pub(crate) const paxPath: &str = "path";
pub(crate) const paxLinkpath: &str = "linkpath";
pub(crate) const paxSize: &str = "size";
pub(crate) const paxUid: &str = "uid";
pub(crate) const paxGid: &str = "gid";
pub(crate) const paxUname: &str = "uname";
pub(crate) const paxGname: &str = "gname";
pub(crate) const paxMtime: &str = "mtime";
pub(crate) const paxAtime: &str = "atime";
pub(crate) const paxCtime: &str = "ctime";

/// Currently unused.
pub(crate) const paxCharset: &str = "charset";
/// Currently unused.
const paxComment: &str = "comment";

pub(crate) const paxSchilyXattr: &str = "SCHILY.xattr.";

/// The prefix every `GNU.sparse.*` key shares.
const paxGNUSparse: &str = "GNU.sparse.";

pub(crate) const paxGNUSparseMajor: &str = "GNU.sparse.major";
pub(crate) const paxGNUSparseMinor: &str = "GNU.sparse.minor";
pub(crate) const paxGNUSparseName: &str = "GNU.sparse.name";
pub(crate) const paxGNUSparseSize: &str = "GNU.sparse.size";
pub(crate) const paxGNUSparseRealSize: &str = "GNU.sparse.realsize";
pub(crate) const paxGNUSparseNumBlocks: &str = "GNU.sparse.numblocks";
pub(crate) const paxGNUSparseOffset: &str = "GNU.sparse.offset";
pub(crate) const paxGNUSparseNumBytes: &str = "GNU.sparse.numbytes";
pub(crate) const paxGNUSparseMap: &str = "GNU.sparse.map";

// ─── Errors ──────────────────────────────────────────────────────────

crate::var! {
    /// Invalid tar header.
    pub ErrHeader: error       = "archive/tar: invalid tar header";

    /// Header field too long.
    pub ErrFieldTooLong: error = "archive/tar: header field too long";

    /// A sparse file's map claims more data than the archive holds.
    /// Unexported in Go: it surfaces from `Read`, never from `Next`,
    /// because only reading discovers the mismatch.
    pub(crate) errMissData: error =
        "archive/tar: sparse file references non-existent data";

    /// A sparse file's archive holds data its map never refers to.
    pub(crate) errUnrefData: error =
        "archive/tar: sparse file contains unreferenced data";

    /// A PAX 1.0 sparse map ran past `maxSpecialFileSize`. The map is
    /// stored in the file's own data, so an archive can otherwise ask
    /// the reader to buffer without bound.
    pub(crate) errSparseTooLong: error = "archive/tar: sparse map too long";
}



// ─── Header ──────────────────────────────────────────────────────────

/// A Header represents a single header in a tar archive.
#[derive(Clone)]
pub struct Header {
    pub Typeflag: byte,
    pub Name: string,
    pub Linkname: string,
    pub Size: i64,
    pub Mode: i64,
    pub Uid: int,
    pub Gid: int,
    pub Uname: string,
    pub Gname: string,
    pub ModTime: Time,
    pub AccessTime: Time,
    pub ChangeTime: Time,
    pub Devmajor: i64,
    pub Devminor: i64,
    pub Xattrs: map<string, string>,
    pub PAXRecords: map<string, string>,
    pub Format: Format,
}

impl Header {
    // go: none — goish idiom: Go's zero value is usable, so a caller
    //     writes `var h Header` / `tar.Header{}`. Rust needs the
    //     constructor spelled.
    pub fn new() -> Self {
        return Self {
            Typeflag: 0,
            Name: string::new(),
            Linkname: string::new(),
            Size: 0,
            Mode: 0,
            Uid: 0,
            Gid: 0,
            Uname: string::new(),
            Gname: string::new(),
            // Go's `Header{}` leaves these as `time.Time{}`, the ZERO
            // Time — year 1, not the epoch. `Header.allowedFormats`
            // asks `!ModTime.IsZero()` to decide whether a PAX record
            // is needed, so the two are not interchangeable.
            ModTime: crate::time::Time::default(),
            AccessTime: crate::time::Time::default(),
            ChangeTime: crate::time::Time::default(),
            Devmajor: 0,
            Devminor: 0,
            Xattrs: map::new(),
            PAXRecords: map::new(),
            Format: FormatUnknown,
        };
    }
}

// ─── Sparse types ───────────────────────────────────────────────────

/// Sparse entry: a Length-sized fragment at Offset.
#[derive(Clone)]
pub struct sparseEntry {
    pub Offset: i64,
    pub Length: i64,
}

impl sparseEntry {
    // go: sdk 1.25.5 archive/tar/common.go:216-216 sparseEntry.endOffset
    pub fn endOffset(&self) -> i64 {
        return self.Offset + self.Length;
    }
}

/// Sparse data fragments.
pub type sparseDatas = slice<sparseEntry>;

/// Sparse hole fragments.
pub type sparseHoles = slice<sparseEntry>;

// go: sdk 1.25.5 archive/tar/common.go:257-278 validateSparseEntries
pub(crate) fn validateSparseEntries(sp: &sparseDatas, size: i64) -> bool {
    if size < 0 {
        return false;
    }
    let mut pre = sparseEntry {
        Offset: 0,
        Length: 0,
    };
    for (_, cur) in crate::range!(sp) {
        if cur.Offset < 0 || cur.Length < 0 {
            return false;
        }
        if cur.Offset > i64::MAX - cur.Length {
            return false;
        }
        if cur.endOffset() > size {
            return false;
        }
        if pre.endOffset() > cur.Offset {
            return false;
        }
        pre.Offset = cur.Offset;
        pre.Length = cur.Length;
    }
    return true;
}

// go: sdk 1.25.5 archive/tar/common.go:310-325 invertSparseEntries
pub(crate) fn invertSparseEntries(src: &sparseDatas, size: i64) -> sparseHoles {
    let mut dst = sparseHoles::new();
    let mut pre = sparseEntry {
        Offset: 0,
        Length: 0,
    };
    for (_, cur) in crate::range!(src) {
        if cur.Length == 0 {
            continue;
        }
        pre.Length = cur.Offset - pre.Offset;
        if pre.Length > 0 {
            dst = crate::append!(dst, pre.clone());
        }
        pre.Offset = cur.endOffset();
    }
    pre.Length = size - pre.Offset;
    return crate::append!(dst, pre);
}

// go: sdk 1.25.5 archive/tar/common.go:287-300 alignSparseEntries
fn alignSparseEntries(src: &sparseDatas, size: i64) -> sparseDatas {
    let mut dst = sparseDatas::new();
    for (_, s) in crate::range!(src) {
        let mut pos = s.Offset;
        let mut end = s.endOffset();
        pos += blockPadding(pos);
        if end != size {
            end -= blockPadding(-end);
        }
        if pos < end {
            dst = crate::append!(
                dst,
                sparseEntry {
                    Offset: pos,
                    Length: end - pos
                }
            );
        }
    }
    return dst;
}

// ─── Internal file handling ────────────────────────────────────────

// go: sdk 1.25.5 archive/tar/common.go:742-749 isHeaderOnlyType
pub(crate) fn isHeaderOnlyType(flag: byte) -> bool {
    return match flag {
        TypeLink | TypeSymlink | TypeChar | TypeBlock | TypeDir | TypeFifo => true,
        _ => false,
    };
}

// ─── Write-side errors (common.go) ───────────────────────────────────

crate::var! {
    /// Write too long — more bytes than Header.Size were written.
    pub ErrWriteTooLong: error    = "archive/tar: write too long";
    /// Write after Close.
    pub ErrWriteAfterClose: error = "archive/tar: write after close";
    /// Insecure file path.
    pub ErrInsecurePath: error    = "archive/tar: insecure file path";
}

// ─── headerError (common.go:45) ──────────────────────────────────────

/// `headerError` — cannot-encode-header error carrying one or more
/// explanatory clauses.
#[derive(Clone)]
struct headerError {
    msgs: slice<string>,
}

impl crate::errors::ErrorTrait for headerError {
    // go: sdk 1.25.5 archive/tar/common.go:47-59 headerError.Error
    fn Error(&self) -> string {
        let prefix = crate::string("archive/tar: cannot encode header");
        let mut ss: Vec<string> = Vec::new();
        for (_, s) in crate::range!(&self.msgs) {
            if s.Len() > 0 {
                ss.push(s.clone());
            }
        }
        if ss.is_empty() {
            return prefix;
        }
        let joined = strings::Join(slice::__from_vec(ss), "; and ");
        return prefix + ": " + joined;
    }
}

// go: none — goish idiom: Go builds the value inline as
//     `&headerError{msgs...}` at every return site. goish's `error` is
//     a handle, so the wrap is a call; named once here.
fn headerErr(msgs: Vec<string>) -> error {
    return crate::errors::Wrap(headerError {
        msgs: slice::__from_vec(msgs),
    });
}

// ─── allowedFormats (common.go:344) ──────────────────────────────────

impl Header {
    // go: sdk 1.25.5 archive/tar/common.go:344-537 Header.allowedFormats
    /// `h.allowedFormats()` — determine which formats can encode this
    /// Header. Returns `(format, paxHdrs, err)`. `format == FormatUnknown`
    /// means the Header cannot be encoded; `err` explains why.
    pub(crate) fn allowedFormats(&self) -> (Format, map<string, string>, error) {
        let mut format = FormatUSTAR | FormatPAX | FormatGNU;
        let mut paxHdrs = map::<string, string>::new();

        let mut whyNoUSTAR = string::new();
        let mut whyNoPAX = string::new();
        let mut whyNoGNU = string::new();
        let mut whyOnlyPAX = string::new();
        let whyOnlyGNU = string::new();
        let mut preferPAX = false;

        // verifyString — mirror of common.go's closure.
        let verify_string = |s: &string,
                             size: int,
                             _name: &'static str,
                             paxKey: &'static str,
                             format: &mut Format,
                             whyNoGNU: &mut string,
                             whyNoUSTAR: &mut string,
                             whyNoPAX: &mut string,
                             paxHdrs: &mut map<string, string>| {
            let too_long = toint(s.Len()) > size;
            let allow_long_gnu = paxKey == paxPath || paxKey == paxLinkpath;
            if hasNUL(s) || (too_long && !allow_long_gnu) {
                *whyNoGNU = crate::string("GNU cannot encode field");
                format.mustNotBe(FormatGNU);
            }
            if !isASCII(s) || too_long {
                let can_split_ustar = paxKey == paxPath;
                let (_, _, ok) = splitUSTARPath(s);
                if !can_split_ustar || !ok {
                    *whyNoUSTAR = crate::string("USTAR cannot encode field");
                    format.mustNotBe(FormatUSTAR);
                }
                if paxKey.is_empty() {
                    *whyNoPAX = crate::string("PAX cannot encode field");
                    format.mustNotBe(FormatPAX);
                } else {
                    paxHdrs.Set(crate::string(paxKey), s.clone());
                }
            }
            let (v, ok) = self.PAXRecords.Get(crate::string(paxKey));
            if ok && v == *s {
                paxHdrs.Set(crate::string(paxKey), v);
            }
        };

        let verify_numeric = |n: i64,
                              size: int,
                              _name: &'static str,
                              paxKey: &'static str,
                              format: &mut Format,
                              whyNoGNU: &mut string,
                              whyNoUSTAR: &mut string,
                              whyNoPAX: &mut string,
                              paxHdrs: &mut map<string, string>| {
            if !fitsInBase256(size, n) {
                *whyNoGNU = crate::string("GNU cannot encode numeric");
                format.mustNotBe(FormatGNU);
            }
            if !fitsInOctal(size, n) {
                *whyNoUSTAR = crate::string("USTAR cannot encode numeric");
                format.mustNotBe(FormatUSTAR);
                if paxKey.is_empty() {
                    *whyNoPAX = crate::string("PAX cannot encode numeric");
                    format.mustNotBe(FormatPAX);
                } else {
                    paxHdrs.Set(crate::string(paxKey), strconv::FormatInt(n, 10));
                }
            }
            let (v, ok) = self.PAXRecords.Get(crate::string(paxKey));
            if ok && v == strconv::FormatInt(n, 10) {
                paxHdrs.Set(crate::string(paxKey), v);
            }
        };

        let verify_time = |ts: Time,
                           size: int,
                           _name: &'static str,
                           paxKey: &'static str,
                           format: &mut Format,
                           whyNoGNU: &mut string,
                           whyNoUSTAR: &mut string,
                           whyNoPAX: &mut string,
                           preferPAX: &mut bool,
                           paxHdrs: &mut map<string, string>| {
            if ts.IsZero() {
                return;
            }
            if !fitsInBase256(size, ts.Unix()) {
                *whyNoGNU = crate::string("GNU cannot encode time");
                format.mustNotBe(FormatGNU);
            }
            let is_mtime = paxKey == paxMtime;
            let fits_octal = fitsInOctal(size, ts.Unix());
            if (is_mtime && !fits_octal) || !is_mtime {
                *whyNoUSTAR = crate::string("USTAR cannot encode time");
                format.mustNotBe(FormatUSTAR);
            }
            let needs_nano = ts.Nanosecond() != 0;
            if !is_mtime || !fits_octal || needs_nano {
                *preferPAX = true;
                if paxKey.is_empty() {
                    *whyNoPAX = crate::string("PAX cannot encode time");
                    format.mustNotBe(FormatPAX);
                } else {
                    paxHdrs.Set(crate::string(paxKey), formatPAXTime(ts));
                }
            }
            let (v, ok) = self.PAXRecords.Get(crate::string(paxKey));
            if ok && v == formatPAXTime(ts) {
                paxHdrs.Set(crate::string(paxKey), v);
            }
        };

        // Check basic fields. Field sizes are fixed per the V7/USTAR/GNU
        // layout (common.go reads them off a zero block).
        verify_string(
            &self.Name,
            100,
            "Name",
            paxPath,
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut paxHdrs,
        );
        verify_string(
            &self.Linkname,
            100,
            "Linkname",
            paxLinkpath,
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut paxHdrs,
        );
        verify_string(
            &self.Uname,
            32,
            "Uname",
            paxUname,
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut paxHdrs,
        );
        verify_string(
            &self.Gname,
            32,
            "Gname",
            paxGname,
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut paxHdrs,
        );
        verify_numeric(
            self.Mode,
            8,
            "Mode",
            "",
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut paxHdrs,
        );
        verify_numeric(
            toint64(self.Uid),
            8,
            "Uid",
            paxUid,
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut paxHdrs,
        );
        verify_numeric(
            toint64(self.Gid),
            8,
            "Gid",
            paxGid,
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut paxHdrs,
        );
        verify_numeric(
            self.Size,
            12,
            "Size",
            paxSize,
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut paxHdrs,
        );
        verify_numeric(
            self.Devmajor,
            8,
            "Devmajor",
            "",
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut paxHdrs,
        );
        verify_numeric(
            self.Devminor,
            8,
            "Devminor",
            "",
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut paxHdrs,
        );
        verify_time(
            self.ModTime,
            12,
            "ModTime",
            paxMtime,
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut preferPAX,
            &mut paxHdrs,
        );
        verify_time(
            self.AccessTime,
            12,
            "AccessTime",
            paxAtime,
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut preferPAX,
            &mut paxHdrs,
        );
        verify_time(
            self.ChangeTime,
            12,
            "ChangeTime",
            paxCtime,
            &mut format,
            &mut whyNoGNU,
            &mut whyNoUSTAR,
            &mut whyNoPAX,
            &mut preferPAX,
            &mut paxHdrs,
        );

        // Check for header-only types.
        match self.Typeflag {
            t if t == TypeReg
                || t == TypeChar
                || t == TypeBlock
                || t == TypeFifo
                || t == TypeGNUSparse =>
            {
                if strings::HasSuffix(self.Name.clone(), "/") {
                    return (
                        FormatUnknown,
                        map::new(),
                        headerErr(alloc::vec![crate::string(
                            "filename may not have trailing slash"
                        )]),
                    );
                }
            }
            t if t == TypeXHeader || t == TypeGNULongName || t == TypeGNULongLink => {
                return (FormatUnknown, map::new(), headerErr(alloc::vec![
                    crate::string("cannot manually encode TypeXHeader, TypeGNULongName, or TypeGNULongLink headers")]));
            }
            t if t == TypeXGlobalHeader => {
                // Only PAXRecords (+ Name/Typeflag/Xattrs/Format) may be set.
                if self.Linkname.Len() > 0
                    || self.Size != 0
                    || self.Mode != 0
                    || self.Uid != 0
                    || self.Gid != 0
                    || self.Uname.Len() > 0
                    || self.Gname.Len() > 0
                    || !self.ModTime.IsZero()
                    || !self.AccessTime.IsZero()
                    || !self.ChangeTime.IsZero()
                    || self.Devmajor != 0
                    || self.Devminor != 0
                {
                    return (
                        FormatUnknown,
                        map::new(),
                        headerErr(alloc::vec![crate::string(
                            "only PAXRecords should be set for TypeXGlobalHeader"
                        )]),
                    );
                }
                whyOnlyPAX = crate::string("only PAX supports TypeXGlobalHeader");
                format.mayOnlyBe(FormatPAX);
            }
            _ => {}
        }
        if !isHeaderOnlyType(self.Typeflag) && self.Size < 0 {
            return (
                FormatUnknown,
                map::new(),
                headerErr(alloc::vec![crate::string(
                    "negative size on header-only type"
                )]),
            );
        }

        // Check PAX records — Xattrs.
        if self.Xattrs.Len() > 0 {
            for (k, v) in crate::range!(&self.Xattrs) {
                paxHdrs.Set(crate::string(paxSchilyXattr) + k.clone(), v.clone());
            }
            whyOnlyPAX = crate::string("only PAX supports Xattrs");
            format.mayOnlyBe(FormatPAX);
        }
        // Check PAX records — PAXRecords.
        if self.PAXRecords.Len() > 0 {
            for (k, v) in crate::range!(&self.PAXRecords) {
                let (_, exists) = paxHdrs.Get(k.clone());
                if exists {
                    continue;
                } else if self.Typeflag == TypeXGlobalHeader {
                    paxHdrs.Set(k.clone(), v.clone());
                } else if !basicKey(k) && !strings::HasPrefix(k.clone(), "GNU.sparse.") {
                    paxHdrs.Set(k.clone(), v.clone());
                }
            }
            whyOnlyPAX = crate::string("only PAX supports PAXRecords");
            format.mayOnlyBe(FormatPAX);
        }
        for (k, v) in crate::range!(&paxHdrs) {
            if !validPAXRecord(k.clone(), v.clone()) {
                return (
                    FormatUnknown,
                    map::new(),
                    headerErr(alloc::vec![crate::string("invalid PAX record")]),
                );
            }
        }

        // Check desired format.
        let want_format = self.Format;
        if want_format != FormatUnknown {
            let mut wf = want_format;
            if wf.has(FormatPAX) && !preferPAX {
                wf.mayBe(FormatUSTAR);
            }
            format.mayOnlyBe(wf);
        }
        let mut err: error = nil;
        if format == FormatUnknown {
            if self.Format == FormatUSTAR {
                err = headerErr(alloc::vec![
                    crate::string("Format specifies USTAR"),
                    whyNoUSTAR,
                    whyOnlyPAX,
                    whyOnlyGNU
                ]);
            } else if self.Format == FormatPAX {
                err = headerErr(alloc::vec![
                    crate::string("Format specifies PAX"),
                    whyNoPAX,
                    whyOnlyGNU
                ]);
            } else if self.Format == FormatGNU {
                err = headerErr(alloc::vec![
                    crate::string("Format specifies GNU"),
                    whyNoGNU,
                    whyOnlyPAX
                ]);
            } else {
                err = headerErr(alloc::vec![
                    whyNoUSTAR, whyNoPAX, whyNoGNU, whyOnlyPAX, whyOnlyGNU
                ]);
            }
        }
        return (format, paxHdrs, err);
    }
}

// go: sdk 1.25.5 archive/tar/common.go:136-146 basicKeys
// goishlint:ignore GOISH014 - the anchor names the GO symbol. Go's
//     `basicKeys` is a `map[string]bool` consulted as `basicKeys[k]`;
//     goish spells the same set as a predicate, so the Rust name is
//     `basicKey`, not `basicKeys`.
/// `basicKeys[k]` — the PAX keys with built-in Header support.
fn basicKey(k: &string) -> bool {
    let kb = k.as_bytes();
    return kb == paxPath.as_bytes()
        || kb == paxLinkpath.as_bytes()
        || kb == paxSize.as_bytes()
        || kb == paxUid.as_bytes()
        || kb == paxGid.as_bytes()
        || kb == paxUname.as_bytes()
        || kb == paxGname.as_bytes()
        || kb == paxMtime.as_bytes()
        || kb == paxAtime.as_bytes()
        || kb == paxCtime.as_bytes();
}

// ─── FileInfoHeader / FileInfo (common.go:540 / 648) ─────────────────

// go: sdk 1.25.5 archive/tar/common.go:619-636 c_ISDIR
// Mode constants from the USTAR spec (common.go:619).
/// Common Unix mode constants; these are not defined in any common tar
/// standard. `Header.FileInfo` understands them, but `FileInfoHeader`
/// will never produce them.
///
/// Go declares all ten in one `const` block, so the anchor above cites
/// the block — that is the declaration. Seven of them were missing, and
/// `Header::FileInfo` matched on integer literals in their place.
const c_ISDIR: i64 = 0o40000;
const c_ISFIFO: i64 = 0o10000;
const c_ISREG: i64 = 0o100000;
const c_ISLNK: i64 = 0o120000;
const c_ISBLK: i64 = 0o60000;
const c_ISCHR: i64 = 0o20000;
const c_ISSOCK: i64 = 0o140000;
const c_ISUID: i64 = 0o4000;
const c_ISGID: i64 = 0o2000;
const c_ISVTX: i64 = 0o1000;

// go: sdk 1.25.5 archive/tar/common.go:648-727 FileInfoHeader
/// `FileInfoHeader` creates a partially-populated [`Header`] from `fi`.
/// If `fi` describes a symlink, `link` is recorded as the link target;
/// a directory gets a trailing slash appended to the name.
pub fn FileInfoHeader(
    fi: &(dyn fs::FileInfo + Send + Sync + 'static),
    link: &string,
) -> (Header, error) {
    // Go guards `if fi == nil`; goish takes `fi` by reference so it is
    // never nil at this point.
    let fm = fi.Mode();
    let mut h = Header::new();
    h.Name = fi.Name();
    h.ModTime = fi.ModTime();
    h.Mode = toint64(fm.Perm().Bits());

    if fm.IsRegular() {
        h.Typeflag = TypeReg;
        h.Size = fi.Size();
    } else if fi.IsDir() {
        h.Typeflag = TypeDir;
        h.Name = h.Name + "/";
    } else if (fm & fs::ModeSymlink) != fs::FileMode(0) {
        h.Typeflag = TypeSymlink;
        h.Linkname = link.clone();
    } else if (fm & fs::ModeDevice) != fs::FileMode(0) {
        if (fm & fs::ModeCharDevice) != fs::FileMode(0) {
            h.Typeflag = TypeChar;
        } else {
            h.Typeflag = TypeBlock;
        }
    } else if (fm & fs::ModeNamedPipe) != fs::FileMode(0) {
        h.Typeflag = TypeFifo;
    } else if (fm & fs::ModeSocket) != fs::FileMode(0) {
        return (
            Header::new(),
            crate::errors::New("archive/tar: sockets not supported"),
        );
    } else {
        return (
            Header::new(),
            crate::errors::New("archive/tar: unknown file mode"),
        );
    }
    if (fm & fs::ModeSetuid) != fs::FileMode(0) {
        h.Mode |= c_ISUID;
    }
    if (fm & fs::ModeSetgid) != fs::FileMode(0) {
        h.Mode |= c_ISGID;
    }
    if (fm & fs::ModeSticky) != fs::FileMode(0) {
        h.Mode |= c_ISVTX;
    }

    // Go: a FileInfo that also implements FileInfoNames supplies Uname
    // and Gname itself, and suppresses the system lookup.
    let mut doNameLookups = true;
    let (names, ok) = crate::cast!(fi, FileInfoNames);
    if ok {
        doNameLookups = false;
        let (gname, err) = names.Gname();
        if !err.IsNil() {
            return (Header::new(), err);
        }
        h.Gname = gname;
        let (uname, err) = names.Uname();
        if !err.IsNil() {
            return (Header::new(), err);
        }
        h.Uname = uname;
    }

    // Go reaches this through the `sysStat` function variable, which
    // each stat_*.go sets in its own init; the indirection exists to
    // pick a platform. goish builds for linux only, so the one
    // implementation is called directly — see stat_unix.rs.
    let err = super::stat_unix::statUnix(fi, &mut h, doNameLookups);
    if !err.IsNil() {
        return (Header::new(), err);
    }
    return (h, nil);
}

// ─── headerFileInfo — Header.FileInfo (common.go:540) ────────────────

/// `headerFileInfo` implements [`fs::FileInfo`] over a [`Header`].
struct headerFileInfo {
    h: Header,
}

impl fs::FileInfo for headerFileInfo {
    // go: sdk 1.25.5 archive/tar/common.go:555-560 headerFileInfo.Name
    fn Name(&self) -> string {
        if self.IsDir() {
            return crate::path::Base(crate::path::Clean(self.h.Name.clone()));
        }
        return crate::path::Base(self.h.Name.clone());
    }
    // go: sdk 1.25.5 archive/tar/common.go:549-549 headerFileInfo.Size
    fn Size(&self) -> i64 {
        return self.h.Size;
    }
    // go: sdk 1.25.5 archive/tar/common.go:551-551 headerFileInfo.ModTime
    fn ModTime(&self) -> Time {
        return self.h.ModTime;
    }
    // go: sdk 1.25.5 archive/tar/common.go:550-550 headerFileInfo.IsDir
    fn IsDir(&self) -> bool {
        return self.Mode().IsDir();
    }
    // go: sdk 1.25.5 archive/tar/common.go:552-552 headerFileInfo.Sys
    fn Sys(&self) -> Arc<dyn core::any::Any + Send + Sync> {
        return Arc::new(());
    }
    // go: sdk 1.25.5 archive/tar/common.go:563-610 headerFileInfo.Mode
    fn Mode(&self) -> fs::FileMode {
        let mut mode = fs::FileMode(touint32(self.h.Mode) & 0o777);
        if self.h.Mode & c_ISUID != 0 {
            mode = mode | fs::ModeSetuid;
        }
        if self.h.Mode & c_ISGID != 0 {
            mode = mode | fs::ModeSetgid;
        }
        if self.h.Mode & c_ISVTX != 0 {
            mode = mode | fs::ModeSticky;
        }

        // Go: switch m := fs.FileMode(fi.h.Mode) &^ 07777; m { … }
        //
        // This whole arm was missing. A header whose Mode carries the
        // Unix type bits — 0o40755 for a directory, 0o120777 for a
        // symlink — was reported as a regular file, because only
        // Typeflag was consulted. Go consults both, and a tar written
        // by anything that fills Mode from a stat(2) puts the type
        // there.
        let m = self.h.Mode & !0o7777;
        if m == c_ISDIR {
            mode = mode | fs::ModeDir;
        } else if m == c_ISFIFO {
            mode = mode | fs::ModeNamedPipe;
        } else if m == c_ISLNK {
            mode = mode | fs::ModeSymlink;
        } else if m == c_ISBLK {
            mode = mode | fs::ModeDevice;
        } else if m == c_ISCHR {
            mode = mode | fs::ModeDevice;
            mode = mode | fs::ModeCharDevice;
        } else if m == c_ISSOCK {
            mode = mode | fs::ModeSocket;
        }

        match self.h.Typeflag {
            t if t == TypeSymlink => mode = mode | fs::ModeSymlink,
            t if t == TypeChar => {
                mode = mode | fs::ModeDevice;
                mode = mode | fs::ModeCharDevice;
            }
            t if t == TypeBlock => mode = mode | fs::ModeDevice,
            t if t == TypeDir => mode = mode | fs::ModeDir,
            t if t == TypeFifo => mode = mode | fs::ModeNamedPipe,
            _ => {}
        }
        return mode;
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl crate::fmt::Stringer for headerFileInfo {
    // go: sdk 1.25.5 archive/tar/common.go:612-614 headerFileInfo.String
    /// Go: `return fs.FormatFileInfo(fi)` — the human-readable rendering
    /// `%v` on a FileInfo produces. Go's is a plain method satisfying
    /// `fmt.Stringer` structurally; goish names the trait.
    fn String(&self) -> string {
        return fs::FormatFileInfo(self);
    }
}

// go: sdk 1.25.5 archive/tar/common.go:732-739 FileInfoNames
/// `tar.FileInfoNames` — an [`fs::FileInfo`] that also knows its user
/// and group names. Passing one to [`FileInfoHeader`] lets the caller
/// skip the system-dependent name lookup by supplying Uname and Gname
/// directly.
///
/// Go embeds `fs.FileInfo`; `#[goish::interface]` does not model
/// embedding, so the inherited methods are re-declared here — the same
/// treatment every composite interface in io/fs gets.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait FileInfoNames {
    /// Base name of the file (from embedded [`fs::FileInfo`]).
    fn Name(&self) -> string;
    /// Length in bytes (from embedded [`fs::FileInfo`]).
    fn Size(&self) -> i64;
    /// File mode bits (from embedded [`fs::FileInfo`]).
    fn Mode(&self) -> fs::FileMode;
    /// Modification time (from embedded [`fs::FileInfo`]).
    fn ModTime(&self) -> Time;
    /// Whether the file is a directory (from embedded [`fs::FileInfo`]).
    fn IsDir(&self) -> bool;
    /// Underlying data source (from embedded [`fs::FileInfo`]).
    fn Sys(&self) -> Arc<dyn core::any::Any + Send + Sync>;
    /// A user name for the file's owner.
    fn Uname(&self) -> (string, error);
    /// A group name for the file's group.
    fn Gname(&self) -> (string, error);
}

impl Header {
    // go: sdk 1.25.5 archive/tar/common.go:540-542 Header.FileInfo
    /// `h.FileInfo()` — an [`fs::FileInfo`] describing the Header.
    pub fn FileInfo(&self) -> Arc<dyn fs::FileInfo + Send + Sync> {
        return Arc::new(headerFileInfo { h: self.clone() });
    }
}
