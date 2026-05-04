// archive/tar — Go's archive/tar reader, ported.
//
// Focus: Reader, Header, Format, and constants.
// Writer is stubbed (not ported).
// Sparse file reading is stubbed — sparse files return ErrHeader.
//
// Public API mirrors Go 1.25 archive/tar reader surface.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types, dead_code)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::strconv;
use crate::strings;
use crate::time::Time;
use crate::types::{byte, int};

// ─── Constants ───────────────────────────────────────────────────────

const blockSize: int = 512;
const nameSize: int = 100;
const prefixSize: int = 155;
const maxSpecialFileSize: int = 1 << 20;

const magicGNU: &str = "ustar ";
const versionGNU: &str = " \x00";
const magicUSTAR: &str = "ustar\x00";
const versionUSTAR: &str = "00";
const trailerSTAR: &str = "tar\x00";

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

const paxPath: &str = "path";
const paxLinkpath: &str = "linkpath";
const paxSize: &str = "size";
const paxUid: &str = "uid";
const paxGid: &str = "gid";
const paxUname: &str = "uname";
const paxGname: &str = "gname";
const paxMtime: &str = "mtime";
const paxAtime: &str = "atime";
const paxCtime: &str = "ctime";

const paxSchilyXattr: &str = "SCHILY.xattr.";

const paxGNUSparseMajor: &str = "GNU.sparse.major";
const paxGNUSparseMinor: &str = "GNU.sparse.minor";
const paxGNUSparseName: &str = "GNU.sparse.name";
const paxGNUSparseSize: &str = "GNU.sparse.size";
const paxGNUSparseRealSize: &str = "GNU.sparse.realsize";
const paxGNUSparseNumBlocks: &str = "GNU.sparse.numblocks";
const paxGNUSparseOffset: &str = "GNU.sparse.offset";
const paxGNUSparseNumBytes: &str = "GNU.sparse.numbytes";
const paxGNUSparseMap: &str = "GNU.sparse.map";

// ─── Errors ──────────────────────────────────────────────────────────

/// Invalid tar header.
pub fn ErrHeader() -> error {
    errors::New("archive/tar: invalid tar header")
}

/// Header field too long.
pub fn ErrFieldTooLong() -> error {
    errors::New("archive/tar: header field too long")
}

// ─── Format ──────────────────────────────────────────────────────────

/// Tar archive format identifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Format(int);

impl Format {
    pub fn has(self, f: Format) -> bool {
        (self.0 & f.0) != 0
    }
    pub fn mayBe(&mut self, f: Format) {
        self.0 |= f.0;
    }
    pub fn mayOnlyBe(&mut self, f: Format) {
        self.0 &= f.0;
    }
    pub fn mustNotBe(&mut self, f: Format) {
        self.0 &= !f.0;
    }
}

impl core::ops::BitOr for Format {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Format(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for Format {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Format(self.0 & rhs.0)
    }
}

impl core::ops::Not for Format {
    type Output = Self;
    fn not(self) -> Self {
        Format(!self.0)
    }
}

impl core::fmt::Display for Format {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut parts: Vec<string> = Vec::new();
        let mut bit: int = 1;
        while bit < formatMax.0 {
            let fmt_bit = Format(bit);
            if self.has(fmt_bit) {
                if let Some(name) = formatName(fmt_bit) {
                    parts.push(name);
                }
            }
            bit <<= 1;
        }
        match parts.len() {
            0 => write!(f, "<unknown>"),
            1 => write!(f, "{}", parts[0]),
            _ => {
                let joined = strings::Join(slice::__from_vec(parts), " | ");
                write!(f, "({})", joined)
            }
        }
    }
}

fn formatName(f: Format) -> Option<string> {
    if f == formatV7 {
        Some(crate::string("V7"))
    } else if f == FormatUSTAR {
        Some(crate::string("USTAR"))
    } else if f == FormatPAX {
        Some(crate::string("PAX"))
    } else if f == FormatGNU {
        Some(crate::string("GNU"))
    } else if f == formatSTAR {
        Some(crate::string("STAR"))
    } else {
        None
    }
}

const formatV7: Format = Format(1 << 0);
pub const FormatUnknown: Format = Format(1 << 1);
pub const FormatUSTAR: Format = Format(1 << 2);
pub const FormatPAX: Format = Format(1 << 3);
pub const FormatGNU: Format = Format(1 << 4);
const formatSTAR: Format = Format(1 << 5);
const formatMax: Format = Format(1 << 6);

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
    pub fn new() -> Self {
        Self {
            Typeflag: 0,
            Name: string::new(),
            Linkname: string::new(),
            Size: 0,
            Mode: 0,
            Uid: 0,
            Gid: 0,
            Uname: string::new(),
            Gname: string::new(),
            ModTime: crate::time::Unix(0, 0),
            AccessTime: crate::time::Unix(0, 0),
            ChangeTime: crate::time::Unix(0, 0),
            Devmajor: 0,
            Devminor: 0,
            Xattrs: map::new(),
            PAXRecords: map::new(),
            Format: FormatUnknown,
        }
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
    pub fn endOffset(&self) -> i64 {
        self.Offset + self.Length
    }
}

/// Sparse data fragments.
pub type sparseDatas = slice<sparseEntry>;

/// Sparse hole fragments.
pub type sparseHoles = slice<sparseEntry>;

fn validateSparseEntries(sp: &sparseDatas, size: i64) -> bool {
    if size < 0 {
        return false;
    }
    let mut pre = sparseEntry { Offset: 0, Length: 0 };
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
    true
}

fn invertSparseEntries(src: &sparseDatas, size: i64) -> sparseHoles {
    let mut dst = sparseHoles::new();
    let mut pre = sparseEntry { Offset: 0, Length: 0 };
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
    crate::append!(dst, pre)
}

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
            dst = crate::append!(dst, sparseEntry { Offset: pos, Length: end - pos });
        }
    }
    dst
}

// ─── block ──────────────────────────────────────────────────────────

/// A tar header block (512 bytes).
pub struct block([byte; 512]);

impl block {
    pub fn new() -> Self {
        Self([0; 512])
    }

    pub fn isZero(&self) -> bool {
        for i in 0..512usize {
            if self.0[i] != 0 {
                return false;
            }
        }
        true
    }

    fn slice(&self, start: int, end: int) -> slice<byte> {
        slice::__from_vec(self.0[start as usize..end as usize].to_vec())
    }

    pub fn v7_name(&self) -> slice<byte> { self.slice(0, 100) }
    pub fn v7_mode(&self) -> slice<byte> { self.slice(100, 108) }
    pub fn v7_uid(&self) -> slice<byte> { self.slice(108, 116) }
    pub fn v7_gid(&self) -> slice<byte> { self.slice(116, 124) }
    pub fn v7_size(&self) -> slice<byte> { self.slice(124, 136) }
    pub fn v7_modTime(&self) -> slice<byte> { self.slice(136, 148) }
    pub fn v7_chksum(&self) -> slice<byte> { self.slice(148, 156) }
    pub fn v7_typeFlag(&self) -> slice<byte> { self.slice(156, 157) }
    pub fn v7_linkName(&self) -> slice<byte> { self.slice(157, 257) }

    pub fn ustar_magic(&self) -> slice<byte> { self.slice(257, 263) }
    pub fn ustar_version(&self) -> slice<byte> { self.slice(263, 265) }
    pub fn ustar_userName(&self) -> slice<byte> { self.slice(265, 297) }
    pub fn ustar_groupName(&self) -> slice<byte> { self.slice(297, 329) }
    pub fn ustar_devMajor(&self) -> slice<byte> { self.slice(329, 337) }
    pub fn ustar_devMinor(&self) -> slice<byte> { self.slice(337, 345) }
    pub fn ustar_prefix(&self) -> slice<byte> { self.slice(345, 500) }

    pub fn gnu_accessTime(&self) -> slice<byte> { self.slice(345, 357) }
    pub fn gnu_changeTime(&self) -> slice<byte> { self.slice(357, 369) }
    pub fn gnu_sparse(&self) -> slice<byte> { self.slice(386, 483) }
    pub fn gnu_realSize(&self) -> slice<byte> { self.slice(483, 495) }

    pub fn star_prefix(&self) -> slice<byte> { self.slice(345, 476) }
    pub fn star_accessTime(&self) -> slice<byte> { self.slice(476, 488) }
    pub fn star_changeTime(&self) -> slice<byte> { self.slice(488, 500) }
    pub fn star_trailer(&self) -> slice<byte> { self.slice(508, 512) }

    pub fn computeChecksum(&self) -> (i64, i64) {
        let mut unsigned: i64 = 0;
        let mut signed: i64 = 0;
        for i in 0..512usize {
            let mut c = self.0[i];
            if 148 <= i && i < 156 {
                c = b' ';
            }
            unsigned += c as i64;
            signed += (c as i8) as i64;
        }
        (unsigned, signed)
    }

    pub fn getFormat(&self) -> Format {
        let mut p = parser::new();
        let value = p.parseOctal(self.v7_chksum());
        let (chksum1, chksum2) = self.computeChecksum();
        if !p.err.IsNil() || (value != chksum1 && value != chksum2) {
            return FormatUnknown;
        }
        let magic = crate::string(self.ustar_magic());
        let version = crate::string(self.ustar_version());
        let trailer = crate::string(self.star_trailer());
        if magic == magicUSTAR && trailer == trailerSTAR {
            return formatSTAR;
        }
        if magic == magicUSTAR {
            return FormatUSTAR | FormatPAX;
        }
        if magic == magicGNU && version == versionGNU {
            return FormatGNU;
        }
        formatV7
    }
}

// ─── Reader ──────────────────────────────────────────────────────────

/// Reader provides sequential access to a tar archive.
pub struct Reader {
    r: Box<dyn crate::io::Reader>,
    pad: i64,
    nb: i64,
    blk: block,
    err: error,
}

/// NewReader creates a new Reader reading from r.
pub fn NewReader(r: Box<dyn crate::io::Reader>) -> Reader {
    Reader {
        r,
        pad: 0,
        nb: 0,
        blk: block::new(),
        err: nil,
    }
}

impl Reader {
    /// Next advances to the next entry in the tar archive.
    pub fn Next(&mut self) -> (Header, error) {
        if !self.err.IsNil() {
            return (Header::new(), self.err.clone());
        }
        let (hdr, err) = self.next();
        self.err = err.clone();
        (hdr, err)
    }

    fn next(&mut self) -> (Header, error) {
        let mut paxHdrs = map::<string, string>::new();
        let mut gnuLongName = string::new();
        let mut gnuLongLink = string::new();

        let mut format = FormatUSTAR | FormatPAX | FormatGNU;

        loop {
            // Discard the remainder of the file and any padding.
            let err = discard(&mut *self.r, self.nb);
            if !err.IsNil() {
                return (Header::new(), err);
            }
            if self.pad > 0 {
                let mut pad_buf = crate::make!([]byte, self.pad as int);
                let (_, err) = tryReadFull(&mut *self.r, &mut pad_buf);
                if !err.IsNil() {
                    return (Header::new(), err);
                }
            }
            self.pad = 0;

            let (mut hdr, err) = self.readHeader();
            if !err.IsNil() {
                return (Header::new(), err);
            }
            let err = self.handleRegularFile(&hdr);
            if !err.IsNil() {
                return (Header::new(), err);
            }
            format.mayOnlyBe(hdr.Format);

            match hdr.Typeflag {
                TypeXHeader | TypeXGlobalHeader => {
                    format.mayOnlyBe(FormatPAX);
                    let (ph, err) = parsePAX(&mut *self.r);
                    if !err.IsNil() {
                        return (Header::new(), err);
                    }
                    if hdr.Typeflag == TypeXGlobalHeader {
                        let mut gh = Header::new();
                        gh.Name = hdr.Name.clone();
                        gh.Typeflag = hdr.Typeflag;
                        gh.Xattrs = hdr.Xattrs.clone();
                        gh.PAXRecords = ph.clone();
                        gh.Format = format;
                        return (gh, nil);
                    }
                    paxHdrs = ph;
                    continue;
                }
                TypeGNULongName | TypeGNULongLink => {
                    format.mayOnlyBe(FormatGNU);
                    let (realname, err) = readSpecialFile(&mut *self.r);
                    if !err.IsNil() {
                        return (Header::new(), err);
                    }
                    let mut p = parser::new();
                    if hdr.Typeflag == TypeGNULongName {
                        gnuLongName = p.parseString(realname);
                    } else {
                        gnuLongLink = p.parseString(realname);
                    }
                    continue;
                }
                _ => {
                    let err = mergePAX(&mut hdr, &paxHdrs);
                    if !err.IsNil() {
                        return (Header::new(), err);
                    }
                    if gnuLongName.Len() > 0 {
                        hdr.Name = gnuLongName.clone();
                    }
                    if gnuLongLink.Len() > 0 {
                        hdr.Linkname = gnuLongLink.clone();
                    }
                    if hdr.Typeflag == TypeRegA {
                        if strings::HasSuffix(hdr.Name.clone(), "/") {
                            hdr.Typeflag = TypeDir;
                        } else {
                            hdr.Typeflag = TypeReg;
                        }
                    }

                    let err = self.handleRegularFile(&hdr);
                    if !err.IsNil() {
                        return (Header::new(), err);
                    }

                    // Sparse file support: stubbed.
                    let err = self.handleSparseFile(&hdr);
                    if !err.IsNil() {
                        return (Header::new(), err);
                    }

                    if format.has(FormatUSTAR | FormatPAX) {
                        format.mayOnlyBe(FormatUSTAR);
                    }
                    hdr.Format = format;
                    return (hdr, nil);
                }
            }
        }
    }
}

impl crate::io::Reader for Reader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }
        let want = if (p.Len() as i64) > self.nb {
            self.nb as int
        } else {
            p.Len()
        };
        if want == 0 {
            return (0, io::EOF.into());
        }
        let mut tmp = crate::make!([]byte, want);
        let (n, mut err) = self.r.Read(&mut tmp);
        for i in 0..n {
            p[i] = tmp[i];
        }
        self.nb -= n as i64;
        if err.IsNil() && self.nb == 0 {
            err = io::EOF.into();
        }
        if err == io::EOF && self.nb > 0 {
            err = io::ErrUnexpectedEOF.into();
        }
        if !err.IsNil() && err != io::EOF {
            self.err = err.clone();
        }
        (n, err)
    }
}

// ─── Internal file handling ────────────────────────────────────────

fn isHeaderOnlyType(flag: byte) -> bool {
    match flag {
        TypeLink | TypeSymlink | TypeChar | TypeBlock | TypeDir | TypeFifo => true,
        _ => false,
    }
}

impl Reader {
    fn handleRegularFile(&mut self, hdr: &Header) -> error {
        let mut nb = hdr.Size;
        if isHeaderOnlyType(hdr.Typeflag) {
            nb = 0;
        }
        if nb < 0 {
            return ErrHeader();
        }
        self.pad = blockPadding(nb);
        self.nb = nb;
        nil
    }

    fn handleSparseFile(&mut self, _hdr: &Header) -> error {
        // Sparse file reading is stubbed.
        // In a full port this would set up a sparseFileReader wrapper.
        nil
    }

    fn readHeader(&mut self) -> (Header, error) {
        let mut tmp = crate::make!([]byte, 512);
        let (_, err) = crate::io::ReadFull(&mut *self.r, &mut tmp);
        if !err.IsNil() {
            return (Header::new(), err);
        }
        let mut i: int = 0;
        while i < 512 {
            self.blk.0[i as usize] = tmp[i];
            i += 1;
        }

        if self.blk.isZero() {
            let mut tmp2 = crate::make!([]byte, 512);
            let (_, err2) = crate::io::ReadFull(&mut *self.r, &mut tmp2);
            if !err2.IsNil() {
                if err2 == io::EOF {
                    return (Header::new(), io::EOF.into());
                }
                return (Header::new(), err2);
            }
            let mut blk2 = block::new();
            let mut i: int = 0;
            while i < 512 {
                blk2.0[i as usize] = tmp2[i];
                i += 1;
            }
            if blk2.isZero() {
                return (Header::new(), io::EOF.into());
            }
            return (Header::new(), ErrHeader());
        }

        let format = self.blk.getFormat();
        if format == FormatUnknown {
            return (Header::new(), ErrHeader());
        }

        let mut p = parser::new();
        let mut hdr = Header::new();

        hdr.Typeflag = self.blk.v7_typeFlag()[0];
        hdr.Name = p.parseString(self.blk.v7_name());
        hdr.Linkname = p.parseString(self.blk.v7_linkName());
        hdr.Size = p.parseNumeric(self.blk.v7_size());
        hdr.Mode = p.parseNumeric(self.blk.v7_mode());
        hdr.Uid = p.parseNumeric(self.blk.v7_uid()) as int;
        hdr.Gid = p.parseNumeric(self.blk.v7_gid()) as int;
        hdr.ModTime = crate::time::Unix(p.parseNumeric(self.blk.v7_modTime()), 0);

        if format.0 > formatV7.0 {
            hdr.Uname = p.parseString(self.blk.ustar_userName());
            hdr.Gname = p.parseString(self.blk.ustar_groupName());
            hdr.Devmajor = p.parseNumeric(self.blk.ustar_devMajor());
            hdr.Devminor = p.parseNumeric(self.blk.ustar_devMinor());

            let mut prefix = string::new();
            if format.has(FormatUSTAR | FormatPAX) {
                hdr.Format = format;
                prefix = p.parseString(self.blk.ustar_prefix());

                let mut has_non_ascii = false;
                for i in 0..512usize {
                    if self.blk.0[i] >= 0x80 {
                        has_non_ascii = true;
                        break;
                    }
                }
                if has_non_ascii {
                    hdr.Format = FormatUnknown;
                }

                let nul = |b: &slice<byte>| -> bool {
                    let bytes: &[u8] = &*b;
                    !bytes.is_empty() && bytes[bytes.len() - 1] == 0
                };
                if !(nul(&self.blk.v7_size()) && nul(&self.blk.v7_mode())
                    && nul(&self.blk.v7_uid()) && nul(&self.blk.v7_gid())
                    && nul(&self.blk.v7_modTime())
                    && nul(&self.blk.ustar_devMajor())
                    && nul(&self.blk.ustar_devMinor()))
                {
                    hdr.Format = FormatUnknown;
                }
            } else if format.has(formatSTAR) {
                prefix = p.parseString(self.blk.star_prefix());
                hdr.AccessTime = crate::time::Unix(p.parseNumeric(self.blk.star_accessTime()), 0);
                hdr.ChangeTime = crate::time::Unix(p.parseNumeric(self.blk.star_changeTime()), 0);
            } else if format.has(FormatGNU) {
                hdr.Format = format;
                let mut p2 = parser::new();
                let at = self.blk.gnu_accessTime();
                let at_bytes: &[u8] = &at;
                if !at_bytes.is_empty() && at_bytes[0] != 0 {
                    hdr.AccessTime = crate::time::Unix(p2.parseNumeric(at), 0);
                }
                let ct = self.blk.gnu_changeTime();
                let ct_bytes: &[u8] = &ct;
                if !ct_bytes.is_empty() && ct_bytes[0] != 0 {
                    hdr.ChangeTime = crate::time::Unix(p2.parseNumeric(ct), 0);
                }
                if !p2.err.IsNil() {
                    hdr.AccessTime = crate::time::Unix(0, 0);
                    hdr.ChangeTime = crate::time::Unix(0, 0);
                    let ps = p.parseString(self.blk.ustar_prefix());
                    if isASCII(&ps) {
                        prefix = ps;
                    }
                    hdr.Format = FormatUnknown;
                }
            }

            if prefix.Len() > 0 {
                hdr.Name = prefix + "/" + hdr.Name;
            }
        }

        (hdr, p.err)
    }
}

// ─── PAX parsing ─────────────────────────────────────────────────────

fn mergePAX(hdr: &mut Header, paxHdrs: &map<string, string>) -> error {
    for (k, v) in crate::range!(paxHdrs) {
        let k = k.clone();
        let v = v.clone();
        if v == "" {
            continue;
        }
        let mut err: error = nil;
        if k == paxPath {
            hdr.Name = v;
        } else if k == paxLinkpath {
            hdr.Linkname = v;
        } else if k == paxUname {
            hdr.Uname = v;
        } else if k == paxGname {
            hdr.Gname = v;
        } else if k == paxUid {
            let (x, e) = strconv::ParseInt(v, 10, 64);
            hdr.Uid = x as int;
            err = e;
        } else if k == paxGid {
            let (x, e) = strconv::ParseInt(v, 10, 64);
            hdr.Gid = x as int;
            err = e;
        } else if k == paxAtime {
            let (t, e) = parsePAXTime(v);
            hdr.AccessTime = t;
            err = e;
        } else if k == paxMtime {
            let (t, e) = parsePAXTime(v);
            hdr.ModTime = t;
            err = e;
        } else if k == paxCtime {
            let (t, e) = parsePAXTime(v);
            hdr.ChangeTime = t;
            err = e;
        } else if k == paxSize {
            let (x, e) = strconv::ParseInt(v, 10, 64);
            hdr.Size = x;
            err = e;
        } else {
            if strings::HasPrefix(k.clone(), paxSchilyXattr) {
                let key = strings::TrimPrefix(k, paxSchilyXattr);
                hdr.Xattrs.Set(key, v);
            }
        }
        if !err.IsNil() {
            return ErrHeader();
        }
    }
    hdr.PAXRecords = paxHdrs.clone();
    nil
}

fn parsePAX(r: &mut dyn crate::io::Reader) -> (map<string, string>, error) {
    let (buf, err) = readSpecialFile(r);
    if !err.IsNil() {
        return (map::new(), err);
    }
    let mut sbuf = crate::string(buf);

    let mut sparseMap: Vec<string> = Vec::new();
    let mut paxHdrs = map::<string, string>::new();

    while sbuf.Len() > 0 {
        let (key, value, residual, err) = parsePAXRecord(sbuf);
        if !err.IsNil() {
            return (map::new(), ErrHeader());
        }
        sbuf = residual;
        let key_bytes = key.as_bytes();
        if key_bytes == paxGNUSparseOffset.as_bytes()
            || key_bytes == paxGNUSparseNumBytes.as_bytes()
        {
            let is_even = (sparseMap.len() % 2) == 0;
            let is_offset = key_bytes == paxGNUSparseOffset.as_bytes();
            if (is_even && !is_offset)
                || (!is_even && is_offset)
                || strings::Contains(value.clone(), ",")
            {
                return (map::new(), ErrHeader());
            }
            sparseMap.push(value);
        } else {
            paxHdrs.Set(key, value);
        }
    }
    if !sparseMap.is_empty() {
        let elems = slice::__from_vec(sparseMap);
        paxHdrs.Set(crate::string(paxGNUSparseMap), strings::Join(elems, ","));
    }
    (paxHdrs, nil)
}

fn parsePAXRecord(s: string) -> (string, string, string, error) {
    let s_bytes = s.as_bytes();
    let mut space_idx = -1;
    for i in 0..s.Len() {
        if s_bytes[i as usize] == b' ' {
            space_idx = i;
            break;
        }
    }
    if space_idx < 0 {
        return (string::new(), string::new(), s, ErrHeader());
    }
    let n_str = s.slice(0, space_idx);
    let rest = s.slice(space_idx + 1, s.Len());
    let (n, err) = strconv::ParseInt(n_str, 10, 0);
    if !err.IsNil() || n < 5 || n > s.Len() {
        return (string::new(), string::new(), s, ErrHeader());
    }
    let rec_len = n - (space_idx + 1);
    if rec_len <= 0 {
        return (string::new(), string::new(), s, ErrHeader());
    }
    let rec = rest.slice(0, rec_len - 1);
    let nl = rest.slice(rec_len - 1, rec_len);
    let rem = rest.slice(rec_len, rest.Len());
    if nl != "\n" {
        return (string::new(), string::new(), s, ErrHeader());
    }

    let rec_bytes = rec.as_bytes();
    let mut eq_idx = -1;
    for i in 0..rec.Len() {
        if rec_bytes[i as usize] == b'=' {
            eq_idx = i;
            break;
        }
    }
    if eq_idx < 0 {
        return (string::new(), string::new(), s, ErrHeader());
    }
    let key = rec.slice(0, eq_idx);
    let val = rec.slice(eq_idx + 1, rec.Len());
    if !validPAXRecord(key.clone(), val.clone()) {
        return (string::new(), string::new(), s, ErrHeader());
    }
    (key, val, rem, nil)
}

fn validPAXRecord(k: string, v: string) -> bool {
    if k == "" || strings::Contains(k.clone(), "=") {
        return false;
    }
    let k_bytes = k.as_bytes();
    if k_bytes == paxPath.as_bytes()
        || k_bytes == paxLinkpath.as_bytes()
        || k_bytes == paxUname.as_bytes()
        || k_bytes == paxGname.as_bytes()
    {
        !strings::Contains(v.clone(), "\x00")
    } else {
        !strings::Contains(k.clone(), "\x00")
    }
}

fn parsePAXTime(s: string) -> (Time, error) {
    const maxNanoSecondDigits: int = 9;
    let parts = strings::SplitN(s, ".", 2);
    let ss = if parts.Len() > 0 { parts[0].clone() } else { string::new() };
    let has_dot = parts.Len() > 1;
    let mut sn = if has_dot { parts[1].clone() } else { string::new() };

    let ss_bytes = ss.as_bytes();
    let (secs, err) = strconv::ParseInt(&ss, 10, 64);
    if !err.IsNil() {
        return (crate::time::Unix(0, 0), ErrHeader());
    }
    if !has_dot {
        return (crate::time::Unix(secs, 0), nil);
    }

    let sn_bytes = sn.as_bytes();
    for &c in sn_bytes {
        if c < b'0' || c > b'9' {
            return (crate::time::Unix(0, 0), ErrHeader());
        }
    }

    let sn_len = sn.Len();
    if sn_len < maxNanoSecondDigits {
        sn = sn + strings::Repeat("0", (maxNanoSecondDigits - sn_len) as int);
    } else if sn_len > maxNanoSecondDigits {
        sn = sn.slice(0, maxNanoSecondDigits);
    }

    let (nsecs, _) = strconv::ParseInt(&sn, 10, 64);
    if !ss_bytes.is_empty() && ss_bytes[0] == b'-' {
        (crate::time::Unix(secs, -nsecs), nil)
    } else {
        (crate::time::Unix(secs, nsecs), nil)
    }
}

// ─── parser ──────────────────────────────────────────────────────────

struct parser {
    err: error,
}

impl parser {
    fn new() -> Self {
        Self { err: nil }
    }

    fn parseString(&mut self, b: slice<byte>) -> string {
        let bytes: &[u8] = &b;
        if let Some(i) = bytes.iter().position(|&c| c == 0) {
            string::from_bytes(&bytes[..i])
        } else {
            string::from_bytes(bytes)
        }
    }

    fn parseNumeric(&mut self, b: slice<byte>) -> i64 {
        let bytes: &[u8] = &b;
        if !bytes.is_empty() && bytes[0] & 0x80 != 0 {
            let inv = if bytes[0] & 0x40 != 0 { 0xff } else { 0x00 };
            let mut x: u64 = 0;
            for (i, &c) in bytes.iter().enumerate() {
                let mut c = c ^ inv;
                if i == 0 {
                    c &= 0x7f;
                }
                if (x >> 56) > 0 {
                    self.err = ErrHeader();
                    return 0;
                }
                x = (x << 8) | (c as u64);
            }
            if (x >> 63) > 0 {
                self.err = ErrHeader();
                return 0;
            }
            if inv == 0xff {
                return !(x as i64);
            }
            return x as i64;
        }
        self.parseOctal(b)
    }

    fn parseOctal(&mut self, b: slice<byte>) -> i64 {
        let bytes: &[u8] = &b;
        let mut start = 0usize;
        let mut end = bytes.len();
        while start < end && (bytes[start] == b' ' || bytes[start] == 0) {
            start += 1;
        }
        while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == 0) {
            end -= 1;
        }
        if start == end {
            return 0;
        }
        let trimmed = slice::__from_vec(bytes[start..end].to_vec());
        let s = self.parseString(trimmed);
        let (x, err) = strconv::ParseUint(s, 8, 64);
        if !err.IsNil() {
            self.err = ErrHeader();
        }
        x as i64
    }
}

// ─── Utility functions ───────────────────────────────────────────────

fn blockPadding(offset: i64) -> i64 {
    (-offset) & (512_i64 - 1)
}

fn discard(r: &mut dyn crate::io::Reader, n: i64) -> error {
    if n <= 0 {
        return nil;
    }
    let mut discarder = crate::io::DiscardWriter();
    let (_, mut err) = crate::io::CopyN(&mut discarder, r, n);
    if err == io::EOF {
        err = io::ErrUnexpectedEOF.into();
    }
    err
}

fn tryReadFull(r: &mut dyn crate::io::Reader, buf: &mut slice<byte>) -> (int, error) {
    let total = buf.Len();
    let mut n: int = 0;
    let mut err: error = nil;
    while total > n && err.IsNil() {
        let cap_left = total - n;
        let mut tmp = crate::make!([]byte, cap_left);
        let (nn, e) = r.Read(&mut tmp);
        for i in 0..nn {
            buf[n + i] = tmp[i];
        }
        n += nn;
        err = e;
    }
    if total == n && err == io::EOF {
        err = nil;
    }
    (n, err)
}

fn mustReadFull(r: &mut dyn crate::io::Reader, buf: &mut slice<byte>) -> (int, error) {
    let (n, mut err) = tryReadFull(r, buf);
    if err == io::EOF {
        err = io::ErrUnexpectedEOF.into();
    }
    (n, err)
}

fn readSpecialFile(r: &mut dyn crate::io::Reader) -> (slice<byte>, error) {
    let mut limited = crate::io::LimitReader(r, (maxSpecialFileSize + 1) as int);
    let (buf, err) = crate::io::ReadAll(&mut limited);
    if buf.Len() > maxSpecialFileSize {
        return (slice::new(), ErrFieldTooLong());
    }
    (buf, err)
}

fn isASCII(s: &string) -> bool {
    let bytes = s.as_bytes();
    for &c in bytes {
        if c >= 0x80 || c == 0x00 {
            return false;
        }
    }
    true
}
