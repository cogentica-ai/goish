// archive/tar — Go's archive/tar reader, ported.
//
// Focus: Reader, Header, Format, and constants.
// Writer is stubbed (not ported).
// Sparse file reading is stubbed — sparse files return ErrHeader.
//
// Public API mirrors Go 1.25 archive/tar reader surface.

#![allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code
)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::errors::{error, nil};
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

crate::var! {
    /// Invalid tar header.
    pub ErrHeader: error       = "archive/tar: invalid tar header";

    /// Header field too long.
    pub ErrFieldTooLong: error = "archive/tar: header field too long";
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
    true
}

fn invertSparseEntries(src: &sparseDatas, size: i64) -> sparseHoles {
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
            dst = crate::append!(
                dst,
                sparseEntry {
                    Offset: pos,
                    Length: end - pos
                }
            );
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

    pub fn v7_name(&self) -> slice<byte> {
        self.slice(0, 100)
    }
    pub fn v7_mode(&self) -> slice<byte> {
        self.slice(100, 108)
    }
    pub fn v7_uid(&self) -> slice<byte> {
        self.slice(108, 116)
    }
    pub fn v7_gid(&self) -> slice<byte> {
        self.slice(116, 124)
    }
    pub fn v7_size(&self) -> slice<byte> {
        self.slice(124, 136)
    }
    pub fn v7_modTime(&self) -> slice<byte> {
        self.slice(136, 148)
    }
    pub fn v7_chksum(&self) -> slice<byte> {
        self.slice(148, 156)
    }
    pub fn v7_typeFlag(&self) -> slice<byte> {
        self.slice(156, 157)
    }
    pub fn v7_linkName(&self) -> slice<byte> {
        self.slice(157, 257)
    }

    pub fn ustar_magic(&self) -> slice<byte> {
        self.slice(257, 263)
    }
    pub fn ustar_version(&self) -> slice<byte> {
        self.slice(263, 265)
    }
    pub fn ustar_userName(&self) -> slice<byte> {
        self.slice(265, 297)
    }
    pub fn ustar_groupName(&self) -> slice<byte> {
        self.slice(297, 329)
    }
    pub fn ustar_devMajor(&self) -> slice<byte> {
        self.slice(329, 337)
    }
    pub fn ustar_devMinor(&self) -> slice<byte> {
        self.slice(337, 345)
    }
    pub fn ustar_prefix(&self) -> slice<byte> {
        self.slice(345, 500)
    }

    pub fn gnu_accessTime(&self) -> slice<byte> {
        self.slice(345, 357)
    }
    pub fn gnu_changeTime(&self) -> slice<byte> {
        self.slice(357, 369)
    }
    pub fn gnu_sparse(&self) -> slice<byte> {
        self.slice(386, 483)
    }
    pub fn gnu_realSize(&self) -> slice<byte> {
        self.slice(483, 495)
    }

    pub fn star_prefix(&self) -> slice<byte> {
        self.slice(345, 476)
    }
    pub fn star_accessTime(&self) -> slice<byte> {
        self.slice(476, 488)
    }
    pub fn star_changeTime(&self) -> slice<byte> {
        self.slice(488, 500)
    }
    pub fn star_trailer(&self) -> slice<byte> {
        self.slice(508, 512)
    }

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

    // ─── Write-side block mutation (writer.go templateV7Plus etc.) ──
    //
    // Go exposes `blk.toV7().name()` → a mutable `[]byte` view into the
    // block. goish models the field views as `&mut [u8]` ranges; the
    // formatter writes through them in place.

    /// `blk.reset()` — zero the whole block.
    pub fn reset(&mut self) {
        self.0 = [0; 512];
    }

    fn slice_mut(&mut self, start: usize, end: usize) -> &mut [u8] {
        &mut self.0[start..end]
    }

    pub fn v7m_name(&mut self) -> &mut [u8] {
        self.slice_mut(0, 100)
    }
    pub fn v7m_mode(&mut self) -> &mut [u8] {
        self.slice_mut(100, 108)
    }
    pub fn v7m_uid(&mut self) -> &mut [u8] {
        self.slice_mut(108, 116)
    }
    pub fn v7m_gid(&mut self) -> &mut [u8] {
        self.slice_mut(116, 124)
    }
    pub fn v7m_size(&mut self) -> &mut [u8] {
        self.slice_mut(124, 136)
    }
    pub fn v7m_modTime(&mut self) -> &mut [u8] {
        self.slice_mut(136, 148)
    }
    pub fn v7m_chksum(&mut self) -> &mut [u8] {
        self.slice_mut(148, 156)
    }
    pub fn v7m_typeFlag(&mut self) -> &mut [u8] {
        self.slice_mut(156, 157)
    }
    pub fn v7m_linkName(&mut self) -> &mut [u8] {
        self.slice_mut(157, 257)
    }

    pub fn ustarm_magic(&mut self) -> &mut [u8] {
        self.slice_mut(257, 263)
    }
    pub fn ustarm_version(&mut self) -> &mut [u8] {
        self.slice_mut(263, 265)
    }
    pub fn ustarm_userName(&mut self) -> &mut [u8] {
        self.slice_mut(265, 297)
    }
    pub fn ustarm_groupName(&mut self) -> &mut [u8] {
        self.slice_mut(297, 329)
    }
    pub fn ustarm_devMajor(&mut self) -> &mut [u8] {
        self.slice_mut(329, 337)
    }
    pub fn ustarm_devMinor(&mut self) -> &mut [u8] {
        self.slice_mut(337, 345)
    }
    pub fn ustarm_prefix(&mut self) -> &mut [u8] {
        self.slice_mut(345, 500)
    }

    pub fn gnum_accessTime(&mut self) -> &mut [u8] {
        self.slice_mut(345, 357)
    }
    pub fn gnum_changeTime(&mut self) -> &mut [u8] {
        self.slice_mut(357, 369)
    }
    pub fn gnum_magic(&mut self) -> &mut [u8] {
        self.slice_mut(257, 263)
    }
    pub fn gnum_version(&mut self) -> &mut [u8] {
        self.slice_mut(263, 265)
    }

    /// `blk.setFormat(f)` — stamp the magic+version for `f` (writer.go).
    pub fn setFormat(&mut self, f: Format) {
        // Set the magic values.
        if f.has(formatV7) {
            // do nothing
        } else if f.has(FormatGNU) {
            copyBytes(self.gnum_magic(), magicGNU.as_bytes());
            copyBytes(self.gnum_version(), versionGNU.as_bytes());
        } else if f.has(formatSTAR) {
            copyBytes(self.ustarm_magic(), magicUSTAR.as_bytes());
            copyBytes(self.ustarm_version(), versionUSTAR.as_bytes());
            copyBytes(self.slice_mut(508, 512), trailerSTAR.as_bytes());
        } else if f.has(FormatUSTAR | FormatPAX) {
            copyBytes(self.ustarm_magic(), magicUSTAR.as_bytes());
            copyBytes(self.ustarm_version(), versionUSTAR.as_bytes());
        } else {
            panic!("invalid format");
        }

        // Update the checksum.
        // This field is special in that it is terminated by a NUL then space.
        // Go formats into field[:7] (7 bytes), leaving field[7] for the trailing SPACE.
        // See: https://cs.opensource.google/go/go/+/refs/tags/go1.25.8:src/archive/tar/format.go;l=223
        //   f.formatOctal(field[:7], chksum) // Never fails since 128776 < 262143
        //   field[7] = ' '
        let (chksum, _) = self.computeChecksum();
        let mut f2 = formatter::new();
        {
            let chksum_field = self.v7m_chksum();
            f2.formatOctal(&mut chksum_field[..7], chksum);
        }
        self.0[155] = b' ';
    }
}

/// `copy(dst, src)` for raw byte ranges — returns the count copied.
fn copyBytes(dst: &mut [u8], src: &[u8]) -> usize {
    let n = core::cmp::min(dst.len(), src.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
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
                    // The PAX extended-header body is exactly `self.nb`
                    // bytes; bound the reader so parsePAX does not read
                    // past it into the next entry.
                    let body_len = self.nb;
                    let (ph, err) = {
                        let mut lr = crate::io::LimitReader(&mut *self.r, body_len as int);
                        parsePAX(&mut lr)
                    };
                    self.nb -= body_len; // body consumed
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
                    // The GNU long-name body is exactly `self.nb` bytes.
                    let body_len = self.nb;
                    let (realname, err) = {
                        let mut lr = crate::io::LimitReader(&mut *self.r, body_len as int);
                        readSpecialFile(&mut lr)
                    };
                    self.nb -= body_len;
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
            return ErrHeader.into();
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
            return (Header::new(), ErrHeader.into());
        }

        let format = self.blk.getFormat();
        if format == FormatUnknown {
            return (Header::new(), ErrHeader.into());
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
                if !(nul(&self.blk.v7_size())
                    && nul(&self.blk.v7_mode())
                    && nul(&self.blk.v7_uid())
                    && nul(&self.blk.v7_gid())
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
            return ErrHeader.into();
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
            return (map::new(), ErrHeader.into());
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
                return (map::new(), ErrHeader.into());
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
        return (string::new(), string::new(), s, ErrHeader.into());
    }
    let n_str = s.slice(0, space_idx);
    let rest = s.slice(space_idx + 1, s.Len());
    let (n, err) = strconv::ParseInt(n_str, 10, 0);
    if !err.IsNil() || n < 5 || n > s.Len() {
        return (string::new(), string::new(), s, ErrHeader.into());
    }
    let rec_len = n - (space_idx + 1);
    if rec_len <= 0 {
        return (string::new(), string::new(), s, ErrHeader.into());
    }
    let rec = rest.slice(0, rec_len - 1);
    let nl = rest.slice(rec_len - 1, rec_len);
    let rem = rest.slice(rec_len, rest.Len());
    if nl != "\n" {
        return (string::new(), string::new(), s, ErrHeader.into());
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
        return (string::new(), string::new(), s, ErrHeader.into());
    }
    let key = rec.slice(0, eq_idx);
    let val = rec.slice(eq_idx + 1, rec.Len());
    if !validPAXRecord(key.clone(), val.clone()) {
        return (string::new(), string::new(), s, ErrHeader.into());
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
    let ss = if parts.Len() > 0 {
        parts[0].clone()
    } else {
        string::new()
    };
    let has_dot = parts.Len() > 1;
    let mut sn = if has_dot {
        parts[1].clone()
    } else {
        string::new()
    };

    let ss_bytes = ss.as_bytes();
    let (secs, err) = strconv::ParseInt(&ss, 10, 64);
    if !err.IsNil() {
        return (crate::time::Unix(0, 0), ErrHeader.into());
    }
    if !has_dot {
        return (crate::time::Unix(secs, 0), nil);
    }

    let sn_bytes = sn.as_bytes();
    for &c in sn_bytes {
        if c < b'0' || c > b'9' {
            return (crate::time::Unix(0, 0), ErrHeader.into());
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
                    self.err = ErrHeader.into();
                    return 0;
                }
                x = (x << 8) | (c as u64);
            }
            if (x >> 63) > 0 {
                self.err = ErrHeader.into();
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
            self.err = ErrHeader.into();
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
        return (slice::new(), ErrFieldTooLong.into());
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

// ─────────────────────────────────────────────────────────────────────
//   Writer — port of Go 1.25 archive/tar writer.go + write-side
//   strconv.go + common.go (allowedFormats / FileInfoHeader / FileInfo).
// ─────────────────────────────────────────────────────────────────────

use crate::io::fs;
use alloc::sync::Arc;

// ─── zeroBlock ───────────────────────────────────────────────────────

/// 512 zero bytes — used for padding and the two-block trailer.
const zeroBlock: [byte; 512] = [0; 512];

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
        prefix + ": " + joined
    }
}

fn headerErr(msgs: Vec<string>) -> error {
    crate::errors::Wrap(headerError {
        msgs: slice::__from_vec(msgs),
    })
}

// ─── toASCII / hasNUL (strconv.go) ───────────────────────────────────

fn hasNUL(s: &string) -> bool {
    strings::Contains(s.clone(), "\x00")
}

/// `toASCII` — best-effort conversion to an ASCII C-style string.
fn toASCII(s: &string) -> string {
    if isASCII(s) {
        return s.clone();
    }
    let mut b: Vec<u8> = Vec::with_capacity(s.Len() as usize);
    for &c in s.as_bytes() {
        if c < 0x80 && c != 0x00 {
            b.push(c);
        }
    }
    string::from_bytes(&b)
}

// ─── formatter — write-side numeric/string encoders (strconv.go) ─────

struct formatter {
    err: error,
}

impl formatter {
    fn new() -> Self {
        Self { err: nil }
    }

    /// `formatString` — copy `s` into `b`, NUL-terminating if possible.
    fn formatString(&mut self, b: &mut [u8], s: &string) {
        let sb = s.as_bytes();
        if sb.len() > b.len() {
            self.err = ErrFieldTooLong.into();
        }
        copyBytes(b, sb);
        if sb.len() < b.len() {
            b[sb.len()] = 0;
        }
        // Buggy-reader workaround: a regular file with a trailing slash
        // in the V7 path field looks like a directory.
        if sb.len() > b.len() && b[b.len() - 1] == b'/' {
            let blen = b.len();
            let trimmed = strings::TrimRight(string::from_bytes(&sb[..blen - 1]), "/");
            let n = trimmed.Len() as usize;
            b[n] = 0;
        }
    }

    /// `formatNumeric` — octal if it fits, else base-256 binary.
    fn formatNumeric(&mut self, b: &mut [u8], mut x: i64) {
        if fitsInOctal(b.len() as int, x) {
            self.formatOctal(b, x);
            return;
        }
        if fitsInBase256(b.len() as int, x) {
            let mut i = b.len();
            while i > 0 {
                i -= 1;
                b[i] = (x & 0xff) as u8;
                x >>= 8;
            }
            b[0] |= 0x80; // Highest bit indicates binary format
            return;
        }
        self.formatOctal(b, 0); // Last resort
        self.err = ErrFieldTooLong.into();
    }

    /// `formatOctal` — base-8 with leading zeros and a NUL terminator.
    fn formatOctal(&mut self, b: &mut [u8], mut x: i64) {
        if !fitsInOctal(b.len() as int, x) {
            x = 0;
            self.err = ErrFieldTooLong.into();
        }
        let mut s = strconv::FormatInt(x, 8);
        // Add leading zeros, but leave room for a NUL.
        let n = (b.len() as int) - (s.Len() as int) - 1;
        if n > 0 {
            s = strings::Repeat("0", n) + s;
        }
        self.formatString(b, &s);
    }
}

/// `fitsInBase256` — reports whether `x` fits in `n` base-256 bytes.
fn fitsInBase256(n: int, x: i64) -> bool {
    let bin_bits: u32 = ((n - 1) as u32) * 8;
    n >= 9 || (x >= -(1_i64 << bin_bits) && x < (1_i64 << bin_bits))
}

/// `fitsInOctal` — reports whether `x` fits in `n` octal bytes.
fn fitsInOctal(n: int, x: i64) -> bool {
    let oct_bits: u32 = ((n - 1) as u32) * 3;
    x >= 0 && (n >= 22 || x < (1_i64 << oct_bits))
}

/// `formatPAXTime` — convert `ts` into a `%d.%d` PAX time string.
fn formatPAXTime(ts: Time) -> string {
    let secs = ts.Unix();
    let nsecs = ts.Nanosecond();
    if nsecs == 0 {
        return strconv::FormatInt(secs, 10);
    }
    let mut sign = string::new();
    let mut secs = secs;
    let mut nsecs = nsecs;
    if secs < 0 {
        sign = crate::string("-");
        secs = -(secs + 1);
        nsecs = -(nsecs - 1_000_000_000);
    }
    // "%s%d.%09d" then strip trailing zeros.
    let mut ns = strconv::FormatInt(nsecs, 10);
    while (ns.Len() as int) < 9 {
        ns = crate::string("0") + ns;
    }
    let composed = sign + strconv::FormatInt(secs, 10) + "." + ns;
    strings::TrimRight(composed, "0")
}

/// `formatPAXRecord` — format one PAX record with its length prefix.
fn formatPAXRecord(k: &string, v: &string) -> (string, error) {
    if !validPAXRecord(k.clone(), v.clone()) {
        return (string::new(), ErrHeader.into());
    }
    const padding: int = 3; // ' ', '=', '\n'
    let mut size = (k.Len() as int) + (v.Len() as int) + padding;
    size += strconv::Itoa(size).Len() as int;
    let build =
        |sz: int| -> string { strconv::Itoa(sz) + " " + k.clone() + "=" + v.clone() + "\n" };
    let mut record = build(size);
    // Final adjustment if the size field grew the record.
    if (record.Len() as int) != size {
        size = record.Len() as int;
        record = build(size);
    }
    (record, nil)
}

// ─── allowedFormats (common.go:344) ──────────────────────────────────

impl Header {
    /// `h.allowedFormats()` — determine which formats can encode this
    /// Header. Returns `(format, paxHdrs, err)`. `format == FormatUnknown`
    /// means the Header cannot be encoded; `err` explains why.
    fn allowedFormats(&self) -> (Format, map<string, string>, error) {
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
            let too_long = (s.Len() as int) > size;
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
            self.Uid as i64,
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
            self.Gid as i64,
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
        (format, paxHdrs, err)
    }
}

/// `basicKeys[k]` — the PAX keys with built-in Header support.
fn basicKey(k: &string) -> bool {
    let kb = k.as_bytes();
    kb == paxPath.as_bytes()
        || kb == paxLinkpath.as_bytes()
        || kb == paxSize.as_bytes()
        || kb == paxUid.as_bytes()
        || kb == paxGid.as_bytes()
        || kb == paxUname.as_bytes()
        || kb == paxGname.as_bytes()
        || kb == paxMtime.as_bytes()
        || kb == paxAtime.as_bytes()
        || kb == paxCtime.as_bytes()
}

// ─── splitUSTARPath (writer.go:454) ──────────────────────────────────

/// `splitUSTARPath` — split a path into USTAR prefix/suffix; returns
/// `("", "", false)` if not splittable.
fn splitUSTARPath(name: &string) -> (string, string, bool) {
    let mut length = name.Len() as int;
    if length <= nameSize || !isASCII(name) {
        return (string::new(), string::new(), false);
    } else if length > prefixSize + 1 {
        length = prefixSize + 1;
    } else if name.as_bytes()[(length - 1) as usize] == b'/' {
        length -= 1;
    }
    let head = name.slice(0, length);
    let i = strings::LastIndex(head, "/");
    let nlen = (name.Len() as int) - i - 1; // length of suffix
    let plen = i; // length of prefix
    if i <= 0 || nlen > nameSize || nlen == 0 || plen > prefixSize {
        return (string::new(), string::new(), false);
    }
    (name.slice(0, i), name.slice(i + 1, name.Len() as int), true)
}

// ─── regFileWriter (writer.go:535) ───────────────────────────────────

/// `regFileWriter` — writes data to a regular file entry. Tracks the
/// number of bytes still owed.
struct regFileWriter {
    nb: i64, // remaining bytes to write
}

impl regFileWriter {
    fn logicalRemaining(&self) -> i64 {
        self.nb
    }
    fn physicalRemaining(&self) -> i64 {
        self.nb
    }
    /// `Write` against the underlying writer `w`.
    fn write(&mut self, w: &mut dyn crate::io::Writer, b: &[u8]) -> (int, error) {
        let overwrite = (b.len() as i64) > self.nb;
        let bb: &[u8] = if overwrite { &b[..self.nb as usize] } else { b };
        let mut n: int = 0;
        let mut err: error = nil;
        if !bb.is_empty() {
            let (nn, e) = w.Write(slice::__from_vec(bb.to_vec()));
            n = nn;
            err = e;
            self.nb -= n as i64;
        }
        if !err.IsNil() {
            (n, err)
        } else if overwrite {
            (n, ErrWriteTooLong.into())
        } else {
            (n, nil)
        }
    }
}

// ─── Writer (writer.go:22) ───────────────────────────────────────────

/// `Writer` provides sequential writing of a tar archive.
///
/// [`Writer::WriteHeader`] begins a new file with the provided
/// [`Header`], after which the file data is supplied via [`Writer::Write`].
pub struct Writer<W: crate::io::Writer> {
    w: W,
    pad: i64,            // padding to write after the current entry
    curr: regFileWriter, // writer state for the current file entry
    hdr: Header,         // safe-to-mutate shallow copy of the Header
    blk: block,          // temporary local storage
    err: error,          // sticky persistent error
}

/// `NewWriter` creates a new [`Writer`] writing to `w`.
pub fn NewWriter<W: crate::io::Writer>(w: W) -> Writer<W> {
    Writer {
        w,
        pad: 0,
        curr: regFileWriter { nb: 0 },
        hdr: Header::new(),
        blk: block::new(),
        err: nil,
    }
}

impl<W: crate::io::Writer> Writer<W> {
    /// `Flush` finishes writing the current file's block padding.
    ///
    /// Unnecessary in normal use — the next [`Writer::WriteHeader`] or
    /// [`Writer::Close`] flushes the padding implicitly.
    pub fn Flush(&mut self) -> error {
        if !self.err.IsNil() {
            return self.err.clone();
        }
        let nb = self.curr.logicalRemaining();
        if nb > 0 {
            return crate::errors::New(
                crate::string("archive/tar: missed writing ")
                    + strconv::FormatInt(nb, 10)
                    + " bytes",
            );
        }
        let pad = self.pad as usize;
        let (_, e) = self.w.Write(slice::__from_vec(zeroBlock[..pad].to_vec()));
        if !e.IsNil() {
            self.err = e.clone();
            return self.err.clone();
        }
        self.pad = 0;
        nil
    }

    /// `WriteHeader` writes `hdr` and prepares to accept the file's
    /// contents. `Header.Size` bounds how many bytes may follow.
    pub fn WriteHeader(&mut self, hdr: &Header) -> error {
        let e = self.Flush();
        if !e.IsNil() {
            return e;
        }
        self.hdr = hdr.clone(); // shallow copy

        // Promote the legacy TypeRegA flag.
        if self.hdr.Typeflag == TypeRegA {
            if strings::HasSuffix(self.hdr.Name.clone(), "/") {
                self.hdr.Typeflag = TypeDir;
            } else {
                self.hdr.Typeflag = TypeReg;
            }
        }

        // Round ModTime and drop sub-second times when format is unset.
        if self.hdr.Format == FormatUnknown {
            self.hdr.ModTime = roundToSecond(self.hdr.ModTime);
            self.hdr.AccessTime = crate::time::Unix(0, 0);
            self.hdr.ChangeTime = crate::time::Unix(0, 0);
        }

        let (allowed_formats, pax_hdrs, err) = self.hdr.allowedFormats();
        if allowed_formats.has(FormatUSTAR) {
            let h = self.hdr.clone();
            self.err = self.writeUSTARHeader(&h);
            self.err.clone()
        } else if allowed_formats.has(FormatPAX) {
            let h = self.hdr.clone();
            self.err = self.writePAXHeader(&h, &pax_hdrs);
            self.err.clone()
        } else if allowed_formats.has(FormatGNU) {
            let h = self.hdr.clone();
            self.err = self.writeGNUHeader(&h);
            self.err.clone()
        } else {
            err // Non-fatal error
        }
    }

    fn writeUSTARHeader(&mut self, hdr: &Header) -> error {
        let mut hdr = hdr.clone();
        // USTAR prefix/suffix splitting.
        let mut namePrefix = string::new();
        let (prefix, suffix, ok) = splitUSTARPath(&hdr.Name);
        if ok {
            namePrefix = prefix;
            hdr.Name = suffix;
        }

        let mut f = formatter::new();
        self.templateV7Plus(&hdr, true, &mut f);
        f.formatString(self.blk.ustarm_prefix(), &namePrefix);
        self.blk.setFormat(FormatUSTAR);
        if !f.err.IsNil() {
            return f.err;
        }
        self.writeRawHeaderInternal(hdr.Size, hdr.Typeflag)
    }

    fn writePAXHeader(&mut self, hdr: &Header, paxHdrs: &map<string, string>) -> error {
        let realName = hdr.Name.clone();

        // Write PAX records to the output.
        let isGlobal = hdr.Typeflag == TypeXGlobalHeader;
        if paxHdrs.Len() > 0 || isGlobal {
            // Sort keys for deterministic ordering.
            let mut keys: Vec<string> = Vec::new();
            for (k, _) in crate::range!(paxHdrs) {
                keys.push(k.clone());
            }
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

            let mut buf: Vec<u8> = Vec::new();
            for k in keys.iter() {
                let (v, _) = paxHdrs.Get(k.clone());
                let (rec, e) = formatPAXRecord(k, &v);
                if !e.IsNil() {
                    return e;
                }
                buf.extend_from_slice(rec.as_bytes());
            }

            let mut name: string;
            let flag: byte;
            if isGlobal {
                name = realName.clone();
                if name.Len() == 0 {
                    name = crate::string("GlobalHead.0.0");
                }
                flag = TypeXGlobalHeader;
            } else {
                let (dir, file) = crate::path::Split(realName.clone());
                name = crate::path::Join(slice::__from_vec(alloc::vec![
                    dir,
                    crate::string("PaxHeaders.0"),
                    file
                ]));
                flag = TypeXHeader;
            }
            if buf.len() > maxSpecialFileSize as usize {
                return ErrFieldTooLong.into();
            }
            let data = string::from_bytes(&buf);
            let e = self.writeRawFile(&name, &data, flag, FormatPAX);
            if !e.IsNil() || isGlobal {
                return e; // Global headers return here
            }
        }

        // Pack the main header. Strings are coerced to ASCII.
        let mut f = formatter::new();
        self.templateV7PlusPAX(hdr, &mut f);
        self.blk.setFormat(FormatPAX);
        self.writeRawHeaderInternal(hdr.Size, hdr.Typeflag)
    }

    fn writeGNUHeader(&mut self, hdr: &Header) -> error {
        const longName: &str = "././@LongLink";
        if (hdr.Name.Len() as int) > nameSize {
            let data = hdr.Name.clone() + "\x00";
            let e = self.writeRawFile(&crate::string(longName), &data, TypeGNULongName, FormatGNU);
            if !e.IsNil() {
                return e;
            }
        }
        if (hdr.Linkname.Len() as int) > nameSize {
            let data = hdr.Linkname.clone() + "\x00";
            let e = self.writeRawFile(&crate::string(longName), &data, TypeGNULongLink, FormatGNU);
            if !e.IsNil() {
                return e;
            }
        }

        let mut f = formatter::new();
        self.templateV7PlusGNU(hdr, &mut f);
        if !hdr.AccessTime.IsZero() {
            f.formatNumeric(self.blk.gnum_accessTime(), hdr.AccessTime.Unix());
        }
        if !hdr.ChangeTime.IsZero() {
            f.formatNumeric(self.blk.gnum_changeTime(), hdr.ChangeTime.Unix());
        }
        self.blk.setFormat(FormatGNU);
        self.writeRawHeaderInternal(hdr.Size, hdr.Typeflag)
    }

    /// `templateV7Plus` — fill V7 fields + shared USTAR fields with
    /// string formatter / octal formatter.
    fn templateV7Plus(&mut self, hdr: &Header, _ascii: bool, f: &mut formatter) {
        self.blk.reset();
        let mut modTime = hdr.ModTime;
        if modTime.IsZero() {
            modTime = crate::time::Unix(0, 0);
        }
        self.blk.v7m_typeFlag()[0] = hdr.Typeflag;
        f.formatString(self.blk.v7m_name(), &hdr.Name);
        f.formatString(self.blk.v7m_linkName(), &hdr.Linkname);
        f.formatOctal(self.blk.v7m_mode(), hdr.Mode);
        f.formatOctal(self.blk.v7m_uid(), hdr.Uid as i64);
        f.formatOctal(self.blk.v7m_gid(), hdr.Gid as i64);
        f.formatOctal(self.blk.v7m_size(), hdr.Size);
        f.formatOctal(self.blk.v7m_modTime(), modTime.Unix());
        f.formatString(self.blk.ustarm_userName(), &hdr.Uname);
        f.formatString(self.blk.ustarm_groupName(), &hdr.Gname);
        f.formatOctal(self.blk.ustarm_devMajor(), hdr.Devmajor);
        f.formatOctal(self.blk.ustarm_devMinor(), hdr.Devminor);
    }

    /// `templateV7Plus` variant — PAX uses `toASCII` for strings.
    fn templateV7PlusPAX(&mut self, hdr: &Header, f: &mut formatter) {
        self.blk.reset();
        let mut modTime = hdr.ModTime;
        if modTime.IsZero() {
            modTime = crate::time::Unix(0, 0);
        }
        self.blk.v7m_typeFlag()[0] = hdr.Typeflag;
        f.formatString(self.blk.v7m_name(), &toASCII(&hdr.Name));
        f.formatString(self.blk.v7m_linkName(), &toASCII(&hdr.Linkname));
        f.formatOctal(self.blk.v7m_mode(), hdr.Mode);
        f.formatOctal(self.blk.v7m_uid(), hdr.Uid as i64);
        f.formatOctal(self.blk.v7m_gid(), hdr.Gid as i64);
        f.formatOctal(self.blk.v7m_size(), hdr.Size);
        f.formatOctal(self.blk.v7m_modTime(), modTime.Unix());
        f.formatString(self.blk.ustarm_userName(), &toASCII(&hdr.Uname));
        f.formatString(self.blk.ustarm_groupName(), &toASCII(&hdr.Gname));
        f.formatOctal(self.blk.ustarm_devMajor(), hdr.Devmajor);
        f.formatOctal(self.blk.ustarm_devMinor(), hdr.Devminor);
    }

    /// `templateV7Plus` variant — GNU uses numeric (base-256) formatting.
    fn templateV7PlusGNU(&mut self, hdr: &Header, f: &mut formatter) {
        self.blk.reset();
        let mut modTime = hdr.ModTime;
        if modTime.IsZero() {
            modTime = crate::time::Unix(0, 0);
        }
        self.blk.v7m_typeFlag()[0] = hdr.Typeflag;
        f.formatString(self.blk.v7m_name(), &hdr.Name);
        f.formatString(self.blk.v7m_linkName(), &hdr.Linkname);
        f.formatNumeric(self.blk.v7m_mode(), hdr.Mode);
        f.formatNumeric(self.blk.v7m_uid(), hdr.Uid as i64);
        f.formatNumeric(self.blk.v7m_gid(), hdr.Gid as i64);
        f.formatNumeric(self.blk.v7m_size(), hdr.Size);
        f.formatNumeric(self.blk.v7m_modTime(), modTime.Unix());
        f.formatString(self.blk.ustarm_userName(), &hdr.Uname);
        f.formatString(self.blk.ustarm_groupName(), &hdr.Gname);
        f.formatNumeric(self.blk.ustarm_devMajor(), hdr.Devmajor);
        f.formatNumeric(self.blk.ustarm_devMinor(), hdr.Devminor);
    }

    /// `writeRawFile` — writes a minimal file (used for PAX/GNU meta).
    fn writeRawFile(&mut self, name: &string, data: &string, flag: byte, format: Format) -> error {
        self.blk.reset();

        // Best effort for the filename.
        let mut nm = toASCII(name);
        if (nm.Len() as int) > nameSize {
            nm = nm.slice(0, nameSize);
        }
        nm = strings::TrimRight(nm, "/");

        let mut f = formatter::new();
        self.blk.v7m_typeFlag()[0] = flag;
        f.formatString(self.blk.v7m_name(), &nm);
        f.formatOctal(self.blk.v7m_mode(), 0);
        f.formatOctal(self.blk.v7m_uid(), 0);
        f.formatOctal(self.blk.v7m_gid(), 0);
        f.formatOctal(self.blk.v7m_size(), data.Len() as i64);
        f.formatOctal(self.blk.v7m_modTime(), 0);
        self.blk.setFormat(format);
        if !f.err.IsNil() {
            return f.err;
        }

        // Write the header and data.
        let e = self.writeRawHeaderInternal(data.Len() as i64, flag);
        if !e.IsNil() {
            return e;
        }
        let (_, we) = self.Write(slice::__from_vec(data.as_bytes().to_vec()));
        we
    }

    /// `writeRawHeader` — writes `self.blk` verbatim and sets up the
    /// Writer to accept a `size`-byte body.
    fn writeRawHeaderInternal(&mut self, mut size: i64, flag: byte) -> error {
        let e = self.Flush();
        if !e.IsNil() {
            return e;
        }
        let (_, we) = self.w.Write(slice::__from_vec(self.blk.0.to_vec()));
        if !we.IsNil() {
            return we;
        }
        if isHeaderOnlyType(flag) {
            size = 0;
        }
        self.curr = regFileWriter { nb: size };
        self.pad = blockPadding(size);
        nil
    }

    /// `Write` writes to the current file in the tar archive. Returns
    /// [`ErrWriteTooLong`] if more than `Header.Size` bytes are written.
    pub fn Write(&mut self, b: slice<byte>) -> (int, error) {
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }
        let bytes: Vec<u8> = b.to_vec();
        let (n, err) = self.curr.write(&mut self.w, &bytes);
        if !err.IsNil() && err != ErrWriteTooLong {
            self.err = err.clone();
        }
        (n, err)
    }

    /// `Close` flushes padding, writes the two-block trailer, and marks
    /// the archive done. Errors on an unfinished current file.
    pub fn Close(&mut self) -> error {
        if self.err == ErrWriteAfterClose {
            return nil;
        }
        if !self.err.IsNil() {
            return self.err.clone();
        }
        // Trailer: two zero blocks.
        let mut err = self.Flush();
        let mut i = 0;
        while i < 2 && err.IsNil() {
            let (_, e) = self.w.Write(slice::__from_vec(zeroBlock.to_vec()));
            err = e;
            i += 1;
        }
        self.err = ErrWriteAfterClose.into();
        err
    }

    /// Consume the Writer, returning the underlying `io.Writer` (so the
    /// finished archive bytes can be drained — used in tests).
    pub fn into_writer(self) -> W {
        self.w
    }

    /// `AddFS` adds the files from `fsys` to the archive, walking the
    /// directory tree from the filesystem root.
    pub fn AddFS(&mut self, fsys: &(dyn fs::FS + Send + Sync + 'static)) -> error {
        // A SpinLock lets the WalkDir closure mutate `self` through a
        // shared borrow (the closure is `Fn`, not `FnMut`).
        let this: &crate::runtime::spin::SpinLock<&mut Writer<W>> =
            &crate::runtime::spin::SpinLock::new(self);
        let walk_err: crate::runtime::spin::SpinLock<error> =
            crate::runtime::spin::SpinLock::new(nil);
        let walk_err_ref = &walk_err;
        let e = fs::WalkDir(fsys, ".", move |name, d, err| {
            if !err.IsNil() {
                return err;
            }
            if name == "." {
                return nil;
            }
            let (info, ierr) = d.Info();
            if !ierr.IsNil() {
                return ierr;
            }
            let typ = d.Type();
            let mut linkTarget = string::new();
            if typ == fs::ModeSymlink {
                // io/fs.ReadLink not wired here; symlinks unsupported.
                return crate::errors::New("tar: cannot add symlink");
            } else if !typ.IsRegular() && typ != fs::ModeDir {
                return crate::errors::New("tar: cannot add non-regular file");
            }
            let (h, herr) = FileInfoHeader(&*info, &linkTarget);
            if !herr.IsNil() {
                return herr;
            }
            let mut h = h;
            h.Name = name.clone();
            if d.IsDir() {
                h.Name = h.Name + "/";
            }
            let _ = &mut linkTarget;
            {
                let mut g = this.lock();
                let we = g.WriteHeader(&h);
                if !we.IsNil() {
                    *walk_err_ref.lock() = we.clone();
                    return we;
                }
            }
            if !d.Type().IsRegular() {
                return nil;
            }
            // Copy file content.
            let (file, oerr) = fsys.Open(name.clone());
            if !oerr.IsNil() {
                return oerr;
            }
            let mut buf = crate::make!([]byte, 32 * 1024);
            loop {
                let (n, rerr) = file.Read(&mut buf);
                if n > 0 {
                    let mut g = this.lock();
                    let (_, we) = g.Write(buf.slice(0, n));
                    if !we.IsNil() {
                        let _ = file.Close();
                        *walk_err_ref.lock() = we.clone();
                        return we;
                    }
                }
                if !rerr.IsNil() {
                    let _ = file.Close();
                    if rerr == crate::io::EOF {
                        return nil;
                    }
                    return rerr;
                }
            }
        });
        if !e.IsNil() {
            return e;
        }
        walk_err.into_inner()
    }
}

/// Round a `Time` to the nearest second (Go: `ModTime.Round(time.Second)`).
fn roundToSecond(t: Time) -> Time {
    let ns = t.Nanosecond();
    if ns == 0 {
        return t;
    }
    let mut secs = t.Unix();
    // Round half-up.
    if ns >= 500_000_000 {
        secs += 1;
    }
    crate::time::Unix(secs, 0)
}

// ─── FileInfoHeader / FileInfo (common.go:540 / 648) ─────────────────

// Mode constants from the USTAR spec (common.go:619).
const c_ISUID: i64 = 0o4000;
const c_ISGID: i64 = 0o2000;
const c_ISVTX: i64 = 0o1000;

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
    h.Mode = fm.Perm().Bits() as i64;

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
    (h, nil)
}

// ─── headerFileInfo — Header.FileInfo (common.go:540) ────────────────

/// `headerFileInfo` implements [`fs::FileInfo`] over a [`Header`].
struct headerFileInfo {
    h: Header,
}

impl fs::FileInfo for headerFileInfo {
    fn Name(&self) -> string {
        if self.IsDir() {
            return crate::path::Base(crate::path::Clean(self.h.Name.clone()));
        }
        crate::path::Base(self.h.Name.clone())
    }
    fn Size(&self) -> i64 {
        self.h.Size
    }
    fn ModTime(&self) -> Time {
        self.h.ModTime
    }
    fn IsDir(&self) -> bool {
        self.Mode().IsDir()
    }
    fn Sys(&self) -> Arc<dyn core::any::Any + Send + Sync> {
        Arc::new(())
    }
    fn Mode(&self) -> fs::FileMode {
        let mut mode = fs::FileMode((self.h.Mode as u32) & 0o777);
        if self.h.Mode & c_ISUID != 0 {
            mode = mode | fs::ModeSetuid;
        }
        if self.h.Mode & c_ISGID != 0 {
            mode = mode | fs::ModeSetgid;
        }
        if self.h.Mode & c_ISVTX != 0 {
            mode = mode | fs::ModeSticky;
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
        mode
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl Header {
    /// `h.FileInfo()` — an [`fs::FileInfo`] describing the Header.
    pub fn FileInfo(&self) -> Arc<dyn fs::FileInfo + Send + Sync> {
        Arc::new(headerFileInfo { h: self.clone() })
    }
}
