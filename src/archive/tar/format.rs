// go: file archive/tar/format.go decls: Format.has, Format.mayBe, Format.mayOnlyBe, Format.mustNotBe, Format.String, formatNames, headerV7.name, headerV7.mode, headerV7.uid, headerV7.gid, headerV7.size, headerV7.modTime, headerV7.chksum, headerV7.typeFlag, headerV7.linkName, headerUSTAR.magic, headerUSTAR.version, headerUSTAR.userName, headerUSTAR.groupName, headerUSTAR.devMajor, headerUSTAR.devMinor, headerUSTAR.prefix, headerGNU.accessTime, headerGNU.changeTime, headerGNU.sparse, headerGNU.realSize, headerSTAR.prefix, headerSTAR.accessTime, headerSTAR.changeTime, headerSTAR.trailer, block.computeChecksum, block.getFormat, block.reset, headerGNU.magic, headerGNU.version, block.setFormat, blockPadding
//
// format.go — Format, the on-disk `block` and its four views.
//
// goishlint:ignore GOISH018 toV7, toGNU, toSTAR, toUSTAR, toSparse, v7 - Go reaches a view of a block by casting the pointer, `(*headerV7)(b)`, and these five are that cast. Rust will not reinterpret one array type as another, so the four views are flattened onto `block` itself with a prefix per view and there is no cast to port. Every field the views expose is anchored individually to its Go accessor.
// goishlint:ignore GOISH021 — file-wide, and only because one of the
// findings cannot be named: goishlint reads `magicGNU, versionGNU =
// "ustar ", " \\x00"` (format.go:136-137) as a constant called `,`,
// and a waiver list is comma-separated. Those four constants ARE
// ported, right below. The rest of what this waives:
// headerV7/headerGNU/headerSTAR/headerUSTAR exist in Go only as cast
// targets (see the GOISH018 waiver above) and are flattened into
// `block`; formatNames is spelled as the lookup function formatName;
// sparseArray and sparseElem belong to the sparse-file half, which
// this port stubs — a sparse header returns ErrHeader.
// goishlint:ignore GOISH018 entry, isExtended, maxEntries, offset, length - sparseArray/sparseElem accessors; see GOISH021 above.
// goishlint:ignore GOISH020 String - Go's `String()` satisfies fmt.Stringer structurally and takes only the receiver; the Rust equivalent is `Display::fmt`, which takes the receiver and a Formatter.

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{int64 as toint64, int8 as toint8};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strings;
use crate::types::{byte, int};

use super::*;

// ─── Constants ───────────────────────────────────────────────────────

const blockSize: int = 512;
pub(crate) const nameSize: int = 100;
pub(crate) const prefixSize: int = 155;
pub(crate) const maxSpecialFileSize: int = 1 << 20;

const magicGNU: &str = "ustar ";
const versionGNU: &str = " \x00";
const magicUSTAR: &str = "ustar\x00";
const versionUSTAR: &str = "00";
const trailerSTAR: &str = "tar\x00";

// ─── Format ──────────────────────────────────────────────────────────

/// Tar archive format identifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Format(pub(crate) int);

impl Format {
    // go: sdk 1.25.5 archive/tar/format.go:108-108 Format.has
    pub fn has(self, f: Format) -> bool {
        return (self.0 & f.0) != 0;
    }
    // go: sdk 1.25.5 archive/tar/format.go:109-109 Format.mayBe
    pub fn mayBe(&mut self, f: Format) {
        self.0 |= f.0;
    }
    // go: sdk 1.25.5 archive/tar/format.go:110-110 Format.mayOnlyBe
    pub fn mayOnlyBe(&mut self, f: Format) {
        self.0 &= f.0;
    }
    // go: sdk 1.25.5 archive/tar/format.go:111-111 Format.mustNotBe
    pub fn mustNotBe(&mut self, f: Format) {
        self.0 &= !f.0;
    }
}

impl core::ops::BitOr for Format {
    type Output = Self;
    // go: none — goish idiom: Go's `Format` is a defined `int`, so `|`,
    //     `&` and `^x` come with the type. Rust gives a newtype none of
    //     them, so each is written out.
    fn bitor(self, rhs: Self) -> Self {
        return Format(self.0 | rhs.0);
    }
}

impl core::ops::BitAnd for Format {
    type Output = Self;
    // go: none — goish idiom: Go's `Format` is a defined `int`, so `|`,
    //     `&` and `^x` come with the type. Rust gives a newtype none of
    //     them, so each is written out.
    fn bitand(self, rhs: Self) -> Self {
        return Format(self.0 & rhs.0);
    }
}

impl core::ops::Not for Format {
    type Output = Self;
    // go: none — goish idiom: Go's `Format` is a defined `int`, so `|`,
    //     `&` and `^x` come with the type. Rust gives a newtype none of
    //     them, so each is written out.
    fn not(self) -> Self {
        return Format(!self.0);
    }
}

impl core::fmt::Display for Format {
    // go: sdk 1.25.5 archive/tar/format.go:117-132 Format.String
    // goishlint:ignore GOISH014 - the anchor names the GO symbol. Go's
    //     `String()` satisfies `fmt.Stringer` structurally; the Rust
    //     equivalent is `Display::fmt`, which cannot be called `String`.
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
        return match parts.len() {
            0 => write!(f, "<unknown>"),
            1 => write!(f, "{}", parts[0]),
            _ => {
                let joined = strings::Join(slice::__from_vec(parts), " | ");
                write!(f, "({})", joined)
            }
        };
    }
}

// go: sdk 1.25.5 archive/tar/format.go:113-116 formatNames
// goishlint:ignore GOISH014 - the anchor names the GO symbol. Go's
//     `formatNames` is a `map[Format]string` indexed by `String()`;
//     goish spells the same table as a lookup function, `formatName`.
fn formatName(f: Format) -> Option<string> {
    return if f == formatV7 {
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
    };
}

pub(crate) const formatV7: Format = Format(1 << 0);
pub const FormatUnknown: Format = Format(1 << 1);
pub const FormatUSTAR: Format = Format(1 << 2);
pub const FormatPAX: Format = Format(1 << 3);
pub const FormatGNU: Format = Format(1 << 4);
pub(crate) const formatSTAR: Format = Format(1 << 5);
const formatMax: Format = Format(1 << 6);

// ─── block ──────────────────────────────────────────────────────────

/// A tar header block (512 bytes).
pub struct block(pub(crate) [byte; 512]);

impl block {
    // go: none — goish idiom: Go's `var b block` is 512 usable zero
    //     bytes. Rust needs the constructor spelled.
    pub fn new() -> Self {
        return Self([0; 512]);
    }

    // go: none — goish idiom: Go writes `bytes.Equal(b[:], zeroBlock[:])`
    //     at the two call sites in reader.go. Named once here.
    pub fn isZero(&self) -> bool {
        for i in 0..512usize {
            if self.0[i] != 0 {
                return false;
            }
        }
        return true;
    }

    // go: none — goish idiom: Go reaches into a block by casting the
    //     pointer — `(*headerV7)(b)` — and then slicing the result,
    //     `h[100:][:8]`. Rust will not reinterpret one array type as
    //     another, so every view accessor goes through this one
    //     bounds-checked window instead.
    fn slice(&self, start: int, end: int) -> slice<byte> {
        return slice::__from_vec(self.0[start as usize..end as usize].to_vec());
    }

    // go: sdk 1.25.5 archive/tar/format.go:249-249 headerV7.name
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn v7_name(&self) -> slice<byte> {
        return self.slice(0, 100);
    }
    // go: sdk 1.25.5 archive/tar/format.go:250-250 headerV7.mode
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn v7_mode(&self) -> slice<byte> {
        return self.slice(100, 108);
    }
    // go: sdk 1.25.5 archive/tar/format.go:251-251 headerV7.uid
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn v7_uid(&self) -> slice<byte> {
        return self.slice(108, 116);
    }
    // go: sdk 1.25.5 archive/tar/format.go:252-252 headerV7.gid
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn v7_gid(&self) -> slice<byte> {
        return self.slice(116, 124);
    }
    // go: sdk 1.25.5 archive/tar/format.go:253-253 headerV7.size
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn v7_size(&self) -> slice<byte> {
        return self.slice(124, 136);
    }
    // go: sdk 1.25.5 archive/tar/format.go:254-254 headerV7.modTime
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn v7_modTime(&self) -> slice<byte> {
        return self.slice(136, 148);
    }
    // go: sdk 1.25.5 archive/tar/format.go:255-255 headerV7.chksum
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn v7_chksum(&self) -> slice<byte> {
        return self.slice(148, 156);
    }
    // go: sdk 1.25.5 archive/tar/format.go:256-256 headerV7.typeFlag
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn v7_typeFlag(&self) -> slice<byte> {
        return self.slice(156, 157);
    }
    // go: sdk 1.25.5 archive/tar/format.go:257-257 headerV7.linkName
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn v7_linkName(&self) -> slice<byte> {
        return self.slice(157, 257);
    }

    // go: sdk 1.25.5 archive/tar/format.go:290-290 headerUSTAR.magic
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn ustar_magic(&self) -> slice<byte> {
        return self.slice(257, 263);
    }
    // go: sdk 1.25.5 archive/tar/format.go:291-291 headerUSTAR.version
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn ustar_version(&self) -> slice<byte> {
        return self.slice(263, 265);
    }
    // go: sdk 1.25.5 archive/tar/format.go:292-292 headerUSTAR.userName
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn ustar_userName(&self) -> slice<byte> {
        return self.slice(265, 297);
    }
    // go: sdk 1.25.5 archive/tar/format.go:293-293 headerUSTAR.groupName
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn ustar_groupName(&self) -> slice<byte> {
        return self.slice(297, 329);
    }
    // go: sdk 1.25.5 archive/tar/format.go:294-294 headerUSTAR.devMajor
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn ustar_devMajor(&self) -> slice<byte> {
        return self.slice(329, 337);
    }
    // go: sdk 1.25.5 archive/tar/format.go:295-295 headerUSTAR.devMinor
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn ustar_devMinor(&self) -> slice<byte> {
        return self.slice(337, 345);
    }
    // go: sdk 1.25.5 archive/tar/format.go:296-296 headerUSTAR.prefix
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn ustar_prefix(&self) -> slice<byte> {
        return self.slice(345, 500);
    }

    // go: sdk 1.25.5 archive/tar/format.go:268-268 headerGNU.accessTime
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn gnu_accessTime(&self) -> slice<byte> {
        return self.slice(345, 357);
    }
    // go: sdk 1.25.5 archive/tar/format.go:269-269 headerGNU.changeTime
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn gnu_changeTime(&self) -> slice<byte> {
        return self.slice(357, 369);
    }
    // go: sdk 1.25.5 archive/tar/format.go:270-270 headerGNU.sparse
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn gnu_sparse(&self) -> slice<byte> {
        return self.slice(386, 483);
    }
    // go: sdk 1.25.5 archive/tar/format.go:271-271 headerGNU.realSize
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn gnu_realSize(&self) -> slice<byte> {
        return self.slice(483, 495);
    }

    // go: sdk 1.25.5 archive/tar/format.go:282-282 headerSTAR.prefix
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn star_prefix(&self) -> slice<byte> {
        return self.slice(345, 476);
    }
    // go: sdk 1.25.5 archive/tar/format.go:283-283 headerSTAR.accessTime
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn star_accessTime(&self) -> slice<byte> {
        return self.slice(476, 488);
    }
    // go: sdk 1.25.5 archive/tar/format.go:284-284 headerSTAR.changeTime
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn star_changeTime(&self) -> slice<byte> {
        return self.slice(488, 500);
    }
    // go: sdk 1.25.5 archive/tar/format.go:285-285 headerSTAR.trailer
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    pub fn star_trailer(&self) -> slice<byte> {
        return self.slice(508, 512);
    }

    // go: sdk 1.25.5 archive/tar/format.go:231-240 block.computeChecksum
    pub fn computeChecksum(&self) -> (i64, i64) {
        let mut unsigned: i64 = 0;
        let mut signed: i64 = 0;
        for i in 0..512usize {
            let mut c = self.0[i];
            if 148 <= i && i < 156 {
                c = b' ';
            }
            unsigned += toint64(c);
            signed += toint64(toint8(c));
        }
        return (unsigned, signed);
    }

    // go: sdk 1.25.5 archive/tar/format.go:172-195 block.getFormat
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
        return formatV7;
    }

    // ─── Write-side block mutation (writer.go templateV7Plus etc.) ──
    //
    // Go exposes `blk.toV7().name()` → a mutable `[]byte` view into the
    // block. goish models the field views as `&mut [u8]` ranges; the
    // formatter writes through them in place.

    // go: sdk 1.25.5 archive/tar/format.go:243-245 block.reset
    /// `blk.reset()` — zero the whole block.
    pub fn reset(&mut self) {
        self.0 = [0; 512];
    }

    // go: none — goish idiom: the &mut half of `slice`; see above.
    fn slice_mut(&mut self, start: usize, end: usize) -> &mut [u8] {
        return &mut self.0[start..end];
    }

    // go: sdk 1.25.5 archive/tar/format.go:249-249 headerV7.name
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn v7m_name(&mut self) -> &mut [u8] {
        return self.slice_mut(0, 100);
    }
    // go: sdk 1.25.5 archive/tar/format.go:250-250 headerV7.mode
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn v7m_mode(&mut self) -> &mut [u8] {
        return self.slice_mut(100, 108);
    }
    // go: sdk 1.25.5 archive/tar/format.go:251-251 headerV7.uid
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn v7m_uid(&mut self) -> &mut [u8] {
        return self.slice_mut(108, 116);
    }
    // go: sdk 1.25.5 archive/tar/format.go:252-252 headerV7.gid
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn v7m_gid(&mut self) -> &mut [u8] {
        return self.slice_mut(116, 124);
    }
    // go: sdk 1.25.5 archive/tar/format.go:253-253 headerV7.size
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn v7m_size(&mut self) -> &mut [u8] {
        return self.slice_mut(124, 136);
    }
    // go: sdk 1.25.5 archive/tar/format.go:254-254 headerV7.modTime
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn v7m_modTime(&mut self) -> &mut [u8] {
        return self.slice_mut(136, 148);
    }
    // go: sdk 1.25.5 archive/tar/format.go:255-255 headerV7.chksum
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn v7m_chksum(&mut self) -> &mut [u8] {
        return self.slice_mut(148, 156);
    }
    // go: sdk 1.25.5 archive/tar/format.go:256-256 headerV7.typeFlag
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn v7m_typeFlag(&mut self) -> &mut [u8] {
        return self.slice_mut(156, 157);
    }
    // go: sdk 1.25.5 archive/tar/format.go:257-257 headerV7.linkName
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn v7m_linkName(&mut self) -> &mut [u8] {
        return self.slice_mut(157, 257);
    }

    // go: sdk 1.25.5 archive/tar/format.go:290-290 headerUSTAR.magic
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn ustarm_magic(&mut self) -> &mut [u8] {
        return self.slice_mut(257, 263);
    }
    // go: sdk 1.25.5 archive/tar/format.go:291-291 headerUSTAR.version
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn ustarm_version(&mut self) -> &mut [u8] {
        return self.slice_mut(263, 265);
    }
    // go: sdk 1.25.5 archive/tar/format.go:292-292 headerUSTAR.userName
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn ustarm_userName(&mut self) -> &mut [u8] {
        return self.slice_mut(265, 297);
    }
    // go: sdk 1.25.5 archive/tar/format.go:293-293 headerUSTAR.groupName
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn ustarm_groupName(&mut self) -> &mut [u8] {
        return self.slice_mut(297, 329);
    }
    // go: sdk 1.25.5 archive/tar/format.go:294-294 headerUSTAR.devMajor
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn ustarm_devMajor(&mut self) -> &mut [u8] {
        return self.slice_mut(329, 337);
    }
    // go: sdk 1.25.5 archive/tar/format.go:295-295 headerUSTAR.devMinor
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn ustarm_devMinor(&mut self) -> &mut [u8] {
        return self.slice_mut(337, 345);
    }
    // go: sdk 1.25.5 archive/tar/format.go:296-296 headerUSTAR.prefix
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn ustarm_prefix(&mut self) -> &mut [u8] {
        return self.slice_mut(345, 500);
    }

    // go: sdk 1.25.5 archive/tar/format.go:268-268 headerGNU.accessTime
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn gnum_accessTime(&mut self) -> &mut [u8] {
        return self.slice_mut(345, 357);
    }
    // go: sdk 1.25.5 archive/tar/format.go:269-269 headerGNU.changeTime
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn gnum_changeTime(&mut self) -> &mut [u8] {
        return self.slice_mut(357, 369);
    }
    // go: sdk 1.25.5 archive/tar/format.go:262-262 headerGNU.magic
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn gnum_magic(&mut self) -> &mut [u8] {
        return self.slice_mut(257, 263);
    }
    // go: sdk 1.25.5 archive/tar/format.go:263-263 headerGNU.version
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `headerV7.name`, because that is the declaration this
    //     ports. Go gets at it by casting `*block` to
    //     `*headerV7` and slicing the result; Rust will not
    //     reinterpret one array type as another, so the four views
    //     are flattened onto `block` with a prefix per view. The
    //     Rust name therefore cannot equal the Go one.
    // The `m` suffix is the &mut view of the same field. Go's one
    // accessor returns a []byte, which is already a mutable window;
    // Rust needs the borrow spelled, so the pair is two methods.
    pub fn gnum_version(&mut self) -> &mut [u8] {
        return self.slice_mut(263, 265);
    }

    // go: sdk 1.25.5 archive/tar/format.go:199-225 block.setFormat
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

// go: none — goish idiom: Go's `copy(dst, src)` is a builtin that
//     stops at the shorter of the two. Rust's `copy_from_slice` panics
//     unless the lengths match, so the min is taken here.
/// `copy(dst, src)` for raw byte ranges — returns the count copied.
pub(crate) fn copyBytes(dst: &mut [u8], src: &[u8]) -> usize {
    let n = core::cmp::min(dst.len(), src.len());
    dst[..n].copy_from_slice(&src[..n]);
    return n;
}

// ─── Utility functions ───────────────────────────────────────────────

// go: sdk 1.25.5 archive/tar/format.go:154-156 blockPadding
pub(crate) fn blockPadding(offset: i64) -> i64 {
    return (-offset) & (512_i64 - 1);
}

// ─── zeroBlock ───────────────────────────────────────────────────────

/// 512 zero bytes — used for padding and the two-block trailer.
pub(crate) const zeroBlock: [byte; 512] = [0; 512];
