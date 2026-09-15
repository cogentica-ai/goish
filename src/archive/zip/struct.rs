// goishlint:ignore GOISH018 FileHeader.FileInfo, headerFileInfo.Name, headerFileInfo.Size, headerFileInfo.IsDir, headerFileInfo.ModTime, headerFileInfo.Mode, headerFileInfo.Type, headerFileInfo.Sys, headerFileInfo.Info, headerFileInfo.String, FileInfoHeader — the fs.FileInfo adaptor in both directions, ABSENT from this slice. It is an interface bridge rather than format work: `FileInfo()` wraps a FileHeader in something that satisfies fs.FileInfo, and `FileInfoHeader` goes the other way and additionally reads a *File out of `fi.Sys()` via a type assertion on `any`. Both want the same runtime interface-satisfaction machinery that ROADMAP §2 tracks, and neither is on the path to reading or writing an archive, so they land with reader.go.
// goishlint:ignore GOISH021 headerFileInfo, zipVersion20, zipVersion45 — headerFileInfo is the adaptor waived above; the two version numbers are written by writer.go, which is unported, and nothing in this file reads them.
// go: file archive/zip/struct.go decls: timeZone, msDosTimeToTime, timeToMsDosTime, FileHeader.ModTime, FileHeader.SetModTime, FileHeader.Mode, FileHeader.SetMode, FileHeader.isZip64, FileHeader.hasDataDescriptor, msdosModeToFileMode, fileModeToUnixMode, unixModeToFileMode
//
// archive/zip/struct.go — the on-disk shapes and the two codecs that sit
// between ZIP's idea of a file and the host's.
//
// The MS-DOS time format is the reason a ZIP's mtime has two-second
// resolution and cannot predate 1980: the date is a uint16 packing
// day/month/(year-1980) into 5/4/7 bits and the time packs
// (second/2)/minute/hour into 5/6/5. Neither is validated on the way in
// — Go builds a time.Date from whatever bits arrive and lets the
// normalisation rules take over, so a month field of 0 means December
// of the previous year and a day of 0 means the last of the month
// before. The reference rows exercise exactly that.
//
// The mode mappings are three separate tables and they are not
// inverses. `msdosModeToFileMode` has only two bits to work with, so
// everything is 0666 or 0777 and read-only clears the write bits;
// `unixModeToFileMode` and `fileModeToUnixMode` carry the type in the
// s_IFMT nibble and the setuid/setgid/sticky trio separately.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use crate::byte;
use crate::goslice::slice;
use crate::gostring::string;
use crate::int;
use crate::io::fs;
use crate::time;
use crate::uint16;
use crate::uint32;
use crate::uint64;

// go: sdk 1.25.5 archive/zip/struct.go:29-33 Store
/// Go: "Compression methods." — `Store` is no compression, `Deflate`
/// is DEFLATE. The numbers are the ZIP spec's, not Go's.
pub const Store: uint16 = 0;
// go: none — see Store; Go declares both in one const block.
pub const Deflate: uint16 = 8;

// go: sdk 1.25.5 archive/zip/struct.go:35-49 fileHeaderSignature
/// Go's block of on-disk signatures and fixed record lengths. The
/// signatures are the four magic bytes that start each record, read
/// little-endian; the lengths exclude the variable-length name, extra
/// field and comment that follow.
pub const fileHeaderSignature: uint32 = 0x04034b50;
// go: none — see fileHeaderSignature.
pub const directoryHeaderSignature: uint32 = 0x02014b50;
// go: none — see fileHeaderSignature.
pub const directoryEndSignature: uint32 = 0x06054b50;
// go: none — see fileHeaderSignature.
pub const directory64LocSignature: uint32 = 0x07064b50;
// go: none — see fileHeaderSignature.
pub const directory64EndSignature: uint32 = 0x06064b50;
// go: none — Go: "de-facto standard; required by OS X Finder"
pub const dataDescriptorSignature: uint32 = 0x08074b50;
// go: none — Go: "+ filename + extra"
pub const fileHeaderLen: int = 30;
// go: none — Go: "+ filename + extra + comment"
pub const directoryHeaderLen: int = 46;
// go: none — Go: "+ comment"
pub const directoryEndLen: int = 22;
// go: none — Go: "four uint32: descriptor signature, crc32, compressed size, size"
pub const dataDescriptorLen: int = 16;
// go: none — Go: "two uint32: signature, crc32 | two uint64: compressed size, size"
pub const dataDescriptor64Len: int = 24;
// go: none — see fileHeaderSignature.
pub const directory64LocLen: int = 20;
// go: none — Go: "+ extra"
pub const directory64EndLen: int = 56;

// go: none — Go's extra-field IDs. Each names a block that may appear
// in a header's variable-length `Extra` area; reader.go and writer.go
// dispatch on them, and they are here because Go declares them here.
pub const zip64ExtraID: uint16 = 0x0001;
// go: none — Go: "NTFS"
pub const ntfsExtraID: uint16 = 0x000a;
// go: none — Go: "UNIX"
pub const unixExtraID: uint16 = 0x000d;
// go: none — Go: "Extended timestamp"
pub const extTimeExtraID: uint16 = 0x5455;
// go: none — Go: "Info-ZIP Unix extension"
pub const infoZipUnixExtraID: uint16 = 0x5855;

// go: none — Go: "Constants for the first byte in CreatorVersion."
pub const creatorFAT: uint16 = 0;
// go: none — see creatorFAT.
pub const creatorUnix: uint16 = 3;
// go: none — see creatorFAT.
pub const creatorNTFS: uint16 = 11;
// go: none — see creatorFAT.
pub const creatorVFAT: uint16 = 14;
// go: none — see creatorFAT.
pub const creatorMacOSX: uint16 = 19;

// go: none — Go: "Limits for non zip64 files."
pub const uint16max: uint32 = 0xffff;
// go: none — see uint16max.
pub const uint32max: uint32 = 0xffffffff;

// go: sdk 1.25.5 archive/zip/struct.go:84-160 FileHeader
/// Go: "FileHeader describes a file within a ZIP file. See the ZIP
/// specification for details."
#[derive(Clone, Default)]
pub struct FileHeader {
    /// Go: "Name is the name of the file. It must be a relative path,
    /// not start with a drive letter (such as "C:"), and must use
    /// forward slashes instead of back slashes. A trailing slash
    /// indicates that this file is a directory and should have no data."
    pub Name: string,
    /// Go: "Comment is any arbitrary user-defined string shorter than
    /// 64KiB."
    pub Comment: string,
    /// Go: "NonUTF8 indicates that Name and Comment are not encoded in
    /// UTF-8. ... This flag should only be set if the user intends to
    /// encode a non-portable ZIP file for a specific localized region."
    pub NonUTF8: bool,
    pub CreatorVersion: uint16,
    pub ReaderVersion: uint16,
    pub Flags: uint16,
    /// Go: "Method is the compression method. If zero, Store is used."
    pub Method: uint16,
    /// Go: "Modified is the modified time of the file. When reading, an
    /// extended timestamp is preferred over the legacy MS-DOS date
    /// field, and the offset between the times is used as the timezone."
    pub Modified: time::Time,
    /// Go: "ModifiedTime is an MS-DOS-encoded time. Deprecated."
    pub ModifiedTime: uint16,
    /// Go: "ModifiedDate is an MS-DOS-encoded date. Deprecated."
    pub ModifiedDate: uint16,
    /// Go: "CRC32 is the CRC32 checksum of the file content."
    pub CRC32: uint32,
    /// Go: "If either the uncompressed or compressed size of the file
    /// does not fit in 32 bits, CompressedSize is set to ^uint32(0).
    /// Deprecated."
    pub CompressedSize: uint32,
    /// Go: as CompressedSize. Deprecated.
    pub UncompressedSize: uint32,
    pub CompressedSize64: uint64,
    pub UncompressedSize64: uint64,
    pub Extra: slice<byte>,
    /// Go: "Meaning depends on CreatorVersion"
    pub ExternalAttrs: uint32,
}

// go: sdk 1.25.5 archive/zip/struct.go:220-229 directoryEnd
/// Go: the end-of-central-directory record, in the widened form the
/// zip64 locator can fill in. Six of its eight fields are read from the
/// wire and four of those Go marks unused.
#[derive(Clone, Default)]
pub struct directoryEnd {
    /// Go: "unused"
    pub diskNbr: uint32,
    /// Go: "unused"
    pub dirDiskNbr: uint32,
    /// Go: "unused"
    pub dirRecordsThisDisk: uint64,
    pub directoryRecords: uint64,
    pub directorySize: uint64,
    /// Go: "relative to file"
    pub directoryOffset: uint64,
    pub commentLen: uint16,
    pub comment: string,
}

// go: sdk 1.25.5 archive/zip/struct.go:229-243 timeZone
/// Go: "timeZone returns a *time.Location based on the provided offset.
/// If the offset is non-sensible, then this uses an offset of zero."
///
/// The alias is 15 minutes because real zones use it — Go's own comment
/// names Nepal at +5:45 — so an extended-timestamp offset that is a few
/// seconds off a real zone still lands on one. Anything outside
/// [-12h, +14h] (Baker Island to the Line Islands) becomes UTC.
pub fn timeZone(offset: time::Duration) -> time::Location {
    // Go: "E.g., Baker island at -12:00"
    let minOffset: time::Duration = -12 * time::Hour;
    // Go: "E.g., Line island at +14:00"
    let maxOffset: time::Duration = 14 * time::Hour;
    // Go: "E.g., Nepal at +5:45"
    let offsetAlias: time::Duration = 15 * time::Minute;
    let mut offset = offset.Round(offsetAlias);
    if offset < minOffset || maxOffset < offset {
        offset = 0 * time::Second;
    }
    return time::FixedZone("", int(crate::int64(offset / time::Second)));
}

// go: sdk 1.25.5 archive/zip/struct.go:245-265 msDosTimeToTime
/// Go: "msDosTimeToTime converts an MS-DOS date and time into a
/// time.Time. The resolution is 2s."
///
/// Nothing here is validated. Go builds a `time.Date` from the raw bit
/// fields and lets Date's normalisation absorb whatever arrives, so a
/// month field of 0 rolls back to December of the previous year and a
/// day of 0 to the last day of the month before — which is why a
/// zero date decodes to 1979-11-30 and not to an error.
pub fn msDosTimeToTime(dosDate: uint16, dosTime: uint16) -> time::Time {
    return time::Date(
        // Go: "date bits 0-4: day of month; 5-8: month; 9-15: years since 1980"
        int(crate::int64(dosDate >> 9) + 1980),
        int(crate::int64(dosDate >> 5 & 0xf)),
        int(crate::int64(dosDate & 0x1f)),
        // Go: "time bits 0-4: second/2; 5-10: minute; 11-15: hour"
        int(crate::int64(dosTime >> 11)),
        int(crate::int64(dosTime >> 5 & 0x3f)),
        int(crate::int64(dosTime & 0x1f) * 2),
        // Go: "nanoseconds"
        0,
        time::UTC,
    );
}

// go: sdk 1.25.5 archive/zip/struct.go:267-273 timeToMsDosTime
/// Go: "timeToMsDosTime converts a time.Time to an MS-DOS date and
/// time. The resolution is 2s."
///
/// The truncation to uint16 is Go's and it is load-bearing: a year
/// beyond 2107 wraps rather than erroring.
pub fn timeToMsDosTime(t: time::Time) -> (uint16, uint16) {
    let fDate = crate::uint16(t.Day() + (t.Month().Int() << 5) + ((t.Year() - 1980) << 9));
    let fTime = crate::uint16(t.Second() / 2 + (t.Minute() << 5) + (t.Hour() << 11));
    return (fDate, fTime);
}

// go: none — Go: "Unix constants. The specification doesn't mention
// them, but these seem to be the values agreed on by tools."
pub const s_IFMT: uint32 = 0xf000;
// go: none — see s_IFMT.
pub const s_IFSOCK: uint32 = 0xc000;
// go: none — see s_IFMT.
pub const s_IFLNK: uint32 = 0xa000;
// go: none — see s_IFMT.
pub const s_IFREG: uint32 = 0x8000;
// go: none — see s_IFMT.
pub const s_IFBLK: uint32 = 0x6000;
// go: none — see s_IFMT.
pub const s_IFDIR: uint32 = 0x4000;
// go: none — see s_IFMT.
pub const s_IFCHR: uint32 = 0x2000;
// go: none — see s_IFMT.
pub const s_IFIFO: uint32 = 0x1000;
// go: none — see s_IFMT.
pub const s_ISUID: uint32 = 0x800;
// go: none — see s_IFMT.
pub const s_ISGID: uint32 = 0x400;
// go: none — see s_IFMT.
pub const s_ISVTX: uint32 = 0x200;
// go: none — see s_IFMT.
pub const msdosDir: uint32 = 0x10;
// go: none — see s_IFMT.
pub const msdosReadOnly: uint32 = 0x01;

impl FileHeader {
    // go: sdk 1.25.5 archive/zip/struct.go:275-281 FileHeader.ModTime
    /// Go: "ModTime returns the modification time in UTC using the
    /// legacy ModifiedDate and ModifiedTime fields. Deprecated: Use
    /// Modified instead."
    pub fn ModTime(&self) -> time::Time {
        return msDosTimeToTime(self.ModifiedDate, self.ModifiedTime);
    }

    // go: sdk 1.25.5 archive/zip/struct.go:283-291 FileHeader.SetModTime
    /// Go: "SetModTime sets the Modified, ModifiedTime, and
    /// ModifiedDate fields to the given time in UTC. Deprecated."
    pub fn SetModTime(&mut self, t: time::Time) {
        // Go: "Convert to UTC for compatibility"
        let t = t.UTC();
        self.Modified = t.clone();
        let (d, tm) = timeToMsDosTime(t);
        self.ModifiedDate = d;
        self.ModifiedTime = tm;
    }

    // go: sdk 1.25.5 archive/zip/struct.go:311-323 FileHeader.Mode
    /// Go: "Mode returns the permission and mode bits for the
    /// FileHeader."
    ///
    /// A CreatorVersion whose high byte names no known creator yields
    /// mode ZERO whatever ExternalAttrs holds — the switch has no
    /// default. The trailing-slash test then runs regardless, so a name
    /// ending in `/` is a directory even from an unknown creator.
    pub fn Mode(&self) -> fs::FileMode {
        let mut mode = fs::FileMode(0);
        let creator = self.CreatorVersion >> 8;
        if creator == creatorUnix || creator == creatorMacOSX {
            mode = unixModeToFileMode(self.ExternalAttrs >> 16);
        } else if creator == creatorNTFS || creator == creatorVFAT || creator == creatorFAT {
            mode = msdosModeToFileMode(self.ExternalAttrs);
        }
        let n = self.Name.as_bytes();
        if n.len() > 0 && n[n.len() - 1] == b'/' {
            mode = fs::FileMode(mode.0 | fs::ModeDir.0);
        }
        return mode;
    }

    // go: sdk 1.25.5 archive/zip/struct.go:325-339 FileHeader.SetMode
    /// Go: "SetMode changes the permission and mode bits for the
    /// FileHeader." It always writes a Unix creator, and then — Go's
    /// comment — sets "MSDOS attributes too, as the original zip does".
    pub fn SetMode(&mut self, mode: fs::FileMode) {
        self.CreatorVersion = self.CreatorVersion & 0xff | creatorUnix << 8;
        self.ExternalAttrs = fileModeToUnixMode(mode) << 16;

        // Go: "set MSDOS attributes too, as the original zip does."
        if mode.0 & fs::ModeDir.0 != 0 {
            self.ExternalAttrs |= msdosDir;
        }
        if mode.0 & 0o200 == 0 {
            self.ExternalAttrs |= msdosReadOnly;
        }
    }

    // go: sdk 1.25.5 archive/zip/struct.go:341-343 FileHeader.isZip64
    /// Go: "isZip64 reports whether the file size exceeds the 32 bit
    /// limit" — and the test is `>=`, so a size of exactly 0xffffffff
    /// is already zip64, because that value is the escape marker.
    pub fn isZip64(&self) -> bool {
        return self.CompressedSize64 >= uint64(uint32max)
            || self.UncompressedSize64 >= uint64(uint32max);
    }

    // go: sdk 1.25.5 archive/zip/struct.go:345-347 FileHeader.hasDataDescriptor
    /// Go: `h.Flags&0x8 != 0` — bit 3 says the sizes and CRC follow the
    /// data instead of preceding it.
    pub fn hasDataDescriptor(&self) -> bool {
        return self.Flags & 0x8 != 0;
    }
}

// go: sdk 1.25.5 archive/zip/struct.go:349-359 msdosModeToFileMode
/// Go: two bits in, a whole FileMode out — so every MS-DOS entry is
/// 0777 or 0666 before the read-only bit clears the write bits.
pub fn msdosModeToFileMode(m: uint32) -> fs::FileMode {
    let mut mode: fs::FileMode;
    if m & msdosDir != 0 {
        mode = fs::FileMode(fs::ModeDir.0 | 0o777);
    } else {
        mode = fs::FileMode(0o666);
    }
    if m & msdosReadOnly != 0 {
        // Go: `mode &^= 0222`
        mode = fs::FileMode(mode.0 & !0o222);
    }
    return mode;
}

// go: sdk 1.25.5 archive/zip/struct.go:361-389 fileModeToUnixMode
/// Go: the FileMode type bits into the s_IFMT nibble. Note the
/// `default` arm: anything that is not one of the six named types —
/// including ModeIrregular, ModeAppend and a plain file — becomes
/// s_IFREG.
pub fn fileModeToUnixMode(mode: fs::FileMode) -> uint32 {
    let mut m: uint32;
    let t = mode.0 & fs::ModeType.0;
    if t == fs::ModeDir.0 {
        m = s_IFDIR;
    } else if t == fs::ModeSymlink.0 {
        m = s_IFLNK;
    } else if t == fs::ModeNamedPipe.0 {
        m = s_IFIFO;
    } else if t == fs::ModeSocket.0 {
        m = s_IFSOCK;
    } else if t == fs::ModeDevice.0 {
        m = s_IFBLK;
    } else if t == (fs::ModeDevice.0 | fs::ModeCharDevice.0) {
        m = s_IFCHR;
    } else {
        m = s_IFREG;
    }
    if mode.0 & fs::ModeSetuid.0 != 0 {
        m |= s_ISUID;
    }
    if mode.0 & fs::ModeSetgid.0 != 0 {
        m |= s_ISGID;
    }
    if mode.0 & fs::ModeSticky.0 != 0 {
        m |= s_ISVTX;
    }
    return m | (mode.0 & 0o777);
}

// go: sdk 1.25.5 archive/zip/struct.go:391-419 unixModeToFileMode
/// Go: the inverse direction, and NOT the inverse function —
/// s_IFREG has "nothing to do", and an s_IFMT value Go does not name
/// (0x3000, say) yields the permission bits alone.
pub fn unixModeToFileMode(m: uint32) -> fs::FileMode {
    let mut mode = fs::FileMode(m & 0o777);
    let t = m & s_IFMT;
    if t == s_IFBLK {
        mode = fs::FileMode(mode.0 | fs::ModeDevice.0);
    } else if t == s_IFCHR {
        mode = fs::FileMode(mode.0 | fs::ModeDevice.0 | fs::ModeCharDevice.0);
    } else if t == s_IFDIR {
        mode = fs::FileMode(mode.0 | fs::ModeDir.0);
    } else if t == s_IFIFO {
        mode = fs::FileMode(mode.0 | fs::ModeNamedPipe.0);
    } else if t == s_IFLNK {
        mode = fs::FileMode(mode.0 | fs::ModeSymlink.0);
    } else if t == s_IFREG {
        // Go: "nothing to do"
    } else if t == s_IFSOCK {
        mode = fs::FileMode(mode.0 | fs::ModeSocket.0);
    }
    if m & s_ISGID != 0 {
        mode = fs::FileMode(mode.0 | fs::ModeSetgid.0);
    }
    if m & s_ISUID != 0 {
        mode = fs::FileMode(mode.0 | fs::ModeSetuid.0);
    }
    if m & s_ISVTX != 0 {
        mode = fs::FileMode(mode.0 | fs::ModeSticky.0);
    }
    return mode;
}
