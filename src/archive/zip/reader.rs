// goishlint:ignore GOISH018 OpenReader, NewReader, Reader.init, Reader.RegisterDecompressor, Reader.decompressor, ReadCloser.Close, File.DataOffset, File.Open, File.OpenRaw, dirReader.Read, dirReader.Close, checksumReader.Stat, checksumReader.Read, checksumReader.Close, File.findBodyOffset, fileListEntry.stat, fileListEntry.Name, fileListEntry.Size, fileListEntry.Mode, fileListEntry.Type, fileListEntry.IsDir, fileListEntry.Sys, fileListEntry.ModTime, fileListEntry.Info, fileListEntry.String, Reader.initFileList, Reader.Open, Reader.openLookup, Reader.openReadDir, openDir.Close, openDir.Stat, openDir.Read, openDir.ReadDir — the Reader itself and its fs.FS surface, ABSENT from this slice. Every one of them needs an io.ReaderAt over a whole archive, a decompressor registry, or the fs.File / fs.DirEntry interface bridge; this slice is the PARSING, which is the half that has to be right about a hostile input and the half a reference can pin byte-for-byte. They land next.
// goishlint:ignore GOISH021 Reader, ReadCloser, dirReader, checksumReader, fileListEntry, fileInfoDirEntry, openDir, dotFile, zipinsecurepath — the Reader's own types and its fs.FS entry list, absent with the methods above. `zipinsecurepath` is a GODEBUG knob and goish has no godebug package.
// goishlint:ignore GOISH019 File — three fields absent: `zip`, `zipr` and `descErr`. `zip` is a back-pointer to the Reader and `zipr` its io.ReaderAt, both of which this slice does not have; neither is read by anything here. The field set comes back whole with the Reader.
// go: file archive/zip/reader.go decls: readDirectoryEnd, findDirectory64End, readDirectory64End, ErrFormat, ErrAlgorithm, ErrChecksum, ErrInsecurePath, readDirectoryHeader, readDataDescriptor, findSignatureInBlock, readBuf.uint8, readBuf.uint16, readBuf.uint32, readBuf.uint64, readBuf.sub, toValidName, fileEntryCompare, split
//
// archive/zip/reader.go — the parsing half.
//
// A ZIP's central directory is the authority: one 46-byte fixed record
// per entry, followed by a name, an extra area and a comment whose
// lengths the record itself declares. `readDirectoryHeader` is where a
// hostile archive meets the parser, and the interesting behaviour is
// all in what it TOLERATES:
//
//   * an extra field whose declared size runs past the end of the area
//     ends the loop silently rather than erroring;
//   * an NTFS or Unix or extended-timestamp block that is too short is
//     skipped, not rejected;
//   * a zip64 block is consulted ONLY for the sizes that were maxed out
//     in the fixed record — Go's comment cites issue 13367 — and a
//     short zip64 block IS an error, but only for a size that was
//     needed;
//   * an uncompressed size of 2³²-1 with no zip64 block is ACCEPTED.
//     Go's comment explains why: 42.zip. A compressed size or header
//     offset of 2³²-1 with no zip64 block is still ErrFormat.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::r#struct::{
    dataDescriptorLen, dataDescriptorSignature, directory64EndLen, directory64EndSignature,
    directory64LocLen, directory64LocSignature, directoryEnd, directoryEndLen,
    directoryEndSignature, directoryHeaderLen, directoryHeaderSignature, extTimeExtraID,
    infoZipUnixExtraID, msDosTimeToTime, ntfsExtraID, timeZone, unixExtraID, zip64ExtraID,
    FileHeader,
};
use super::writer::detectUTF8;
use crate::byte;
use crate::errors;
use crate::goslice::slice;
use crate::gostring::string;
use crate::int;
use crate::int64;
use crate::time;
use crate::uint16;
use crate::uint32;
use crate::uint64;

// go: sdk 1.25.5 archive/zip/reader.go:28-33 ErrFormat
/// Go's four sentinel errors. Functions rather than statics because
/// goish's `error` is not const-constructible.
pub fn ErrFormat() -> crate::error {
    return errors::New("zip: not a valid zip file");
}
// go: none — see ErrFormat; Go declares all four in one var block.
pub fn ErrAlgorithm() -> crate::error {
    return errors::New("zip: unsupported compression algorithm");
}
// go: none — see ErrFormat.
pub fn ErrChecksum() -> crate::error {
    return errors::New("zip: checksum error");
}
// go: none — see ErrFormat.
pub fn ErrInsecurePath() -> crate::error {
    return errors::New("zip: insecure file path");
}

// go: sdk 1.25.5 archive/zip/reader.go:59-66 File
/// Go: "A File is a single file in a ZIP archive. The file information
/// is in the embedded FileHeader. The file content can be accessed by
/// calling File.Open."
#[derive(Clone, Default)]
pub struct File {
    /// Go embeds `FileHeader`; goish names the field, and the accessors
    /// below forward so a caller reads `f.CRC32` as in Go.
    pub FileHeader: FileHeader,
    /// Go: "includes overall ZIP archive baseOffset"
    pub headerOffset: int64,
    /// Go: "zip64 extended information extra field presence"
    pub zip64: bool,
}

// go: sdk 1.25.5 archive/zip/reader.go:715-715 readBuf
/// Go: `type readBuf []byte` — a byte slice whose pointer-receiver
/// methods consume from the front. Every read RESLICES, so the
/// remaining length is the parser's only bounds check, and a caller
/// that forgets to check it reads past the end.
#[derive(Clone, Default)]
pub struct readBuf(pub slice<byte>);

impl readBuf {
    // go: none — goish idiom: Go writes `readBuf(buf[:])`, a conversion;
    // goish's is a tuple struct and needs a constructor spelled out.
    pub fn new(b: slice<byte>) -> Self {
        return readBuf(b);
    }

    // go: none — goish idiom: Go asks `len(b)` of the slice directly.
    pub fn Len(&self) -> int {
        return self.0.Len();
    }

    // go: sdk 1.25.5 archive/zip/reader.go:717-721 readBuf.uint8
    /// Go: one byte off the front.
    pub fn uint8(&mut self) -> byte {
        let v = self.0[0];
        self.0 = self.0.slice(1, self.0.Len());
        return v;
    }

    // go: sdk 1.25.5 archive/zip/reader.go:723-727 readBuf.uint16
    /// Go: `binary.LittleEndian.Uint16` — ZIP is little-endian
    /// throughout.
    pub fn uint16(&mut self) -> uint16 {
        let v = crate::encoding::binary::LittleEndian.Uint16(self.0.slice(0, 2).as_ref());
        self.0 = self.0.slice(2, self.0.Len());
        return v;
    }

    // go: sdk 1.25.5 archive/zip/reader.go:729-733 readBuf.uint32
    /// Go: see uint16.
    pub fn uint32(&mut self) -> uint32 {
        let v = crate::encoding::binary::LittleEndian.Uint32(self.0.slice(0, 4).as_ref());
        self.0 = self.0.slice(4, self.0.Len());
        return v;
    }

    // go: sdk 1.25.5 archive/zip/reader.go:735-739 readBuf.uint64
    /// Go: see uint16.
    pub fn uint64(&mut self) -> uint64 {
        let v = crate::encoding::binary::LittleEndian.Uint64(self.0.slice(0, 8).as_ref());
        self.0 = self.0.slice(8, self.0.Len());
        return v;
    }

    // go: sdk 1.25.5 archive/zip/reader.go:741-745 readBuf.sub
    /// Go: take the first n bytes as their own readBuf and advance.
    pub fn sub(&mut self, n: int) -> readBuf {
        let b2 = self.0.slice(0, n);
        self.0 = self.0.slice(n, self.0.Len());
        return readBuf(b2);
    }
}

// go: sdk 1.25.5 archive/zip/reader.go:353-526 readDirectoryHeader
/// Go: "It returns io.ErrUnexpectedEOF if it cannot read a complete
/// header, and ErrFormat if it doesn't find a valid header signature."
pub fn readDirectoryHeader(f: &mut File, r: &mut dyn crate::io::Reader) -> crate::error {
    let mut buf: slice<byte> =
        slice::__from_vec(alloc::vec![0u8; directoryHeaderLen as usize]);
    let (_, err) = crate::io::ReadFull(r, &mut buf);
    if err != errors::nil {
        return err;
    }
    let mut b = readBuf::new(buf.clone());
    let sig = b.uint32();
    if sig != directoryHeaderSignature {
        return ErrFormat();
    }
    f.FileHeader.CreatorVersion = b.uint16();
    f.FileHeader.ReaderVersion = b.uint16();
    f.FileHeader.Flags = b.uint16();
    f.FileHeader.Method = b.uint16();
    f.FileHeader.ModifiedTime = b.uint16();
    f.FileHeader.ModifiedDate = b.uint16();
    f.FileHeader.CRC32 = b.uint32();
    f.FileHeader.CompressedSize = b.uint32();
    f.FileHeader.UncompressedSize = b.uint32();
    f.FileHeader.CompressedSize64 = uint64(f.FileHeader.CompressedSize);
    f.FileHeader.UncompressedSize64 = uint64(f.FileHeader.UncompressedSize);
    let filenameLen = int(int64(b.uint16()));
    let extraLen = int(int64(b.uint16()));
    let commentLen = int(int64(b.uint16()));
    // Go: "skipped start disk number and internal attributes (2x uint16)"
    b.0 = b.0.slice(4, b.0.Len());
    f.FileHeader.ExternalAttrs = b.uint32();
    f.headerOffset = int64(b.uint32());
    let mut d: slice<byte> =
        slice::__from_vec(alloc::vec![0u8; (filenameLen + extraLen + commentLen) as usize]);
    let (_, err) = crate::io::ReadFull(r, &mut d);
    if err != errors::nil {
        return err;
    }
    f.FileHeader.Name = string::from_bytes(d.slice(0, filenameLen).as_ref());
    f.FileHeader.Extra = d.slice(filenameLen, filenameLen + extraLen);
    f.FileHeader.Comment = string::from_bytes(d.slice(filenameLen + extraLen, d.Len()).as_ref());

    // Go: "Determine the character encoding."
    let (utf8Valid1, utf8Require1) = detectUTF8(f.FileHeader.Name.as_bytes());
    let (utf8Valid2, utf8Require2) = detectUTF8(f.FileHeader.Comment.as_bytes());
    if !utf8Valid1 || !utf8Valid2 {
        // Go: "Name and Comment definitely not UTF-8."
        f.FileHeader.NonUTF8 = true;
    } else if !utf8Require1 && !utf8Require2 {
        // Go: "Name and Comment use only single-byte runes that overlap
        // with UTF-8."
        f.FileHeader.NonUTF8 = false;
    } else {
        // Go: "Might be UTF-8, might be some other encoding; preserve
        // existing flag. Some ZIP writers use UTF-8 encoding without
        // setting the UTF-8 flag. Since it is impossible to always
        // distinguish valid UTF-8 from some other encoding (e.g., GBK
        // or Shift-JIS), we trust the flag."
        f.FileHeader.NonUTF8 = f.FileHeader.Flags & 0x800 == 0;
    }

    let needUSize = f.FileHeader.UncompressedSize == uint32max_();
    let mut needCSize = f.FileHeader.CompressedSize == uint32max_();
    let mut needHeaderOffset = f.headerOffset == int64(uint32max_());
    let mut needUSize = needUSize;

    // Go: "Best effort to find what we need. Other zip authors might not
    // even follow the basic format, and we'll just ignore the Extra
    // content in that case."
    let mut modified = time::Time::default();
    let mut extra = readBuf::new(f.FileHeader.Extra.clone());
    // Go labels this loop `parseExtras` so the NTFS arm can `continue`
    // the OUTER loop from inside its own.
    'parseExtras: while extra.Len() >= 4 {
        // Go: "need at least tag and size"
        let fieldTag = extra.uint16();
        let fieldSize = int(int64(extra.uint16()));
        if extra.Len() < fieldSize {
            break;
        }
        let mut fieldBuf = extra.sub(fieldSize);

        if fieldTag == zip64ExtraID {
            f.zip64 = true;

            // Go: "update directory values from the zip64 extra block.
            // They should only be consulted if the sizes read earlier
            // are maxed out. See golang.org/issue/13367."
            if needUSize {
                needUSize = false;
                if fieldBuf.Len() < 8 {
                    return ErrFormat();
                }
                f.FileHeader.UncompressedSize64 = fieldBuf.uint64();
            }
            if needCSize {
                needCSize = false;
                if fieldBuf.Len() < 8 {
                    return ErrFormat();
                }
                f.FileHeader.CompressedSize64 = fieldBuf.uint64();
            }
            if needHeaderOffset {
                needHeaderOffset = false;
                if fieldBuf.Len() < 8 {
                    return ErrFormat();
                }
                f.headerOffset = int64(fieldBuf.uint64());
            }
        } else if fieldTag == ntfsExtraID {
            if fieldBuf.Len() < 4 {
                continue 'parseExtras;
            }
            // Go: "reserved (ignored)"
            fieldBuf.uint32();
            // Go: "need at least tag and size"
            while fieldBuf.Len() >= 4 {
                let attrTag = fieldBuf.uint16();
                let attrSize = int(int64(fieldBuf.uint16()));
                if fieldBuf.Len() < attrSize {
                    continue 'parseExtras;
                }
                let mut attrBuf = fieldBuf.sub(attrSize);
                if attrTag != 1 || attrSize != 24 {
                    // Go: "Ignore irrelevant attributes"
                    continue;
                }

                // Go: "Windows timestamp resolution"
                let ticksPerSecond: int64 = 10_000_000;
                // Go: "ModTime since Windows epoch"
                let ts = int64(attrBuf.uint64());
                let secs = ts / ticksPerSecond;
                let nsecs = (1_000_000_000 / ticksPerSecond) * (ts % ticksPerSecond);
                let epoch = time::Date(1601, 1, 1, 0, 0, 0, 0, time::UTC);
                modified = time::Unix(epoch.Unix() + secs, nsecs);
            }
        } else if fieldTag == unixExtraID || fieldTag == infoZipUnixExtraID {
            if fieldBuf.Len() < 8 {
                continue 'parseExtras;
            }
            // Go: "AcTime (ignored)"
            fieldBuf.uint32();
            // Go: "ModTime since Unix epoch"
            let ts = int64(fieldBuf.uint32());
            modified = time::Unix(ts, 0);
        } else if fieldTag == extTimeExtraID {
            if fieldBuf.Len() < 5 || fieldBuf.uint8() & 1 == 0 {
                continue 'parseExtras;
            }
            // Go: "ModTime since Unix epoch"
            let ts = int64(fieldBuf.uint32());
            modified = time::Unix(ts, 0);
        }
    }

    let msdosModified = msDosTimeToTime(f.FileHeader.ModifiedDate, f.FileHeader.ModifiedTime);
    f.FileHeader.Modified = msdosModified.clone();
    if !modified.IsZero() {
        f.FileHeader.Modified = modified.UTC();

        // Go: "If legacy MS-DOS timestamps are set, we can use the delta
        // between the legacy and extended versions to estimate timezone
        // offset. A non-UTC timezone is always used (even if offset is
        // zero). Thus, FileHeader.Modified.Location() == time.UTC is
        // useful for determining whether extended timestamps are
        // present."
        if f.FileHeader.ModifiedTime != 0 || f.FileHeader.ModifiedDate != 0 {
            f.FileHeader.Modified =
                modified.In(timeZone(msdosModified.Sub(modified.clone())));
        }
    }

    // Go: "Assume that uncompressed size 2³²-1 could plausibly happen in
    // an old zip32 file that was sharding inputs into the largest chunks
    // possible (or is just malicious; search the web for 42.zip). If
    // needUSize is true still, it means we didn't see a zip64 extension.
    // As long as the compressed size is not also 2³²-1 (implausible) and
    // the header is not also 2³²-1 (equally implausible), accept the
    // uncompressed size 2³²-1 as valid."
    let _ = needUSize;

    if needCSize || needHeaderOffset {
        return ErrFormat();
    }

    return errors::nil;
}

// go: none — goish idiom: Go writes `^uint32(0)` inline; a named helper
// reads better than repeating the cast three times.
fn uint32max_() -> uint32 {
    return 0xffffffff;
}

// go: sdk 1.25.5 archive/zip/reader.go:529-566 readDataDescriptor
/// Go: "The spec says: 'Although not originally assigned a signature,
/// the value 0x08074b50 has commonly been adopted as a signature value
/// for the data descriptor record. Implementers should be aware that
/// ZIP files may be encountered with or without this signature marking
/// data descriptors and should account for either case when reading ZIP
/// files to ensure compatibility.'"
///
/// So it reads four bytes, decides whether they were a signature, and
/// keeps them as the CRC if they were not. Only the CRC is checked —
/// Go's comment: the two sizes that follow "can be either 32 bits or 64
/// bits but the spec is not very clear on this", and the central
/// directory already has them.
pub fn readDataDescriptor(r: &mut dyn crate::io::Reader, f: &File) -> crate::error {
    let mut buf: slice<byte> =
        slice::__from_vec(alloc::vec![0u8; dataDescriptorLen as usize]);
    // Go: "dataDescriptorLen includes the size of the signature but
    // first read just those 4 bytes to see if it exists."
    let mut head = buf.slice(0, 4);
    let (_, err) = crate::io::ReadFull(r, &mut head);
    if err != errors::nil {
        return err;
    }
    let mut i: int = 0;
    while i < 4 {
        buf[i] = head[i];
        i += 1;
    }
    let mut off: int = 0;
    let mut maybeSig = readBuf::new(head.clone());
    if maybeSig.uint32() != dataDescriptorSignature {
        // Go: "No data descriptor signature. Keep these four bytes."
        off += 4;
    }
    let mut rest = buf.slice(off, 12);
    let (_, err) = crate::io::ReadFull(r, &mut rest);
    if err != errors::nil {
        return err;
    }
    let mut i: int = 0;
    while i < rest.Len() {
        buf[off + i] = rest[i];
        i += 1;
    }
    let mut b = readBuf::new(buf.slice(0, 12));
    if b.uint32() != f.FileHeader.CRC32 {
        return ErrChecksum();
    }

    return errors::nil;
}

// go: sdk 1.25.5 archive/zip/reader.go:697-713 findSignatureInBlock
/// Go: scan BACKWARDS for the end-of-central-directory signature, and
/// reject a hit whose declared comment would run past the block —
/// Go's comment: "Some parsers (such as Info-ZIP) ignore the truncated
/// comment rather than treating it as a hard error", and Go does not.
pub fn findSignatureInBlock(b: &[byte]) -> int {
    let mut i: i64 = crate::int64(b.len()) - directoryEndLen;
    while i >= 0 {
        let i_ = i as usize;
        // Go: "defined from directoryEndSignature in struct.go"
        if b[i_] == b'P' && b[i_ + 1] == b'K' && b[i_ + 2] == 0x05 && b[i_ + 3] == 0x06 {
            // Go: "n is length of comment"
            let n = crate::int64(b[i_ + directoryEndLen as usize - 2])
                | crate::int64(b[i_ + directoryEndLen as usize - 1]) << 8;
            if n + directoryEndLen + i > crate::int64(b.len()) {
                // Go: "Truncated comment."
                return -1;
            }
            return int(i);
        }
        i -= 1;
    }
    return -1;
}

// go: sdk 1.25.5 archive/zip/reader.go:791-803 toValidName
/// Go: "toValidName coerces name to be a valid name for fs.FS.Open."
/// Backslashes become slashes FIRST, so a Windows-style path is
/// normalised before Clean sees it; then any leading `/` and every
/// leading `../` come off.
pub fn toValidName<S: Into<string>>(name: S) -> string {
    let name: string = name.into();
    let name = crate::strings::ReplaceAll(name, "\\", "/");
    let p = crate::path::Clean(name);

    let mut p = crate::strings::TrimPrefix(p, "/");

    while crate::strings::HasPrefix(p.clone(), "../") {
        p = p.slice(3, p.Len());
    }

    return p;
}

// go: sdk 1.25.5 archive/zip/reader.go:875-882 fileEntryCompare
/// Go: order by directory first, then by element — NOT plain string
/// order, so `a/b/c` sorts after `z` because its directory is `a/b`.
pub fn fileEntryCompare<S1: Into<string>, S2: Into<string>>(x: S1, y: S2) -> int {
    let (xdir, xelem, _) = split(x.into());
    let (ydir, yelem, _) = split(y.into());
    if xdir != ydir {
        return crate::strings::Compare(xdir, ydir);
    }
    return crate::strings::Compare(xelem, yelem);
}

// go: sdk 1.25.5 archive/zip/reader.go:908-915 split
/// Go: split a slash path into directory and element, reporting whether
/// it named a directory by ending in `/`. A name with no slash gets
/// `"."` as its directory.
pub fn split<S: Into<string>>(name: S) -> (string, string, bool) {
    let (name, isDir) = crate::strings::CutSuffix(name.into(), "/");
    let i = crate::strings::LastIndexByte(name.clone(), b'/');
    if i < 0 {
        return (string::from_static("."), name, isDir);
    }
    return (name.slice(0, i), name.slice(i + 1, name.Len()), isDir);
}

// ─── the end-of-central-directory records ─────────────────────────────

// go: none — goish idiom: Go hands `readDirectoryEnd`'s `io.ReaderAt`
// straight to `io.NewSectionReader`, because an interface value is a
// pointer and costs nothing to pass on. goish's `NewSectionReader`
// takes `Box<dyn ReaderAt>` — OWNERSHIP — and `readDirectoryEnd` only
// has a borrow, so the one place Go builds a section reader is spelled
// as a borrow-based cursor here. It implements exactly what
// `readDirectoryHeader` asks of a reader: sequential Read over a
// window, EOF at the end.
struct sectionCursor<'a> {
    r: &'a mut dyn crate::io::ReaderAt,
    off: int64,
    limit: int64,
}

impl crate::io::Reader for sectionCursor<'_> {
    // go: none — goish idiom: see the note on sectionCursor.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, crate::error) {
        if self.off >= self.limit {
            return (0, crate::io::EOF.into());
        }
        let avail = self.limit - self.off;
        let want = if int64(p.Len()) > avail {
            int(avail)
        } else {
            p.Len()
        };
        let mut tmp = p.slice(0, want);
        let (n, err) = self.r.ReadAt(&mut tmp, self.off);
        let mut i: int = 0;
        while i < n {
            p[i] = tmp[i];
            i += 1;
        }
        self.off += int64(n);
        return (n, err);
    }
}

// go: sdk 1.25.5 archive/zip/reader.go:566-645 readDirectoryEnd
/// Go: find the end-of-central-directory record "in the last 1k, then
/// in the last 65k", read it, and — when its fields are maxed out —
/// replace them from the zip64 record the locator points at.
///
/// The `baseOffset` return is the reason this is not just a parse: a
/// JAR can be a shell script with a zip appended, so the directory's
/// recorded offset is relative to the zip, not to the file. Go derives
/// the prefix length and then, per its own comment, THROWS IT AWAY if a
/// directory header parses at the recorded offset with no prefix at
/// all — "We've seen files in which the directory end data gives us an
/// incorrect baseOffset."
pub fn readDirectoryEnd(
    r: &mut dyn crate::io::ReaderAt,
    size: int64,
) -> (Option<directoryEnd>, int64, crate::error) {
    // Go: "look for directoryEndSignature in the last 1k, then in the
    // last 65k"
    let mut buf: slice<byte> = crate::slice!([]byte{});
    let mut directoryEndOffset: int64 = 0;
    let lens: [int64; 2] = [1024, 65 * 1024];
    let mut i: usize = 0;
    let mut found = false;
    while i < 2 {
        let mut bLen = lens[i];
        if bLen > size {
            bLen = size;
        }
        buf = slice::__from_vec(alloc::vec![0u8; bLen as usize]);
        let (_, err) = r.ReadAt(&mut buf, size - bLen);
        if err != errors::nil && !errors::Is(err.clone(), crate::io::EOF) {
            return (None, 0, err);
        }
        let p = findSignatureInBlock(buf.as_ref());
        if p >= 0 {
            buf = buf.slice(p, buf.Len());
            directoryEndOffset = size - bLen + int64(p);
            found = true;
            break;
        }
        if i == 1 || bLen == size {
            return (None, 0, ErrFormat());
        }
        i += 1;
    }
    if !found {
        return (None, 0, ErrFormat());
    }

    // Go: "read header into struct" — `readBuf(buf[4:])`, skipping the
    // signature.
    let mut b = readBuf::new(buf.slice(4, buf.Len()));
    let mut d = directoryEnd {
        diskNbr: uint32(b.uint16()),
        dirDiskNbr: uint32(b.uint16()),
        dirRecordsThisDisk: uint64(b.uint16()),
        directoryRecords: uint64(b.uint16()),
        directorySize: uint64(b.uint32()),
        directoryOffset: uint64(b.uint32()),
        commentLen: b.uint16(),
        comment: string::from_static(""),
    };
    let l = int(int64(d.commentLen));
    if l > b.Len() {
        return (None, 0, errors::New("zip: invalid comment length"));
    }
    d.comment = string::from_bytes(b.0.slice(0, l).as_ref());

    // Go: "These values mean that the file can be a zip64 file"
    if d.directoryRecords == 0xffff || d.directorySize == 0xffff || d.directoryOffset == 0xffffffff
    {
        let (p, err) = findDirectory64End(r, directoryEndOffset);
        let mut err = err;
        if err == errors::nil && p >= 0 {
            directoryEndOffset = p;
            err = readDirectory64End(r, p, &mut d);
        }
        if err != errors::nil {
            return (None, 0, err);
        }
    }

    let maxInt64: uint64 = (1u64 << 63) - 1;
    if d.directorySize > maxInt64 || d.directoryOffset > maxInt64 {
        return (None, 0, ErrFormat());
    }

    let mut baseOffset =
        directoryEndOffset - int64(d.directorySize) - int64(d.directoryOffset);

    // Go: "Make sure directoryOffset points to somewhere in our file."
    let o = baseOffset + int64(d.directoryOffset);
    if o < 0 || o >= size {
        return (None, 0, ErrFormat());
    }

    // Go: "If the directory end data tells us to use a non-zero
    // baseOffset, but we would find a valid directory entry if we assume
    // that the baseOffset is 0, then just use a baseOffset of 0. We've
    // seen files in which the directory end data gives us an incorrect
    // baseOffset."
    if baseOffset > 0 {
        let off = int64(d.directoryOffset);
        let mut rs = sectionCursor {
            r,
            off,
            limit: size,
        };
        let mut probe = File::default();
        if readDirectoryHeader(&mut probe, &mut rs) == errors::nil {
            baseOffset = 0;
        }
    }

    return (Some(d), baseOffset, errors::nil);
}

// go: sdk 1.25.5 archive/zip/reader.go:647-670 findDirectory64End
/// Go: "findDirectory64End tries to read the zip64 locator just before
/// the directory end and returns the offset of the zip64 directory end
/// if found."
///
/// Every disagreement returns `(-1, nil)` rather than an error — a
/// missing signature, a disk number that is not zero, a disk total that
/// is not one. Go's comment on the last two: "the file is not a valid
/// zip64-file", and the caller then keeps the 32-bit values it already
/// read.
pub fn findDirectory64End(
    r: &mut dyn crate::io::ReaderAt,
    directoryEndOffset: int64,
) -> (int64, crate::error) {
    let locOffset = directoryEndOffset - directory64LocLen;
    if locOffset < 0 {
        // Go: "no need to look for a header outside the file"
        return (-1, errors::nil);
    }
    let mut buf: slice<byte> =
        slice::__from_vec(alloc::vec![0u8; directory64LocLen as usize]);
    let (_, err) = r.ReadAt(&mut buf, locOffset);
    if err != errors::nil {
        return (-1, err);
    }
    let mut b = readBuf::new(buf);
    let sig = b.uint32();
    if sig != directory64LocSignature {
        return (-1, errors::nil);
    }
    // Go: "number of the disk with the start of the zip64 end of
    // central directory"
    if b.uint32() != 0 {
        // Go: "the file is not a valid zip64-file"
        return (-1, errors::nil);
    }
    // Go: "relative offset of the zip64 end of central directory record"
    let p = b.uint64();
    // Go: "total number of disks"
    if b.uint32() != 1 {
        // Go: "the file is not a valid zip64-file"
        return (-1, errors::nil);
    }
    return (int64(p), errors::nil);
}

// go: sdk 1.25.5 archive/zip/reader.go:675-695 readDirectory64End
/// Go: "readDirectory64End reads the zip64 directory end and updates
/// the directory end with the zip64 directory end values."
pub fn readDirectory64End(
    r: &mut dyn crate::io::ReaderAt,
    offset: int64,
    d: &mut directoryEnd,
) -> crate::error {
    let mut buf: slice<byte> =
        slice::__from_vec(alloc::vec![0u8; directory64EndLen as usize]);
    let (_, err) = r.ReadAt(&mut buf, offset);
    if err != errors::nil {
        return err;
    }

    let mut b = readBuf::new(buf);
    let sig = b.uint32();
    if sig != directory64EndSignature {
        return ErrFormat();
    }

    // Go: "skip dir size, version and version needed (uint64 + 2x uint16)"
    b.0 = b.0.slice(12, b.0.Len());
    // Go: "number of this disk"
    d.diskNbr = b.uint32();
    // Go: "number of the disk with the start of the central directory"
    d.dirDiskNbr = b.uint32();
    // Go: "total number of entries in the central directory on this disk"
    d.dirRecordsThisDisk = b.uint64();
    // Go: "total number of entries in the central directory"
    d.directoryRecords = b.uint64();
    // Go: "size of the central directory"
    d.directorySize = b.uint64();
    // Go: "offset of start of central directory with respect to the
    // starting disk number"
    d.directoryOffset = b.uint64();

    return errors::nil;
}
