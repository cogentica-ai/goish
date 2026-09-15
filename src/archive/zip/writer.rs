// goishlint:ignore GOISH018 NewWriter, Writer.SetOffset, Writer.Flush, Writer.SetComment, Writer.Close, Writer.Create, Writer.CreateHeader, Writer.prepare, Writer.CreateRaw, Writer.Copy, Writer.RegisterCompressor, Writer.AddFS, Writer.compressor, fileWriter.Write, fileWriter.close, fileWriter.writeDataDescriptor — the Writer ITSELF, absent from this slice. This one ports the byte-level pieces it is built from — writeHeader, writeBuf, countWriter, dirWriter, nopCloser — which are what a reference can pin exactly; the Writer that drives them lands next, with the compressor registry's write half.
// goishlint:ignore GOISH021 Writer, fileWriter — the Writer and the per-entry writer it hands out, absent with the methods above.
// goishlint:ignore GOISH019 header — Go EMBEDS `*FileHeader`, so the field has no name and its members promote; goish names it `FileHeader` and callers spell `h.FileHeader.Name`. Same field set, one spelling apart.
// goishlint:ignore GOISH019 nopCloser — Go EMBEDS `io.Writer`, which both names the field and promotes Write; goish names it `Writer` and forwards Write in an impl. Same reason as `header` above.
// go: file archive/zip/writer.go decls: detectUTF8, writeHeader, dirWriter.Write, countWriter.Write, nopCloser.Close, writeBuf.uint8, writeBuf.uint16, writeBuf.uint32, writeBuf.uint64
//
// archive/zip/writer.go — the byte-level half.
//
// `writeHeader` is the mirror of reader.go's `readDirectoryHeader`, and
// the one thing in it worth reading twice is which sizes it writes.
// When THIS package does the compression it cannot know the sizes yet,
// so it writes three zeros and puts the real values in the trailing
// data descriptor. Only in RAW mode, where the caller compressed the
// bytes itself and did not ask for a descriptor, are they written here
// — and then they are clamped to `uint32max`, which is the escape
// marker the zip64 extra field replaces.
//
// `detectUTF8` is the writer's, but the READER calls it: a central
// directory header's name and comment are raw bytes, and Go decides
// whether to set FileHeader.NonUTF8 by running exactly this test over
// them.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::r#struct::{fileHeaderLen, fileHeaderSignature, uint32max, FileHeader};
use crate::byte;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::int;
use crate::int64;
use crate::io;
use crate::uint16;
use crate::uint32;
use crate::uint64;

// go: sdk 1.25.5 archive/zip/writer.go:231-249 detectUTF8
/// Go: "Officially, ZIP uses CP-437, but many readers use the system's
/// local character encoding. Most encoding are compatible with a large
/// subset of CP-437, which itself is ASCII-like. Forbid 0x7e and 0x5c
/// since EUC-KR and Shift-JIS replace those characters with localized
/// currency and overline characters."
///
/// Returns `(valid, require)`: valid is false the moment a byte
/// sequence is not UTF-8 at all; require becomes true once some
/// character outside the safe CP-437 subset appears, which is what
/// tells the writer it must set the UTF-8 flag.
///
/// The parameter is BYTES, not `&str`. Go's `s` is a `string`, which is
/// arbitrary bytes, and deciding whether those bytes are valid UTF-8 is
/// the entire job — a `&str` cannot hold the failing input, and goish's
/// `string: AsRef<str>` would silently truncate it at the first invalid
/// byte. `readDirectoryHeader` feeds it a name read straight off the
/// wire.
pub fn detectUTF8(s: &[byte]) -> (bool, bool) {
    let mut require = false;
    let mut i: usize = 0;
    while i < s.len() {
        let (r, size) = crate::unicode::utf8::DecodeRune(&s[i..]);
        let size = size as usize;
        i += size;
        if r < 0x20 || r > 0x7d || r == 0x5c {
            if !crate::unicode::utf8::ValidRune(r)
                || (r == crate::unicode::utf8::RuneError && size == 1)
            {
                return (false, false);
            }
            require = true;
        }
    }
    return (true, require);
}

// go: sdk 1.25.5 archive/zip/writer.go:19-22 errLongName
/// Go's two length-limit errors. `crate::var!` for the same reason
/// reader.go's sentinels are: Go compares them by identity.
crate::var! {
    pub errLongName: error = "zip: FileHeader.Name too long";
    pub errLongExtra: error = "zip: FileHeader.Extra too long";
}

// go: sdk 1.25.5 archive/zip/writer.go:38-42 header
/// Go: a `*FileHeader` plus where it landed and whether the caller
/// compressed it. The central directory is a slice of these.
#[derive(Clone, Default)]
pub struct header {
    pub FileHeader: FileHeader,
    pub offset: uint64,
    pub raw: bool,
}

// go: sdk 1.25.5 archive/zip/writer.go:660-660 writeBuf
/// Go: `type writeBuf []byte` — the mirror of reader.go's `readBuf`,
/// and like it each write RESLICES, so the remaining length is the only
/// bound.
///
/// Go's writeBuf ALIASES the caller's array: `b := writeBuf(buf[:])`
/// fills `buf`, and the caller then writes `buf` out. goish's slices
/// are values, so this holds the buffer and an offset instead, and
/// `Bytes()` hands the whole filled buffer back. `Len()` is Go's — the
/// REMAINING room, not the capacity.
#[derive(Clone, Default)]
pub struct writeBuf {
    pub buf: slice<byte>,
    pub off: int,
}

impl writeBuf {
    // go: none — goish idiom: Go writes `writeBuf(buf[:])`, a
    // conversion; goish's carries an offset and needs a constructor.
    pub fn new(b: slice<byte>) -> Self {
        return writeBuf { buf: b, off: 0 };
    }

    // go: none — goish idiom: Go asks `len(b)` of the reslice, which is
    // the room LEFT.
    pub fn Len(&self) -> int {
        return self.buf.Len() - self.off;
    }

    // go: none — goish idiom: Go's caller reads the array the writeBuf
    // aliased; goish's reads it back from here.
    pub fn Bytes(&self) -> slice<byte> {
        return self.buf.clone();
    }

    // go: sdk 1.25.5 archive/zip/writer.go:662-665 writeBuf.uint8
    pub fn uint8(&mut self, v: byte) {
        self.buf[self.off] = v;
        self.off += 1;
    }

    // go: sdk 1.25.5 archive/zip/writer.go:667-670 writeBuf.uint16
    pub fn uint16(&mut self, v: uint16) {
        let mut tmp: [byte; 2] = [0; 2];
        crate::encoding::binary::LittleEndian.PutUint16(&mut tmp[..], v);
        let mut i: int = 0;
        while i < 2 {
            self.buf[self.off + i] = tmp[i as usize];
            i += 1;
        }
        self.off += 2;
    }

    // go: sdk 1.25.5 archive/zip/writer.go:672-675 writeBuf.uint32
    pub fn uint32(&mut self, v: uint32) {
        let mut tmp: [byte; 4] = [0; 4];
        crate::encoding::binary::LittleEndian.PutUint32(&mut tmp[..], v);
        let mut i: int = 0;
        while i < 4 {
            self.buf[self.off + i] = tmp[i as usize];
            i += 1;
        }
        self.off += 4;
    }

    // go: sdk 1.25.5 archive/zip/writer.go:677-680 writeBuf.uint64
    pub fn uint64(&mut self, v: uint64) {
        let mut tmp: [byte; 8] = [0; 8];
        crate::encoding::binary::LittleEndian.PutUint64(&mut tmp[..], v);
        let mut i: int = 0;
        while i < 8 {
            self.buf[self.off + i] = tmp[i as usize];
            i += 1;
        }
        self.off += 8;
    }
}

// go: sdk 1.25.5 archive/zip/writer.go:639-643 countWriter
/// Go: an `io.Writer` that remembers how many bytes went through it.
/// The Writer keeps one so a header can record its own offset.
pub struct countWriter<W: io::Writer> {
    pub w: W,
    pub count: int64,
}

impl<W: io::Writer> countWriter<W> {
    // go: sdk 1.25.5 archive/zip/writer.go:645-649 countWriter.Write
    /// Go: counts what the inner writer ACCEPTED, not what was offered,
    /// so a short write leaves the count honest.
    pub fn Write(&mut self, p: slice<byte>) -> (int, crate::error) {
        let (n, err) = self.w.Write(p);
        self.count += int64(n);
        return (n, err);
    }
}

impl<W: io::Writer> io::Writer for countWriter<W> {
    // go: none — goish idiom: Go's *countWriter satisfies io.Writer by
    // having the method; Rust needs the trait impl spelled out.
    fn Write(&mut self, p: slice<byte>) -> (int, crate::error) {
        return countWriter::Write(self, p);
    }
}

// go: sdk 1.25.5 archive/zip/writer.go:652-654 nopCloser
/// Go: an `io.Writer` given a no-op Close, so the Store method can be
/// registered as a Compressor alongside Deflate.
pub struct nopCloser<W: io::Writer> {
    pub Writer: W,
}

impl<W: io::Writer> nopCloser<W> {
    // go: sdk 1.25.5 archive/zip/writer.go:656-658 nopCloser.Close
    /// Go: `return nil`.
    pub fn Close(&mut self) -> crate::error {
        return errors::nil;
    }
}

impl<W: io::Writer> io::Writer for nopCloser<W> {
    // go: none — goish idiom: Go EMBEDS io.Writer, which promotes the
    // method; Rust needs the forwarding impl written out.
    fn Write(&mut self, p: slice<byte>) -> (int, crate::error) {
        return self.Writer.Write(p);
    }
}

impl<W: io::Writer> io::Closer for nopCloser<W> {
    // go: none — goish idiom: see the Writer impl above.
    fn Close(&mut self) -> crate::error {
        return nopCloser::Close(self);
    }
}

// go: sdk 1.25.5 archive/zip/writer.go:552-552 dirWriter
/// Go: the writer a directory entry gets. An EMPTY write succeeds — Go
/// returns `(0, nil)` before the error — so a caller that writes
/// nothing is fine and one that writes a byte is not.
#[derive(Clone, Default)]
pub struct dirWriter {}

impl dirWriter {
    // go: sdk 1.25.5 archive/zip/writer.go:554-559 dirWriter.Write
    /// Go: see the note on the struct.
    pub fn Write(&mut self, b: slice<byte>) -> (int, crate::error) {
        if b.Len() == 0 {
            return (0, errors::nil);
        }
        return (0, errors::New("zip: write to directory"));
    }
}

impl io::Writer for dirWriter {
    // go: none — goish idiom: Go's dirWriter satisfies io.Writer by
    // having the method; Rust needs the trait impl spelled out.
    fn Write(&mut self, p: slice<byte>) -> (int, crate::error) {
        return dirWriter::Write(self, p);
    }
}

// go: sdk 1.25.5 archive/zip/writer.go:386-430 writeHeader
/// Go: writes a LOCAL file header.
///
/// The sizes are the part to read twice. When this package does the
/// compression it cannot know them yet, so it writes three zeros and
/// puts the real values in the trailing data descriptor — which is what
/// the `nonraw-with-desc` and `plain` reference rows show. Only in RAW
/// mode with no descriptor are they written here, clamped to
/// `uint32max`, which is the escape marker the zip64 extra field
/// replaces.
pub fn writeHeader<W: io::Writer + ?Sized>(w: &mut W, h: &header) -> crate::error {
    let maxUint16: int = (1 << 16) - 1;
    if h.FileHeader.Name.Len() > maxUint16 {
        return errLongName.clone().into();
    }
    if h.FileHeader.Extra.Len() > maxUint16 {
        return errLongExtra.clone().into();
    }

    let buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; fileHeaderLen as usize]);
    let mut b = writeBuf::new(buf);
    b.uint32(uint32(fileHeaderSignature));
    b.uint16(h.FileHeader.ReaderVersion);
    b.uint16(h.FileHeader.Flags);
    b.uint16(h.FileHeader.Method);
    b.uint16(h.FileHeader.ModifiedTime);
    b.uint16(h.FileHeader.ModifiedDate);
    // Go: "In raw mode (caller does the compression), the values are
    // either written here or in the trailing data descriptor based on
    // the header flags."
    if h.raw && !h.FileHeader.hasDataDescriptor() {
        b.uint32(h.FileHeader.CRC32);
        b.uint32(uint32(__min_u64(h.FileHeader.CompressedSize64, uint64(uint32max))));
        b.uint32(uint32(__min_u64(h.FileHeader.UncompressedSize64, uint64(uint32max))));
    } else {
        // Go: "When this package handle the compression, these values
        // are always written to the trailing data descriptor."
        // Go: crc32
        b.uint32(0);
        // Go: compressed size
        b.uint32(0);
        // Go: uncompressed size
        b.uint32(0);
    }
    b.uint16(uint16(h.FileHeader.Name.Len()));
    b.uint16(uint16(h.FileHeader.Extra.Len()));
    // Go writes the array the writeBuf aliased; goish reads it back out
    // of the writeBuf, which is the same bytes.
    let (_, err) = w.Write(b.Bytes());
    if err != errors::nil {
        return err;
    }
    // Go: `io.WriteString(w, h.Name)`; goish's WriteString wants a
    // sized writer, and the bytes are the same either way.
    let (_, err) = w.Write(slice::__from_vec(h.FileHeader.Name.as_bytes().to_vec()));
    if err != errors::nil {
        return err;
    }
    let (_, err) = w.Write(h.FileHeader.Extra.clone());
    return err;
}

// go: none — goish idiom: Go 1.21's builtin `min` over two uint64s.
fn __min_u64(a: uint64, b: uint64) -> uint64 {
    if a < b {
        return a;
    }
    return b;
}

