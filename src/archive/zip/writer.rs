// goishlint:ignore GOISH018 Writer.CreateRaw, Writer.Copy, Writer.RegisterCompressor, Writer.AddFS, Writer.compressor — the four entry points this slice does not have. CreateRaw and Copy write pre-compressed bytes (their shape is `raw: true`, which writeHeader and fileWriter already handle, but neither has a caller yet); RegisterCompressor is the per-Writer override map, the write-side twin of the Reader's; AddFS walks an fs.FS, which needs the fs.File / fs.DirEntry bridge.
// goishlint:ignore GOISH019 Writer — two fields absent: `compressors`, the per-Writer override map RegisterCompressor fills, and `testHookCloseSizeOffset`, a test hook Go's own test sets. Both belong to methods that are not here.
// goishlint:ignore GOISH019 fileWriter — Go EMBEDS `*header`; goish names it `header`. Same field set, one spelling apart, as for `header` and `nopCloser` below.
// goishlint:ignore GOISH019 header — Go EMBEDS `*FileHeader`, so the field has no name and its members promote; goish names it `FileHeader` and callers spell `h.FileHeader.Name`. Same field set, one spelling apart.
// goishlint:ignore GOISH019 nopCloser — Go EMBEDS `io.Writer`, which both names the field and promotes Write; goish names it `Writer` and forwards Write in an impl. Same reason as `header` above.
// goishlint:ignore GOISH020 Writer.prepare — one fewer parameter. Go passes the `*FileHeader` so it can compare it by POINTER with the last directory entry, the check for golang.org/issue/11144's duplicate-header confusion. goish's CreateHeader takes the header by reference and CLONES it, so there is no pointer to alias and the check has nothing to compare; the rest of prepare — closing the previous entry — is unchanged.
// go: file archive/zip/writer.go decls: NewWriter, Writer.SetOffset, Writer.Flush, Writer.SetComment, Writer.Close, Writer.Create, Writer.CreateHeader, Writer.prepare, fileWriter.Write, fileWriter.close, fileWriter.writeDataDescriptor, detectUTF8, writeHeader, dirWriter.Write, countWriter.Write, nopCloser.Close, writeBuf.uint8, writeBuf.uint16, writeBuf.uint32, writeBuf.uint64
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

use super::r#struct::{
    dataDescriptor64Len, dataDescriptorLen, dataDescriptorSignature, directory64EndLen,
    directory64EndSignature, directory64LocLen, directory64LocSignature, directoryEndLen,
    directoryEndSignature, directoryHeaderLen, directoryHeaderSignature, extTimeExtraID,
    fileHeaderLen, fileHeaderSignature, timeToMsDosTime, uint16max, uint32max, zip64ExtraID,
    zipVersion20, zipVersion45, Deflate, FileHeader, Store,
};
use crate::hash::Hash;
use crate::hash::Hash32;
use crate::io::Writer as __IoWriter;
use crate::io::Closer as __IoCloser;
use crate::byte;
use crate::gostring::string;
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


// ─── the Writer ───────────────────────────────────────────────────────
//
// OWNERSHIP, and why this shape. Go's writer is a chain of aliases of
// ONE sink: `fileWriter.zipw` is the Writer's `countWriter`, its
// `compCount` wraps that same countWriter, the compressor wraps
// compCount, and `rawCount` wraps the compressor — and at Close the
// fileWriter reads the counts back out of two of them and MUTATES the
// `*header` that also sits in the Writer's directory slice.
//
// goish spells every one of those aliases `Arc<sync::Mutex<T>>`, which
// io/io.rs makes a Writer and a Closer for exactly this. The upshot is
// that `CreateHeader` hands back an OWNED writer rather than one
// borrowing the Writer, so a caller writes the entry and then calls
// `Close()` on the Writer just as in Go.

// go: none — goish idiom: Go's interface values are pointers, so one
// sink reached from four places is one object. goish spells that
// `Arc<Mutex<T>>`; this alias keeps the signatures readable.
type Shared<T> = alloc::sync::Arc<crate::sync::Mutex<T>>;

// go: none — goish idiom: see `Shared`.
fn __share<T>(v: T) -> Shared<T> {
    return alloc::sync::Arc::new(crate::sync::Mutex::new(v));
}

// go: sdk 1.25.5 archive/zip/writer.go:25-36 Writer
/// Go: "Writer implements a zip file writer."
pub struct Writer<W: io::Writer> {
    pub cw: Shared<countWriter<crate::bufio::Writer<W>>>,
    pub dir: Vec<Shared<header>>,
    pub last: Option<Shared<fileWriter<W>>>,
    pub closed: bool,
    pub comment: string,
}

// go: sdk 1.25.5 archive/zip/writer.go:561-569 fileWriter
/// Go: the per-entry writer `CreateHeader` hands back. It CRCs and
/// counts the plaintext, feeds the compressor, counts the ciphertext,
/// and at close writes the data descriptor.
pub struct fileWriter<W: io::Writer> {
    pub header: Shared<header>,
    pub zipw: Shared<countWriter<crate::bufio::Writer<W>>>,
    pub rawCount: Shared<countWriter<Shared<alloc::boxed::Box<dyn io::WriteCloser>>>>,
    pub comp: Shared<alloc::boxed::Box<dyn io::WriteCloser>>,
    pub compCount: Shared<countWriter<Shared<countWriter<crate::bufio::Writer<W>>>>>,
    pub crc32: crate::hash::crc32::digest,
    pub closed: bool,
}

impl<W: io::Writer> fileWriter<W> {
    // go: sdk 1.25.5 archive/zip/writer.go:571-580 fileWriter.Write
    /// Go: in RAW mode the bytes go straight to the archive; otherwise
    /// they are CRC'd, counted and handed to the compressor.
    pub fn Write(&mut self, p: slice<byte>) -> (int, crate::error) {
        if self.closed {
            return (0, errors::New("zip: write to closed file"));
        }
        if self.header.Lock().raw {
            return self.zipw.Write(p);
        }
        self.crc32.Write(p.clone());
        return self.rawCount.Write(p);
    }
}

impl<W: io::Writer> io::Writer for fileWriter<W> {
    // go: none — goish idiom: Go's *fileWriter satisfies io.Writer by
    // having the method; Rust needs the trait impl spelled out.
    fn Write(&mut self, p: slice<byte>) -> (int, crate::error) {
        return fileWriter::Write(self, p);
    }
}

impl<W: io::Writer> fileWriter<W> {
    // go: sdk 1.25.5 archive/zip/writer.go:580-610 fileWriter.close
    /// Go: close the compressor, then write the true sizes and CRC back
    /// into the header — which the Writer's directory slice shares, so
    /// the central directory sees them — and emit the data descriptor.
    pub fn close(&mut self) -> crate::error {
        if self.closed {
            return errors::New("zip: file closed twice");
        }
        self.closed = true;
        if self.header.Lock().raw {
            return self.writeDataDescriptor();
        }
        let err = self.comp.Close();
        if err != errors::nil {
            return err;
        }

        // Go: "update FileHeader"
        {
            let mut h = self.header.Lock();
            h.FileHeader.CRC32 = self.crc32.Sum32();
            h.FileHeader.CompressedSize64 = uint64(self.compCount.Lock().count);
            h.FileHeader.UncompressedSize64 = uint64(self.rawCount.Lock().count);

            if h.FileHeader.isZip64() {
                h.FileHeader.CompressedSize = uint32max;
                h.FileHeader.UncompressedSize = uint32max;
                // Go: "requires 4.5 - File uses ZIP64 format extensions"
                h.FileHeader.ReaderVersion = zipVersion45;
            } else {
                h.FileHeader.CompressedSize = uint32(h.FileHeader.CompressedSize64);
                h.FileHeader.UncompressedSize = uint32(h.FileHeader.UncompressedSize64);
            }
        }

        return self.writeDataDescriptor();
    }

    // go: sdk 1.25.5 archive/zip/writer.go:612-638 fileWriter.writeDataDescriptor
    /// Go: "This is more complicated than one would think, see e.g.
    /// comments in zipfile.c:putextended() and
    /// https://bugs.openjdk.org/browse/JDK-7073588. The approach here is
    /// to write 8 byte sizes if needed without adding a zip64 extra in
    /// the local header (too late anyway)."
    pub fn writeDataDescriptor(&mut self) -> crate::error {
        let (has64, crc, cs64, us64, cs, us) = {
            let h = self.header.Lock();
            (
                h.FileHeader.isZip64(),
                h.FileHeader.CRC32,
                h.FileHeader.CompressedSize64,
                h.FileHeader.UncompressedSize64,
                h.FileHeader.CompressedSize,
                h.FileHeader.UncompressedSize,
            )
        };
        if !self.header.Lock().FileHeader.hasDataDescriptor() {
            return errors::nil;
        }
        let n = if has64 {
            dataDescriptor64Len
        } else {
            dataDescriptorLen
        };
        let buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; n as usize]);
        let mut b = writeBuf::new(buf);
        // Go: "de-facto standard, required by OS X"
        b.uint32(dataDescriptorSignature);
        b.uint32(crc);
        if has64 {
            b.uint64(cs64);
            b.uint64(us64);
        } else {
            b.uint32(cs);
            b.uint32(us);
        }
        let (_, err) = self.zipw.Write(b.Bytes());
        return err;
    }
}

// go: sdk 1.25.5 archive/zip/writer.go:43-46 NewWriter
/// Go: "NewWriter returns a new Writer writing a zip file to w."
pub fn NewWriter<W: io::Writer>(w: W) -> Writer<W> {
    return Writer {
        cw: __share(countWriter {
            w: crate::bufio::NewWriter(w),
            count: 0,
        }),
        dir: Vec::new(),
        last: None,
        closed: false,
        comment: string::from_static(""),
    };
}

impl<W: io::Writer + 'static> Writer<W> {
    // go: sdk 1.25.5 archive/zip/writer.go:53-58 Writer.SetOffset
    /// Go: "SetOffset sets the offset of the beginning of the zip data
    /// within the underlying writer. It should be used when the zip data
    /// is appended to an existing file, such as a binary executable. It
    /// must be called before any data is written." — and it PANICS if
    /// it was not.
    pub fn SetOffset(&mut self, n: int64) {
        if self.cw.Lock().count != 0 {
            panic!("zip: SetOffset called after data was written");
        }
        self.cw.Lock().count = n;
    }

    // go: sdk 1.25.5 archive/zip/writer.go:62-64 Writer.Flush
    /// Go: "Flush flushes any buffered data to the underlying writer.
    /// Calling Flush is not normally necessary; calling Close is
    /// sufficient."
    pub fn Flush(&mut self) -> crate::error {
        return self.cw.Lock().w.Flush();
    }

    // go: sdk 1.25.5 archive/zip/writer.go:68-74 Writer.SetComment
    /// Go: "SetComment sets the end-of-central-directory comment field.
    /// It can only be called before Writer.Close."
    pub fn SetComment<S: Into<string>>(&mut self, comment: S) -> crate::error {
        let comment: string = comment.into();
        if comment.Len() > int64(uint16max) {
            return errors::New("zip: Writer.Comment too long");
        }
        self.comment = comment;
        return errors::nil;
    }

    // go: sdk 1.25.5 archive/zip/writer.go:251-263 Writer.prepare
    /// Go: "prepare performs the bookkeeping operations required at the
    /// start of CreateHeader and CreateRaw." The duplicate-FileHeader
    /// check cites golang.org/issue/11144; goish compares the header
    /// VALUE rather than the pointer, because goish's FileHeader is not
    /// handed in behind one.
    pub fn prepare(&mut self) -> crate::error {
        let needs_close = match &self.last {
            Some(l) => !l.Lock().closed,
            None => false,
        };
        if needs_close {
            let last = self.last.clone().unwrap();
            let err = last.Lock().close();
            if err != errors::nil {
                return err;
            }
        }
        return errors::nil;
    }

    // go: sdk 1.25.5 archive/zip/writer.go:273-386 Writer.CreateHeader
    /// Go: "CreateHeader adds a file to the zip archive using the
    /// provided FileHeader for the file metadata. ... The file's
    /// contents must be written to the io.Writer before the next call to
    /// Create, CreateHeader, CreateRaw, or Close."
    ///
    /// The UTF-8 decision is Go's and is worth keeping in view: "In
    /// order to avoid breaking readers without UTF-8 support, we avoid
    /// setting the UTF-8 flag if the strings are CP-437 compatible.
    /// However, if the strings require multibyte UTF-8 encoding and is a
    /// valid UTF-8 string, then we set the UTF-8 bit."
    pub fn CreateHeader(
        &mut self,
        fh: &FileHeader,
    ) -> (Option<alloc::boxed::Box<dyn io::Writer>>, crate::error) {
        let err = self.prepare();
        if err != errors::nil {
            return (None, err);
        }
        let mut fh = fh.clone();

        let (utf8Valid1, utf8Require1) = detectUTF8(fh.Name.as_bytes());
        let (utf8Valid2, utf8Require2) = detectUTF8(fh.Comment.as_bytes());
        if fh.NonUTF8 {
            fh.Flags &= !0x800;
        } else if (utf8Require1 || utf8Require2) && (utf8Valid1 && utf8Valid2) {
            fh.Flags |= 0x800;
        }

        // Go: "preserve compatibility byte"
        fh.CreatorVersion = fh.CreatorVersion & 0xff00 | zipVersion20;
        fh.ReaderVersion = zipVersion20;

        // Go: "If Modified is set, this takes precedence over MS-DOS
        // timestamp fields. Contrary to the FileHeader.SetModTime
        // method, we intentionally do not convert to UTC, because we
        // assume the user intends to encode the date using the specified
        // timezone."
        if !fh.Modified.IsZero() {
            let (d, t) = timeToMsDosTime(fh.Modified.clone());
            fh.ModifiedDate = d;
            fh.ModifiedTime = t;

            // Go: "Use 'extended timestamp' format since this is what
            // Info-ZIP uses. ... This format happens to be identical for
            // both local and central header if modification time is the
            // only timestamp being encoded."
            // Go: 2*SizeOf(uint16) + SizeOf(uint8) + SizeOf(uint32)
            let mbuf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 9]);
            let mt = uint32(fh.Modified.Unix());
            let mut eb = writeBuf::new(mbuf);
            eb.uint16(extTimeExtraID);
            // Go: Size: SizeOf(uint8) + SizeOf(uint32)
            eb.uint16(5);
            // Go: Flags: ModTime
            eb.uint8(1);
            // Go: ModTime
            eb.uint32(mt);
            fh.Extra = crate::append!(fh.Extra.clone(), eb.Bytes()...);
        }

        let is_dir = crate::strings::HasSuffix(fh.Name.clone(), "/");
        if is_dir {
            // Go: "Set the compression method to Store to ensure data
            // length is truly zero, which the writeHeader method always
            // encodes for the size fields. This is necessary as most
            // compression formats have non-zero lengths even when
            // compressing an empty string."
            fh.Method = Store;
            // Go: "we will not write a data descriptor"
            fh.Flags &= !0x8;
            // Go: "Explicitly clear sizes as they have no meaning for
            // directories."
            fh.CompressedSize = 0;
            fh.CompressedSize64 = 0;
            fh.UncompressedSize = 0;
            fh.UncompressedSize64 = 0;
        } else {
            // Go: "we will write a data descriptor"
            fh.Flags |= 0x8;
        }

        let h = __share(header {
            FileHeader: fh.clone(),
            offset: uint64(self.cw.Lock().count),
            raw: false,
        });

        let ow: alloc::boxed::Box<dyn io::Writer>;
        let mut fw_shared: Option<Shared<fileWriter<W>>> = None;
        if is_dir {
            ow = alloc::boxed::Box::new(dirWriter::default());
        } else {
            let compCount = __share(countWriter {
                w: self.cw.clone(),
                count: 0,
            });
            let comp = match super::register::compressor(fh.Method) {
                Some(c) => c,
                None => return (None, super::reader::ErrAlgorithm.clone().into()),
            };
            let (c, err) = comp(alloc::boxed::Box::new(compCount.clone()));
            if err != errors::nil {
                return (None, err);
            }
            let comp = __share(c);
            let rawCount = __share(countWriter {
                w: comp.clone(),
                count: 0,
            });
            let fw = __share(fileWriter {
                header: h.clone(),
                zipw: self.cw.clone(),
                rawCount,
                comp,
                compCount,
                crc32: crate::hash::crc32::NewIEEE(),
                closed: false,
            });
            fw_shared = Some(fw.clone());
            ow = alloc::boxed::Box::new(fw);
        }
        self.dir.push(h.clone());
        let err = {
            let hh = h.Lock().clone();
            let mut cw = self.cw.clone();
            writeHeader(&mut cw, &hh)
        };
        if err != errors::nil {
            return (None, err);
        }
        // Go: "If we're creating a directory, fw is nil."
        self.last = fw_shared;
        return (Some(ow), errors::nil);
    }

    // go: sdk 1.25.5 archive/zip/writer.go:218-228 Writer.Create
    /// Go: "Create adds a file to the zip file using the provided name.
    /// ... The file contents will be compressed using the Deflate
    /// method."
    pub fn Create<S: Into<string>>(
        &mut self,
        name: S,
    ) -> (Option<alloc::boxed::Box<dyn io::Writer>>, crate::error) {
        let mut header = FileHeader::default();
        header.Name = name.into();
        header.Method = Deflate;
        return self.CreateHeader(&header);
    }

    // go: sdk 1.25.5 archive/zip/writer.go:76-207 Writer.Close
    /// Go: "Close finishes writing the zip file by writing the central
    /// directory. It does not close the underlying writer."
    pub fn Close(&mut self) -> crate::error {
        let needs_close = match &self.last {
            Some(l) => !l.Lock().closed,
            None => false,
        };
        if needs_close {
            let last = self.last.clone().unwrap();
            let err = last.Lock().close();
            if err != errors::nil {
                return err;
            }
            self.last = None;
        }
        if self.closed {
            return errors::New("zip: writer closed twice");
        }
        self.closed = true;

        // Go: "write central directory"
        let start = self.cw.Lock().count;
        for hs in self.dir.clone().iter() {
            let mut h = hs.Lock().clone();
            let buf: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; directoryHeaderLen as usize]);
            let mut b = writeBuf::new(buf);
            b.uint32(uint32(directoryHeaderSignature));
            b.uint16(h.FileHeader.CreatorVersion);
            b.uint16(h.FileHeader.ReaderVersion);
            b.uint16(h.FileHeader.Flags);
            b.uint16(h.FileHeader.Method);
            b.uint16(h.FileHeader.ModifiedTime);
            b.uint16(h.FileHeader.ModifiedDate);
            b.uint32(h.FileHeader.CRC32);
            if h.FileHeader.isZip64() || h.offset >= uint64(uint32max) {
                // Go: "the file needs a zip64 header. store maxint in
                // both 32 bit size fields (and offset later) to signal
                // that the zip64 extra header should be used."
                // Go: compressed size
                b.uint32(uint32max);
                // Go: uncompressed size
                b.uint32(uint32max);

                // Go: "append a zip64 extra block to Extra"
                // Go: 2x uint16 + 3x uint64
                let ebuf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 28]);
                let mut eb = writeBuf::new(ebuf);
                eb.uint16(zip64ExtraID);
                // Go: size = 3x uint64
                eb.uint16(24);
                eb.uint64(h.FileHeader.UncompressedSize64);
                eb.uint64(h.FileHeader.CompressedSize64);
                eb.uint64(h.offset);
                h.FileHeader.Extra = crate::append!(h.FileHeader.Extra.clone(), eb.Bytes()...);
            } else {
                b.uint32(h.FileHeader.CompressedSize);
                b.uint32(h.FileHeader.UncompressedSize);
            }

            b.uint16(uint16(h.FileHeader.Name.Len()));
            b.uint16(uint16(h.FileHeader.Extra.Len()));
            b.uint16(uint16(h.FileHeader.Comment.Len()));
            // Go: "skip disk number start and internal file attr (2x uint16)"
            b.off += 4;
            b.uint32(h.FileHeader.ExternalAttrs);
            if h.offset > uint64(uint32max) {
                b.uint32(uint32max);
            } else {
                b.uint32(uint32(h.offset));
            }
            let (_, err) = self.cw.Write(b.Bytes());
            if err != errors::nil {
                return err;
            }
            let (_, err) = self
                .cw
                .Write(slice::__from_vec(h.FileHeader.Name.as_bytes().to_vec()));
            if err != errors::nil {
                return err;
            }
            let (_, err) = self.cw.Write(h.FileHeader.Extra.clone());
            if err != errors::nil {
                return err;
            }
            let (_, err) = self
                .cw
                .Write(slice::__from_vec(h.FileHeader.Comment.as_bytes().to_vec()));
            if err != errors::nil {
                return err;
            }
        }
        let end = self.cw.Lock().count;

        let mut records = uint64(crate::int64(self.dir.len()));
        let mut size = uint64(end - start);
        let mut offset = uint64(start);

        if records >= uint64(uint16max) || size >= uint64(uint32max) || offset >= uint64(uint32max)
        {
            let buf: slice<byte> = slice::__from_vec(
                alloc::vec![0u8; (directory64EndLen + directory64LocLen) as usize],
            );
            let mut b = writeBuf::new(buf);

            // Go: "zip64 end of central directory record"
            b.uint32(directory64EndSignature);
            // Go: "length minus signature (uint32) and length fields (uint64)"
            b.uint64(uint64(directory64EndLen - 12));
            // Go: "version made by"
            b.uint16(zipVersion45);
            // Go: "version needed to extract"
            b.uint16(zipVersion45);
            // Go: "number of this disk"
            b.uint32(0);
            // Go: "number of the disk with the start of the central directory"
            b.uint32(0);
            // Go: "total number of entries in the central directory on this disk"
            b.uint64(records);
            // Go: "total number of entries in the central directory"
            b.uint64(records);
            // Go: "size of the central directory"
            b.uint64(size);
            // Go: "offset of start of central directory with respect to
            // the starting disk number"
            b.uint64(offset);

            // Go: "zip64 end of central directory locator"
            b.uint32(directory64LocSignature);
            // Go: "number of the disk with the start of the zip64 end of
            // central directory"
            b.uint32(0);
            // Go: "relative offset of the zip64 end of central directory record"
            b.uint64(uint64(end));
            // Go: "total number of disks"
            b.uint32(1);

            let (_, err) = self.cw.Write(b.Bytes());
            if err != errors::nil {
                return err;
            }

            // Go: "store max values in the regular end record to signal
            // that the zip64 values should be used instead"
            records = uint64(uint16max);
            size = uint64(uint32max);
            offset = uint64(uint32max);
        }

        // Go: "write end record"
        let buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; directoryEndLen as usize]);
        let mut b = writeBuf::new(buf);
        b.uint32(uint32(directoryEndSignature));
        // Go: "skip over disk number and first disk number (2x uint16)"
        b.off += 4;
        // Go: "number of entries this disk"
        b.uint16(uint16(records));
        // Go: "number of entries total"
        b.uint16(uint16(records));
        // Go: "size of directory"
        b.uint32(uint32(size));
        // Go: "start of directory"
        b.uint32(uint32(offset));
        // Go: "byte size of EOCD comment"
        b.uint16(uint16(self.comment.Len()));
        let (_, err) = self.cw.Write(b.Bytes());
        if err != errors::nil {
            return err;
        }
        let (_, err) = self
            .cw
            .Write(slice::__from_vec(self.comment.as_bytes().to_vec()));
        if err != errors::nil {
            return err;
        }

        return self.cw.Lock().w.Flush();
    }
}
