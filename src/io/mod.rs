// io — Go's `io` package, ported.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   type Reader interface {              pub trait Reader {
//       Read(p []byte) (n int, err error)    fn Read(&mut self, p: &mut slice<byte>) -> (int, error);
//   }                                     }
//
//   type Writer interface {              pub trait Writer {
//       Write(p []byte) (n int, err error)   fn Write(&mut self, p: slice<byte>) -> (int, error);
//   }                                     }
//
//   var EOF = errors.New("EOF")          pub fn EOF.into() -> error  // cached, ptr-stable
//   io.Copy(dst, src)                     io::Copy(dst, src) -> (int64, error)
//   io.WriteString(w, s)                  io::WriteString(w, s) -> (int, error)
//
// Method-receiver trait shape: `&mut self` mirrors Go's `*File` /
// pointer receiver — both express "needs exclusive access to the
// underlying resource (fd cursor, buffer position)".
//
// Buffer arguments:
//   - `Write` takes `slice<byte>` by value (consumed). Call sites read
//     as Go: `w.Write(buf)`. Trade: caller can't reuse `buf` after.
//   - `Read` takes `&mut slice<byte>` — unavoidable; the function must
//     mutate the caller's buffer in place to honor Go's pre-allocate
//     idiom.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::error;
use crate::goslice::slice;
use crate::types::{byte, int};
use crate::errors::{self, nil};

// ─── Reader / Writer / Closer traits ───────────────────────────────────

/// Go's `io.Reader`. Read up to `len(p)` bytes into `p`; returns
/// `(n, err)`. EOF is signaled by returning `io::EOF` as the error.
#[goish::interface]
pub trait Reader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error);
}

/// Go's `io.Writer`. Write `len(p)` bytes from `p`. Returns `(n, err)`
/// where `n < len(p)` requires a non-nil `err`.
#[goish::interface]
pub trait Writer {
    fn Write(&mut self, p: slice<byte>) -> (int, error);
}

/// Go's `io.Closer`.
#[goish::interface]
pub trait Closer {
    fn Close(&mut self) -> error;
}

/// Go's `io.ReadCloser` — combines [`Reader`] and [`Closer`].
pub trait ReadCloser: Reader + Closer {}

/// Blanket impl: any type that implements both `Reader` and `Closer`
/// automatically implements `ReadCloser`.
impl<T: Reader + Closer> ReadCloser for T {}

/// Go's `io.Seeker` (io.go:126). Reposition the read/write head.
/// Whence is one of `SeekStart`, `SeekCurrent`, `SeekEnd`.
#[goish::interface]
pub trait Seeker {
    fn Seek(&mut self, offset: i64, whence: int) -> (i64, error);
}

/// Whence values for [`Seeker::Seek`] (io.go:22).
pub const SeekStart: int = 0;
pub const SeekCurrent: int = 1;
pub const SeekEnd: int = 2;

/// Go's `io.ReaderAt` (io.go:230). Random-access read at byte offset
/// `off`. Implementations must not retain `p` across the call.
#[goish::interface]
pub trait ReaderAt {
    fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error);
}

/// Go's `io.WriterAt` (io.go:249). Random-access write at byte offset
/// `off`. Implementations must not retain `p` across the call.
#[goish::interface]
pub trait WriterAt {
    fn WriteAt(&mut self, p: slice<byte>, off: i64) -> (int, error);
}

/// Go's `io.ByteReader` (io.go:262).
#[goish::interface]
pub trait ByteReader {
    fn ReadByte(&mut self) -> (byte, error);
}

/// Go's `io.ByteScanner` (io.go:274).
pub trait ByteScanner: ByteReader {
    fn UnreadByte(&mut self) -> error;
}

/// Go's `io.ByteWriter` (io.go:280).
#[goish::interface]
pub trait ByteWriter {
    fn WriteByte(&mut self, c: byte) -> error;
}

/// Go's `io.RuneReader` (io.go:289).
#[goish::interface]
pub trait RuneReader {
    fn ReadRune(&mut self) -> (crate::types::rune, int, error);
}

/// Go's `io.RuneScanner` (io.go:301). Extends RuneReader with the
/// ability to push back the last-read rune. Surfaced by gopkg.in/
/// inf.v0's `Dec.scan(r io.RuneScanner)` parser path.
pub trait RuneScanner: RuneReader {
    fn UnreadRune(&mut self) -> error;
}

/// Go's `io.StringWriter` (io.go:307).
#[goish::interface]
pub trait StringWriter {
    fn WriteString(&mut self, s: crate::gostring::string) -> (int, error);
}

/// Go's `io.ReaderFrom` (io.go:189). Used by `Copy` for fast-path
/// fan-in when the destination supports it.
#[goish::interface]
pub trait ReaderFrom {
    fn ReadFrom(&mut self, r: &mut dyn Reader) -> (i64, error);
}

/// Go's `io.WriterTo` (io.go:200). Used by `Copy` for fast-path
/// fan-out when the source supports it.
#[goish::interface]
pub trait WriterTo {
    fn WriteTo(&mut self, w: &mut dyn Writer) -> (i64, error);
}

// Blanket impls so `Box<dyn T>` satisfies the trait. The `&mut R`
// blanket is now auto-emitted by `#[goish::interface]` (section 6.7a
// of goish-macros); the Box<R> blanket below is retained because
// Box<dyn T> needs the same dispatch shape for owned trait-object
// callers and the macro doesn't emit it yet.
impl<R: Reader + ?Sized> Reader for alloc::boxed::Box<R> {
    #[inline]
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        (**self).Read(p)
    }
}

impl<W: Writer + ?Sized> Writer for alloc::boxed::Box<W> {
    #[inline]
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        (**self).Write(p)
    }
}

impl<C: Closer + ?Sized> Closer for alloc::boxed::Box<C> {
    #[inline]
    fn Close(&mut self) -> error {
        (**self).Close()
    }
}

// ─── Sentinel errors ───────────────────────────────────────────────────
//
// Go pattern: `var EOF = errors.New("EOF")` — a single Arc value used
// for `if err == io.EOF` comparisons. We achieve the same by lazily
// initializing each sentinel into a static SpinLock-protected slot;
// every call to `EOF.into()` returns a clone of the *same* Arc, so
// `errors::Is(err, io::EOF)` succeeds via Arc::ptr_eq.
//
// When OnceLock-equivalent infrastructure lands in goish::sync, these
// helpers swap to a lock-free read fast-path. The shape stays.

use crate::runtime::spin::SpinLock;

fn cached_error(slot: &SpinLock<Option<error>>, init: fn() -> error) -> error {
    let mut g = slot.lock();
    if g.is_none() {
        *g = Some(init());
    }
    g.as_ref().unwrap().clone()
}

// io sentinels — Doctrine 2 marker form. Use sites compare bare:
//   if errors::Is(err, io::EOF) { ... }
//   if err == io::EOF { ... }
//   return io::EOF.into();   // .into() needed for return slot
crate::var! {
    /// `io.EOF` — sentinel returned by Reader.Read at end-of-input.
    pub EOF: error = "EOF";

    /// `io.ErrShortWrite` — Writer wrote fewer bytes than requested,
    /// non-nil error, no other reason.
    pub ErrShortWrite: error = "short write";

    /// `io.ErrUnexpectedEOF` — Reader hit EOF mid-record (e.g. ReadFull
    /// got fewer bytes than buffer length).
    pub ErrUnexpectedEOF: error = "unexpected EOF";

    /// `io.ErrShortBuffer` — provided buffer was too small.
    pub ErrShortBuffer: error = "short buffer";

    /// `io.ErrNoProgress` — Reader returned no bytes and no error across
    /// many consecutive Read calls; clients use this to break livelocks.
    pub ErrNoProgress: error = "multiple Read calls return no data or error";
}

// ─── Copy / WriteString ────────────────────────────────────────────────

/// `io.Copy(dst, src)` — copy from src to dst until EOF. Returns the
/// number of bytes copied and the first error encountered (other than
/// `io.EOF`, which is normal termination).
///
/// Buffer size: 32 KiB (matches Go's default genericReadFrom path).
pub fn Copy(dst: &mut dyn Writer, src: &mut dyn Reader) -> (i64, error) {
    let mut total: i64 = 0;
    let mut buf = crate::make!([]byte, 32 * 1024);
    let eof: error = EOF.into();
    loop {
        let (n, rerr) = src.Read(&mut buf);
        if n > 0 {
            // Hand only the first n bytes to the writer.
            let chunk = buf.slice(0, n);
            let chunk_len = chunk.Len();
            let (wn, werr) = dst.Write(chunk);
            total += wn as i64;
            if werr != nil {
                return (total, werr);
            }
            if (wn as int) < chunk_len {
                return (total, ErrShortWrite.into());
            }
        }
        if rerr != nil {
            // EOF is a normal end-of-input signal in Go: not propagated.
            if rerr == eof {
                return (total, nil);
            }
            return (total, rerr);
        }
    }
}

/// `io.WriteString(w, s)` — convenience: write a string to a Writer.
pub fn WriteString<S: Into<crate::gostring::string>>(
    w: &mut dyn Writer,
    s: S,
) -> (int, error) {
    let buf = crate::convert::bytes(s.into());
    w.Write(buf)
}

/// `io.CopyBuffer(dst, src, buf)` (io.go:398) — like Copy but stages
/// through the caller-supplied buffer. If `buf` is nil (zero-length
/// slice constructed via `make!([]byte, 0)`), CopyBuffer allocates one
/// internally — slim deviation from Go which panics on empty (non-nil)
/// buffer; goish has no nil/empty distinction for slices, so any
/// zero-length buf triggers the internal allocation.
///
/// **Slim deviation from Go**: doesn't try src.WriteTo / dst.ReadFrom
/// fast paths (goish doesn't yet have an io::WriterTo / io::ReaderFrom
/// trait surface for runtime dispatch). Always stages through the
/// buffer.
pub fn CopyBuffer(
    dst: &mut dyn Writer,
    src: &mut dyn Reader,
    buf: slice<byte>,
) -> (i64, error) {
    // Go: if buf == nil { buf = make([]byte, size) } — goish: if the
    // caller passed an empty slice, allocate the default 32 KiB.
    let mut buf = if buf.Len() == 0 {
        crate::make!([]byte, 32 * 1024)
    } else {
        buf
    };
    // Go: var written int64; for { nr, er := src.Read(buf); ... }
    let mut written: i64 = 0;
    let eof: error = EOF.into();
    loop {
        let (nr, rerr) = src.Read(&mut buf);
        if nr > 0 {
            // Go: nw, ew := dst.Write(buf[0:nr])
            let chunk = buf.slice(0, nr);
            let chunk_len = chunk.Len();
            let (nw, werr) = dst.Write(chunk);
            written += nw as i64;
            // Go: if ew != nil { err = ew; break }
            if werr != nil {
                return (written, werr);
            }
            // Go: if nr != nw { err = ErrShortWrite; break }
            if (nw as int) < chunk_len {
                return (written, ErrShortWrite.into());
            }
        }
        // Go: if er != nil { if er != EOF { err = er }; break }
        if rerr != nil {
            if rerr == eof {
                return (written, nil);
            }
            return (written, rerr);
        }
    }
}

// ─── LimitReader / LimitedReader ─────────────────────────────────────

/// `io.LimitedReader` (io.go:467). Reads from `R` but stops at `N` bytes.
pub struct LimitedReader<R: Reader> {
    pub R: R,
    pub N: int,
}

impl<R: Reader> Reader for LimitedReader<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: if l.N <= 0 { return 0, EOF }
        if self.N <= 0 {
            return (0, EOF.into());
        }
        // Go: if int64(len(p)) > l.N { p = p[0:l.N] }
        // We can't shrink p in place (caller-owned); read into a tmp.
        let cap = if p.Len() > self.N { self.N } else { p.Len() };
        let mut tmp = crate::make!([]byte, cap);
        let (n, err) = self.R.Read(&mut tmp);
        // Copy what was read into the caller's buffer.
        for i in 0..n {
            p[i] = tmp[i];
        }
        // Go: l.N -= int64(n)
        self.N -= n;
        (n, err)
    }
}

/// `io.LimitReader(r, n)` (io.go:461) — return a Reader that reads at
/// most `n` bytes from `r` before signaling EOF.
pub fn LimitReader<R: Reader>(r: R, n: int) -> LimitedReader<R> {
    LimitedReader { R: r, N: n }
}

// ─── TeeReader ───────────────────────────────────────────────────────

/// `io.teeReader` (io.go:622) — Reader that mirrors all reads to a Writer.
pub struct TeeReaderImpl<R: Reader, W: Writer> {
    r: R,
    w: W,
}

impl<R: Reader, W: Writer> Reader for TeeReaderImpl<R, W> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: n, err = t.r.Read(p)
        let (n, err) = self.r.Read(p);
        // Go: if n > 0 { if n, err := t.w.Write(p[:n]); err != nil { return n, err } }
        if n > 0 {
            let chunk = p.slice(0, n);
            let (wn, werr) = self.w.Write(chunk);
            if !werr.IsNil() {
                return (wn, werr);
            }
        }
        (n, err)
    }
}

/// `io.TeeReader(r, w)` (io.go:618) — every Read also writes to `w`.
/// Errors from `w` surface as Read errors.
pub fn TeeReader<R: Reader, W: Writer>(r: R, w: W) -> TeeReaderImpl<R, W> {
    TeeReaderImpl { r, w }
}

// ─── Discard ─────────────────────────────────────────────────────────

/// `io.Discard` analogue (io.go:639). A Writer whose every Write
/// silently succeeds. Use as a sink for body draining or benchmarks.
///
/// Go exposes `Discard` as a singleton; goish exposes a constructor
/// because static-trait-object initialization is unwieldy here.
pub struct Discard;

/// Construct a fresh Discard writer.
pub fn DiscardWriter() -> Discard {
    Discard
}

impl Writer for Discard {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: return len(p), nil
        (p.Len(), nil)
    }
}

// ─── Empty / Null counterparts ──────────────────────────────────────

/// Reader counterpart to `Discard` — every `Read` returns `(0, EOF)`.
/// Mirrors the behaviour of an empty `bytes.Reader`. Used as the
/// default sentinel for `Box<dyn io::Reader>` struct fields when a
/// goishc-generated `Default` impl needs a concrete value.
pub struct Empty;

/// Construct a fresh Empty reader.
pub fn EmptyReader() -> Empty {
    Empty
}

impl Reader for Empty {
    fn Read(&mut self, _p: &mut slice<byte>) -> (int, error) {
        (0, EOF.into())
    }
}

/// Closer counterpart whose `Close` is a no-op returning nil. Used as
/// the default sentinel for `Box<dyn io::Closer>` struct fields.
pub struct NullCloser;

/// Construct a fresh NullCloser.
pub fn NopCloser_() -> NullCloser {
    NullCloser
}

impl Closer for NullCloser {
    fn Close(&mut self) -> error {
        nil.into()
    }
}

// ─── NopCloser ───────────────────────────────────────────────────────

/// `io.NopCloser(r)` analogue (io.go:682). Wraps a Reader so Close is
/// a no-op. WriterTo special case is dropped (slim port).
pub struct NopCloserImpl<R: Reader> {
    r: R,
}

impl<R: Reader> Reader for NopCloserImpl<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        self.r.Read(p)
    }
}

impl<R: Reader> Closer for NopCloserImpl<R> {
    fn Close(&mut self) -> error {
        nil
    }
}

/// `io.NopCloser(r)` (io.go:682) — produce a `Reader+Closer` whose
/// Close is a no-op.
pub fn NopCloser<R: Reader>(r: R) -> NopCloserImpl<R> {
    NopCloserImpl { r }
}

// ─── SectionReader ───────────────────────────────────────────────────
//
// Slim port of io.go:486 + :501. Internal `r` is `Box<dyn ReaderAt>` —
// the goish-idiomatic representation of Go's interface value. Outer()
// is omitted because it would require ceding ownership of `r` to the
// caller (Go can return the interface by value cheaply because Reader
// values are reference-y; goish must Box, which forces a choice
// between cloning or moving).

/// `io.SectionReader` (io.go:501) — Read/Seek/ReadAt over a contiguous
/// `[off, off+n)` window of an underlying `ReaderAt`.
pub struct SectionReader {
    r: alloc::boxed::Box<dyn ReaderAt>,
    base: i64,
    off: i64,
    limit: i64,
    #[allow(dead_code)]
    n: i64,
}

impl SectionReader {
    /// `(s *SectionReader).Read(p)` (io.go:509). Truncates the read
    /// window when fewer than `len(p)` bytes remain.
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: if s.off >= s.limit { return 0, EOF }
        if self.off >= self.limit {
            return (0, EOF.into());
        }
        // Go: if max := s.limit - s.off; int64(len(p)) > max { p = p[0:max] }
        let avail = self.limit - self.off;
        let want = if (p.Len() as i64) > avail {
            avail as int
        } else {
            p.Len()
        };
        let mut tmp = crate::make!([]byte, want);
        // Go: n, err = s.r.ReadAt(p, s.off)
        let (n, err) = self.r.ReadAt(&mut tmp, self.off);
        for i in 0..n {
            p[i] = tmp[i];
        }
        self.off += n as i64;
        (n, err)
    }

    /// `(s *SectionReader).Seek(offset, whence)` (io.go:524).
    pub fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        // Go: switch whence { ... }
        let new_off: i64 = if whence == SeekStart {
            offset.wrapping_add(self.base)
        } else if whence == SeekCurrent {
            offset.wrapping_add(self.off)
        } else if whence == SeekEnd {
            offset.wrapping_add(self.limit)
        } else {
            return (0, crate::errors::New("Seek: invalid whence"));
        };
        // Go: if offset < s.base { return 0, errOffset }
        if new_off < self.base {
            return (0, crate::errors::New("Seek: invalid offset"));
        }
        self.off = new_off;
        (new_off - self.base, nil)
    }

    /// `(s *SectionReader).ReadAt(p, off)` (io.go:542). Surfaces EOF
    /// when reading past the section boundary.
    pub fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        // Go: if off < 0 || off >= s.Size() { return 0, EOF }
        if off < 0 || off >= self.Size() {
            return (0, EOF.into());
        }
        let abs_off = off + self.base;
        let avail = self.limit - abs_off;
        // Go: if max := s.limit - off; int64(len(p)) > max { p = p[0:max] ... err = EOF }
        if (p.Len() as i64) > avail {
            let mut tmp = crate::make!([]byte, avail as int);
            let (n, mut err) = self.r.ReadAt(&mut tmp, abs_off);
            for i in 0..n {
                p[i] = tmp[i];
            }
            if err.IsNil() {
                err = EOF.into();
            }
            return (n, err);
        }
        // Go: return s.r.ReadAt(p, off)
        self.r.ReadAt(p, abs_off)
    }

    /// `(s *SectionReader).Size()` (io.go:559). Constant after creation.
    pub fn Size(&self) -> i64 {
        self.limit - self.base
    }
}

impl Reader for SectionReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        SectionReader::Read(self, p)
    }
}

impl Seeker for SectionReader {
    fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        SectionReader::Seek(self, offset, whence)
    }
}

impl ReaderAt for SectionReader {
    fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        SectionReader::ReadAt(self, p, off)
    }
}

/// `io.NewSectionReader(r, off, n)` (io.go:486) — read from `r`
/// starting at offset `off`, capped at `n` bytes.
pub fn NewSectionReader(
    r: alloc::boxed::Box<dyn ReaderAt>,
    off: i64,
    n: i64,
) -> SectionReader {
    // Go: const maxint64 = 1<<63 - 1
    //     if off <= maxint64 - n { remaining = n + off } else { remaining = maxint64 }
    let maxint64 = i64::MAX;
    let remaining = if off <= maxint64.wrapping_sub(n) {
        n + off
    } else {
        maxint64
    };
    SectionReader {
        r,
        base: off,
        off,
        limit: remaining,
        n,
    }
}

// ─── OffsetWriter ────────────────────────────────────────────────────
//
// Slim port of io.go:569 + :578. Symmetric to SectionReader: maps
// writes at offset `base` to offset `base+off` in the underlying
// `WriterAt`. Internal `w` is `Box<dyn WriterAt>`.

/// `io.OffsetWriter` (io.go:570) — Write/WriteAt/Seek over a fixed
/// offset window of an underlying `WriterAt`.
pub struct OffsetWriter {
    w: alloc::boxed::Box<dyn WriterAt>,
    base: i64,
    off: i64,
}

impl OffsetWriter {
    /// `(o *OffsetWriter).Write(p)` (io.go:582). Advances the cursor.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: n, err = o.w.WriteAt(p, o.off); o.off += int64(n)
        let (n, err) = self.w.WriteAt(p, self.off);
        self.off += n as i64;
        (n, err)
    }

    /// `(o *OffsetWriter).WriteAt(p, off)` (io.go:588). Random-access
    /// write. Negative `off` returns `errOffset`.
    pub fn WriteAt(&mut self, p: slice<byte>, off: i64) -> (int, error) {
        // Go: if off < 0 { return 0, errOffset }
        if off < 0 {
            return (0, crate::errors::New("Seek: invalid offset"));
        }
        // Go: off += o.base; return o.w.WriteAt(p, off)
        self.w.WriteAt(p, off + self.base)
    }

    /// `(o *OffsetWriter).Seek(offset, whence)` (io.go:597). Note: Go's
    /// OffsetWriter.Seek does NOT support SeekEnd (no underlying size
    /// to anchor against).
    pub fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        // Go: switch whence { case SeekStart: ...; case SeekCurrent: ... }
        let new_off: i64 = if whence == SeekStart {
            offset.wrapping_add(self.base)
        } else if whence == SeekCurrent {
            offset.wrapping_add(self.off)
        } else {
            return (0, crate::errors::New("Seek: invalid whence"));
        };
        if new_off < self.base {
            return (0, crate::errors::New("Seek: invalid offset"));
        }
        self.off = new_off;
        (new_off - self.base, nil)
    }
}

impl Writer for OffsetWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        OffsetWriter::Write(self, p)
    }
}

impl WriterAt for OffsetWriter {
    fn WriteAt(&mut self, p: slice<byte>, off: i64) -> (int, error) {
        OffsetWriter::WriteAt(self, p, off)
    }
}

impl Seeker for OffsetWriter {
    fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        OffsetWriter::Seek(self, offset, whence)
    }
}

/// `io.NewOffsetWriter(w, off)` (io.go:578) — write to `w` starting at
/// offset `off`.
pub fn NewOffsetWriter(w: alloc::boxed::Box<dyn WriterAt>, off: i64) -> OffsetWriter {
    OffsetWriter { w, base: off, off }
}

// ─── CopyN ───────────────────────────────────────────────────────────

/// `io.CopyN(dst, src, n)` (io.go:363) — copy exactly `n` bytes from
/// `src` to `dst`. Returns `(written, err)` where `written == n iff err == nil`.
/// If `src` ends early, surfaces `io.EOF`.
pub fn CopyN(dst: &mut dyn Writer, src: &mut dyn Reader, n: i64) -> (i64, error) {
    // Go: written, err = Copy(dst, LimitReader(src, n))
    let mut limited = LimitReader(src, n as int);
    let (written, err) = Copy(dst, &mut limited);
    // Go: if written == n { return n, nil }
    if written == n {
        return (n, nil);
    }
    // Go: if written < n && err == nil { err = EOF }
    if written < n && err.IsNil() {
        return (written, EOF.into());
    }
    (written, err)
}

// ─── ReadAll / ReadFull / ReadAtLeast ────────────────────────────────

/// `io.ReadAll(r)` (io.go:709) — drain `r` until EOF/error, return the
/// accumulated bytes. EOF is normal termination (returned err == nil).
///
/// Slim deviation: uses `bytes::Buffer` for the growing accumulator
/// rather than Go's `b[len(b):cap(b)]` capacity-grow trick (goish slice
/// subslicing copies, so the Go pattern doesn't apply).
pub fn ReadAll(r: &mut dyn Reader) -> (slice<byte>, error) {
    let eof: error = EOF.into();
    // Go: b := make([]byte, 0, 512)
    let mut buf = crate::bytes::NewBuffer(crate::make!([]byte, 0));
    // Reusable read chunk; size matches Go's initial capacity.
    let mut chunk: slice<byte> = crate::make!([]byte, 512);
    loop {
        // Go: n, err := r.Read(b[len(b):cap(b)])
        let (n, err) = r.Read(&mut chunk);
        if n > 0 {
            // Go: b = b[:len(b)+n]
            let part = chunk.slice(0, n);
            let _ = buf.Write(part);
        }
        if !err.IsNil() {
            // Go: if err == EOF { err = nil }; return b, err
            if err == eof {
                return (buf.Bytes(), nil);
            }
            return (buf.Bytes(), err);
        }
    }
}

/// `io.ReadAtLeast(r, buf, min)` (io.go:329) — read into `buf` until
/// at least `min` bytes are accumulated. Returns ErrShortBuffer if
/// `len(buf) < min`, ErrUnexpectedEOF if EOF arrives after some bytes
/// but before reaching `min`.
pub fn ReadAtLeast(r: &mut dyn Reader, buf: &mut slice<byte>, min: int) -> (int, error) {
    // Go: if len(buf) < min { return 0, ErrShortBuffer }
    if buf.Len() < min {
        return (0, ErrShortBuffer.into());
    }
    let eof: error = EOF.into();
    let total = buf.Len();
    let mut n: int = 0;
    let mut err: error = nil;
    // Go: for n < min && err == nil
    while n < min && err.IsNil() {
        // Go: nn, err = r.Read(buf[n:])
        // goish slice subslicing copies; we instead read into a
        // temp scratch chunk sized to remaining capacity, then copy
        // the bytes into buf at [n..n+nn].
        let cap_left = total - n;
        let mut tmp = crate::make!([]byte, cap_left);
        let (nn, e) = r.Read(&mut tmp);
        for i in 0..nn {
            buf[n + i] = tmp[i];
        }
        n += nn;
        err = e;
    }
    // Go: if n >= min { err = nil }
    if n >= min {
        err = nil;
    } else if n > 0 && err == eof {
        // Go: else if n > 0 && err == EOF { err = ErrUnexpectedEOF }
        err = ErrUnexpectedEOF.into();
    }
    (n, err)
}

/// `io.ReadFull(r, buf)` (io.go:353) — read exactly `len(buf)` bytes
/// or fail. Thin wrapper over ReadAtLeast.
pub fn ReadFull(r: &mut dyn Reader, buf: &mut slice<byte>) -> (int, error) {
    let n = buf.Len();
    ReadAtLeast(r, buf, n)
}

// ─── MultiReader ─────────────────────────────────────────────────────
//
// Slim port of multi.go:13 (`multiReader`). Public surface accepts a
// `slice<Box<dyn Reader>>` — Go's variadic `...Reader` becomes a slice
// of trait-object readers. Internal storage is `Vec<Box<dyn Reader>>`
// because Box<dyn Reader> is not Clone (slice's `.slice()` requires
// Clone, and we need pop-from-front via Vec::remove(0)).
//
// Deviations from Go: no flatten optimisation for nested multiReaders
// (multi.go:20-25); no WriteTo special case (multi.go:44-66).

/// `io.MultiReader` (multi.go:73) — concrete reader that concatenates
/// `mr.readers` sequentially. Returned by [`MultiReader`].
pub struct MultiReaderImpl {
    readers: alloc::vec::Vec<alloc::boxed::Box<dyn Reader>>,
}

impl Reader for MultiReaderImpl {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: for len(mr.readers) > 0
        let eof: error = EOF.into();
        while !self.readers.is_empty() {
            // Go: n, err = mr.readers[0].Read(p)
            let (n, err) = self.readers[0].Read(p);
            // Go: if err == EOF { mr.readers = mr.readers[1:] }
            let is_eof = err == eof;
            if is_eof {
                self.readers.remove(0);
            }
            // Go: if n > 0 || err != EOF { ... return }
            if n > 0 || !is_eof {
                // Go: if err == EOF && len(mr.readers) > 0 { err = nil }
                let mut err_out = err;
                if is_eof && !self.readers.is_empty() {
                    err_out = nil;
                }
                return (n, err_out);
            }
            // n == 0 && err == EOF: pop'd above, loop to next reader.
        }
        // Go: return 0, EOF
        (0, EOF.into())
    }
}

/// `io.MultiReader(readers...)` (multi.go:73) — slim port. Returns a
/// Reader that reads from each in sequence; EOF from one advances to
/// the next; final EOF surfaces only after the last reader is drained.
///
/// Pass readers as `slice<Box<dyn io::Reader>>` (the Go-variadic shape).
pub fn MultiReader(readers: slice<alloc::boxed::Box<dyn Reader>>) -> MultiReaderImpl {
    MultiReaderImpl { readers: readers.__into_vec() }
}

// ─── MultiWriter ─────────────────────────────────────────────────────
//
// Slim port of multi.go:79 (`multiWriter`). Each Write is fanned out to
// every wrapped writer; first error short-circuits. No flatten of nested
// multiWriters (multi.go:127-135) and no StringWriter optimisation
// (multi.go:97-119) — slim path always goes through Write.

/// `io.multiWriter` (multi.go:79) — concrete writer returned by
/// [`MultiWriter`]. Fans each Write out to all `t.writers`.
pub struct MultiWriterImpl {
    writers: alloc::vec::Vec<alloc::boxed::Box<dyn Writer>>,
}

impl Writer for MultiWriterImpl {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: for _, w := range t.writers
        let plen = p.Len();
        for w in self.writers.iter_mut() {
            // Slim port: clone p per writer because goish Write consumes
            // its argument (Go shares the same []byte across writers).
            let (n, err) = w.Write(p.clone());
            // Go: if err != nil { return }
            if !err.IsNil() {
                return (n, err);
            }
            // Go: if n != len(p) { err = ErrShortWrite; return }
            if n != plen {
                return (n, ErrShortWrite.into());
            }
        }
        // Go: return len(p), nil
        (plen, nil)
    }
}

/// `io.MultiWriter(writers...)` (multi.go:127) — slim port. Returns a
/// Writer that duplicates each Write to all listed writers in order.
pub fn MultiWriter(writers: slice<alloc::boxed::Box<dyn Writer>>) -> MultiWriterImpl {
    MultiWriterImpl { writers: writers.__into_vec() }
}

// ─── Pipe (line-by-line port of pipe.go) ─────────────────────────────

pub mod pipe;
pub use pipe::{ErrClosedPipe, Pipe, PipeReader, PipeWriter};

// ─── io/fs subpackage (slim — FileMode, ValidPath, PathError) ──────

pub mod fs;

// ─── io/ioutil — Go 1.16-deprecated forwarders ────────────────────────
//
// `io/ioutil` was split into `io` and `os` in Go 1.16, but a long
// tail of code (rs/xid, hashicorp libs, K8s client deps) still spells
// `ioutil.ReadFile`, `ioutil.WriteFile`, etc. The module here is a
// compatibility shim — every entry is a thin forwarder to the
// post-split home.
pub mod ioutil {
    use super::*;

    /// `ioutil.ReadFile(name)` — see `os::ReadFile`.
    #[inline]
    pub fn ReadFile<N: Into<crate::string>>(name: N) -> (slice<byte>, error) {
        crate::os::ReadFile(name)
    }

    /// `ioutil.WriteFile(name, data, perm)` — see `os::WriteFile`.
    #[inline]
    pub fn WriteFile<N: Into<crate::string>>(
        name: N,
        data: slice<byte>,
        perm: u32,
    ) -> error {
        crate::os::WriteFile(name, data, perm)
    }

    /// `ioutil.TempDir(dir, pattern) (name string, err error)` —
    /// Go 1.16+ moved to `os.MkdirTemp`. Slim port: create
    /// `<dir>/<pattern><N>` with a process-local counter for
    /// uniqueness. Real `mkstemp(3)`-grade collision-avoidance is
    /// deferred (sufficient for short-lived test/scratch dirs).
    pub fn TempDir<S: Into<crate::string>, S2: Into<crate::string>>(
        dir: S,
        pattern: S2,
    ) -> (crate::string, error) {
        let dir: crate::string = dir.into();
        let pattern: crate::string = pattern.into();
        let base = if dir.Len() == 0 { crate::os::TempDir() } else { dir };

        static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        let mut path: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        path.extend_from_slice(base.as_bytes());
        if !path.ends_with(b"/") {
            path.push(b'/');
        }
        path.extend_from_slice(pattern.as_bytes());
        append_u64(&mut path, n);

        let name = crate::string::from_bytes(&path);
        let err = crate::os::Mkdir(name.clone(), 0o700);
        (name, err)
    }

    /// `ioutil.TempFile(dir, pattern) (*os.File, error)` — same
    /// naming caveat as `TempDir`. Deprecated in Go 1.16 (replaced by
    /// `os.CreateTemp`).
    pub fn TempFile<S: Into<crate::string>, S2: Into<crate::string>>(
        dir: S,
        pattern: S2,
    ) -> (crate::gonilable::nilable<crate::os::File>, error) {
        let dir: crate::string = dir.into();
        let pattern: crate::string = pattern.into();
        let base = if dir.Len() == 0 { crate::os::TempDir() } else { dir };

        static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        let mut path: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        path.extend_from_slice(base.as_bytes());
        if !path.ends_with(b"/") {
            path.push(b'/');
        }
        path.extend_from_slice(pattern.as_bytes());
        append_u64(&mut path, n);

        let name = crate::string::from_bytes(&path);
        crate::os::Create(name)
    }

    fn append_u64(buf: &mut alloc::vec::Vec<u8>, mut n: u64) {
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        if n == 0 {
            i -= 1;
            digits[i] = b'0';
        } else {
            while n > 0 {
                i -= 1;
                digits[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        buf.extend_from_slice(&digits[i..]);
    }
}
