// goishlint:ignore GOISH019 — two findings, on `NopCloserImpl` and
// `NopCloserWriterToImpl`: Go's field is an ANONYMOUS `Reader` embed,
// which has no name in the AST, so the rule reads Go's field set as
// empty and any Rust field at all as an addition. Both are named
// `Reader`, which is the name Go's embedding gives them. The rule has
// no line-scoped form. Every other struct here passes the check.
// go: file io/io.go decls: Copy, WriteString, CopyBuffer, LimitedReader.Read, LimitReader, teeReader.Read, TeeReader, blackHolePool, discard.ReadFrom, discard.Write, nopCloser.Close, nopCloserWriterTo.Close, nopCloserWriterTo.WriteTo, NopCloser, SectionReader.Read, SectionReader.Seek, SectionReader.ReadAt, SectionReader.Size, SectionReader.Outer, NewSectionReader, OffsetWriter.Write, OffsetWriter.WriteAt, OffsetWriter.Seek, NewOffsetWriter, CopyN, ReadAll, ReadAtLeast, ReadFull
//
// io.go — the interfaces, the sentinel errors, and the free functions
// that only need them.

use crate::convert::{int as toint, int64 as toint64};
use crate::error;
use crate::errors::nil;
use crate::goslice::slice;
use crate::types::{byte, int};

// ─── Reader / Writer / Closer traits ───────────────────────────────────

// go: sdk 1.25.5 io/io.go:86-88 Reader
/// Go's `io.Reader`. Read up to `len(p)` bytes into `p`; returns
/// `(n, err)`. EOF is signaled by returning `io::EOF` as the error.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait Reader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error);
}

// go: sdk 1.25.5 io/io.go:99-101 Writer
/// Go's `io.Writer`. Write `len(p)` bytes from `p`. Returns `(n, err)`
/// where `n < len(p)` requires a non-nil `err`.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait Writer {
    fn Write(&mut self, p: slice<byte>) -> (int, error);
}

/// goish addition: a shareable writer. `Arc<sync::Mutex<W>>` implements
/// [`Writer`] by serializing each `Write` through the mutex, so several
/// holders observe writes to the same underlying value. This mirrors Go's
/// habit of passing a `*T` pointer as an `io.Writer` — e.g.
/// `log.New(&buf, …)` where the caller later reads `buf.String()`.
impl<W: Writer> Writer for alloc::sync::Arc<crate::sync::Mutex<W>> {
    // go: none — goish idiom: Go's interface values are already
    //     pointers, so an `io.Writer` handed to two owners is one
    //     writer. goish's are owned, so sharing one takes an `Arc` and
    //     a mutex — and this is what makes that pair a `Writer`.
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return self.Lock().Write(p);
    }
}

// go: sdk 1.25.5 io/io.go:107-109 Closer
/// Go's `io.Closer`.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait Closer {
    fn Close(&mut self) -> error;
}

/// Go's `io.ReadCloser` — combines [`Reader`] and [`Closer`].
// go: sdk 1.25.5 io/io.go:137-140 ReadCloser
pub trait ReadCloser: Reader + Closer {}

/// Blanket impl: any type that implements both `Reader` and `Closer`
/// automatically implements `ReadCloser`.
impl<T: Reader + Closer> ReadCloser for T {}

/// Go's `io.ReadWriter` — combines [`Reader`] and [`Writer`].
// go: sdk 1.25.5 io/io.go:131-134 ReadWriter
pub trait ReadWriter: Reader + Writer {}

/// Blanket impl. Go's interface satisfaction is structural, so a type
/// with the right methods *is* an `io.ReadWriter`; goish's traits are
/// nominal, so each grouping interface needs one of these.
impl<T: Reader + Writer> ReadWriter for T {}

/// Go's `io.WriteCloser` — combines [`Writer`] and [`Closer`].
// go: sdk 1.25.5 io/io.go:143-146 WriteCloser
pub trait WriteCloser: Writer + Closer {}

/// Blanket impl, as for [`ReadWriter`].
impl<T: Writer + Closer> WriteCloser for T {}

/// Go's `io.ReadWriteCloser` — combines [`Reader`], [`Writer`] and
/// [`Closer`].
// go: sdk 1.25.5 io/io.go:149-153 ReadWriteCloser
pub trait ReadWriteCloser: Reader + Writer + Closer {}

/// Blanket impl, as for [`ReadWriter`].
impl<T: Reader + Writer + Closer> ReadWriteCloser for T {}

/// Go's `io.ReadSeekCloser` — combines [`Reader`], [`Seeker`] and
/// [`Closer`].
// go: sdk 1.25.5 io/io.go:163-167 ReadSeekCloser
pub trait ReadSeekCloser: Reader + Seeker + Closer {}

/// Blanket impl, as for [`ReadWriter`].
impl<T: Reader + Seeker + Closer> ReadSeekCloser for T {}

/// Go's `io.WriteSeeker` — combines [`Writer`] and [`Seeker`].
// go: sdk 1.25.5 io/io.go:170-173 WriteSeeker
pub trait WriteSeeker: Writer + Seeker {}

/// Blanket impl, as for [`ReadWriter`].
impl<T: Writer + Seeker> WriteSeeker for T {}

/// Go's `io.ReadWriteSeeker` — combines [`Reader`], [`Writer`] and
/// [`Seeker`].
// go: sdk 1.25.5 io/io.go:176-180 ReadWriteSeeker
pub trait ReadWriteSeeker: Reader + Writer + Seeker {}

/// Blanket impl, as for [`ReadWriter`].
impl<T: Reader + Writer + Seeker> ReadWriteSeeker for T {}

/// Go's `io.ReadSeeker` (io.go:139) — combines [`Reader`] and
/// [`Seeker`]. net/http's ServeContent takes one.
// go: sdk 1.25.5 io/io.go:156-159 ReadSeeker
pub trait ReadSeeker: Reader + Seeker {}

/// Blanket impl, as for [`ReadCloser`].
impl<T: Reader + Seeker> ReadSeeker for T {}

// go: sdk 1.25.5 io/io.go:126-128 Seeker
/// Go's `io.Seeker` (io.go:126). Reposition the read/write head.
/// Whence is one of `SeekStart`, `SeekCurrent`, `SeekEnd`.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait Seeker {
    fn Seek(&mut self, offset: i64, whence: int) -> (i64, error);
}

/// Whence values for [`Seeker::Seek`] (io.go:22).
pub const SeekStart: int = 0;
pub const SeekCurrent: int = 1;
pub const SeekEnd: int = 2;

// go: sdk 1.25.5 io/io.go:230-232 ReaderAt
/// Go's `io.ReaderAt` (io.go:230). Random-access read at byte offset
/// `off`. Implementations must not retain `p` across the call.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait ReaderAt {
    fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error);
}

// go: sdk 1.25.5 io/io.go:249-251 WriterAt
/// Go's `io.WriterAt` (io.go:249). Random-access write at byte offset
/// `off`. Implementations must not retain `p` across the call.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait WriterAt {
    fn WriteAt(&mut self, p: slice<byte>, off: i64) -> (int, error);
}

// go: sdk 1.25.5 io/io.go:262-264 ByteReader
/// Go's `io.ByteReader` (io.go:262).
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait ByteReader {
    fn ReadByte(&mut self) -> (byte, error);
}

/// Go's `io.ByteScanner` (io.go:274).
// go: sdk 1.25.5 io/io.go:274-277 ByteScanner
pub trait ByteScanner: ByteReader {
    fn UnreadByte(&mut self) -> error;
}

// go: sdk 1.25.5 io/io.go:280-282 ByteWriter
/// Go's `io.ByteWriter` (io.go:280).
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait ByteWriter {
    fn WriteByte(&mut self, c: byte) -> error;
}

// go: sdk 1.25.5 io/io.go:289-291 RuneReader
/// Go's `io.RuneReader` (io.go:289).
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait RuneReader {
    fn ReadRune(&mut self) -> (crate::types::rune, int, error);
}

/// Go's `io.RuneScanner` (io.go:301). Extends RuneReader with the
/// ability to push back the last-read rune. Surfaced by gopkg.in/
/// inf.v0's `Dec.scan(r io.RuneScanner)` parser path.
// go: sdk 1.25.5 io/io.go:301-304 RuneScanner
pub trait RuneScanner: RuneReader {
    fn UnreadRune(&mut self) -> error;
}

// go: sdk 1.25.5 io/io.go:307-309 StringWriter
/// Go's `io.StringWriter` (io.go:307).
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait StringWriter {
    fn WriteString(&mut self, s: crate::gostring::string) -> (int, error);
}

// go: sdk 1.25.5 io/io.go:189-191 ReaderFrom
/// Go's `io.ReaderFrom` (io.go:189). Used by `Copy` for fast-path
/// fan-in when the destination supports it.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait ReaderFrom {
    fn ReadFrom(&mut self, r: &mut dyn Reader) -> (i64, error);
}

// go: sdk 1.25.5 io/io.go:200-202 WriterTo
/// Go's `io.WriterTo` (io.go:200). Used by `Copy` for fast-path
/// fan-out when the source supports it.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait WriterTo {
    fn WriteTo(&mut self, w: &mut dyn Writer) -> (i64, error);
}

// Blanket impls so `Box<dyn T>` satisfies the trait. The `&mut R`
// blanket is now auto-emitted by `#[goish::interface]` (section 6.7a
// of goish-macros); the Box<R> blanket below is retained because
// Box<dyn T> needs the same dispatch shape for owned trait-object
// callers and the macro doesn't emit it yet.
impl<R: Reader + ?Sized> Reader for alloc::boxed::Box<R> {
    // go: none — goish idiom: Go's `Box<dyn T>` equivalent is the
    //     interface value itself, which already satisfies the
    //     interface. A Rust `Box<dyn T>` does not, so the forwarding
    //     impl has to be written out.
    #[inline]
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return (**self).Read(p);
    }
}

impl<W: Writer + ?Sized> Writer for alloc::boxed::Box<W> {
    // go: none — goish idiom: Go's `Box<dyn T>` equivalent is the
    //     interface value itself, which already satisfies the
    //     interface. A Rust `Box<dyn T>` does not, so the forwarding
    //     impl has to be written out.
    #[inline]
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return (**self).Write(p);
    }
}

impl<C: Closer + ?Sized> Closer for alloc::boxed::Box<C> {
    // go: none — goish idiom: Go's `Box<dyn T>` equivalent is the
    //     interface value itself, which already satisfies the
    //     interface. A Rust `Box<dyn T>` does not, so the forwarding
    //     impl has to be written out.
    #[inline]
    fn Close(&mut self) -> error {
        return (**self).Close();
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

// The three unexported ones. Go declares these package-level so the
// copy and seek paths can compare against a single value; goish's
// used to call `errors.New` at each return site, which builds a fresh
// error every time and makes `errors.Is` against the previous one
// false. Nothing outside the package can name them, so nothing
// noticed — but the values are still meant to be the same value.
crate::var! {
    // go: sdk 1.25.5 io/io.go:32-32 errInvalidWrite
    /// A `Write` reported a byte count that cannot be right — negative,
    /// or larger than what it was handed.
    errInvalidWrite: error = "invalid write result";

    // go: sdk 1.25.5 io/io.go:521-521 errWhence
    /// `Seek` was given a `whence` that is none of the three constants.
    errWhence: error = "Seek: invalid whence";

    // go: sdk 1.25.5 io/io.go:522-522 errOffset
    /// `Seek` was given an offset before the start of the section.
    errOffset: error = "Seek: invalid offset";
}

// ─── Copy / WriteString ────────────────────────────────────────────────

// go: sdk 1.25.5 io/io.go:387-389 Copy
/// `io.Copy(dst, src)` — copy from src to dst until EOF. Returns the
/// number of bytes copied and the first error encountered (other than
/// `io.EOF`, which is normal termination).
///
/// Buffer size: 32 KiB (matches Go's default genericReadFrom path).
// goishlint:ignore GOISH023 — the body ends in an infinite `loop` whose
//     every exit is a `return` from inside it, so there is no tail
//     expression to make explicit. Go writes the same shape: `for { … }`
//     with returns in the body.
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
            let (mut wn, mut werr) = dst.Write(chunk);
            // Go: a Writer that claims a negative count, or more than it
            // was handed, is not to be believed — the count is discarded
            // and, if it did not say why, `errInvalidWrite` does.
            if wn < 0 || chunk_len < wn {
                wn = 0;
                if werr == nil {
                    werr = errInvalidWrite.into();
                }
            }
            total += toint64(wn);
            if werr != nil {
                return (total, werr);
            }
            if toint(wn) < chunk_len {
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

// go: sdk 1.25.5 io/io.go:314-319 WriteString
/// `io.WriteString(w, s)` — convenience: write a string to a Writer.
pub fn WriteString<S: Into<crate::gostring::string>>(w: &mut dyn Writer, s: S) -> (int, error) {
    let buf = crate::convert::bytes(s.into());
    return w.Write(buf);
}

// go: sdk 1.25.5 io/io.go:398-403 CopyBuffer
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
// goishlint:ignore GOISH023 — the body ends in an infinite `loop` whose
//     every exit is a `return` from inside it, so there is no tail
//     expression to make explicit. Go writes the same shape: `for { … }`
//     with returns in the body.
pub fn CopyBuffer(dst: &mut dyn Writer, src: &mut dyn Reader, buf: slice<byte>) -> (i64, error) {
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
            let (mut nw, mut werr) = dst.Write(chunk);
            // Go: if nw < 0 || nr < nw { nw = 0; if ew == nil { ew = errInvalidWrite } }
            if nw < 0 || chunk_len < nw {
                nw = 0;
                if werr == nil {
                    werr = errInvalidWrite.into();
                }
            }
            written += toint64(nw);
            // Go: if ew != nil { err = ew; break }
            if werr != nil {
                return (written, werr);
            }
            // Go: if nr != nw { err = ErrShortWrite; break }
            if toint(nw) < chunk_len {
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
    // go: sdk 1.25.5 io/io.go:472-482 LimitedReader.Read
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
        return (n, err);
    }
}

// go: sdk 1.25.5 io/io.go:461-461 LimitReader
/// `io.LimitReader(r, n)` (io.go:461) — return a Reader that reads at
/// most `n` bytes from `r` before signaling EOF.
pub fn LimitReader<R: Reader>(r: R, n: int) -> LimitedReader<R> {
    return LimitedReader { R: r, N: n };
}

// ─── TeeReader ───────────────────────────────────────────────────────

/// `io.teeReader` (io.go:622) — Reader that mirrors all reads to a Writer.
pub struct TeeReaderImpl<R: Reader, W: Writer> {
    r: R,
    w: W,
}

impl<R: Reader, W: Writer> Reader for TeeReaderImpl<R, W> {
    // go: sdk 1.25.5 io/io.go:627-635 teeReader.Read
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
        return (n, err);
    }
}

// go: sdk 1.25.5 io/io.go:618-620 TeeReader
/// `io.TeeReader(r, w)` (io.go:618) — every Read also writes to `w`.
/// Errors from `w` surface as Read errors.
pub fn TeeReader<R: Reader, W: Writer>(r: R, w: W) -> TeeReaderImpl<R, W> {
    return TeeReaderImpl { r, w };
}

// ─── Discard ─────────────────────────────────────────────────────────

/// `io.Discard` analogue (io.go:639). A Writer whose every Write
/// silently succeeds. Use as a sink for body draining or benchmarks.
///
/// Go exposes `Discard` as a singleton; goish exposes a constructor
/// because static-trait-object initialization is unwieldy here.
pub struct Discard;

// go: none — goish idiom: Go's `io.Discard` is a package-level
//     `var` holding an interface value. goish has no interface
//     value to park in a static, so the sink is minted on demand;
//     `Discard` is a zero-sized type, so this allocates nothing.
/// Construct a fresh Discard writer.
pub fn DiscardWriter() -> Discard {
    return Discard;
}

// go: sdk 1.25.5 io/io.go:655-660 blackHolePool
/// The scratch buffers `Discard::ReadFrom` drains into.
///
/// Go's is a package-level `var … = sync.Pool{New: …}` of `*[]byte`,
/// built at init. goish's `Pool` is built by a constructor call, so it
/// is minted on first use behind a `Lazy` — the same shape the rest of
/// goish uses for a package-level pool. It holds the slice itself; a
/// `slice<byte>` is already a handle to its backing store.
fn blackHolePool() -> &'static crate::sync::Pool<slice<byte>> {
    static POOL: crate::lazy::Lazy<crate::sync::Pool<slice<byte>>> =
        crate::lazy::Lazy::new(|| crate::sync::Pool::new(|| crate::make!([]byte, 8192)));
    return POOL.get();
}

impl ReaderFrom for Discard {
    // go: sdk 1.25.5 io/io.go:662-676 discard.ReadFrom
    // goishlint:ignore GOISH023 — the body ends in an infinite `loop`
    //     whose every exit is a `return` from inside it. Go writes the
    //     same shape: `for { … }` with returns in the body.
    /// Drains `r` to nowhere and reports how much went by. EOF is the
    /// normal end, and is not reported as an error.
    fn ReadFrom(&mut self, r: &mut dyn Reader) -> (i64, error) {
        let mut buf = blackHolePool().Get();
        let mut n: i64 = 0;
        let eof: error = EOF.into();
        loop {
            let (readSize, err) = r.Read(&mut buf);
            n += toint64(readSize);
            if !err.IsNil() {
                blackHolePool().Put(buf);
                if err == eof {
                    return (n, nil);
                }
                return (n, err);
            }
        }
    }
}

impl Writer for Discard {
    // go: sdk 1.25.5 io/io.go:647-649 discard.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: return len(p), nil
        return (p.Len(), nil);
    }
}

// ─── Empty / Null counterparts ──────────────────────────────────────

/// Reader counterpart to `Discard` — every `Read` returns `(0, EOF)`.
/// Mirrors the behaviour of an empty `bytes.Reader`. Used as the
/// default sentinel for `Box<dyn io::Reader>` struct fields when a
/// goishc-generated `Default` impl needs a concrete value.
pub struct Empty;

// go: none — goish idiom: the reader counterpart of
//     `DiscardWriter`, for the same reason. Go reaches for a
//     `bytes.Reader` over an empty slice; goish uses this as the
//     default value for a `Box<dyn io::Reader>` field, which has to
//     be some concrete type.
/// Construct a fresh Empty reader.
pub fn EmptyReader() -> Empty {
    return Empty;
}

impl Reader for Empty {
    // go: none — goish idiom: see `EmptyReader`.
    fn Read(&mut self, _p: &mut slice<byte>) -> (int, error) {
        return (0, EOF.into());
    }
}

/// Closer counterpart whose `Close` is a no-op returning nil. Used as
/// the default sentinel for `Box<dyn io::Closer>` struct fields.
pub struct NullCloser;

// go: none — goish idiom: the closer counterpart of
//     `DiscardWriter`. Go has no such value — a `nil` `io.Closer`
//     field is idiomatic there — but goish's `Box<dyn io::Closer>`
//     fields need a concrete default.
/// Construct a fresh NullCloser.
pub fn NopCloser_() -> NullCloser {
    return NullCloser;
}

impl Closer for NullCloser {
    // go: none — goish idiom: see `NopCloser_`.
    fn Close(&mut self) -> error {
        return nil.into();
    }
}

// ─── NopCloser ───────────────────────────────────────────────────────

// go: sdk 1.25.5 io/io.go:689-691 nopCloser
/// `io.nopCloser` — a `Reader` with a no-op `Close`, returned by
/// [`NopCloser`].
///
/// Go names this `nopCloser` and keeps it unexported, handing callers
/// the `ReadCloser` interface. goish returns the concrete type, so the
/// name is public even though nothing outside constructs one.
pub struct NopCloserImpl<R: Reader> {
    // Go embeds the interface: `struct { Reader }`, which names the
    // field after the type. Keeping that name keeps the layouts equal.
    Reader: R,
}

impl<R: Reader> Reader for NopCloserImpl<R> {
    // go: none — goish idiom: Go embeds the `Reader` in the struct,
    //     which promotes its `Read` for free. Rust has no embedding,
    //     so the forward is written out.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return self.Reader.Read(p);
    }
}

impl<R: Reader> Closer for NopCloserImpl<R> {
    // go: sdk 1.25.5 io/io.go:693-693 nopCloser.Close
    fn Close(&mut self) -> error {
        return nil;
    }
}

// go: sdk 1.25.5 io/io.go:695-697 nopCloserWriterTo
/// The [`WriterTo`]-preserving twin of [`NopCloserImpl`].
///
/// Go picks between the two inside `NopCloser` with a type assertion on
/// `r`, so a reader that can write itself out keeps that ability
/// through the wrapper — `io.Copy` from the wrapped value still takes
/// the fast path. goish decides at the type level instead: the caller
/// reaches for [`NopCloserWriterTo`] when the reader is a `WriterTo`,
/// because `NopCloser` is generic and cannot ask at runtime what `R`
/// implements.
pub struct NopCloserWriterToImpl<R: Reader + WriterTo> {
    // Go embeds the interface: `struct { Reader }`.
    Reader: R,
}

impl<R: Reader + WriterTo> Reader for NopCloserWriterToImpl<R> {
    // go: none — goish idiom: the promoted `Read` of Go's embedded
    //     `Reader`, written out. Same as `NopCloserImpl`.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return self.Reader.Read(p);
    }
}

impl<R: Reader + WriterTo> Closer for NopCloserWriterToImpl<R> {
    // go: sdk 1.25.5 io/io.go:699-699 nopCloserWriterTo.Close
    fn Close(&mut self) -> error {
        return nil;
    }
}

impl<R: Reader + WriterTo> WriterTo for NopCloserWriterToImpl<R> {
    // go: sdk 1.25.5 io/io.go:701-703 nopCloserWriterTo.WriteTo
    fn WriteTo(&mut self, w: &mut dyn Writer) -> (i64, error) {
        return self.Reader.WriteTo(w);
    }
}

// go: none — goish idiom: the `WriterTo`-preserving half of Go's
//     `NopCloser`. Go's one constructor picks the wrapper with a type
//     assertion on the `Reader` interface value it was handed; goish's
//     is generic over `R`, which is resolved at compile time and cannot
//     be asked what it implements, so the choice moves to the caller.
pub fn NopCloserWriterTo<R: Reader + WriterTo>(r: R) -> NopCloserWriterToImpl<R> {
    return NopCloserWriterToImpl { Reader: r };
}

// go: sdk 1.25.5 io/io.go:682-687 NopCloser
/// `io.NopCloser(r)` (io.go:682) — produce a `Reader+Closer` whose
/// Close is a no-op.
///
/// Go's also checks whether `r` is a [`WriterTo`] and, if so, returns a
/// wrapper that forwards `WriteTo`. That check is a runtime type
/// assertion on an interface value; this is generic over `R` and has no
/// value to assert on, so the second wrapper is reached through
/// [`NopCloserWriterTo`] instead.
pub fn NopCloser<R: Reader>(r: R) -> NopCloserImpl<R> {
    return NopCloserImpl { Reader: r };
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
    // go: sdk 1.25.5 io/io.go:509-519 SectionReader.Read
    /// `(s *SectionReader).Read(p)` (io.go:509). Truncates the read
    /// window when fewer than `len(p)` bytes remain.
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: if s.off >= s.limit { return 0, EOF }
        if self.off >= self.limit {
            return (0, EOF.into());
        }
        // Go: if max := s.limit - s.off; int64(len(p)) > max { p = p[0:max] }
        let avail = self.limit - self.off;
        let want = if toint64(p.Len()) > avail {
            toint(avail)
        } else {
            p.Len()
        };
        let mut tmp = crate::make!([]byte, want);
        // Go: n, err = s.r.ReadAt(p, s.off)
        let (n, err) = self.r.ReadAt(&mut tmp, self.off);
        for i in 0..n {
            p[i] = tmp[i];
        }
        self.off += toint64(n);
        return (n, err);
    }

    // go: sdk 1.25.5 io/io.go:524-540 SectionReader.Seek
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
            return (0, errWhence.into());
        };
        // Go: if offset < s.base { return 0, errOffset }
        if new_off < self.base {
            return (0, errOffset.into());
        }
        self.off = new_off;
        return (new_off - self.base, nil);
    }

    // go: sdk 1.25.5 io/io.go:542-556 SectionReader.ReadAt
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
        if toint64(p.Len()) > avail {
            let mut tmp = crate::make!([]byte, toint(avail));
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
        return self.r.ReadAt(p, abs_off);
    }

    // go: sdk 1.25.5 io/io.go:559-559 SectionReader.Size
    /// `(s *SectionReader).Size()` (io.go:559). Constant after creation.
    pub fn Size(&self) -> i64 {
        return self.limit - self.base;
    }

    // go: sdk 1.25.5 io/io.go:565-567 SectionReader.Outer
    /// The underlying [`ReaderAt`] and the offsets for the section —
    /// the same three values [`NewSectionReader`] was given.
    ///
    /// Go hands back the `ReaderAt` itself. goish's `SectionReader`
    /// owns its reader in a `Box`, and there is no second owner to hand
    /// out, so this borrows it.
    pub fn Outer(&self) -> (&dyn ReaderAt, i64, i64) {
        return (&*self.r, self.base, self.n);
    }
}

impl Reader for SectionReader {
    // go: sdk 1.25.5 io/io.go:509-519 SectionReader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return SectionReader::Read(self, p);
    }
}

impl Seeker for SectionReader {
    // go: sdk 1.25.5 io/io.go:524-540 SectionReader.Seek
    fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        return SectionReader::Seek(self, offset, whence);
    }
}

impl ReaderAt for SectionReader {
    // go: sdk 1.25.5 io/io.go:542-556 SectionReader.ReadAt
    fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        return SectionReader::ReadAt(self, p, off);
    }
}

// go: sdk 1.25.5 io/io.go:486-497 NewSectionReader
/// `io.NewSectionReader(r, off, n)` (io.go:486) — read from `r`
/// starting at offset `off`, capped at `n` bytes.
pub fn NewSectionReader(r: alloc::boxed::Box<dyn ReaderAt>, off: i64, n: i64) -> SectionReader {
    // Go: const maxint64 = 1<<63 - 1
    //     if off <= maxint64 - n { remaining = n + off } else { remaining = maxint64 }
    let maxint64 = i64::MAX;
    let remaining = if off <= maxint64.wrapping_sub(n) {
        n + off
    } else {
        maxint64
    };
    return SectionReader {
        r,
        base: off,
        off,
        limit: remaining,
        n,
    };
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
    // go: sdk 1.25.5 io/io.go:582-586 OffsetWriter.Write
    /// `(o *OffsetWriter).Write(p)` (io.go:582). Advances the cursor.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: n, err = o.w.WriteAt(p, o.off); o.off += int64(n)
        let (n, err) = self.w.WriteAt(p, self.off);
        self.off += toint64(n);
        return (n, err);
    }

    // go: sdk 1.25.5 io/io.go:588-595 OffsetWriter.WriteAt
    /// `(o *OffsetWriter).WriteAt(p, off)` (io.go:588). Random-access
    /// write. Negative `off` returns `errOffset`.
    pub fn WriteAt(&mut self, p: slice<byte>, off: i64) -> (int, error) {
        // Go: if off < 0 { return 0, errOffset }
        if off < 0 {
            return (0, errOffset.into());
        }
        // Go: off += o.base; return o.w.WriteAt(p, off)
        return self.w.WriteAt(p, off + self.base);
    }

    // go: sdk 1.25.5 io/io.go:597-611 OffsetWriter.Seek
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
            return (0, errWhence.into());
        };
        if new_off < self.base {
            return (0, errOffset.into());
        }
        self.off = new_off;
        return (new_off - self.base, nil);
    }
}

impl Writer for OffsetWriter {
    // go: sdk 1.25.5 io/io.go:582-586 OffsetWriter.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return OffsetWriter::Write(self, p);
    }
}

impl WriterAt for OffsetWriter {
    // go: sdk 1.25.5 io/io.go:588-595 OffsetWriter.WriteAt
    fn WriteAt(&mut self, p: slice<byte>, off: i64) -> (int, error) {
        return OffsetWriter::WriteAt(self, p, off);
    }
}

impl Seeker for OffsetWriter {
    // go: sdk 1.25.5 io/io.go:597-611 OffsetWriter.Seek
    fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        return OffsetWriter::Seek(self, offset, whence);
    }
}

// go: sdk 1.25.5 io/io.go:578-580 NewOffsetWriter
/// `io.NewOffsetWriter(w, off)` (io.go:578) — write to `w` starting at
/// offset `off`.
pub fn NewOffsetWriter(w: alloc::boxed::Box<dyn WriterAt>, off: i64) -> OffsetWriter {
    return OffsetWriter { w, base: off, off };
}

// ─── CopyN ───────────────────────────────────────────────────────────

// go: sdk 1.25.5 io/io.go:363-373 CopyN
/// `io.CopyN(dst, src, n)` (io.go:363) — copy exactly `n` bytes from
/// `src` to `dst`. Returns `(written, err)` where `written == n iff err == nil`.
/// If `src` ends early, surfaces `io.EOF`.
pub fn CopyN(dst: &mut dyn Writer, src: &mut dyn Reader, n: i64) -> (i64, error) {
    // Go: written, err = Copy(dst, LimitReader(src, n))
    let mut limited = LimitReader(src, toint(n));
    let (written, err) = Copy(dst, &mut limited);
    // Go: if written == n { return n, nil }
    if written == n {
        return (n, nil);
    }
    // Go: if written < n && err == nil { err = EOF }
    if written < n && err.IsNil() {
        return (written, EOF.into());
    }
    return (written, err);
}

// ─── ReadAll / ReadFull / ReadAtLeast ────────────────────────────────

// go: sdk 1.25.5 io/io.go:709-726 ReadAll
/// `io.ReadAll(r)` (io.go:709) — drain `r` until EOF/error, return the
/// accumulated bytes. EOF is normal termination (returned err == nil).
///
/// Slim deviation: uses `bytes::Buffer` for the growing accumulator
/// rather than Go's `b[len(b):cap(b)]` capacity-grow trick (goish slice
/// subslicing copies, so the Go pattern doesn't apply).
// goishlint:ignore GOISH023 — the body ends in an infinite `loop` whose
//     every exit is a `return` from inside it, so there is no tail
//     expression to make explicit. Go writes the same shape: `for { … }`
//     with returns in the body.
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

// go: sdk 1.25.5 io/io.go:329-344 ReadAtLeast
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
    return (n, err);
}

// go: sdk 1.25.5 io/io.go:353-355 ReadFull
/// `io.ReadFull(r, buf)` (io.go:353) — read exactly `len(buf)` bytes
/// or fail. Thin wrapper over ReadAtLeast.
pub fn ReadFull(r: &mut dyn Reader, buf: &mut slice<byte>) -> (int, error) {
    let n = buf.Len();
    return ReadAtLeast(r, buf, n);
}
