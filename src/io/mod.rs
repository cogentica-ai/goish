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
//   var EOF = errors.New("EOF")          pub fn EOF() -> error  // cached, ptr-stable
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

use crate::errors::error;
use crate::goslice::slice;
use crate::types::{byte, int};
use crate::{errors, nil};

// ─── Reader / Writer / Closer traits ───────────────────────────────────

/// Go's `io.Reader`. Read up to `len(p)` bytes into `p`; returns
/// `(n, err)`. EOF is signaled by returning `io::EOF()` as the error.
pub trait Reader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error);
}

/// Go's `io.Writer`. Write `len(p)` bytes from `p`. Returns `(n, err)`
/// where `n < len(p)` requires a non-nil `err`.
pub trait Writer {
    fn Write(&mut self, p: slice<byte>) -> (int, error);
}

/// Go's `io.Closer`.
pub trait Closer {
    fn Close(&mut self) -> error;
}

// Blanket impls so `&mut R` and `&mut W` satisfy the trait without
// transferring ownership. Mirrors Go's "any pointer-receiver method
// promotes through a `*T`" — lets callers do
// `bufio.NewWriter(&mut buf)` and keep `buf` alive after.
impl<R: Reader + ?Sized> Reader for &mut R {
    #[inline]
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        (**self).Read(p)
    }
}

impl<W: Writer + ?Sized> Writer for &mut W {
    #[inline]
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        (**self).Write(p)
    }
}

impl<C: Closer + ?Sized> Closer for &mut C {
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
// every call to `EOF()` returns a clone of the *same* Arc, so
// `errors::Is(err, io::EOF())` succeeds via Arc::ptr_eq.
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

/// `io.EOF` — the sentinel returned by Reader.Read at end-of-input.
pub fn EOF() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || errors::New("EOF"))
}

/// `io.ErrShortWrite` — Writer wrote fewer bytes than requested,
/// non-nil error, no other reason.
pub fn ErrShortWrite() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || errors::New("short write"))
}

/// `io.ErrUnexpectedEOF` — Reader hit EOF mid-record (e.g. ReadFull
/// got fewer bytes than buffer length).
pub fn ErrUnexpectedEOF() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || errors::New("unexpected EOF"))
}

/// `io.ErrShortBuffer` — provided buffer was too small.
pub fn ErrShortBuffer() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || errors::New("short buffer"))
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
    let eof = EOF();
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
                return (total, ErrShortWrite());
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
pub fn WriteString(w: &mut dyn Writer, s: crate::gostring::string) -> (int, error) {
    let buf = crate::convert::bytes(s);
    w.Write(buf)
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
            return (0, EOF());
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

// ─── ReadAll / ReadFull / ReadAtLeast ────────────────────────────────

/// `io.ReadAll(r)` (io.go:709) — drain `r` until EOF/error, return the
/// accumulated bytes. EOF is normal termination (returned err == nil).
///
/// Slim deviation: uses `bytes::Buffer` for the growing accumulator
/// rather than Go's `b[len(b):cap(b)]` capacity-grow trick (goish slice
/// subslicing copies, so the Go pattern doesn't apply).
pub fn ReadAll(r: &mut dyn Reader) -> (slice<byte>, error) {
    let eof = EOF();
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
        return (0, ErrShortBuffer());
    }
    let eof = EOF();
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
        err = ErrUnexpectedEOF();
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
        let eof = EOF();
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
        (0, EOF())
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
                return (n, ErrShortWrite());
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
