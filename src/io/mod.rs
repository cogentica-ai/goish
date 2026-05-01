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
