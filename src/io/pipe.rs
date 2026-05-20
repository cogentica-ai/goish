// io/pipe — Go's io.Pipe (synchronous in-memory pipe).
//
// Line-by-line port of /share/go/src/io/pipe.go. Wires an io.Reader
// to an io.Writer via a pair of shared chans:
//
//   wrCh chan []byte  — writer hands a buffer slice to a reader
//   rdCh chan int     — reader reports how many bytes it consumed
//   done chan struct{} — closed by either side to terminate the pipe
//
// PipeReader and PipeWriter share a single Arc<PipeData> so that
// closing one half is observable from the other.
//
// **Goish deviations from Go's pipe.go:**
//   - Go embeds `pipe` directly into PipeReader and `r PipeReader` into
//     PipeWriter so `&pw.r` and `pw` share the same memory; goish uses
//     Arc<PipeData> for the same shared-state effect.
//   - Go uses a private `onceError` (sync.Mutex + error field). Goish
//     reuses sync::Mutex<error> directly with the same store-once
//     semantics.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;

use crate::errors::error;
use crate::gochan::chan;
use crate::goslice::slice;
use crate::errors::nil;
use crate::sync::{Mutex, Once};
use crate::types::{byte, int};

use super::{Closer, Reader, Writer, EOF};

// ─── ErrClosedPipe (pipe.go:36) ───────────────────────────────────────

crate::var! {
    /// `io.ErrClosedPipe` (pipe.go:36) — error returned from Read/Write
    /// on a closed pipe. Identity-stable so `errors::Is(err, ErrClosedPipe)`
    /// succeeds via Arc::ptr_eq.
    pub ErrClosedPipe: error = "io: read/write on closed pipe";
}

// ─── onceError (pipe.go:16-33) ───────────────────────────────────────

/// `onceError` (pipe.go:16) — stores the FIRST non-nil error; later
/// stores are ignored. Mirrors Go's sync.Mutex-protected struct.
struct OnceError {
    inner: Mutex<error>,
}

impl OnceError {
    const fn new() -> Self {
        OnceError { inner: Mutex::new(nil) }
    }
    // Go: func (a *onceError) Store(err error)
    fn Store(&self, err: error) {
        // Go: a.Lock(); defer a.Unlock()
        let mut g = self.inner.Lock();
        // Go: if a.err != nil { return }
        if !g.IsNil() {
            return;
        }
        // Go: a.err = err
        *g = err;
    }
    // Go: func (a *onceError) Load() error
    fn Load(&self) -> error {
        // Go: a.Lock(); defer a.Unlock(); return a.err
        let g = self.inner.Lock();
        g.clone()
    }
}

// ─── pipe (pipe.go:39) ────────────────────────────────────────────────

/// `pipe` (pipe.go:39) — internal shared state. Held in an Arc so both
/// PipeReader and PipeWriter can observe each other's close.
struct PipeData {
    // Go: wrMu sync.Mutex (serializes Write operations)
    wrMu: Mutex,
    // Go: wrCh chan []byte
    wrCh: chan<slice<byte>>,
    // Go: rdCh chan int
    rdCh: chan<int>,
    // Go: once sync.Once (protects closing done)
    once: Once,
    // Go: done chan struct{}
    done: chan<()>,
    // Go: rerr onceError
    rerr: OnceError,
    // Go: werr onceError
    werr: OnceError,
}

impl PipeData {
    // Go: func (p *pipe) read(b []byte) (n int, err error) — pipe.go:50
    fn read(&self, b: &mut slice<byte>) -> (int, error) {
        // select! requires bare-ident chan operands; clone the chan
        // handles into locals (Arc clone, cheap) before the macro.
        let done = self.done.clone();
        let wrCh = self.wrCh.clone();

        // Go: select { case <-p.done: return 0, p.readCloseError(); default: }
        let mut closed = false;
        crate::select! {
            let _ = done.Recv() => { closed = true; },
            default => {},
        }
        if closed {
            return (0, self.readCloseError());
        }

        // Go: select { case bw := <-p.wrCh: ... case <-p.done: ... }
        let mut bw_opt: Option<slice<byte>> = None;
        let mut closed = false;
        crate::select! {
            let bw_v = wrCh.Recv() => { bw_opt = Some(bw_v); },
            let _ = done.Recv() => { closed = true; },
        }
        if closed {
            return (0, self.readCloseError());
        }
        let bw = bw_opt.unwrap();
        // Go: nr := copy(b, bw)
        let nr: int = crate::copy!(*b, bw);
        // Go: p.rdCh <- nr
        self.rdCh.Send(nr);
        // Go: return nr, nil
        (nr, nil)
    }

    // Go: func (p *pipe) closeRead(err error) error — pipe.go:67
    fn closeRead(&self, mut err: error) -> error {
        // Go: if err == nil { err = ErrClosedPipe }
        if err.IsNil() {
            err = ErrClosedPipe.into();
        }
        // Go: p.rerr.Store(err)
        self.rerr.Store(err);
        // Go: p.once.Do(func() { close(p.done) })
        self.once.Do(|| {
            self.done.Close();
        });
        // Go: return nil
        nil
    }

    // Go: func (p *pipe) write(b []byte) (n int, err error) — pipe.go:76
    fn write(&self, mut b: slice<byte>) -> (int, error) {
        // select! requires bare-ident chan operands; clone the chan
        // handles into locals (Arc clone, cheap) before the macro.
        let done = self.done.clone();
        let wrCh = self.wrCh.clone();

        // Go: select { case <-p.done: return 0, p.writeCloseError(); default: { p.wrMu.Lock(); defer p.wrMu.Unlock() } }
        let mut closed = false;
        crate::select! {
            let _ = done.Recv() => { closed = true; },
            default => {},
        }
        if closed {
            return (0, self.writeCloseError());
        }
        let _g = self.wrMu.Lock();

        // Go: var n int; for once := true; once || len(b) > 0; once = false { ... }
        let mut n: int = 0;
        let mut once_flag = true;
        while once_flag || b.Len() > 0 {
            once_flag = false;
            // Go: select { case p.wrCh <- b: nw := <-p.rdCh; b = b[nw:]; n += nw
            //              case <-p.done: return n, p.writeCloseError() }
            let mut sent = false;
            let mut done_fired = false;
            crate::select! {
                wrCh.Send(b.clone()) => { sent = true; },
                let _ = done.Recv() => { done_fired = true; },
            }
            if done_fired {
                return (n, self.writeCloseError());
            }
            // Go: nw := <-p.rdCh
            let (nw, _) = self.rdCh.Recv();
            // Go: b = b[nw:]
            b = b.slice(nw, b.Len());
            // Go: n += nw
            n += nw;
            let _ = sent;
        }
        // Go: return n, nil
        (n, nil)
    }

    // Go: func (p *pipe) closeWrite(err error) error — pipe.go:98
    fn closeWrite(&self, mut err: error) -> error {
        // Go: if err == nil { err = EOF }
        if err.IsNil() {
            err = EOF.into();
        }
        // Go: p.werr.Store(err)
        self.werr.Store(err);
        // Go: p.once.Do(func() { close(p.done) })
        self.once.Do(|| {
            self.done.Close();
        });
        // Go: return nil
        nil
    }

    // Go: func (p *pipe) readCloseError() error — pipe.go:108
    fn readCloseError(&self) -> error {
        // Go: rerr := p.rerr.Load()
        let rerr = self.rerr.Load();
        // Go: if werr := p.werr.Load(); rerr == nil && werr != nil { return werr }
        let werr = self.werr.Load();
        if rerr.IsNil() && !werr.IsNil() {
            return werr;
        }
        // Go: return ErrClosedPipe
        ErrClosedPipe.into()
    }

    // Go: func (p *pipe) writeCloseError() error — pipe.go:117
    fn writeCloseError(&self) -> error {
        // Go: werr := p.werr.Load()
        let werr = self.werr.Load();
        // Go: if rerr := p.rerr.Load(); werr == nil && rerr != nil { return rerr }
        let rerr = self.rerr.Load();
        if werr.IsNil() && !rerr.IsNil() {
            return rerr;
        }
        // Go: return ErrClosedPipe
        ErrClosedPipe.into()
    }
}

// ─── PipeReader / PipeWriter (pipe.go:126 / pipe.go:152) ──────────────

/// `PipeReader` (pipe.go:126) — read half of a pipe. Reads block until
/// a writer sends or the write end closes.
pub struct PipeReader {
    p: Arc<PipeData>,
}

impl PipeReader {
    /// `(*PipeReader).Read(data)` (pipe.go:133).
    pub fn Read(&mut self, data: &mut slice<byte>) -> (int, error) {
        // Go: return r.pipe.read(data)
        self.p.read(data)
    }

    /// `(*PipeReader).Close()` (pipe.go:139).
    pub fn Close(&self) -> error {
        // Go: return r.CloseWithError(nil)
        self.CloseWithError(nil)
    }

    /// `(*PipeReader).CloseWithError(err)` (pipe.go:148). Subsequent
    /// Writes return `err` (or `ErrClosedPipe` if `err == nil`).
    /// Never overwrites a previous error and always returns nil.
    pub fn CloseWithError(&self, err: error) -> error {
        // Go: return r.pipe.closeRead(err)
        self.p.closeRead(err)
    }
}

impl Reader for PipeReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        self.p.read(p)
    }
}

impl Closer for PipeReader {
    fn Close(&mut self) -> error {
        self.CloseWithError(nil)
    }
}

/// `PipeWriter` (pipe.go:152) — write half of a pipe. Writes block
/// until one or more readers consume the data or the read end closes.
pub struct PipeWriter {
    p: Arc<PipeData>,
}

impl PipeWriter {
    /// `(*PipeWriter).Write(data)` (pipe.go:160).
    pub fn Write(&mut self, data: slice<byte>) -> (int, error) {
        // Go: return w.r.pipe.write(data)
        self.p.write(data)
    }

    /// `(*PipeWriter).Close()` (pipe.go:166). Subsequent Reads return
    /// `(0, EOF)`.
    pub fn Close(&self) -> error {
        // Go: return w.CloseWithError(nil)
        self.CloseWithError(nil)
    }

    /// `(*PipeWriter).CloseWithError(err)` (pipe.go:176). Subsequent
    /// Reads return `(0, err)` (or `(0, EOF)` if `err == nil`). Never
    /// overwrites a previous error and always returns nil.
    pub fn CloseWithError(&self, err: error) -> error {
        // Go: return w.r.pipe.closeWrite(err)
        self.p.closeWrite(err)
    }
}

impl Writer for PipeWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        self.p.write(p)
    }
}

impl Closer for PipeWriter {
    fn Close(&mut self) -> error {
        self.CloseWithError(nil)
    }
}

// ─── Pipe (pipe.go:195) ───────────────────────────────────────────────

/// `io.Pipe()` (pipe.go:195) — synchronous in-memory pipe. Returns the
/// read half and the write half. Reads and Writes are matched
/// one-to-one (a single Write may satisfy multiple Reads, but the Write
/// blocks until all of its data is consumed).
///
/// Safe to call Read and Write in parallel with each other and with
/// Close. Parallel Reads or parallel Writes are also safe (each call
/// is gated sequentially via `wrMu` and the unbuffered chans).
pub fn Pipe() -> (PipeReader, PipeWriter) {
    // Go: pw := &PipeWriter{r: PipeReader{pipe: pipe{
    //         wrCh: make(chan []byte),
    //         rdCh: make(chan int),
    //         done: make(chan struct{}),
    // }}}
    let p = Arc::new(PipeData {
        wrMu: Mutex::new(()),
        wrCh: chan::<slice<byte>>::new_unbuffered(),
        rdCh: chan::<int>::new_unbuffered(),
        once: Once::new(),
        done: chan::<()>::new_unbuffered(),
        rerr: OnceError::new(),
        werr: OnceError::new(),
    });
    // Go: return &pw.r, pw
    (
        PipeReader { p: p.clone() },
        PipeWriter { p },
    )
}
