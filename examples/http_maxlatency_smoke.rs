// http_maxlatency_smoke — reverseproxy.go's body-copy half:
// copyBuffer, copyResponse, maxLatencyWriter and the BufferPool hook.
//
// The interesting behaviour is all about WHEN a flush happens, and
// what a partial copy reports:
//
//   * a negative flush interval means "flush on every write" — that is
//     how flushInterval() spells an SSE stream, and buffering one is
//     indistinguishable from a hung backend.
//   * a positive interval must NOT flush inline. It arms one timer and
//     coalesces: writes arriving while a flush is pending do not each
//     schedule their own.
//   * stop() must cancel a pending flush. Go re-checks flushPending
//     inside delayedFlush for exactly this race.
//   * copyBuffer reports a short write as io.ErrShortWrite rather than
//     silently truncating, and normalises EOF to nil.
//   * a non-EOF read error is logged but the bytes already read are
//     still written before it is returned.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, Ordering};

use goish::bytes;
use goish::errors;
use goish::fmt;
use goish::goslice::slice;
use goish::net::http::httputil::reverseproxy::{__newMaxLatencyWriter, BufferPool, ReverseProxy};
use goish::net::http::responsewriter::{Flusher, HeaderHandle, ResponseWriter};
use goish::net::http::Header;
use goish::time;
use goish::types::{byte, int};
use goish::{make, string};

static PASSED: AtomicI64 = AtomicI64::new(0);
static FAILED: AtomicI64 = AtomicI64::new(0);
static FLUSHES: AtomicI64 = AtomicI64::new(0);
static WRITTEN: AtomicI64 = AtomicI64::new(0);
static POOL_GETS: AtomicI64 = AtomicI64::new(0);
static POOL_PUTS: AtomicI64 = AtomicI64::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

// ── a ResponseWriter that counts flushes and bytes ────────────────

struct counting;

impl ResponseWriter for counting {
    fn Header(&self) -> HeaderHandle {
        return HeaderHandle::new(Header::new());
    }
    fn Write(&self, p: slice<byte>) -> (int, goish::error) {
        let n = goish::builtin::len(&p);
        WRITTEN.fetch_add(n as i64, Ordering::Relaxed);
        return (n, errors::nil);
    }
    fn WriteHeader(&self, _statusCode: int) {}

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Flusher for counting {
    fn Flush(&self) {
        FLUSHES.fetch_add(1, Ordering::Relaxed);
    }
}

// ── io::Writer stand-ins for copyBuffer's failure modes ───────────

/// Accepts everything and remembers it.
struct sink {
    got: Vec<u8>,
}

impl goish::io::Writer for sink {
    fn Write(&mut self, p: slice<byte>) -> (int, goish::error) {
        let n = goish::builtin::len(&p);
        for i in 0..n {
            self.got.push(p[i]);
        }
        return (n, errors::nil);
    }
}

/// Reports one byte fewer than it was given — the io.ErrShortWrite case.
struct shortWriter;

impl goish::io::Writer for shortWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, goish::error) {
        let n = goish::builtin::len(&p);
        if n == 0 {
            return (0, errors::nil);
        }
        return (n - 1, errors::nil);
    }
}

/// Fails outright.
struct failWriter;

impl goish::io::Writer for failWriter {
    fn Write(&mut self, _p: slice<byte>) -> (int, goish::error) {
        return (0, errors::New(string("disk on fire")));
    }
}

/// Yields `abc`, then a read error that is neither EOF nor
/// context.Canceled — Go logs it and returns it, but only AFTER the
/// bytes it already handed over have been written.
struct partialReader {
    done: bool,
}

impl goish::io::Reader for partialReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, goish::error) {
        if self.done {
            return (0, errors::New(string("backend hung up")));
        }
        self.done = true;
        let src = goish::bytes("abc");
        for i in 0..3 {
            p[i] = src[i];
        }
        return (3, errors::New(string("backend hung up")));
    }
}

// ── a BufferPool that counts ──────────────────────────────────────

struct countingPool;

impl BufferPool for countingPool {
    fn Get(&self) -> slice<byte> {
        POOL_GETS.fetch_add(1, Ordering::Relaxed);
        return make!([]byte, 8);
    }
    fn Put(&self, _b: slice<byte>) {
        POOL_PUTS.fetch_add(1, Ordering::Relaxed);
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() -> ! {
    goish::net::http::responsewriter::__goish_register_ResponseWriter_impl::<counting>();
    goish::net::http::responsewriter::__goish_register_Flusher_impl::<counting>();

    let p = ReverseProxy::default();

    // ── copyBuffer ────────────────────────────────────────────────
    {
        let mut src = bytes::NewReader(goish::bytes("hello world"));
        let mut dst = sink { got: Vec::new() };
        let (n, err) = p.copyBuffer(&mut dst, &mut src, slice::<byte>::new());
        check(
            "copyBuffer copies every byte and normalises EOF to nil",
            n == 11 && err.IsNil() && dst.got.as_slice() == b"hello world",
            fmt::Sprintf!("n=%d err=%v", n, err),
        );
    }
    {
        let mut src = bytes::NewReader(goish::bytes("hello"));
        let mut dst = shortWriter;
        let (n, err) = p.copyBuffer(&mut dst, &mut src, slice::<byte>::new());
        check(
            "a short write is io.ErrShortWrite, not silent truncation",
            errors::Is(err.clone(), goish::io::ErrShortWrite) && n == 4,
            fmt::Sprintf!("n=%d err=%v", n, err),
        );
    }
    {
        let mut src = bytes::NewReader(goish::bytes("hello"));
        let mut dst = failWriter;
        let (n, err) = p.copyBuffer(&mut dst, &mut src, slice::<byte>::new());
        check(
            "a write error is returned verbatim with nothing counted",
            !err.IsNil() && err.Error() == "disk on fire" && n == 0,
            fmt::Sprintf!("n=%d err=%v", n, err),
        );
    }
    {
        let mut src = partialReader { done: false };
        let mut dst = sink { got: Vec::new() };
        let (n, err) = p.copyBuffer(&mut dst, &mut src, slice::<byte>::new());
        check(
            "bytes read before a non-EOF read error are still written",
            n == 3 && dst.got.as_slice() == b"abc" && !err.IsNil(),
            fmt::Sprintf!("n=%d got=%d err=%v", n, dst.got.len() as i64, err),
        );
    }

    // ── copyResponse: no flush interval ───────────────────────────
    let rw: Arc<dyn ResponseWriter + Send + Sync + 'static> = Arc::new(counting);
    {
        FLUSHES.store(0, Ordering::Relaxed);
        WRITTEN.store(0, Ordering::Relaxed);
        let mut src = bytes::NewReader(goish::bytes("0123456789"));
        let err = p.copyResponse(rw.clone(), &mut src, time::Duration(0));
        check(
            "a zero interval copies straight through and never flushes",
            err.IsNil() && WRITTEN.load(Ordering::Relaxed) == 10
                && FLUSHES.load(Ordering::Relaxed) == 0,
            fmt::Sprintf!(
                "wrote=%d flushes=%d",
                WRITTEN.load(Ordering::Relaxed),
                FLUSHES.load(Ordering::Relaxed)
            ),
        );
    }

    // ── copyResponse: BufferPool is consulted, and returned to ────
    {
        let pooled = ReverseProxy {
            BufferPool: Some(Arc::new(countingPool)),
            ..Default::default()
        };
        let mut src = bytes::NewReader(goish::bytes("0123456789ABCDEFGHIJ"));
        let err = pooled.copyResponse(rw.clone(), &mut src, time::Duration(0));
        check(
            "the BufferPool is used for the copy and the buffer is Put back",
            err.IsNil()
                && POOL_GETS.load(Ordering::Relaxed) == 1
                && POOL_PUTS.load(Ordering::Relaxed) == 1,
            fmt::Sprintf!(
                "gets=%d puts=%d",
                POOL_GETS.load(Ordering::Relaxed),
                POOL_PUTS.load(Ordering::Relaxed)
            ),
        );
    }

    // ── maxLatencyWriter: negative latency flushes inline ─────────
    {
        FLUSHES.store(0, Ordering::Relaxed);
        WRITTEN.store(0, Ordering::Relaxed);
        let mut src = bytes::NewReader(goish::bytes("0123456789"));
        let err = p.copyResponse(rw.clone(), &mut src, time::Duration(-1));
        check(
            "a negative interval still copies the whole body",
            err.IsNil() && WRITTEN.load(Ordering::Relaxed) == 10,
            fmt::Sprintf!("wrote=%d", WRITTEN.load(Ordering::Relaxed)),
        );

        // The count is what matters, and it must be per-write and
        // INLINE — no timer is involved on this path at all. A `>= 1`
        // assertion here would pass on the initial armed flush alone,
        // which is not the property SSE depends on.
        FLUSHES.store(0, Ordering::Relaxed);
        let mlw = __newMaxLatencyWriter(rw.clone(), time::Duration(-1));
        let _ = mlw.Write(goish::bytes("a"));
        let _ = mlw.Write(goish::bytes("b"));
        let _ = mlw.Write(goish::bytes("c"));
        check(
            "a negative interval flushes on every write (the SSE case)",
            FLUSHES.load(Ordering::Relaxed) == 3,
            fmt::Sprintf!("flushes=%d", FLUSHES.load(Ordering::Relaxed)),
        );
        mlw.stop();
    }

    // ── maxLatencyWriter: a positive latency defers, then fires ───
    {
        FLUSHES.store(0, Ordering::Relaxed);
        let mlw = __newMaxLatencyWriter(
            rw.clone(),
            time::Duration(120 * 1_000_000),
        );
        // The deadline belongs to the FIRST write of a pending run.
        // A later write must not push it out — that is what Go's
        // `if m.flushPending { return }` buys, and without it a busy
        // stream can starve the flush indefinitely. So: write at t=0,
        // write again at t=100ms, and look at t=160ms. Held deadline
        // ⇒ already flushed; slid deadline ⇒ not yet.
        let _ = mlw.Write(goish::bytes("a"));
        let early = FLUSHES.load(Ordering::Relaxed);
        time::Sleep(time::Duration(100 * 1_000_000));
        let _ = mlw.Write(goish::bytes("b"));
        time::Sleep(time::Duration(60 * 1_000_000));
        let late = FLUSHES.load(Ordering::Relaxed);
        time::Sleep(time::Duration(200 * 1_000_000));
        let settled = FLUSHES.load(Ordering::Relaxed);
        check(
            "a positive interval defers the flush and a later write does not push it out",
            early == 0 && late == 1 && settled == 1,
            fmt::Sprintf!("early=%d late=%d settled=%d", early, late, settled),
        );
        mlw.stop();
    }

    // ── stop() cancels a pending flush ────────────────────────────
    {
        FLUSHES.store(0, Ordering::Relaxed);
        let mlw = __newMaxLatencyWriter(
            rw.clone(),
            time::Duration(120 * 1_000_000),
        );
        let _ = mlw.Write(goish::bytes("a"));
        mlw.stop();
        time::Sleep(time::Duration(300 * 1_000_000));
        check(
            "stop() cancels the pending flush",
            FLUSHES.load(Ordering::Relaxed) == 0,
            fmt::Sprintf!("flushes=%d", FLUSHES.load(Ordering::Relaxed)),
        );
    }

    let pa = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", pa, f);
    if f == 0 {
        fmt::Printf!("HTTP_MAXLATENCY_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_MAXLATENCY_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
