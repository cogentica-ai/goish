// http_responsecontroller_smoke — net/http/responsecontroller.go.
//
// ResponseController exists for one reason: a handler wrapped in
// middleware must still be able to reach the real connection. Every
// method is the same walk — try the capability, else Unwrap and try
// again, else an error matching ErrNotSupported — so the checks that
// matter are the ones about the WALK, not about any single capability:
//
//   * check 3: a writer with no capability at all reports
//     ErrNotSupported, and reports it via errors::Is rather than by
//     identity. Go is explicit that errNotSupported returns something
//     that Is ErrNotSupported but is not == to it, so a caller cannot
//     come to depend on the pointer.
//   * check 4: the capability is found through TWO layers of wrapper.
//     One layer would also pass for an implementation that tried the
//     writer and then its unwrap once, without looping.
//   * check 5: FlushError WINS over Flush on a writer that has both.
//     That is the order of Go's type switch, and getting it backwards
//     silently swallows the write error a caller asked for.
//   * check 6: the walk terminates on a chain that unwraps to a plain
//     writer, instead of spinning.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, Ordering};

use goish::errors;
use goish::fmt;
use goish::goslice::slice;
use goish::net::http::responsewriter::{Flusher, HeaderHandle, ResponseWriter};
use goish::net::http::responsecontroller::{FlushErrorer, NewResponseController, rwUnwrapper};
use goish::net::http::{ErrNotSupported, Header};
use goish::types::{byte, int};
use goish::{string, syscall};

static FLUSHED: AtomicI64 = AtomicI64::new(0);
static FLUSH_ERRORED: AtomicI64 = AtomicI64::new(0);

/// A writer with NO optional capability — the ErrNotSupported case.
struct bare;

impl ResponseWriter for bare {
    fn Header(&self) -> HeaderHandle {
        return HeaderHandle::new(Header::new());
    }
    fn Write(&self, p: slice<byte>) -> (int, goish::error) {
        return (goish::builtin::len(&p), errors::nil);
    }
    fn WriteHeader(&self, _statusCode: int) {}

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

/// A writer that can Flush, and nothing else.
struct flushOnly;

impl ResponseWriter for flushOnly {
    fn Header(&self) -> HeaderHandle {
        return HeaderHandle::new(Header::new());
    }
    fn Write(&self, p: slice<byte>) -> (int, goish::error) {
        return (goish::builtin::len(&p), errors::nil);
    }
    fn WriteHeader(&self, _statusCode: int) {}

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Flusher for flushOnly {
    fn Flush(&self) {
        FLUSHED.fetch_add(1, Ordering::SeqCst);
    }

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

/// A writer with BOTH FlushError and Flush. Go's type switch reaches
/// FlushError first; if goish reached Flush first the error would be
/// lost.
struct bothFlushes;

impl ResponseWriter for bothFlushes {
    fn Header(&self) -> HeaderHandle {
        return HeaderHandle::new(Header::new());
    }
    fn Write(&self, p: slice<byte>) -> (int, goish::error) {
        return (goish::builtin::len(&p), errors::nil);
    }
    fn WriteHeader(&self, _statusCode: int) {}

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Flusher for bothFlushes {
    fn Flush(&self) {
        FLUSHED.fetch_add(1, Ordering::SeqCst);
    }

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl FlushErrorer for bothFlushes {
    fn FlushError(&self) -> goish::error {
        FLUSH_ERRORED.fetch_add(1, Ordering::SeqCst);
        return errors::New(string("disk on fire"));
    }

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

/// Middleware: forwards everything, exposes Unwrap.
struct wrapper {
    inner: Arc<dyn ResponseWriter + Send + Sync + 'static>,
}

impl ResponseWriter for wrapper {
    fn Header(&self) -> HeaderHandle {
        return self.inner.Header();
    }
    fn Write(&self, p: slice<byte>) -> (int, goish::error) {
        return self.inner.Write(p);
    }
    fn WriteHeader(&self, statusCode: int) {
        return self.inner.WriteHeader(statusCode);
    }

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl rwUnwrapper for wrapper {
    fn Unwrap(&self) -> Arc<dyn ResponseWriter + Send + Sync + 'static> {
        return self.inner.clone();
    }

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

fn wrap(
    inner: Arc<dyn ResponseWriter + Send + Sync + 'static>,
) -> Arc<dyn ResponseWriter + Send + Sync + 'static> {
    return Arc::new(wrapper { inner });
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // Every concrete implementor of a #[goish::interface] trait has to
    // be registered before `cast!` can find it through a `dyn` carrier.
    // Go's type switch needs no such step; goish's downcast consults a
    // per-trait registry, and an unregistered type simply reads as "does
    // not implement", which is a silent miss rather than an error.
    goish::net::http::responsewriter::__goish_register_ResponseWriter_impl::<bare>();
    goish::net::http::responsewriter::__goish_register_ResponseWriter_impl::<flushOnly>();
    goish::net::http::responsewriter::__goish_register_ResponseWriter_impl::<bothFlushes>();
    goish::net::http::responsewriter::__goish_register_ResponseWriter_impl::<wrapper>();
    goish::net::http::responsewriter::__goish_register_Flusher_impl::<flushOnly>();
    goish::net::http::responsewriter::__goish_register_Flusher_impl::<bothFlushes>();
    goish::net::http::responsecontroller::__goish_register_FlushErrorer_impl::<bothFlushes>();
    goish::net::http::responsecontroller::__goish_register_rwUnwrapper_impl::<wrapper>();

    // 1. Flush reaches a bare Flusher.
    {
        FLUSHED.store(0, Ordering::SeqCst);
        let w: Arc<dyn ResponseWriter + Send + Sync + 'static> = Arc::new(flushOnly);
        let rc = NewResponseController(w);
        let err = rc.Flush();
        if err.IsNil() && FLUSHED.load(Ordering::SeqCst) == 1 {
            fmt::Println!("[ 1] Flush reaches Flusher     PASS");
        } else {
            fmt::Println!("[ 1] Flush reaches Flusher     FAIL");
            failed += 1;
        }
    }

    // 2. The other four methods report ErrNotSupported on a writer that
    //    has none of them — the common case for a hand-written writer.
    {
        let w: Arc<dyn ResponseWriter + Send + Sync + 'static> = Arc::new(flushOnly);
        let rc = NewResponseController(w);
        let a = rc.SetReadDeadline(goish::time::Time::default());
        let b = rc.SetWriteDeadline(goish::time::Time::default());
        let c = rc.EnableFullDuplex();
        let target: goish::error = ErrNotSupported.into();
        if errors::Is(a, target.clone())
            && errors::Is(b, target.clone())
            && errors::Is(c, target)
        {
            fmt::Println!("[ 2] deadlines unsupported     PASS");
        } else {
            fmt::Println!("[ 2] deadlines unsupported     FAIL");
            failed += 1;
        }
    }

    // 3. ErrNotSupported is matched by errors::Is and NOT by identity.
    //    Go wraps it with %w precisely so callers cannot compare
    //    pointers; if goish returned the sentinel itself this would
    //    still pass the Is half and quietly license `==`.
    {
        let w: Arc<dyn ResponseWriter + Send + Sync + 'static> = Arc::new(bare);
        let rc = NewResponseController(w);
        let err = rc.Flush();
        let target: goish::error = ErrNotSupported.into();
        let is = errors::Is(err.clone(), target.clone());
        let same = err == target;
        if is && !same {
            fmt::Println!("[ 3] Is but not ==             PASS");
        } else {
            fmt::Println!("[ 3] Is but not ==             FAIL is=", is, " same=", same);
            failed += 1;
        }
    }

    // 4. The walk goes through TWO wrappers. A single unwrap would pass
    //    a one-layer test and fail here.
    {
        FLUSHED.store(0, Ordering::SeqCst);
        let inner: Arc<dyn ResponseWriter + Send + Sync + 'static> = Arc::new(flushOnly);
        let w = wrap(wrap(inner));
        let rc = NewResponseController(w);
        let err = rc.Flush();
        if err.IsNil() && FLUSHED.load(Ordering::SeqCst) == 1 {
            fmt::Println!("[ 4] unwraps two layers        PASS");
        } else {
            fmt::Println!("[ 4] unwraps two layers        FAIL");
            failed += 1;
        }
    }

    // 5. FlushError wins over Flush. Go's type switch lists it first,
    //    and the whole point is to surface a write failure the plain
    //    Flush() signature cannot report.
    {
        FLUSHED.store(0, Ordering::SeqCst);
        FLUSH_ERRORED.store(0, Ordering::SeqCst);
        let w: Arc<dyn ResponseWriter + Send + Sync + 'static> = Arc::new(bothFlushes);
        let rc = NewResponseController(w);
        let err = rc.Flush();
        if !err.IsNil()
            && err.Error() == "disk on fire"
            && FLUSH_ERRORED.load(Ordering::SeqCst) == 1
            && FLUSHED.load(Ordering::SeqCst) == 0
        {
            fmt::Println!("[ 5] FlushError beats Flush    PASS");
        } else {
            fmt::Println!("[ 5] FlushError beats Flush    FAIL");
            failed += 1;
        }
    }

    // 6. A wrapped writer with no capability terminates rather than
    //    spinning: the walk must stop when Unwrap runs out.
    {
        let inner: Arc<dyn ResponseWriter + Send + Sync + 'static> = Arc::new(bare);
        let rc = NewResponseController(wrap(wrap(inner)));
        let err = rc.EnableFullDuplex();
        let target: goish::error = ErrNotSupported.into();
        if errors::Is(err, target) {
            fmt::Println!("[ 6] walk terminates           PASS");
        } else {
            fmt::Println!("[ 6] walk terminates           FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
