// http_persistconn_smoke — transport.go's persistConn state machine,
// the part the connection pool reasons about. Values from goref.
//
// Staged port: nothing constructs a persistConn on a live request yet.
// These are the invariants the pool depends on, tested now so the
// rewire has something to land against.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::transport::{
    connectMethodKey, errCloseIdleConns, errRequestCanceled, persistConn, shouldRetryRequest,
};
use goish::net::http::{NewRequest, Transport};
use goish::{errors, slice, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let key = connectMethodKey::default();

    // A fresh conn is neither reused nor broken.
    {
        let pc = persistConn::__new(key.clone());
        check(
            "a fresh persistConn is not reused and not broken",
            !pc.isReused() && !pc.isBroken() && pc.canceled().IsNil(),
            string(""),
        );
        pc.markReused();
        check("markReused flips isReused", pc.isReused(), string(""));
    }

    // close records the FIRST reason only.
    {
        let pc = persistConn::__new(key.clone());
        pc.close(errCloseIdleConns.into());
        let broken_after_first = pc.isBroken();
        let first = pc.__closed_err().Error();
        pc.close(errors::New(string("a later, less useful reason")));
        // Go guards on `pc.closed == nil`, so only the FIRST reason is
        // kept — a later close must not bury the error that explains
        // the failure.
        check(
            "close marks broken, and a second close cannot overwrite the reason",
            broken_after_first
                && pc.isBroken()
                && first == "http: CloseIdleConnections called"
                && pc.__closed_err().Error() == first,
            pc.__closed_err().Error(),
        );
    }

    // cancelRequest records why AND closes.
    {
        let pc = persistConn::__new(key.clone());
        let why = errors::New(string("context deadline exceeded"));
        pc.cancelRequest(why);
        check(
            "cancelRequest records canceledErr and closes the conn",
            pc.isBroken()
                && !pc.canceled().IsNil()
                && pc.canceled().Error() == "context deadline exceeded",
            pc.canceled().Error(),
        );
        // Go sets canceledErr to the CAUSE but closes with
        // errRequestCanceled — two different errors, deliberately.
        check(
            "the cancel cause is kept distinct from the close reason",
            {
                let rc: goish::error = errRequestCanceled.into();
                pc.canceled().Error() != rc.Error()
            },
            pc.canceled().Error(),
        );
    }

    // isReused is what gates the retry decision.
    {
        let (get, _) = NewRequest(string("GET"), string("http://x/"), slice::new());
        let pc = persistConn::__new(key.clone());
        let before = shouldRetryRequest(
            &get,
            goish::net::http::transport::errServerClosedIdle.into(),
            pc.isReused(),
        );
        pc.markReused();
        let after = shouldRetryRequest(
            &get,
            goish::net::http::transport::errServerClosedIdle.into(),
            pc.isReused(),
        );
        check(
            "markReused is exactly what makes a request retryable",
            !before && after,
            string(""),
        );
    }

    // maxHeaderResponseSize: 10 MiB default, negative passes through.
    {
        let mut t = Transport::default();
        let d = persistConn::maxHeaderResponseSize(&t);
        t.MaxResponseHeaderBytes = -1;
        let neg = persistConn::maxHeaderResponseSize(&t);
        t.MaxResponseHeaderBytes = 4096;
        let set = persistConn::maxHeaderResponseSize(&t);
        check(
            "maxHeaderResponseSize: 10 MiB default, negative passes through",
            d == 10 << 20 && neg == -1 && set == 4096,
            fmt::Sprintf!("d=%d neg=%d set=%d", d, neg, set),
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_PERSISTCONN_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_PERSISTCONN_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
