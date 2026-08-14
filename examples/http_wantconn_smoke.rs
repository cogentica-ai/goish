// http_wantconn_smoke — transport.go's wantConn, the record a request
// waits on while a connection is dialled or fished out of the pool.
//
// Staged: the `result` channel and getConn are not ported. What is
// tested is the state machine those coordinate through, and its two
// safety properties — delivery is idempotent (several dials may race
// for one waiter, only one wins) and cancelling AFTER a delivery
// hands the connection back to the pool instead of dropping it.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::transport::{
    connectMethod, persistConn, wantConn, wantConnQueue, Waiter,
};
use goish::net::http::{ParseURL, Transport};
use goish::{errors, string, time};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok { PASSED.fetch_add(1, Ordering::Relaxed); fmt::Printf!("PASS: %s\n", name); }
    else { FAILED.fetch_add(1, Ordering::Relaxed); fmt::Printf!("FAIL: %s — %s\n", name, detail); }
}

fn conn(host: &'static str) -> Arc<persistConn> {
    let (u, _) = ParseURL(fmt::Sprintf!("http://%s/", string(host)));
    let cm = connectMethod {
        proxyURL: None,
        targetScheme: string("http"),
        targetAddr: goish::net::http::transport::canonicalAddr(&u),
        onlyH1: false,
    };
    Arc::new(persistConn::__new(cm.key()))
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn run() {
    let z = time::Time::default();

    // A fresh waiter is waiting; delivery ends that, once.
    {
        let w = Arc::new(wantConn::__new());
        check("a fresh wantConn is waiting", w.waiting(), string(""));
        let first = w.tryDeliver(Some(conn("a.com")), errors::nil, z);
        let second = w.tryDeliver(Some(conn("a.com")), errors::nil, z);
        check("delivery succeeds once and only once, and ends the wait",
              first && !second && !w.waiting(), string(""));
    }

    // An error delivery is equally valid and equally final.
    {
        let w = Arc::new(wantConn::__new());
        let ok = w.tryDeliver(None, errors::New(string("dial failed")), z);
        check("an error can be delivered instead of a conn",
              ok && !w.waiting() && w.__delivered().is_none(), string(""));
    }

    // Cancelling AFTER delivery returns the conn to the pool.
    {
        let t = Transport::default();
        let w = Arc::new(wantConn::__new());
        let pc = conn("a.com");
        let _ = w.tryDeliver(Some(pc.clone()), errors::nil, z);
        w.cancel(&t);
        // Handed back means pooled, which marks it reused.
        check("cancel after delivery hands the conn back to the pool",
              pc.isReused() && !pc.isBroken(), string(""));
        // And it really is in the pool: the per-host cap of 2 now has
        // one slot used, so a third of the same host is refused.
        let e1 = t.tryPutIdleConn(&conn("a.com"));
        let e2 = t.tryPutIdleConn(&conn("a.com"));
        check("the handed-back conn occupies a real pool slot",
              e1.IsNil() && !e2.IsNil(), fmt::Sprintf!("%v / %v", e1, e2));
    }

    // Cancelling BEFORE delivery just ends the wait.
    {
        let t = Transport::default();
        let w = Arc::new(wantConn::__new());
        w.cancel(&t);
        check("cancel before delivery ends the wait with nothing to return",
              !w.waiting() && w.__delivered().is_none(), string(""));
    }

    // The queue drops waiters that are no longer waiting.
    {
        let mut q = wantConnQueue::<Arc<wantConn>>::new();
        let a = Arc::new(wantConn::__new());
        let b = Arc::new(wantConn::__new());
        q.pushBack(a.clone());
        q.pushBack(b.clone());
        let _ = a.tryDeliver(Some(conn("a.com")), errors::nil, z);
        let cleaned = q.cleanFrontNotWaiting();
        check("cleanFrontNotWaiting drops a delivered waiter from the front",
              cleaned && q.len() == 1, fmt::Sprintf!("cleaned=%v len=%d", cleaned, q.len()));
        // b is still waiting, so a second sweep changes nothing.
        check("and stops at the first still-waiting entry",
              !q.cleanFrontNotWaiting() && q.len() == 1, string(""));
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 { fmt::Printf!("HTTP_WANTCONN_SMOKE_OK\n"); goish::os::Exit(0); }
    fmt::Printf!("HTTP_WANTCONN_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
