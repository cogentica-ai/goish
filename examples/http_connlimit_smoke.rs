// http_connlimit_smoke — transport.go's MaxConnsPerHost limiter.
//
// Staged: startDialConnForLocked is not ported, so decConnsPerHost
// RETURNS the waiter it would have started rather than starting it.
// The policy is what matters and is testable now.
//
// The hand-off is the subtle part. When a slot frees, Go gives it to a
// still-waiting dialer instead of decrementing the count — and skips
// waiters that have since given up, because "we don't want to kick off
// any spurious dial operations". Always decrementing instead would
// leave a waiter parked while the count claims a slot is free.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::transport::{connectMethod, persistConn, wantConn};
use goish::net::http::{ParseURL, Transport};
use goish::{errors, string, time};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok { PASSED.fetch_add(1, Ordering::Relaxed); fmt::Printf!("PASS: %s\n", name); }
    else { FAILED.fetch_add(1, Ordering::Relaxed); fmt::Printf!("FAIL: %s — %s\n", name, detail); }
}

fn key(host: &'static str) -> goish::net::http::transport::connectMethodKey {
    let (u, _) = ParseURL(fmt::Sprintf!("http://%s/", string(host)));
    connectMethod {
        proxyURL: None,
        targetScheme: string("http"),
        targetAddr: goish::net::http::transport::canonicalAddr(&u),
        onlyH1: false,
    }.key()
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn run() {
    // MaxConnsPerHost <= 0 means unlimited: every slot request succeeds
    // and dec is a no-op (notably, it does NOT panic on underflow).
    {
        let t = Transport::default();
        let k = key("a.com");
        let all = t.__take_conn_slot(&k) && t.__take_conn_slot(&k) && t.__take_conn_slot(&k);
        let handed = t.decConnsPerHost(&k);
        check("MaxConnsPerHost <= 0 is unlimited and dec is inert",
              all && handed.is_none(), string(""));
    }

    // With a cap of 2, the third is refused — per host.
    {
        let mut t = Transport::default();
        t.MaxConnsPerHost = 2;
        let a = key("a.com");
        let b = key("b.com");
        check("the cap admits exactly MaxConnsPerHost, and is per host",
              t.__take_conn_slot(&a) && t.__take_conn_slot(&a)
                  && !t.__take_conn_slot(&a) && t.__take_conn_slot(&b),
              string(""));
    }

    // Freeing a slot with nobody waiting just decrements.
    {
        let mut t = Transport::default();
        t.MaxConnsPerHost = 1;
        let k = key("a.com");
        let _ = t.__take_conn_slot(&k);
        check("a freed slot with no waiter is returned to the count",
              t.decConnsPerHost(&k).is_none() && t.__take_conn_slot(&k),
              string(""));
    }

    // Freeing a slot with a waiter HANDS IT OVER rather than decrementing.
    {
        let mut t = Transport::default();
        t.MaxConnsPerHost = 1;
        let k = key("a.com");
        let _ = t.__take_conn_slot(&k);
        let w = Arc::new(wantConn::__new());
        t.__queue_for_slot(&k, w.clone());
        let handed = t.decConnsPerHost(&k);
        check("a freed slot goes to a waiting dialer",
              handed.is_some(), string(""));
        // The count was NOT decremented — the slot moved, it did not
        // free. So a fresh caller still finds the host at capacity.
        check("and the count is not also decremented",
              !t.__take_conn_slot(&k), string(""));
    }

    // Waiters that gave up are skipped, not handed a slot.
    {
        let mut t = Transport::default();
        t.MaxConnsPerHost = 1;
        let k = key("a.com");
        let _ = t.__take_conn_slot(&k);
        let dead = Arc::new(wantConn::__new());
        let live = Arc::new(wantConn::__new());
        // `dead` already got a conn elsewhere, so it is no longer waiting.
        let pc: Arc<persistConn> = Arc::new(persistConn::__new(k.clone()));
        let _ = dead.tryDeliver(Some(pc), errors::nil, time::Time::default());
        t.__queue_for_slot(&k, dead.clone());
        t.__queue_for_slot(&k, live.clone());
        let handed = t.decConnsPerHost(&k);
        check("a waiter that already gave up is skipped for one still waiting",
              handed.is_some() && Arc::ptr_eq(&handed.unwrap(), &live), string(""));
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 { fmt::Printf!("HTTP_CONNLIMIT_SMOKE_OK\n"); goish::os::Exit(0); }
    fmt::Printf!("HTTP_CONNLIMIT_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
