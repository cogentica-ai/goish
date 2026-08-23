// http_connreader_smoke — server.go's connReader read-limit state.
//
// Staged: goish's serve loop bounds the header read with a socket read
// deadline instead, so this is not wired. The limit arithmetic is
// worth pinning first — it is what stops an unbounded header block.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::sync::Arc;
use goish::fmt;
use goish::net::http::server::connReader;
use goish::net::http::{Handler, HandlerFunc, Request, ResponseWriter, ServeMux};
use goish::string;

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
    // A zero limit is already hit — Go's `remain <= 0`, so a fresh
    // connReader is limited until someone sets a budget.
    {
        let cr = connReader::__new();
        check(
            "a fresh connReader is at its limit",
            cr.hitReadLimit(),
            string(""),
        );
    }
    // The test is `<= 0`, not `== 0`: a read that OVERSHOOTS must stay
    // limited rather than wrapping back to unlimited.
    {
        let cr = connReader::__new();
        cr.setReadLimit(10);
        let before = cr.hitReadLimit();
        cr.setReadLimit(0);
        let at = cr.hitReadLimit();
        cr.setReadLimit(-5);
        let over = cr.hitReadLimit();
        check(
            "hitReadLimit is <= 0, so an overshoot stays limited",
            !before && at && over,
            string(""),
        );
    }
    // setInfiniteReadLimit is maxInt64, not a sentinel — the counter
    // keeps working and hitReadLimit needs no special case.
    {
        let cr = connReader::__new();
        cr.setInfiniteReadLimit();
        check(
            "setInfiniteReadLimit is a huge budget, not a flag",
            !cr.hitReadLimit(),
            string(""),
        );
    }

    // lock()/unlock() are a real manual acquire/release pair, not a
    // no-op: releaseConn locks, mutates, and unlocks across three
    // statements, and the mutex must be free afterwards.
    {
        let cr = connReader::__new();
        check(
            "releaseConn takes and releases the lock across statements",
            !cr.__released() && {
                cr.releaseConn();
                cr.__released()
            },
            string(""),
        );
        // If unlock() were a no-op the next acquire would deadlock;
        // reaching this line at all proves it released.
        cr.lock();
        cr.unlock();
        cr.setReadLimit(1);
        check(
            "the mutex is genuinely free again afterwards",
            !cr.hitReadLimit(),
            string(""),
        );
    }

    // ── ServeMux.register ── Go's single registration choke point
    {
        let mux = ServeMux::new();
        mux.register(
            "/x",
            Arc::new(HandlerFunc(
                |w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request| {
                    let _ = w.Write(goish::bytes("hit"));
                },
            )) as Arc<dyn Handler>,
        );
        // Registering the same pattern twice must panic in Go; here we
        // only assert the first one took, which the mux reports by
        // routing to it.
        let (req, _) =
            goish::net::http::NewRequest(string("GET"), string("http://h/x"), goish::slice::new());
        let (_, pat) = mux.Handler(&req);
        check(
            "register routes the pattern it was given",
            pat.Len() > 0,
            pat,
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_CONNREADER_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_CONNREADER_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
