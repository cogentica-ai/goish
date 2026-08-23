// http_retry_smoke — Request.isReplayable and transport.go's
// shouldRetryRequest: the logic that decides whether a request that
// failed mid-flight may be re-sent. Values from scripts/goref.sh.
//
// Getting this wrong in the permissive direction silently duplicates
// non-idempotent side effects — a POST charged twice.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::transport::{
    errNothingWritten, errServerClosedIdle, errTransportReadFromServer, shouldRetryRequest,
};
use goish::net::http::{NewRequest, Request};
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

fn req(method: &'static str, idem: &'static str) -> Request {
    let (r, _) = NewRequest(string(method), string("http://x/"), slice::new());
    let mut r = r;
    r.Method = string(method);
    if !idem.is_empty() {
        r.Header.Set(string(idem), string("k"));
    }
    r
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
    // ── isReplayable ──
    {
        let idempotent: &[&str] = &["GET", "HEAD", "OPTIONS", "TRACE", ""];
        let not: &[&str] = &["POST", "PUT", "DELETE", "PATCH"];
        let mut bad = string("");
        for m in idempotent {
            if !req(m, "").isReplayable() {
                bad = fmt::Sprintf!("%s should replay", string(*m));
            }
        }
        for m in not {
            if req(m, "").isReplayable() {
                bad = fmt::Sprintf!("%s should NOT replay", string(*m));
            }
            // The non-standard opt-in headers make them replayable.
            if !req(m, "Idempotency-Key").isReplayable()
                || !req(m, "X-Idempotency-Key").isReplayable()
            {
                bad = fmt::Sprintf!("%s + Idempotency-Key should replay", string(*m));
            }
        }
        check(
            "isReplayable: idempotent methods, empty method, and the two opt-in headers",
            bad.Len() == 0,
            bad,
        );
    }

    // ── shouldRetryRequest ──
    {
        let post = req("POST", "");
        let get = req("GET", "");
        let other = errors::New(string("some other failure"));

        // A FRESH connection never retries, whatever the error — Go's
        // guard against looping forever against a server that just
        // hangs up on requests it dislikes.
        let fresh_never = !shouldRetryRequest(&get, errServerClosedIdle.into(), false)
            && !shouldRetryRequest(&get, errNothingWritten.into(), false)
            && !shouldRetryRequest(&post, errNothingWritten.into(), false);
        check("a fresh connection never retries", fresh_never, string(""));

        // Nothing-written is checked BEFORE replayability, so even a
        // POST retries when no byte reached the wire.
        check(
            "nothing-written retries even a POST",
            shouldRetryRequest(&post, errNothingWritten.into(), true),
            string(""),
        );

        // A reused conn retries an idempotent request on these two.
        check(
            "reused + idempotent retries on read-from-server and server-closed-idle",
            shouldRetryRequest(&get, errTransportReadFromServer.into(), true)
                && shouldRetryRequest(&get, errServerClosedIdle.into(), true),
            string(""),
        );

        // But NOT a POST — that is the duplicate-side-effect guard.
        check(
            "a reused conn does NOT retry a POST on a mid-flight failure",
            !shouldRetryRequest(&post, errServerClosedIdle.into(), true)
                && !shouldRetryRequest(&post, errTransportReadFromServer.into(), true),
            string(""),
        );

        // Unknown errors are conservative.
        check(
            "an unrecognised error does not retry",
            !shouldRetryRequest(&get, other, true),
            string(""),
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_RETRY_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_RETRY_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
