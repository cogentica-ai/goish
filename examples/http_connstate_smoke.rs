// http_connstate_smoke — Server.ConnState, and the httptest conn
// bookkeeping built on it.
//
// Go reports four transitions per connection: New when it is
// accepted, Active when a request is being read or served, Idle
// between keep-alive requests, and Closed when it goes away. The
// ORDER is an assertion about the server's own state machine —
// httptest panics on an invalid transition — and the Closed event is
// load-bearing: httptest.Server.Close waits on a WaitGroup that the
// hook increments on New and decrements on Closed, so a missing
// Closed hangs Close forever. That is not hypothetical; the HTTPS
// serve loop was missing it, and this test hung until it was fixed.
//
// goish's hook reports the connection's FD where Go passes the
// net.Conn: the hook has to be able to outlive the call (httptest
// keeps a set of live conns and closes them later), which a borrowed
// conn cannot express.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::net::http::httptest;
use goish::sync::Mutex;
use goish::time;
use goish::{go, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

/// Every (fd, state) the hook saw, in order.
static SEEN: Mutex<Vec<(i64, i64)>> = Mutex::new(Vec::new());

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
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() -> ! {
    let mux = http::ServeMux::new();
    mux.HandleFunc("/", |w, _r| {
        let _ = w.Write(goish::bytes("ok"));
    });

    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
        ..Default::default()
    });
    srv.SetConnState(Some(Arc::new(|fd: goish::types::int, cs: http::server::ConnState| {
        SEEN.Lock().push((fd as i64, cs as i64));
    })));

    let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !lerr.IsNil() {
        check("listen", false, fmt::Sprintf!("%v", lerr));
        finish();
    }
    let port = ln.Addr().Port;
    {
        let s = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s.Serve(ln);
        });
    }
    time::Sleep(time::Duration(150 * 1_000_000));

    // Two keep-alive requests on ONE conn, then close it. Go's
    // sequence for that conn is New, Active, Idle, Active, Idle,
    // Closed.
    {
        let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
        let (mut c, e) = net::Dial(string("tcp"), addr);
        if !e.IsNil() {
            check("dial", false, fmt::Sprintf!("%v", e));
            finish();
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
        for _ in 0..2 {
            let _ = c.Write(goish::bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
            let mut buf = goish::make!([]goish::byte, 512);
            let (n, _) = c.Read(&mut buf);
            if n == 0 {
                break;
            }
        }
        let _ = c.Close();
        // Give the serve loop time to notice the peer went away.
        time::Sleep(time::Duration(400 * 1_000_000));
    }

    let seen = SEEN.Lock().clone();
    let states: Vec<i64> = seen.iter().map(|(_, s)| *s).collect();
    let one_fd = seen.iter().all(|(f, _)| *f == seen[0].0);

    check(
        "one connection reports one fd throughout",
        !seen.is_empty() && one_fd,
        fmt::Sprintf!("saw %d events", seen.len() as i64),
    );
    check(
        "the sequence is New, Active, Idle, Active, Idle, Closed",
        states == alloc::vec![0i64, 1, 2, 1, 2, 4],
        fmt::Sprintf!("got %d states", states.len() as i64),
    );

    // ── httptest keeps the same books, and Close waits on them ──
    {
        let h = http::ServeMux::new();
        h.HandleFunc("/", |w, _r| {
            let _ = w.Write(goish::bytes("hi"));
        });
        let ts = httptest::NewServer(Arc::new(h));
        let c = ts.Client();
        let (resp, err) = c.Get(fmt::Sprintf!("%s/", ts.URL()));
        let ok = err.IsNil() && resp.StatusCode == 200;
        // CloseClientConnections must return — it is bounded at five
        // seconds precisely so it cannot hang a test.
        let start = time::Now();
        ts.CloseClientConnections();
        let elapsed = time::Since(start);
        check(
            "CloseClientConnections returns promptly",
            ok && elapsed < time::Duration(5 * 1_000_000_000),
            fmt::Sprintf!("ok=%v elapsed=%dms", ok, elapsed.0 / 1_000_000),
        );

        // And Close still returns after it: the conn the hook was
        // tracking has to have reached Closed, or the WaitGroup never
        // drains.
        let start2 = time::Now();
        ts.Close();
        let elapsed2 = time::Since(start2);
        check(
            "Close returns after CloseClientConnections",
            elapsed2 < time::Duration(5 * 1_000_000_000),
            fmt::Sprintf!("elapsed=%dms", elapsed2.0 / 1_000_000),
        );
    }

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_CONNSTATE_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_CONNSTATE_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
