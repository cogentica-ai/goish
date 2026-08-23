// http_conn_reuse_smoke — shouldReuseConnection + the RST-avoidance
// close (finishRequest / closeWriteAndWait wiring).
//
// The discriminators:
//
//   * A handler that PROMISES more Content-Length than it delivers
//     must not leave the connection open — a keep-alive peer would
//     block forever waiting for the shortfall, then misparse the next
//     response. Asserted by the second request on the same conn
//     failing (conn closed), while a well-behaved handler's conn IS
//     reused.
//   * A 413 (request too large) must reach a client that is still
//     mid-upload. Kernel RST behaviour makes this the classic lost-
//     error-response case; closeWriteAndWait's half-close + delay is
//     Go's fix, and the observable is simply that the error response
//     is READABLE after sending an oversized body.
//   * A silent handler still yields HTTP/1.1 200 with
//     Content-Length: 0 (finishRequest's default WriteHeader).

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
use goish::time;
use goish::{go, string};

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

/// Read exactly one framed response: headers, then the Content-Length
/// body. Stops at the frame boundary so a keep-alive follow-up is not
/// consumed, and arms its own deadline so calls are independent.
fn read_response(c: &mut net::TCPConn) -> goish::string {
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
    let mut raw: Vec<u8> = Vec::new();
    let deadline = time::Now().Add(time::Duration(5 * 1_000_000_000));
    loop {
        let s = goish::string::from_bytes(&raw);
        let sv: &str = s.as_ref();
        if let Some(hdr_end) = sv.find("\r\n\r\n") {
            let body_have = raw.len() - (hdr_end + 4);
            let want: usize = sv
                .lines()
                .find_map(|l| {
                    let ll = l.to_ascii_lowercase();
                    ll.strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if body_have >= want {
                break;
            }
        }
        if time::Now().After(deadline) {
            break;
        }
        let mut buf = goish::make!([]goish::byte, 1024);
        let (n, e) = c.Read(&mut buf);
        for i in 0..n {
            raw.push(buf[i]);
        }
        if !e.IsNil() || n == 0 {
            break;
        }
    }
    goish::string::from_bytes(&raw)
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
    // Promises 100 bytes, delivers 5.
    mux.HandleFunc("/short", |w, _r| {
        w.Header().Set(string("Content-Length"), string("100"));
        let _ = w.Write(goish::bytes("only5"));
    });
    // Honest handler.
    mux.HandleFunc("/ok", |w, _r| {
        let _ = w.Write(goish::bytes("fine"));
    });
    // Never writes anything.
    mux.HandleFunc("/silent", |_w, _r| {});

    // A body-capped route: over-limit requests get a hand-written 413
    // (as Go handlers do after MaxBytesReader errors), and the wrap
    // has already told the writer via requestTooLarge.
    let capped = http::ServeMux::new();
    capped.HandleFunc("/capped", |w, r| {
        let (body, _) = goish::io::ReadAll(&mut r.Body.clone());
        if body.Len() >= 1024 {
            // The handler saw the truncated body; answer 413.
            w.WriteHeader(413);
            let _ = w.Write(goish::bytes("too big"));
            return;
        }
        let _ = w.Write(goish::bytes("small"));
    });
    let capped_handler = http::server::MaxBytesHandler(Arc::new(capped), 1024);

    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
        ..Default::default()
    });
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
    let capped_srv = Arc::new(http::Server {
        Handler: capped_handler,
        ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
        ..Default::default()
    });
    let (ln2, l2err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !l2err.IsNil() {
        check("listen 2", false, fmt::Sprintf!("%v", l2err));
        finish();
    }
    let port2 = ln2.Addr().Port;
    {
        let s2 = capped_srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s2.Serve(ln2);
        });
    }
    time::Sleep(time::Duration(150 * 1_000_000));
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let limited_addr = fmt::Sprintf!("127.0.0.1:%d", port2 as i64);

    // ── honest handler: conn is REUSED ──
    {
        let (mut c, e) = net::Dial(string("tcp"), addr.clone());
        if !e.IsNil() {
            check("dial", false, fmt::Sprintf!("%v", e));
            finish();
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
        let _ = c.Write(goish::bytes("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n"));
        let r1 = read_response(&mut c);
        let _ = c.Write(goish::bytes("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n"));
        let r2 = read_response(&mut c);
        check(
            "well-behaved conn serves a second request",
            (r1.as_ref() as &str).contains("fine") && (r2.as_ref() as &str).contains("fine"),
            fmt::Sprintf!("r2=%q", r2),
        );
        let _ = c.Close();
    }

    // ── short-write handler: conn is CLOSED, not reused ──
    {
        let (mut c, e) = net::Dial(string("tcp"), addr.clone());
        if !e.IsNil() {
            check("dial 2", false, fmt::Sprintf!("%v", e));
            finish();
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
        let _ = c.Write(goish::bytes("GET /short HTTP/1.1\r\nHost: x\r\n\r\n"));
        let r1 = read_response(&mut c);
        check(
            "short-write response still delivered",
            (r1.as_ref() as &str).contains("only5"),
            r1.clone(),
        );
        // The server must have closed: a second request gets no reply.
        let _ = c.Write(goish::bytes("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n"));
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(1_500_000_000)));
        let mut buf = goish::make!([]goish::byte, 64);
        let (n, _) = c.Read(&mut buf);
        check(
            "under-delivering handler kills keep-alive",
            n == 0,
            fmt::Sprintf!("read %d bytes after short write", n as i64),
        );
        let _ = c.Close();
    }

    // ── silent handler: finishRequest defaults to 200, CL 0 ──
    {
        let (mut c, e) = net::Dial(string("tcp"), addr.clone());
        if !e.IsNil() {
            check("dial 3", false, fmt::Sprintf!("%v", e));
            finish();
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
        let _ = c.Write(goish::bytes(
            "GET /silent HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ));
        let r = read_response(&mut c);
        let rs: &str = r.as_ref();
        check(
            "silent handler yields 200 with Content-Length: 0",
            rs.starts_with("HTTP/1.1 200") && rs.contains("Content-Length: 0"),
            r.clone(),
        );
        let _ = c.Close();
    }

    // ── limit-hit: 413 readable, conn closed via closeWriteAndWait ──
    {
        let (mut c, e) = net::Dial(string("tcp"), limited_addr.clone());
        if !e.IsNil() {
            check("dial 4", false, fmt::Sprintf!("%v", e));
            finish();
        }
        let mut big: Vec<u8> = alloc::vec![b'x'; 8 * 1024];
        let head = fmt::Sprintf!(
            "POST /capped HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n",
            (8 * 1024) as i64
        );
        let mut wire: Vec<u8> = head.as_bytes().to_vec();
        wire.append(&mut big);
        let started = time::Now();
        let _ = c.Write(goish::slice::<goish::byte>::__from_vec(wire));
        let r = read_response(&mut c);
        let rs: &str = r.as_ref();
        check(
            "over-limit upload still receives the 413",
            rs.starts_with("HTTP/1.1 413"),
            fmt::Sprintf!("got %q", r),
        );
        let _ = started;
        // closeWriteAndWait half-closes (immediate FIN → client EOF)
        // and holds the read side open for rstAvoidanceDelay before
        // the full close. HONESTY NOTE — verified by A/B: on loopback
        // these three assertions pass with closeWriteAndWait REPLACED
        // by a bare Close too (the kernel accepts the first straggler
        // write into a dead socket and RSTs the later ones), so they
        // pin the 413-then-close CONTRACT but do not discriminate the
        // RST-avoidance mechanism itself; that would need a peer whose
        // unread bytes actually get dropped, which loopback does not
        // reproduce deterministically.
        let mut buf = goish::make!([]goish::byte, 16);
        let (n, _) = c.Read(&mut buf);
        check(
            "conn EOFs after the 413",
            n == 0,
            fmt::Sprintf!("n=%d", n as i64),
        );
        let (_, we1) = c.Write(goish::bytes("straggler"));
        check(
            "write during the RST-avoidance window still succeeds",
            we1.IsNil(),
            fmt::Sprintf!("%v", we1),
        );
        time::Sleep(time::Duration(800 * 1_000_000));
        let (_, we2a) = c.Write(goish::bytes("late"));
        let (_, we2b) = c.Write(goish::bytes("late2"));
        check(
            "write after the full close fails",
            !we2a.IsNil() || !we2b.IsNil(),
            fmt::Sprintf!("%v / %v", we2a, we2b),
        );
        let _ = c.Close();
    }

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_CONN_REUSE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_CONN_REUSE_FAIL\n");
    goish::os::Exit(1);
}
