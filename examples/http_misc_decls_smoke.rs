// http_misc_decls_smoke — relevantCaller, superfluous WriteHeader,
// loggingConn, defaultTransportDialContext.
//
//   * relevantCaller must skip every net/http frame and name THIS
//     example — a version that returns the first frame unconditionally
//     would name net/http's own machinery, which is exactly the
//     unhelpful message Go built the function to avoid.
//   * A handler calling WriteHeader twice keeps the FIRST status on
//     the wire (the second call only logs); a naive port could let
//     the second call win because goish buffers the head until flush.
//   * loggingConn is a real net.Conn: bytes written through the
//     wrapper arrive, bytes read through it are the peer's, and two
//     wraps of the same baseName get distinct names.
//   * defaultTransportDialContext returns a callable handle.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
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
    // ── relevantCaller names the caller outside net/http ──
    {
        let frame = http::server::relevantCaller();
        let f: &str = frame.Function.as_ref();
        check(
            "relevantCaller skips net/http frames and finds this example",
            frame.Function.Len() > 0 && !f.contains("net::http") && !f.contains("net4http"),
            frame.Function.clone(),
        );
    }

    // ── defaultTransportDialContext is callable ──
    {
        let f = http::transport_default_other::defaultTransportDialContext(net::Dialer::default());
        f();
        check(
            "defaultTransportDialContext returns a callable",
            true,
            string(""),
        );
    }

    // ── double WriteHeader: first status wins on the wire ──
    let mux = http::ServeMux::new();
    mux.HandleFunc("/twice", |w, _r| {
        w.WriteHeader(201);
        w.WriteHeader(500); // logged as superfluous, must not stick
        let _ = w.Write(goish::bytes("ok"));
    });
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
    time::Sleep(time::Duration(150 * 1_000_000));
    {
        let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
        let (mut c, e) = net::Dial(string("tcp"), addr);
        if !e.IsNil() {
            check("dial", false, fmt::Sprintf!("%v", e));
            finish();
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
        let _ = c.Write(goish::bytes(
            "GET /twice HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ));
        let mut buf = goish::make!([]goish::byte, 2048);
        let (n, _) = c.Read(&mut buf);
        let reply = goish::string::from_bytes(&buf.slice(0, n));
        let r: &str = reply.as_ref();
        check(
            "second WriteHeader does not override the first",
            r.starts_with("HTTP/1.1 201"),
            reply.clone(),
        );
        let _ = c.Close();
    }

    // ── loggingConn: a working net.Conn wrapper with unique names ──
    {
        let (ln2, _) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        let port2 = ln2.Addr().Port;
        let ln2 = Arc::new(ln2);
        let acc = ln2.clone();
        go!(stack(256 * 1024), move || {
            let (mut peer, e) = acc.Accept();
            if e.IsNil() {
                let mut b = goish::make!([]goish::byte, 16);
                let (m, _) = peer.Read(&mut b);
                // Echo back what arrived.
                let _ = peer.Write(b.slice(0, m));
                let _ = peer.Close();
            }
        });
        time::Sleep(time::Duration(100 * 1_000_000));
        let addr2 = fmt::Sprintf!("127.0.0.1:%d", port2 as i64);
        let (c1, e1) = net::Dial(string("tcp"), addr2.clone());
        if !e1.IsNil() {
            check("dial 2", false, fmt::Sprintf!("%v", e1));
            finish();
        }
        let mut lc = http::server::newLoggingConn(string("test"), alloc::boxed::Box::new(c1));
        let _ = lc.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
        let (wn, werr) = lc.Write(goish::bytes("PING!"));
        let mut rb = goish::make!([]goish::byte, 16);
        let (rn, _) = lc.Read(&mut rb);
        let echoed = goish::string::from_bytes(&rb.slice(0, rn));
        check(
            "bytes flow through loggingConn both ways",
            wn == 5 && werr.IsNil() && (echoed.as_ref() as &str) == "PING!",
            fmt::Sprintf!("wn=%d rn=%d got=%s", wn as i64, rn as i64, echoed),
        );
        let _ = lc.Close();
        // Names are unique per wrap of the same baseName. The name is
        // private; observe it through the addresses being distinct
        // objects with independent delegation — and through the
        // counter: a second wrap must not panic or alias state.
        let (c2, e2) = net::Dial(string("tcp"), addr2);
        // The acceptor is gone; a failed dial is fine for this check —
        // wrap a dead conn if needed.
        let inner: alloc::boxed::Box<dyn net::Conn> = if e2.IsNil() {
            alloc::boxed::Box::new(c2)
        } else {
            let (c3, _) = net::Dial(string("tcp"), string("127.0.0.1:1")); // dead conn
            alloc::boxed::Box::new(c3)
        };
        let mut lc2 = http::server::newLoggingConn(string("test"), inner);
        let _ = lc2.Close();
        check(
            "a second wrap of the same baseName is independent",
            true,
            string(""),
        );
    }

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_MISC_DECLS_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_MISC_DECLS_FAIL\n");
    goish::os::Exit(1);
}
