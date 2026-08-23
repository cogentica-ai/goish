// http_protoversion_smoke — an HTTP/1 server must refuse to parse
// what is not HTTP/1.
//
// Go's readRequest ends with `if !http1ServerSupportsRequest(req) {
// return nil, statusError{505, "unsupported protocol version"} }`
// (server.go:1113), and conn.serve renders that error onto the wire
// (:2069). goish had no such gate: a request line claiming HTTP/2.0
// or HTTP/0.9 was parsed as HTTP/1 and handed to the handler, which
// is reading a frame stream — bytes that are not ASCII and not under
// the peer's obligation to be well-formed — as a request line.
//
// The one exemption is `PRI * HTTP/2.0`, the HTTP/2 connection
// preface. Go deliberately lets it reach the handler so an
// application can implement its own upgrade, and a port that
// "helpfully" rejected it would break that.
//
// The response shape is Go's, and it is unusual on purpose: the
// status text appears TWICE (status line and body) and there is no
// Content-Length — `Connection: close` is the delimiter.

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
static PRI_SEEN: AtomicUsize = AtomicUsize::new(0);

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
    mux.HandleFunc("/", |w, r| {
        if r.Method == "PRI" {
            PRI_SEEN.fetch_add(1, Ordering::Relaxed);
        }
        let _ = w.Write(goish::bytes("served"));
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

    // ── an HTTP/2.0 request line on an HTTP/1 server ──
    {
        let raw = send(port, b"GET / HTTP/2.0\r\nHost: x\r\n\r\n");
        let w: &str = raw.as_ref();
        check(
            "an HTTP/2.0 request line is refused with 505, not served",
            w.starts_with("HTTP/1.1 505 HTTP Version Not Supported: unsupported protocol version")
                && !w.contains("served"),
            raw.clone(),
        );
        check(
            "the 505 carries Connection: close and repeats the text as the body",
            w.contains("\r\nConnection: close\r\n\r\n505 HTTP Version Not Supported: unsupported protocol version")
                && !w.contains("Content-Length"),
            raw,
        );
    }

    // ── HTTP/0.9 ──
    {
        let raw = send(port, b"GET / HTTP/0.9\r\nHost: x\r\n\r\n");
        let w: &str = raw.as_ref();
        check(
            "an HTTP/0.9 request line is refused too",
            !w.contains("served") && !w.starts_with("HTTP/1.1 200"),
            raw,
        );
    }

    // ── the HTTP/2 preface is the ONE exemption ──
    //
    // It passes the version gate — and is then answered 400 by the
    // ServeMux, because `RequestURI == "*"` is not a route. Both
    // halves are Go 1.25.5's, taken from scripts/goref.sh: the 505
    // above and this 400 come from the same run. Before the mux gained
    // the asterisk branch goish answered `301 -> /*` here.
    {
        let raw = send(
            port,
            b"PRI * HTTP/2.0\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        let w: &str = raw.as_ref();
        check(
            "PRI * HTTP/2.0 passes the version gate (Go's upgrade hook)",
            !w.contains("505"),
            raw.clone(),
        );
        check(
            "the asterisk request-target is answered 400, not redirected",
            w.starts_with("HTTP/1.1 400 Bad Request")
                && w.contains("Connection: close")
                && !w.contains("Location:"),
            raw,
        );
    }

    // ── OPTIONS * is the other asterisk case, and it is a 200 ──
    {
        let raw = send(
            port,
            b"OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        let w: &str = raw.as_ref();
        check(
            "OPTIONS * is answered 200 by the global options handler",
            w.starts_with("HTTP/1.1 200"),
            raw,
        );
    }

    // ── an Expect the server does not know is 417 + close ──
    //
    // Go 1.25.5 answers exactly:
    //   HTTP/1.1 417 Expectation Failed\r\nConnection: close\r\n
    //   Date: …\r\nContent-Length: 0\r\n\r\n
    // (scripts/goref.sh). The `Connection: close` is the load-bearing
    // half: the client is holding a body back waiting for a 100, so a
    // kept-alive conn would carry that body into the next request's
    // parse.
    {
        let raw = send(
            port,
            b"POST / HTTP/1.1\r\nHost: x\r\nExpect: banana\r\nContent-Length: 3\r\n\r\nabc",
        );
        let w: &str = raw.as_ref();
        check(
            "an unknown Expect value is 417 with Connection: close",
            w.starts_with("HTTP/1.1 417 Expectation Failed")
                && w.contains("Connection: close")
                && !w.contains("served"),
            raw,
        );
    }

    // ── the ordinary case is untouched ──
    {
        let raw = send(
            port,
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        let w: &str = raw.as_ref();
        check(
            "an HTTP/1.1 request is still served",
            w.starts_with("HTTP/1.1 200") && w.contains("served"),
            raw,
        );
    }

    finish();
}

fn send(port: goish::types::int, req: &[u8]) -> goish::string {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        return fmt::Sprintf!("dial: %v", e);
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(req.to_vec()));
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    loop {
        let (n, re) = c.Read(&mut buf);
        for i in 0..n {
            raw.push(buf[i]);
        }
        if !re.IsNil() || n == 0 {
            break;
        }
    }
    let _ = c.Close();
    return goish::string::from_bytes(&raw);
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_PROTOVERSION_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_PROTOVERSION_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
