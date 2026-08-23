// http_keepalive_token_smoke — the server must honour `Connection:
// close` when it arrives as one token among several, or on a second
// header line.
//
// Both spellings are real. Before the serve loop was moved onto
// transfer.go's shouldClose it compared the WHOLE `Connection` value
// against "close" using Header.Get (first line only), so both of
// these kept the connection alive after the client had asked to close
// it. This test drives a real socket and watches what happens on the
// wire: a conn the server should have closed will instead sit there
// accepting a second request.

#![no_std]
#![no_main]

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

fn pass(name: &'static str) {
    PASSED.fetch_add(1, Ordering::Relaxed);
    fmt::Printf!("PASS: %s\n", name);
}

fn fail(msg: goish::string) {
    FAILED.fetch_add(1, Ordering::Relaxed);
    fmt::Printf!("FAIL: %s\n", msg);
}

/// Send `req`, read one response, then send a second request on the
/// SAME socket. Returns true if the server served the second one —
/// i.e. it kept the connection alive.
fn conn_survives_second_request(port: goish::int, req: &[u8]) -> bool {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        return false;
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(3 * 1_000_000_000)));
    let (_, we) = c.Write(goish::slice::<goish::byte>::__from_vec(req.to_vec()));
    if !we.IsNil() {
        let _ = c.Close();
        return false;
    }
    // First response.
    let mut buf = goish::make!([]goish::byte, 4096);
    let (n1, _) = c.Read(&mut buf);
    if n1 == 0 {
        let _ = c.Close();
        return false;
    }
    // Second request on the same socket.
    let (_, we2) = c.Write(goish::slice::<goish::byte>::__from_vec(
        b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".to_vec(),
    ));
    if !we2.IsNil() {
        let _ = c.Close();
        return false;
    }
    let mut buf2 = goish::make!([]goish::byte, 4096);
    let (n2, _) = c.Read(&mut buf2);
    let mut got: Vec<u8> = Vec::new();
    for i in 0..n2 {
        got.push(buf2[i]);
    }
    let _ = c.Close();
    let s = goish::string::from_bytes(&got);
    let sr: &str = s.as_ref();
    return n2 > 0 && sr.contains("200 OK");
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

fn run() {
    let mux = http::ServeMux::new();
    mux.HandleFunc("/ok", |w, _r| {
        let _ = w.Write(goish::bytes("ok"));
    });
    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ReadHeaderTimeout: time::Duration(2 * 1_000_000_000),
        ..Default::default()
    });
    let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !lerr.IsNil() {
        fail(fmt::Sprintf!("net.Listen: %v", lerr));
        finish();
    }
    let port = ln.Addr().Port;
    {
        let srv2 = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = srv2.Serve(ln);
        });
    }
    time::Sleep(time::Duration(100 * 1_000_000));

    // ── control: no Connection header on HTTP/1.1 keeps the conn ──
    if conn_survives_second_request(port, b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n") {
        pass("control: HTTP/1.1 with no Connection header keeps the conn");
    } else {
        fail(string(
            "control: plain HTTP/1.1 request did not keep the conn",
        ));
    }

    // ── control: a bare `Connection: close` closes it ──
    if !conn_survives_second_request(
        port,
        b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    ) {
        pass("control: bare `Connection: close` closes the conn");
    } else {
        fail(string("bare `Connection: close` did NOT close the conn"));
    }

    // ── the tokenising case ──
    if !conn_survives_second_request(
        port,
        b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, close\r\n\r\n",
    ) {
        pass("`Connection: keep-alive, close` closes the conn");
    } else {
        fail(string(
            "`Connection: keep-alive, close` was ignored — conn stayed alive",
        ));
    }

    // ── the multi-line case: Get() only ever saw the first ──
    if !conn_survives_second_request(
        port,
        b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n",
    ) {
        pass("a second `Connection: close` header line closes the conn");
    } else {
        fail(string(
            "second `Connection: close` header line was ignored — conn stayed alive",
        ));
    }

    // ── HTTP/1.0 defaults to close unless keep-alive is asked for ──
    if !conn_survives_second_request(port, b"GET /ok HTTP/1.0\r\nHost: x\r\n\r\n") {
        pass("HTTP/1.0 without keep-alive closes the conn");
    } else {
        fail(string("HTTP/1.0 without keep-alive stayed alive"));
    }

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_KEEPALIVE_TOKEN_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_KEEPALIVE_TOKEN_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
