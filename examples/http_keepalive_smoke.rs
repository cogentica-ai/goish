// http_keepalive_smoke — drive a goish HTTP server with curl in
// keep-alive mode and assert all responses arrive on a single TCP
// connection.
//
// Identical setup to http_hello but spawns a sibling goroutine that
// dials the server in-process and pipelines three back-to-back
// requests on the same connection, asserting all three return 200.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::runtime::sched::schedule;
use goish::{bytes, go, make, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    let mux = http::ServeMux::new();
    mux.HandleFunc(string("/"), |w, _r| {
        let _ = w.Write(bytes("hi\n"));
    });
    let mux: Arc<dyn http::Handler> = Arc::new(mux);

    let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    check(err.IsNil(), b"Listen failed\n");
    let port = ln.Addr().Port;

    static CLIENT_PORT: AtomicI32 = AtomicI32::new(0);
    static OK_COUNT: AtomicUsize = AtomicUsize::new(0);
    CLIENT_PORT.store(port as i32, Ordering::Release);

    // Start the server.
    let mux_clone = mux.clone();
    go!(move || {
        let _ = http::Serve(ln, mux_clone);
    });

    // Client side: open ONE conn, send three requests, expect three
    // 200-OK responses.
    go!(|| {
        let p = CLIENT_PORT.load(Ordering::Acquire) as u32;
        let mut addr_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(24);
        addr_buf.extend_from_slice(b"127.0.0.1:");
        let mut tmp = [0u8; 6];
        let mut i = tmp.len();
        let mut n = p;
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        addr_buf.extend_from_slice(&tmp[i..]);
        let addr = string::from_bytes(&addr_buf);

        let (mut conn, err) = net::Dial(string("tcp"), addr);
        if !err.IsNil() {
            die(b"Dial failed\n");
        }

        // Send three sequential requests on the same conn (one
        // request, read its response fully, then next). v1 does not
        // support HTTP/1.1 pipelining (request-burst before responses
        // come back) — that requires lifting bufio across the
        // server's keep-alive loop, which is deferred. Real clients
        // (curl --next, browsers) all use the sequential pattern.
        let req: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n";
        let dl = goish::time::Now().Add(goish::time::Second * 2);
        let _ = conn.SetReadDeadline(dl);

        let mut ok_seen = 0usize;
        for _ in 0..3 {
            let (n, err) = conn.Write(bytes(core::str::from_utf8(req).unwrap()));
            if !err.IsNil() || n as usize != req.len() {
                die(b"client Write failed\n");
            }
            // Read until the response body's last byte arrives. We
            // know body length is "hi\n" = 3 bytes, status+headers
            // end with \r\n\r\n. So look for "hi\n" preceded by
            // a blank line.
            let mut buf = make!([]u8, 4096);
            let mut accum: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            loop {
                let (nread, err) = conn.Read(&mut buf);
                if nread > 0 {
                    accum.extend_from_slice(&(*buf)[..nread as usize]);
                    if accum.windows(7).any(|w| w == b"\r\n\r\nhi\n") {
                        break;
                    }
                } else if !err.IsNil() {
                    die(b"client Read errored mid-response\n");
                }
            }
            if accum.windows(6).any(|w| w == b"200 OK") {
                ok_seen += 1;
            }
        }

        let _ = conn.Close();
        OK_COUNT.store(ok_seen, Ordering::Release);
    });

    while OK_COUNT.load(Ordering::Acquire) < 3 {
        goish::runtime::sched::Gosched();
    }

    let ok: &[u8] = b"http_keepalive_smoke: 3/3 responses on single conn\n";
    syscall::Write(syscall::STDOUT, ok.as_ptr(), ok.len());
    syscall::Exit(0);
}

