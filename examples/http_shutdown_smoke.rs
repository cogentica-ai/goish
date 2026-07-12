// http_shutdown_smoke — exercise http::Server.Shutdown.
//
// Spawns a Server in one goroutine, sends an in-process request,
// then calls Shutdown. Asserts:
//   1. Shutdown returns nil within its timeout.
//   2. ListenAndServe returns ErrServerClosed (not a generic error).
//   3. Post-shutdown Dial fails (port unbound).

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::{bytes, go, make, string, syscall, time};

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

    // Bind on 127.0.0.1:0 outside the server so we can grab the port,
    // then hand the listener to Server.Serve.
    let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    check(err.IsNil(), b"Listen failed\n");
    let port = ln.Addr().Port;

    let mut srv = http::Server::default();
    srv.Handler = mux;
    srv.ReadHeaderTimeout = time::Millisecond * 100;
    let srv = Arc::new(srv);

    static SERVE_DONE: AtomicUsize = AtomicUsize::new(0);
    static SERVE_ERR_IS_CLOSED: AtomicUsize = AtomicUsize::new(0);
    static CLIENT_PORT: AtomicI32 = AtomicI32::new(0);
    CLIENT_PORT.store(port as i32, Ordering::Release);

    let srv_run = srv.clone();
    go!(move || {
        let err = srv_run.Serve(ln);
        if err.Error() == "http: Server closed" {
            SERVE_ERR_IS_CLOSED.store(1, Ordering::Release);
        }
        SERVE_DONE.store(1, Ordering::Release);
    });

    // One in-process request to confirm the server is up.
    {
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
        check(err.IsNil(), b"client Dial failed\n");
        let req: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        let (n, err) = conn.Write(bytes(core::str::from_utf8(req).unwrap()));
        check(err.IsNil() && n as usize == req.len(), b"client Write failed\n");
        let mut buf = make!([]u8, 256);
        let _ = conn.Read(&mut buf);
        let _ = conn.Close();
    }

    // Shutdown. Timeout 2s; with ReadHeaderTimeout=100ms keep-alive
    // conns drain almost immediately.
    let t0 = time::Now();
    let err = srv.clone().Shutdown(time::Second * 2);
    let elapsed = time::Since(t0);
    check(err.IsNil(), b"Shutdown returned an error\n");
    check(
        elapsed.Nanoseconds() < 2_000_000_000,
        b"Shutdown took longer than 2s\n",
    );

    // Wait for Serve to actually return.
    while SERVE_DONE.load(Ordering::Acquire) == 0 {
        goish::runtime::sched::Gosched();
    }
    check(
        SERVE_ERR_IS_CLOSED.load(Ordering::Acquire) == 1,
        b"Serve did not return ErrServerClosed\n",
    );

    // Post-shutdown Dial should fail (port unbound). Connection refused.
    {
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
        let (_conn, err) = net::Dial(string("tcp"), addr);
        check(!err.IsNil(), b"post-shutdown Dial unexpectedly succeeded\n");
    }

    let ok: &[u8] = b"http_shutdown_smoke: ok\n";
    syscall::Write(syscall::STDOUT, ok.as_ptr(), ok.len());
    syscall::Exit(0);
}
