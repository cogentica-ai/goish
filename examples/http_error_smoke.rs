// http_error_smoke — exercise http::Error, http::NotFound, MaxBytesReader.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;

use goish::fmt;
use goish::bytes::NewReader;
use goish::goslice::slice;
use goish::io::{self, Reader};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{bytes, errors, go, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. http::Error sets text/plain + nosniff and writes body.
    let mux = http::ServeMux::new();
    mux.HandleFunc(string("/err"), |w, _r| {
        http::Error(w, string("oops"), http::StatusInternalServerError);
    });
    mux.HandleFunc(string("/missing"), |w, r| {
        http::NotFound(w, r);
    });
    let mux_arc: Arc<dyn http::Handler> = Arc::new(mux);
    let mut srv = http::Server::default();
    srv.Handler = mux_arc;
    let (ln, _e) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let addr = ln.Addr().String();
    let srv_arc = Arc::new(srv);
    let srv_for_serve = srv_arc.clone();
    go!(move || {
        let _ = srv_for_serve.Serve(ln);
    });
    time::Sleep(time::Millisecond * 30);

    // Error handler — 500, body "oops\n", Content-Type: text/plain, X-Content-Type-Options: nosniff.
    {
        let url = build_url(&addr, "/err");
        let (mut resp, _) = http::Get(url);
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        let ct = resp.Header.Get(string("Content-Type"));
        let ncto = resp.Header.Get(string("X-Content-Type-Options"));
        if resp.StatusCode == 500
            && body_eq(&body, b"oops\n")
            && ct == "text/plain; charset=utf-8"
            && ncto == "nosniff"
        {
            fmt::Println!("[ 1] http::Error               PASS");
        } else {
            fmt::Println!("[ 1] http::Error               FAIL status={} ct={} ncto={}", resp.StatusCode, ct, ncto);
            failed += 1;
        }
    }

    // NotFound handler — 404, "404 page not found\n".
    {
        let url = build_url(&addr, "/missing");
        let (mut resp, _) = http::Get(url);
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        if resp.StatusCode == 404 && body_eq(&body, b"404 page not found\n") {
            fmt::Println!("[ 2] http::NotFound            PASS");
        } else {
            fmt::Println!("[ 2] http::NotFound            FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    let _ = srv_arc.Shutdown(time::Second);

    // MaxBytesReader: limit a 100-byte source to 10 bytes.
    {
        let src = bytes("0123456789abcdefghij"); // 20 bytes
        let r = NewReader(src);
        let mut limited = http::NewMaxBytesReader(None, r, 10);
        let mut buf = slice::<u8>::__from_vec(alloc::vec![0u8; 32]);
        let (n1, _e1) = limited.Read(&mut buf);
        let (n2, e2) = limited.Read(&mut buf);
        // First Read returns up to 11 bytes (limit + 1 probe). After
        // remaining hits 0, the next Read returns 0 + ErrMaxBytes.
        if (n1 == 10 || n1 == 11) && n2 == 0 && errors::Is(e2, http::ErrMaxBytes) {
            fmt::Println!("[ 3] MaxBytesReader limit      PASS");
        } else {
            fmt::Println!("[ 3] MaxBytesReader limit      FAIL n1={} n2={}", n1, n2);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 3", failed);
        syscall::Exit(1);
    }
}

fn build_url(addr: &goish::string, path: &str) -> goish::string {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"http://");
    let ab = bytes(addr.clone());
    for i in 0..ab.Len() {
        buf.push(ab[i]);
    }
    buf.extend_from_slice(path.as_bytes());
    goish::string::from_bytes(&buf)
}

fn body_eq(body: &goish::slice<u8>, expected: &[u8]) -> bool {
    if body.Len() as usize != expected.len() {
        return false;
    }
    for i in 0..expected.len() {
        if body[i as i64] != expected[i] {
            return false;
        }
    }
    true
}
