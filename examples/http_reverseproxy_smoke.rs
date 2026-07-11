// http_reverseproxy_smoke — end-to-end test for
// httputil::NewSingleHostReverseProxy. Spins up a backend, points a
// reverse-proxy at it, and verifies a request flows through.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;

use goish::convert::bytes;
use goish::net;
use goish::net::http;
use goish::time;
use goish::{go, string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // ── Backend ──
    let backend_mux = http::NewServeMux();
    backend_mux.HandleFunc(string("/api/echo"), |w, r| {
        w.Header()
            .Set(string("X-Backend"), string("goish"));
        let _ = w.Write(bytes("backend says hello "));
        let _ = w.Write(bytes(r.URL.Path.clone()));
    });
    backend_mux.HandleFunc(string("/api/q"), |w, r| {
        let _ = w.Write(bytes(r.URL.RawQuery.clone()));
    });

    let mut backend = http::Server::default();
    backend.Handler = backend_mux;
    let (back_ln, _) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let back_addr = back_ln.Addr().String();
    let back_arc = Arc::new(backend);
    let back_serve = back_arc.clone();
    go!(move || {
        let _ = back_serve.Serve(back_ln);
    });
    time::Sleep(time::Millisecond * 30);

    // ── Reverse-proxy front-end ──
    let target_url = {
        let mut s = goish::strings::Builder::new();
        let _ = s.WriteString(string("http://"));
        let _ = s.WriteString(back_addr.clone());
        s.String()
    };
    let (target, _) = http::ParseURL(target_url);

    let proxy = http::NewSingleHostReverseProxy(target);
    let mut front = http::Server::default();
    front.Handler = proxy;
    let (front_ln, _) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let front_addr = front_ln.Addr().String();
    let front_arc = Arc::new(front);
    let front_serve = front_arc.clone();
    go!(move || {
        let _ = front_serve.Serve(front_ln);
    });
    time::Sleep(time::Millisecond * 30);

    // 1. GET front:/api/echo → 200, body proxied from backend.
    {
        let url = build_url(&front_addr, "/api/echo");
        let (resp, _) = http::Get(url);
        let body = body_str(&resp.Body);
        let xb = resp.Header.Get(string("X-Backend"));
        if resp.StatusCode == 200
            && goish::strings::Contains(body.clone(), string("backend says hello"))
            && xb == "goish"
        {
            Println!("[ 1] proxy passthrough         PASS");
        } else {
            Println!(
                "[ 1] proxy passthrough         FAIL status={} body={}",
                resp.StatusCode, body
            );
            failed += 1;
        }
    }

    // 2. Query string is forwarded.
    {
        let url = build_url(&front_addr, "/api/q?a=1&b=two");
        let (resp, _) = http::Get(url);
        let body = body_str(&resp.Body);
        if resp.StatusCode == 200 && body == "a=1&b=two" {
            Println!("[ 2] query forwarded           PASS");
        } else {
            Println!("[ 2] query forwarded           FAIL body={}", body);
            failed += 1;
        }
    }

    // 3. Backend not on a route → 404 propagates.
    {
        let url = build_url(&front_addr, "/no-such-route");
        let (resp, _) = http::Get(url);
        if resp.StatusCode == 404 {
            Println!("[ 3] 404 propagates            PASS");
        } else {
            Println!("[ 3] 404 propagates            FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    let _ = front_arc.Shutdown(time::Second);
    let _ = back_arc.Shutdown(time::Second);

    if failed == 0 {
        Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 3", failed);
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

fn body_str(body: &goish::slice<u8>) -> goish::string {
    let mut buf: Vec<u8> = Vec::with_capacity(body.Len() as usize);
    for i in 0..body.Len() {
        buf.push(body[i]);
    }
    goish::string::from_bytes(&buf)
}
