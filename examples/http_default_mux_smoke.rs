// http_default_mux_smoke — exercise the package-level Handle /
// HandleFunc free functions against http::DefaultServeMux().

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;

use goish::net;
use goish::net::http;
use goish::time;
use goish::{bytes, go, string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Register on the default mux via the free fn.
    http::HandleFunc(string("/hello"), |w, _r| {
        let _ = w.Write(bytes("from default mux\n"));
    });

    // Bring up a Server with the DefaultServeMux as its handler.
    let mut srv = http::Server::default();
    srv.Handler = http::DefaultServeMux() as Arc<dyn http::Handler>;
    let (ln, _e) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let addr = ln.Addr().String();
    let srv_arc = Arc::new(srv);
    let srv_for_serve = srv_arc.clone();
    go!(move || {
        let _ = srv_for_serve.Serve(ln);
    });
    time::Sleep(time::Millisecond * 30);

    let url = build_url(&addr, "/hello");
    let (resp, _) = http::Get(url);
    if resp.StatusCode == 200 && body_eq(&resp.Body, b"from default mux\n") {
        Println!("[ 1] DefaultServeMux dispatch  PASS");
    } else {
        Println!("[ 1] DefaultServeMux dispatch  FAIL status={}", resp.StatusCode);
        failed += 1;
    }
    let _ = srv_arc.Shutdown(time::Second);

    if failed == 0 {
        Println!("ok 1/1");
        syscall::Exit(0);
    } else {
        Println!("FAIL");
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
