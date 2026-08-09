// http_redirect_smoke — exercise StripPrefix, Redirect, RedirectHandler.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;

use goish::fmt;
use goish::io;
use goish::net;
use goish::net::http;
use goish::time;
use goish::{bytes, go, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    let mux = http::ServeMux::new();

    // /api/status served via StripPrefix → /status under inner mux.
    let inner = http::ServeMux::new();
    inner.HandleFunc(string("/status"), |w, _r| {
        let _ = w.Write(bytes("inner-status\n"));
    });
    let inner_arc: Arc<dyn http::Handler> = Arc::new(inner);
    let stripped = http::StripPrefix(string("/api"), inner_arc);
    // Mount under the prefix.
    mux.Handle(string("/api/"), stripped);

    // /old → permanent redirect to /new via RedirectHandler.
    mux.Handle(
        string("/old"),
        http::RedirectHandler(string("/new"), http::StatusMovedPermanently),
    );
    // /new responds with content so we can verify.
    mux.HandleFunc(string("/new"), |w, _r| {
        let _ = w.Write(bytes("welcome to /new\n"));
    });

    // /custom-redirect uses Redirect() directly inside a handler.
    mux.HandleFunc(string("/custom-redirect"), |w, r| {
        http::Redirect(w, r, string("/new"), http::StatusFound);
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

    // 1. StripPrefix routes /api/status → inner /status.
    {
        let url = build_url(&addr, "/api/status");
        let (mut resp, _) = http::Get(url);
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = goish::io::Closer::Close(&mut resp.Body);
        if resp.StatusCode == 200 && body_eq(&body, b"inner-status\n") {
            fmt::Println!("[ 1] StripPrefix routes        PASS");
        } else {
            fmt::Println!("[ 1] StripPrefix routes        FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    // 2. RedirectHandler returns 301 → client follows → 200 from /new.
    {
        let url = build_url(&addr, "/old");
        let (mut resp, _) = http::Get(url);
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = goish::io::Closer::Close(&mut resp.Body);
        if resp.StatusCode == 200 && body_eq(&body, b"welcome to /new\n") {
            fmt::Println!("[ 2] RedirectHandler 301→200   PASS");
        } else {
            fmt::Println!("[ 2] RedirectHandler 301→200   FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    // 3. Redirect() inline returns 302 → client follows → 200.
    {
        let url = build_url(&addr, "/custom-redirect");
        let (mut resp, _) = http::Get(url);
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = goish::io::Closer::Close(&mut resp.Body);
        if resp.StatusCode == 200 && body_eq(&body, b"welcome to /new\n") {
            fmt::Println!("[ 3] inline Redirect()         PASS");
        } else {
            fmt::Println!("[ 3] inline Redirect()         FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    let _ = srv_arc.Shutdown(time::Second);

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
