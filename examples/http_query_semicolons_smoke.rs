// http_query_semicolons_smoke — exercise http::NewServeMux and
// http::AllowQuerySemicolons end-to-end.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;

use goish::fmt;
use goish::convert::bytes;
use goish::io;
use goish::net;
use goish::net::http;
use goish::time;
use goish::{go, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Mount a handler that returns the raw query string. It echoes
    // r.URL.RawQuery, then a newline, then "a=" + r.FormValue("a").
    let mux = http::NewServeMux();
    mux.HandleFunc(string("/echo"), |w, r| {
        let raw = r.URL.RawQuery.clone();
        let _ = w.Write(bytes(raw.clone()));
        let _ = w.Write(bytes("\n"));
        // ParseForm splits on '&' only — semicolons would survive if
        // not already rewritten by AllowQuerySemicolons.
        let (vals, _) = http::url::ParseQuery(raw);
        let (vs, ok) = vals.Get(string("a"));
        let _ = w.Write(bytes("a="));
        if ok && vs.Len() > 0 {
            let _ = w.Write(bytes(vs[0].clone()));
        }
    });

    // Wrap with AllowQuerySemicolons so semicolons get rewritten to '&'.
    let wrapped: Arc<dyn http::Handler> = http::AllowQuerySemicolons(mux);

    let mut srv = http::Server::default();
    srv.Handler = wrapped;
    let (ln, _e) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let addr = ln.Addr().String();
    let srv_arc = Arc::new(srv);
    let srv_for_serve = srv_arc.clone();
    go!(move || {
        let _ = srv_for_serve.Serve(ln);
    });
    time::Sleep(time::Millisecond * 30);

    // 1. Plain query: a=1&b=2 — RawQuery survives untouched.
    {
        let url = build_url(&addr, "/echo?a=1&b=2");
        let (mut resp, _) = http::Get(url);
        let (body_bytes, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        let body = body_str(&body_bytes);
        if resp.StatusCode == 200 && body == "a=1&b=2\na=1" {
            fmt::Println!("[ 1] no semicolons              PASS");
        } else {
            fmt::Println!("[ 1] no semicolons              FAIL body={}", body);
            failed += 1;
        }
    }

    // 2. Semicolon query: AllowQuerySemicolons rewrites ';' → '&'.
    {
        let url = build_url(&addr, "/echo?a=1;b=2");
        let (mut resp, _) = http::Get(url);
        let (body_bytes, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        let body = body_str(&body_bytes);
        // Server-side handler observes the rewritten RawQuery.
        if resp.StatusCode == 200 && body == "a=1&b=2\na=1" {
            fmt::Println!("[ 2] semicolon rewritten       PASS");
        } else {
            fmt::Println!("[ 2] semicolon rewritten       FAIL body={}", body);
            failed += 1;
        }
    }

    // 3. Multiple semicolons: a=1;b=2;c=3.
    {
        let url = build_url(&addr, "/echo?a=1;b=2;c=3");
        let (mut resp, _) = http::Get(url);
        let (body_bytes, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        let body = body_str(&body_bytes);
        if resp.StatusCode == 200 && body == "a=1&b=2&c=3\na=1" {
            fmt::Println!("[ 3] multiple semicolons       PASS");
        } else {
            fmt::Println!("[ 3] multiple semicolons       FAIL body={}", body);
            failed += 1;
        }
    }

    // 4. NewServeMux returns a working router (negative path: no route → 404).
    {
        let url = build_url(&addr, "/nope");
        let (resp, _) = http::Get(url);
        if resp.StatusCode == 404 {
            fmt::Println!("[ 4] NewServeMux 404           PASS");
        } else {
            fmt::Println!("[ 4] NewServeMux 404           FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    let _ = srv_arc.Shutdown(time::Second);

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 4", failed);
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
