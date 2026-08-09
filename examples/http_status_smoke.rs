// http_status_smoke — verify StatusText lookup + that ResponseWriter
// uses the full IANA registry (e.g. status 418 → "I'm a teapot").

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;

use goish::fmt;
use goish::net;
use goish::net::http;
use goish::time;
use goish::{bytes, go, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Direct table lookups.
    let cases: [(i64, &str); 8] = [
        (200, "OK"),
        (201, "Created"),
        (301, "Moved Permanently"),
        (404, "Not Found"),
        (418, "I'm a teapot"),
        (429, "Too Many Requests"),
        (503, "Service Unavailable"),
        (999, ""), // unknown → empty
    ];
    for &(code, want) in &cases {
        let got = http::StatusText(code);
        if got == want {
            fmt::Println!("[ok] StatusText({}) = {}", code, got);
        } else {
            fmt::Println!("[FAIL] StatusText({}) want={:?} got={}", code, want, got);
            failed += 1;
        }
    }

    // Through the wire: handler returns 418, client sees "418 I'm a teapot".
    let mux = http::ServeMux::new();
    mux.HandleFunc(string("/teapot"), |w, _r| {
        w.WriteHeader(http::StatusTeapot);
        let _ = w.Write(bytes("brew\n"));
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

    let url = build_url(&addr, "/teapot");
    let (resp, _) = http::Get(url);
    if resp.StatusCode == 418 && resp.Status.Len() > 0 {
        // Status string contains the reason phrase. Check it.
        let parts = goish::strings::Split(resp.Status.clone(), string(" "));
        // Expected: "418 I'm a teapot"
        let s = resp.Status.clone();
        if parts.Len() >= 2 && goish::strings::Contains(s, string("teapot")) {
            fmt::Println!("[ok] wire 418 → I'm a teapot");
        } else {
            fmt::Println!("[FAIL] wire 418 — Status={}", resp.Status);
            failed += 1;
        }
    } else {
        fmt::Println!("[FAIL] wire 418 status={}", resp.StatusCode);
        failed += 1;
    }

    let _ = srv_arc.Shutdown(time::Second);

    if failed == 0 {
        fmt::Println!("ok status smoke");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {}", failed);
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
