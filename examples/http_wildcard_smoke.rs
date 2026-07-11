// http_wildcard_smoke — exercise Go 1.22-style ServeMux patterns:
//   /users/{id}              - single-segment binding
//   /files/{path...}         - trailing multi-segment binding
//   GET /api/{resource}      - method-prefixed pattern
//   exact-match co-existence - "/users/me" still beats /users/{id}
//
// Pass criteria: every named subtest prints "PASS"; final "ok" line.

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

    // Build the mux.
    let mux = http::ServeMux::new();
    // Plain literal — this should still work post-port.
    mux.HandleFunc(string("/health"), |w, _r| {
        let _ = w.Write(bytes("alive\n"));
    });
    // Exact under a wildcard's namespace — exact must win.
    mux.HandleFunc(string("/users/me"), |w, _r| {
        let _ = w.Write(bytes("self\n"));
    });
    // Single-segment wildcard.
    mux.HandleFunc(string("/users/{id}"), |w, r| {
        let id = r.PathValue(string("id"));
        let s = goish::Sprintf!("user-id=%s\n", id);
        let _ = w.Write(bytes(s));
    });
    // Trailing multi-segment wildcard.
    mux.HandleFunc(string("/files/{path...}"), |w, r| {
        let p = r.PathValue(string("path"));
        let s = goish::Sprintf!("file-path=%s\n", p);
        let _ = w.Write(bytes(s));
    });
    // Method-prefixed wildcard.
    mux.HandleFunc(string("GET /api/{resource}"), |w, r| {
        let res = r.PathValue(string("resource"));
        let s = goish::Sprintf!("api-get=%s\n", res);
        let _ = w.Write(bytes(s));
    });

    let mux_arc: Arc<dyn http::Handler> = Arc::new(mux);
    let mut srv = http::Server::default();
    srv.Handler = mux_arc;

    let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !lerr.IsNil() {
        Println!("Listen FAIL");
        syscall::Exit(1);
    }
    let addr = ln.Addr().String();
    let srv_arc = Arc::new(srv);
    let srv_for_serve = srv_arc.clone();
    go!(move || {
        let _ = srv_for_serve.Serve(ln);
    });
    time::Sleep(time::Millisecond * 30);

    let base_url = make_url(&addr);

    // 1. Plain literal still routes (regression).
    {
        let url = url_join(&base_url, "/health");
        let (resp, _) = http::Get(url);
        if resp.StatusCode == 200 && body_eq(&resp.Body, b"alive\n") {
            Println!("[ 1] literal route             PASS");
        } else {
            Println!("[ 1] literal route             FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    // 2. Single-segment wildcard binding.
    {
        let url = url_join(&base_url, "/users/42");
        let (resp, _) = http::Get(url);
        if resp.StatusCode == 200 && body_eq(&resp.Body, b"user-id=42\n") {
            Println!("[ 2] {{id}} bind               PASS");
        } else {
            Println!("[ 2] {{id}} bind               FAIL");
            failed += 1;
        }
    }

    // 3. Exact match wins over wildcard.
    {
        let url = url_join(&base_url, "/users/me");
        let (resp, _) = http::Get(url);
        if resp.StatusCode == 200 && body_eq(&resp.Body, b"self\n") {
            Println!("[ 3] exact > wildcard          PASS");
        } else {
            Println!("[ 3] exact > wildcard          FAIL");
            failed += 1;
        }
    }

    // 4. Trailing multi-segment wildcard binds the rest.
    {
        let url = url_join(&base_url, "/files/a/b/c.txt");
        let (resp, _) = http::Get(url);
        if resp.StatusCode == 200 && body_eq(&resp.Body, b"file-path=a/b/c.txt\n") {
            Println!("[ 4] {{path...}} bind          PASS");
        } else {
            Println!("[ 4] {{path...}} bind          FAIL body_len={}", resp.Body.Len());
            failed += 1;
        }
    }

    // 5. Method-prefixed wildcard matches GET.
    {
        let url = url_join(&base_url, "/api/widgets");
        let (resp, _) = http::Get(url);
        if resp.StatusCode == 200 && body_eq(&resp.Body, b"api-get=widgets\n") {
            Println!("[ 5] GET /api/{{resource}}     PASS");
        } else {
            Println!("[ 5] GET /api/{{resource}}     FAIL");
            failed += 1;
        }
    }

    // 6. /users/ (no segment) → 404 since {id} requires a non-empty
    //    segment (matches Go).
    {
        let url = url_join(&base_url, "/users/");
        let (resp, _) = http::Get(url);
        if resp.StatusCode == 404 {
            Println!("[ 6] /users/ → 404             PASS");
        } else {
            Println!("[ 6] /users/ → 404             FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    let _ = srv_arc.Shutdown(time::Second);

    if failed == 0 {
        Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 6", failed);
        syscall::Exit(1);
    }
}

fn make_url(addr: &goish::string) -> goish::string {
    let mut buf: Vec<u8> = Vec::with_capacity(7 + addr.Len() as usize);
    buf.extend_from_slice(b"http://");
    let ab = bytes(addr.clone());
    for i in 0..ab.Len() {
        buf.push(ab[i]);
    }
    goish::string::from_bytes(&buf)
}

fn url_join(base: &goish::string, path: &str) -> goish::string {
    let mut buf: Vec<u8> = Vec::new();
    let bb = bytes(base.clone());
    for i in 0..bb.Len() {
        buf.push(bb[i]);
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
