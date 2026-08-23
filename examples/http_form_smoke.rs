// http_form_smoke — exercise Request.ParseForm + FormValue + PostFormValue
// against a goish http::Server.
//
// Coverage:
//   1. URL query parsing  → r.FormValue("q")
//   2. POST body parsing  → r.PostFormValue("name")
//   3. Body+query merge   → both visible via r.FormValue
//   4. URL-decoded value  → "%20" → " ", "+" → " "
//
// Pass criteria: every named subtest prints "PASS"; final "ok" line.

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

    let q_seen = Arc::new(goish::sync::Mutex::new(string::new()));
    let pf_name = Arc::new(goish::sync::Mutex::new(string::new()));
    let merged = Arc::new(goish::sync::Mutex::new(string::new()));
    let decoded = Arc::new(goish::sync::Mutex::new(string::new()));

    let mux = http::ServeMux::new();
    {
        let s = q_seen.clone();
        mux.HandleFunc(string("/q"), move |w, r| {
            *s.Lock() = r.FormValue(string("q"));
            let _ = w.Write(bytes("ok\n"));
        });
    }
    {
        let s = pf_name.clone();
        mux.HandleFunc(string("/p"), move |w, r| {
            *s.Lock() = r.PostFormValue(string("name"));
            let _ = w.Write(bytes("ok\n"));
        });
    }
    {
        let s = merged.clone();
        mux.HandleFunc(string("/merge"), move |w, r| {
            // Body has key=body; URL has key=query.
            // ParseForm puts both into Form; PostForm wins for key in body.
            *s.Lock() = r.FormValue(string("key"));
            let _ = w.Write(bytes("ok\n"));
        });
    }
    {
        let s = decoded.clone();
        mux.HandleFunc(string("/d"), move |w, r| {
            *s.Lock() = r.FormValue(string("text"));
            let _ = w.Write(bytes("ok\n"));
        });
    }

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

    // 1. Query string FormValue.
    {
        let url = build_url(&addr, "/q?q=hello");
        let (resp, _) = http::Get(url);
        let v = q_seen.Lock().clone();
        if resp.StatusCode == 200 && v == "hello" {
            fmt::Println!("[ 1] FormValue from query      PASS");
        } else {
            fmt::Println!("[ 1] FormValue from query      FAIL got={}", v);
            failed += 1;
        }
    }

    // 2. POST body FormValue.
    {
        let url = build_url(&addr, "/p");
        let body = bytes("name=world");
        let (resp, _) = http::Post(url, string("application/x-www-form-urlencoded"), body);
        let v = pf_name.Lock().clone();
        if resp.StatusCode == 200 && v == "world" {
            fmt::Println!("[ 2] PostFormValue             PASS");
        } else {
            fmt::Println!("[ 2] PostFormValue             FAIL got={}", v);
            failed += 1;
        }
    }

    // 3. body+query merge — POST body has key=body, query has key=query.
    //    Per Go: PostForm values take precedence.
    {
        let url = build_url(&addr, "/merge?key=query");
        let body = bytes("key=body");
        let (resp, _) = http::Post(url, string("application/x-www-form-urlencoded"), body);
        let v = merged.Lock().clone();
        if resp.StatusCode == 200 && v == "body" {
            fmt::Println!("[ 3] body > query precedence   PASS");
        } else {
            fmt::Println!("[ 3] body > query precedence   FAIL got={}", v);
            failed += 1;
        }
    }

    // 4. URL-decode: %20 and + both → space.
    {
        let url = build_url(&addr, "/d?text=hello%20world+goodbye");
        let (resp, _) = http::Get(url);
        let v = decoded.Lock().clone();
        if resp.StatusCode == 200 && v == "hello world goodbye" {
            fmt::Println!("[ 4] %20 / + decode            PASS");
        } else {
            fmt::Println!("[ 4] %20 / + decode            FAIL got={}", v);
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
