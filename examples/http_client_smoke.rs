// http_client_smoke — exercise the goish http::Client against a goish
// http::Server running in-process.
//
// Coverage:
//   1. http::Get  on a 200 OK route, fixed-length body.
//   2. http::Get  on a 404 route — verify StatusCode + body.
//   3. http::Post application/json — verify req.Body lands at server.
//   4. http::PostForm — verify URL-encoded body decode.
//   5. Redirect chain (302) — verify Client follows + final response.
//   6. Chunked response — verify Client decodes Transfer-Encoding: chunked.
//   7. Response.Cookies() — verify Set-Cookie parses out of the response.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io;
use goish::net;
use goish::net::http;
use goish::time;
use goish::{bytes, go, string, syscall};

#[goish::main]
fn main() {
    // Stand up one server with all routes.
    let mux = http::ServeMux::new();
    mux.HandleFunc(string("/hello"), |w, _r| {
        let _ = w.Write(bytes("hello, client\n"));
    });
    mux.HandleFunc(string("/notfound"), |w, _r| {
        w.WriteHeader(404);
        let _ = w.Write(bytes("missing\n"));
    });

    let echo_seen_len = Arc::new(AtomicUsize::new(0));
    let echo_seen_ct = Arc::new(goish::sync::Mutex::new(string::new()));
    {
        let len_h = echo_seen_len.clone();
        let ct_h = echo_seen_ct.clone();
        mux.HandleFunc(string("/echo"), move |w, r| {
            let (rbody, _) = goish::io::ReadAll(&mut r.Body.clone());
            len_h.store(rbody.Len() as usize, Ordering::SeqCst);
            *ct_h.Lock() = r.Header.Get(string("Content-Type"));
            let _ = w.Write(rbody);
        });
    }

    let form_seen_a = Arc::new(goish::sync::Mutex::new(string::new()));
    let form_seen_b = Arc::new(goish::sync::Mutex::new(string::new()));
    {
        let a_h = form_seen_a.clone();
        let b_h = form_seen_b.clone();
        mux.HandleFunc(string("/form"), move |w, r| {
            // Convert the request body to a Vec<u8> for parsing.
            let (rbody, _) = goish::io::ReadAll(&mut r.Body.clone());
            let body = &rbody;
            let mut bv: Vec<u8> = Vec::new();
            for i in 0..body.Len() {
                bv.push(body[i]);
            }
            let parts = split_amp(&bv);
            for kv in parts {
                let (k, v) = split_eq(&kv);
                let v_decoded = url_decode(&v);
                if k == b"alpha" {
                    *a_h.Lock() = goish::string::from_bytes(&v_decoded);
                }
                if k == b"beta" {
                    *b_h.Lock() = goish::string::from_bytes(&v_decoded);
                }
            }
            let _ = w.Write(bytes("form-ok\n"));
        });
    }

    mux.HandleFunc(string("/redir"), |w, _r| {
        w.Header().Set(string("Location"), string("/hello"));
        w.WriteHeader(302);
        let _ = w.Write(bytes(""));
    });
    mux.HandleFunc(string("/stream"), |w, _r| {
        // Go: f, ok := w.(http.Flusher)
        let (f, ok) = goish::cast!(w, http::Flusher);
        if ok {
            f.Flush();
        }
        let _ = w.Write(bytes("alpha-"));
        if ok {
            f.Flush();
        }
        let _ = w.Write(bytes("beta-"));
        if ok {
            f.Flush();
        }
        let _ = w.Write(bytes("gamma"));
    });
    mux.HandleFunc(string("/setcookie"), |w, _r| {
        let mut c = http::Cookie::new(string("session"), string("xyz"));
        c.HttpOnly = true;
        http::SetCookie(w, &c);
        let _ = w.Write(bytes("ok\n"));
    });

    let mux_arc: Arc<dyn http::Handler> = Arc::new(mux);
    let mut srv = http::Server::default();
    srv.Handler = mux_arc;

    let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !lerr.IsNil() {
        fmt::Println!("Listen failed: {}", lerr);
        syscall::Exit(1);
    }
    let addr = ln.Addr().String();
    let srv_arc = Arc::new(srv);
    let srv_for_serve = srv_arc.clone();
    go!(move || {
        let _ = srv_for_serve.Serve(ln);
    });
    time::Sleep(time::Millisecond * 30);

    // Build base URL like "http://127.0.0.1:NNNN".
    let base_url = make_url(&addr);

    let mut failed = 0;

    // 1. Get 200.
    {
        let url = url_join(&base_url, "/hello");
        let (mut resp, err) = http::Get(url);
        if !err.IsNil() {
            fmt::Println!("[ 1] Get hello FAIL err={}", err);
            failed += 1;
        } else {
            let (body, _) = io::ReadAll(&mut resp.Body);
            let _ = io::Closer::Close(&mut resp.Body);
            let body_ok = body_eq(&body, b"hello, client\n");
            if resp.StatusCode == 200 && body_ok {
                fmt::Println!("[ 1] Get 200 OK               PASS");
            } else {
                fmt::Println!(
                    "[ 1] Get 200 OK               FAIL status={} body_ok={}",
                    resp.StatusCode, body_ok
                );
                failed += 1;
            }
        }
    }

    // 2. Get 404.
    {
        let url = url_join(&base_url, "/notfound");
        let (mut resp, _err) = http::Get(url);
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        if resp.StatusCode == 404 && body_eq(&body, b"missing\n") {
            fmt::Println!("[ 2] Get 404                  PASS");
        } else {
            fmt::Println!("[ 2] Get 404                  FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    // 3. Post JSON.
    {
        let url = url_join(&base_url, "/echo");
        let body = bytes(r#"{"k":"v"}"#);
        let (mut resp, err) = http::Post(url, string("application/json"), body);
        let seen_len = echo_seen_len.load(Ordering::SeqCst);
        let seen_ct = echo_seen_ct.Lock().clone();
        let (resp_body, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        if !err.IsNil() {
            fmt::Println!("[ 3] Post JSON                FAIL err={}", err);
            failed += 1;
        } else if resp.StatusCode == 200
            && seen_len == 9
            && seen_ct == "application/json"
            && body_eq(&resp_body, br#"{"k":"v"}"#)
        {
            fmt::Println!("[ 3] Post JSON                PASS");
        } else {
            fmt::Println!(
                "[ 3] Post JSON                FAIL status={} seen_len={}",
                resp.StatusCode, seen_len
            );
            failed += 1;
        }
    }

    // 4. PostForm.
    {
        let url = url_join(&base_url, "/form");
        let vals = [
            (string("alpha"), string("hello world")),
            (string("beta"), string("a&b=c")),
        ];
        let (resp, _err) = http::PostForm(url, &vals);
        let a = form_seen_a.Lock().clone();
        let b = form_seen_b.Lock().clone();
        if resp.StatusCode == 200 && a == "hello world" && b == "a&b=c" {
            fmt::Println!("[ 4] PostForm                 PASS");
        } else {
            fmt::Println!(
                "[ 4] PostForm                 FAIL status={}",
                resp.StatusCode
            );
            failed += 1;
        }
    }

    // 5. Redirect (302 → /hello).
    {
        let url = url_join(&base_url, "/redir");
        let (mut resp, _err) = http::Get(url);
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        if resp.StatusCode == 200 && body_eq(&body, b"hello, client\n") {
            fmt::Println!("[ 5] Redirect 302→200         PASS");
        } else {
            fmt::Println!("[ 5] Redirect 302→200         FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    // 6. Chunked response.
    {
        let url = url_join(&base_url, "/stream");
        let (mut resp, _err) = http::Get(url);
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        if resp.StatusCode == 200
            && body_eq(&body, b"alpha-beta-gamma")
            && resp.ContentLength == -1
        {
            fmt::Println!("[ 6] Chunked response         PASS");
        } else {
            fmt::Println!(
                "[ 6] Chunked response         FAIL status={} cl={} body_len={}",
                resp.StatusCode, resp.ContentLength, body.Len()
            );
            failed += 1;
        }
    }

    // 7. Cookies().
    {
        let url = url_join(&base_url, "/setcookie");
        let (resp, _err) = http::Get(url);
        let cookies = resp.Cookies();
        if cookies.Len() == 1
            && cookies[0].Name == "session"
            && cookies[0].Value == "xyz"
            && cookies[0].HttpOnly
        {
            fmt::Println!("[ 7] Response.Cookies()       PASS");
        } else {
            fmt::Println!("[ 7] Response.Cookies()       FAIL n={}", cookies.Len());
            failed += 1;
        }
    }

    let _ = srv_arc.Shutdown(time::Second);

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 7", failed);
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

fn split_amp(s: &[u8]) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in s {
        if b == b'&' {
            out.push(core::mem::take(&mut cur));
        } else {
            cur.push(b);
        }
    }
    out.push(cur);
    out
}

fn split_eq(s: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if let Some(i) = s.iter().position(|&b| b == b'=') {
        (s[..i].to_vec(), s[i + 1..].to_vec())
    } else {
        (s.to_vec(), Vec::new())
    }
}

fn url_decode(b: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'+' {
            out.push(b' ');
            i += 1;
        } else if c == b'%' && i + 2 < b.len() {
            let h1 = hex_d(b[i + 1]);
            let h2 = hex_d(b[i + 2]);
            if h1 < 16 && h2 < 16 {
                out.push((h1 << 4) | h2);
                i += 3;
            } else {
                out.push(c);
                i += 1;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn hex_d(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 255,
    }
}
