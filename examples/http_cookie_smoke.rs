// http_cookie_smoke — exercise http::Cookie serialize/parse round-trip,
// http::ParseSetCookie attribute parsing, Request.Cookies, and SetCookie.
//
// Mirrors net/http/cookie_test.go's headline cases.
//
// Pass criteria: every named subtest prints "PASS"; final "ok" line.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http::{self, Cookie, SameSite};
use goish::time;
use goish::{bytes, go, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Cookie::String for a simple Name=Value pair.
    {
        let c = Cookie::new(string("session"), string("abc123"));
        let s = c.String();
        if s == "session=abc123" {
            fmt::Println!("[ 1] simple Name=Value         PASS");
        } else {
            fmt::Println!("[ 1] simple Name=Value         FAIL got {}", s);
            failed += 1;
        }
    }

    // 2. Full attribute set.
    {
        let mut c = Cookie::new(string("k"), string("v"));
        c.Path = string("/");
        c.Domain = string("example.com");
        c.Secure = true;
        c.HttpOnly = true;
        c.SameSite = SameSite::LaxMode;
        c.MaxAge = 3600;
        let s = c.String();
        if s == "k=v; Path=/; Domain=example.com; Max-Age=3600; HttpOnly; Secure; SameSite=Lax" {
            fmt::Println!("[ 2] full attribute set        PASS");
        } else {
            fmt::Println!("[ 2] full attribute set        FAIL got {}", s);
            failed += 1;
        }
    }

    // 3. MaxAge<0 → Max-Age=0 ("delete now").
    {
        let mut c = Cookie::new(string("d"), string("x"));
        c.MaxAge = -1;
        let s = c.String();
        if s == "d=x; Max-Age=0" {
            fmt::Println!("[ 3] MaxAge<0 → Max-Age=0      PASS");
        } else {
            fmt::Println!("[ 3] MaxAge<0 → Max-Age=0      FAIL got {}", s);
            failed += 1;
        }
    }

    // 4. Value with space/comma → quoted on the wire.
    {
        let c = Cookie::new(string("k"), string("hello, world"));
        let s = c.String();
        if s == "k=\"hello, world\"" {
            fmt::Println!("[ 4] value with space/comma    PASS");
        } else {
            fmt::Println!("[ 4] value with space/comma    FAIL got {}", s);
            failed += 1;
        }
    }

    // 5. Invalid name → empty string.
    {
        let c = Cookie::new(string("bad name"), string("v"));
        let s = c.String();
        if s.Len() == 0 {
            fmt::Println!("[ 5] invalid name → empty      PASS");
        } else {
            fmt::Println!("[ 5] invalid name → empty      FAIL got {}", s);
            failed += 1;
        }
    }

    // 6. Round-trip ParseSetCookie on what String emitted.
    {
        let mut c = Cookie::new(string("sid"), string("xyz"));
        c.Path = string("/api");
        c.HttpOnly = true;
        c.SameSite = SameSite::StrictMode;
        c.MaxAge = 600;
        let serialized = c.String();
        let (parsed, err) = http::ParseSetCookie(serialized.clone());
        let ok = err.IsNil()
            && parsed.Name == "sid"
            && parsed.Value == "xyz"
            && parsed.Path == "/api"
            && parsed.HttpOnly
            && parsed.SameSite == SameSite::StrictMode
            && parsed.MaxAge == 600;
        if ok {
            fmt::Println!("[ 6] round-trip parse          PASS");
        } else {
            fmt::Println!("[ 6] round-trip parse          FAIL serialized={}", serialized);
            failed += 1;
        }
    }

    // 7. ParseCookie of a Cookie: header with two values.
    {
        let line = string("a=1; b=two");
        let (cookies, err) = http::ParseCookie(line);
        let ok = err.IsNil()
            && cookies.Len() == 2
            && cookies[0].Name == "a"
            && cookies[0].Value == "1"
            && cookies[1].Name == "b"
            && cookies[1].Value == "two";
        if ok {
            fmt::Println!("[ 7] ParseCookie 2 values      PASS");
        } else {
            fmt::Println!("[ 7] ParseCookie 2 values      FAIL");
            failed += 1;
        }
    }

    // 8. Quoted value strips quotes, retains Quoted=true.
    {
        let line = string("session=\"with space\"");
        let (cs, _err) = http::ParseCookie(line);
        let ok = cs.Len() == 1 && cs[0].Value == "with space" && cs[0].Quoted;
        if ok {
            fmt::Println!("[ 8] quoted value parse        PASS");
        } else {
            fmt::Println!("[ 8] quoted value parse        FAIL");
            failed += 1;
        }
    }

    // 9. Expires round-trip via parse → String → parse.
    {
        let mut c = Cookie::new(string("e"), string("v"));
        c.Expires = time::Date(2027, 1, 15, 10, 30, 45, 0, goish::time::UTC);
        let s = c.String();
        let (parsed, _err) = http::ParseSetCookie(s.clone());
        let y = parsed.Expires.Year();
        let m = parsed.Expires.Month();
        let d = parsed.Expires.Day();
        let (hh, mm, ss) = parsed.Expires.Clock();
        if y == 2027 && m == 1 && d == 15 && hh == 10 && mm == 30 && ss == 45 {
            fmt::Println!("[ 9] Expires round-trip        PASS");
        } else {
            fmt::Println!(
                "[ 9] Expires round-trip        FAIL serialized={} y={} m={} d={} {}:{}:{}",
                s, y, m, d, hh, mm, ss
            );
            failed += 1;
        }
    }

    // 10. Live HTTP server: Set-Cookie header travels through wire.
    {
        let mux = http::ServeMux::new();
        mux.HandleFunc(string("/login"), |w, _r| {
            let mut c = Cookie::new(string("auth"), string("token42"));
            c.HttpOnly = true;
            c.MaxAge = 7200;
            http::SetCookie(w, &c);
            let _ = w.Write(bytes("ok\n"));
        });
        let mux_arc: Arc<dyn http::Handler> = Arc::new(mux);
        let mut srv = http::Server::default();
        srv.Handler = mux_arc;
        let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if !err.IsNil() {
            fmt::Println!("[10] Listen FAIL {}", err);
            failed += 1;
        } else {
            let addr = ln.Addr().String();
            let srv_arc = Arc::new(srv);
            let srv_for_serve = srv_arc.clone();
            go!(move || {
                let _ = srv_for_serve.Serve(ln);
            });
            time::Sleep(time::Millisecond * 20);

            let (mut conn, derr) = net::Dial(string("tcp"), addr.clone());
            if !derr.IsNil() {
                fmt::Println!("[10] Dial FAIL {}", derr);
                failed += 1;
            } else {
                let req = bytes("GET /login HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
                let _ = conn.Write(req);

                let mut total: usize = 0;
                let mut whole: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(2048);
                loop {
                    let mut dst = goish::goslice::slice::<u8>::__from_vec(alloc::vec![0u8; 1024]);
                    let (n, e) = conn.Read(&mut dst);
                    let n = n as usize;
                    if n == 0 {
                        break;
                    }
                    for i in 0..n {
                        whole.push(dst[i as i64]);
                    }
                    total += n;
                    if !e.IsNil() {
                        break;
                    }
                }
                let _ = total;
                // Find Set-Cookie header.
                let needle = b"Set-Cookie:";
                let mut i = 0;
                let mut sc_line: Option<&[u8]> = None;
                while i + needle.len() <= whole.len() {
                    if &whole[i..i + needle.len()] == needle {
                        let after = &whole[i + needle.len()..];
                        let crlf = after.iter().position(|&b| b == b'\r').unwrap_or(after.len());
                        sc_line = Some(&after[..crlf]);
                        break;
                    }
                    i += 1;
                }
                match sc_line {
                    Some(line) => {
                        let mut start = 0;
                        while start < line.len() && line[start] == b' ' {
                            start += 1;
                        }
                        let val = string::from_bytes(&line[start..]);
                        let (parsed, perr) = http::ParseSetCookie(val);
                        if perr.IsNil()
                            && parsed.Name == "auth"
                            && parsed.Value == "token42"
                            && parsed.HttpOnly
                            && parsed.MaxAge == 7200
                        {
                            fmt::Println!("[10] live server SetCookie     PASS");
                        } else {
                            fmt::Println!("[10] live server SetCookie     FAIL");
                            failed += 1;
                        }
                    }
                    None => {
                        fmt::Println!("[10] live server SetCookie     FAIL no Set-Cookie");
                        failed += 1;
                    }
                }
                let _ = conn.Close();
            }
            let srv_for_shut = srv_arc.clone();
            let _ = srv_for_shut.Shutdown(time::Second);
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 10", failed);
        syscall::Exit(1);
    }
}
