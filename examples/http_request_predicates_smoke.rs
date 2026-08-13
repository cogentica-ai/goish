// http_request_predicates_smoke — net/http's token matcher and the
// small Request predicates built on it: hasToken (header.go:240),
// isTokenBoundary (:272), valueOrDefault (request.go:534),
// Request.isH2Upgrade (:529), expectsContinue (:1509),
// wantsHttp10KeepAlive (:1513) and requiresHTTP1 (:1579).
//
// Every expected value is Go 1.25.5 output via scripts/goref.sh
// net/http, not read off the source.
//
// hasToken is the one with teeth. It is NOT a substring search and NOT
// a split-on-comma: it walks candidate positions and requires a token
// BOUNDARY (space, comma or tab) on each side, then confirms with an
// ASCII case-insensitive compare. So "closely" and "notclose" do not
// match "close" though they contain it, "a\tclose\tb" does, and
// "~lose" is rejected by the EqualFold confirmation after passing the
// cheap first-byte screen. Getting this wrong means a Connection
// header of "closely" would close the connection.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http::header::{hasToken, isTokenBoundary, Header};
use goish::net::http::request::{valueOrDefault, Request};
use goish::net::http;
use goish::{fmt, string, syscall};

fn req(method: &'static str, proto: &'static str, maj: i64, min: i64, path: &'static str, hdrs: &[(&'static str, &'static str)]) -> Request {
    let mut h = Header::new();
    let mut i = 0;
    while i < hdrs.len() {
        h.Set(string(hdrs[i].0), string(hdrs[i].1));
        i += 1;
    }
    // Request carries private fields (path_values, form_state, ctx),
    // so it cannot be built from a struct literal outside the crate.
    // NewRequest is the supported constructor; the fields under test
    // are public and set afterwards.
    let (mut r, err) = http::NewRequest(string(method), string("http://x/"), goish::nil);
    if err != goish::nil {
        fmt::Println!("setup: NewRequest failed: ", err);
        syscall::Exit(1);
    }
    r.URL.Path = string(path);
    r.Proto = string(proto);
    r.ProtoMajor = maj;
    r.ProtoMinor = min;
    r.Header = h;
    return r;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. hasToken — 18 pairs pinned to Go.
    let pairs: &[(&str, &str, bool)] = &[
        ("", "close", false),
        ("close", "close", true),
        ("Close", "close", true),
        ("CLOSE", "close", true),
        ("keep-alive, close", "close", true),
        ("close, keep-alive", "close", true),
        ("foo,close ,bar", "close", true),
        ("closely", "close", false),
        ("notclose", "close", false),
        ("a\tclose\tb", "close", true),
        ("~lose", "close", false),
        ("upgrade", "upgrade", true),
        ("Upgrade, HTTP2-Settings", "upgrade", true),
        ("close", "", false),
        ("x", "close", false),
        ("keep-alive", "keep-alive", true),
        ("Keep-Alive", "keep-alive", true),
        ("100-continue", "100-continue", true),
    ];
    let mut bad = 0;
    for (v, tok, want) in pairs {
        if hasToken(string(*v), string(*tok)) != *want {
            fmt::Println!("     hasToken FAIL v=", *v, " token=", *tok);
            bad += 1;
        }
    }
    if bad == 0 {
        fmt::Println!("[1] hasToken, 18 pairs vs Go  PASS");
    } else {
        failed += 1;
    }

    // 2. isTokenBoundary — space, comma, tab and nothing else.
    {
        if isTokenBoundary(b' ')
            && isTokenBoundary(b',')
            && isTokenBoundary(b'\t')
            && !isTokenBoundary(b'a')
            && !isTokenBoundary(b'-')
            && !isTokenBoundary(b'\n')
        {
            fmt::Println!("[2] isTokenBoundary  PASS");
        } else {
            fmt::Println!("[2] isTokenBoundary  FAIL");
            failed += 1;
        }
    }

    // 3. valueOrDefault.
    {
        if valueOrDefault(string(""), string("GET")) == "GET"
            && valueOrDefault(string("POST"), string("GET")) == "POST"
        {
            fmt::Println!("[3] valueOrDefault  PASS");
        } else {
            fmt::Println!("[3] valueOrDefault  FAIL");
            failed += 1;
        }
    }

    // 4. isH2Upgrade — the HTTP/2 client preface. ALL FOUR conditions
    //    must hold, including an empty header set.
    {
        let a = req("PRI", "HTTP/2.0", 2, 0, "*", &[]);
        let b = req("PRI", "HTTP/2.0", 2, 0, "*", &[("X", "y")]);
        let c = req("GET", "HTTP/2.0", 2, 0, "*", &[]);
        if a.isH2Upgrade() && !b.isH2Upgrade() && !c.isH2Upgrade() {
            fmt::Println!("[4] isH2Upgrade  PASS");
        } else {
            fmt::Println!("[4] isH2Upgrade  FAIL ", a.isH2Upgrade(), b.isH2Upgrade(), c.isH2Upgrade());
            failed += 1;
        }
    }

    // 5. expectsContinue — case-insensitive on the token.
    {
        let a = req("POST", "HTTP/1.1", 1, 1, "/", &[("Expect", "100-continue")]);
        let b = req("POST", "HTTP/1.1", 1, 1, "/", &[("Expect", "100-Continue")]);
        let c = req("POST", "HTTP/1.1", 1, 1, "/", &[]);
        if a.expectsContinue() && b.expectsContinue() && !c.expectsContinue() {
            fmt::Println!("[5] expectsContinue  PASS");
        } else {
            fmt::Println!("[5] expectsContinue  FAIL");
            failed += 1;
        }
    }

    // 6. wantsHttp10KeepAlive — only for HTTP/1.0 exactly.
    {
        let a = req("GET", "HTTP/1.0", 1, 0, "/", &[("Connection", "keep-alive")]);
        let b = req("GET", "HTTP/1.1", 1, 1, "/", &[("Connection", "keep-alive")]);
        let c = req("GET", "HTTP/1.0", 1, 0, "/", &[]);
        if a.wantsHttp10KeepAlive() && !b.wantsHttp10KeepAlive() && !c.wantsHttp10KeepAlive() {
            fmt::Println!("[6] wantsHttp10KeepAlive  PASS");
        } else {
            fmt::Println!("[6] wantsHttp10KeepAlive  FAIL");
            failed += 1;
        }
    }

    // 7. requiresHTTP1 — Connection: Upgrade AND Upgrade: websocket.
    {
        let a = req("GET", "HTTP/1.1", 1, 1, "/", &[("Connection", "Upgrade"), ("Upgrade", "websocket")]);
        let b = req("GET", "HTTP/1.1", 1, 1, "/", &[("Connection", "Upgrade"), ("Upgrade", "h2c")]);
        let c = req("GET", "HTTP/1.1", 1, 1, "/", &[("Upgrade", "websocket")]);
        if a.requiresHTTP1() && !b.requiresHTTP1() && !c.requiresHTTP1() {
            fmt::Println!("[7] requiresHTTP1  PASS");
        } else {
            fmt::Println!("[7] requiresHTTP1  FAIL");
            failed += 1;
        }
    }

    // 8. wantsClose — the Close FIELD or a "close" token in Connection.
    //    "closely" must NOT match, which is the hasToken boundary rule
    //    (case 1) reaching a place where getting it wrong drops a
    //    connection the client wanted kept.
    {
        let cases: &[(bool, &'static str, bool)] = &[
            (false, "", false),
            (true, "", true),
            (false, "close", true),
            (false, "Close", true),
            (false, "keep-alive", false),
            (false, "keep-alive, close", true),
            (false, "closely", false),
            (true, "keep-alive", true),
        ];
        let mut bad = 0;
        for (close, conn, want) in cases {
            let mut r = req("GET", "HTTP/1.1", 1, 1, "/", &[]);
            r.Close = *close;
            if *conn != "" {
                r.Header.Set(string("Connection"), string(*conn));
            }
            if r.wantsClose() != *want {
                fmt::Println!("     wantsClose(Close=", *close, " Connection=", *conn, ") wrong");
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[8] wantsClose, 8 cases vs Go  PASS");
        } else {
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 8");
        syscall::Exit(1);
    }
}
