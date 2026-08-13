// http_server_handlers_smoke — net/http/server.go's handler helpers:
// Error (:2337), NotFound (:2358), Redirect (:2403) and htmlEscape
// (:2468).
//
// Every expectation is Go 1.25.5 output via scripts/goref.sh net/http.
//
// Two details are security-relevant rather than cosmetic:
//
//   * Error sets "X-Content-Type-Options: nosniff" alongside a
//     text/plain content type. Without it a browser may sniff an
//     error body containing attacker-influenced text as HTML and
//     execute it.
//   * Redirect writes a small HTML body for GET, and the URL in that
//     body goes through htmlEscape. htmlEscape covers `'` and `"` as
//     well as the angle brackets — quoting matters because the URL is
//     interpolated into an href ATTRIBUTE, where a bare quote would
//     break out of it.
//
// Redirect also relativises: a target with no leading slash is
// resolved against the request path's directory, so "c" from "/a/b"
// becomes "/a/c" — not "/c" and not "c".

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::response::ResponseWriter;
use goish::net::http::server::htmlEscape;
use goish::{fmt, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. htmlEscape covers the five characters Go's replacer does.
    {
        let cases: &[(&str, &str)] = &[
            ("<a>", "&lt;a&gt;"),
            ("a&b", "a&amp;b"),
            ("a\"b", "a&#34;b"),
            ("a'b", "a&#39;b"),
            ("plain", "plain"),
            ("", ""),
        ];
        let mut bad = 0;
        for (s, want) in cases {
            let got = htmlEscape(string(*s));
            if got != *want {
                fmt::Println!("     htmlEscape(", *s, ") = ", got, " want ", *want);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[1] htmlEscape, 6 cases vs Go  PASS");
        } else {
            failed += 1;
        }
    }

    // 2. Error — status, content type, nosniff, trailing newline.
    {
        let r = httptest::NewRecorder();
        {
            let w: &(dyn ResponseWriter + Send + Sync + 'static) = &r;
            http::Error(w, string("boom"), 500);
        }
        let body = string::from_bytes(&r.Body());
        if r.Code() == 500
            && r.Header().Get(string("Content-Type")) == "text/plain; charset=utf-8"
            && r.Header().Get(string("X-Content-Type-Options")) == "nosniff"
            && body == "boom\n"
        {
            fmt::Println!("[2] Error sets nosniff + text/plain  PASS");
        } else {
            fmt::Println!("[2] Error  FAIL code=", r.Code(), " body=", body);
            failed += 1;
        }
    }

    // 3. NotFound is Error with Go's exact message.
    {
        let r = httptest::NewRecorder();
        let (req, _) = http::NewRequest(string("GET"), string("http://x/"), goish::nil);
        {
            let w: &(dyn ResponseWriter + Send + Sync + 'static) = &r;
            http::NotFound(w, &req);
        }
        let body = string::from_bytes(&r.Body());
        if r.Code() == 404 && body == "404 page not found\n" {
            fmt::Println!("[3] NotFound  PASS");
        } else {
            fmt::Println!("[3] NotFound  FAIL code=", r.Code(), " body=", body);
            failed += 1;
        }
    }

    // 4. Redirect — Location, status, and the escaped HTML body.
    //    A relative target resolves against the request directory.
    {
        let cases: &[(&str, &str, &str)] = &[
            ("/c", "/c", "<a href=\"/c\">Found</a>.\n\n"),
            (
                "http://other/",
                "http://other/",
                "<a href=\"http://other/\">Found</a>.\n\n",
            ),
            ("c", "/a/c", "<a href=\"/a/c\">Found</a>.\n\n"),
        ];
        let (req, _) = http::NewRequest(string("GET"), string("http://x/a/b"), goish::nil);
        let mut bad = 0;
        for (target, wantLoc, wantBody) in cases {
            let r = httptest::NewRecorder();
            {
                let w: &(dyn ResponseWriter + Send + Sync + 'static) = &r;
                http::Redirect(w, &req, string(*target), 302);
            }
            let loc = r.Header().Get(string("Location"));
            let body = string::from_bytes(&r.Body());
            if loc != *wantLoc || r.Code() != 302 || body != *wantBody {
                fmt::Println!("     Redirect(", *target, ") loc=", loc, " body=", body);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[4] Redirect, 3 cases vs Go  PASS");
        } else {
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 4");
        syscall::Exit(1);
    }
}
