// http_mux_precedence_smoke — ServeMux picks the MOST SPECIFIC
// pattern, not the first registered.
//
// Go 1.22's mux orders patterns by specificity globally
// (server.go:2842 findHandler, via the routingNode tree). goish used
// to scan a Vec of wildcard patterns in REGISTRATION ORDER, and its
// own comment admitted the approximation:
//
//     // Go 1.22's mux compares pattern specificity globally; we
//     // approximate by deferring `/` to step 4.
//
// The case below is where that diverged. With "/{a}/{b}" registered
// BEFORE "/p/{b}", a request for "/p/x" went to the general pattern
// because it was seen first. Go sends it to "/p/{b}".
//
// Expected values captured from Go 1.25.5 via scripts/goref.sh:
//
//     /p/x     -> body="specific" pattern="/p/{b}"
//     /z/x     -> body="general"  pattern="/{a}/{b}"
//
// Registration order in this file is deliberately general-first, so a
// regression to order-based matching fails case 1 immediately.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::response::ResponseWriter;
use goish::{convert, fmt, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    let mux = http::NewServeMux();
    mux.HandleFunc(
        string("/{a}/{b}"),
        |w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &http::Request| {
            let _ = w.Write(convert::bytes(string("general")));
        },
    );
    mux.HandleFunc(
        string("/p/{b}"),
        |w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &http::Request| {
            let _ = w.Write(convert::bytes(string("specific")));
        },
    );

    let cases: &[(&str, &str, &str)] = &[
        ("/p/x", "specific", "/p/{b}"),
        ("/z/x", "general", "/{a}/{b}"),
    ];

    let mut bad = 0;
    for (path, wantBody, wantPat) in cases {
        let rec = httptest::NewRecorder();
        let (req, _) = http::NewRequest(
            string("GET"),
            string("http://e.com") + string(*path),
            goish::nil,
        );
        {
            let w: &(dyn ResponseWriter + Send + Sync + 'static) = &rec;
            http::Handler::ServeHTTP(&mux, w, &req);
        }
        let (_h, pat) = mux.Handler(&req);
        let body = string::from_bytes(&rec.Body());
        if body != *wantBody || pat != *wantPat {
            fmt::Println!("     ", *path, " -> body=", body, " pattern=", pat);
            bad += 1;
        }
    }
    if bad == 0 {
        fmt::Println!("[1] most-specific pattern wins, not first-registered  PASS");
    } else {
        fmt::Println!("[1] mux precedence  FAIL");
        failed += 1;
    }

    // 2. The wildcard binding still reaches the handler by NAME. The
    //    tree returns positional matches, so this checks the zip
    //    against the pattern's wild segments.
    {
        let m2 = http::NewServeMux();
        m2.HandleFunc(
            string("/u/{id}/p/{sub}"),
            |w: &(dyn ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                let _ = w.Write(convert::bytes(
                    r.PathValue(string("id")) + "|" + r.PathValue(string("sub")),
                ));
            },
        );
        let rec = httptest::NewRecorder();
        let (req, _) = http::NewRequest(string("GET"), string("http://e.com/u/7/p/z"), goish::nil);
        {
            let w: &(dyn ResponseWriter + Send + Sync + 'static) = &rec;
            http::Handler::ServeHTTP(&m2, w, &req);
        }
        let body = string::from_bytes(&rec.Body());
        if body == "7|z" {
            fmt::Println!("[2] positional matches bind to wildcard names  PASS");
        } else {
            fmt::Println!("[2] wildcard binding  FAIL got=", body);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 2/2");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 2");
        syscall::Exit(1);
    }
}
