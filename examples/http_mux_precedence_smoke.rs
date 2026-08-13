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

    // 3. Trailing-slash redirect (matchOrRedirect + exactMatch). A
    //    request for "/dir" reaches a handler registered as "/dir/"
    //    via a 301, NOT by matching it directly — and the query
    //    string is carried across. "/file/" does NOT redirect back to
    //    "/file": the rule only adds a slash, never removes one.
    //    Pinned from Go 1.25.5.
    {
        let m3 = http::NewServeMux();
        m3.HandleFunc(
            string("/dir/"),
            |w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &http::Request| {
                let _ = w.Write(convert::bytes(string("dir")));
            },
        );
        m3.HandleFunc(
            string("/file"),
            |w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &http::Request| {
                let _ = w.Write(convert::bytes(string("file")));
            },
        );
        let cases: &[(&str, i64, &str, &str)] = &[
            ("/dir/", 200, "", "dir"),
            ("/dir", 301, "/dir/", "<a href=\"/dir/\">Moved Permanently</a>.\n\n"),
            ("/dir?q=1", 301, "/dir/?q=1", "<a href=\"/dir/?q=1\">Moved Permanently</a>.\n\n"),
            ("/file", 200, "", "file"),
            ("/file/", 404, "", "404 page not found\n"),
            ("/nope", 404, "", "404 page not found\n"),
        ];
        let mut bad = 0;
        for (path, wantCode, wantLoc, wantBody) in cases {
            let rec = httptest::NewRecorder();
            let (req, _) = http::NewRequest(
                string("GET"),
                string("http://e.com") + string(*path),
                goish::nil,
            );
            {
                let w: &(dyn ResponseWriter + Send + Sync + 'static) = &rec;
                http::Handler::ServeHTTP(&m3, w, &req);
            }
            let body = string::from_bytes(&rec.Body());
            let loc = rec.Header().Get(string("Location"));
            if rec.Code() != *wantCode || loc != *wantLoc || body != *wantBody {
                fmt::Println!("     ", *path, " code=", rec.Code(), " loc=", loc, " body=", body);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[3] trailing-slash 301, query preserved, no reverse  PASS");
        } else {
            fmt::Println!("[3] trailing-slash redirect  FAIL");
            failed += 1;
        }
    }

    // 4. Pattern conflicts. Go rejects two patterns that both match
    //    some path where NEITHER is more specific, because the choice
    //    between them would otherwise be arbitrary. These four are the
    //    accept cases, verified against Go: disjoint literals, a
    //    specific pattern alongside a general one (specificity
    //    resolves it), and the same path split by method.
    //
    //    The REJECT case is "/{a}/{b}" with "/q/" — both match "/q/b",
    //    neither is more specific. goish now panics there with Go's
    //    description verbatim ("/q/ and /{a}/{b} both match some
    //    paths, like \"/q/b\"." ...), which is not asserted here only
    //    because a panic ends the example.
    {
        let sets: &[&[&'static str]] = &[
            &["/a", "/b"],
            &["/{a}/{b}", "/p/{b}"],
            &["GET /x", "POST /x"],
        ];
        let mut bad = 0;
        for pats in sets {
            let m = http::NewServeMux();
            for p in pats.iter() {
                m.HandleFunc(
                    string(*p),
                    |_w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &http::Request| {},
                );
            }
            // Reaching here without a panic is the assertion.
            bad += 0;
        }
        if bad == 0 {
            fmt::Println!("[4] non-conflicting pattern sets all register  PASS");
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
