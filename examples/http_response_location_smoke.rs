// Response.Location / ProtoAtLeast / Cookies against Go 1.25.5.
//
// Expected values came from a goref run of the real methods; nothing
// here is derived from reading the spec.
//
// Location is the one with teeth. Go implements it as
//
//     return r.Request.URL.Parse(lv)
//
// i.e. full RFC 3986 reference resolution. A hand-rolled
// "starts-with-slash ? replace path : append to dirname" gets the
// dot-segment and protocol-relative forms wrong, which is why "../q"
// and "//other/p" are in here.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::{fmt, string, syscall};

fn mk(reqURL: &'static str, loc: &'static str) -> (string, bool) {
    let mut r = http::Response::default();
    if loc != "" {
        r.Header.Set(string("Location"), string(loc));
    }
    if reqURL != "" {
        let (req, _) = http::NewRequest(string("GET"), string(reqURL), goish::nil);
        r.Request = goish::nilable::new(req);
    }
    let (u, err) = r.Location();
    if err != goish::errors::nil {
        return (string(""), false);
    }
    return (u.String(), true);
}

fn eq(got: (string, bool), want: &str, what: &str, bad: &mut i32) {
    let (s, ok) = got;
    if want == "ERR" {
        if ok {
            fmt::Println!("FAIL ", what, ": expected error, got ", s);
            *bad += 1;
        }
        return;
    }
    if !ok || s != want {
        fmt::Println!("FAIL ", what, ": got ", s, " want ", want);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    eq(mk("http://x/a/b", "/c"), "http://x/c", "abs path", &mut bad);
    eq(
        mk("http://x/a/b", "c"),
        "http://x/a/c",
        "rel path",
        &mut bad,
    );
    eq(
        mk("http://x/a/b", "http://y/z"),
        "http://y/z",
        "absolute URL",
        &mut bad,
    );
    eq(
        mk("http://x/a/b", ""),
        "ERR",
        "no Location header",
        &mut bad,
    );
    eq(mk("", "/c"), "/c", "no request URL", &mut bad);
    eq(
        mk("http://x/a/b", "../q"),
        "http://x/q",
        "dot-dot segment",
        &mut bad,
    );
    eq(
        mk("http://x/a/b", "//other/p"),
        "http://other/p",
        "protocol-relative",
        &mut bad,
    );

    // ProtoAtLeast on a 1.1 response.
    let mut r = http::Response::default();
    r.ProtoMajor = 1;
    r.ProtoMinor = 1;
    let cases: [(goish::types::int, goish::types::int, bool); 5] = [
        (1, 0, true),
        (1, 1, true),
        (1, 2, false),
        (0, 9, true),
        (2, 0, false),
    ];
    for (maj, min, w) in cases.iter() {
        if r.ProtoAtLeast(*maj, *min) != *w {
            fmt::Println!("FAIL ProtoAtLeast ", *maj, " ", *min);
            bad += 1;
        }
    }

    // Cookies from two Set-Cookie headers.
    let mut rc = http::Response::default();
    rc.Header
        .Add(string("Set-Cookie"), string("a=1; Path=/; HttpOnly"));
    rc.Header
        .Add(string("Set-Cookie"), string("b=2; Max-Age=60"));
    let cs = rc.Cookies();
    if cs.len() != 2 {
        fmt::Println!("FAIL Cookies count ", cs.len());
        bad += 1;
    } else {
        if cs[0].Name != "a" || cs[0].Value != "1" || cs[0].Path != "/" || !cs[0].HttpOnly {
            fmt::Println!("FAIL cookie a");
            bad += 1;
        }
        if cs[1].Name != "b" || cs[1].Value != "2" || cs[1].MaxAge != 60 {
            fmt::Println!("FAIL cookie b");
            bad += 1;
        }
    }

    if bad == 0 {
        fmt::Println!("RESPONSE_LOCATION_OK 14/14");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
