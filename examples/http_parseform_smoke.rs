// Request.ParseForm / FormValue / PostFormValue against Go 1.25.5.
//
// Expected values came from a goref run; nothing is derived from
// reading the docs.
//
// The case with teeth is "both": Go merges PostForm INTO Form with the
// POST values FIRST, so with ?a=1 and body a=9 the result is
// Form[a] == ["9","1"] and FormValue("a") == "9". A port that appended
// query-first would pass every single-source test and fail this one.
//
// The bad-escape case pins that ParseForm reports the error AND still
// returns the values it could parse.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::{fmt, string, syscall};

fn joined(v: &goish::slice<string>) -> string {
    let mut out = string::new();
    for i in 0..v.len() {
        if i > 0 {
            out = out + string("|");
        }
        out = out + v[i].clone();
    }
    return out;
}

fn eq(got: string, want: &str, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what, ": got ", got, " want ", want);
        *bad += 1;
    }
}

fn postReq(target: &'static str, body: &'static str) -> http::Request {
    let (mut r, _) = http::NewRequest(
        string("POST"),
        string(target),
        goish::slice::<u8>::__from_vec(body.as_bytes().to_vec()),
    );
    r.Header.Set(
        string("Content-Type"),
        string("application/x-www-form-urlencoded"),
    );
    return r;
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    // Query only: Form has both values of a, PostForm empty.
    {
        let (r, _) = http::NewRequest(string("GET"), string("http://x/?a=1&b=2&a=3"), goish::nil);
        let _ = r.ParseForm();
        eq(
            joined(&{
                let (v, _) = r.Form().Get(string("a"));
                v
            }),
            "1|3",
            "query Form[a]",
            &mut bad,
        );
        eq(
            r.FormValue(string("a")),
            "1",
            "query FormValue(a)",
            &mut bad,
        );
        eq(
            r.PostFormValue(string("a")),
            "",
            "query PostFormValue(a)",
            &mut bad,
        );
    }

    // POST body only.
    {
        let r = postReq("http://x/", "a=9&c=7");
        let _ = r.ParseForm();
        eq(r.FormValue(string("a")), "9", "post FormValue(a)", &mut bad);
        eq(
            r.PostFormValue(string("a")),
            "9",
            "post PostFormValue(a)",
            &mut bad,
        );
        eq(r.FormValue(string("c")), "7", "post FormValue(c)", &mut bad);
    }

    // Both — POST values come FIRST in Form.
    {
        let r = postReq("http://x/?a=1&b=2", "a=9&c=7");
        let _ = r.ParseForm();
        eq(
            joined(&{
                let (v, _) = r.Form().Get(string("a"));
                v
            }),
            "9|1",
            "both Form[a] order",
            &mut bad,
        );
        eq(r.FormValue(string("a")), "9", "both FormValue(a)", &mut bad);
        eq(
            r.PostFormValue(string("a")),
            "9",
            "both PostFormValue(a)",
            &mut bad,
        );
        eq(r.FormValue(string("b")), "2", "both FormValue(b)", &mut bad);
    }

    // GET with a body is NOT parsed as a post form.
    {
        let (mut r, _) = http::NewRequest(
            string("GET"),
            string("http://x/?a=1"),
            goish::slice::<u8>::__from_vec(b"a=9".to_vec()),
        );
        r.Header.Set(
            string("Content-Type"),
            string("application/x-www-form-urlencoded"),
        );
        let _ = r.ParseForm();
        eq(
            r.FormValue(string("a")),
            "1",
            "get+body FormValue(a)",
            &mut bad,
        );
        eq(
            r.PostFormValue(string("a")),
            "",
            "get+body PostFormValue(a)",
            &mut bad,
        );
    }

    // Bad escape: error reported, parseable values still present.
    {
        let (r, _) = http::NewRequest(string("GET"), string("http://x/?a=%zz&b=2"), goish::nil);
        let err = r.ParseForm();
        if err == goish::errors::nil {
            fmt::Println!("FAIL bad escape: expected an error");
            bad += 1;
        }
        eq(
            r.FormValue(string("b")),
            "2",
            "bad escape keeps b",
            &mut bad,
        );
        eq(r.FormValue(string("a")), "", "bad escape drops a", &mut bad);
    }

    if bad == 0 {
        fmt::Println!("PARSEFORM_OK 15/15");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
