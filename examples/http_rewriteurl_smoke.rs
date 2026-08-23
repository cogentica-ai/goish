// httputil rewriteRequestURL against Go 1.25.5. Expected values from
// a goref run of the real unexported function.
//
// This is what a single-host reverse proxy does to every request, so
// the joins have to be exact:
//
//   target /base + req /dir  -> /base/dir   (one slash inserted)
//   target /base/ + req /dir -> /base/dir   (NOT /base//dir)
//   target /base + req /     -> /base/
//   target / + req /dir      -> /dir        (no doubled slash)
//   target (no path) + /dir  -> /dir
//
// and the query rule is concatenate, with "&" only when BOTH sides
// are non-empty — target query first.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::net::http::httputil;
use goish::net::http::url;
use goish::{errors, fmt, string, syscall};

fn chk(target: &'static str, reqURL: &'static str, want: &str, bad: &mut i32) {
    let (tgt, e1) = url::Parse(string(target));
    let (mut req, e2) = http::NewRequest(string("GET"), string(reqURL), goish::nil);
    if e1 != errors::nil || e2 != errors::nil {
        fmt::Println!("FAIL parse ", target, " / ", reqURL);
        *bad += 1;
        return;
    }
    httputil::rewriteRequestURL(&mut req, &tgt);
    let got = req.URL.String();
    if got != want {
        fmt::Println!("FAIL target=", target, " req=", reqURL);
        fmt::Println!("  got  ", got);
        fmt::Println!("  want ", want);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    chk(
        "http://back/base",
        "http://front/dir",
        "http://back/base/dir",
        &mut bad,
    );
    chk(
        "http://back/base/",
        "http://front/dir",
        "http://back/base/dir",
        &mut bad,
    );
    chk(
        "http://back/base",
        "http://front/",
        "http://back/base/",
        &mut bad,
    );
    chk(
        "http://back/",
        "http://front/dir",
        "http://back/dir",
        &mut bad,
    );
    chk(
        "http://back",
        "http://front/dir",
        "http://back/dir",
        &mut bad,
    );
    chk(
        "http://back/base?t=1",
        "http://front/dir?r=2",
        "http://back/base/dir?t=1&r=2",
        &mut bad,
    );
    chk(
        "http://back/base?t=1",
        "http://front/dir",
        "http://back/base/dir?t=1",
        &mut bad,
    );
    chk(
        "http://back/base",
        "http://front/dir?r=2",
        "http://back/base/dir?r=2",
        &mut bad,
    );

    if bad == 0 {
        fmt::Println!("REWRITEURL_OK 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
