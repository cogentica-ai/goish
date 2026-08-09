// url_escape_smoke — exercise QueryEscape / PathEscape (line-by-line
// port of url.go:281 / :287) round-tripping with the existing
// QueryUnescape / PathUnescape helpers.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. QueryEscape: spaces → '+', reserved chars escaped.
    {
        let got = http::QueryEscape(string("hello world & friends"));
        if got == "hello+world+%26+friends" {
            fmt::Println!("[ 1] QueryEscape spaces+amp     PASS");
        } else {
            fmt::Println!("[ 1] QueryEscape spaces+amp     FAIL got={}", got);
            failed += 1;
        }
    }

    // 2. PathEscape: spaces → '%20', '/' escaped, '?' escaped, ',' escaped.
    {
        let got = http::PathEscape(string("foo/bar baz?,"));
        if got == "foo%2Fbar%20baz%3F%2C" {
            fmt::Println!("[ 2] PathEscape segment         PASS");
        } else {
            fmt::Println!("[ 2] PathEscape segment         FAIL got={}", got);
            failed += 1;
        }
    }

    // 3. Unreserved chars (alphanum, -, _, ., ~) are never escaped.
    {
        let s = string("AaZz09-_.~");
        let q = http::QueryEscape(s.clone());
        let p = http::PathEscape(s.clone());
        if q == "AaZz09-_.~" && p == "AaZz09-_.~" {
            fmt::Println!("[ 3] unreserved untouched      PASS");
        } else {
            fmt::Println!("[ 3] unreserved untouched      FAIL q={} p={}", q, p);
            failed += 1;
        }
    }

    // 4. QueryEscape → QueryUnescape round-trip.
    {
        let s = string("a b+c%d&e=f");
        let q = http::QueryEscape(s.clone());
        let (back, err) = http::QueryUnescape(q);
        if err.IsNil() && back == s {
            fmt::Println!("[ 4] Query round-trip           PASS");
        } else {
            fmt::Println!("[ 4] Query round-trip           FAIL");
            failed += 1;
        }
    }

    // 5. PathEscape → PathUnescape round-trip on a path-shaped value.
    {
        let s = string("foo/bar baz?,#hash");
        let p = http::PathEscape(s.clone());
        let (back, err) = http::PathUnescape(p);
        if err.IsNil() && back == s {
            fmt::Println!("[ 5] Path round-trip            PASS");
        } else {
            fmt::Println!("[ 5] Path round-trip            FAIL");
            failed += 1;
        }
    }

    // 6. Empty input → empty output, no allocation surprises.
    {
        if http::QueryEscape(string("")).Len() == 0
            && http::PathEscape(string("")).Len() == 0
        {
            fmt::Println!("[ 6] empty                      PASS");
        } else {
            fmt::Println!("[ 6] empty                      FAIL");
            failed += 1;
        }
    }

    // 7. PathEscape allows ':', '@', '$', '&', '+', '=' (sub-delims).
    {
        let got = http::PathEscape(string(":@$&+="));
        if got == ":@$&+=" {
            fmt::Println!("[ 7] PathEscape sub-delims      PASS");
        } else {
            fmt::Println!("[ 7] PathEscape sub-delims      FAIL got={}", got);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 7", failed);
        syscall::Exit(1);
    }
}
