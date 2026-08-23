// http_fs_path_smoke — net/http fs.go's path-safety helpers:
// containsDotDot (fs.go:861) and toHTTPError (fs.go:769).
//
// Every expected value is Go 1.25.5 output, captured by running the
// two functions inside a writable GOROOT (scripts/goref.sh net/http),
// not transcribed from the source.
//
// The cases that matter are the near-misses. containsDotDot splits on
// BOTH '/' and '\\' (isSlashRune) and compares whole path elements, so
// "a/..b", "..a/b", "foo..bar", "...." and "a/....../b" are all
// harmless, while "a\\..\\b" and "..\\" are traversal — a checker that
// merely looked for the substring ".." would reject the first five and
// one that split on '/' alone would admit the last two.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::io::fs as iofs;
use goish::net::http::fs::{containsDotDot, errInvalidUnsafePath, errSeeker, toHTTPError};
use goish::net::http::status::{StatusForbidden, StatusInternalServerError, StatusNotFound};
use goish::{errors, fmt, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. containsDotDot, pinned to Go 1.25.5.
    let cases: &[(&str, bool)] = &[
        ("", false),
        ("..", true),
        ("/..", true),
        ("../a", true),
        ("a/../b", true),
        ("a/..b", false),
        ("..a/b", false),
        ("a/b/..", true),
        ("a\\..\\b", true),
        ("a/./b", false),
        ("....", false),
        ("a/....../b", false),
        ("/a/../../b", true),
        ("..\\", true),
        ("foo..bar", false),
        ("/..%2f", false),
        ("a/../", true),
    ];
    let mut bad = 0;
    for (v, want) in cases {
        let got = containsDotDot(string(*v));
        if got != *want {
            fmt::Println!("     containsDotDot FAIL ", *v, " got=", got);
            bad += 1;
        }
    }
    if bad == 0 {
        fmt::Println!("[1] containsDotDot, 17 cases vs Go  PASS");
    } else {
        failed += 1;
    }

    // 2. toHTTPError maps the three sentinels and defaults to 500.
    {
        let (m1, s1) = toHTTPError(iofs::ErrNotExist.into());
        let (m2, s2) = toHTTPError(iofs::ErrPermission.into());
        let (m3, s3) = toHTTPError(errInvalidUnsafePath.into());
        let (m4, s4) = toHTTPError(errors::New(string("something else")));
        if m1 == "404 page not found"
            && s1 == StatusNotFound
            && m2 == "403 Forbidden"
            && s2 == StatusForbidden
            && m3 == "404 page not found"
            && s3 == StatusNotFound
            && m4 == "500 Internal Server Error"
            && s4 == StatusInternalServerError
        {
            fmt::Println!("[2] toHTTPError maps all four cases  PASS");
        } else {
            fmt::Println!("[2] toHTTPError  FAIL ", m1, "/", s1, " ", m4, "/", s4);
            failed += 1;
        }
    }

    // 3. An unsafe path must NOT leak as a 500: errInvalidUnsafePath is
    //    answered 404 so a probe cannot tell "rejected" from "absent".
    {
        let (msg, code) = toHTTPError(errInvalidUnsafePath.into());
        let (nmsg, ncode) = toHTTPError(iofs::ErrNotExist.into());
        if msg == nmsg && code == ncode {
            fmt::Println!("[3] unsafe path is indistinguishable from absent  PASS");
        } else {
            fmt::Println!("[3] unsafe path leaks  FAIL");
            failed += 1;
        }
    }

    // 4. Sentinel texts match Go.
    {
        let e1: errors::error = errInvalidUnsafePath.into();
        let e2: errors::error = errSeeker.into();
        if e1.Error() == "http: invalid or unsafe file path" && e2.Error() == "seeker can't seek" {
            fmt::Println!("[4] sentinel texts match Go  PASS");
        } else {
            fmt::Println!("[4] sentinel texts  FAIL");
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
