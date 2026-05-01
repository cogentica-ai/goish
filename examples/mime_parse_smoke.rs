// mime_parse_smoke — exercise mime::ParseMediaType
// (slim line-by-line port of mediatype.go:134).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::mime;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Bare type/subtype with no params.
    {
        let (mt, params, err) = mime::ParseMediaType(string("text/plain"));
        if err.IsNil() && mt == "text/plain" && params.Len() == 0 {
            Println!("[ 1] bare type                  PASS");
        } else {
            Println!("[ 1] bare type                  FAIL mt={}", mt);
            failed += 1;
        }
    }

    // 2. Type with single charset param.
    {
        let (mt, params, err) =
            mime::ParseMediaType(string("text/html; charset=utf-8"));
        let (cs, _) = params.Get(string("charset"));
        if err.IsNil() && mt == "text/html" && cs == "utf-8" && params.Len() == 1 {
            Println!("[ 2] type + charset             PASS");
        } else {
            Println!("[ 2] type + charset             FAIL mt={} cs={}", mt, cs);
            failed += 1;
        }
    }

    // 3. Quoted parameter value.
    {
        let (mt, params, err) =
            mime::ParseMediaType(string("application/x; foo=\"bar baz\""));
        let (foo, _) = params.Get(string("foo"));
        if err.IsNil() && mt == "application/x" && foo == "bar baz" {
            Println!("[ 3] quoted value               PASS");
        } else {
            Println!("[ 3] quoted value               FAIL foo={}", foo);
            failed += 1;
        }
    }

    // 4. Type is lowercased; param key lowercased; value preserved.
    {
        let (mt, params, err) =
            mime::ParseMediaType(string("Text/HTML; CharSet=UTF-8"));
        let (cs, _) = params.Get(string("charset"));
        if err.IsNil() && mt == "text/html" && cs == "UTF-8" {
            Println!("[ 4] case folding              PASS");
        } else {
            Println!("[ 4] case folding              FAIL mt={} cs={}", mt, cs);
            failed += 1;
        }
    }

    // 5. Multiple params.
    {
        let (mt, params, err) =
            mime::ParseMediaType(string("multipart/form-data; boundary=abc; charset=utf-8"));
        let (b, _) = params.Get(string("boundary"));
        let (cs, _) = params.Get(string("charset"));
        if err.IsNil() && mt == "multipart/form-data" && b == "abc" && cs == "utf-8" {
            Println!("[ 5] multiple params           PASS");
        } else {
            Println!("[ 5] multiple params           FAIL");
            failed += 1;
        }
    }

    // 6. Empty media type → error.
    {
        let (_mt, _params, err) = mime::ParseMediaType(string(""));
        if !err.IsNil() {
            Println!("[ 6] empty input err           PASS");
        } else {
            Println!("[ 6] empty input err           FAIL");
            failed += 1;
        }
    }

    // 7. No subtype → error.
    {
        let (_mt, _params, err) = mime::ParseMediaType(string("text/"));
        if !err.IsNil() {
            Println!("[ 7] no subtype err            PASS");
        } else {
            Println!("[ 7] no subtype err            FAIL");
            failed += 1;
        }
    }

    // 8. Backslash-escape inside quoted value.
    {
        let (_mt, params, err) =
            mime::ParseMediaType(string("text/x; q=\"a\\\"b\""));
        let (q, _) = params.Get(string("q"));
        if err.IsNil() && q == "a\"b" {
            Println!("[ 8] backslash-escape          PASS");
        } else {
            Println!("[ 8] backslash-escape          FAIL q={}", q);
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 8", failed);
        syscall::Exit(1);
    }
}
