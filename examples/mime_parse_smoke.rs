// mime_parse_smoke — exercise mime::ParseMediaType + FormatMediaType
// (slim line-by-line ports of mediatype.go:134 / :21).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::mime;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Bare type/subtype with no params.
    {
        let (mt, params, err) = mime::ParseMediaType(string("text/plain"));
        if err.IsNil() && mt == "text/plain" && params.Len() == 0 {
            fmt::Println!("[ 1] bare type                  PASS");
        } else {
            fmt::Println!("[ 1] bare type                  FAIL mt={}", mt);
            failed += 1;
        }
    }

    // 2. Type with single charset param.
    {
        let (mt, params, err) = mime::ParseMediaType(string("text/html; charset=utf-8"));
        let (cs, _) = params.Get(string("charset"));
        if err.IsNil() && mt == "text/html" && cs == "utf-8" && params.Len() == 1 {
            fmt::Println!("[ 2] type + charset             PASS");
        } else {
            fmt::Println!("[ 2] type + charset             FAIL mt={} cs={}", mt, cs);
            failed += 1;
        }
    }

    // 3. Quoted parameter value.
    {
        let (mt, params, err) = mime::ParseMediaType(string("application/x; foo=\"bar baz\""));
        let (foo, _) = params.Get(string("foo"));
        if err.IsNil() && mt == "application/x" && foo == "bar baz" {
            fmt::Println!("[ 3] quoted value               PASS");
        } else {
            fmt::Println!("[ 3] quoted value               FAIL foo={}", foo);
            failed += 1;
        }
    }

    // 4. Type is lowercased; param key lowercased; value preserved.
    {
        let (mt, params, err) = mime::ParseMediaType(string("Text/HTML; CharSet=UTF-8"));
        let (cs, _) = params.Get(string("charset"));
        if err.IsNil() && mt == "text/html" && cs == "UTF-8" {
            fmt::Println!("[ 4] case folding              PASS");
        } else {
            fmt::Println!("[ 4] case folding              FAIL mt={} cs={}", mt, cs);
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
            fmt::Println!("[ 5] multiple params           PASS");
        } else {
            fmt::Println!("[ 5] multiple params           FAIL");
            failed += 1;
        }
    }

    // 6. Empty media type → error.
    {
        let (_mt, _params, err) = mime::ParseMediaType(string(""));
        if !err.IsNil() {
            fmt::Println!("[ 6] empty input err           PASS");
        } else {
            fmt::Println!("[ 6] empty input err           FAIL");
            failed += 1;
        }
    }

    // 7. No subtype → error.
    {
        let (_mt, _params, err) = mime::ParseMediaType(string("text/"));
        if !err.IsNil() {
            fmt::Println!("[ 7] no subtype err            PASS");
        } else {
            fmt::Println!("[ 7] no subtype err            FAIL");
            failed += 1;
        }
    }

    // 8. Backslash-escape inside quoted value.
    {
        let (_mt, params, err) = mime::ParseMediaType(string("text/x; q=\"a\\\"b\""));
        let (q, _) = params.Get(string("q"));
        if err.IsNil() && q == "a\"b" {
            fmt::Println!("[ 8] backslash-escape          PASS");
        } else {
            fmt::Println!("[ 8] backslash-escape          FAIL q={}", q);
            failed += 1;
        }
    }

    // 9. FormatMediaType: roundtrip a simple type/subtype + param.
    {
        let mut params: goish::gomap::map<string, string> = goish::gomap::map::new();
        params.Set(string("charset"), string("utf-8"));
        let s = mime::FormatMediaType(string("text/plain"), params);
        if s == "text/plain; charset=utf-8" {
            fmt::Println!("[ 9] Format simple             PASS");
        } else {
            fmt::Println!("[ 9] Format simple             FAIL got={}", s);
            failed += 1;
        }
    }

    // 10. FormatMediaType: value with space → quoted.
    {
        let mut params: goish::gomap::map<string, string> = goish::gomap::map::new();
        params.Set(string("filename"), string("hello world.txt"));
        let s = mime::FormatMediaType(string("attachment"), params);
        if s == "attachment; filename=\"hello world.txt\"" {
            fmt::Println!("[10] Format quoted value       PASS");
        } else {
            fmt::Println!("[10] Format quoted value       FAIL got={}", s);
            failed += 1;
        }
    }

    // 11. FormatMediaType: invalid token in type → "".
    {
        let params: goish::gomap::map<string, string> = goish::gomap::map::new();
        let s = mime::FormatMediaType(string("bad type"), params);
        if s.Len() == 0 {
            fmt::Println!("[11] Format invalid type       PASS");
        } else {
            fmt::Println!("[11] Format invalid type       FAIL");
            failed += 1;
        }
    }

    // 12. FormatMediaType → ParseMediaType round-trip.
    {
        let mut params: goish::gomap::map<string, string> = goish::gomap::map::new();
        params.Set(string("boundary"), string("X-Boundary-1234"));
        params.Set(string("charset"), string("utf-8"));
        let s = mime::FormatMediaType(string("multipart/form-data"), params);
        let (mt, p, err) = mime::ParseMediaType(s);
        let (b, _) = p.Get(string("boundary"));
        let (cs, _) = p.Get(string("charset"));
        if err.IsNil() && mt == "multipart/form-data" && b == "X-Boundary-1234" && cs == "utf-8" {
            fmt::Println!("[12] Format → Parse round-tr   PASS");
        } else {
            fmt::Println!("[12] Format → Parse round-tr   FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 12", failed);
        syscall::Exit(1);
    }
}
