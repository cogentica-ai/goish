// http_range_smoke — exercise http::ParseRange.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. "bytes=0-99" on size 1000 → start=0 length=100
    {
        let (rs, err) = http::ParseRange(string("bytes=0-99"), 1000);
        if err.IsNil() && rs.Len() == 1 && rs[0].Start == 0 && rs[0].Length == 100 {
            Println!("[ 1] simple range              PASS");
        } else {
            Println!("[ 1] simple range              FAIL");
            failed += 1;
        }
    }

    // 2. "bytes=200-" → start=200 length=size-200
    {
        let (rs, err) = http::ParseRange(string("bytes=200-"), 1000);
        if err.IsNil() && rs.Len() == 1 && rs[0].Start == 200 && rs[0].Length == 800 {
            Println!("[ 2] open-ended range          PASS");
        } else {
            Println!("[ 2] open-ended range          FAIL");
            failed += 1;
        }
    }

    // 3. "bytes=-50" → suffix: last 50 bytes
    {
        let (rs, err) = http::ParseRange(string("bytes=-50"), 1000);
        if err.IsNil() && rs.Len() == 1 && rs[0].Start == 950 && rs[0].Length == 50 {
            Println!("[ 3] suffix range              PASS");
        } else {
            Println!("[ 3] suffix range              FAIL");
            failed += 1;
        }
    }

    // 4. "bytes=0-99,200-299" → two ranges
    {
        let (rs, err) = http::ParseRange(string("bytes=0-99,200-299"), 1000);
        if err.IsNil() && rs.Len() == 2 && rs[0].Length == 100 && rs[1].Start == 200 {
            Println!("[ 4] multi-range               PASS");
        } else {
            Println!("[ 4] multi-range               FAIL n={}", rs.Len());
            failed += 1;
        }
    }

    // 5. Empty header → empty list, no error.
    {
        let (rs, err) = http::ParseRange(string(""), 1000);
        if err.IsNil() && rs.Len() == 0 {
            Println!("[ 5] empty → no ranges         PASS");
        } else {
            Println!("[ 5] empty → no ranges         FAIL");
            failed += 1;
        }
    }

    // 6. Malformed → error.
    {
        let (_rs, err) = http::ParseRange(string("not a range"), 1000);
        if !err.IsNil() {
            Println!("[ 6] malformed → error         PASS");
        } else {
            Println!("[ 6] malformed → error         FAIL");
            failed += 1;
        }
    }

    // 7. ContentRange formatting.
    {
        let r = http::HttpRange { Start: 0, Length: 100 };
        let s = r.ContentRange(1000);
        if s == "bytes 0-99/1000" {
            Println!("[ 7] ContentRange format       PASS");
        } else {
            Println!("[ 7] ContentRange format       FAIL got={}", s);
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 7", failed);
        syscall::Exit(1);
    }
}
