// strconv_quote_smoke — exercise strconv::Quote / Unquote (slim port).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::strconv;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Plain ASCII round-trip.
    {
        let q = strconv::Quote(string("hello"));
        if q == "\"hello\"" {
            fmt::Println!("[ 1] Quote plain               PASS");
        } else {
            fmt::Println!("[ 1] Quote plain               FAIL got={}", q);
            failed += 1;
        }
        let (uq, err) = strconv::Unquote(q);
        if err.IsNil() && uq == "hello" {
            fmt::Println!("[ 2] Unquote plain             PASS");
        } else {
            fmt::Println!("[ 2] Unquote plain             FAIL");
            failed += 1;
        }
    }

    // 3. Backslash + quote escapes.
    {
        let q = strconv::Quote(string("a\\b\"c"));
        if q == "\"a\\\\b\\\"c\"" {
            fmt::Println!("[ 3] Quote escapes             PASS");
        } else {
            fmt::Println!("[ 3] Quote escapes             FAIL got={}", q);
            failed += 1;
        }
        let (uq, _) = strconv::Unquote(q);
        if uq == "a\\b\"c" {
            fmt::Println!("[ 4] Unquote escapes           PASS");
        } else {
            fmt::Println!("[ 4] Unquote escapes           FAIL got={}", uq);
            failed += 1;
        }
    }

    // 5. Control chars: \n \r \t.
    {
        let q = strconv::Quote(string("a\nb\rc\td"));
        if q == "\"a\\nb\\rc\\td\"" {
            fmt::Println!("[ 5] Quote control            PASS");
        } else {
            fmt::Println!("[ 5] Quote control            FAIL got={}", q);
            failed += 1;
        }
        let (uq, _) = strconv::Unquote(q);
        if uq == "a\nb\rc\td" {
            fmt::Println!("[ 6] Unquote control          PASS");
        } else {
            fmt::Println!("[ 6] Unquote control          FAIL");
            failed += 1;
        }
    }

    // 7. Non-printable \xHH form.
    {
        let q = strconv::Quote(string("\x01\x7f"));
        if q == "\"\\x01\\x7f\"" {
            fmt::Println!("[ 7] Quote \\xHH                PASS");
        } else {
            fmt::Println!("[ 7] Quote \\xHH                FAIL got={}", q);
            failed += 1;
        }
        let (uq, _) = strconv::Unquote(q);
        if uq == "\x01\x7f" {
            fmt::Println!("[ 8] Unquote \\xHH              PASS");
        } else {
            fmt::Println!("[ 8] Unquote \\xHH              FAIL");
            failed += 1;
        }
    }

    // 9. Malformed input → error.
    {
        let (_uq, err) = strconv::Unquote(string("not quoted"));
        if !err.IsNil() {
            fmt::Println!("[ 9] Unquote bad → err         PASS");
        } else {
            fmt::Println!("[ 9] Unquote bad → err         FAIL");
            failed += 1;
        }
    }

    // 10. Invalid escape → error.
    {
        let (_uq, err) = strconv::Unquote(string("\"\\q\""));
        if !err.IsNil() {
            fmt::Println!("[10] Unquote bad esc → err     PASS");
        } else {
            fmt::Println!("[10] Unquote bad esc → err     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 10", failed);
        syscall::Exit(1);
    }
}
