// strconv_quote_smoke — exercise strconv::Quote / Unquote (slim port).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::strconv;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Plain ASCII round-trip.
    {
        let q = strconv::Quote(string("hello"));
        if q == "\"hello\"" {
            Println!("[ 1] Quote plain               PASS");
        } else {
            Println!("[ 1] Quote plain               FAIL got={}", q);
            failed += 1;
        }
        let (uq, err) = strconv::Unquote(q);
        if err.IsNil() && uq == "hello" {
            Println!("[ 2] Unquote plain             PASS");
        } else {
            Println!("[ 2] Unquote plain             FAIL");
            failed += 1;
        }
    }

    // 3. Backslash + quote escapes.
    {
        let q = strconv::Quote(string("a\\b\"c"));
        if q == "\"a\\\\b\\\"c\"" {
            Println!("[ 3] Quote escapes             PASS");
        } else {
            Println!("[ 3] Quote escapes             FAIL got={}", q);
            failed += 1;
        }
        let (uq, _) = strconv::Unquote(q);
        if uq == "a\\b\"c" {
            Println!("[ 4] Unquote escapes           PASS");
        } else {
            Println!("[ 4] Unquote escapes           FAIL got={}", uq);
            failed += 1;
        }
    }

    // 5. Control chars: \n \r \t.
    {
        let q = strconv::Quote(string("a\nb\rc\td"));
        if q == "\"a\\nb\\rc\\td\"" {
            Println!("[ 5] Quote control            PASS");
        } else {
            Println!("[ 5] Quote control            FAIL got={}", q);
            failed += 1;
        }
        let (uq, _) = strconv::Unquote(q);
        if uq == "a\nb\rc\td" {
            Println!("[ 6] Unquote control          PASS");
        } else {
            Println!("[ 6] Unquote control          FAIL");
            failed += 1;
        }
    }

    // 7. Non-printable \xHH form.
    {
        let q = strconv::Quote(string("\x01\x7f"));
        if q == "\"\\x01\\x7f\"" {
            Println!("[ 7] Quote \\xHH                PASS");
        } else {
            Println!("[ 7] Quote \\xHH                FAIL got={}", q);
            failed += 1;
        }
        let (uq, _) = strconv::Unquote(q);
        if uq == "\x01\x7f" {
            Println!("[ 8] Unquote \\xHH              PASS");
        } else {
            Println!("[ 8] Unquote \\xHH              FAIL");
            failed += 1;
        }
    }

    // 9. Malformed input → error.
    {
        let (_uq, err) = strconv::Unquote(string("not quoted"));
        if !err.IsNil() {
            Println!("[ 9] Unquote bad → err         PASS");
        } else {
            Println!("[ 9] Unquote bad → err         FAIL");
            failed += 1;
        }
    }

    // 10. Invalid escape → error.
    {
        let (_uq, err) = strconv::Unquote(string("\"\\q\""));
        if !err.IsNil() {
            Println!("[10] Unquote bad esc → err     PASS");
        } else {
            Println!("[10] Unquote bad esc → err     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 10", failed);
        syscall::Exit(1);
    }
}
