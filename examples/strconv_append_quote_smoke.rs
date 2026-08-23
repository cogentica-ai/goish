// strconv_append_quote_smoke — exercise strconv.AppendQuote
// (quote.go:131) and strconv.CanBackquote (quote.go:212).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes as as_bytes;
use goish::fmt;
use goish::strconv;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. AppendQuote on empty dst returns "\"hello\"".
    {
        let dst = as_bytes(string(""));
        let got = strconv::AppendQuote(dst, string("hello"));
        let s = string::from_bytes(&got.__into_vec());
        if s == "\"hello\"" {
            fmt::Println!("[ 1] AppendQuote empty dst      PASS");
        } else {
            fmt::Println!("[ 1] AppendQuote empty dst      FAIL got=", s);
            failed += 1;
        }
    }

    // 2. AppendQuote preserves dst prefix: "X" + "ab" → "X\"ab\"".
    {
        let dst = as_bytes(string("X"));
        let got = strconv::AppendQuote(dst, string("ab"));
        let s = string::from_bytes(&got.__into_vec());
        if s == "X\"ab\"" {
            fmt::Println!("[ 2] AppendQuote prefix preserved PASS");
        } else {
            fmt::Println!("[ 2] AppendQuote prefix preserved FAIL got=", s);
            failed += 1;
        }
    }

    // 3. AppendQuote escapes inner double-quote: "a\"b" → \"a\\\"b\".
    {
        let dst = as_bytes(string(""));
        let got = strconv::AppendQuote(dst, string("a\"b"));
        let s = string::from_bytes(&got.__into_vec());
        if s == "\"a\\\"b\"" {
            fmt::Println!("[ 3] AppendQuote escapes \"     PASS");
        } else {
            fmt::Println!("[ 3] AppendQuote escapes \"     FAIL got=", s);
            failed += 1;
        }
    }

    // 4. CanBackquote("hello") → true.
    {
        if strconv::CanBackquote(string("hello")) {
            fmt::Println!("[ 4] CanBackquote ascii         PASS");
        } else {
            fmt::Println!("[ 4] CanBackquote ascii         FAIL");
            failed += 1;
        }
    }

    // 5. CanBackquote with backquote → false.
    {
        if !strconv::CanBackquote(string("a`b")) {
            fmt::Println!("[ 5] CanBackquote rejects `    PASS");
        } else {
            fmt::Println!("[ 5] CanBackquote rejects `    FAIL");
            failed += 1;
        }
    }

    // 6. CanBackquote with newline → false.
    {
        if !strconv::CanBackquote(string("a\nb")) {
            fmt::Println!("[ 6] CanBackquote rejects \\n  PASS");
        } else {
            fmt::Println!("[ 6] CanBackquote rejects \\n  FAIL");
            failed += 1;
        }
    }

    // 7. CanBackquote with tab → true (tab is allowed).
    {
        if strconv::CanBackquote(string("a\tb")) {
            fmt::Println!("[ 7] CanBackquote allows \\t   PASS");
        } else {
            fmt::Println!("[ 7] CanBackquote allows \\t   FAIL");
            failed += 1;
        }
    }

    // 8. CanBackquote with DEL (0x7F) → false.
    {
        let raw: [u8; 3] = [b'a', 0x7F, b'b'];
        if !strconv::CanBackquote(string::from_bytes(&raw)) {
            fmt::Println!("[ 8] CanBackquote rejects DEL  PASS");
        } else {
            fmt::Println!("[ 8] CanBackquote rejects DEL  FAIL");
            failed += 1;
        }
    }

    // 9. CanBackquote on empty string → true.
    {
        if strconv::CanBackquote(string("")) {
            fmt::Println!("[ 9] CanBackquote empty        PASS");
        } else {
            fmt::Println!("[ 9] CanBackquote empty        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 9/9");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 9");
        syscall::Exit(1);
    }
}
