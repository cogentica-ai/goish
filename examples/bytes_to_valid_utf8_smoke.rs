// bytes_to_valid_utf8_smoke — exercise bytes.ToValidUTF8
// (bytes/bytes.go:779). Mirrors strings_to_valid_utf8_smoke.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::convert::bytes as as_bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::types::byte;
use goish::{string, syscall};

fn check_eq(a: slice<byte>, want: &[u8]) -> bool {
    if a.Len() as usize != want.len() {
        return false;
    }
    let mut i: i64 = 0;
    while (i as usize) < want.len() {
        if a[i] != want[i as usize] {
            return false;
        }
        i += 1;
    }
    true
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ASCII unchanged.
    {
        let got = bytes::ToValidUTF8(as_bytes(string("hello")), as_bytes(string("X")));
        if check_eq(got, b"hello") {
            fmt::Println!("[ 1] ASCII unchanged           PASS");
        } else {
            fmt::Println!("[ 1] ASCII unchanged           FAIL");
            failed += 1;
        }
    }

    // 2. Empty input.
    {
        let got = bytes::ToValidUTF8(as_bytes(string("")), as_bytes(string("X")));
        if got.Len() == 0 {
            fmt::Println!("[ 2] empty input               PASS");
        } else {
            fmt::Println!("[ 2] empty input               FAIL");
            failed += 1;
        }
    }

    // 3. Valid multi-byte unchanged: "é" = 0xc3 0xa9.
    {
        let s = string::from_bytes(&[b'h', 0xc3, 0xa9, b'l', b'l', b'o']);
        let got = bytes::ToValidUTF8(as_bytes(s), as_bytes(string("?")));
        if check_eq(got, &[b'h', 0xc3, 0xa9, b'l', b'l', b'o']) {
            fmt::Println!("[ 3] valid multi-byte          PASS");
        } else {
            fmt::Println!("[ 3] valid multi-byte          FAIL");
            failed += 1;
        }
    }

    // 4. Single bare 0xFF -> "?".
    {
        let s = string::from_bytes(&[b'a', b'b', 0xFF, b'c', b'd']);
        let got = bytes::ToValidUTF8(as_bytes(s), as_bytes(string("?")));
        if check_eq(got, b"ab?cd") {
            fmt::Println!("[ 4] single bad byte           PASS");
        } else {
            fmt::Println!("[ 4] single bad byte           FAIL");
            failed += 1;
        }
    }

    // 5. Run of invalid bytes -> one replacement.
    {
        let s = string::from_bytes(&[b'a', 0xFF, 0xFE, 0xFD, b'c', b'd']);
        let got = bytes::ToValidUTF8(as_bytes(s), as_bytes(string("?")));
        if check_eq(got, b"a?cd") {
            fmt::Println!("[ 5] run of bad bytes          PASS");
        } else {
            fmt::Println!("[ 5] run of bad bytes          FAIL");
            failed += 1;
        }
    }

    // 6. Empty replacement drops invalid bytes.
    {
        let s = string::from_bytes(&[b'a', b'b', 0xFF, b'c', b'd']);
        let got = bytes::ToValidUTF8(as_bytes(s), as_bytes(string("")));
        if check_eq(got, b"abcd") {
            fmt::Println!("[ 6] empty replacement drops   PASS");
        } else {
            fmt::Println!("[ 6] empty replacement drops   FAIL");
            failed += 1;
        }
    }

    // 7. Multi-byte replacement.
    {
        let s = string::from_bytes(&[b'a', 0xFF, b'b']);
        let got = bytes::ToValidUTF8(as_bytes(s), as_bytes(string("REPL")));
        if check_eq(got, b"aREPLb") {
            fmt::Println!("[ 7] multi-byte replacement    PASS");
        } else {
            fmt::Println!("[ 7] multi-byte replacement    FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
