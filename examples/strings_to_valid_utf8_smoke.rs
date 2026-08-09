// strings_to_valid_utf8_smoke — exercise strings.ToValidUTF8
// (strings/strings.go:790).
//
// Test cases adapted from Go's strings_test.go ToValidUTF8 table.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::strings;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Pure ASCII unchanged.
    {
        let got = strings::ToValidUTF8(string("hello"), string("X"));
        if got == "hello" {
            fmt::Println!("[ 1] ASCII unchanged           PASS");
        } else {
            fmt::Println!("[ 1] ASCII unchanged           FAIL got=", got);
            failed += 1;
        }
    }

    // 2. Empty input -> empty.
    {
        let got = strings::ToValidUTF8(string(""), string("X"));
        if got == "" {
            fmt::Println!("[ 2] empty input               PASS");
        } else {
            fmt::Println!("[ 2] empty input               FAIL got=", got);
            failed += 1;
        }
    }

    // 3. Valid UTF-8 (multi-byte) unchanged: "héllo" (h-e_acute-l-l-o).
    {
        let got = strings::ToValidUTF8(string("h\u{00e9}llo"), string("X"));
        if got == "h\u{00e9}llo" {
            fmt::Println!("[ 3] valid multi-byte          PASS");
        } else {
            fmt::Println!("[ 3] valid multi-byte          FAIL got=", got);
            failed += 1;
        }
    }

    // 4. Single bare 0xFF byte -> replacement "?".
    {
        // build "ab\xFFcd" via raw bytes
        let raw: [u8; 5] = [b'a', b'b', 0xFF, b'c', b'd'];
        let s = string::from_bytes(&raw);
        let got = strings::ToValidUTF8(s, string("?"));
        if got == "ab?cd" {
            fmt::Println!("[ 4] single bad byte           PASS");
        } else {
            fmt::Println!("[ 4] single bad byte           FAIL got=", got);
            failed += 1;
        }
    }

    // 5. Run of invalid bytes collapsed to one replacement.
    {
        let raw: [u8; 6] = [b'a', 0xFF, 0xFE, 0xFD, b'c', b'd'];
        let s = string::from_bytes(&raw);
        let got = strings::ToValidUTF8(s, string("?"));
        if got == "a?cd" {
            fmt::Println!("[ 5] run of bad bytes          PASS");
        } else {
            fmt::Println!("[ 5] run of bad bytes          FAIL got=", got);
            failed += 1;
        }
    }

    // 6. Empty replacement drops invalid bytes.
    {
        let raw: [u8; 5] = [b'a', b'b', 0xFF, b'c', b'd'];
        let s = string::from_bytes(&raw);
        let got = strings::ToValidUTF8(s, string(""));
        if got == "abcd" {
            fmt::Println!("[ 6] empty replacement drops   PASS");
        } else {
            fmt::Println!("[ 6] empty replacement drops   FAIL got=", got);
            failed += 1;
        }
    }

    // 7. Multiple separate invalid runs each get their own replacement.
    {
        let raw: [u8; 7] = [b'a', 0xFF, b'b', 0xFE, b'c', 0xFD, b'd'];
        let s = string::from_bytes(&raw);
        let got = strings::ToValidUTF8(s, string("?"));
        if got == "a?b?c?d" {
            fmt::Println!("[ 7] multiple invalid runs     PASS");
        } else {
            fmt::Println!("[ 7] multiple invalid runs     FAIL got=", got);
            failed += 1;
        }
    }

    // 8. Multi-byte replacement string.
    {
        let raw: [u8; 3] = [b'a', 0xFF, b'b'];
        let s = string::from_bytes(&raw);
        let got = strings::ToValidUTF8(s, string("REPL"));
        if got == "aREPLb" {
            fmt::Println!("[ 8] multi-byte replacement    PASS");
        } else {
            fmt::Println!("[ 8] multi-byte replacement    FAIL got=", got);
            failed += 1;
        }
    }

    // 9. Trailing invalid bytes.
    {
        let raw: [u8; 4] = [b'h', b'i', 0xFF, 0xFE];
        let s = string::from_bytes(&raw);
        let got = strings::ToValidUTF8(s, string("?"));
        if got == "hi?" {
            fmt::Println!("[ 9] trailing invalid          PASS");
        } else {
            fmt::Println!("[ 9] trailing invalid          FAIL got=", got);
            failed += 1;
        }
    }

    // 10. Leading invalid bytes.
    {
        let raw: [u8; 4] = [0xFF, 0xFE, b'a', b'b'];
        let s = string::from_bytes(&raw);
        let got = strings::ToValidUTF8(s, string("?"));
        if got == "?ab" {
            fmt::Println!("[10] leading invalid           PASS");
        } else {
            fmt::Println!("[10] leading invalid           FAIL got=", got);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
