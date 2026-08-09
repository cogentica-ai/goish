// http_helpers_smoke — exercise the small private helpers ported
// from net/http/http.go (hasPort, removeEmptyPort, isToken,
// stringContainsCTLByte, hexEscapeNonASCII).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http::helpers::{
    hasPort, hexEscapeNonASCII, isToken, removeEmptyPort, stringContainsCTLByte,
};
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. hasPort: "host:port" → true.
    {
        if hasPort(&string("example.com:80")) {
            fmt::Println!("[ 1] hasPort host:port         PASS");
        } else {
            fmt::Println!("[ 1] hasPort host:port         FAIL");
            failed += 1;
        }
    }

    // 2. hasPort: bare host → false.
    {
        if !hasPort(&string("example.com")) {
            fmt::Println!("[ 2] hasPort bare host         PASS");
        } else {
            fmt::Println!("[ 2] hasPort bare host         FAIL");
            failed += 1;
        }
    }

    // 3. hasPort: "[::1]:8080" → true (port follows ']').
    {
        if hasPort(&string("[::1]:8080")) {
            fmt::Println!("[ 3] hasPort ipv6 with port    PASS");
        } else {
            fmt::Println!("[ 3] hasPort ipv6 with port    FAIL");
            failed += 1;
        }
    }

    // 4. hasPort: "[::1]" → false (last ':' inside brackets).
    {
        if !hasPort(&string("[::1]")) {
            fmt::Println!("[ 4] hasPort ipv6 no port      PASS");
        } else {
            fmt::Println!("[ 4] hasPort ipv6 no port      FAIL");
            failed += 1;
        }
    }

    // 5. removeEmptyPort: "host:" → "host".
    {
        let got = removeEmptyPort(string("example.com:"));
        if got == "example.com" {
            fmt::Println!("[ 5] removeEmptyPort strip     PASS");
        } else {
            fmt::Println!("[ 5] removeEmptyPort strip     FAIL got={}", got);
            failed += 1;
        }
    }

    // 6. removeEmptyPort: "host:80" preserved.
    {
        let got = removeEmptyPort(string("example.com:80"));
        if got == "example.com:80" {
            fmt::Println!("[ 6] removeEmptyPort keep      PASS");
        } else {
            fmt::Println!("[ 6] removeEmptyPort keep      FAIL got={}", got);
            failed += 1;
        }
    }

    // 7. removeEmptyPort: bare "host" preserved (no port at all).
    {
        let got = removeEmptyPort(string("example.com"));
        if got == "example.com" {
            fmt::Println!("[ 7] removeEmptyPort bare      PASS");
        } else {
            fmt::Println!("[ 7] removeEmptyPort bare      FAIL got={}", got);
            failed += 1;
        }
    }

    // 8. isToken: "Content-Type" → true.
    {
        if isToken(&string("Content-Type")) {
            fmt::Println!("[ 8] isToken header name       PASS");
        } else {
            fmt::Println!("[ 8] isToken header name       FAIL");
            failed += 1;
        }
    }

    // 9. isToken: empty → false.
    {
        if !isToken(&string("")) {
            fmt::Println!("[ 9] isToken empty             PASS");
        } else {
            fmt::Println!("[ 9] isToken empty             FAIL");
            failed += 1;
        }
    }

    // 10. isToken: contains space → false.
    {
        if !isToken(&string("Bad Header")) {
            fmt::Println!("[10] isToken with space        PASS");
        } else {
            fmt::Println!("[10] isToken with space        FAIL");
            failed += 1;
        }
    }

    // 11. isToken: contains '(' (separator) → false.
    {
        if !isToken(&string("Foo(Bar)")) {
            fmt::Println!("[11] isToken with separator    PASS");
        } else {
            fmt::Println!("[11] isToken with separator    FAIL");
            failed += 1;
        }
    }

    // 12. stringContainsCTLByte: clean ASCII → false.
    {
        if !stringContainsCTLByte(&string("hello world")) {
            fmt::Println!("[12] CTLByte clean             PASS");
        } else {
            fmt::Println!("[12] CTLByte clean             FAIL");
            failed += 1;
        }
    }

    // 13. stringContainsCTLByte: embedded \n → true.
    {
        if stringContainsCTLByte(&string("hello\nworld")) {
            fmt::Println!("[13] CTLByte with newline      PASS");
        } else {
            fmt::Println!("[13] CTLByte with newline      FAIL");
            failed += 1;
        }
    }

    // 14. stringContainsCTLByte: DEL byte (0x7f) → true.
    {
        let s = string::from_bytes(b"abc\x7fdef");
        if stringContainsCTLByte(&s) {
            fmt::Println!("[14] CTLByte with DEL          PASS");
        } else {
            fmt::Println!("[14] CTLByte with DEL          FAIL");
            failed += 1;
        }
    }

    // 15. hexEscapeNonASCII: pure ASCII pass-through.
    {
        let got = hexEscapeNonASCII(string("/foo/bar"));
        if got == "/foo/bar" {
            fmt::Println!("[15] hexEscape ascii           PASS");
        } else {
            fmt::Println!("[15] hexEscape ascii           FAIL got={}", got);
            failed += 1;
        }
    }

    // 16. hexEscapeNonASCII: 0xC3 0xA9 ("é" UTF-8) → "%c3%a9".
    {
        let s = string::from_bytes(b"r\xc3\xa9");
        let got = hexEscapeNonASCII(s);
        if got == "r%c3%a9" {
            fmt::Println!("[16] hexEscape utf-8 e-acute   PASS");
        } else {
            fmt::Println!("[16] hexEscape utf-8 e-acute   FAIL got={}", got);
            failed += 1;
        }
    }

    // 17. hexEscapeNonASCII: trailing non-ASCII handled.
    {
        let s = string::from_bytes(b"abc\xff");
        let got = hexEscapeNonASCII(s);
        if got == "abc%ff" {
            fmt::Println!("[17] hexEscape trailing        PASS");
        } else {
            fmt::Println!("[17] hexEscape trailing        FAIL got={}", got);
            failed += 1;
        }
    }

    // 18. hexEscapeNonASCII: only non-ASCII bytes.
    {
        let s = string::from_bytes(b"\x80\x81");
        let got = hexEscapeNonASCII(s);
        if got == "%80%81" {
            fmt::Println!("[18] hexEscape only non-ascii  PASS");
        } else {
            fmt::Println!("[18] hexEscape only non-ascii  FAIL got={}", got);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 18/18");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 18", failed);
        syscall::Exit(1);
    }
}
