// http_helpers_smoke — exercise the small private helpers ported
// from net/http/http.go (hasPort, removeEmptyPort, isToken,
// stringContainsCTLByte, hexEscapeNonASCII).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http::helpers::{
    hasPort, hexEscapeNonASCII, isToken, removeEmptyPort, stringContainsCTLByte,
};
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. hasPort: "host:port" → true.
    {
        if hasPort(&string("example.com:80")) {
            Println!("[ 1] hasPort host:port         PASS");
        } else {
            Println!("[ 1] hasPort host:port         FAIL");
            failed += 1;
        }
    }

    // 2. hasPort: bare host → false.
    {
        if !hasPort(&string("example.com")) {
            Println!("[ 2] hasPort bare host         PASS");
        } else {
            Println!("[ 2] hasPort bare host         FAIL");
            failed += 1;
        }
    }

    // 3. hasPort: "[::1]:8080" → true (port follows ']').
    {
        if hasPort(&string("[::1]:8080")) {
            Println!("[ 3] hasPort ipv6 with port    PASS");
        } else {
            Println!("[ 3] hasPort ipv6 with port    FAIL");
            failed += 1;
        }
    }

    // 4. hasPort: "[::1]" → false (last ':' inside brackets).
    {
        if !hasPort(&string("[::1]")) {
            Println!("[ 4] hasPort ipv6 no port      PASS");
        } else {
            Println!("[ 4] hasPort ipv6 no port      FAIL");
            failed += 1;
        }
    }

    // 5. removeEmptyPort: "host:" → "host".
    {
        let got = removeEmptyPort(string("example.com:"));
        if got == "example.com" {
            Println!("[ 5] removeEmptyPort strip     PASS");
        } else {
            Println!("[ 5] removeEmptyPort strip     FAIL got={}", got);
            failed += 1;
        }
    }

    // 6. removeEmptyPort: "host:80" preserved.
    {
        let got = removeEmptyPort(string("example.com:80"));
        if got == "example.com:80" {
            Println!("[ 6] removeEmptyPort keep      PASS");
        } else {
            Println!("[ 6] removeEmptyPort keep      FAIL got={}", got);
            failed += 1;
        }
    }

    // 7. removeEmptyPort: bare "host" preserved (no port at all).
    {
        let got = removeEmptyPort(string("example.com"));
        if got == "example.com" {
            Println!("[ 7] removeEmptyPort bare      PASS");
        } else {
            Println!("[ 7] removeEmptyPort bare      FAIL got={}", got);
            failed += 1;
        }
    }

    // 8. isToken: "Content-Type" → true.
    {
        if isToken(&string("Content-Type")) {
            Println!("[ 8] isToken header name       PASS");
        } else {
            Println!("[ 8] isToken header name       FAIL");
            failed += 1;
        }
    }

    // 9. isToken: empty → false.
    {
        if !isToken(&string("")) {
            Println!("[ 9] isToken empty             PASS");
        } else {
            Println!("[ 9] isToken empty             FAIL");
            failed += 1;
        }
    }

    // 10. isToken: contains space → false.
    {
        if !isToken(&string("Bad Header")) {
            Println!("[10] isToken with space        PASS");
        } else {
            Println!("[10] isToken with space        FAIL");
            failed += 1;
        }
    }

    // 11. isToken: contains '(' (separator) → false.
    {
        if !isToken(&string("Foo(Bar)")) {
            Println!("[11] isToken with separator    PASS");
        } else {
            Println!("[11] isToken with separator    FAIL");
            failed += 1;
        }
    }

    // 12. stringContainsCTLByte: clean ASCII → false.
    {
        if !stringContainsCTLByte(&string("hello world")) {
            Println!("[12] CTLByte clean             PASS");
        } else {
            Println!("[12] CTLByte clean             FAIL");
            failed += 1;
        }
    }

    // 13. stringContainsCTLByte: embedded \n → true.
    {
        if stringContainsCTLByte(&string("hello\nworld")) {
            Println!("[13] CTLByte with newline      PASS");
        } else {
            Println!("[13] CTLByte with newline      FAIL");
            failed += 1;
        }
    }

    // 14. stringContainsCTLByte: DEL byte (0x7f) → true.
    {
        let s = string::from_bytes(b"abc\x7fdef");
        if stringContainsCTLByte(&s) {
            Println!("[14] CTLByte with DEL          PASS");
        } else {
            Println!("[14] CTLByte with DEL          FAIL");
            failed += 1;
        }
    }

    // 15. hexEscapeNonASCII: pure ASCII pass-through.
    {
        let got = hexEscapeNonASCII(string("/foo/bar"));
        if got == "/foo/bar" {
            Println!("[15] hexEscape ascii           PASS");
        } else {
            Println!("[15] hexEscape ascii           FAIL got={}", got);
            failed += 1;
        }
    }

    // 16. hexEscapeNonASCII: 0xC3 0xA9 ("é" UTF-8) → "%c3%a9".
    {
        let s = string::from_bytes(b"r\xc3\xa9");
        let got = hexEscapeNonASCII(s);
        if got == "r%c3%a9" {
            Println!("[16] hexEscape utf-8 e-acute   PASS");
        } else {
            Println!("[16] hexEscape utf-8 e-acute   FAIL got={}", got);
            failed += 1;
        }
    }

    // 17. hexEscapeNonASCII: trailing non-ASCII handled.
    {
        let s = string::from_bytes(b"abc\xff");
        let got = hexEscapeNonASCII(s);
        if got == "abc%ff" {
            Println!("[17] hexEscape trailing        PASS");
        } else {
            Println!("[17] hexEscape trailing        FAIL got={}", got);
            failed += 1;
        }
    }

    // 18. hexEscapeNonASCII: only non-ASCII bytes.
    {
        let s = string::from_bytes(b"\x80\x81");
        let got = hexEscapeNonASCII(s);
        if got == "%80%81" {
            Println!("[18] hexEscape only non-ascii  PASS");
        } else {
            Println!("[18] hexEscape only non-ascii  FAIL got={}", got);
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 18/18");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 18", failed);
        syscall::Exit(1);
    }
}
