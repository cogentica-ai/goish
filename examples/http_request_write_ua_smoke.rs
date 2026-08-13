// http_request_write_ua_smoke — Request.Write's User-Agent handling
// (net/http/request.go:689-697).
//
// Expected bytes are Go 1.25.5 output via scripts/goref.sh net/http.
//
// Go's logic is:
//
//     userAgent := defaultUserAgent
//     if r.Header.has("User-Agent") { userAgent = r.Header.Get(...) }
//     if userAgent != "" { …write, sanitized… }
//
// The test is `has`, NOT `Get(...) == ""`. Setting User-Agent to the
// empty string explicitly SUPPRESSES the header entirely; only an
// ABSENT one gets the default. goish used to test Get's length, so an
// explicit blank produced the default anyway and the one documented
// way to send no User-Agent did not work.
//
// goish also sent "goish/0.1" where Go sends "Go-http-client/1.1",
// with defaultUserAgent ported but unused.
//
// The value is sanitized before writing — newlines to spaces, then
// trimmed — so a caller-supplied User-Agent cannot inject a header.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::net::http;
use goish::{fmt, string, syscall};

fn write_of(r: &http::Request) -> string {
    let mut b = bytes::Buffer::new();
    let _ = r.Write(&mut b);
    return string::from_bytes(&b.Bytes());
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Absent User-Agent gets Go's default.
    {
        let (r, _) = http::NewRequest(string("GET"), string("http://example.com/p?q=1"), goish::nil);
        let got = write_of(&r);
        if got == "GET /p?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go-http-client/1.1\r\n\r\n" {
            fmt::Println!("[1] absent UA -> Go-http-client/1.1  PASS");
        } else {
            fmt::Println!("[1] absent UA  FAIL:\n", got);
            failed += 1;
        }
    }

    // 2. An EXPLICIT empty User-Agent suppresses the header. This is
    //    the case goish got wrong: it wrote the default instead.
    {
        let (mut r, _) = http::NewRequest(string("GET"), string("http://example.com/"), goish::nil);
        r.Header.Set(string("User-Agent"), string(""));
        let got = write_of(&r);
        if got == "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" {
            fmt::Println!("[2] explicit empty UA suppresses the header  PASS");
        } else {
            fmt::Println!("[2] explicit empty UA  FAIL:\n", got);
            failed += 1;
        }
    }

    // 3. A set User-Agent overrides the default.
    {
        let (mut r, _) = http::NewRequest(string("GET"), string("http://example.com/"), goish::nil);
        r.Header.Set(string("User-Agent"), string("mine/2"));
        let got = write_of(&r);
        if goish::strings::Contains(got.clone(), string("User-Agent: mine/2\r\n")) {
            fmt::Println!("[3] set UA overrides the default  PASS");
        } else {
            fmt::Println!("[3] set UA  FAIL:\n", got);
            failed += 1;
        }
    }

    // 4. A User-Agent carrying CRLF is sanitized, not injected. Without
    //    the newline-to-space pass this would open a second header.
    //    Note the value ends up with TWO spaces — "\r" and "\n" each
    //    become one — which is Go's exact output, verified rather than
    //    assumed: my first assertion here guessed one space and was
    //    wrong about Go, not about the code.
    {
        let (mut r, _) = http::NewRequest(string("GET"), string("http://example.com/"), goish::nil);
        r.Header.Set(string("User-Agent"), string("evil\r\nX-Injected: yes"));
        let got = write_of(&r);
        // The check is exact equality, not "does not contain
        // X-Injected" — the SANITIZED User-Agent line legitimately
        // ends with that text. What matters is that it is folded into
        // the UA value and never begins a line of its own.
        if got == "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: evil  X-Injected: yes\r\n\r\n"
            && !goish::strings::Contains(got.clone(), string("\r\nX-Injected:"))
        {
            fmt::Println!("[4] CRLF in UA is folded, not injected  PASS");
        } else {
            fmt::Println!("[4] UA injection  FAIL:\n", got);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 4");
        syscall::Exit(1);
    }
}
