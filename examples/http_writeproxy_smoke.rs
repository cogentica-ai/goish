// http_writeproxy_smoke — exercise Request.Write vs Request.WriteProxy.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::bytes;
use goish::context;
use goish::convert;
use goish::net::http;
use goish::strings;
use goish::{byte, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    let ctx = context::Background();
    let (req, err) = http::NewRequestWithContext(
        ctx,
        string("GET"),
        string("http://example.com/path?q=1"),
        convert::bytes(""),
    );
    if !err.IsNil() {
        fmt::Println!("setup FAIL");
        syscall::Exit(1);
    }

    // 1. Write emits a relative Request-URI (origin form).
    {
        let mut buf = bytes::NewBuffer(goish::make!([]byte, 0));
        let werr = req.Write(&mut buf);
        let s = buf.String();
        let first_line_ok = strings::HasPrefix(s.clone(), string("GET /path?q=1 HTTP/1.1"));
        if werr.IsNil() && first_line_ok {
            fmt::Println!("[ 1] Write origin form         PASS");
        } else {
            fmt::Println!("[ 1] Write origin form         FAIL line0={}", s);
            failed += 1;
        }
    }

    // 2. WriteProxy emits an absolute Request-URI.
    {
        let mut buf = bytes::NewBuffer(goish::make!([]byte, 0));
        let werr = req.WriteProxy(&mut buf);
        let s = buf.String();
        let first_line_ok = strings::HasPrefix(
            s.clone(),
            string("GET http://example.com/path?q=1 HTTP/1.1"),
        );
        if werr.IsNil() && first_line_ok {
            fmt::Println!("[ 2] WriteProxy absolute URI   PASS");
        } else {
            fmt::Println!("[ 2] WriteProxy absolute URI   FAIL line0={}", s);
            failed += 1;
        }
    }

    // 3. WriteProxy still emits the Host header.
    {
        let mut buf = bytes::NewBuffer(goish::make!([]byte, 0));
        let _ = req.WriteProxy(&mut buf);
        let s = buf.String();
        if strings::Contains(s, string("\r\nHost: example.com\r\n")) {
            fmt::Println!("[ 3] WriteProxy Host header    PASS");
        } else {
            fmt::Println!("[ 3] WriteProxy Host header    FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 3", failed);
        syscall::Exit(1);
    }
}
