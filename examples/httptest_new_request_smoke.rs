// httptest_new_request_smoke — exercise httptest.NewRequest +
// httptest.NewRequestWithContext (httptest.go:19 + 46).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::context;
use goish::convert::bytes;
use goish::goslice::slice;
use goish::net::http::httptest;
use goish::types::byte;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Empty method defaults to GET.
    {
        let r = httptest::NewRequest(string(""), string("/foo"), slice::<byte>::new());
        if r.Method == "GET" && r.URL.Path == "/foo" {
            Println!("[ 1] Empty method → GET        PASS");
        } else {
            Println!("[ 1] Empty method → GET        FAIL method=", r.Method);
            failed += 1;
        }
    }

    // 2. Explicit method preserved.
    {
        let r = httptest::NewRequest(string("POST"), string("/bar"), bytes("hi"));
        if r.Method == "POST" && r.URL.Path == "/bar" {
            Println!("[ 2] POST method               PASS");
        } else {
            Println!("[ 2] POST method               FAIL");
            failed += 1;
        }
    }

    // 3. Default Host = "example.com".
    {
        let r = httptest::NewRequest(string("GET"), string("/"), slice::<byte>::new());
        if r.Host == "example.com" {
            Println!("[ 3] Host default              PASS");
        } else {
            Println!("[ 3] Host default              FAIL host=", r.Host);
            failed += 1;
        }
    }

    // 4. Absolute URL → Host taken from URL.
    {
        let r = httptest::NewRequest(
            string("GET"),
            string("http://other.test/x"),
            slice::<byte>::new(),
        );
        if r.Host == "other.test" {
            Println!("[ 4] Host from absolute URL    PASS");
        } else {
            Println!("[ 4] Host from absolute URL    FAIL host=", r.Host);
            failed += 1;
        }
    }

    // 5. Proto = "HTTP/1.1".
    {
        let r = httptest::NewRequest(string("GET"), string("/"), slice::<byte>::new());
        if r.Proto == "HTTP/1.1" && r.ProtoMajor == 1 && r.ProtoMinor == 1 {
            Println!("[ 5] Proto HTTP/1.1            PASS");
        } else {
            Println!("[ 5] Proto HTTP/1.1            FAIL");
            failed += 1;
        }
    }

    // 6. RemoteAddr is RFC 5737 TEST-NET.
    {
        let r = httptest::NewRequest(string("GET"), string("/"), slice::<byte>::new());
        if r.RemoteAddr == "192.0.2.1:1234" {
            Println!("[ 6] RemoteAddr TEST-NET       PASS");
        } else {
            Println!("[ 6] RemoteAddr TEST-NET       FAIL got=", r.RemoteAddr);
            failed += 1;
        }
    }

    // 7. Body length carried in ContentLength.
    {
        let r = httptest::NewRequest(string("POST"), string("/upload"), bytes("hello"));
        if r.ContentLength == 5 {
            Println!("[ 7] ContentLength = body.Len  PASS");
        } else {
            Println!("[ 7] ContentLength = body.Len  FAIL got=", r.ContentLength);
            failed += 1;
        }
    }

    // 8. NewRequestWithContext also works.
    {
        let r = httptest::NewRequestWithContext(
            context::Background(),
            string("GET"),
            string("/ctx"),
            slice::<byte>::new(),
        );
        if r.Method == "GET" && r.URL.Path == "/ctx" {
            Println!("[ 8] WithContext               PASS");
        } else {
            Println!("[ 8] WithContext               FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
