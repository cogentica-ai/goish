// http_request_write_smoke — exercise Request.Write +
// Request.CookiesNamed (line-by-line ports of request.go:561 / :434).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::convert::bytes;
use goish::io::Writer;
use goish::net::http;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Request.Write produces a valid HTTP/1.1 wire form.
    {
        let (mut req, _) = http::NewRequest(
            string("POST"),
            string("http://example.com:8080/api"),
            bytes("hello"),
        );
        req.Header.Set(string("Content-Type"), string("text/plain"));

        let mut buf =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(Vec::new()));
        let err = req.Write(&mut buf);
        if !err.IsNil() {
            Println!("[ 1] Write returned err        FAIL");
            failed += 1;
        } else {
            let on_wire = buf.Bytes();
            let mut v: Vec<u8> = Vec::with_capacity(on_wire.Len() as usize);
            for i in 0..on_wire.Len() {
                v.push(on_wire[i]);
            }
            let s = goish::string::from_bytes(&v);
            let head_ok = goish::strings::HasPrefix(
                s.clone(),
                string("POST /api HTTP/1.1\r\n"),
            );
            let host_ok = goish::strings::Contains(s.clone(), string("Host: example.com:8080\r\n"));
            let len_ok = goish::strings::Contains(s.clone(), string("Content-Length: 5\r\n"));
            let body_ok = goish::strings::HasSuffix(s.clone(), string("hello"));
            if head_ok && host_ok && len_ok && body_ok {
                Println!("[ 1] Write wire format         PASS");
            } else {
                Println!(
                    "[ 1] Write wire format         FAIL head={} host={} len={} body={}",
                    head_ok, host_ok, len_ok, body_ok
                );
                failed += 1;
            }
        }
    }

    // 2. CookiesNamed returns matching cookies, empty for unknown name.
    {
        let (mut req, _) =
            http::NewRequest(string("GET"), string("http://example.com/x"), bytes(""));
        req.Header.Add(string("Cookie"), string("a=1; b=2; a=3"));

        let only_a = req.CookiesNamed(string("a"));
        let nope = req.CookiesNamed(string("nope"));
        let empty_name = req.CookiesNamed(string(""));

        if only_a.Len() == 2
            && only_a[0].Name == "a"
            && only_a[0].Value == "1"
            && only_a[1].Name == "a"
            && only_a[1].Value == "3"
            && nope.Len() == 0
            && empty_name.Len() == 0
        {
            Println!("[ 2] CookiesNamed              PASS");
        } else {
            Println!(
                "[ 2] CookiesNamed              FAIL a={} nope={} empty={}",
                only_a.Len(),
                nope.Len(),
                empty_name.Len()
            );
            failed += 1;
        }
    }

    // 3. GET with no body — Content-Length omitted.
    {
        let (req, _) =
            http::NewRequest(string("GET"), string("http://x.example.com/p"), bytes(""));
        let mut buf =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(Vec::new()));
        let _ = req.Write(&mut buf);
        let on_wire = buf.Bytes();
        let mut v: Vec<u8> = Vec::with_capacity(on_wire.Len() as usize);
        for i in 0..on_wire.Len() {
            v.push(on_wire[i]);
        }
        let s = goish::string::from_bytes(&v);
        // GET typically has no Content-Length header (we omit when body empty).
        if goish::strings::HasPrefix(s.clone(), string("GET /p HTTP/1.1\r\n"))
            && !goish::strings::Contains(s.clone(), string("Content-Length:"))
        {
            Println!("[ 3] GET no body, no CL        PASS");
        } else {
            Println!("[ 3] GET no body, no CL        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 3", failed);
        syscall::Exit(1);
    }
}
