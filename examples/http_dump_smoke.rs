// http_dump_smoke — exercise httputil::DumpRequest.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http;
use goish::{bytes, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Build a Request via NewRequest, set a header, dump.
    let body = bytes("hello\n");
    let (mut req, _) = http::NewRequest(string("POST"), string("http://example.com/api?x=1"), body);
    req.Header.Set(string("X-Test"), string("y"));
    let (dump, err) = http::httputil::DumpRequest(&req, true);
    if !err.IsNil() {
        fmt::Println!("DumpRequest err");
        syscall::Exit(1);
    }
    // Convert dump to string for printing.
    let s = goish::convert::string(dump.clone());
    let _ = s;

    let needles: [&[u8]; 5] = [
        b"POST /api?x=1 HTTP/1.1\r\n",
        b"Host: example.com\r\n",
        b"X-Test: y\r\n",
        b"\r\n\r\n",
        b"hello\n",
    ];
    let mut hay = alloc::vec::Vec::new();
    for i in 0..dump.Len() {
        hay.push(dump[i]);
    }
    for (i, n) in needles.iter().enumerate() {
        if find_subseq(&hay, n) {
            fmt::Println!("[{}] needle present            PASS", i);
        } else {
            fmt::Println!("[{}] needle missing            FAIL n={}", i, n.len());
            failed += 1;
        }
    }

    // CanonicalHeaderKey
    if http::CanonicalHeaderKey(string("content-type")) == "Content-Type"
        && http::CanonicalHeaderKey(string("ACCEPT-ENCODING")) == "Accept-Encoding"
    {
        fmt::Println!("[+] CanonicalHeaderKey         PASS");
    } else {
        fmt::Println!("[+] CanonicalHeaderKey         FAIL");
        failed += 1;
    }

    // ParseHTTPVersion
    {
        let (a, b, ok1) = http::ParseHTTPVersion(string("HTTP/1.1"));
        let (_c, _d, ok_bad) = http::ParseHTTPVersion(string("HTTP/2"));
        if ok1 && a == 1 && b == 1 && !ok_bad {
            fmt::Println!("[+] ParseHTTPVersion           PASS");
        } else {
            fmt::Println!("[+] ParseHTTPVersion           FAIL");
            failed += 1;
        }
    }

    // DumpResponse — synthesize a response with Status, Header, Body.
    {
        let mut resp = http::Response::default();
        resp.StatusCode = 418;
        resp.Status = string("418 I'm a teapot");
        resp.ProtoMajor = 1;
        resp.ProtoMinor = 1;
        resp.ContentLength = 5;
        resp.Body = http::Body::from(bytes("brew\n"));
        resp.Header.Set(string("X-Mark"), string("z"));
        let (rdump, _err) = http::httputil::DumpResponse(&resp, true);
        let mut h2 = alloc::vec::Vec::new();
        for i in 0..rdump.Len() {
            h2.push(rdump[i]);
        }
        let needles2: [&[u8]; 4] = [
            b"HTTP/1.1 418 I'm a teapot\r\n",
            b"Content-Length: 5\r\n",
            b"X-Mark: z\r\n",
            b"brew\n",
        ];
        let mut bad = false;
        for n in needles2.iter() {
            if !find_subseq(&h2, n) {
                bad = true;
            }
        }
        if !bad {
            fmt::Println!("[+] DumpResponse               PASS");
        } else {
            fmt::Println!("[+] DumpResponse               FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok dump smoke");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {}", failed);
        syscall::Exit(1);
    }
}

fn find_subseq(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    for i in 0..=hay.len() - needle.len() {
        if &hay[i..i + needle.len()] == needle {
            return true;
        }
    }
    false
}
