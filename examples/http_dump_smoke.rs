// http_dump_smoke — exercise httputil::DumpRequest.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::{bytes, string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Build a Request via NewRequest, set a header, dump.
    let body = bytes("hello\n");
    let (mut req, _) = http::NewRequest(string("POST"), string("http://example.com/api?x=1"), body);
    req.Header.Set(string("X-Test"), string("y"));
    let (dump, err) = http::httputil::DumpRequest(&req, true);
    if !err.IsNil() {
        Println!("DumpRequest err");
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
            Println!("[{}] needle present            PASS", i);
        } else {
            Println!("[{}] needle missing            FAIL n={}", i, n.len());
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok dump smoke");
        syscall::Exit(0);
    } else {
        Println!("FAIL {}", failed);
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
