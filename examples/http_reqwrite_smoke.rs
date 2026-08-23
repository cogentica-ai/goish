// Request.Write — the exact bytes goish puts on the wire for an
// outbound request, against Go 1.25.5. Expected values from a goref
// run of the real (*Request).Write.
//
// Six cases, each pinning something a hand-rolled writer gets wrong:
//   header ORDER (Host, then User-Agent, then the sorted rest)
//   Content-Length placement and derivation from the body
//   a custom User-Agent replacing the default
//   an EXPLICITLY EMPTY User-Agent omitting the header entirely
//   r.Host overriding the URL's host
//   r.Close emitting "Connection: close"
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::{bytes, errors, fmt, string, syscall};

fn wire(r: &http::Request) -> string {
    let mut b = bytes::Buffer::new();
    let err = r.Write(&mut b);
    if err != errors::nil {
        return string("err ") + err.Error();
    }
    return string::from_bytes(&b.Bytes());
}

fn eq(got: string, want: &str, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what);
        fmt::Println!("  got  ", got);
        fmt::Println!("  want ", want);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    {
        let (r, _) = http::NewRequest(
            string("GET"),
            string("http://example.com/a?q=1"),
            goish::nil,
        );
        eq(
            wire(&r),
            "GET /a?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go-http-client/1.1\r\n\r\n",
            "plain GET",
            &mut bad,
        );
    }
    {
        let (mut r, _) = http::NewRequest(
            string("POST"),
            string("http://example.com/p"),
            goish::slice::<u8>::__from_vec(b"hello".to_vec()),
        );
        r.Header.Set(string("Content-Type"), string("text/plain"));
        eq(wire(&r),
           "POST /p HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
           "POST with body", &mut bad);
    }
    {
        let (mut r, _) = http::NewRequest(string("GET"), string("http://example.com/"), goish::nil);
        r.Header.Set(string("User-Agent"), string("mine/1.0"));
        r.Header.Set(string("X-B"), string("2"));
        r.Header.Set(string("X-A"), string("1"));
        eq(wire(&r),
           "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: mine/1.0\r\nX-A: 1\r\nX-B: 2\r\n\r\n",
           "custom UA + sorted extra headers", &mut bad);
    }
    {
        let (mut r, _) = http::NewRequest(string("GET"), string("http://example.com/"), goish::nil);
        r.Header.Set(string("User-Agent"), string(""));
        eq(
            wire(&r),
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "explicit empty UA omits the header",
            &mut bad,
        );
    }
    {
        let (mut r, _) = http::NewRequest(string("GET"), string("http://example.com/"), goish::nil);
        r.Host = string("other.example");
        eq(
            wire(&r),
            "GET / HTTP/1.1\r\nHost: other.example\r\nUser-Agent: Go-http-client/1.1\r\n\r\n",
            "r.Host overrides URL host",
            &mut bad,
        );
    }
    {
        let (mut r, _) = http::NewRequest(string("GET"), string("http://example.com/"), goish::nil);
        r.Close = true;
        eq(wire(&r),
           "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\n\r\n",
           "r.Close emits Connection: close", &mut bad);
    }

    if bad == 0 {
        fmt::Println!("REQWRITE_OK 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
