// httputil dump.go helpers — valueOrDefault and outgoingLength.
//
// Expected values are Go 1.25.5's, taken from a goref run of the real
// unexported functions inside net/http/httputil, not transcribed.
//
// outgoingLength is the interesting one: Go reads three body states
// through an io.ReadCloser (nil, the http.NoBody sentinel, a real
// body) and goish's slice<byte> Body collapses the first two into
// "empty". This pins that the collapse is observationally identical —
// all four of Go's cases still produce Go's answer.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::net::http::httputil;
use goish::{fmt, slice, string, syscall};

fn eqi(got: goish::types::int64, want: goish::types::int64, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what, ": got ", got, " want ", want);
        *bad += 1;
    }
}

fn eqs(got: string, want: &str, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what, ": got ", got);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    // valueOrDefault — Go: ("a","b")->"a", ("","b")->"b"
    eqs(
        httputil::valueOrDefault(string("a"), string("b")),
        "a",
        "valueOrDefault nonempty",
        &mut bad,
    );
    eqs(
        httputil::valueOrDefault(string(""), string("b")),
        "b",
        "valueOrDefault empty",
        &mut bad,
    );

    // outgoingLength — Go: nil->0, 5-byte CL=5 ->5, body CL=0 ->-1,
    // NoBody->0.
    let (mut r, err) = http::NewRequest(string("GET"), string("http://x/"), goish::nil);
    if err != goish::nil {
        fmt::Println!("FAIL NewRequest: ", err.Error());
        syscall::Exit(1);
    }
    eqi(httputil::outgoingLength(&r), 0, "no body", &mut bad);

    r.Body = http::Body::from_bytes(slice::<u8>::__from_vec(b"hello".to_vec()));
    r.ContentLength = 5;
    eqi(
        httputil::outgoingLength(&r),
        5,
        "5-byte body, CL=5",
        &mut bad,
    );

    r.ContentLength = 0;
    eqi(
        httputil::outgoingLength(&r),
        -1,
        "body with CL forced 0",
        &mut bad,
    );

    // goish has no NoBody sentinel; an empty slice IS that state, and
    // Go answers 0 for it.
    r.Body = http::Body::from_bytes(slice::<u8>::new());
    r.ContentLength = 0;
    eqi(
        httputil::outgoingLength(&r),
        0,
        "NoBody equivalent",
        &mut bad,
    );

    if bad == 0 {
        fmt::Println!("DUMP_HELPERS_OK 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
