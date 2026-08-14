// MaxBytesReader against Go 1.25.5.
//
// Expected read sequences came from a goref run of the real
// http.MaxBytesReader; nothing is derived from reading the code.
//
// The subtle part is Go's "n+1" trick: when fewer than len(p) bytes
// remain, it shrinks the read to remaining+1 so ONE extra byte
// answers "did we go over?". That is what makes the boundary cases
// behave differently:
//
//   body exactly at the limit -> full read, then a plain EOF
//   body one byte over        -> full read, then MaxBytesError
//   limit 0                   -> MaxBytesError on the very first read
//
// A port that shrank to `remaining` instead of `remaining+1` would
// pass the "exact" case and report EOF for the "over" case — i.e. it
// would silently accept an oversized body.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::io::Reader;
use goish::net::http;
use goish::types::byte;
use goish::{errors, fmt, slice, string, syscall, types::int};

/// Drive reads until an error, returning "n,n,...|err".
fn drive(body: &'static str, limit: int, bufSize: int) -> string {
    let mut r = http::MaxBytesReader(None, goish::bytes::NewReader(slice::<u8>::__from_vec(body.as_bytes().to_vec())),
        limit,
    );
    let mut out = string::new();
    for _ in 0..6 {
        let mut buf = goish::make!([]byte, bufSize);
        let (n, err) = r.Read(&mut buf);
        out = out + fmt::Sprintf!("%d", n);
        if err != errors::nil {
            out = out + string("|") + err.Error();
            // Sticky: a second read must report the same error.
            let mut b2 = goish::make!([]byte, bufSize);
            let (n2, e2) = r.Read(&mut b2);
            out = out + string("|again:") + fmt::Sprintf!("%d", n2);
            if e2 != errors::nil {
                out = out + string(",") + e2.Error();
            }
            return out;
        }
        out = out + string(",");
    }
    return out;
}

fn eq(got: string, want: string, what: &str, bad: &mut i32) {
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
    const TOO_LARGE: &str = "http: request body too large";

    // Exactly at the limit: 5 bytes, then a plain EOF (NOT MaxBytesError).
    eq(
        drive("hello", 5, 16),
        string("5,0|EOF|again:0,EOF"),
        "exact",
        &mut bad,
    );

    // One byte over: 5 bytes then MaxBytesError.
    eq(
        drive("hello!", 5, 16),
        string("5|") + string(TOO_LARGE) + string("|again:0,") + string(TOO_LARGE),
        "over",
        &mut bad,
    );

    // Zero limit: error on the first read, having read nothing.
    eq(
        drive("x", 0, 16),
        string("0|") + string(TOO_LARGE) + string("|again:0,") + string(TOO_LARGE),
        "zero-limit",
        &mut bad,
    );

    // Small buffer: the limit is enforced across several reads.
    eq(
        drive("hello!", 5, 2),
        string("2,2,1|") + string(TOO_LARGE) + string("|again:0,") + string(TOO_LARGE),
        "small-buf",
        &mut bad,
    );

    if bad == 0 {
        fmt::Println!("MAXBYTES_OK 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
