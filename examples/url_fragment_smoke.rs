// url_fragment_smoke — exercise URL.Fragment + EscapedFragment + String round-trip.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http::url;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Parse splits off #fragment.
    {
        let (u, err) = url::Parse(string("https://example.com/path?q=1#section-2"));
        if err.IsNil()
            && u.Fragment == "section-2"
            && u.Path == "/path"
            && u.RawQuery == "q=1"
        {
            fmt::Println!("[ 1] Parse fragment           PASS");
        } else {
            fmt::Println!(
                "[ 1] Parse fragment           FAIL frag={} path={}",
                u.Fragment, u.Path
            );
            failed += 1;
        }
    }

    // 2. URL.String() round-trip preserves fragment.
    {
        let (u, _) = url::Parse(string("http://x/p?a=1#frag"));
        let s = u.String();
        if s == "http://x/p?a=1#frag" {
            fmt::Println!("[ 2] String roundtrip          PASS");
        } else {
            fmt::Println!("[ 2] String roundtrip          FAIL got={}", s);
            failed += 1;
        }
    }

    // 3. No fragment → no '#' in String().
    {
        let (u, _) = url::Parse(string("http://x/p"));
        let s = u.String();
        if s == "http://x/p" {
            fmt::Println!("[ 3] no fragment               PASS");
        } else {
            fmt::Println!("[ 3] no fragment               FAIL got={}", s);
            failed += 1;
        }
    }

    // 4. EscapedFragment returns RawFragment if non-empty.
    {
        let (u, _) = url::Parse(string("http://x/p#hello"));
        let ef = u.EscapedFragment();
        if ef == "hello" {
            fmt::Println!("[ 4] EscapedFragment           PASS");
        } else {
            fmt::Println!("[ 4] EscapedFragment           FAIL got={}", ef);
            failed += 1;
        }
    }

    // 5. Empty fragment after '#' is captured as empty Fragment but
    //    has_frag is still true (Fragment="" RawFragment="").
    {
        let (u, _) = url::Parse(string("http://x/p#"));
        if u.Fragment == "" {
            fmt::Println!("[ 5] empty fragment            PASS");
        } else {
            fmt::Println!("[ 5] empty fragment            FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 5", failed);
        syscall::Exit(1);
    }
}
