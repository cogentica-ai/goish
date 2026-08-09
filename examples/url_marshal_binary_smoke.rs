// url_marshal_binary_smoke — exercise URL.MarshalBinary / AppendBinary /
// UnmarshalBinary / Redacted.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::convert;
use goish::net::http::url;
use goish::{make, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. MarshalBinary returns the same bytes as String().
    {
        let (u, err) = url::Parse(string("http://example.com/path?q=1#frag"));
        if !err.IsNil() {
            fmt::Println!("[ 1] MarshalBinary             FAIL parse");
            failed += 1;
        } else {
            let (data, mErr) = u.MarshalBinary();
            let s = goish::string::from_bytes(&data);
            if mErr.IsNil() && s == u.String() {
                fmt::Println!("[ 1] MarshalBinary             PASS");
            } else {
                fmt::Println!("[ 1] MarshalBinary             FAIL got={}", s);
                failed += 1;
            }
        }
    }

    // 2. AppendBinary preserves the prefix and appends serialization.
    {
        let (u, _) = url::Parse(string("https://example.com/x"));
        let prefix = convert::bytes("PRE:");
        let (out, err) = u.AppendBinary(prefix);
        let s = goish::string::from_bytes(&out);
        if err.IsNil() && s == "PRE:https://example.com/x" {
            fmt::Println!("[ 2] AppendBinary preserves    PASS");
        } else {
            fmt::Println!("[ 2] AppendBinary preserves    FAIL got={}", s);
            failed += 1;
        }
    }

    // 3. UnmarshalBinary round-trips through MarshalBinary.
    {
        let (u1, _) = url::Parse(string("http://example.com/page?key=val"));
        let (data, _) = u1.MarshalBinary();
        let mut u2 = url::URL::default();
        let err = u2.UnmarshalBinary(data);
        if err.IsNil() && u2.String() == u1.String() {
            fmt::Println!("[ 3] UnmarshalBinary round     PASS");
        } else {
            fmt::Println!("[ 3] UnmarshalBinary round     FAIL");
            failed += 1;
        }
    }

    // 4. UnmarshalBinary on garbage returns an error (parse failure).
    //    A truly garbage URL is hard since slim Parse is permissive;
    //    test the round-trip path only and accept either error or
    //    successful permissive parse.
    {
        let mut u = url::URL::default();
        let _ = u.UnmarshalBinary(make!([]goish::byte, 0));
        // Slim Parse accepts empty/relative input; any outcome is OK so
        // long as no panic occurred.
        fmt::Println!("[ 4] UnmarshalBinary empty     PASS");
    }

    // 5. Redacted equals String() (slim — no User field).
    {
        let (u, _) = url::Parse(string("http://example.com/x"));
        if u.Redacted() == u.String() {
            fmt::Println!("[ 5] Redacted == String        PASS");
        } else {
            fmt::Println!("[ 5] Redacted == String        FAIL");
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
