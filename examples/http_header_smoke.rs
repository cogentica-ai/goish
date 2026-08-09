// http_header_smoke — exercise Header.Clone + Header.Write +
// Header.WriteSubset.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::bytes::NewBuffer;
use goish::gomap::map;
use goish::goslice::slice;
use goish::net::http::Header;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Clone deep-copies values so mutations don't propagate.
    {
        let mut h1 = Header::new();
        h1.Set(string("X-Foo"), string("v1"));
        h1.Add(string("X-Foo"), string("v2"));
        let h2 = h1.Clone();
        // Mutate h1; h2 should be unchanged.
        h1.Set(string("X-Foo"), string("only"));
        if h2.Values(string("X-Foo")).Len() == 2 && h2.Values(string("X-Foo"))[0] == "v1" {
            fmt::Println!("[ 1] Clone independence        PASS");
        } else {
            fmt::Println!("[ 1] Clone independence        FAIL n={}", h2.Values(string("X-Foo")).Len());
            failed += 1;
        }
    }

    // Write emits "Key: value\r\n" lines, sorted by key.
    {
        let mut h = Header::new();
        h.Set(string("Content-Type"), string("text/plain"));
        h.Set(string("Authorization"), string("Bearer xyz"));
        let mut buf = NewBuffer(slice::<u8>::__from_vec(alloc::vec::Vec::new()));
        let _ = h.Write(&mut buf);
        let bytes = buf.Bytes();
        // Sorted lex: Authorization < Content-Type
        let expected = b"Authorization: Bearer xyz\r\nContent-Type: text/plain\r\n";
        let mut got = alloc::vec::Vec::new();
        for i in 0..bytes.Len() {
            got.push(bytes[i]);
        }
        if got.as_slice() == expected {
            fmt::Println!("[ 2] Write sorted              PASS");
        } else {
            fmt::Println!("[ 2] Write sorted              FAIL got len={}", got.len());
            failed += 1;
        }
    }

    // WriteSubset skips excluded keys.
    {
        let mut h = Header::new();
        h.Set(string("X-A"), string("a"));
        h.Set(string("X-B"), string("b"));
        h.Set(string("X-C"), string("c"));
        let mut excl: map<string, bool> = map::<string, bool>::new();
        excl.Set(string("X-B"), true);
        let mut buf = NewBuffer(slice::<u8>::__from_vec(alloc::vec::Vec::new()));
        let _ = h.WriteSubset(&mut buf, &excl);
        let bytes = buf.Bytes();
        let expected = b"X-A: a\r\nX-C: c\r\n";
        let mut got = alloc::vec::Vec::new();
        for i in 0..bytes.Len() {
            got.push(bytes[i]);
        }
        if got.as_slice() == expected {
            fmt::Println!("[ 3] WriteSubset exclude       PASS");
        } else {
            fmt::Println!("[ 3] WriteSubset exclude       FAIL got len={}", got.len());
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
