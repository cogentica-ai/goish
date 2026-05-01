// strings_replacer_smoke — exercise strings::NewReplacer + Replace.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::strings;
use goish::{string, syscall, Println};

fn pairs(items: &'static [&'static str]) -> slice<goish::string> {
    let mut s: slice<goish::string> = slice::__from_vec(alloc::vec::Vec::new());
    for it in items.iter() {
        s = goish::append!(s, string(*it));
    }
    s
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Single byte → multi-byte (HTML escape style).
    {
        let r = strings::NewReplacer(pairs(&["&", "&amp;", "<", "&lt;"]));
        let out = r.Replace(string("a&b<c"));
        if out == "a&amp;b&lt;c" {
            Println!("[ 1] HTML-style escapes        PASS");
        } else {
            Println!("[ 1] HTML-style escapes        FAIL got={}", out);
            failed += 1;
        }
    }

    // 2. Multi-byte → single byte.
    {
        let r = strings::NewReplacer(pairs(&["foo", "X", "bar", "Y"]));
        let out = r.Replace(string("foobar foobaz"));
        if out == "XY Xbaz" {
            Println!("[ 2] multi → single            PASS");
        } else {
            Println!("[ 2] multi → single            FAIL got={}", out);
            failed += 1;
        }
    }

    // 3. No-match pass-through.
    {
        let r = strings::NewReplacer(pairs(&["zzz", "!"]));
        let out = r.Replace(string("hello"));
        if out == "hello" {
            Println!("[ 3] no match                  PASS");
        } else {
            Println!("[ 3] no match                  FAIL got={}", out);
            failed += 1;
        }
    }

    // 4. First-pair-wins on overlap.
    {
        let r = strings::NewReplacer(pairs(&["foo", "1", "foobar", "2"]));
        let out = r.Replace(string("foobar"));
        // "foo" matches first → "1bar"
        if out == "1bar" {
            Println!("[ 4] first pair wins           PASS");
        } else {
            Println!("[ 4] first pair wins           FAIL got={}", out);
            failed += 1;
        }
    }

    // 5. Replacement equals original (no-op).
    {
        let r = strings::NewReplacer(pairs(&["x", "x"]));
        let out = r.Replace(string("xxx"));
        if out == "xxx" {
            Println!("[ 5] identity                  PASS");
        } else {
            Println!("[ 5] identity                  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 5", failed);
        syscall::Exit(1);
    }
}
