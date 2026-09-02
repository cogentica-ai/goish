// url_values_encode_smoke — exercise url.Values.Encode (line-by-line
// port of url.go:1028; exposed as ValuesEncode free fn).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gomap::map;
use goish::goslice::slice;
use goish::net::http;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Empty Values → empty string.
    {
        let v: map<string, slice<string>> = map::new();
        if http::ValuesEncode(&v).Len() == 0 {
            fmt::Println!("[ 1] empty                      PASS");
        } else {
            fmt::Println!("[ 1] empty                      FAIL");
            failed += 1;
        }
    }

    // 2. Single key=value.
    {
        let mut v: map<string, slice<string>> = map::new();
        let mut s: slice<string> = slice::__from_vec(alloc::vec![]);
        s = goish::append!(s, "hello");
        v.Set(string("greeting"), s);
        let got = http::ValuesEncode(&v);
        if got == "greeting=hello" {
            fmt::Println!("[ 2] single pair                PASS");
        } else {
            fmt::Println!("[ 2] single pair                FAIL got=", got);
            failed += 1;
        }
    }

    // 3. Two keys: output sorted lexicographically.
    {
        let mut v: map<string, slice<string>> = map::new();
        let mut a: slice<string> = slice::__from_vec(alloc::vec![]);
        a = goish::append!(a, "1");
        let mut b: slice<string> = slice::__from_vec(alloc::vec![]);
        b = goish::append!(b, "2");
        v.Set(string("z"), a);
        v.Set(string("a"), b);
        let got = http::ValuesEncode(&v);
        if got == "a=2&z=1" {
            fmt::Println!("[ 3] sorted keys                PASS");
        } else {
            fmt::Println!("[ 3] sorted keys                FAIL got=", got);
            failed += 1;
        }
    }

    // 4. Multi-value key emits multiple pairs in slice order.
    {
        let mut v: map<string, slice<string>> = map::new();
        let mut s: slice<string> = slice::__from_vec(alloc::vec![]);
        s = goish::append!(s, "1");
        s = goish::append!(s, "2");
        s = goish::append!(s, "3");
        v.Set(string("k"), s);
        let got = http::ValuesEncode(&v);
        if got == "k=1&k=2&k=3" {
            fmt::Println!("[ 4] multi-value                PASS");
        } else {
            fmt::Println!("[ 4] multi-value                FAIL got=", got);
            failed += 1;
        }
    }

    // 5. Special characters in keys and values get percent-escaped /
    //    spaces become '+'.
    {
        let mut v: map<string, slice<string>> = map::new();
        let mut s: slice<string> = slice::__from_vec(alloc::vec![]);
        s = goish::append!(s, "hello world");
        v.Set(string("name=key"), s);
        let got = http::ValuesEncode(&v);
        if got == "name%3Dkey=hello+world" {
            fmt::Println!("[ 5] special chars escaped      PASS");
        } else {
            fmt::Println!("[ 5] special chars escaped      FAIL got=", got);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
