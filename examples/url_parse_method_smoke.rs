// url_parse_method_smoke — exercise URL.Parse method + url.ValuesHas
// (url.go:1123 + 974).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gomap::map;
use goish::goslice::slice;
use goish::net::http::{ParseURL, ValuesHas};
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Base + relative ref ("file.html") → resolves against base path.
    {
        let (base, e) = ParseURL(string("http://example.com/a/b/index.html"));
        if !e.IsNil() {
            Println!("[ 1] Parse base                FAIL parse-base");
            failed += 1;
        } else {
            let (resolved, e2) = base.Parse(string("file.html"));
            if !e2.IsNil() {
                Println!("[ 1] URL.Parse relative        FAIL parse-ref");
                failed += 1;
            } else if resolved.Path == "/a/b/file.html" && resolved.Host == "example.com" {
                Println!("[ 1] URL.Parse relative        PASS");
            } else {
                Println!("[ 1] URL.Parse relative        FAIL path=", resolved.Path);
                failed += 1;
            }
        }
    }

    // 2. Base + absolute URI → replaces.
    {
        let (base, _) = ParseURL(string("http://example.com/a/b/"));
        let (resolved, e) = base.Parse(string("https://other.test/x"));
        if e.IsNil() && resolved.Scheme == "https" && resolved.Host == "other.test"
            && resolved.Path == "/x"
        {
            Println!("[ 2] URL.Parse absolute        PASS");
        } else {
            Println!("[ 2] URL.Parse absolute        FAIL");
            failed += 1;
        }
    }

    // 3. URL.Parse with query: base + "?q=1" → query carried.
    {
        let (base, _) = ParseURL(string("http://example.com/a/b/"));
        let (r, e) = base.Parse(string("?q=1"));
        if e.IsNil() && r.Host == "example.com" && r.RawQuery == "q=1" {
            Println!("[ 3] URL.Parse query carried   PASS");
        } else {
            Println!("[ 3] URL.Parse query carried   FAIL rawq=", r.RawQuery);
            failed += 1;
        }
    }

    // 4. URL.Parse with absolute path: base "/a/b/c" + "/x" → "/x".
    {
        let (base, _) = ParseURL(string("http://example.com/a/b/c"));
        let (r, e) = base.Parse(string("/x"));
        if e.IsNil() && r.Path == "/x" && r.Host == "example.com" {
            Println!("[ 4] URL.Parse absolute path   PASS");
        } else {
            Println!("[ 4] URL.Parse absolute path   FAIL");
            failed += 1;
        }
    }

    // 5. URL.Parse with empty ref → resolves to base.
    {
        let (base, _) = ParseURL(string("http://example.com/a/b/c"));
        let (r, e) = base.Parse(string(""));
        if e.IsNil() && r.Host == "example.com" && r.Path == "/a/b/c" {
            Println!("[ 5] URL.Parse empty ref       PASS");
        } else {
            Println!("[ 5] URL.Parse empty ref       FAIL path=", r.Path);
            failed += 1;
        }
    }

    // 6. ValuesHas: present key → true.
    {
        let mut v: map<string, slice<string>> = map::<string, slice<string>>::new();
        let mut s: slice<string> = slice::__from_vec(alloc::vec::Vec::new());
        s = goish::append!(s, "v1");
        v.Set(string("k"), s);
        if ValuesHas(&v, string("k")) {
            Println!("[ 6] ValuesHas present         PASS");
        } else {
            Println!("[ 6] ValuesHas present         FAIL");
            failed += 1;
        }
    }

    // 7. ValuesHas: absent key → false.
    {
        let v: map<string, slice<string>> = map::<string, slice<string>>::new();
        if !ValuesHas(&v, string("missing")) {
            Println!("[ 7] ValuesHas absent          PASS");
        } else {
            Println!("[ 7] ValuesHas absent          FAIL");
            failed += 1;
        }
    }

    // 8. ValuesHas: empty-list key still counts as present.
    {
        let mut v: map<string, slice<string>> = map::<string, slice<string>>::new();
        let s: slice<string> = slice::__from_vec(alloc::vec::Vec::new());
        v.Set(string("empty"), s);
        if ValuesHas(&v, string("empty")) {
            Println!("[ 8] ValuesHas empty-list      PASS");
        } else {
            Println!("[ 8] ValuesHas empty-list      FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
