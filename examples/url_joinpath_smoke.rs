// url_joinpath_smoke — exercise URL.JoinPath + url::JoinPath free fn
// (line-by-line ports of url.go:1262 / :1338).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::net::http::url;
use goish::{string, syscall, Println};

fn vec_of(items: &'static [&'static str]) -> slice<goish::string> {
    let mut s: slice<goish::string> = slice::__from_vec(alloc::vec::Vec::new());
    for it in items.iter() {
        s = goish::append!(s, string(*it));
    }
    s
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Append two segments to an absolute URL.
    {
        let (out, err) = url::JoinPath(
            string("http://example.com/api"),
            vec_of(&["users", "42"]),
        );
        if err.IsNil() && out == "http://example.com/api/users/42" {
            Println!("[ 1] absolute base + 2 elems   PASS");
        } else {
            Println!("[ 1] absolute base + 2 elems   FAIL got={}", out);
            failed += 1;
        }
    }

    // 2. Trailing slash preserved when last elem ends with /.
    {
        let (out, err) = url::JoinPath(
            string("http://example.com/api/"),
            vec_of(&["users/"]),
        );
        if err.IsNil() && out == "http://example.com/api/users/" {
            Println!("[ 2] trailing slash preserved  PASS");
        } else {
            Println!("[ 2] trailing slash preserved  FAIL got={}", out);
            failed += 1;
        }
    }

    // 3. ../ collapsed by path.Join.
    {
        let (out, err) = url::JoinPath(
            string("http://example.com/a/b/c"),
            vec_of(&["..", "d"]),
        );
        if err.IsNil() && out == "http://example.com/a/b/d" {
            Println!("[ 3] dot-dot collapsed         PASS");
        } else {
            Println!("[ 3] dot-dot collapsed         FAIL got={}", out);
            failed += 1;
        }
    }

    // 4. Relative base — JoinPath returns relative result.
    {
        let (out, err) = url::JoinPath(string("foo/bar"), vec_of(&["baz"]));
        if err.IsNil() && out == "foo/bar/baz" {
            Println!("[ 4] relative base             PASS");
        } else {
            Println!("[ 4] relative base             FAIL got={}", out);
            failed += 1;
        }
    }

    // 5. Method form on parsed URL.
    {
        let (u, err) = url::Parse(string("https://example.com/api?x=1"));
        if err.IsNil() {
            let joined = u.JoinPath(vec_of(&["v2", "users"]));
            if joined.Path == "/api/v2/users" && joined.RawQuery == "x=1" {
                Println!("[ 5] URL.JoinPath method       PASS");
            } else {
                Println!(
                    "[ 5] URL.JoinPath method       FAIL path={} q={}",
                    joined.Path, joined.RawQuery
                );
                failed += 1;
            }
        } else {
            Println!("[ 5] URL.JoinPath method       FAIL parse");
            failed += 1;
        }
    }

    // 6. Empty elems list returns base URL path canonicalized.
    {
        let (out, err) = url::JoinPath(string("http://x/a/./b"), vec_of(&[]));
        if err.IsNil() && out == "http://x/a/b" {
            Println!("[ 6] empty elems canonicalize  PASS");
        } else {
            Println!("[ 6] empty elems canonicalize  FAIL got={}", out);
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 6", failed);
        syscall::Exit(1);
    }
}
