// http_mux_handler_smoke — exercise ServeMux::Handler(r)
// (line-by-line port of server.go:2683).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes;
use goish::fmt;
use goish::net::http;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    let mux = http::ServeMux::new();
    mux.HandleFunc(string("/exact"), |_, _| {});
    mux.HandleFunc(string("/prefix/"), |_, _| {});
    mux.HandleFunc(string("/api/users/{id}"), |_, _| {});

    // 1. Exact match returns the literal pattern.
    {
        let (req, _) = http::NewRequest(string("GET"), string("http://x/exact"), bytes(""));
        let (_h, pat) = mux.Handler(&req);
        if pat == "/exact" {
            fmt::Println!("[ 1] exact pattern             PASS");
        } else {
            fmt::Println!("[ 1] exact pattern             FAIL got={}", pat);
            failed += 1;
        }
    }

    // 2. Prefix match returns the registered prefix.
    {
        let (req, _) =
            http::NewRequest(string("GET"), string("http://x/prefix/foo/bar"), bytes(""));
        let (_h, pat) = mux.Handler(&req);
        if pat == "/prefix/" {
            fmt::Println!("[ 2] prefix pattern            PASS");
        } else {
            fmt::Println!("[ 2] prefix pattern            FAIL got={}", pat);
            failed += 1;
        }
    }

    // 3. Wildcard pattern match returns the original pattern string.
    {
        let (req, _) = http::NewRequest(string("GET"), string("http://x/api/users/42"), bytes(""));
        let (_h, pat) = mux.Handler(&req);
        if pat == "/api/users/{id}" {
            fmt::Println!("[ 3] wildcard pattern          PASS");
        } else {
            fmt::Println!("[ 3] wildcard pattern          FAIL got={}", pat);
            failed += 1;
        }
    }

    // 4. No match → empty pattern + NotFoundHandler.
    {
        let (req, _) = http::NewRequest(string("GET"), string("http://x/nope"), bytes(""));
        let (_h, pat) = mux.Handler(&req);
        if pat.Len() == 0 {
            fmt::Println!("[ 4] no match → empty          PASS");
        } else {
            fmt::Println!("[ 4] no match → empty          FAIL got={}", pat);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 4", failed);
        syscall::Exit(1);
    }
}
