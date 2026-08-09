// http_basicauth_smoke — exercise SetBasicAuth + BasicAuth + UserAgent + Referer.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http;
use goish::{bytes, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Round-trip: SetBasicAuth then BasicAuth.
    {
        let (mut req, _) = http::NewRequest(string("GET"), string("http://x/"), bytes(""));
        req.SetBasicAuth(string("Aladdin"), string("open sesame"));
        let auth = req.Header.Get(string("Authorization"));
        // The classic "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" example.
        if auth == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" {
            fmt::Println!("[ 1] SetBasicAuth wire form     PASS");
        } else {
            fmt::Println!("[ 1] SetBasicAuth wire form     FAIL got {}", auth);
            failed += 1;
        }
        let (u, p, ok) = req.BasicAuth();
        if ok && u == "Aladdin" && p == "open sesame" {
            fmt::Println!("[ 2] BasicAuth decode           PASS");
        } else {
            fmt::Println!("[ 2] BasicAuth decode           FAIL");
            failed += 1;
        }
    }

    // No Authorization header → BasicAuth returns ok=false.
    {
        let (req, _) = http::NewRequest(string("GET"), string("http://x/"), bytes(""));
        let (_, _, ok) = req.BasicAuth();
        if !ok {
            fmt::Println!("[ 3] no auth header → ok=false  PASS");
        } else {
            fmt::Println!("[ 3] no auth header → ok=false  FAIL");
            failed += 1;
        }
    }

    // UserAgent and Referer convenience methods.
    {
        let (mut req, _) = http::NewRequest(string("GET"), string("http://x/"), bytes(""));
        req.Header.Set(string("User-Agent"), string("test/1.0"));
        req.Header.Set(string("Referer"), string("http://prev/"));
        if req.UserAgent() == "test/1.0" && req.Referer() == "http://prev/" {
            fmt::Println!("[ 4] UserAgent + Referer        PASS");
        } else {
            fmt::Println!("[ 4] UserAgent + Referer        FAIL");
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
