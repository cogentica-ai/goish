// http_constants_smoke — exercise SameSite* constants (Go shape) and
// NewRequestWithContext API surface.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::context;
use goish::convert::bytes;
use goish::fmt;
use goish::net::http;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. SameSite* constants are reachable at the http:: level and
    //    match the enum variants.
    {
        if http::SameSiteDefaultMode == http::SameSite::DefaultMode
            && http::SameSiteLaxMode == http::SameSite::LaxMode
            && http::SameSiteStrictMode == http::SameSite::StrictMode
            && http::SameSiteNoneMode == http::SameSite::NoneMode
        {
            fmt::Println!("[ 1] SameSite* constants       PASS");
        } else {
            fmt::Println!("[ 1] SameSite* constants       FAIL");
            failed += 1;
        }
    }

    // 2. SetCookie attaches with SameSite=Lax via the Go-style constant.
    {
        let mut c = http::Cookie::default();
        c.Name = string("session");
        c.Value = string("xyz");
        c.SameSite = http::SameSiteLaxMode;
        let s = c.String();
        if goish::strings::Contains(s.clone(), string("SameSite=Lax")) {
            fmt::Println!("[ 2] Cookie SameSite=Lax       PASS");
        } else {
            fmt::Println!("[ 2] Cookie SameSite=Lax       FAIL got={}", s);
            failed += 1;
        }
    }

    // 3. NewRequestWithContext accepts a ctx and returns a usable Request.
    {
        let ctx = context::Background();
        let (req, err) = http::NewRequestWithContext(
            ctx,
            string("GET"),
            string("http://example.com/x"),
            bytes(""),
        );
        if err.IsNil() && req.Method == "GET" && req.URL.Host == "example.com" {
            fmt::Println!("[ 3] NewRequestWithContext     PASS");
        } else {
            fmt::Println!("[ 3] NewRequestWithContext     FAIL");
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
