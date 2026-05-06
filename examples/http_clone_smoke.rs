// http_clone_smoke — exercise Request.Context / WithContext / Clone (slim).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::context;
use goish::convert::bytes;
use goish::net::http;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Build a request with a header to verify deep-clone independence.
    let ctx = context::Background();
    let (req, err) = http::NewRequestWithContext(
        ctx.clone(),
        string("GET"),
        string("http://example.com/path"),
        bytes(""),
    );
    if !err.IsNil() {
        Println!("setup FAIL");
        syscall::Exit(1);
    }

    // 1. Context() returns a Background analogue (non-nil Arc).
    {
        let _c = req.Context();
        Println!("[ 1] Context() returns ctx     PASS");
    }

    // 2. WithContext returns a clone whose Method/URL match the original.
    {
        let r2 = req.WithContext(ctx.clone());
        if r2.Method == "GET" && r2.URL.Host == "example.com" {
            Println!("[ 2] WithContext copy          PASS");
        } else {
            Println!("[ 2] WithContext copy          FAIL");
            failed += 1;
        }
    }

    // 3. Clone returns a deep copy — mutating the clone's Header
    //    doesn't affect the original.
    {
        let mut r2 = req.Clone(ctx.clone());
        r2.Header.Set(string("X-Test"), string("v1"));
        let original_v = req.Header.Get(string("X-Test"));
        let cloned_v = r2.Header.Get(string("X-Test"));
        if original_v.Len() == 0 && cloned_v == "v1" {
            Println!("[ 3] Clone deep-copies Header  PASS");
        } else {
            Println!(
                "[ 3] Clone deep-copies Header  FAIL orig=[{}] clone=[{}]",
                original_v, cloned_v
            );
            failed += 1;
        }
    }

    // 4. Clone preserves Method, URL, Proto.
    {
        let r2 = req.Clone(ctx.clone());
        if r2.Method == "GET"
            && r2.URL.Host == "example.com"
            && r2.URL.Path == "/path"
            && r2.Proto == "HTTP/1.1"
        {
            Println!("[ 4] Clone preserves fields    PASS");
        } else {
            Println!("[ 4] Clone preserves fields    FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 4", failed);
        syscall::Exit(1);
    }
}
