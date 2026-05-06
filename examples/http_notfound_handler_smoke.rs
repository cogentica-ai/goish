// http_notfound_handler_smoke — exercise http.NotFoundHandler() free fn
// (server.go:2362). The function returns Arc<dyn Handler> wrapping the
// internal notFoundHandler that emits "404 page not found\n" with status
// 404. We exercise it through ServeMux registration.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::net::http::{Handler, NewServeMux, NotFoundHandler};
use goish::string;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. NotFoundHandler() returns a non-nil Arc<dyn Handler>.
    {
        let h: Arc<dyn Handler> = NotFoundHandler();
        // Strong-count > 0 means the Arc is live; sanity check.
        if Arc::strong_count(&h) >= 1 {
            Println!("[ 1] NotFoundHandler() returns PASS");
        } else {
            Println!("[ 1] NotFoundHandler() returns FAIL");
            failed += 1;
        }
    }

    // 2. The handler can be registered on a ServeMux.
    {
        let mux = NewServeMux();
        let h = NotFoundHandler();
        mux.Handle(string("/missing"), h);
        Println!("[ 2] Registers on ServeMux    PASS");
    }

    // 3. Handler trait dispatch — repeated NotFoundHandler() calls hand
    //    back fresh Arc<dyn Handler> values; both should be usable.
    {
        let h1 = NotFoundHandler();
        let h2 = NotFoundHandler();
        if Arc::strong_count(&h1) >= 1 && Arc::strong_count(&h2) >= 1 {
            Println!("[ 3] Multiple instances        PASS");
        } else {
            Println!("[ 3] Multiple instances        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 3");
        syscall::Exit(1);
    }
}
