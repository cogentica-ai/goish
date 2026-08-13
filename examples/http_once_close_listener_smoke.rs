// http_once_close_listener_smoke — net/http/server.go's
// onceCloseListener (:3956) and its Close (:3964).
//
// Go: "onceCloseListener wraps a net.Listener, protecting it from
// multiple Close calls."
//
// That is not tidiness. Serve and Shutdown can both reach the
// listener, and closing an fd twice is a use-after-free at the
// descriptor level: between the two closes the number can be reissued
// to an unrelated open, and the second close then closes THAT. The
// sync.Once makes the second call a no-op returning the first call's
// error.
//
// This checks the wrapper's contract directly — Close twice, second
// returns the same value and does not touch the fd again.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::net;
use goish::net::http::server::onceCloseListener;
use goish::{fmt, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if err != goish::nil {
        fmt::Println!("setup: Listen failed: ", err);
        syscall::Exit(1);
    }

    let oc = onceCloseListener::new(Arc::new(ln));

    // 1. First Close succeeds.
    let e1 = oc.Close();
    if e1 == goish::nil {
        fmt::Println!("[1] first Close succeeds  PASS");
    } else {
        fmt::Println!("[1] first Close  FAIL err=", e1);
        failed += 1;
    }

    // 2. Second and third Close return the SAME result without
    //    touching the descriptor again. A bare listener would attempt
    //    close(2) a second time here.
    let e2 = oc.Close();
    let e3 = oc.Close();
    if e2 == goish::nil && e3 == goish::nil {
        fmt::Println!("[2] repeated Close is a no-op, same result  PASS");
    } else {
        fmt::Println!("[2] repeated Close  FAIL e2=", e2, " e3=", e3);
        failed += 1;
    }

    if failed == 0 {
        fmt::Println!("ok 2/2");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 2");
        syscall::Exit(1);
    }
}
