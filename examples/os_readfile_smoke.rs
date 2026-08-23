// os_readfile_smoke — verify ReadFile / WriteFile + http.Method* constants.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes;
use goish::fmt;
use goish::net::http;
use goish::os;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // ReadFile /etc/passwd
    {
        let (data, err) = os::ReadFile(string("/etc/passwd"));
        if err.IsNil() && data.Len() > 0 {
            fmt::Println!("[ 1] ReadFile /etc/passwd      PASS {}B", data.Len());
        } else {
            fmt::Println!("[ 1] ReadFile /etc/passwd      FAIL");
            failed += 1;
        }
    }

    // WriteFile + ReadFile round-trip in /tmp.
    {
        let path = string("/tmp/goish-readfile-smoke.txt");
        let want = bytes("hello, write+read\n");
        let werr = os::WriteFile(path.clone(), want.clone(), 0o644);
        if !werr.IsNil() {
            fmt::Println!("[ 2] WriteFile                 FAIL");
            failed += 1;
        } else {
            let (got, rerr) = os::ReadFile(path.clone());
            if rerr.IsNil() && got.Len() == want.Len() {
                fmt::Println!("[ 2] WriteFile + ReadFile      PASS");
            } else {
                fmt::Println!("[ 2] WriteFile + ReadFile      FAIL got={}B", got.Len());
                failed += 1;
            }
        }
    }

    // http.Method* constants are the right strings.
    if http::MethodGet == "GET"
        && http::MethodPost == "POST"
        && http::MethodPut == "PUT"
        && http::MethodDelete == "DELETE"
        && http::MethodPatch == "PATCH"
        && http::MethodHead == "HEAD"
    {
        fmt::Println!("[ 3] Method* constants         PASS");
    } else {
        fmt::Println!("[ 3] Method* constants         FAIL");
        failed += 1;
    }

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 3", failed);
        syscall::Exit(1);
    }
}
