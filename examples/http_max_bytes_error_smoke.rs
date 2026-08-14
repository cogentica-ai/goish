// http_max_bytes_error_smoke — exercise http::MaxBytesError typed error
// (line-by-line port of request.go:1193).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::convert::bytes;
use goish::io::Reader;
use goish::net::http;
use goish::types::byte;
use goish::{errors, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Construct a MaxBytesError directly. Limit field is preserved
    //    and Error() returns the canonical message.
    {
        let err = http::NewMaxBytesError(1024);
        if err.Error() == "http: request body too large" {
            fmt::Println!("[ 1] error message            PASS");
        } else {
            fmt::Println!("[ 1] error message            FAIL got={}", err.Error());
            failed += 1;
        }
    }

    // 2. MaxBytesReader returns MaxBytesError when limit is exceeded.
    {
        let payload = bytes("0123456789");
        let buf = goish::bytes::NewBuffer(payload);
        let mut limited = http::NewMaxBytesReader(None, buf, 5);
        let mut out = goish::make!([]byte, 32);
        let mut total: i64 = 0;
        let mut last_err = errors::nil.clone();
        loop {
            let (n, err) = limited.Read(&mut out);
            total += n;
            if !err.IsNil() {
                last_err = err;
                break;
            }
            if n == 0 {
                break;
            }
        }
        if total >= 5 && !last_err.IsNil() && last_err.Error() == "http: request body too large" {
            fmt::Println!("[ 2] limit triggers err       PASS");
        } else {
            fmt::Println!(
                "[ 2] limit triggers err       FAIL total={} err={}",
                total,
                last_err.Error()
            );
            failed += 1;
        }
    }

    // 3. Reads under the limit succeed cleanly.
    {
        let payload = bytes("hi");
        let buf = goish::bytes::NewBuffer(payload);
        let mut limited = http::NewMaxBytesReader(None, buf, 100);
        let mut out = goish::make!([]byte, 4);
        let (n, err) = limited.Read(&mut out);
        // Should read 2 bytes, no error.
        if n == 2 && err.IsNil() && out[0] == b'h' && out[1] == b'i' {
            fmt::Println!("[ 3] under-limit Read         PASS");
        } else {
            fmt::Println!("[ 3] under-limit Read         FAIL n={}", n);
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
