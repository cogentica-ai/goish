// io_copy_buffer_smoke — exercise io.CopyBuffer.
//
// Validates the line-by-line port of io/io.go:398:
//   • CopyBuffer with caller-supplied buffer: full data round-trip,
//     return value = (total bytes, nil.into()).
//   • CopyBuffer with empty buffer: allocates 32 KiB internally;
//     same behavior as Copy.
//   • Multi-iteration loop: small caller buffer forces multiple
//     Read/Write rounds.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::convert;
use goish::fmt;
use goish::io;
use goish::{make, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. CopyBuffer with caller-supplied 16-byte buffer copies all bytes.
    {
        let mut src = bytes::NewReader(convert::bytes("Hello, world!"));
        let mut dst = bytes::Buffer::new();
        let buf = make!([]goish::byte, 16);
        let (n, err) = io::CopyBuffer(&mut dst, &mut src, buf);
        if err.IsNil() && n == 13 && dst.String() == "Hello, world!" {
            fmt::Println!("[ 1] CopyBuffer 16-byte buf    PASS");
        } else {
            fmt::Println!(
                "[ 1] CopyBuffer 16-byte buf    FAIL n={} dst={}",
                n,
                dst.String()
            );
            failed += 1;
        }
    }

    // 2. CopyBuffer with tiny 4-byte buffer forces multiple iterations.
    {
        let mut src = bytes::NewReader(convert::bytes("ABCDEFGH"));
        let mut dst = bytes::Buffer::new();
        let buf = make!([]goish::byte, 4);
        let (n, err) = io::CopyBuffer(&mut dst, &mut src, buf);
        if err.IsNil() && n == 8 && dst.String() == "ABCDEFGH" {
            fmt::Println!("[ 2] CopyBuffer 4-byte loops   PASS");
        } else {
            fmt::Println!("[ 2] CopyBuffer 4-byte loops   FAIL n={}", n);
            failed += 1;
        }
    }

    // 3. CopyBuffer with len-0 buffer: internal default 32 KiB allocated.
    {
        let mut src = bytes::NewReader(convert::bytes("x"));
        let mut dst = bytes::Buffer::new();
        let buf = make!([]goish::byte, 0);
        let (n, err) = io::CopyBuffer(&mut dst, &mut src, buf);
        if err.IsNil() && n == 1 && dst.String() == "x" {
            fmt::Println!("[ 3] CopyBuffer len=0 default  PASS");
        } else {
            fmt::Println!("[ 3] CopyBuffer len=0 default  FAIL");
            failed += 1;
        }
    }

    // 4. CopyBuffer of empty source returns (0, nil.into()).
    {
        let mut src = bytes::NewReader(convert::bytes(""));
        let mut dst = bytes::Buffer::new();
        let buf = make!([]goish::byte, 64);
        let (n, err) = io::CopyBuffer(&mut dst, &mut src, buf);
        if err.IsNil() && n == 0 && dst.String() == "" {
            fmt::Println!("[ 4] CopyBuffer empty source   PASS");
        } else {
            fmt::Println!("[ 4] CopyBuffer empty source   FAIL");
            failed += 1;
        }
    }

    // 5. CopyBuffer total matches input total for larger payload.
    {
        let mut payload_v: alloc::vec::Vec<goish::byte> = alloc::vec::Vec::new();
        for i in 0..1024i32 {
            payload_v.push((i % 251) as goish::byte);
        }
        let payload = goish::goslice::slice::__from_vec(payload_v);
        let mut src = bytes::NewReader(payload.clone());
        let mut dst = bytes::Buffer::new();
        let buf = make!([]goish::byte, 100);
        let (n, err) = io::CopyBuffer(&mut dst, &mut src, buf);
        let bytes_out = dst.Bytes();
        let mut all_ok = bytes_out.Len() == 1024;
        if all_ok {
            for i in 0..1024i32 {
                if bytes_out[i as goish::int] != (i % 251) as goish::byte {
                    all_ok = false;
                    break;
                }
            }
        }
        if err.IsNil() && n == 1024 && all_ok {
            fmt::Println!("[ 5] CopyBuffer 1024 round     PASS");
        } else {
            fmt::Println!("[ 5] CopyBuffer 1024 round     FAIL n={}", n);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 5", failed);
        syscall::Exit(1);
    }
}
