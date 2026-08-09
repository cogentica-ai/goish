// io_helpers_smoke — exercise io::LimitReader / TeeReader / Discard /
// NopCloser (line-by-line ports of io.go:461 / :618 / :639 / :682).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes;
use goish::io::{self, Closer, Reader, Writer};
use goish::types::byte;
use goish::{errors, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. LimitReader stops at N bytes with EOF.
    {
        let src = bytes("0123456789abcdef"); // 16 bytes
        let r = goish::bytes::NewReader(src);
        let mut lr = io::LimitReader(r, 5);
        let mut out = goish::make!([]byte, 32);
        let (n, _) = lr.Read(&mut out);
        // Second read returns 0 + EOF.
        let (n2, err2) = lr.Read(&mut out);
        if n == 5 && n2 == 0 && errors::Is(err2, io::EOF) {
            Println!("[ 1] LimitReader stops         PASS");
        } else {
            Println!("[ 1] LimitReader stops         FAIL n={} n2={}", n, n2);
            failed += 1;
        }
    }

    // 2. LimitReader honors the remaining count across multiple reads.
    {
        let src = bytes("AAAAA");
        let r = goish::bytes::NewReader(src);
        let mut lr = io::LimitReader(r, 3);
        let mut out = goish::make!([]byte, 2);
        let (n1, _) = lr.Read(&mut out);
        let (n2, _) = lr.Read(&mut out);
        let (n3, e3) = lr.Read(&mut out);
        // 2 + 1 = 3, then EOF.
        if n1 == 2 && n2 == 1 && n3 == 0 && errors::Is(e3, io::EOF) {
            Println!("[ 2] LimitReader split         PASS");
        } else {
            Println!("[ 2] LimitReader split         FAIL");
            failed += 1;
        }
    }

    // 3. TeeReader mirrors reads to the side Writer.
    {
        let src = bytes("hello world");
        let r = goish::bytes::NewReader(src);
        let mut sink =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(alloc::vec::Vec::new()));
        let mut tee = io::TeeReader(r, &mut sink);
        let mut out = goish::make!([]byte, 32);
        let (n, _) = tee.Read(&mut out);
        let mirror = sink.Bytes();
        if n == 11 && mirror.Len() == 11 && mirror[0] == b'h' && mirror[10] == b'd' {
            Println!("[ 3] TeeReader mirrors         PASS");
        } else {
            Println!("[ 3] TeeReader mirrors         FAIL n={} m={}", n, mirror.Len());
            failed += 1;
        }
    }

    // 4. Discard accepts every Write without error.
    {
        let mut d = io::DiscardWriter();
        let (n, err) = d.Write(bytes("hello"));
        let (n2, err2) = d.Write(bytes(""));
        if n == 5 && err.IsNil() && n2 == 0 && err2.IsNil() {
            Println!("[ 4] Discard sinks             PASS");
        } else {
            Println!("[ 4] Discard sinks             FAIL");
            failed += 1;
        }
    }

    // 5. NopCloser wraps a Reader; Close is a no-op.
    {
        let src = bytes("abc");
        let r = goish::bytes::NewReader(src);
        let mut nc = io::NopCloser(r);
        let mut out = goish::make!([]byte, 8);
        let (n, _) = nc.Read(&mut out);
        let cerr = nc.Close();
        if n == 3 && cerr.IsNil() {
            Println!("[ 5] NopCloser Close noop      PASS");
        } else {
            Println!("[ 5] NopCloser Close noop      FAIL");
            failed += 1;
        }
    }

    // 6. io::Copy from a LimitReader bounds the copied length.
    {
        let src = bytes("0123456789abcdef");
        let r = goish::bytes::NewReader(src);
        let mut lr = io::LimitReader(r, 7);
        let mut sink =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(alloc::vec::Vec::new()));
        let (n, err) = io::Copy(&mut sink, &mut lr);
        if err.IsNil() && n == 7 && sink.Bytes().Len() == 7 {
            Println!("[ 6] Copy from LimitReader     PASS");
        } else {
            Println!("[ 6] Copy from LimitReader     FAIL n={}", n);
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
