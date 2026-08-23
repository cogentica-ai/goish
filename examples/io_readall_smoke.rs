// io_readall_smoke — exercise io.ReadAll / ReadFull / ReadAtLeast.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::fmt;
use goish::io;
use goish::strings;
use goish::{byte, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ReadAll on a strings.Reader returns the full content.
    {
        let mut r = strings::NewReader(string("hello, world"));
        let (data, err) = io::ReadAll(&mut r);
        if err.IsNil() && data.Len() == 12 && data[0] == b'h' && data[11] == b'd' {
            fmt::Println!("[ 1] ReadAll body              PASS");
        } else {
            fmt::Println!("[ 1] ReadAll body              FAIL");
            failed += 1;
        }
    }

    // 2. ReadAll on an empty source returns zero bytes / no error.
    {
        let mut r = strings::NewReader(string(""));
        let (data, err) = io::ReadAll(&mut r);
        if err.IsNil() && data.Len() == 0 {
            fmt::Println!("[ 2] ReadAll empty             PASS");
        } else {
            fmt::Println!("[ 2] ReadAll empty             FAIL");
            failed += 1;
        }
    }

    // 3. ReadFull fills exactly len(buf) bytes.
    {
        let mut r = strings::NewReader(string("0123456789"));
        let mut p = goish::make!([]byte, 5);
        let (n, err) = io::ReadFull(&mut r, &mut p);
        if err.IsNil() && n == 5 && p[4] == b'4' {
            fmt::Println!("[ 3] ReadFull exact            PASS");
        } else {
            fmt::Println!("[ 3] ReadFull exact            FAIL");
            failed += 1;
        }
    }

    // 4. ReadFull on a too-short source returns ErrUnexpectedEOF.
    {
        let mut r = strings::NewReader(string("abc"));
        let mut p = goish::make!([]byte, 8);
        let (n, err) = io::ReadFull(&mut r, &mut p);
        let want = io::ErrUnexpectedEOF;
        if !err.IsNil() && err == want && n == 3 {
            fmt::Println!("[ 4] ReadFull unexpected EOF   PASS");
        } else {
            fmt::Println!("[ 4] ReadFull unexpected EOF   FAIL n={}", n);
            failed += 1;
        }
    }

    // 5. ReadAtLeast with min > buf returns ErrShortBuffer.
    {
        let mut r = strings::NewReader(string("data"));
        let mut p = goish::make!([]byte, 2);
        let (n, err) = io::ReadAtLeast(&mut r, &mut p, 5);
        let want = io::ErrShortBuffer;
        if !err.IsNil() && err == want && n == 0 {
            fmt::Println!("[ 5] ReadAtLeast short buf     PASS");
        } else {
            fmt::Println!("[ 5] ReadAtLeast short buf     FAIL");
            failed += 1;
        }
    }

    // 6. ReadAtLeast: EOF on exact min boundary returns nil err.
    {
        let mut r = strings::NewReader(string("xyz"));
        let mut p = goish::make!([]byte, 4);
        let (n, err) = io::ReadAtLeast(&mut r, &mut p, 3);
        if err.IsNil() && n == 3 && p[0] == b'x' && p[2] == b'z' {
            fmt::Println!("[ 6] ReadAtLeast min reached   PASS");
        } else {
            fmt::Println!("[ 6] ReadAtLeast min reached   FAIL n={}", n);
            failed += 1;
        }
    }

    // 7. CopyN copies exactly n bytes when src has enough.
    {
        let mut r = strings::NewReader(string("0123456789"));
        let mut buf = bytes::NewBuffer(goish::make!([]byte, 0));
        let (n, err) = io::CopyN(&mut buf, &mut r, 4);
        if err.IsNil() && n == 4 && buf.String() == "0123" {
            fmt::Println!("[ 7] CopyN exact               PASS");
        } else {
            fmt::Println!(
                "[ 7] CopyN exact               FAIL n={} got={}",
                n,
                buf.String()
            );
            failed += 1;
        }
    }

    // 8. CopyN on too-short src returns EOF.
    {
        let mut r = strings::NewReader(string("ab"));
        let mut buf = bytes::NewBuffer(goish::make!([]byte, 0));
        let (n, err) = io::CopyN(&mut buf, &mut r, 5);
        let want = io::EOF;
        if !err.IsNil() && err == want && n == 2 {
            fmt::Println!("[ 8] CopyN short src=EOF       PASS");
        } else {
            fmt::Println!("[ 8] CopyN short src=EOF       FAIL n={}", n);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 8", failed);
        syscall::Exit(1);
    }
}
