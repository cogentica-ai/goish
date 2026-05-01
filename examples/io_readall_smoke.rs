// io_readall_smoke — exercise io.ReadAll / ReadFull / ReadAtLeast.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::io;
use goish::strings;
use goish::{byte, string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ReadAll on a strings.Reader returns the full content.
    {
        let mut r = strings::NewReader(string("hello, world"));
        let (data, err) = io::ReadAll(&mut r);
        if err.IsNil() && data.Len() == 12 && data[0] == b'h' && data[11] == b'd' {
            Println!("[ 1] ReadAll body              PASS");
        } else {
            Println!("[ 1] ReadAll body              FAIL");
            failed += 1;
        }
    }

    // 2. ReadAll on an empty source returns zero bytes / no error.
    {
        let mut r = strings::NewReader(string(""));
        let (data, err) = io::ReadAll(&mut r);
        if err.IsNil() && data.Len() == 0 {
            Println!("[ 2] ReadAll empty             PASS");
        } else {
            Println!("[ 2] ReadAll empty             FAIL");
            failed += 1;
        }
    }

    // 3. ReadFull fills exactly len(buf) bytes.
    {
        let mut r = strings::NewReader(string("0123456789"));
        let mut p = goish::make!([]byte, 5);
        let (n, err) = io::ReadFull(&mut r, &mut p);
        if err.IsNil() && n == 5 && p[4] == b'4' {
            Println!("[ 3] ReadFull exact            PASS");
        } else {
            Println!("[ 3] ReadFull exact            FAIL");
            failed += 1;
        }
    }

    // 4. ReadFull on a too-short source returns ErrUnexpectedEOF.
    {
        let mut r = strings::NewReader(string("abc"));
        let mut p = goish::make!([]byte, 8);
        let (n, err) = io::ReadFull(&mut r, &mut p);
        let want = io::ErrUnexpectedEOF();
        if !err.IsNil() && err == want && n == 3 {
            Println!("[ 4] ReadFull unexpected EOF   PASS");
        } else {
            Println!("[ 4] ReadFull unexpected EOF   FAIL n={}", n);
            failed += 1;
        }
    }

    // 5. ReadAtLeast with min > buf returns ErrShortBuffer.
    {
        let mut r = strings::NewReader(string("data"));
        let mut p = goish::make!([]byte, 2);
        let (n, err) = io::ReadAtLeast(&mut r, &mut p, 5);
        let want = io::ErrShortBuffer();
        if !err.IsNil() && err == want && n == 0 {
            Println!("[ 5] ReadAtLeast short buf     PASS");
        } else {
            Println!("[ 5] ReadAtLeast short buf     FAIL");
            failed += 1;
        }
    }

    // 6. ReadAtLeast: EOF on exact min boundary returns nil err.
    {
        let mut r = strings::NewReader(string("xyz"));
        let mut p = goish::make!([]byte, 4);
        let (n, err) = io::ReadAtLeast(&mut r, &mut p, 3);
        if err.IsNil() && n == 3 && p[0] == b'x' && p[2] == b'z' {
            Println!("[ 6] ReadAtLeast min reached   PASS");
        } else {
            Println!("[ 6] ReadAtLeast min reached   FAIL n={}", n);
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
