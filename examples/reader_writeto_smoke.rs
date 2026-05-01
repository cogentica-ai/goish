// reader_writeto_smoke — exercise bytes.Reader.WriteTo and
// strings.Reader.WriteTo.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::io;
use goish::strings;
use goish::{make, string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. bytes.Reader.WriteTo drains tail to dst.
    {
        let mut r = bytes::NewReader(goish::convert::bytes("abcdef"));
        let mut dst = bytes::NewBuffer(make!([]goish::byte, 0));
        let (n, err) = r.WriteTo(&mut dst);
        if err.IsNil() && n == 6 && dst.String() == "abcdef" {
            Println!("[ 1] bytes.Reader.WriteTo      PASS");
        } else {
            Println!("[ 1] bytes.Reader.WriteTo      FAIL n={} dst={}", n, dst.String());
            failed += 1;
        }
    }

    // 2. After WriteTo, Reader.Len() reports zero.
    {
        let mut r = bytes::NewReader(goish::convert::bytes("xyz"));
        let mut dst = bytes::NewBuffer(make!([]goish::byte, 0));
        let _ = r.WriteTo(&mut dst);
        if r.Len() == 0 {
            Println!("[ 2] bytes.Reader exhausted    PASS");
        } else {
            Println!("[ 2] bytes.Reader exhausted    FAIL len={}", r.Len());
            failed += 1;
        }
    }

    // 3. WriteTo on already-drained Reader returns (0, nil).
    {
        let mut r = bytes::NewReader(goish::convert::bytes("a"));
        let mut dst = bytes::NewBuffer(make!([]goish::byte, 0));
        let _ = r.WriteTo(&mut dst);
        let mut dst2 = bytes::NewBuffer(make!([]goish::byte, 0));
        let (n, err) = r.WriteTo(&mut dst2);
        if err.IsNil() && n == 0 && dst2.Len() == 0 {
            Println!("[ 3] WriteTo on drained        PASS");
        } else {
            Println!("[ 3] WriteTo on drained        FAIL");
            failed += 1;
        }
    }

    // 4. strings.Reader.WriteTo drains the underlying string.
    {
        let mut r = strings::NewReader(string("hello"));
        let mut dst = bytes::NewBuffer(make!([]goish::byte, 0));
        let (n, err) = r.WriteTo(&mut dst);
        if err.IsNil() && n == 5 && dst.String() == "hello" {
            Println!("[ 4] strings.Reader.WriteTo    PASS");
        } else {
            Println!("[ 4] strings.Reader.WriteTo    FAIL n={}", n);
            failed += 1;
        }
    }

    // 5. WriterTo trait: usable through &mut dyn dispatch.
    {
        let mut r: bytes::Reader = bytes::NewReader(goish::convert::bytes("trait"));
        let mut dst = bytes::NewBuffer(make!([]goish::byte, 0));
        let (n, err) = io::WriterTo::WriteTo(&mut r, &mut dst);
        if err.IsNil() && n == 5 && dst.String() == "trait" {
            Println!("[ 5] io.WriterTo trait         PASS");
        } else {
            Println!("[ 5] io.WriterTo trait         FAIL");
            failed += 1;
        }
    }

    // 6. Mid-stream WriteTo respects the read cursor.
    {
        let mut r = bytes::NewReader(goish::convert::bytes("0123456789"));
        let mut scratch = make!([]goish::byte, 3);
        let _ = r.Read(&mut scratch); // advance past "012"
        let mut dst = bytes::NewBuffer(make!([]goish::byte, 0));
        let (n, _) = r.WriteTo(&mut dst);
        if n == 7 && dst.String() == "3456789" {
            Println!("[ 6] mid-stream WriteTo        PASS");
        } else {
            Println!("[ 6] mid-stream WriteTo        FAIL got={}", dst.String());
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
