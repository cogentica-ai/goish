// io_multi_smoke — exercise io.MultiReader and io.MultiWriter (slim).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use goish::bytes;
use goish::goslice::slice;
use goish::io::{self, Reader, Writer};
use goish::strings;
use goish::{byte, string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. MultiReader concatenates two strings.Reader into "hello, world".
    {
        let mut v: alloc::vec::Vec<Box<dyn Reader>> = alloc::vec::Vec::new();
        v.push(Box::new(strings::NewReader(string("hello, "))));
        v.push(Box::new(strings::NewReader(string("world"))));
        let readers: slice<Box<dyn Reader>> = slice::__from_vec(v);
        let mut mr = io::MultiReader(readers);

        // Drain into a Buffer via io::Copy.
        let mut buf = bytes::NewBuffer(goish::make!([]byte, 0));
        let (n, err) = io::Copy(&mut buf, &mut mr);
        if err.IsNil() && n == 12 && buf.String() == "hello, world" {
            Println!("[ 1] MultiReader concat        PASS");
        } else {
            Println!(
                "[ 1] MultiReader concat        FAIL n={} got={}",
                n,
                buf.String()
            );
            failed += 1;
        }
    }

    // 2. MultiReader with empty list returns EOF immediately.
    {
        let v: alloc::vec::Vec<Box<dyn Reader>> = alloc::vec::Vec::new();
        let readers: slice<Box<dyn Reader>> = slice::__from_vec(v);
        let mut mr = io::MultiReader(readers);
        let mut p = goish::make!([]byte, 4);
        let (n, err) = mr.Read(&mut p);
        let eof = io::EOF();
        if n == 0 && err == eof {
            Println!("[ 2] MultiReader empty=EOF     PASS");
        } else {
            Println!("[ 2] MultiReader empty=EOF     FAIL");
            failed += 1;
        }
    }

    // 3. MultiWriter fans a write out to two buffers.
    {
        let mut v: alloc::vec::Vec<Box<dyn Writer>> = alloc::vec::Vec::new();
        v.push(Box::new(bytes::NewBuffer(goish::make!([]byte, 0))));
        v.push(Box::new(bytes::NewBuffer(goish::make!([]byte, 0))));
        let writers: slice<Box<dyn Writer>> = slice::__from_vec(v);
        let mut mw = io::MultiWriter(writers);
        let payload = goish::convert::bytes("tee-output");
        let (n, err) = mw.Write(payload);
        if err.IsNil() && n == 10 {
            Println!("[ 3] MultiWriter Write returns PASS");
        } else {
            Println!("[ 3] MultiWriter Write returns FAIL n={}", n);
            failed += 1;
        }
    }

    // 4. MultiWriter with no writers is a no-op.
    {
        let v: alloc::vec::Vec<Box<dyn Writer>> = alloc::vec::Vec::new();
        let writers: slice<Box<dyn Writer>> = slice::__from_vec(v);
        let mut mw = io::MultiWriter(writers);
        let payload = goish::convert::bytes("x");
        let (n, err) = mw.Write(payload);
        if err.IsNil() && n == 1 {
            Println!("[ 4] MultiWriter empty noop    PASS");
        } else {
            Println!("[ 4] MultiWriter empty noop    FAIL n={}", n);
            failed += 1;
        }
    }

    // 5. MultiReader: reading exact-size chunks crosses reader boundary.
    {
        let mut v: alloc::vec::Vec<Box<dyn Reader>> = alloc::vec::Vec::new();
        v.push(Box::new(strings::NewReader(string("ab"))));
        v.push(Box::new(strings::NewReader(string("cd"))));
        let readers: slice<Box<dyn Reader>> = slice::__from_vec(v);
        let mut mr = io::MultiReader(readers);

        let mut p1 = goish::make!([]byte, 2);
        let (n1, e1) = mr.Read(&mut p1);
        let mut p2 = goish::make!([]byte, 2);
        let (n2, e2) = mr.Read(&mut p2);
        let mut p3 = goish::make!([]byte, 2);
        let (n3, e3) = mr.Read(&mut p3);

        let eof = io::EOF();
        // First two reads should yield 2 bytes each, third should be EOF.
        if n1 == 2 && e1.IsNil()
            && n2 == 2 && (e2.IsNil() || e2 == eof.clone())
            && n3 == 0 && e3 == eof
            && p1[0] == b'a' && p1[1] == b'b'
            && p2[0] == b'c' && p2[1] == b'd'
        {
            Println!("[ 5] MultiReader boundaries    PASS");
        } else {
            Println!(
                "[ 5] MultiReader boundaries    FAIL n1={} n2={} n3={}",
                n1, n2, n3
            );
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 5", failed);
        syscall::Exit(1);
    }
}
