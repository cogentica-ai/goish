// io_section_reader_smoke — exercise io.NewSectionReader.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use goish::bytes;
use goish::io::{self, ReaderAt};
use goish::{byte, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Read of full window.
    {
        let r: Box<dyn ReaderAt> = Box::new(bytes::NewReader(goish::convert::bytes("0123456789")));
        let mut sr = io::NewSectionReader(r, 2, 5);
        if sr.Size() == 5 {
            let mut p = goish::make!([]byte, 5);
            let (n, err) = sr.Read(&mut p);
            if err.IsNil() && n == 5 && p[0] == b'2' && p[4] == b'6' {
                Println!("[ 1] Section Read full         PASS");
            } else {
                Println!("[ 1] Section Read full         FAIL n={}", n);
                failed += 1;
            }
        } else {
            Println!("[ 1] Section Read full         FAIL size={}", sr.Size());
            failed += 1;
        }
    }

    // 2. Read past window returns EOF.
    {
        let r: Box<dyn ReaderAt> = Box::new(bytes::NewReader(goish::convert::bytes("0123456789")));
        let mut sr = io::NewSectionReader(r, 2, 3);
        let mut p = goish::make!([]byte, 5);
        let (n, _) = sr.Read(&mut p);
        // First read should give 3 bytes.
        let (n2, e2) = sr.Read(&mut p);
        let eof = io::EOF;
        if n == 3 && n2 == 0 && e2 == eof {
            Println!("[ 2] Section EOF after window  PASS");
        } else {
            Println!("[ 2] Section EOF after window  FAIL n={} n2={}", n, n2);
            failed += 1;
        }
    }

    // 3. Seek SeekStart positions correctly.
    {
        let r: Box<dyn ReaderAt> = Box::new(bytes::NewReader(goish::convert::bytes("ABCDEFGHIJ")));
        let mut sr = io::NewSectionReader(r, 3, 5);
        let (pos, err) = sr.Seek(1, io::SeekStart);
        if err.IsNil() && pos == 1 {
            let mut p = goish::make!([]byte, 1);
            let _ = sr.Read(&mut p);
            // base=3, sought to offset 1 → absolute 4 → 'E'.
            if p[0] == b'E' {
                Println!("[ 3] Section Seek+Read         PASS");
            } else {
                Println!("[ 3] Section Seek+Read         FAIL got={}", p[0]);
                failed += 1;
            }
        } else {
            Println!("[ 3] Section Seek+Read         FAIL pos={}", pos);
            failed += 1;
        }
    }

    // 4. ReadAt at random offset within window.
    {
        let r: Box<dyn ReaderAt> = Box::new(bytes::NewReader(goish::convert::bytes("ABCDEFGHIJ")));
        let mut sr = io::NewSectionReader(r, 2, 6);
        let mut p = goish::make!([]byte, 2);
        let (n, err) = sr.ReadAt(&mut p, 3);
        // base=2 + off=3 → absolute 5 → 'F','G'.
        if err.IsNil() && n == 2 && p[0] == b'F' && p[1] == b'G' {
            Println!("[ 4] Section ReadAt window     PASS");
        } else {
            Println!("[ 4] Section ReadAt window     FAIL");
            failed += 1;
        }
    }

    // 5. ReadAt past Size returns EOF.
    {
        let r: Box<dyn ReaderAt> = Box::new(bytes::NewReader(goish::convert::bytes("xyz")));
        let mut sr = io::NewSectionReader(r, 0, 2);
        let mut p = goish::make!([]byte, 1);
        let (n, err) = sr.ReadAt(&mut p, 5);
        let eof = io::EOF;
        if n == 0 && err == eof {
            Println!("[ 5] ReadAt past Size → EOF    PASS");
        } else {
            Println!("[ 5] ReadAt past Size → EOF    FAIL");
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
