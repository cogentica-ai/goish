// iotest_smoke — exercise testing/iotest reader wrappers.
// (testing/iotest/reader.go + reader_test.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::convert;
use goish::errors;
use goish::goslice::slice;
use goish::io::{self, Reader};
use goish::testing::iotest::{
    DataErrReader, ErrReader, ErrTimeout, HalfReader, OneByteReader, TimeoutReader,
};
use goish::types::byte;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. OneByteReader: reads exactly one byte per Read.
    {
        let buf = bytes::NewBufferString(string("Hello"));
        let mut obr = OneByteReader(buf);
        let mut b: slice<byte> = slice::__from_vec(alloc::vec![0u8; 3]);
        let (n, e) = obr.Read(&mut b);
        if n == 1 && e.IsNil() && b[0] == b'H' {
            Println!("[ 1] OneByteReader basic     PASS");
        } else {
            Println!("[ 1] OneByteReader basic     FAIL n={}", n);
            failed += 1;
        }
    }

    // 2. OneByteReader: drain to EOF.
    {
        let buf = bytes::NewBufferString(string("abc"));
        let mut obr = OneByteReader(buf);
        let mut b: slice<byte> = slice::__from_vec(alloc::vec![0u8; 3]);
        let mut got = alloc::vec::Vec::new();
        loop {
            let (n, e) = obr.Read(&mut b);
            if !e.IsNil() {
                if errors::Is(e, io::EOF) {
                    break;
                }
                Println!("[ 2] OneByteReader drain     FAIL unexpected err");
                syscall::Exit(1);
            }
            if n != 1 {
                Println!("[ 2] OneByteReader drain     FAIL got n={}", n);
                syscall::Exit(1);
            }
            got.push(b[0]);
        }
        if got == alloc::vec![b'a', b'b', b'c'] {
            Println!("[ 2] OneByteReader drain     PASS");
        } else {
            Println!("[ 2] OneByteReader drain     FAIL");
            failed += 1;
        }
    }

    // 3. HalfReader: reads (len(p)+1)/2 bytes.
    {
        let buf = bytes::NewBufferString(string("ABCD"));
        let mut hr = HalfReader(buf);
        let mut b: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4]);
        // (4+1)/2 == 2 bytes.
        let (n, e) = hr.Read(&mut b);
        if n == 2 && e.IsNil() && b[0] == b'A' && b[1] == b'B' {
            Println!("[ 3] HalfReader 2 of 4       PASS");
        } else {
            Println!("[ 3] HalfReader 2 of 4       FAIL n={}", n);
            failed += 1;
        }
    }

    // 4. HalfReader: with len 1, reads 1 byte ((1+1)/2 == 1).
    {
        let buf = bytes::NewBufferString(string("xy"));
        let mut hr = HalfReader(buf);
        let mut b: slice<byte> = slice::__from_vec(alloc::vec![0u8; 1]);
        let (n, e) = hr.Read(&mut b);
        if n == 1 && e.IsNil() && b[0] == b'x' {
            Println!("[ 4] HalfReader 1 of 1       PASS");
        } else {
            Println!("[ 4] HalfReader 1 of 1       FAIL n={}", n);
            failed += 1;
        }
    }

    // 5. TimeoutReader: 2nd Read returns ErrTimeout.
    {
        let buf = bytes::NewBufferString(string("Hello"));
        let mut tor = TimeoutReader(buf);
        let mut b: slice<byte> = slice::__from_vec(alloc::vec![0u8; 3]);
        let (n1, e1) = tor.Read(&mut b);
        let (n2, e2) = tor.Read(&mut b);
        // First call succeeds, second returns ErrTimeout (count == 2).
        let __ev_timeout_msg: goish::error = ErrTimeout.into(); let timeout_msg = __ev_timeout_msg.Error();
        if n1 > 0 && e1.IsNil() && n2 == 0 && !e2.IsNil() && e2.Error() == timeout_msg {
            Println!("[ 5] TimeoutReader 2nd call  PASS");
        } else {
            Println!("[ 5] TimeoutReader 2nd call  FAIL");
            failed += 1;
        }
    }

    // 6. TimeoutReader: 3rd call delegates again to underlying reader.
    {
        let buf = bytes::NewBufferString(string("Hello"));
        let mut tor = TimeoutReader(buf);
        let mut b: slice<byte> = slice::__from_vec(alloc::vec![0u8; 3]);
        let (_n1, _e1) = tor.Read(&mut b);
        let (_n2, _e2) = tor.Read(&mut b); // ErrTimeout
        let (n3, e3) = tor.Read(&mut b);
        if n3 > 0 && e3.IsNil() {
            Println!("[ 6] TimeoutReader 3rd call  PASS");
        } else {
            Println!("[ 6] TimeoutReader 3rd call  FAIL n={}", n3);
            failed += 1;
        }
    }

    // 7. ErrReader: returns (0, err) every time.
    {
        let sentinel = errors::New(string("io failure"));
        let mut er = ErrReader(sentinel.clone());
        let mut b: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4]);
        let (n, e) = er.Read(&mut b);
        if n == 0 && e.Error() == sentinel.Error() {
            Println!("[ 7] ErrReader returns err   PASS");
        } else {
            Println!("[ 7] ErrReader returns err   FAIL");
            failed += 1;
        }
    }

    // 8. ErrReader with EOF.
    {
        let mut er = ErrReader(io::EOF.into());
        let mut b: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4]);
        let (n, e) = er.Read(&mut b);
        if n == 0 && errors::Is(e, io::EOF) {
            Println!("[ 8] ErrReader EOF           PASS");
        } else {
            Println!("[ 8] ErrReader EOF           FAIL");
            failed += 1;
        }
    }

    // 9. DataErrReader: drains all data, EOF returned with last data (not next).
    {
        let buf = bytes::NewBufferString(string("Hello, World!"));
        let mut der = DataErrReader(buf);
        let mut b: slice<byte> = slice::__from_vec(alloc::vec![0u8; 3]);
        let mut got = alloc::vec::Vec::new();
        let mut last_n: i64;
        let mut last_err: goish::error;
        loop {
            let (n, e) = der.Read(&mut b);
            for i in 0..n as usize {
                got.push(b[i as i64]);
            }
            last_n = n;
            last_err = e.clone();
            if !e.IsNil() {
                break;
            }
        }
        // last call should have n>0 AND err==EOF.
        let want = convert::bytes("Hello, World!");
        let want_raw: &[byte] = &want;
        if last_n > 0 && errors::Is(last_err, io::EOF) && got.as_slice() == want_raw {
            Println!("[ 9] DataErrReader drain     PASS");
        } else {
            Println!("[ 9] DataErrReader drain     FAIL last_n={}", last_n);
            failed += 1;
        }
    }

    // 10. DataErrReader on empty source: first Read returns (0, EOF).
    {
        let buf = bytes::NewBufferString(string(""));
        let mut der = DataErrReader(buf);
        let mut b: slice<byte> = slice::__from_vec(alloc::vec![0u8; 5]);
        let (n, e) = der.Read(&mut b);
        if n == 0 && errors::Is(e, io::EOF) {
            Println!("[10] DataErrReader empty     PASS");
        } else {
            Println!("[10] DataErrReader empty     FAIL n={}", n);
            failed += 1;
        }
    }

    // 11. ErrTimeout sentinel constant message.
    {
        let e1: goish::error = ErrTimeout.into();
        let e2: goish::error = ErrTimeout.into();
        if e1.Error() == string("timeout") && e2.Error() == string("timeout") {
            Println!("[11] ErrTimeout message      PASS");
        } else {
            Println!("[11] ErrTimeout message      FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 11/11");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 11");
        syscall::Exit(1);
    }
}
