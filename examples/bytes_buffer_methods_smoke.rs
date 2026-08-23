// bytes_buffer_methods_smoke — exercise Buffer.Truncate / ReadByte /
// UnreadByte / ReadBytes / ReadString.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::fmt;
use goish::syscall;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Truncate keeps first n unread bytes.
    {
        let mut b = bytes::NewBufferString("0123456789");
        b.Truncate(4);
        if b.String() == "0123" && b.Len() == 4 {
            fmt::Println!("[ 1] Truncate keeps prefix     PASS");
        } else {
            fmt::Println!("[ 1] Truncate keeps prefix     FAIL got={}", b.String());
            failed += 1;
        }
    }

    // 2. Truncate(0) resets the buffer.
    {
        let mut b = bytes::NewBufferString("hello");
        b.Truncate(0);
        if b.Len() == 0 {
            fmt::Println!("[ 2] Truncate(0) resets        PASS");
        } else {
            fmt::Println!("[ 2] Truncate(0) resets        FAIL");
            failed += 1;
        }
    }

    // 3. ReadByte yields each byte then EOF.
    {
        let mut b = bytes::NewBufferString("ab");
        let (c1, e1) = b.ReadByte();
        let (c2, e2) = b.ReadByte();
        let (c3, e3) = b.ReadByte();
        let eof = goish::io::EOF;
        if c1 == b'a' && e1.IsNil() && c2 == b'b' && e2.IsNil() && c3 == 0 && e3 == eof {
            fmt::Println!("[ 3] ReadByte sequence + EOF   PASS");
        } else {
            fmt::Println!("[ 3] ReadByte sequence + EOF   FAIL");
            failed += 1;
        }
    }

    // 4. UnreadByte after ReadByte rewinds one byte.
    {
        let mut b = bytes::NewBufferString("xyz");
        let (_, _) = b.ReadByte();
        let err = b.UnreadByte();
        let (c, _) = b.ReadByte();
        if err.IsNil() && c == b'x' {
            fmt::Println!("[ 4] UnreadByte rewinds        PASS");
        } else {
            fmt::Println!("[ 4] UnreadByte rewinds        FAIL");
            failed += 1;
        }
    }

    // 5. UnreadByte at start returns an error.
    {
        let mut b = bytes::NewBufferString("a");
        let err = b.UnreadByte();
        if !err.IsNil() {
            fmt::Println!("[ 5] UnreadByte at start err   PASS");
        } else {
            fmt::Println!("[ 5] UnreadByte at start err   FAIL");
            failed += 1;
        }
    }

    // 6. ReadBytes returns up-to-and-including the delimiter.
    {
        let mut b = bytes::NewBufferString("foo,bar,baz");
        let (line, err) = b.ReadBytes(b',');
        if err.IsNil() && line.Len() == 4 && line[0] == b'f' && line[3] == b',' {
            fmt::Println!("[ 6] ReadBytes incl delim      PASS");
        } else {
            fmt::Println!("[ 6] ReadBytes incl delim      FAIL n={}", line.Len());
            failed += 1;
        }
    }

    // 7. ReadString without delim returns rest + io.EOF.
    {
        let mut b = bytes::NewBufferString("notfound");
        let (s, err) = b.ReadString(b'\n');
        let eof = goish::io::EOF;
        if err == eof && s == "notfound" {
            fmt::Println!("[ 7] ReadString no delim → EOF PASS");
        } else {
            fmt::Println!("[ 7] ReadString no delim → EOF FAIL got={}", s);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 7", failed);
        syscall::Exit(1);
    }
}
