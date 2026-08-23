// io_traits_smoke — exercise the new io trait declarations and the
// bytes.Reader Seek / ReadAt impls.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::fmt;
use goish::io::{self};
use goish::strings;
use goish::{byte, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. SeekStart / SeekCurrent / SeekEnd constants are 0/1/2.
    {
        if io::SeekStart == 0 && io::SeekCurrent == 1 && io::SeekEnd == 2 {
            fmt::Println!("[ 1] Seek* constants           PASS");
        } else {
            fmt::Println!("[ 1] Seek* constants           FAIL");
            failed += 1;
        }
    }

    // 2. bytes.Reader satisfies Seeker.
    {
        let mut r = bytes::NewReader(goish::convert::bytes("0123456789"));
        let (pos, err) = io::Seeker::Seek(&mut r, 4, io::SeekStart);
        if err.IsNil() && pos == 4 {
            let mut buf = goish::make!([]byte, 2);
            let _ = r.Read(&mut buf);
            if buf[0] == b'4' && buf[1] == b'5' {
                fmt::Println!("[ 2] Reader Seek+Read          PASS");
            } else {
                fmt::Println!("[ 2] Reader Seek+Read          FAIL bytes");
                failed += 1;
            }
        } else {
            fmt::Println!("[ 2] Reader Seek+Read          FAIL pos={}", pos);
            failed += 1;
        }
    }

    // 3. bytes.Reader satisfies ReaderAt.
    {
        let mut r = bytes::NewReader(goish::convert::bytes("ABCDEF"));
        let mut p = goish::make!([]byte, 3);
        let (n, err) = io::ReaderAt::ReadAt(&mut r, &mut p, 2);
        if err.IsNil() && n == 3 && p[0] == b'C' && p[1] == b'D' && p[2] == b'E' {
            fmt::Println!("[ 3] Reader ReadAt offset      PASS");
        } else {
            fmt::Println!("[ 3] Reader ReadAt offset      FAIL");
            failed += 1;
        }
    }

    // 4. ReadAt past end returns EOF.
    {
        let mut r = bytes::NewReader(goish::convert::bytes("xy"));
        let mut p = goish::make!([]byte, 4);
        let (n, err) = io::ReaderAt::ReadAt(&mut r, &mut p, 5);
        let eof = io::EOF;
        if n == 0 && err == eof {
            fmt::Println!("[ 4] ReadAt past end → EOF     PASS");
        } else {
            fmt::Println!("[ 4] ReadAt past end → EOF     FAIL");
            failed += 1;
        }
    }

    // 5. bytes.Buffer satisfies ByteReader / ByteScanner trait.
    {
        let mut b = bytes::NewBufferString("zz");
        let (c, err) = io::ByteReader::ReadByte(&mut b);
        let unread_err = io::ByteScanner::UnreadByte(&mut b);
        let (c2, _) = io::ByteReader::ReadByte(&mut b);
        if err.IsNil() && unread_err.IsNil() && c == b'z' && c2 == b'z' {
            fmt::Println!("[ 5] Buffer ByteScanner trait  PASS");
        } else {
            fmt::Println!("[ 5] Buffer ByteScanner trait  FAIL");
            failed += 1;
        }
    }

    // 6. bytes.Buffer satisfies ByteWriter / StringWriter.
    {
        let mut b = bytes::Buffer::new();
        let _ = io::ByteWriter::WriteByte(&mut b, b'A');
        let _ = io::StringWriter::WriteString(&mut b, string("BC"));
        if b.String() == "ABC" {
            fmt::Println!("[ 6] Buffer ByteWriter trait   PASS");
        } else {
            fmt::Println!("[ 6] Buffer ByteWriter trait   FAIL got={}", b.String());
            failed += 1;
        }
    }

    // 7. strings.Reader satisfies Seeker.
    {
        let mut r = strings::NewReader(string("0123456789"));
        let (pos, err) = io::Seeker::Seek(&mut r, 7, io::SeekStart);
        if err.IsNil() && pos == 7 {
            let mut buf = goish::make!([]byte, 2);
            let _ = r.Read(&mut buf);
            if buf[0] == b'7' && buf[1] == b'8' {
                fmt::Println!("[ 7] strings Reader Seek       PASS");
            } else {
                fmt::Println!("[ 7] strings Reader Seek       FAIL bytes");
                failed += 1;
            }
        } else {
            fmt::Println!("[ 7] strings Reader Seek       FAIL pos={}", pos);
            failed += 1;
        }
    }

    // 8. strings.Reader satisfies ReaderAt.
    {
        let mut r = strings::NewReader(string("hello"));
        let mut p = goish::make!([]byte, 3);
        let (n, err) = io::ReaderAt::ReadAt(&mut r, &mut p, 1);
        if err.IsNil() && n == 3 && p[0] == b'e' && p[1] == b'l' && p[2] == b'l' {
            fmt::Println!("[ 8] strings Reader ReadAt     PASS");
        } else {
            fmt::Println!("[ 8] strings Reader ReadAt     FAIL");
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
