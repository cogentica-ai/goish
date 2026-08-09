// bytes_buffer_io_smoke — exercise Buffer.ReadFrom + Buffer.WriteTo
// + MinRead constant.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::bytes;
use goish::io;
use goish::{make, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. MinRead constant matches Go.
    {
        if bytes::MinRead == 512 {
            fmt::Println!("[ 1] MinRead == 512            PASS");
        } else {
            fmt::Println!("[ 1] MinRead == 512            FAIL got={}", bytes::MinRead);
            failed += 1;
        }
    }

    // 2. ReadFrom drains a bytes.Reader fully.
    {
        let mut src = bytes::NewReader(goish::convert::bytes("hello world"));
        let mut buf = bytes::NewBuffer(make!([]goish::byte, 0));
        let (n, err) = buf.ReadFrom(&mut src);
        if err.IsNil() && n == 11 && buf.String() == "hello world" {
            fmt::Println!("[ 2] ReadFrom drains source    PASS");
        } else {
            fmt::Println!("[ 2] ReadFrom drains source    FAIL n={} body={}", n, buf.String());
            failed += 1;
        }
    }

    // 3. ReadFrom from empty reader returns (0, nil.into()).
    {
        let mut src = bytes::NewReader(make!([]goish::byte, 0));
        let mut buf = bytes::NewBuffer(make!([]goish::byte, 0));
        let (n, err) = buf.ReadFrom(&mut src);
        if err.IsNil() && n == 0 && buf.Len() == 0 {
            fmt::Println!("[ 3] ReadFrom empty            PASS");
        } else {
            fmt::Println!("[ 3] ReadFrom empty            FAIL");
            failed += 1;
        }
    }

    // 4. WriteTo drains buffer into a destination Buffer.
    {
        let mut src = bytes::NewBufferString(string("payload bytes"));
        let mut dst = bytes::NewBuffer(make!([]goish::byte, 0));
        let (n, err) = src.WriteTo(&mut dst);
        if err.IsNil() && n == 13 && dst.String() == "payload bytes" && src.Len() == 0 {
            fmt::Println!("[ 4] WriteTo drains            PASS");
        } else {
            fmt::Println!("[ 4] WriteTo drains            FAIL n={}", n);
            failed += 1;
        }
    }

    // 5. WriteTo on empty buffer returns (0, nil.into()) without writes.
    {
        let mut src = bytes::NewBuffer(make!([]goish::byte, 0));
        let mut dst = bytes::NewBuffer(make!([]goish::byte, 0));
        let (n, err) = src.WriteTo(&mut dst);
        if err.IsNil() && n == 0 && dst.Len() == 0 {
            fmt::Println!("[ 5] WriteTo empty             PASS");
        } else {
            fmt::Println!("[ 5] WriteTo empty             FAIL");
            failed += 1;
        }
    }

    // 6. Round-trip: ReadFrom then WriteTo preserves bytes.
    {
        let original = "round-trip-data";
        let mut src = bytes::NewReader(goish::convert::bytes(original));
        let mut mid = bytes::NewBuffer(make!([]goish::byte, 0));
        let _ = mid.ReadFrom(&mut src);
        let mut dst = bytes::NewBuffer(make!([]goish::byte, 0));
        let (_, _) = mid.WriteTo(&mut dst);
        if dst.String() == original {
            fmt::Println!("[ 6] round-trip preserves      PASS");
        } else {
            fmt::Println!("[ 6] round-trip preserves      FAIL got={}", dst.String());
            failed += 1;
        }
    }

    // 7. Buffer satisfies io.ReaderFrom and io.WriterTo traits.
    {
        let mut src = bytes::NewReader(goish::convert::bytes("trait-fast-path"));
        let mut buf = bytes::NewBuffer(make!([]goish::byte, 0));
        let (n, err) = io::ReaderFrom::ReadFrom(&mut buf, &mut src);
        if err.IsNil() && n == 15 && buf.String() == "trait-fast-path" {
            fmt::Println!("[ 7] trait ReaderFrom          PASS");
        } else {
            fmt::Println!("[ 7] trait ReaderFrom          FAIL");
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
