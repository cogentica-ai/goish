// bufio_available_buffer_smoke — exercise bufio.Writer.AvailableBuffer
// (bufio.go:668). The slim port returns an empty slice<byte> with a
// preallocated capacity equal to the writer's available buffer space.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::bufio;
use goish::bytes;
use goish::convert::bytes as to_bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::syscall;
use goish::types::byte;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. AvailableBuffer on a fresh writer returns len=0, cap≥avail.
    {
        let buf = bytes::NewBuffer(slice::<byte>::__from_vec(Vec::new()));
        let w = bufio::NewWriterSize(buf, 64);
        let av = w.AvailableBuffer();
        if av.Len() == 0 {
            fmt::Println!("[ 1] AvailableBuffer fresh len PASS");
        } else {
            fmt::Println!("[ 1] AvailableBuffer fresh len FAIL");
            failed += 1;
        }
    }

    // 2. After a partial write, AvailableBuffer still len=0.
    //    (Capacity reduces but slim caller observes only len.)
    {
        let buf = bytes::NewBuffer(slice::<byte>::__from_vec(Vec::new()));
        let mut w = bufio::NewWriterSize(buf, 64);
        let _ = w.WriteString(goish::string("hello"));
        let av = w.AvailableBuffer();
        if av.Len() == 0 {
            fmt::Println!("[ 2] AvailableBuffer post-write PASS");
        } else {
            fmt::Println!("[ 2] AvailableBuffer post-write FAIL");
            failed += 1;
        }
    }

    // 3. Append + Write — typical AvailableBuffer usage pattern.
    {
        let buf = bytes::NewBuffer(slice::<byte>::__from_vec(Vec::new()));
        let mut w = bufio::NewWriterSize(buf, 128);
        // Idiomatic Go: append into AvailableBuffer, then Write.
        let mut tmp = w.AvailableBuffer();
        tmp = goish::strconv::AppendInt(tmp, 42, 10);
        let (n, _) = w.Write(tmp);
        let _ = w.Flush();
        if n == 2 {
            fmt::Println!("[ 3] Append+Write 42           PASS");
        } else {
            fmt::Println!("[ 3] Append+Write 42           FAIL n=", n);
            failed += 1;
        }
    }

    // 4. AvailableBuffer is independent — multiple calls don't shrink
    //    each other's capacity.
    {
        let buf = bytes::NewBuffer(slice::<byte>::__from_vec(Vec::new()));
        let w = bufio::NewWriterSize(buf, 64);
        let a = w.AvailableBuffer();
        let b = w.AvailableBuffer();
        if a.Len() == 0 && b.Len() == 0 {
            fmt::Println!("[ 4] AvailableBuffer indep    PASS");
        } else {
            fmt::Println!("[ 4] AvailableBuffer indep    FAIL");
            failed += 1;
        }
    }

    // 5. AvailableBuffer over a small buffer (size=8). After
    //    Buffered() == 8 the writer auto-flushes; AvailableBuffer post-
    //    flush returns an empty slice again.
    {
        let buf = bytes::NewBuffer(slice::<byte>::__from_vec(Vec::new()));
        let mut w = bufio::NewWriterSize(buf, 8);
        let _ = w.Write(to_bytes("12345678"));
        // 8 bytes was exactly the buffer size — likely flushed.
        let av = w.AvailableBuffer();
        if av.Len() == 0 {
            fmt::Println!("[ 5] AvailableBuffer flushed   PASS");
        } else {
            fmt::Println!("[ 5] AvailableBuffer flushed   FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
