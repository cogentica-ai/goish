// bytes_buffer_more_smoke — exercise Buffer.Next, Available,
// AvailableBuffer, ReadRune, UnreadRune.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::fmt;
use goish::io;
use goish::{make, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Next(n) returns the next n bytes and advances the cursor.
    {
        let mut b = bytes::NewBufferString(string("abcdefgh"));
        let head = b.Next(3);
        if head.Len() == 3
            && head[0] == b'a'
            && head[1] == b'b'
            && head[2] == b'c'
            && b.String() == "defgh"
        {
            fmt::Println!("[ 1] Next(3)                   PASS");
        } else {
            fmt::Println!("[ 1] Next(3)                   FAIL");
            failed += 1;
        }
    }

    // 2. Next(big) returns whole remaining buffer.
    {
        let mut b = bytes::NewBufferString(string("hi"));
        let all = b.Next(100);
        if all.Len() == 2 && b.Len() == 0 {
            fmt::Println!("[ 2] Next(big)                 PASS");
        } else {
            fmt::Println!("[ 2] Next(big)                 FAIL got_len={}", all.Len());
            failed += 1;
        }
    }

    // 3. Next(0) returns empty slice and doesn't advance.
    {
        let mut b = bytes::NewBufferString(string("xyz"));
        let none = b.Next(0);
        if none.Len() == 0 && b.Len() == 3 {
            fmt::Println!("[ 3] Next(0)                   PASS");
        } else {
            fmt::Println!("[ 3] Next(0)                   FAIL");
            failed += 1;
        }
    }

    // 4. Available reports cap-len after Grow.
    {
        let mut b = bytes::NewBuffer(make!([]goish::byte, 0));
        b.Grow(64);
        if b.Available() >= 64 {
            fmt::Println!("[ 4] Available after Grow      PASS");
        } else {
            fmt::Println!("[ 4] Available after Grow      FAIL got={}", b.Available());
            failed += 1;
        }
    }

    // 5. AvailableBuffer returns empty slice<byte> (slim contract).
    {
        let b = bytes::NewBuffer(make!([]goish::byte, 0));
        let buf = b.AvailableBuffer();
        if buf.Len() == 0 {
            fmt::Println!("[ 5] AvailableBuffer empty     PASS");
        } else {
            fmt::Println!("[ 5] AvailableBuffer empty     FAIL");
            failed += 1;
        }
    }

    // 6. ReadRune on ASCII byte returns (r, 1, nil.into()).
    {
        let mut b = bytes::NewBufferString(string("Ab"));
        let (r, n, err) = b.ReadRune();
        if err.IsNil() && r == 'A' as goish::rune && n == 1 && b.String() == "b" {
            fmt::Println!("[ 6] ReadRune ASCII            PASS");
        } else {
            fmt::Println!("[ 6] ReadRune ASCII            FAIL r={} n={}", r, n);
            failed += 1;
        }
    }

    // 7. ReadRune on UTF-8 multi-byte rune ("é" = 0xC3 0xA9).
    {
        let mut b = bytes::NewBuffer(make!([]goish::byte, 0));
        let _ = b.WriteRune(0x00E9 as goish::rune); // 'é'
        let (r, n, err) = b.ReadRune();
        if err.IsNil() && r == 0x00E9 && n == 2 && b.Len() == 0 {
            fmt::Println!("[ 7] ReadRune UTF-8 2-byte     PASS");
        } else {
            fmt::Println!("[ 7] ReadRune UTF-8 2-byte     FAIL r={} n={}", r, n);
            failed += 1;
        }
    }

    // 8. ReadRune on empty buffer returns (0, 0, EOF).
    {
        let mut b = bytes::NewBuffer(make!([]goish::byte, 0));
        let (r, n, err) = b.ReadRune();
        if !err.IsNil() && r == 0 && n == 0 && goish::errors::Is(err, io::EOF) {
            fmt::Println!("[ 8] ReadRune empty EOF        PASS");
        } else {
            fmt::Println!("[ 8] ReadRune empty EOF        FAIL");
            failed += 1;
        }
    }

    // 9. UnreadRune after ReadRune restores cursor.
    {
        let mut b = bytes::NewBufferString(string("xy"));
        let _ = b.ReadRune();
        let err = b.UnreadRune();
        if err.IsNil() && b.String() == "xy" {
            fmt::Println!("[ 9] UnreadRune restores       PASS");
        } else {
            fmt::Println!("[ 9] UnreadRune restores       FAIL");
            failed += 1;
        }
    }

    // 10. UnreadRune without prior ReadRune returns error.
    {
        let mut b = bytes::NewBufferString(string("a"));
        let err = b.UnreadRune();
        if !err.IsNil() {
            fmt::Println!("[10] UnreadRune unprovoked     PASS");
        } else {
            fmt::Println!("[10] UnreadRune unprovoked     FAIL");
            failed += 1;
        }
    }

    // 11. UnreadRune fails after a write.
    {
        let mut b = bytes::NewBufferString(string("z"));
        let _ = b.ReadRune();
        let _ = b.WriteByte(b'q');
        let err = b.UnreadRune();
        if !err.IsNil() {
            fmt::Println!("[11] UnreadRune after write    PASS");
        } else {
            fmt::Println!("[11] UnreadRune after write    FAIL");
            failed += 1;
        }
    }

    // 12. Round-trip: WriteRune(é) → ReadRune(é) → UnreadRune → ReadRune(é).
    {
        let mut b = bytes::NewBuffer(make!([]goish::byte, 0));
        let _ = b.WriteRune(0x00E9 as goish::rune);
        let (r1, _, _) = b.ReadRune();
        let _ = b.UnreadRune();
        let (r2, _, _) = b.ReadRune();
        if r1 == 0x00E9 && r2 == 0x00E9 && b.Len() == 0 {
            fmt::Println!("[12] WriteRune+RR+UR+RR        PASS");
        } else {
            fmt::Println!("[12] WriteRune+RR+UR+RR        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 12", failed);
        syscall::Exit(1);
    }
}
