// reader_byte_rune_smoke — exercise ReadByte/UnreadByte/ReadRune/
// UnreadRune on bytes.Reader and strings.Reader.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::bytes;
use goish::io;
use goish::strings;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // ─── bytes.Reader ─────────────────────────────────────────────

    // 1. bytes.Reader.ReadByte returns sequential bytes.
    {
        let mut r = bytes::NewReader(goish::convert::bytes("AB"));
        let (b1, e1) = r.ReadByte();
        let (b2, e2) = r.ReadByte();
        let (_, e3) = r.ReadByte();
        if e1.IsNil() && e2.IsNil() && b1 == b'A' && b2 == b'B' && goish::errors::Is(e3, io::EOF) {
            fmt::Println!("[ 1] bytes.Reader ReadByte     PASS");
        } else {
            fmt::Println!("[ 1] bytes.Reader ReadByte     FAIL");
            failed += 1;
        }
    }

    // 2. bytes.Reader.UnreadByte after ReadByte rewinds.
    {
        let mut r = bytes::NewReader(goish::convert::bytes("X"));
        let _ = r.ReadByte();
        let err = r.UnreadByte();
        let (b2, _) = r.ReadByte();
        if err.IsNil() && b2 == b'X' {
            fmt::Println!("[ 2] bytes.Reader UnreadByte   PASS");
        } else {
            fmt::Println!("[ 2] bytes.Reader UnreadByte   FAIL");
            failed += 1;
        }
    }

    // 3. bytes.Reader.UnreadByte at start returns error.
    {
        let mut r = bytes::NewReader(goish::convert::bytes("hi"));
        let err = r.UnreadByte();
        if !err.IsNil() {
            fmt::Println!("[ 3] UnreadByte at start       PASS");
        } else {
            fmt::Println!("[ 3] UnreadByte at start       FAIL");
            failed += 1;
        }
    }

    // 4. bytes.Reader.ReadRune ASCII fast-path.
    {
        let mut r = bytes::NewReader(goish::convert::bytes("z"));
        let (ch, sz, err) = r.ReadRune();
        if err.IsNil() && ch == 'z' as goish::rune && sz == 1 {
            fmt::Println!("[ 4] bytes.Reader ReadRune ASC PASS");
        } else {
            fmt::Println!("[ 4] bytes.Reader ReadRune ASC FAIL");
            failed += 1;
        }
    }

    // 5. bytes.Reader.ReadRune multi-byte rune ("é" 0xC3 0xA9).
    {
        let mut buf: alloc::vec::Vec<goish::byte> = alloc::vec::Vec::new();
        buf.extend_from_slice(b"a\xc3\xa9b");
        let s = goish::goslice::slice::__from_vec(buf);
        let mut r = bytes::NewReader(s);
        let _ = r.ReadByte(); // skip 'a'
        let (ch, sz, _) = r.ReadRune();
        if ch == 0x00E9 && sz == 2 {
            fmt::Println!("[ 5] bytes.Reader ReadRune utf PASS");
        } else {
            fmt::Println!("[ 5] bytes.Reader ReadRune utf FAIL ch={} sz={}", ch, sz);
            failed += 1;
        }
    }

    // 6. bytes.Reader.UnreadRune after ReadRune restores cursor.
    {
        let mut r = bytes::NewReader(goish::convert::bytes("ab"));
        let _ = r.ReadRune();
        let err = r.UnreadRune();
        let (ch, _, _) = r.ReadRune();
        if err.IsNil() && ch == 'a' as goish::rune {
            fmt::Println!("[ 6] bytes.Reader UnreadRune   PASS");
        } else {
            fmt::Println!("[ 6] bytes.Reader UnreadRune   FAIL");
            failed += 1;
        }
    }

    // 7. UnreadRune fails after a ReadByte (not the most recent op).
    {
        let mut r = bytes::NewReader(goish::convert::bytes("ab"));
        let _ = r.ReadRune();
        let _ = r.ReadByte();
        let err = r.UnreadRune();
        if !err.IsNil() {
            fmt::Println!("[ 7] UnreadRune after ReadByte PASS");
        } else {
            fmt::Println!("[ 7] UnreadRune after ReadByte FAIL");
            failed += 1;
        }
    }

    // 8. bytes.Reader EOF on empty ReadRune.
    {
        let mut r = bytes::NewReader(goish::convert::bytes(""));
        let (ch, sz, err) = r.ReadRune();
        if !err.IsNil() && ch == 0 && sz == 0 {
            fmt::Println!("[ 8] bytes.Reader empty ReadRune PASS");
        } else {
            fmt::Println!("[ 8] bytes.Reader empty ReadRune FAIL");
            failed += 1;
        }
    }

    // ─── strings.Reader ───────────────────────────────────────────

    // 9. strings.Reader.ReadByte returns sequential bytes.
    {
        let mut r = strings::NewReader(string("CD"));
        let (b1, _) = r.ReadByte();
        let (b2, _) = r.ReadByte();
        if b1 == b'C' && b2 == b'D' {
            fmt::Println!("[ 9] strings.Reader ReadByte   PASS");
        } else {
            fmt::Println!("[ 9] strings.Reader ReadByte   FAIL");
            failed += 1;
        }
    }

    // 10. strings.Reader.UnreadByte rewinds.
    {
        let mut r = strings::NewReader(string("Z"));
        let _ = r.ReadByte();
        let err = r.UnreadByte();
        let (b2, _) = r.ReadByte();
        if err.IsNil() && b2 == b'Z' {
            fmt::Println!("[10] strings.Reader UnreadByte PASS");
        } else {
            fmt::Println!("[10] strings.Reader UnreadByte FAIL");
            failed += 1;
        }
    }

    // 11. strings.Reader.ReadRune ASCII fast-path.
    {
        let mut r = strings::NewReader(string("Q"));
        let (ch, sz, err) = r.ReadRune();
        if err.IsNil() && ch == 'Q' as goish::rune && sz == 1 {
            fmt::Println!("[11] strings.Reader ReadRune A PASS");
        } else {
            fmt::Println!("[11] strings.Reader ReadRune A FAIL");
            failed += 1;
        }
    }

    // 12. strings.Reader.ReadRune multi-byte rune.
    {
        let mut buf: alloc::vec::Vec<goish::byte> = alloc::vec::Vec::new();
        buf.extend_from_slice(b"\xc3\xa9");
        let s = goish::gostring::string::from_bytes(&buf);
        let mut r = strings::NewReader(s);
        let (ch, sz, _) = r.ReadRune();
        if ch == 0x00E9 && sz == 2 {
            fmt::Println!("[12] strings.Reader ReadRune u PASS");
        } else {
            fmt::Println!("[12] strings.Reader ReadRune u FAIL");
            failed += 1;
        }
    }

    // 13. strings.Reader.UnreadRune restores cursor.
    {
        let mut r = strings::NewReader(string("ab"));
        let _ = r.ReadRune();
        let err = r.UnreadRune();
        let (ch, _, _) = r.ReadRune();
        if err.IsNil() && ch == 'a' as goish::rune {
            fmt::Println!("[13] strings.Reader UnreadRune PASS");
        } else {
            fmt::Println!("[13] strings.Reader UnreadRune FAIL");
            failed += 1;
        }
    }

    // 14. strings.Reader UnreadRune unprovoked error.
    {
        let mut r = strings::NewReader(string("xy"));
        let _ = r.ReadByte();
        let err = r.UnreadRune();
        if !err.IsNil() {
            fmt::Println!("[14] strings UnreadRune err    PASS");
        } else {
            fmt::Println!("[14] strings UnreadRune err    FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 14/14");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 14", failed);
        syscall::Exit(1);
    }
}
