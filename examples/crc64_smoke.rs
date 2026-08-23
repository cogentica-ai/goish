// crc64_smoke — exercise hash/crc64 (ISO + ECMA polynomials).
// (hash/crc64/crc64.go)
//
// Reference values cribbed from Go 1.25's hash/crc64/crc64_test.go
// `golden` table. Format: (ISO, ECMA, input).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::hash::crc64;
use goish::hash::{Hash, Hash64};
use goish::io::Writer as _;
use goish::syscall;
use goish::types::byte;

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

fn equal_bytes(a: slice<byte>, b: slice<byte>) -> bool {
    let aa: &[byte] = &a;
    let bb: &[byte] = &b;
    aa == bb
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ISO Checksum("") = 0.
    {
        let tab = crc64::ISOTable();
        if crc64::Checksum(to_bytes(""), &tab) == 0 {
            fmt::Println!("[ 1] ISO empty                 PASS");
        } else {
            fmt::Println!("[ 1] ISO empty                 FAIL");
            failed += 1;
        }
    }

    // 2. ECMA Checksum("") = 0.
    {
        let tab = crc64::ECMATable();
        if crc64::Checksum(to_bytes(""), &tab) == 0 {
            fmt::Println!("[ 2] ECMA empty                PASS");
        } else {
            fmt::Println!("[ 2] ECMA empty                FAIL");
            failed += 1;
        }
    }

    // 3. ISO Checksum("a") = 0x3420000000000000.
    {
        let tab = crc64::ISOTable();
        if crc64::Checksum(to_bytes("a"), &tab) == 0x3420000000000000 {
            fmt::Println!("[ 3] ISO \"a\"                   PASS");
        } else {
            fmt::Println!("[ 3] ISO \"a\"                   FAIL");
            failed += 1;
        }
    }

    // 4. ECMA Checksum("a") = 0x330284772e652b05.
    {
        let tab = crc64::ECMATable();
        if crc64::Checksum(to_bytes("a"), &tab) == 0x330284772e652b05 {
            fmt::Println!("[ 4] ECMA \"a\"                  PASS");
        } else {
            fmt::Println!("[ 4] ECMA \"a\"                  FAIL");
            failed += 1;
        }
    }

    // 5. ECMA Checksum("abc") = 0x2cd8094a1a277627.
    {
        let tab = crc64::ECMATable();
        if crc64::Checksum(to_bytes("abc"), &tab) == 0x2cd8094a1a277627 {
            fmt::Println!("[ 5] ECMA \"abc\"                PASS");
        } else {
            fmt::Println!("[ 5] ECMA \"abc\"                FAIL");
            failed += 1;
        }
    }

    // 6. ISO Checksum("abcdefghij") = 0x7f5b6e21b002d367.
    {
        let tab = crc64::ISOTable();
        if crc64::Checksum(to_bytes("abcdefghij"), &tab) == 0x7f5b6e21b002d367 {
            fmt::Println!("[ 6] ISO \"abcdefghij\"          PASS");
        } else {
            fmt::Println!("[ 6] ISO \"abcdefghij\"          FAIL");
            failed += 1;
        }
    }

    // 7. New + streaming Write equals one-shot Checksum.
    {
        let tab = crc64::ECMATable();
        let mut h = crc64::New(tab.clone());
        let _ = h.Write(to_bytes("ab"));
        let _ = h.Write(to_bytes("c"));
        if h.Sum64() == 0x2cd8094a1a277627 {
            fmt::Println!("[ 7] ECMA streaming            PASS");
        } else {
            fmt::Println!("[ 7] ECMA streaming            FAIL");
            failed += 1;
        }
    }

    // 8. Reset zeros the running CRC.
    {
        let tab = crc64::ISOTable();
        let mut h = crc64::New(tab);
        let _ = h.Write(to_bytes("hello"));
        h.Reset();
        if h.Sum64() == 0 {
            fmt::Println!("[ 8] Reset                     PASS");
        } else {
            fmt::Println!("[ 8] Reset                     FAIL");
            failed += 1;
        }
    }

    // 9. Sum appends 8 BE bytes — ECMA "a" = 0x330284772e652b05.
    {
        let tab = crc64::ECMATable();
        let mut h = crc64::New(tab);
        let _ = h.Write(to_bytes("a"));
        let out = h.Sum(empty_buf());
        let mut want_v: Vec<byte> = Vec::new();
        want_v.push(0x33);
        want_v.push(0x02);
        want_v.push(0x84);
        want_v.push(0x77);
        want_v.push(0x2e);
        want_v.push(0x65);
        want_v.push(0x2b);
        want_v.push(0x05);
        let want = slice::<byte>::__from_vec(want_v);
        if equal_bytes(out, want) {
            fmt::Println!("[ 9] Sum BE 8-byte append      PASS");
        } else {
            fmt::Println!("[ 9] Sum BE 8-byte append      FAIL");
            failed += 1;
        }
    }

    // 10. Sum preserves dst prefix.
    {
        let tab = crc64::ECMATable();
        let mut h = crc64::New(tab);
        let _ = h.Write(to_bytes("a"));
        let dst = to_bytes("PRE:");
        let out = h.Sum(dst);
        let raw: &[byte] = &out;
        if raw.len() == 4 + 8 && &raw[0..4] == b"PRE:" && raw[4] == 0x33 && raw[11] == 0x05 {
            fmt::Println!("[10] Sum prefix                PASS");
        } else {
            fmt::Println!("[10] Sum prefix                FAIL");
            failed += 1;
        }
    }

    // 11. Update — incremental seed produces same CRC as one-shot.
    {
        let tab = crc64::ECMATable();
        let mut crc: u64 = 0;
        crc = crc64::Update(crc, &tab, to_bytes("foo"));
        crc = crc64::Update(crc, &tab, to_bytes("bar"));
        let mut h = crc64::New(tab);
        let _ = h.Write(to_bytes("foobar"));
        if crc == h.Sum64() {
            fmt::Println!("[11] Update incremental        PASS");
        } else {
            fmt::Println!("[11] Update incremental        FAIL");
            failed += 1;
        }
    }

    // 12. ISOTable / ECMATable singletons return identical entries.
    {
        let a = crc64::ISOTable();
        let b = crc64::ISOTable();
        let c = crc64::ECMATable();
        // Same poly → entries match; different poly → entries differ.
        if a.at(1) == b.at(1) && a.at(255) == b.at(255) && a.at(1) != c.at(1) {
            fmt::Println!("[12] Table singletons          PASS");
        } else {
            fmt::Println!("[12] Table singletons          FAIL");
            failed += 1;
        }
    }

    // 13. Size + BlockSize.
    {
        let tab = crc64::ISOTable();
        let h = crc64::New(tab);
        if h.Size() == crc64::Size && h.BlockSize() == 1 {
            fmt::Println!("[13] Size/BlockSize            PASS");
        } else {
            fmt::Println!("[13] Size/BlockSize            FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 13/13");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 13");
        syscall::Exit(1);
    }
}
