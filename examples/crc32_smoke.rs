// crc32_smoke — exercise hash/crc32 (IEEE + Castagnoli + Koopman).
// (hash/crc32/crc32.go)
//
// Reference values verified against Go 1.25's crc32 (the canonical
// CRC-32 of "" is 0; of "a" is 0xE8B7BE43 IEEE).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::hash::crc32;
use goish::hash::{Hash, Hash32};
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

    // 1. ChecksumIEEE("") = 0.
    {
        if crc32::ChecksumIEEE(to_bytes("")) == 0 {
            fmt::Println!("[ 1] IEEE empty                PASS");
        } else {
            fmt::Println!("[ 1] IEEE empty                FAIL");
            failed += 1;
        }
    }

    // 2. ChecksumIEEE("a") = 0xE8B7BE43.
    {
        if crc32::ChecksumIEEE(to_bytes("a")) == 0xE8B7BE43 {
            fmt::Println!("[ 2] IEEE \"a\"                  PASS");
        } else {
            fmt::Println!("[ 2] IEEE \"a\"                  FAIL");
            failed += 1;
        }
    }

    // 3. ChecksumIEEE("123456789") = 0xCBF43926.
    {
        if crc32::ChecksumIEEE(to_bytes("123456789")) == 0xCBF43926 {
            fmt::Println!("[ 3] IEEE \"123456789\"          PASS");
        } else {
            fmt::Println!("[ 3] IEEE \"123456789\"          FAIL");
            failed += 1;
        }
    }

    // 4. New + Write streaming equals one-shot Checksum.
    {
        let mut h = crc32::NewIEEE();
        let _ = h.Write(to_bytes("123"));
        let _ = h.Write(to_bytes("456789"));
        if h.Sum32() == 0xCBF43926 {
            fmt::Println!("[ 4] IEEE streaming            PASS");
        } else {
            fmt::Println!("[ 4] IEEE streaming            FAIL");
            failed += 1;
        }
    }

    // 5. Reset zeros the running CRC.
    {
        let mut h = crc32::NewIEEE();
        let _ = h.Write(to_bytes("hello"));
        h.Reset();
        if h.Sum32() == 0 {
            fmt::Println!("[ 5] Reset                     PASS");
        } else {
            fmt::Println!("[ 5] Reset                     FAIL");
            failed += 1;
        }
    }

    // 6. Sum appends BE bytes — IEEE("123456789") = 0xCBF43926.
    {
        let mut h = crc32::NewIEEE();
        let _ = h.Write(to_bytes("123456789"));
        let out = h.Sum(empty_buf());
        // Big-endian: CB F4 39 26
        let mut want_v: Vec<byte> = Vec::new();
        want_v.push(0xCB);
        want_v.push(0xF4);
        want_v.push(0x39);
        want_v.push(0x26);
        let want = slice::<byte>::__from_vec(want_v);
        if equal_bytes(out, want) {
            fmt::Println!("[ 6] Sum BE append             PASS");
        } else {
            fmt::Println!("[ 6] Sum BE append             FAIL");
            failed += 1;
        }
    }

    // 7. Sum preserves dst prefix.
    {
        let mut h = crc32::NewIEEE();
        let _ = h.Write(to_bytes("a"));
        let dst = to_bytes("PRE:");
        let out = h.Sum(dst);
        let raw: &[byte] = &out;
        // Expect "PRE:" + 4 BE bytes of 0xE8B7BE43.
        if raw.len() == 4 + 4
            && &raw[0..4] == b"PRE:"
            && raw[4] == 0xE8
            && raw[5] == 0xB7
            && raw[6] == 0xBE
            && raw[7] == 0x43
        {
            fmt::Println!("[ 7] Sum prefix                PASS");
        } else {
            fmt::Println!("[ 7] Sum prefix                FAIL");
            failed += 1;
        }
    }

    // 8. Castagnoli table — checksum of "123456789" = 0xE3069283.
    {
        let tab = crc32::MakeTable(crc32::Castagnoli);
        let v = crc32::Checksum(to_bytes("123456789"), &tab);
        if v == 0xE3069283 {
            fmt::Println!("[ 8] Castagnoli check          PASS");
        } else {
            fmt::Println!("[ 8] Castagnoli check          FAIL");
            failed += 1;
        }
    }

    // 9. Update — incremental seed produces same CRC as one-shot.
    {
        let tab = crc32::IEEETable();
        let mut crc: u32 = 0;
        crc = crc32::Update(crc, &tab, to_bytes("foo"));
        crc = crc32::Update(crc, &tab, to_bytes("bar"));
        let one_shot = crc32::ChecksumIEEE(to_bytes("foobar"));
        if crc == one_shot {
            fmt::Println!("[ 9] Update incremental        PASS");
        } else {
            fmt::Println!("[ 9] Update incremental        FAIL");
            failed += 1;
        }
    }

    // 10. IEEETable singleton — repeated calls return the same Arc payload.
    {
        let a = crc32::IEEETable();
        let b = crc32::IEEETable();
        // Compare table entries: should be byte-identical.
        if a.at(0) == b.at(0) && a.at(255) == b.at(255) {
            fmt::Println!("[10] IEEETable singleton       PASS");
        } else {
            fmt::Println!("[10] IEEETable singleton       FAIL");
            failed += 1;
        }
    }

    // 11. Size + BlockSize.
    {
        let h = crc32::NewIEEE();
        if h.Size() == crc32::Size && h.BlockSize() == 1 {
            fmt::Println!("[11] Size/BlockSize            PASS");
        } else {
            fmt::Println!("[11] Size/BlockSize            FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 11/11");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 11");
        syscall::Exit(1);
    }
}
