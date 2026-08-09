// binary_varint_smoke — exercise encoding/binary varint + AppendUint*.
// (varint.go:41, 68, 91, 115; binary.go AppendUint16/32/64)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::fmt;
use goish::encoding::binary;
use goish::goslice::slice;
use goish::types::{byte, int, uint};
use goish::{syscall};

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. AppendUvarint round-trip — small (< 0x80, single byte).
    {
        let buf = binary::AppendUvarint(empty_buf(), 0x42);
        if buf.Len() == 1 && buf[0] == 0x42 {
            fmt::Println!("[ 1] AppendUvarint small       PASS");
        } else {
            fmt::Println!("[ 1] AppendUvarint small       FAIL");
            failed += 1;
        }
    }

    // 2. AppendUvarint — 150 spans 2 bytes (0x96 0x01).
    {
        let buf = binary::AppendUvarint(empty_buf(), 150);
        if buf.Len() == 2 && buf[0] == 0x96 && buf[1] == 0x01 {
            fmt::Println!("[ 2] AppendUvarint 150         PASS");
        } else {
            fmt::Println!("[ 2] AppendUvarint 150         FAIL");
            failed += 1;
        }
    }

    // 3. AppendUvarint round-trip — verifies Uvarint decode matches.
    {
        let values: [uint; 6] = [0, 1, 127, 128, 16384, 1_000_000_000];
        let mut all_ok = true;
        for v in values {
            let buf = binary::AppendUvarint(empty_buf(), v);
            let (got, n) = binary::Uvarint(buf.clone());
            if got != v || n <= 0 || n != buf.Len() {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            fmt::Println!("[ 3] Uvarint round-trip        PASS");
        } else {
            fmt::Println!("[ 3] Uvarint round-trip        FAIL");
            failed += 1;
        }
    }

    // 4. Uvarint empty buf → (0, 0).
    {
        let (v, n) = binary::Uvarint(empty_buf());
        if v == 0 && n == 0 {
            fmt::Println!("[ 4] Uvarint empty             PASS");
        } else {
            fmt::Println!("[ 4] Uvarint empty             FAIL");
            failed += 1;
        }
    }

    // 5. AppendVarint round-trip — positive + negative + zero.
    {
        let values: [int; 5] = [0, 1, -1, 100, -100];
        let mut all_ok = true;
        for v in values {
            let buf = binary::AppendVarint(empty_buf(), v);
            let (got, n) = binary::Varint(buf);
            if got != v || n <= 0 {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            fmt::Println!("[ 5] Varint round-trip         PASS");
        } else {
            fmt::Println!("[ 5] Varint round-trip         FAIL");
            failed += 1;
        }
    }

    // 6. AppendVarint — zig-zag encoding (-1 → 0x01).
    {
        let buf = binary::AppendVarint(empty_buf(), -1);
        if buf.Len() == 1 && buf[0] == 0x01 {
            fmt::Println!("[ 6] AppendVarint -1           PASS");
        } else {
            fmt::Println!("[ 6] AppendVarint -1           FAIL");
            failed += 1;
        }
    }

    // 7. MaxVarintLen* constants.
    {
        if binary::MaxVarintLen16 == 3
            && binary::MaxVarintLen32 == 5
            && binary::MaxVarintLen64 == 10
        {
            fmt::Println!("[ 7] MaxVarintLenN             PASS");
        } else {
            fmt::Println!("[ 7] MaxVarintLenN             FAIL");
            failed += 1;
        }
    }

    // 8. BigEndian.AppendUint16.
    {
        let buf = binary::BigEndian.AppendUint16(empty_buf(), 0x1234);
        if buf.Len() == 2 && buf[0] == 0x12 && buf[1] == 0x34 {
            fmt::Println!("[ 8] BE.AppendUint16           PASS");
        } else {
            fmt::Println!("[ 8] BE.AppendUint16           FAIL");
            failed += 1;
        }
    }

    // 9. BigEndian.AppendUint32.
    {
        let buf = binary::BigEndian.AppendUint32(empty_buf(), 0xDEADBEEF);
        if buf.Len() == 4
            && buf[0] == 0xDE
            && buf[1] == 0xAD
            && buf[2] == 0xBE
            && buf[3] == 0xEF
        {
            fmt::Println!("[ 9] BE.AppendUint32           PASS");
        } else {
            fmt::Println!("[ 9] BE.AppendUint32           FAIL");
            failed += 1;
        }
    }

    // 10. BigEndian.AppendUint64.
    {
        let buf = binary::BigEndian.AppendUint64(empty_buf(), 0x0102030405060708);
        if buf.Len() == 8
            && buf[0] == 0x01
            && buf[7] == 0x08
        {
            fmt::Println!("[10] BE.AppendUint64           PASS");
        } else {
            fmt::Println!("[10] BE.AppendUint64           FAIL");
            failed += 1;
        }
    }

    // 11. LittleEndian.AppendUint32 (byte-order flip).
    {
        let buf = binary::LittleEndian.AppendUint32(empty_buf(), 0xDEADBEEF);
        if buf.Len() == 4
            && buf[0] == 0xEF
            && buf[1] == 0xBE
            && buf[2] == 0xAD
            && buf[3] == 0xDE
        {
            fmt::Println!("[11] LE.AppendUint32           PASS");
        } else {
            fmt::Println!("[11] LE.AppendUint32           FAIL");
            failed += 1;
        }
    }

    // 12. AppendUint16 builds on existing buf (preserves prefix).
    {
        let prefix: alloc::vec::Vec<byte> = alloc::vec![0xAA, 0xBB];
        let buf = binary::BigEndian.AppendUint16(slice::__from_vec(prefix), 0x1234);
        if buf.Len() == 4
            && buf[0] == 0xAA
            && buf[1] == 0xBB
            && buf[2] == 0x12
            && buf[3] == 0x34
        {
            fmt::Println!("[12] AppendUint16 prefix       PASS");
        } else {
            fmt::Println!("[12] AppendUint16 prefix       FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
