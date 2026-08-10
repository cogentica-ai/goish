// subtle_smoke — exercise crypto/subtle.
// (crypto/subtle/constant_time.go + xor.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::crypto::subtle::{
    ConstantTimeByteEq, ConstantTimeCompare, ConstantTimeCopy, ConstantTimeEq,
    ConstantTimeLessOrEq, ConstantTimeSelect, XORBytes,
};
// Go keeps ConstantTimeLessOrEqBytes in the FIPS module only; crypto/subtle
// does not re-export it (crypto/internal/fips140/subtle/constant_time.go:34).
use goish::crypto::internal::fips140::subtle::ConstantTimeLessOrEqBytes;
use goish::goslice::slice;
use goish::types::byte;
use goish::{convert, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ConstantTimeCompare equal/unequal/length-mismatch.
    {
        let a = convert::bytes("hello");
        let b = convert::bytes("hello");
        let c = convert::bytes("world");
        let d = convert::bytes("hellox");
        let r1 = ConstantTimeCompare(&a, &b); // equal
        let r2 = ConstantTimeCompare(&a, &c); // diff content
        let r3 = ConstantTimeCompare(&a, &d); // length mismatch
        if r1 == 1 && r2 == 0 && r3 == 0 {
            fmt::Println!("[ 1] Compare                   PASS");
        } else {
            fmt::Println!("[ 1] Compare                   FAIL r1={} r2={} r3={}", r1, r2, r3);
            failed += 1;
        }
    }

    // 2. ConstantTimeByteEq.
    {
        let r1 = ConstantTimeByteEq(0x42, 0x42);
        let r2 = ConstantTimeByteEq(0x42, 0x43);
        let r3 = ConstantTimeByteEq(0xff, 0xff);
        let r4 = ConstantTimeByteEq(0x00, 0xff);
        if r1 == 1 && r2 == 0 && r3 == 1 && r4 == 0 {
            fmt::Println!("[ 2] ByteEq                    PASS");
        } else {
            fmt::Println!("[ 2] ByteEq                    FAIL");
            failed += 1;
        }
    }

    // 3. ConstantTimeEq (i32).
    {
        let r1 = ConstantTimeEq(0, 0);
        let r2 = ConstantTimeEq(123, 123);
        let r3 = ConstantTimeEq(-1, -1);
        let r4 = ConstantTimeEq(123, 124);
        let r5 = ConstantTimeEq(i32::MAX, i32::MAX);
        let r6 = ConstantTimeEq(i32::MAX, i32::MIN);
        if r1 == 1 && r2 == 1 && r3 == 1 && r4 == 0 && r5 == 1 && r6 == 0 {
            fmt::Println!("[ 3] Eq (i32)                  PASS");
        } else {
            fmt::Println!("[ 3] Eq (i32)                  FAIL");
            failed += 1;
        }
    }

    // 4. ConstantTimeSelect: v=1→x, v=0→y.
    {
        let r1 = ConstantTimeSelect(1, 100, 200);
        let r2 = ConstantTimeSelect(0, 100, 200);
        let r3 = ConstantTimeSelect(1, -5, 7);
        let r4 = ConstantTimeSelect(0, -5, 7);
        if r1 == 100 && r2 == 200 && r3 == -5 && r4 == 7 {
            fmt::Println!("[ 4] Select                    PASS");
        } else {
            fmt::Println!("[ 4] Select                    FAIL");
            failed += 1;
        }
    }

    // 5. ConstantTimeLessOrEq.
    {
        let r1 = ConstantTimeLessOrEq(5, 10);  // 1
        let r2 = ConstantTimeLessOrEq(10, 10); // 1
        let r3 = ConstantTimeLessOrEq(11, 10); // 0
        let r4 = ConstantTimeLessOrEq(0, 0);   // 1
        if r1 == 1 && r2 == 1 && r3 == 0 && r4 == 1 {
            fmt::Println!("[ 5] LessOrEq                  PASS");
        } else {
            fmt::Println!("[ 5] LessOrEq                  FAIL");
            failed += 1;
        }
    }

    // 6. ConstantTimeCopy with v=1 copies; v=0 leaves unchanged.
    {
        let mut x: slice<byte> = slice::__from_vec(alloc::vec![0u8, 0u8, 0u8, 0u8]);
        let y = convert::bytes("YYYY");
        ConstantTimeCopy(1, &mut x, &y);
        let raw: &[byte] = &x;
        let ok1 = raw == b"YYYY";

        let mut x2: slice<byte> = slice::__from_vec(alloc::vec![b'A', b'B', b'C', b'D']);
        let y2 = convert::bytes("ZZZZ");
        ConstantTimeCopy(0, &mut x2, &y2);
        let raw2: &[byte] = &x2;
        let ok2 = raw2 == b"ABCD";

        if ok1 && ok2 {
            fmt::Println!("[ 6] Copy                      PASS");
        } else {
            fmt::Println!("[ 6] Copy                      FAIL");
            failed += 1;
        }
    }

    // 7. XORBytes correctness.
    {
        let x: slice<byte> =
            slice::__from_vec(alloc::vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let y: slice<byte> =
            slice::__from_vec(alloc::vec![0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8]);
        let mut dst: slice<byte> = slice::__from_vec(alloc::vec![0u8; 8]);
        let n = XORBytes(&mut dst, &x, &y);
        let raw: &[byte] = &dst;
        let want: &[u8] = &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        if n == 8 && raw == want {
            fmt::Println!("[ 7] XORBytes                  PASS");
        } else {
            fmt::Println!("[ 7] XORBytes                  FAIL n={}", n);
            failed += 1;
        }
    }

    // 8. XORBytes with shorter y → only min(len) bytes written.
    {
        let x: slice<byte> = slice::__from_vec(alloc::vec![0xaa, 0xaa, 0xaa, 0xaa]);
        let y: slice<byte> = slice::__from_vec(alloc::vec![0x55, 0x55]);
        let mut dst: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4]);
        let n = XORBytes(&mut dst, &x, &y);
        let raw: &[byte] = &dst;
        // Only first 2 bytes XOR'd; rest left untouched (== 0).
        let want: &[u8] = &[0xff, 0xff, 0x00, 0x00];
        if n == 2 && raw == want {
            fmt::Println!("[ 8] XORBytes shorter          PASS");
        } else {
            fmt::Println!("[ 8] XORBytes shorter          FAIL n={}", n);
            failed += 1;
        }
    }

    // 9. ConstantTimeLessOrEqBytes — single block (≤8 bytes).
    {
        let a: slice<byte> = slice::__from_vec(alloc::vec![0x00, 0x00, 0x05]);
        let b: slice<byte> = slice::__from_vec(alloc::vec![0x00, 0x00, 0x05]);
        let c: slice<byte> = slice::__from_vec(alloc::vec![0x00, 0x00, 0x06]);
        let d: slice<byte> = slice::__from_vec(alloc::vec![0x00, 0x00, 0x04]);
        let e: slice<byte> = slice::__from_vec(alloc::vec![0x00, 0x00, 0x05, 0x00]);
        let r1 = ConstantTimeLessOrEqBytes(&a, &b);
        let r2 = ConstantTimeLessOrEqBytes(&a, &c);
        let r3 = ConstantTimeLessOrEqBytes(&a, &d);
        let r4 = ConstantTimeLessOrEqBytes(&a, &e);
        if r1 == 1 && r2 == 1 && r3 == 0 && r4 == 0 {
            fmt::Println!("[ 9] LessOrEqBytes short       PASS");
        } else {
            fmt::Println!("[ 9] LessOrEqBytes short       FAIL r={},{},{},{}", r1, r2, r3, r4);
            failed += 1;
        }
    }

    // 10. ConstantTimeLessOrEqBytes — multi-block (> 8 bytes).
    {
        let a: slice<byte> = slice::__from_vec(alloc::vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05
        ]);
        let b: slice<byte> = slice::__from_vec(alloc::vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06
        ]);
        let c: slice<byte> = slice::__from_vec(alloc::vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04
        ]);
        let r1 = ConstantTimeLessOrEqBytes(&a, &b);
        let r2 = ConstantTimeLessOrEqBytes(&a, &c);
        let r3 = ConstantTimeLessOrEqBytes(&a, &a);
        if r1 == 1 && r2 == 0 && r3 == 1 {
            fmt::Println!("[10] LessOrEqBytes multi       PASS");
        } else {
            fmt::Println!("[10] LessOrEqBytes multi       FAIL");
            failed += 1;
        }
    }

    // 11. Empty slices.
    {
        let empty: slice<byte> = slice::__from_vec(alloc::vec![]);
        let r1 = ConstantTimeCompare(&empty, &empty);
        let r2 = ConstantTimeLessOrEqBytes(&empty, &empty);
        if r1 == 1 && r2 == 1 {
            fmt::Println!("[11] Empty slices              PASS");
        } else {
            fmt::Println!("[11] Empty slices              FAIL");
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
