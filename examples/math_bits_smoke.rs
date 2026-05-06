// math_bits_smoke — exercise math/bits.
// (math/bits/bits.go: 25 LeadingZeros, 59 TrailingZeros, 117 OnesCount,
//                     176 RotateLeft, 226 Reverse, 266 ReverseBytes,
//                     302 Len, 470 Mul64)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::math::bits;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. UintSize.
    {
        if bits::UintSize == 64 {
            Println!("[ 1] UintSize 64               PASS");
        } else {
            Println!("[ 1] UintSize 64               FAIL");
            failed += 1;
        }
    }

    // 2. LeadingZeros family.
    {
        if bits::LeadingZeros8(0) == 8
            && bits::LeadingZeros8(0xFF) == 0
            && bits::LeadingZeros8(0x01) == 7
            && bits::LeadingZeros16(0) == 16
            && bits::LeadingZeros16(0x0001) == 15
            && bits::LeadingZeros32(0) == 32
            && bits::LeadingZeros32(0x80000000) == 0
            && bits::LeadingZeros64(0) == 64
            && bits::LeadingZeros64(1) == 63
            && bits::LeadingZeros(1) == 63
        {
            Println!("[ 2] LeadingZeros family       PASS");
        } else {
            Println!("[ 2] LeadingZeros family       FAIL");
            failed += 1;
        }
    }

    // 3. TrailingZeros family.
    {
        if bits::TrailingZeros8(0) == 8
            && bits::TrailingZeros8(0x80) == 7
            && bits::TrailingZeros8(0x01) == 0
            && bits::TrailingZeros16(0) == 16
            && bits::TrailingZeros16(0x0100) == 8
            && bits::TrailingZeros32(0) == 32
            && bits::TrailingZeros32(0x10) == 4
            && bits::TrailingZeros64(0) == 64
            && bits::TrailingZeros64(0xE000_0000_0000_0000) == 61
            && bits::TrailingZeros(1) == 0
        {
            Println!("[ 3] TrailingZeros family      PASS");
        } else {
            Println!("[ 3] TrailingZeros family      FAIL");
            failed += 1;
        }
    }

    // 4. OnesCount family.
    {
        if bits::OnesCount8(0) == 0
            && bits::OnesCount8(0xFF) == 8
            && bits::OnesCount8(0x05) == 2
            && bits::OnesCount16(0xFFFF) == 16
            && bits::OnesCount32(0x12345678) == 13
            && bits::OnesCount64(0xFFFFFFFFFFFFFFFF) == 64
            && bits::OnesCount(0) == 0
        {
            Println!("[ 4] OnesCount family          PASS");
        } else {
            Println!("[ 4] OnesCount family          FAIL");
            failed += 1;
        }
    }

    // 5. RotateLeft 32 — 0x12345678 rotated 8 → 0x34567812.
    {
        if bits::RotateLeft32(0x12345678, 8) == 0x34567812
            && bits::RotateLeft32(0x12345678, -8) == 0x78123456
            && bits::RotateLeft32(0x12345678, 0) == 0x12345678
            && bits::RotateLeft32(0x12345678, 32) == 0x12345678
            && bits::RotateLeft8(0xC3, 1) == 0x87
        {
            Println!("[ 5] RotateLeft 32             PASS");
        } else {
            Println!("[ 5] RotateLeft 32             FAIL");
            failed += 1;
        }
    }

    // 6. Reverse 8 — 0xC3 (1100_0011) → 0xC3 (palindrome).
    {
        // 0xC3 = 1100_0011 → reverse bits = 1100_0011 = 0xC3.
        // 0xA0 = 1010_0000 → reverse = 0000_0101 = 0x05.
        if bits::Reverse8(0xC3) == 0xC3
            && bits::Reverse8(0xA0) == 0x05
            && bits::Reverse16(0xABCD).reverse_bits() == 0xABCD  // round trip
            && bits::Reverse32(1) == 0x80000000
            && bits::Reverse64(1) == 0x8000_0000_0000_0000
        {
            Println!("[ 6] Reverse family            PASS");
        } else {
            Println!("[ 6] Reverse family            FAIL");
            failed += 1;
        }
    }

    // 7. ReverseBytes — known patterns.
    {
        if bits::ReverseBytes16(0xABCD) == 0xCDAB
            && bits::ReverseBytes32(0x12345678) == 0x78563412
            && bits::ReverseBytes64(0x0123456789ABCDEF) == 0xEFCDAB8967452301
            && bits::ReverseBytes(0x0123456789ABCDEF) == 0xEFCDAB8967452301
        {
            Println!("[ 7] ReverseBytes family       PASS");
        } else {
            Println!("[ 7] ReverseBytes family       FAIL");
            failed += 1;
        }
    }

    // 8. Len family.
    {
        if bits::Len8(0) == 0
            && bits::Len8(1) == 1
            && bits::Len8(0xFF) == 8
            && bits::Len16(0x0100) == 9
            && bits::Len32(0xFFFFFFFF) == 32
            && bits::Len64(0x8000_0000_0000_0000) == 64
            && bits::Len(0) == 0
        {
            Println!("[ 8] Len family                PASS");
        } else {
            Println!("[ 8] Len family                FAIL");
            failed += 1;
        }
    }

    // 9. Mul64 — 0xFFFF_FFFF_FFFF_FFFF * 2 = (1, 0xFFFF_FFFF_FFFF_FFFE).
    {
        let (hi, lo) = bits::Mul64(0xFFFF_FFFF_FFFF_FFFF, 2);
        if hi == 1 && lo == 0xFFFF_FFFF_FFFF_FFFE {
            Println!("[ 9] Mul64 *2                  PASS");
        } else {
            Println!("[ 9] Mul64 *2                  FAIL");
            failed += 1;
        }
    }

    // 10. Mul64 — 0 * x = 0.
    {
        let (hi, lo) = bits::Mul64(0, 0xDEADBEEF);
        if hi == 0 && lo == 0 {
            Println!("[10] Mul64 zero                PASS");
        } else {
            Println!("[10] Mul64 zero                FAIL");
            failed += 1;
        }
    }

    // 11. Mul64 — 0xFFFFFFFF * 0xFFFFFFFF (32-bit max squared, fits in 64).
    {
        let (hi, lo) = bits::Mul64(0xFFFFFFFF, 0xFFFFFFFF);
        // 0xFFFFFFFE_00000001 with hi=0.
        if hi == 0 && lo == 0xFFFF_FFFE_0000_0001 {
            Println!("[11] Mul64 32×32               PASS");
        } else {
            Println!("[11] Mul64 32×32               FAIL");
            failed += 1;
        }
    }

    // 12. Mul64 — generic mid-range (matches Go reference).
    {
        // 0x100000001 * 0x100000001 = 0x10000_00020000_0001.
        let (hi, lo) = bits::Mul64(0x1_0000_0001, 0x1_0000_0001);
        if hi == 0x1 && lo == 0x2_0000_0001 {
            Println!("[12] Mul64 generic             PASS");
        } else {
            Println!("[12] Mul64 generic             FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
