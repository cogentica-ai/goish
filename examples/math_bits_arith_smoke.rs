// math_bits_arith_smoke — exercise math/bits Add/Sub/Mul/Div/Rem
// family. Reference vectors hand-derived against Go's docs.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::fmt;
use goish::math::bits;
use goish::syscall;

#[goish::main]
fn main() {
    let mut failed = 0;

    // ── Add64 — basic ──────────────────────────────────────────────────
    // 1+2+0 = (3, 0)
    {
        let (s, c) = bits::Add64(1, 2, 0);
        if s == 3 && c == 0 {
            fmt::Println!("[ 1] Add64 1+2+0=(3,0)         PASS");
        } else {
            fmt::Println!("[ 1] Add64 1+2+0=(3,0)         FAIL");
            failed += 1;
        }
    }

    // ── Add64 — with carry-out ─────────────────────────────────────────
    // u64::MAX + 1 + 0 = (0, 1)
    {
        let (s, c) = bits::Add64(u64::MAX, 1, 0);
        if s == 0 && c == 1 {
            fmt::Println!("[ 2] Add64 carry-out           PASS");
        } else {
            fmt::Println!("[ 2] Add64 carry-out           FAIL");
            failed += 1;
        }
    }

    // ── Add32 — boundary ───────────────────────────────────────────────
    // u32::MAX + u32::MAX + 1 = sum=u32::MAX (=2^33 - 1), carry=1
    {
        let (s, c) = bits::Add32(u32::MAX, u32::MAX, 1);
        // 0xFFFFFFFF + 0xFFFFFFFF + 1 = 0x1_FFFFFFFF
        if s == 0xFFFFFFFFu32 && c == 1 {
            fmt::Println!("[ 3] Add32 max+max+1           PASS");
        } else {
            fmt::Println!("[ 3] Add32 max+max+1           FAIL");
            failed += 1;
        }
    }

    // ── Sub64 — basic ──────────────────────────────────────────────────
    // 5 - 3 - 0 = (2, 0)
    {
        let (d, b) = bits::Sub64(5, 3, 0);
        if d == 2 && b == 0 {
            fmt::Println!("[ 4] Sub64 5-3-0=(2,0)         PASS");
        } else {
            fmt::Println!("[ 4] Sub64 5-3-0=(2,0)         FAIL");
            failed += 1;
        }
    }

    // ── Sub64 — with borrow-out ────────────────────────────────────────
    // 0 - 1 - 0 = (u64::MAX, 1)
    {
        let (d, b) = bits::Sub64(0, 1, 0);
        if d == u64::MAX && b == 1 {
            fmt::Println!("[ 5] Sub64 borrow-out          PASS");
        } else {
            fmt::Println!("[ 5] Sub64 borrow-out          FAIL");
            failed += 1;
        }
    }

    // ── Sub32 — borrow chain ───────────────────────────────────────────
    // 5 - 5 - 1 = (u32::MAX, 1)
    {
        let (d, b) = bits::Sub32(5, 5, 1);
        if d == u32::MAX && b == 1 {
            fmt::Println!("[ 6] Sub32 borrow chain        PASS");
        } else {
            fmt::Println!("[ 6] Sub32 borrow chain        FAIL");
            failed += 1;
        }
    }

    // ── Mul32 — exact ──────────────────────────────────────────────────
    // 0xFFFF * 0xFFFF = 0xFFFE_0001 -> (hi=0, lo=0xFFFE0001)
    {
        let (hi, lo) = bits::Mul32(0xFFFF, 0xFFFF);
        if hi == 0 && lo == 0xFFFE_0001 {
            fmt::Println!("[ 7] Mul32 16×16               PASS");
        } else {
            fmt::Println!("[ 7] Mul32 16×16               FAIL");
            failed += 1;
        }
    }

    // ── Mul32 — full-width ─────────────────────────────────────────────
    // 0xFFFFFFFF * 2 = 0x1_FFFFFFFE -> (hi=1, lo=0xFFFFFFFE)
    {
        let (hi, lo) = bits::Mul32(0xFFFFFFFF, 2);
        if hi == 1 && lo == 0xFFFFFFFE {
            fmt::Println!("[ 8] Mul32 full-width          PASS");
        } else {
            fmt::Println!("[ 8] Mul32 full-width          FAIL");
            failed += 1;
        }
    }

    // ── Div64 — hi == 0 fast path ──────────────────────────────────────
    // (0, 100) / 7 = (14, 2)
    {
        let (q, r) = bits::Div64(0, 100, 7);
        if q == 14 && r == 2 {
            fmt::Println!("[ 9] Div64 hi=0 fast path      PASS");
        } else {
            fmt::Println!("[ 9] Div64 hi=0 fast path      FAIL");
            failed += 1;
        }
    }

    // ── Div64 — wide dividend ──────────────────────────────────────────
    // (1, 0) / 3 = q=(2^64)/3 = 0x5555_5555_5555_5555, r=1
    {
        let (q, r) = bits::Div64(1, 0, 3);
        if q == 0x5555_5555_5555_5555 && r == 1 {
            fmt::Println!("[10] Div64 wide dividend       PASS");
        } else {
            fmt::Println!("[10] Div64 wide dividend       FAIL");
            failed += 1;
        }
    }

    // ── Div32 — full-width ─────────────────────────────────────────────
    // (hi=1, lo=0) / 3 = q=(2^32)/3 = 0x55555555, r=1
    {
        let (q, r) = bits::Div32(1, 0, 3);
        if q == 0x5555_5555 && r == 1 {
            fmt::Println!("[11] Div32 wide dividend       PASS");
        } else {
            fmt::Println!("[11] Div32 wide dividend       FAIL");
            failed += 1;
        }
    }

    // ── Rem64 — large hi (would overflow Div64) ────────────────────────
    // (10, 5) / 7 — Rem reduces hi%7 first to avoid overflow panic.
    // Reference: 10*2^64 + 5 = 184467440737095516205
    //   184467440737095516205 mod 7 = 184467440737095516205 - 7*k
    // Compute: hi%7 = 10%7 = 3; Div64(3, 5, 7) gives full result.
    {
        let r = bits::Rem64(10, 5, 7);
        // 3<<64 + 5 mod 7. 3<<64 = 3*2^64. 2^64 mod 7 = 2 (since
        // 2^3 = 8 ≡ 1 mod 7, 2^64 = 2^(3*21+1) = 2). So 3*2^64 mod 7
        // = 6 mod 7 = 6. Plus 5 = 11 mod 7 = 4.
        if r == 4 {
            fmt::Println!("[12] Rem64 large hi            PASS");
        } else {
            fmt::Println!("[12] Rem64 large hi            FAIL");
            failed += 1;
        }
    }

    // ── Add wraps to Add64 (UintSize=64 in goish) ──────────────────────
    {
        let (s, c) = bits::Add(u64::MAX as goish::types::uint, 1, 0);
        if s == 0 && c == 1 {
            fmt::Println!("[13] Add → Add64               PASS");
        } else {
            fmt::Println!("[13] Add → Add64               FAIL");
            failed += 1;
        }
    }

    // ── Sub wraps to Sub64 ─────────────────────────────────────────────
    {
        let (d, b) = bits::Sub(0, 1, 0);
        if d == u64::MAX as goish::types::uint && b == 1 {
            fmt::Println!("[14] Sub → Sub64               PASS");
        } else {
            fmt::Println!("[14] Sub → Sub64               FAIL");
            failed += 1;
        }
    }

    // ── Mul wraps to Mul64 ─────────────────────────────────────────────
    {
        let (hi, lo) = bits::Mul(0xFFFF_FFFF_FFFF_FFFF, 2);
        // Equivalent of Mul64.
        if hi == 1 && lo == 0xFFFF_FFFF_FFFF_FFFE {
            fmt::Println!("[15] Mul → Mul64               PASS");
        } else {
            fmt::Println!("[15] Mul → Mul64               FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 15/15");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 15");
        syscall::Exit(1);
    }
}
