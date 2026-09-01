// go: file math/bits/bits.go decls: LeadingZeros, LeadingZeros8, LeadingZeros16, LeadingZeros32, LeadingZeros64, TrailingZeros, TrailingZeros8, TrailingZeros16, TrailingZeros32, TrailingZeros64, OnesCount, OnesCount8, OnesCount16, OnesCount32, OnesCount64, RotateLeft, RotateLeft8, RotateLeft16, RotateLeft32, RotateLeft64, Reverse, Reverse8, Reverse16, Reverse32, Reverse64, ReverseBytes, ReverseBytes16, ReverseBytes32, ReverseBytes64, Len, Len8, Len16, Len32, Len64, Add, Add32, Add64, Sub, Sub32, Sub64, Mul, Mul32, Mul64, Div, Div32, Div64, Rem, Rem32, Rem64
// goishlint:ignore GOISH021 ntz8tab, len8tab, rev8tab, m0, m1, m2, m3, m4, m5, deBruijn32, deBruijn64, deBruijn32tab, deBruijn64tab, uintSize — Go's portable fallbacks: the three lookup tables in bits_tables.go, the six SWAR masks its OnesCount uses, and the two de Bruijn sequences behind TrailingZeros. goish maps each function onto the corresponding Rust `u{N}` method, which is the same LLVM intrinsic Go's compiler emits when it does NOT take the portable path, so there is nothing for a table or a mask to serve. `uintSize` is the unexported half of `UintSize`, which is a const here.
// math/bits — Go's `math/bits`, ported.
//
// Bit counting and manipulation functions for the predeclared unsigned
// integer types. Go's comment notes these are typically intrinsics:
// "Functions in this package may be implemented directly by the
// compiler, for better performance." This port maps each function to
// the corresponding Rust core::intrinsic / built-in u{N}::method,
// which is itself an LLVM intrinsic on x86_64 — matching Go's intent.
//
// Slim coverage (matches the most-used surface for HTTP/encoding work):
//
//   LeadingZeros{,8,16,32,64}   TrailingZeros{,8,16,32,64}
//   OnesCount{,8,16,32,64}      RotateLeft{,8,16,32,64}
//   Reverse{,8,16,32,64}        ReverseBytes{,16,32,64}
//   Len{,8,16,32,64}            Mul64
//
// `uint` is u64 in goish (UintSize = 64).

use crate::convert::int as toint;
use crate::types::{int, uint};

// Go: const uintSize = 32 << (^uint(0) >> 63) // 32 or 64
//     pub const UintSize = uintSize
/// `bits.UintSize` (bits.go:20) — width of `uint` in bits. Goish pins
/// `uint = u64`, so this is always 64 on supported targets.
pub const UintSize: int = 64;

// ─── LeadingZeros (bits.go:25) ────────────────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:25-25 LeadingZeros
/// `bits.LeadingZeros(x)` — number of leading zero bits in `x`; the
/// result is `UintSize` for `x == 0`.
pub fn LeadingZeros(x: uint) -> int {
    // Go: return UintSize - Len(x)
    return LeadingZeros64(x);
}

// go: sdk 1.25.5 math/bits/bits.go:28-28 LeadingZeros8
/// `bits.LeadingZeros8(x)` — result is 8 for `x == 0`.
pub fn LeadingZeros8(x: u8) -> int {
    // Go: return 8 - Len8(x)  (intrinsic: x.leading_zeros() bit-for-bit)
    return toint(x.leading_zeros());
}

// go: sdk 1.25.5 math/bits/bits.go:31-31 LeadingZeros16
/// `bits.LeadingZeros16(x)` — result is 16 for `x == 0`.
pub fn LeadingZeros16(x: u16) -> int {
    return toint(x.leading_zeros());
}

// go: sdk 1.25.5 math/bits/bits.go:34-34 LeadingZeros32
/// `bits.LeadingZeros32(x)` — result is 32 for `x == 0`.
pub fn LeadingZeros32(x: u32) -> int {
    return toint(x.leading_zeros());
}

// go: sdk 1.25.5 math/bits/bits.go:37-37 LeadingZeros64
/// `bits.LeadingZeros64(x)` — result is 64 for `x == 0`.
pub fn LeadingZeros64(x: u64) -> int {
    return toint(x.leading_zeros());
}

// ─── TrailingZeros (bits.go:59) ───────────────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:59-64 TrailingZeros
/// `bits.TrailingZeros(x)` — result is `UintSize` for `x == 0`.
pub fn TrailingZeros(x: uint) -> int {
    return TrailingZeros64(x);
}

// go: sdk 1.25.5 math/bits/bits.go:67-69 TrailingZeros8
/// `bits.TrailingZeros8(x)` — result is 8 for `x == 0`.
pub fn TrailingZeros8(x: u8) -> int {
    return if x == 0 { 8 } else { x.trailing_zeros() as int };
}

// go: sdk 1.25.5 math/bits/bits.go:72-78 TrailingZeros16
/// `bits.TrailingZeros16(x)` — result is 16 for `x == 0`.
pub fn TrailingZeros16(x: u16) -> int {
    return if x == 0 {
        16
    } else {
        x.trailing_zeros() as int
    };
}

// go: sdk 1.25.5 math/bits/bits.go:81-87 TrailingZeros32
/// `bits.TrailingZeros32(x)` — result is 32 for `x == 0`.
pub fn TrailingZeros32(x: u32) -> int {
    return if x == 0 {
        32
    } else {
        x.trailing_zeros() as int
    };
}

// go: sdk 1.25.5 math/bits/bits.go:90-106 TrailingZeros64
/// `bits.TrailingZeros64(x)` — result is 64 for `x == 0`.
pub fn TrailingZeros64(x: u64) -> int {
    return if x == 0 {
        64
    } else {
        x.trailing_zeros() as int
    };
}

// ─── OnesCount (bits.go:117) ──────────────────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:117-122 OnesCount
/// `bits.OnesCount(x)` — number of one bits ("population count").
pub fn OnesCount(x: uint) -> int {
    return OnesCount64(x);
}

// go: sdk 1.25.5 math/bits/bits.go:125-127 OnesCount8
/// `bits.OnesCount8(x)`.
pub fn OnesCount8(x: u8) -> int {
    return toint(x.count_ones());
}

// go: sdk 1.25.5 math/bits/bits.go:130-132 OnesCount16
/// `bits.OnesCount16(x)`.
pub fn OnesCount16(x: u16) -> int {
    return toint(x.count_ones());
}

// go: sdk 1.25.5 math/bits/bits.go:135-137 OnesCount32
/// `bits.OnesCount32(x)`.
pub fn OnesCount32(x: u32) -> int {
    return toint(x.count_ones());
}

// go: sdk 1.25.5 math/bits/bits.go:140-168 OnesCount64
/// `bits.OnesCount64(x)`.
pub fn OnesCount64(x: u64) -> int {
    return toint(x.count_ones());
}

// ─── RotateLeft (bits.go:176) ─────────────────────────────────────────
// Go: rotates by (k mod N) where k is an `int`; negative k rotates right.

// go: sdk 1.25.5 math/bits/bits.go:176-181 RotateLeft
/// `bits.RotateLeft(x, k)` — rotate `x` left by `(k mod UintSize)` bits.
/// To rotate right by `k`, call `RotateLeft(x, -k)`.
pub fn RotateLeft(x: uint, k: int) -> uint {
    return RotateLeft64(x, k);
}

// go: sdk 1.25.5 math/bits/bits.go:187-191 RotateLeft8
/// `bits.RotateLeft8(x, k)`.
pub fn RotateLeft8(x: u8, k: int) -> u8 {
    // Go: const n = 8; s := uint(k) & (n - 1); return x<<s | x>>(n-s)
    // Rust's `rotate_left` takes u32; cast k to that domain via mod 8.
    return x.rotate_left((k.rem_euclid(8)) as u32);
}

// go: sdk 1.25.5 math/bits/bits.go:197-201 RotateLeft16
/// `bits.RotateLeft16(x, k)`.
pub fn RotateLeft16(x: u16, k: int) -> u16 {
    return x.rotate_left((k.rem_euclid(16)) as u32);
}

// go: sdk 1.25.5 math/bits/bits.go:207-211 RotateLeft32
/// `bits.RotateLeft32(x, k)`.
pub fn RotateLeft32(x: u32, k: int) -> u32 {
    return x.rotate_left((k.rem_euclid(32)) as u32);
}

// go: sdk 1.25.5 math/bits/bits.go:217-221 RotateLeft64
/// `bits.RotateLeft64(x, k)`.
pub fn RotateLeft64(x: u64, k: int) -> u64 {
    return x.rotate_left((k.rem_euclid(64)) as u32);
}

// ─── Reverse (bits.go:226) ────────────────────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:226-231 Reverse
/// `bits.Reverse(x)` — bits reversed.
pub fn Reverse(x: uint) -> uint {
    return Reverse64(x);
}

// go: sdk 1.25.5 math/bits/bits.go:234-236 Reverse8
/// `bits.Reverse8(x)`.
pub fn Reverse8(x: u8) -> u8 {
    return x.reverse_bits();
}

// go: sdk 1.25.5 math/bits/bits.go:239-241 Reverse16
/// `bits.Reverse16(x)`.
pub fn Reverse16(x: u16) -> u16 {
    return x.reverse_bits();
}

// go: sdk 1.25.5 math/bits/bits.go:244-250 Reverse32
/// `bits.Reverse32(x)`.
pub fn Reverse32(x: u32) -> u32 {
    return x.reverse_bits();
}

// go: sdk 1.25.5 math/bits/bits.go:253-259 Reverse64
/// `bits.Reverse64(x)`.
pub fn Reverse64(x: u64) -> u64 {
    return x.reverse_bits();
}

// ─── ReverseBytes (bits.go:266) ───────────────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:266-271 ReverseBytes
/// `bits.ReverseBytes(x)`.
pub fn ReverseBytes(x: uint) -> uint {
    return ReverseBytes64(x);
}

// go: sdk 1.25.5 math/bits/bits.go:276-278 ReverseBytes16
/// `bits.ReverseBytes16(x)`.
pub fn ReverseBytes16(x: u16) -> u16 {
    return x.swap_bytes();
}

// go: sdk 1.25.5 math/bits/bits.go:283-287 ReverseBytes32
/// `bits.ReverseBytes32(x)`.
pub fn ReverseBytes32(x: u32) -> u32 {
    return x.swap_bytes();
}

// go: sdk 1.25.5 math/bits/bits.go:292-297 ReverseBytes64
/// `bits.ReverseBytes64(x)`.
pub fn ReverseBytes64(x: u64) -> u64 {
    return x.swap_bytes();
}

// ─── Len (bits.go:302) ────────────────────────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:302-307 Len
/// `bits.Len(x)` — minimum bits required; 0 for `x == 0`.
pub fn Len(x: uint) -> int {
    return Len64(x);
}

// go: sdk 1.25.5 math/bits/bits.go:310-312 Len8
/// `bits.Len8(x)`.
pub fn Len8(x: u8) -> int {
    return toint(8 - x.leading_zeros());
}

// go: sdk 1.25.5 math/bits/bits.go:315-321 Len16
/// `bits.Len16(x)`.
pub fn Len16(x: u16) -> int {
    return toint(16 - x.leading_zeros());
}

// go: sdk 1.25.5 math/bits/bits.go:324-334 Len32
/// `bits.Len32(x)`.
pub fn Len32(x: u32) -> int {
    return toint(32 - x.leading_zeros());
}

// go: sdk 1.25.5 math/bits/bits.go:337-351 Len64
/// `bits.Len64(x)`.
pub fn Len64(x: u64) -> int {
    return toint(64 - x.leading_zeros());
}

// ─── Add / Add32 / Add64 (bits.go:360-393) ────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:360-367 Add
/// `bits.Add(x, y, carry)` — sum-with-carry; `(sum, carryOut)`.
/// `carry` must be 0 or 1; `carryOut` is 0 or 1.
pub fn Add(x: uint, y: uint, carry: uint) -> (uint, uint) {
    // Go: UintSize == 64 path on goish.
    let (s, c) = Add64(x as u64, y as u64, carry as u64);
    return (s as uint, c as uint);
}

// go: sdk 1.25.5 math/bits/bits.go:374-379 Add32
/// `bits.Add32(x, y, carry)` — sum-with-carry on 32-bit operands.
pub fn Add32(x: u32, y: u32, carry: u32) -> (u32, u32) {
    // Go: sum64 := uint64(x) + uint64(y) + uint64(carry)
    //     sum = uint32(sum64); carryOut = uint32(sum64 >> 32)
    let sum64 = (x as u64) + (y as u64) + (carry as u64);
    return (sum64 as u32, (sum64 >> 32) as u32);
}

// go: sdk 1.25.5 math/bits/bits.go:386-393 Add64
/// `bits.Add64(x, y, carry)` — sum-with-carry on 64-bit operands.
pub fn Add64(x: u64, y: u64, carry: u64) -> (u64, u64) {
    // Go: sum = x + y + carry
    //     carryOut = ((x & y) | ((x | y) &^ sum)) >> 63
    let sum = x.wrapping_add(y).wrapping_add(carry);
    let carry_out = ((x & y) | ((x | y) & !sum)) >> 63;
    return (sum, carry_out);
}

// ─── Sub / Sub32 / Sub64 (bits.go:402-436) ────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:402-409 Sub
/// `bits.Sub(x, y, borrow)` — diff-with-borrow; `(diff, borrowOut)`.
pub fn Sub(x: uint, y: uint, borrow: uint) -> (uint, uint) {
    let (d, b) = Sub64(x as u64, y as u64, borrow as u64);
    return (d as uint, b as uint);
}

// go: sdk 1.25.5 math/bits/bits.go:416-424 Sub32
/// `bits.Sub32(x, y, borrow)`.
pub fn Sub32(x: u32, y: u32, borrow: u32) -> (u32, u32) {
    // Go: diff = x - y - borrow
    //     borrowOut = ((^x & y) | (^(x ^ y) & diff)) >> 31
    let diff = x.wrapping_sub(y).wrapping_sub(borrow);
    let borrow_out = (((!x) & y) | ((!(x ^ y)) & diff)) >> 31;
    return (diff, borrow_out);
}

// go: sdk 1.25.5 math/bits/bits.go:431-436 Sub64
/// `bits.Sub64(x, y, borrow)`.
pub fn Sub64(x: u64, y: u64, borrow: u64) -> (u64, u64) {
    // Go: diff = x - y - borrow
    //     borrowOut = ((^x & y) | (^(x ^ y) & diff)) >> 63
    let diff = x.wrapping_sub(y).wrapping_sub(borrow);
    let borrow_out = (((!x) & y) | ((!(x ^ y)) & diff)) >> 63;
    return (diff, borrow_out);
}

// ─── Mul / Mul32 (bits.go:445-463) ────────────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:445-452 Mul
/// `bits.Mul(x, y)` — full-width product `(hi, lo) = x * y`.
pub fn Mul(x: uint, y: uint) -> (uint, uint) {
    let (h, l) = Mul64(x as u64, y as u64);
    return (h as uint, l as uint);
}

// go: sdk 1.25.5 math/bits/bits.go:459-463 Mul32
/// `bits.Mul32(x, y)` — 64-bit product, returned as `(hi, lo)`.
pub fn Mul32(x: u32, y: u32) -> (u32, u32) {
    // Go: tmp := uint64(x) * uint64(y); hi, lo = uint32(tmp>>32), uint32(tmp)
    let tmp = (x as u64).wrapping_mul(y as u64);
    return ((tmp >> 32) as u32, tmp as u32);
}

// ─── Mul64 (bits.go:470) ──────────────────────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:470-484 Mul64
/// `bits.Mul64(x, y)` — full 128-bit product `(hi, lo) = x * y`.
/// Execution time does not depend on the inputs (matches Go).
pub fn Mul64(x: u64, y: u64) -> (u64, u64) {
    // Go: const mask32 = 1<<32 - 1
    //     x0 := x & mask32; x1 := x >> 32
    //     y0 := y & mask32; y1 := y >> 32
    //     w0 := x0 * y0
    //     t := x1*y0 + w0>>32
    //     w1 := t & mask32; w2 := t >> 32
    //     w1 += x0 * y1
    //     hi = x1*y1 + w2 + w1>>32
    //     lo = x * y
    let mask32: u64 = (1u64 << 32) - 1;
    let x0 = x & mask32;
    let x1 = x >> 32;
    let y0 = y & mask32;
    let y1 = y >> 32;
    let w0 = x0.wrapping_mul(y0);
    let t = x1.wrapping_mul(y0).wrapping_add(w0 >> 32);
    let w1 = (t & mask32).wrapping_add(x0.wrapping_mul(y1));
    let w2 = t >> 32;
    let hi = x1.wrapping_mul(y1).wrapping_add(w2).wrapping_add(w1 >> 32);
    let lo = x.wrapping_mul(y);
    return (hi, lo);
}

// ─── Div / Div32 / Div64 (bits.go:492-568) ────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:492-499 Div
/// `bits.Div(hi, lo, y)` — `(hi, lo)/y` -> `(quo, rem)`. Panics for
/// `y == 0` or `y <= hi` (quotient overflow).
pub fn Div(hi: uint, lo: uint, y: uint) -> (uint, uint) {
    let (q, r) = Div64(hi as u64, lo as u64, y as u64);
    return (q as uint, r as uint);
}

// go: sdk 1.25.5 math/bits/bits.go:505-512 Div32
/// `bits.Div32(hi, lo, y)` — 64-bit dividend, 32-bit divisor.
pub fn Div32(hi: u32, lo: u32, y: u32) -> (u32, u32) {
    // Go: if y != 0 && y <= hi { panic(overflowError) }
    //     z := uint64(hi)<<32 | uint64(lo)
    //     quo, rem = uint32(z/uint64(y)), uint32(z%uint64(y))
    if y == 0 {
        panic!("runtime error: integer divide by zero");
    }
    if y <= hi {
        panic!("runtime error: integer overflow");
    }
    let z = ((hi as u64) << 32) | (lo as u64);
    let yy = y as u64;
    return ((z / yy) as u32, (z % yy) as u32);
}

// go: sdk 1.25.5 math/bits/bits.go:518-568 Div64
/// `bits.Div64(hi, lo, y)` — 128-bit dividend, 64-bit divisor.
pub fn Div64(hi: u64, lo: u64, mut y: u64) -> (u64, u64) {
    // Go: if y == 0 { panic(divideError) }
    //     if y <= hi { panic(overflowError) }
    if y == 0 {
        panic!("runtime error: integer divide by zero");
    }
    if y <= hi {
        panic!("runtime error: integer overflow");
    }
    // Go: if hi == 0 { return lo / y, lo % y }
    if hi == 0 {
        return (lo / y, lo % y);
    }
    // Go: s := uint(LeadingZeros64(y))
    //     y <<= s
    let s = LeadingZeros64(y) as u32;
    y <<= s;

    // Go: const two32 = 1 << 32; const mask32 = two32 - 1
    let two32: u64 = 1 << 32;
    let mask32: u64 = two32 - 1;
    let yn1 = y >> 32;
    let yn0 = y & mask32;
    // Go: un32 := hi<<s | lo>>(64-s)
    //     un10 := lo << s
    let un32: u64 = if s == 0 {
        hi
    } else {
        (hi << s) | (lo >> (64 - s))
    };
    let un10 = lo << s;
    let un1 = un10 >> 32;
    let un0 = un10 & mask32;
    let mut q1 = un32 / yn1;
    let mut rhat = un32 - q1 * yn1;

    // Go: for q1 >= two32 || q1*yn0 > two32*rhat+un1 { q1--; rhat += yn1; if rhat >= two32 { break } }
    while q1 >= two32 || q1.wrapping_mul(yn0) > two32.wrapping_mul(rhat).wrapping_add(un1) {
        q1 -= 1;
        rhat = rhat.wrapping_add(yn1);
        if rhat >= two32 {
            break;
        }
    }

    // Go: un21 := un32*two32 + un1 - q1*y
    let un21 = un32
        .wrapping_mul(two32)
        .wrapping_add(un1)
        .wrapping_sub(q1.wrapping_mul(y));
    let mut q0 = un21 / yn1;
    rhat = un21 - q0 * yn1;

    while q0 >= two32 || q0.wrapping_mul(yn0) > two32.wrapping_mul(rhat).wrapping_add(un0) {
        q0 -= 1;
        rhat = rhat.wrapping_add(yn1);
        if rhat >= two32 {
            break;
        }
    }

    // Go: return q1*two32 + q0, (un21*two32 + un0 - q0*y) >> s
    let quo = q1.wrapping_mul(two32).wrapping_add(q0);
    let rem = un21
        .wrapping_mul(two32)
        .wrapping_add(un0)
        .wrapping_sub(q0.wrapping_mul(y))
        >> s;
    return (quo, rem);
}

// ─── Rem / Rem32 / Rem64 (bits.go:573-599) ────────────────────────────

// go: sdk 1.25.5 math/bits/bits.go:573-578 Rem
/// `bits.Rem(hi, lo, y)` — remainder of `(hi, lo)/y`. Panics on `y == 0`,
/// but unlike `Div` does not panic on quotient overflow.
pub fn Rem(hi: uint, lo: uint, y: uint) -> uint {
    return Rem64(hi as u64, lo as u64, y as u64) as uint;
}

// go: sdk 1.25.5 math/bits/bits.go:583-585 Rem32
/// `bits.Rem32(hi, lo, y)`.
pub fn Rem32(hi: u32, lo: u32, y: u32) -> u32 {
    // Go: return uint32((uint64(hi)<<32 | uint64(lo)) % uint64(y))
    if y == 0 {
        panic!("runtime error: integer divide by zero");
    }
    return ((((hi as u64) << 32) | (lo as u64)) % (y as u64)) as u32;
}

// go: sdk 1.25.5 math/bits/bits.go:590-599 Rem64
/// `bits.Rem64(hi, lo, y)`. Reduces `hi mod y` first to avoid the
/// quotient-overflow panic in `Div64`.
pub fn Rem64(hi: u64, lo: u64, y: u64) -> u64 {
    // Go: _, rem := Div64(hi%y, lo, y); return rem
    if y == 0 {
        panic!("runtime error: integer divide by zero");
    }
    let (_, rem) = Div64(hi % y, lo, y);
    return rem;
}
