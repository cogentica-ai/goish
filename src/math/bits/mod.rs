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

#![allow(non_snake_case, non_upper_case_globals)]

use crate::types::{int, uint};

// Go: const uintSize = 32 << (^uint(0) >> 63) // 32 or 64
//     pub const UintSize = uintSize
/// `bits.UintSize` (bits.go:20) — width of `uint` in bits. Goish pins
/// `uint = u64`, so this is always 64 on supported targets.
pub const UintSize: int = 64;

// ─── LeadingZeros (bits.go:25) ────────────────────────────────────────

/// `bits.LeadingZeros(x)` — number of leading zero bits in `x`; the
/// result is `UintSize` for `x == 0`.
pub fn LeadingZeros(x: uint) -> int {
    // Go: return UintSize - Len(x)
    LeadingZeros64(x)
}

/// `bits.LeadingZeros8(x)` — result is 8 for `x == 0`.
pub fn LeadingZeros8(x: u8) -> int {
    // Go: return 8 - Len8(x)  (intrinsic: x.leading_zeros() bit-for-bit)
    x.leading_zeros() as int
}

/// `bits.LeadingZeros16(x)` — result is 16 for `x == 0`.
pub fn LeadingZeros16(x: u16) -> int {
    x.leading_zeros() as int
}

/// `bits.LeadingZeros32(x)` — result is 32 for `x == 0`.
pub fn LeadingZeros32(x: u32) -> int {
    x.leading_zeros() as int
}

/// `bits.LeadingZeros64(x)` — result is 64 for `x == 0`.
pub fn LeadingZeros64(x: u64) -> int {
    x.leading_zeros() as int
}

// ─── TrailingZeros (bits.go:59) ───────────────────────────────────────

/// `bits.TrailingZeros(x)` — result is `UintSize` for `x == 0`.
pub fn TrailingZeros(x: uint) -> int {
    TrailingZeros64(x)
}

/// `bits.TrailingZeros8(x)` — result is 8 for `x == 0`.
pub fn TrailingZeros8(x: u8) -> int {
    if x == 0 { 8 } else { x.trailing_zeros() as int }
}

/// `bits.TrailingZeros16(x)` — result is 16 for `x == 0`.
pub fn TrailingZeros16(x: u16) -> int {
    if x == 0 { 16 } else { x.trailing_zeros() as int }
}

/// `bits.TrailingZeros32(x)` — result is 32 for `x == 0`.
pub fn TrailingZeros32(x: u32) -> int {
    if x == 0 { 32 } else { x.trailing_zeros() as int }
}

/// `bits.TrailingZeros64(x)` — result is 64 for `x == 0`.
pub fn TrailingZeros64(x: u64) -> int {
    if x == 0 { 64 } else { x.trailing_zeros() as int }
}

// ─── OnesCount (bits.go:117) ──────────────────────────────────────────

/// `bits.OnesCount(x)` — number of one bits ("population count").
pub fn OnesCount(x: uint) -> int {
    OnesCount64(x)
}

/// `bits.OnesCount8(x)`.
pub fn OnesCount8(x: u8) -> int {
    x.count_ones() as int
}

/// `bits.OnesCount16(x)`.
pub fn OnesCount16(x: u16) -> int {
    x.count_ones() as int
}

/// `bits.OnesCount32(x)`.
pub fn OnesCount32(x: u32) -> int {
    x.count_ones() as int
}

/// `bits.OnesCount64(x)`.
pub fn OnesCount64(x: u64) -> int {
    x.count_ones() as int
}

// ─── RotateLeft (bits.go:176) ─────────────────────────────────────────
// Go: rotates by (k mod N) where k is an `int`; negative k rotates right.

/// `bits.RotateLeft(x, k)` — rotate `x` left by `(k mod UintSize)` bits.
/// To rotate right by `k`, call `RotateLeft(x, -k)`.
pub fn RotateLeft(x: uint, k: int) -> uint {
    RotateLeft64(x, k)
}

/// `bits.RotateLeft8(x, k)`.
pub fn RotateLeft8(x: u8, k: int) -> u8 {
    // Go: const n = 8; s := uint(k) & (n - 1); return x<<s | x>>(n-s)
    // Rust's `rotate_left` takes u32; cast k to that domain via mod 8.
    x.rotate_left((k.rem_euclid(8)) as u32)
}

/// `bits.RotateLeft16(x, k)`.
pub fn RotateLeft16(x: u16, k: int) -> u16 {
    x.rotate_left((k.rem_euclid(16)) as u32)
}

/// `bits.RotateLeft32(x, k)`.
pub fn RotateLeft32(x: u32, k: int) -> u32 {
    x.rotate_left((k.rem_euclid(32)) as u32)
}

/// `bits.RotateLeft64(x, k)`.
pub fn RotateLeft64(x: u64, k: int) -> u64 {
    x.rotate_left((k.rem_euclid(64)) as u32)
}

// ─── Reverse (bits.go:226) ────────────────────────────────────────────

/// `bits.Reverse(x)` — bits reversed.
pub fn Reverse(x: uint) -> uint {
    Reverse64(x)
}

/// `bits.Reverse8(x)`.
pub fn Reverse8(x: u8) -> u8 {
    x.reverse_bits()
}

/// `bits.Reverse16(x)`.
pub fn Reverse16(x: u16) -> u16 {
    x.reverse_bits()
}

/// `bits.Reverse32(x)`.
pub fn Reverse32(x: u32) -> u32 {
    x.reverse_bits()
}

/// `bits.Reverse64(x)`.
pub fn Reverse64(x: u64) -> u64 {
    x.reverse_bits()
}

// ─── ReverseBytes (bits.go:266) ───────────────────────────────────────

/// `bits.ReverseBytes(x)`.
pub fn ReverseBytes(x: uint) -> uint {
    ReverseBytes64(x)
}

/// `bits.ReverseBytes16(x)`.
pub fn ReverseBytes16(x: u16) -> u16 {
    x.swap_bytes()
}

/// `bits.ReverseBytes32(x)`.
pub fn ReverseBytes32(x: u32) -> u32 {
    x.swap_bytes()
}

/// `bits.ReverseBytes64(x)`.
pub fn ReverseBytes64(x: u64) -> u64 {
    x.swap_bytes()
}

// ─── Len (bits.go:302) ────────────────────────────────────────────────

/// `bits.Len(x)` — minimum bits required; 0 for `x == 0`.
pub fn Len(x: uint) -> int {
    Len64(x)
}

/// `bits.Len8(x)`.
pub fn Len8(x: u8) -> int {
    8 - x.leading_zeros() as int
}

/// `bits.Len16(x)`.
pub fn Len16(x: u16) -> int {
    16 - x.leading_zeros() as int
}

/// `bits.Len32(x)`.
pub fn Len32(x: u32) -> int {
    32 - x.leading_zeros() as int
}

/// `bits.Len64(x)`.
pub fn Len64(x: u64) -> int {
    64 - x.leading_zeros() as int
}

// ─── Mul64 (bits.go:470) ──────────────────────────────────────────────

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
    let hi = x1
        .wrapping_mul(y1)
        .wrapping_add(w2)
        .wrapping_add(w1 >> 32);
    let lo = x.wrapping_mul(y);
    (hi, lo)
}
