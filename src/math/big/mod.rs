// math/big — minimal port of Go's `math/big` package.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   var z big.Int                        let mut z = big::Int::default();
//   z := big.NewInt(42)                  let z = big::NewInt(42);
//   z.SetInt64(x)                        z.SetInt64(x);
//   z.Cmp(other)                         z.Cmp(&other)
//   z.Int64()                            z.Int64()
//   z.Exp(x, y, m)                       z.Exp(&x, &y, &m)   (panics if y is negative)
//   z.Mod(x, y)                          z.Mod(&x, &y)       (Euclidean)
//
// Scope: this v1 is the minimum surface a Goish port needs to handle
// small-prime ROCA-style modular arithmetic on RSA-sized inputs (the
// `titanous/rocacheck` use-case). The internal layout is `Vec<u32>`
// little-endian limbs + a sign bit — same shape as Go's `nat []Word`,
// just narrower so the small-divisor reduction loop stays in u64
// arithmetic without `__udivmodti4`.
//
// Limitations that callers should know about:
//   * `Mod`/`QuoRem` require the divisor to fit in u32 (single-precision
//     long division). Mods by larger divisors panic — matches the
//     observed rocacheck pattern (mod by primes ≤ 157).
//   * `Exp` works for any modulus up to u32::MAX (uses u64-arithmetic
//     square-and-multiply). Larger moduli panic.
//   * Negative moduli are not yet supported (panics).
//
// These limits are deliberate, not architectural: filling them out is
// straightforward "more port" work, deferred until a port hits the gap.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::types::int;

/// `big.Int` — signed multi-precision integer. Zero value represents 0.
#[derive(Clone, Default)]
pub struct Int {
    neg: bool,
    abs: Vec<u32>, // little-endian limbs, no trailing zeros
}

impl Int {
    /// `var z big.Int` — fresh zero-valued Int.
    pub fn new() -> Self {
        Int { neg: false, abs: Vec::new() }
    }

    /// `(*Int).Sign()` — -1, 0, or +1.
    pub fn Sign(&self) -> int {
        if self.abs.is_empty() { 0 } else if self.neg { -1 } else { 1 }
    }

    /// `(*Int).SetInt64(x)` — assign and return self (Go: `z *Int`).
    pub fn SetInt64(&mut self, x: i64) -> &mut Self {
        let (neg, mag) = if x < 0 {
            (true, (x as i128).unsigned_abs() as u64)
        } else {
            (false, x as u64)
        };
        self.neg = neg;
        self.abs = u64_to_limbs(mag);
        self
    }

    /// `(*Int).Set(x)` — copy x into self and return self.
    pub fn Set(&mut self, x: &Int) -> &mut Self {
        self.neg = x.neg;
        self.abs = x.abs.clone();
        self
    }

    /// `(*Int).Int64()` — low 64 bits as a signed value (Go bit-truncates).
    pub fn Int64(&self) -> i64 {
        let mag = limbs_to_u64(&self.abs);
        if self.neg { -(mag as i64) } else { mag as i64 }
    }

    /// `(*Int).Cmp(y)` — -1 / 0 / 1.
    pub fn Cmp(&self, y: &Int) -> int {
        match (self.Sign(), y.Sign()) {
            (a, b) if a < b => -1,
            (a, b) if a > b => 1,
            _ => match abs_cmp(&self.abs, &y.abs) {
                Ordering::Less => if self.neg { 1 } else { -1 },
                Ordering::Equal => 0,
                Ordering::Greater => if self.neg { -1 } else { 1 },
            },
        }
    }

    /// `(*Int).Mod(x, y)` — Euclidean remainder (always 0 ≤ r < |y|).
    /// Returns self after assigning the result. Panics if y == 0 or
    /// |y| > u32::MAX (single-precision divisor only in v1).
    pub fn Mod(&mut self, x: &Int, y: &Int) -> &mut Self {
        if y.abs.is_empty() {
            panic!("big::Int::Mod: division by zero");
        }
        if y.abs.len() > 1 {
            panic!("big::Int::Mod: divisor exceeds u32; multi-precision divisor not implemented in v1");
        }
        if y.neg {
            panic!("big::Int::Mod: negative divisor not supported in v1");
        }
        let d = y.abs[0];
        let r = mod_by_u32(&x.abs, d);
        // Euclidean: if x is negative and r != 0, return d - r.
        let mag = if x.neg && r != 0 { d - r } else { r };
        self.neg = false;
        self.abs = if mag == 0 { Vec::new() } else { alloc::vec![mag] };
        self
    }

    /// `(*Int).Exp(x, y, m)` — modular exponentiation. y must be ≥ 0;
    /// m may be nil-equivalent (zero) for plain Exp, but rocacheck
    /// always passes a modulus, so v1 requires m != 0 with |m| ≤
    /// u32::MAX. Operands x and y must also fit in u32.
    pub fn Exp(&mut self, x: &Int, y: &Int, m: &Int) -> &mut Self {
        if y.neg {
            panic!("big::Int::Exp: negative exponent");
        }
        if m.abs.is_empty() {
            panic!("big::Int::Exp: zero modulus not supported in v1");
        }
        if m.abs.len() > 1 || x.abs.len() > 1 || y.abs.len() > 1 {
            panic!("big::Int::Exp: multi-precision operands not supported in v1");
        }
        let m_v = m.abs[0] as u64;
        let mut base = (x.abs.first().copied().unwrap_or(0) as u64) % m_v;
        if x.neg && base != 0 {
            base = m_v - base;
        }
        let mut exp = y.abs.first().copied().unwrap_or(0) as u64;
        let mut acc: u64 = 1 % m_v;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = (acc * base) % m_v;
            }
            exp >>= 1;
            if exp > 0 {
                base = (base * base) % m_v;
            }
        }
        self.neg = false;
        self.abs = if acc == 0 { Vec::new() } else { alloc::vec![acc as u32] };
        self
    }
}

/// `big.NewInt(x)` — Go's package-level constructor.
pub fn NewInt(x: i64) -> Int {
    let mut z = Int::new();
    z.SetInt64(x);
    z
}

// ─── nil-poly: Go callers do `if z == nil` on `*big.Int` ──────────────
//
// In goish the canonical zero-value of `Int` IS the zero, so the
// "nil pointer" case is equivalent to a fresh `Int::default()`. Match
// any zero-valued Int.
impl PartialEq<crate::nilval::Nil> for Int {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.abs.is_empty() && !self.neg
    }
}
impl PartialEq<Int> for crate::nilval::Nil {
    fn eq(&self, other: &Int) -> bool {
        other.abs.is_empty() && !other.neg
    }
}
impl From<crate::nilval::Nil> for Int {
    fn from(_: crate::nilval::Nil) -> Self {
        Int::new()
    }
}

// ─── helpers ───────────────────────────────────────────────────────────

fn u64_to_limbs(x: u64) -> Vec<u32> {
    if x == 0 {
        Vec::new()
    } else if x <= u32::MAX as u64 {
        alloc::vec![x as u32]
    } else {
        alloc::vec![x as u32, (x >> 32) as u32]
    }
}

fn limbs_to_u64(limbs: &[u32]) -> u64 {
    match limbs.len() {
        0 => 0,
        1 => limbs[0] as u64,
        _ => limbs[0] as u64 | ((limbs[1] as u64) << 32),
    }
}

fn abs_cmp(a: &[u32], b: &[u32]) -> Ordering {
    match a.len().cmp(&b.len()) {
        Ordering::Equal => {
            for (x, y) in a.iter().rev().zip(b.iter().rev()) {
                match x.cmp(y) {
                    Ordering::Equal => continue,
                    o => return o,
                }
            }
            Ordering::Equal
        }
        o => o,
    }
}

/// Long division by a single u32 divisor. Returns the remainder.
/// Standard textbook algorithm: walk limbs MSB→LSB carrying the
/// 64-bit (rem << 32 | limb) into a divide.
fn mod_by_u32(num: &[u32], d: u32) -> u32 {
    debug_assert!(d != 0);
    let dv = d as u64;
    let mut r: u64 = 0;
    for &limb in num.iter().rev() {
        r = ((r << 32) | (limb as u64)) % dv;
    }
    r as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newint_int64_roundtrip() {
        for &x in &[0i64, 1, -1, 42, -42, 1_000_000, -(1i64 << 40)] {
            assert_eq!(NewInt(x).Int64(), x, "roundtrip {x}");
        }
    }

    #[test]
    fn cmp_basic() {
        assert_eq!(NewInt(1).Cmp(&NewInt(2)), -1);
        assert_eq!(NewInt(2).Cmp(&NewInt(2)), 0);
        assert_eq!(NewInt(3).Cmp(&NewInt(2)), 1);
        assert_eq!(NewInt(-1).Cmp(&NewInt(1)), -1);
    }

    #[test]
    fn mod_small_divisor() {
        // 100 mod 7 = 2
        let mut r = Int::default();
        r.Mod(&NewInt(100), &NewInt(7));
        assert_eq!(r.Int64(), 2);

        // Build a "large" int by hand: 2^40 + 5 == 1099511627781
        let mut big = Int::default();
        big.SetInt64(1_099_511_627_781);
        let mut r2 = Int::default();
        r2.Mod(&big, &NewInt(11));
        // 1099511627781 % 11 == ?
        assert_eq!(r2.Int64(), (1_099_511_627_781i64 % 11));
    }

    #[test]
    fn exp_modular() {
        // 2^10 mod 13 = 1024 mod 13 = 10
        let mut r = Int::default();
        r.Exp(&NewInt(2), &NewInt(10), &NewInt(13));
        assert_eq!(r.Int64(), 10);

        // ROCA fingerprint check: residue r=2 prime p=11 → 2^k mod 11
        // for k=0..11 should cover {1,2,4,8,5,10,9,7,3,6,1} (cycle).
        // The "fingerprint" set is the j values where 2^j ≡ 1 mod 11
        // — only j=0 and j=10 satisfy that.
        let mut found = alloc::vec::Vec::new();
        for j in 0i64..11 {
            let mut acc = Int::default();
            acc.Exp(&NewInt(j), &NewInt(2), &NewInt(11));
            if acc.Cmp(&NewInt(1)) == 0 { found.push(j); }
        }
        // Wait, I had it backwards: rocacheck checks `j^residue mod prime == 1`.
        // For (residue=2, prime=11) ROCA pair: j^2 ≡ 1 mod 11 means j ≡ ±1
        // mod 11, i.e. j ∈ {1, 10}.
        assert_eq!(found, alloc::vec![1, 10]);
    }
}
