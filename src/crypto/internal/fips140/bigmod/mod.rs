// crypto/internal/fips140/bigmod — constant-time multi-precision
// modular arithmetic. Faithful port of Go 1.25.5
// crypto/internal/fips140/bigmod/nat.go + nat_noasm.go.
//
// `Nat` is an arbitrary natural number; `Modulus` precomputes the
// constants needed for Montgomery arithmetic. Operations are
// constant-time with respect to secret values: they never branch or
// array-index on a limb's value. The `choice` type carries a 0/1 mask
// turned into all-0s/all-1s word masks for branch-free selection.
//
// goish notes:
//   * `uint` is u64, so `_W = 64`, `_S = 8`. Limb storage is
//     `Vec<u64>` (internal — never appears in a public signature).
//   * `addMulVVW1024/1536/2048` in Go are unsafe-slice shims over
//     assembly. There is no assembly here; the specialized
//     `montgomeryMul`/`Mul` size cases collapse into the generic path,
//     which runs the exact same algorithm.
//   * The Go `//go:norace` annotations are race-detector hints only and
//     have no goish equivalent.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::math::bits;
use crate::types::{byte, int, uint};
use alloc::vec::Vec;

// Side-effecting blank import in Go: `_ "crypto/internal/fips140/check"`.
// goish's `check` module is side-effect-free; referenced here only to
// mirror the import.
#[allow(unused_imports)]
use crate::crypto::internal::fips140::check as _check;

// `_W` is the size in bits of our limbs; `_S` the size in bytes.
const _W: uint = 64;
const _S: usize = 8;

// ─── choice — a constant-time boolean (Go: nat.go:33) ─────────────────

/// `choice` represents a constant-time boolean: always 1 or 0. We use a
/// word instead of a bool so decisions can be made by turning it into a
/// mask.
type choice = uint;

const yes: choice = 1;
const no: choice = 0;

/// `not(c)` (nat.go:35) — logical negation of a `choice`.
fn not(c: choice) -> choice {
    1 ^ c
}

/// `ctMask(on)` (nat.go:41) — all 1s if `on` is yes, all 0s otherwise.
fn ctMask(on: choice) -> uint {
    // Go: -uint(on). Two's-complement negation, branch-free.
    on.wrapping_neg()
}

/// `ctEq(x, y)` (nat.go:45) — 1 if x == y, 0 otherwise; constant time.
fn ctEq(x: uint, y: uint) -> choice {
    // If x != y, then either x - y or y - x will generate a borrow.
    let (_, c1) = bits::Sub64(x, y, 0);
    let (_, c2) = bits::Sub64(y, x, 0);
    not(c1 | c2)
}

// ─── byteorder helper (Go: fips140deps/byteorder) ─────────────────────

/// Big-endian decode of an 8-byte buffer to a `uint` word. `_W == 64`.
fn bigEndianUint(buf: &[byte]) -> uint {
    u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ])
}

// ─── Nat (Go: nat.go:57) ──────────────────────────────────────────────

/// `Nat` represents an arbitrary natural number.
///
/// Each `Nat` has an announced length (number of limbs stored).
/// Operations may leak this length but never the values in the limbs.
#[derive(Clone)]
pub struct Nat {
    // limbs is little-endian in base 2^_W.
    limbs: Vec<uint>,
}

// preallocTarget is the bit size of the most common RSA key size.
const preallocTarget: usize = 2048;
const _W_usize: usize = 64; // _W as a usize, for capacity arithmetic
const preallocLimbs: usize = (preallocTarget + _W_usize - 1) / _W_usize;

impl Nat {
    /// `NewNat()` (nat.go:71) — a new zero-length `Nat` with capacity for
    /// up to `preallocTarget` bits.
    pub fn NewNat() -> Nat {
        Nat {
            limbs: Vec::with_capacity(preallocLimbs),
        }
    }

    /// `expand` (nat.go:77) — expand x to n limbs, value unchanged.
    fn expand(&mut self, n: usize) -> &mut Nat {
        if self.limbs.len() > n {
            panic!("bigmod: internal error: shrinking nat");
        }
        // Go reuses backing capacity; a plain resize is value-equivalent.
        self.limbs.resize(n, 0);
        self
    }

    /// `reset` (nat.go:94) — a zero `Nat` of n limbs, reusing storage.
    fn reset(&mut self, n: usize) -> &mut Nat {
        // Clear all current limbs, then resize to n (new limbs are 0).
        for l in self.limbs.iter_mut() {
            *l = 0;
        }
        self.limbs.resize(n, 0);
        self
    }

    /// `resetToBytes` (nat.go:110) — assign x = b (big-endian bytes),
    /// resizing to fit, with the announced length set from the actual
    /// bit size (leading zeroes ignored).
    fn resetToBytes(&mut self, b: &[byte]) -> &mut Nat {
        self.reset((b.len() + _S - 1) / _S);
        if !self.setBytes(b).IsNil() {
            panic!("bigmod: internal error: bad arithmetic");
        }
        self.trim()
    }

    /// `trim` (nat.go:119) — reduce the size of x to match its value.
    fn trim(&mut self) -> &mut Nat {
        // Trim most-significant (trailing in little-endian) zero limbs.
        // Comparison with zero is assumed constant time (the branch is
        // not — but only the announced length leaks here).
        let mut i = self.limbs.len();
        while i > 0 {
            if self.limbs[i - 1] != 0 {
                break;
            }
            i -= 1;
        }
        self.limbs.truncate(i);
        self
    }

    /// `set` (nat.go:132) — assign x = y, resizing as needed.
    fn set(&mut self, y: &Nat) -> &mut Nat {
        self.reset(y.limbs.len());
        self.limbs.copy_from_slice(&y.limbs);
        self
    }

    /// `Bits()` (nat.go:141) — x as a little-endian slice of `uint`. The
    /// length matches the announced length of x.
    pub fn Bits(&self) -> slice<uint> {
        slice::<uint>::__from_vec(self.limbs.clone())
    }

    /// `Bytes(m)` (nat.go:149) — x as a zero-extended big-endian byte
    /// slice sized to m. x must have m's size and be `<= m`.
    pub fn Bytes(&self, m: &Modulus) -> slice<byte> {
        let mut i = m.Size();
        let mut bytes: Vec<byte> = alloc::vec![0u8; i as usize];
        for &limb0 in self.limbs.iter() {
            let mut limb = limb0;
            for _ in 0.._S {
                i -= 1;
                if i < 0 {
                    if limb == 0 {
                        break;
                    }
                    panic!("bigmod: modulus is smaller than nat");
                }
                bytes[i as usize] = byte::try_from(limb & 0xff).unwrap_or(0);
                limb >>= 8;
            }
        }
        slice::<byte>::__from_vec(bytes)
    }

    /// `SetBytes(b, m)` (nat.go:174) — assign x = b (big-endian).
    /// Returns an error if `b >= m`. Output is resized to m's size.
    pub fn SetBytes(&mut self, b: slice<byte>, m: &Modulus) -> (Nat, error) {
        let bv = slice_to_vec(&b);
        self.resetFor(m);
        let e = self.setBytes(&bv);
        if !e.IsNil() {
            return (Nat::NewNat(), e);
        }
        if self.cmpGeq(&m.nat) == yes {
            return (Nat::NewNat(), errors::New("input overflows the modulus"));
        }
        (self.clone(), errors::nil)
    }

    /// `SetOverflowingBytes(b, m)` (nat.go:190) — assign x = b, reducing
    /// values up to `2^⌈log2(m)⌉ - 1`. Errors if b has a longer bit
    /// length than m.
    pub fn SetOverflowingBytes(&mut self, b: slice<byte>, m: &Modulus) -> (Nat, error) {
        let bv = slice_to_vec(&b);
        self.resetFor(m);
        let e = self.setBytes(&bv);
        if !e.IsNil() {
            return (Nat::NewNat(), e);
        }
        // setBytes errors on a limb-size overflow, so we only need to
        // compare the most-significant limb's bit length.
        let xs = *self.limbs.last().unwrap();
        let ms = *m.nat.limbs.last().unwrap();
        if bitLen(xs) > bitLen(ms) {
            return (
                Nat::NewNat(),
                errors::New("input overflows the modulus size"),
            );
        }
        self.maybeSubtractModulus(no, m);
        (self.clone(), errors::nil)
    }

    /// `setBytes` (nat.go:214) — internal big-endian byte loader.
    fn setBytes(&mut self, b: &[byte]) -> error {
        let mut i = b.len();
        let mut k = 0usize;
        while k < self.limbs.len() && i >= _S {
            self.limbs[k] = bigEndianUint(&b[i - _S..i]);
            i -= _S;
            k += 1;
        }
        let mut s: uint = 0;
        while s < _W && k < self.limbs.len() && i > 0 {
            self.limbs[k] |= uint::from(b[i - 1]) << s;
            i -= 1;
            s += 8;
        }
        if i > 0 {
            return errors::New("input overflows the modulus size");
        }
        errors::nil
    }

    /// `SetUint(y)` (nat.go:234) — assign x = y; resized to one limb.
    pub fn SetUint(&mut self, y: uint) -> &mut Nat {
        self.reset(1);
        self.limbs[0] = y;
        self
    }

    /// `Equal(y)` (nat.go:245) — 1 if x == y, else 0. Operands must
    /// share the same announced length.
    pub fn Equal(&self, y: &Nat) -> uint {
        let size = self.limbs.len();
        let mut equal = yes;
        for i in 0..size {
            equal &= ctEq(self.limbs[i], y.limbs[i]);
        }
        equal
    }

    /// `IsZero()` (nat.go:261) — 1 if x == 0, else 0.
    pub fn IsZero(&self) -> uint {
        let size = self.limbs.len();
        let mut zero = yes;
        for i in 0..size {
            zero &= ctEq(self.limbs[i], 0);
        }
        zero
    }

    /// `IsOne()` (nat.go:276) — 1 if x == 1, else 0.
    pub fn IsOne(&self) -> uint {
        let size = self.limbs.len();
        if size == 0 {
            return no;
        }
        let mut one = ctEq(self.limbs[0], 1);
        for i in 1..size {
            one &= ctEq(self.limbs[i], 0);
        }
        one
    }

    /// `IsMinusOne(m)` (nat.go:298) — 1 if x == -1 mod m, else 0. x must
    /// match m's size and be reduced modulo m.
    pub fn IsMinusOne(&self, m: &Modulus) -> uint {
        let mut minusOne = m.Nat();
        minusOne.SubOne(m);
        self.Equal(&minusOne)
    }

    /// `IsOdd()` (nat.go:305) — 1 if x is odd, else 0.
    pub fn IsOdd(&self) -> uint {
        if self.limbs.is_empty() {
            return no;
        }
        self.limbs[0] & 1
    }

    /// `TrailingZeroBitsVarTime()` (nat.go:313) — number of trailing zero
    /// bits in x. Leaks the value through timing.
    pub fn TrailingZeroBitsVarTime(&self) -> uint {
        let mut t: uint = 0;
        for &l in self.limbs.iter() {
            if l == 0 {
                t += _W;
                continue;
            }
            t += uint::try_from(bits::TrailingZeros64(l)).unwrap_or(0);
            break;
        }
        t
    }

    /// `cmpGeq(y)` (nat.go:332) — 1 if x >= y, else 0; constant time.
    fn cmpGeq(&self, y: &Nat) -> choice {
        let size = self.limbs.len();
        let mut c: uint = 0;
        for i in 0..size {
            let (_, cc) = bits::Sub64(self.limbs[i], y.limbs[i], c);
            c = cc;
        }
        // A carry means the subtraction underflowed: x < y.
        not(c)
    }

    /// `assign(on, y)` (nat.go:352) — x <- y if `on == 1`, else nothing.
    fn assign(&mut self, on: choice, y: &Nat) -> &mut Nat {
        let size = self.limbs.len();
        let mask = ctMask(on);
        for i in 0..size {
            self.limbs[i] ^= mask & (self.limbs[i] ^ y.limbs[i]);
        }
        self
    }

    /// `add(y)` (nat.go:370) — x += y, returns the carry.
    fn add(&mut self, y: &Nat) -> uint {
        let size = self.limbs.len();
        let mut c: uint = 0;
        for i in 0..size {
            let (s, cc) = bits::Add64(self.limbs[i], y.limbs[i], c);
            self.limbs[i] = s;
            c = cc;
        }
        c
    }

    /// `sub(y)` (nat.go:387) — x -= y, returns the borrow.
    fn sub(&mut self, y: &Nat) -> uint {
        let size = self.limbs.len();
        let mut c: uint = 0;
        for i in 0..size {
            let (d, cc) = bits::Sub64(self.limbs[i], y.limbs[i], c);
            self.limbs[i] = d;
            c = cc;
        }
        c
    }

    /// `ShiftRightVarTime(n)` (nat.go:404) — x = x >> n; announced
    /// length unchanged.
    pub fn ShiftRightVarTime(&mut self, n: uint) -> &mut Nat {
        let size = self.limbs.len();
        let shift: uint = n % _W;
        let shiftLimbs = usize::try_from(n / _W).unwrap_or(usize::MAX);

        // shiftedLimbs is the window self.limbs[shiftLimbs:] (or empty).
        let shifted: Vec<uint> = if shiftLimbs < size {
            self.limbs[shiftLimbs..].to_vec()
        } else {
            Vec::new()
        };

        for i in 0..size {
            if i >= shifted.len() {
                self.limbs[i] = 0;
                continue;
            }
            let mut v = shifted[i] >> shift;
            if i + 1 < shifted.len() {
                // Go: shiftedLimbs[i+1] << (_W - shift). When shift == 0,
                // _W - shift == 64 which is a no-op shift in Go; Rust
                // would panic, so the high part is simply 0.
                if shift != 0 {
                    v |= shifted[i + 1] << (_W - shift);
                }
            }
            self.limbs[i] = v;
        }
        self
    }

    /// `BitLenVarTime()` (nat.go:436) — actual size of x in bits. The
    /// value (not just the announced size) leaks through timing.
    pub fn BitLenVarTime(&self) -> int {
        let size = self.limbs.len();
        let mut i = size;
        while i > 0 {
            i -= 1;
            if self.limbs[i] != 0 {
                return int::try_from(i).unwrap_or(0) * int::try_from(_W).unwrap_or(64)
                    + int::try_from(bitLen(self.limbs[i])).unwrap_or(0);
            }
        }
        0
    }

    /// `resetFor(m)` (nat.go:684) — ensure out has m's size; zeroed.
    fn resetFor(&mut self, m: &Modulus) -> &mut Nat {
        self.reset(m.nat.limbs.len())
    }

    /// `ExpandFor(m)` (nat.go:677) — ensure x has m's size. The announced
    /// size of x must be `<=` m's.
    pub fn ExpandFor(&mut self, m: &Modulus) -> &mut Nat {
        self.expand(m.nat.limbs.len())
    }

    /// `shiftIn(y, m)` (nat.go:607) — x = x << _W + y mod m. Assumes x is
    /// already reduced mod m.
    fn shiftIn(&mut self, y: uint, m: &Modulus) -> &mut Nat {
        let size = m.nat.limbs.len();
        let mut d: Vec<uint> = alloc::vec![0u64; size];

        // Each iteration computes x = 2x + b mod m for one bit b of y,
        // by computing both 2x + b and 2x + b - m and selecting later.
        let mut needSubtraction: choice = no;
        let mut i: int = int::try_from(_W).unwrap_or(64) - 1;
        while i >= 0 {
            let mut carry: uint = (y >> i) & 1;
            let mut borrow: uint = 0;
            let mask = ctMask(needSubtraction);
            for j in 0..size {
                let l = self.limbs[j] ^ (mask & (self.limbs[j] ^ d[j]));
                let (s, c) = bits::Add64(l, l, carry);
                self.limbs[j] = s;
                carry = c;
                let (sd, b) = bits::Sub64(self.limbs[j], m.nat.limbs[j], borrow);
                d[j] = sd;
                borrow = b;
            }
            // Need the subtraction if 2x+b didn't underflow m, or if
            // computing 2x+b overflowed (so 2x+b > 2^_W*n > m).
            needSubtraction = not(borrow) | carry;
            i -= 1;
        }
        let dn = Nat { limbs: d };
        self.assign(needSubtraction, &dn)
    }

    /// `Mod(x, m)` (nat.go:648) — out = x mod m, for x of any size.
    /// Output resized to m's size.
    pub fn Mod(&mut self, x: &Nat, m: &Modulus) -> &mut Nat {
        self.resetFor(m);
        // Insert each limb at the least-significant position, shifting
        // previous limbs left by _W each time. N-1 limbs can be inserted
        // without overflowing m; after that, reduce on every shift.
        let mut i: int = int::try_from(x.limbs.len()).unwrap_or(0) - 1;
        let mut start: int = int::try_from(m.nat.limbs.len()).unwrap_or(0) - 2;
        if i < start {
            start = i;
        }
        let mut j = start;
        while j >= 0 {
            self.limbs[j as usize] = x.limbs[i as usize];
            i -= 1;
            j -= 1;
        }
        while i >= 0 {
            self.shiftIn(x.limbs[i as usize], m);
            i -= 1;
        }
        self
    }

    /// `maybeSubtractModulus(always, m)` (nat.go:699) — x -= m iff x >= m
    /// or `always` is yes. Reduces a value up to `2m - 1`.
    fn maybeSubtractModulus(&mut self, always: choice, m: &Modulus) {
        let mut t = Nat::NewNat();
        t.set(self);
        let underflow = t.sub(&m.nat);
        // Keep x - m if it didn't underflow (x >= m) or if always set.
        let keep = not(underflow) | always;
        self.assign(keep, &t);
    }

    /// `Sub(y, m)` (nat.go:714) — x = x - y mod m. Operands must match
    /// m's size and be reduced modulo m.
    pub fn Sub(&mut self, y: &Nat, m: &Modulus) -> &mut Nat {
        let underflow = self.sub(y);
        // If the subtraction underflowed, add m back.
        let mut t = Nat::NewNat();
        t.set(self);
        t.add(&m.nat);
        self.assign(underflow, &t);
        self
    }

    /// `SubOne(m)` (nat.go:726) — x = x - 1 mod m. x must match m's size.
    pub fn SubOne(&mut self, m: &Modulus) -> &mut Nat {
        let mut one = Nat::NewNat();
        one.ExpandFor(m);
        one.limbs[0] = 1;
        self.Sub(&one, m)
    }

    /// `Add(y, m)` (nat.go:740) — x = x + y mod m. Operands must match
    /// m's size and be reduced modulo m.
    pub fn Add(&mut self, y: &Nat, m: &Modulus) -> &mut Nat {
        let overflow = self.add(y);
        self.maybeSubtractModulus(overflow, m);
        self
    }

    /// `montgomeryRepresentation(m)` (nat.go:753) — x = x * R mod m,
    /// `R = 2^(_W*n)`. Assumes x reduced mod m.
    fn montgomeryRepresentation(&mut self, m: &Modulus) -> &mut Nat {
        // Montgomery-multiplying by R*R works out to multiplying by R.
        let rr = m.rr.clone().expect("bigmod: even modulus has no rr");
        let xc = self.clone();
        self.montgomeryMul(&xc, &rr, m)
    }

    /// `montgomeryReduction(m)` (nat.go:763) — x = x / R mod m. Assumes
    /// x reduced mod m.
    fn montgomeryReduction(&mut self, m: &Modulus) -> &mut Nat {
        // Montgomery-multiplying by 1 (not in Montgomery form) divides
        // by R, taking x out of the Montgomery domain.
        let mut one = Nat::NewNat();
        one.ExpandFor(m);
        one.limbs[0] = 1;
        let xc = self.clone();
        self.montgomeryMul(&xc, &one, m)
    }

    /// `montgomeryMul(a, b, m)` (nat.go:779) — x = a * b / R mod m, a
    /// Montgomery multiplication. All inputs must share m's size and be
    /// reduced modulo m. x is resized to m's size.
    fn montgomeryMul(&mut self, a: &Nat, b: &Nat, m: &Modulus) -> &mut Nat {
        let n = m.nat.limbs.len();
        let mLimbs = &m.nat.limbs[..n];
        let aLimbs = &a.limbs[..n];
        let bLimbs = &b.limbs[..n];

        // Word-by-Word Montgomery Multiplication — Algorithm 4 of Gueron,
        // "Efficient Software Implementations of Modular Exponentiation".
        // The size-specialized Go cases (1024/1536/2048) call assembly;
        // here they all collapse into this generic loop.
        let mut t: Vec<uint> = alloc::vec![0u64; n * 2];
        let mut c: uint = 0;
        for i in 0..n {
            // Step 1 (T = a×b) is computed on the fly: digit d of the
            // multiplier, shifted product into T[i:n+i], carry c1.
            let d = bLimbs[i];
            let c1 = addMulVVW(&mut t[i..n + i], aLimbs, d);

            // Step 6 is the virtual window shift: our T is T[i:]. T1 of
            // the algorithm (T mod 2^_W) is T[i]; k0 is m.m0inv.
            let y = t[i].wrapping_mul(m.m0inv);

            // Steps 4-5 add Y×m to T (stored at T[i:]). The two carries
            // (from a×d and Y×m) add up in T[n+i], with that carry bit
            // brought forward to the next iteration.
            let c2 = addMulVVW(&mut t[i..n + i], mLimbs, y);
            let (s, cc) = bits::Add64(c1, c2, c);
            t[n + i] = s;
            c = cc;
        }

        // Step 7: copy the final T window into x and subtract m if
        // necessary (x >= m, or x overflowed — see maybeSubtractModulus).
        self.reset(n);
        self.limbs.copy_from_slice(&t[n..]);
        self.maybeSubtractModulus(c, m);
        self
    }

    /// `Mul(y, m)` (nat.go:924) — x = x * y mod m. Operands must match
    /// m's size and be reduced modulo m.
    pub fn Mul(&mut self, y: &Nat, m: &Modulus) -> &mut Nat {
        if m.odd {
            // A Montgomery multiplication by a value out of the
            // Montgomery domain takes the result out of it.
            let mut xR = Nat::NewNat();
            xR.set(self);
            xR.montgomeryRepresentation(m); // xR = x*R mod m
            let xR2 = xR.clone();
            return self.montgomeryMul(&xR2, y, m); // x = xR*y/R mod m
        }

        let n = m.nat.limbs.len();
        let xLimbs = self.limbs[..n].to_vec();
        let yLimbs = &y.limbs[..n];

        // T = x * y, then x = T mod m.
        let mut t: Vec<uint> = alloc::vec![0u64; n * 2];
        for i in 0..n {
            let carry = addMulVVW(&mut t[i..n + i], &xLimbs, yLimbs[i]);
            t[n + i] = carry;
        }
        let tn = Nat { limbs: t };
        self.Mod(&tn, m)
    }

    /// `Exp(x, e, m)` (nat.go:987) — out = x^e mod m, e big-endian.
    /// Output resized to m's size; x must be reduced mod m. Panics if m
    /// is even. Constant-time in e.
    pub fn Exp(&mut self, x: &Nat, e: slice<byte>, m: &Modulus) -> &mut Nat {
        if !m.odd {
            panic!("bigmod: modulus for Exp must be odd");
        }
        let ev = slice_to_vec(&e);

        // 4-bit window. table[i] = x^(i+1) in Montgomery form.
        let mut table: Vec<Nat> = Vec::with_capacity(15);
        for _ in 0..15 {
            table.push(Nat::NewNat());
        }
        table[0].set(x);
        table[0].montgomeryRepresentation(m);
        for i in 1..15 {
            let prev = table[i - 1].clone();
            let base = table[0].clone();
            table[i].montgomeryMul(&prev, &base, m);
        }

        self.resetFor(m);
        self.limbs[0] = 1;
        self.montgomeryRepresentation(m);
        let mut tmp = Nat::NewNat();
        tmp.ExpandFor(m);
        for &b in ev.iter() {
            for &j in [4i64, 0i64].iter() {
                // Square four times.
                let s0 = self.clone();
                self.montgomeryMul(&s0, &s0, m);
                let s1 = self.clone();
                self.montgomeryMul(&s1, &s1, m);
                let s2 = self.clone();
                self.montgomeryMul(&s2, &s2, m);
                let s3 = self.clone();
                self.montgomeryMul(&s3, &s3, m);

                // Constant-time table select of x^k.
                let k: uint = uint::from((b >> j) & 0b1111);
                for i in 0..table.len() {
                    let want = uint::try_from(i + 1).unwrap_or(0);
                    let ti = table[i].clone();
                    tmp.assign(ctEq(k, want), &ti);
                }

                // Multiply by x^k, discarding the result if k == 0.
                let out_c = self.clone();
                let tmp_c = tmp.clone();
                tmp.montgomeryMul(&out_c, &tmp_c, m);
                self.assign(not(ctEq(k, 0)), &tmp);
            }
        }

        self.montgomeryReduction(m)
    }

    /// `ExpShortVarTime(x, e, m)` (nat.go:1042) — out = x^e mod m. Output
    /// resized to m's size; x must be reduced mod m. Leaks e through
    /// timing. Panics if m is even.
    pub fn ExpShortVarTime(&mut self, x: &Nat, e: uint, m: &Modulus) -> &mut Nat {
        if !m.odd {
            panic!("bigmod: modulus for ExpShortVarTime must be odd");
        }
        // Conditional square-and-multiply chain, skipping leading zeroes.
        let mut xR = Nat::NewNat();
        xR.set(x);
        xR.montgomeryRepresentation(m);
        self.set(&xR);
        let usize_bits = bits::UintSize;
        let mut i = usize_bits - bits::Len64(e) + 1;
        while i < usize_bits {
            let s = self.clone();
            self.montgomeryMul(&s, &s, m);
            let shift = usize_bits - i - 1;
            let k = (e >> shift) & 1;
            if k != 0 {
                let s2 = self.clone();
                self.montgomeryMul(&s2, &xR, m);
            }
            i += 1;
        }
        self.montgomeryReduction(m)
    }

    /// `InverseVarTime(a, m)` (nat.go:1068) — x = a⁻¹ mod m; returns
    /// `(x, true)` if a is invertible, else `(x, false)` with x
    /// unchanged. a must be reduced mod m. Output resized to m's size.
    pub fn InverseVarTime(&mut self, a: &Nat, m: &Modulus) -> (Nat, bool) {
        match extendedGCD(a, &m.nat) {
            Err(_) => (self.clone(), false),
            Ok((u, big_a)) => {
                if u.IsOne() == no {
                    return (self.clone(), false);
                }
                self.set(&big_a);
                (self.clone(), true)
            }
        }
    }

    /// `GCDVarTime(a, b)` (nat.go:1083) — x = GCD(a, b); at least one of
    /// a/b must be odd and both non-zero. On error x is unchanged.
    /// Output resized to the size of the larger operand.
    pub fn GCDVarTime(&mut self, a: &Nat, b: &Nat) -> (Nat, error) {
        match extendedGCD(a, b) {
            Err(e) => (Nat::NewNat(), e),
            Ok((u, _)) => {
                self.set(&u);
                (self.clone(), errors::nil)
            }
        }
    }

    /// `DivShortVarTime(y)` (nat.go:1219) — x = x / y, returns the
    /// remainder. Panics if y is zero.
    pub fn DivShortVarTime(&mut self, y: uint) -> uint {
        if y == 0 {
            panic!("bigmod: division by zero");
        }
        let mut r: uint = 0;
        let mut i: int = int::try_from(self.limbs.len()).unwrap_or(0) - 1;
        while i >= 0 {
            let (q, rem) = bits::Div64(r, self.limbs[i as usize], y);
            self.limbs[i as usize] = q;
            r = rem;
            i -= 1;
        }
        r
    }
}

/// `addMulVVW(z, x, y)` (nat.go:902) — multiply multi-word x by single
/// word y, add into z, return the final carry. One row of a pen-and-
/// paper column multiplication.
fn addMulVVW(z: &mut [uint], x: &[uint], y: uint) -> uint {
    let mut carry: uint = 0;
    for i in 0..z.len() {
        let (hi0, lo0) = bits::Mul64(x[i], y);
        let (lo1, c0) = bits::Add64(lo0, z[i], 0);
        let (hi1, _) = bits::Add64(hi0, 0, c0);
        let (lo2, c1) = bits::Add64(lo1, carry, 0);
        let (hi2, _) = bits::Add64(hi1, 0, c1);
        carry = hi2;
        z[i] = lo2;
    }
    carry
}

// ─── Modulus (Go: nat.go:467) ─────────────────────────────────────────

/// `Modulus` is used for modular arithmetic, precomputing relevant
/// constants. It can leak the exact bit length of its value (stored
/// without padding) but keeps the value itself secret.
#[derive(Clone)]
pub struct Modulus {
    // The underlying natural number, stored without padding.
    nat: Nat,

    // If the modulus is even, the following fields are not set.
    odd: bool,
    m0inv: uint,       // -nat.limbs[0]⁻¹ mod _W
    rr: Option<Nat>,   // R*R for montgomeryRepresentation
}

impl Modulus {
    /// `NewModulus(b)` (nat.go:551) — a `Modulus` from big-endian bytes.
    /// The modulus must be greater than one. The bit length and parity
    /// leak through timing.
    pub fn NewModulus(b: slice<byte>) -> (Modulus, error) {
        let bv = slice_to_vec(&b);
        let mut n = Nat::NewNat();
        n.resetToBytes(&bv);
        newModulus(n)
    }

    /// `NewModulusProduct(a, b)` (nat.go:560) — a `Modulus` from the
    /// product of two big-endian byte slices. The result must be > 1.
    pub fn NewModulusProduct(a: slice<byte>, b: slice<byte>) -> (Modulus, error) {
        let av = slice_to_vec(&a);
        let bv = slice_to_vec(&b);
        let mut x = Nat::NewNat();
        x.resetToBytes(&av);
        let mut y = Nat::NewNat();
        y.resetToBytes(&bv);
        let xn = x.limbs.len();
        let yn = y.limbs.len();
        let mut n: Vec<uint> = alloc::vec![0u64; xn + yn];
        for i in 0..yn {
            let carry = addMulVVW(&mut n[i..i + xn], &x.limbs, y.limbs[i]);
            n[i + xn] = carry;
        }
        let mut nn = Nat { limbs: n };
        nn.trim();
        newModulus(nn)
    }

    /// `Size()` (nat.go:584) — size of m in bytes.
    pub fn Size(&self) -> int {
        (self.BitLen() + 7) / 8
    }

    /// `BitLen()` (nat.go:589) — size of m in bits.
    pub fn BitLen(&self) -> int {
        self.nat.BitLenVarTime()
    }

    /// `Nat()` (nat.go:594) — m as a `Nat` (a fresh copy).
    pub fn Nat(&self) -> Nat {
        let mut n = Nat::NewNat();
        n.set(&self.nat);
        n
    }
}

/// `newModulus(n)` (nat.go:570) — finalize a `Modulus` from its `Nat`.
fn newModulus(n: Nat) -> (Modulus, error) {
    let mut m = Modulus {
        nat: n,
        odd: false,
        m0inv: 0,
        rr: None,
    };
    if m.nat.IsZero() == yes || m.nat.IsOne() == yes {
        return (
            Modulus {
                nat: Nat::NewNat(),
                odd: false,
                m0inv: 0,
                rr: None,
            },
            errors::New("modulus must be > 1"),
        );
    }
    if m.nat.IsOdd() == 1 {
        m.odd = true;
        m.m0inv = minusInverseModW(m.nat.limbs[0]);
        m.rr = Some(rr(&m));
    }
    (m, errors::nil)
}

/// `minusInverseModW(x)` (nat.go:532) — compute -x⁻¹ mod _W, x odd.
fn minusInverseModW(x: uint) -> uint {
    // Each iteration doubles the correct low bits of the inverse in y.
    // The first three bits are already correct, so five doublings cover
    // 64 bits. See https://crypto.stackexchange.com/a/47496.
    let mut y = x;
    for _ in 0..5 {
        y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    }
    y.wrapping_neg()
}

/// `rr(m)` (nat.go:481) — compute R*R with `R = 2^(_W*n)`,
/// `n = len(m.nat.limbs)`.
fn rr(m: &Modulus) -> Nat {
    let mut rr = Nat::NewNat();
    rr.ExpandFor(m);
    let n: uint = uint::try_from(rr.limbs.len()).unwrap_or(0);
    let mLen: uint = uint::try_from(m.BitLen()).unwrap_or(0);
    let logR: uint = _W * n;

    // Start by computing R = 2^(_W*n) mod m, getting close to 2^⌊log₂m⌋
    // by setting the highest bit we can without needing a reduction.
    rr.limbs[(n - 1) as usize] = 1u64 << ((mLen - 1) % _W);
    // Double until we reach 2^(_W*n).
    let mut i = mLen - 1;
    while i < logR {
        let rc = rr.clone();
        rr.Add(&rc, m);
        i += 1;
    }

    // Get from R to 2^(_W*n) R mod m (one to R in the Montgomery
    // domain): a mix of doublings and a square-and-double chain.
    let threshold = n / 4;

    // How many of the most-significant exponent bits we compute with
    // doublings before crossing the threshold. `shr_w` mirrors Go's
    // `uint >> n` (n >= 64 yields 0); Rust would panic on shift-by-64.
    let mut ib: int = bits::UintSize;
    while shr_w(logR, ib) <= threshold {
        ib -= 1;
    }
    let mut k: uint = 0;
    while k < shr_w(logR, ib) {
        let rc = rr.clone();
        rr.Add(&rc, m);
        k += 1;
    }

    // Process the remaining exponent bits with a square-and-double chain.
    while ib > 0 {
        let rc = rr.clone();
        rr.montgomeryMul(&rc, &rc, m);
        ib -= 1;
        if shr_w(logR, ib) & 1 != 0 {
            let rc2 = rr.clone();
            rr.Add(&rc2, m);
        }
    }

    rr
}

/// Go-semantics right shift of a `uint` word: a shift count `>= _W`
/// yields 0 (Go defines this; Rust's `>>` panics in debug). The count is
/// an `int` to match the `bits::UintSize` index domain in `rr`.
fn shr_w(x: uint, n: int) -> uint {
    let n = uint::try_from(n).expect("bigmod: internal error: negative shift");
    if n >= _W {
        return 0;
    }
    x >> n
}

/// `bitLen(n)` (nat.go:452) — bits.Len that only leaks the bit length of
/// n, not its value (no lookup table).
fn bitLen(mut n: uint) -> int {
    let mut len: int = 0;
    // Comparison to zero is assumed constant time across non-zero values.
    while n != 0 {
        len += 1;
        n >>= 1;
    }
    len
}

/// `rshift1(a, carry)` (nat.go:1200) — a >>= 1, shifting `carry` into the
/// top bit of the most-significant limb.
fn rshift1(a: &mut Nat, carry: uint) {
    let size = a.limbs.len();
    for i in 0..size {
        a.limbs[i] >>= 1;
        if i + 1 < size {
            a.limbs[i] |= a.limbs[i + 1] << (_W - 1);
        } else {
            a.limbs[i] |= carry << (_W - 1);
        }
    }
}

/// `extendedGCD(a, m)` (nat.go:1096) — compute u and A such that
/// `u = GCD(a, m)` and `u = A*a - B*m`. u has the size of the larger of
/// a and m; A has m's size. Errors if a or m is zero, or both are even.
fn extendedGCD(a: &Nat, m: &Nat) -> Result<(Nat, Nat), error> {
    // Extended binary GCD (HAC Algorithm 14.61), adapted by BoringSSL to
    // bound coefficients and avoid negatives. Does not handle zero input.
    if a.IsZero() == yes || m.IsZero() == yes {
        return Err(errors::New("extendedGCD: a or m is zero"));
    }
    if a.IsOdd() == no && m.IsOdd() == no {
        return Err(errors::New("extendedGCD: both a and m are even"));
    }

    let size = a.limbs.len().max(m.limbs.len());
    let mut u = Nat::NewNat();
    u.set(a);
    u.expand(size);
    let mut v = Nat::NewNat();
    v.set(m);
    v.expand(size);

    let mut big_a = Nat::NewNat();
    big_a.reset(m.limbs.len());
    big_a.limbs[0] = 1;
    let mut big_b = Nat::NewNat();
    big_b.reset(a.limbs.len());
    let mut big_c = Nat::NewNat();
    big_c.reset(m.limbs.len());
    let mut big_d = Nat::NewNat();
    big_d.reset(a.limbs.len());
    big_d.limbs[0] = 1;

    // The Add calls below need a Modulus wrapper around the bare `Nat`,
    // matching Go's `&Modulus{nat: m}` / `&Modulus{nat: a}`.
    let m_mod = Modulus {
        nat: m.clone(),
        odd: false,
        m0inv: 0,
        rr: None,
    };
    let a_mod = Modulus {
        nat: a.clone(),
        odd: false,
        m0inv: 0,
        rr: None,
    };

    // Invariants (before/after each iteration):
    //   u = A*a - B*m, v = D*m - C*a, with bounded coefficients.
    // Each iteration shrinks at least one of u/v by a factor of two.
    loop {
        // If both u and v are odd, subtract the smaller from the larger.
        // If u == v, subtract from v to hit the modified exit condition.
        if u.IsOdd() == yes && v.IsOdd() == yes {
            if v.cmpGeq(&u) == no {
                u.sub(&v);
                let cc = big_c.clone();
                big_a.Add(&cc, &m_mod);
                let dd = big_d.clone();
                big_b.Add(&dd, &a_mod);
            } else {
                v.sub(&u);
                let aa = big_a.clone();
                big_c.Add(&aa, &m_mod);
                let bb = big_b.clone();
                big_d.Add(&bb, &a_mod);
            }
        }

        // Exactly one of u and v is now even.
        if u.IsOdd() == v.IsOdd() {
            panic!("bigmod: internal error: u and v are not in the expected state");
        }

        // Halve the even one and adjust the corresponding coefficient.
        if u.IsOdd() == no {
            rshift1(&mut u, 0);
            if big_a.IsOdd() == yes || big_b.IsOdd() == yes {
                let c1 = big_a.add(m);
                rshift1(&mut big_a, c1);
                let c2 = big_b.add(a);
                rshift1(&mut big_b, c2);
            } else {
                rshift1(&mut big_a, 0);
                rshift1(&mut big_b, 0);
            }
        } else {
            rshift1(&mut v, 0);
            if big_c.IsOdd() == yes || big_d.IsOdd() == yes {
                let c1 = big_c.add(m);
                rshift1(&mut big_c, c1);
                let c2 = big_d.add(a);
                rshift1(&mut big_d, c2);
            } else {
                rshift1(&mut big_c, 0);
                rshift1(&mut big_d, 0);
            }
        }

        if v.IsZero() == yes {
            return Ok((u, big_a));
        }
    }
}

/// Internal: copy a goish `slice<byte>` into a `Vec<byte>` for byte-level
/// loops. Conversion at the boundary; no Rust container leaks the API.
fn slice_to_vec(s: &slice<byte>) -> Vec<byte> {
    let n = s.Len();
    let mut v: Vec<byte> = Vec::with_capacity(n as usize);
    let mut i: int = 0;
    while i < n {
        v.push(s[i]);
        i += 1;
    }
    v
}
