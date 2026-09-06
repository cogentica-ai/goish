// go: file vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go decls: initialize, mul64, add128, shiftRightBy2, updateGeneric, select64, finalize, newMACGeneric, macGeneric.Write, macGeneric.Sum
// goishlint:ignore GOISH018 sumGeneric — Go's one-shot convenience
//     wrapper: newMACGeneric, Write, Sum. Nothing in goish calls it;
//     the public poly1305::Sum in poly1305.rs is that shape already.
// goishlint:ignore GOISH021 uint128 — spelled `U128` here, because
//     `u128` is a Rust primitive and `uint128` would read as one.
// goishlint:ignore GOISH021 maskLow2Bits, maskNotLow2Bits — Go names
//     these two constants and uses each once, inside updateGeneric
//     and finalize. goish writes the literals at those same two
//     sites; the clamping masks that DO get names here are the ones
//     Go also names, R_MASK0 and R_MASK1.
//
// crypto/poly1305 — the portable Poly1305 arithmetic: the 130-bit
// accumulator, its 128-bit helpers, and the block update. Go keeps
// these in their own file so the assembly builds can replace the
// whole thing; goish has no assembly path, so this is always what
// runs.
//
// Deviations worth naming:
//   * Go's `uint128` is `U128` here — `u128` is a Rust primitive and
//     the name would shadow it.
//   * Go reaches for `bits.Add64` / `bits.Sub64`; `adc` and `sbb` are
//     those two, spelled locally, and carry `// go: none`.
//   * `initialize` is `mac_initialize`: `initialize` alone reads as a
//     constructor for the module rather than for macState.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::types::byte;

use super::poly1305::TagSize;

// ─── clamping masks ────────────────────────────────────────────────────
const R_MASK0: u64 = 0x0FFFFFFC0FFFFFFF;
const R_MASK1: u64 = 0x0FFFFFFC0FFFFFFC;

// ─── uint128 helpers ───────────────────────────────────────────────────

#[derive(Copy, Clone)]
struct U128 {
    lo: u64,
    hi: u64,
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go:119-122 mul64
#[inline(always)]
fn mul64(a: u64, b: u64) -> U128 {
    let v = (a as u128) * (b as u128);
    return U128 {
        lo: v as u64, // goishlint:ignore GOISH005 - narrowing a u128 intermediate; goish has no uint128 and so no call-cast from one
        hi: (v >> 64) as u64, // goishlint:ignore GOISH005 - same u128 intermediate, high half
    };
}

#[inline(always)]
// go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go:124-131 add128
fn add128(a: U128, b: U128) -> U128 {
    let lo = a.lo.wrapping_add(b.lo);
    let carry = if lo < a.lo { 1u64 } else { 0u64 };
    return U128 {
        lo,
        hi: a.hi.wrapping_add(b.hi).wrapping_add(carry),
    };
}

#[inline(always)]
// go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go:133-137 shiftRightBy2
fn shift_right_by_2(a: U128) -> U128 {
    return U128 {
        lo: (a.lo >> 2) | ((a.hi & 3) << 62),
        hi: a.hi >> 2,
    };
}

/// `bits.Add64(a, b, c)` — returns (a + b + c mod 2^64, carry_out).
/// Equivalent to Go's `bits.Add64`. The naive
/// `a.overflowing_add(b.wrapping_add(c))` loses the carry when `b + c`
/// overflows (e.g. b = u64::MAX, c = 1), which is the bug that broke
/// Poly1305 finalization for ~25% of TLS 1.3 ChaCha20-Poly1305 sessions.
#[inline(always)]
// go: none — goish helper. Go calls bits.Add64 from math/bits;
// this is that, spelled locally.
fn adc(a: u64, b: u64, carry_in: u64) -> (u64, u64) {
    let (x, c1) = a.overflowing_add(b);
    let (y, c2) = x.overflowing_add(carry_in);
    return (y, (c1 as u64) | (c2 as u64)); // goishlint:ignore GOISH005 - bool to u64; goish has no call-cast from bool
}

/// `bits.Sub64(a, b, c)` — returns (a - b - c mod 2^64, borrow_out).
/// See `adc` for why a separate helper is required.
#[inline(always)]
// go: none — goish helper. Go calls bits.Sub64 from math/bits.
fn sbb(a: u64, b: u64, borrow_in: u64) -> (u64, u64) {
    let (x, b1) = a.overflowing_sub(b);
    let (y, b2) = x.overflowing_sub(borrow_in);
    return (y, (b1 as u64) | (b2 as u64)); // goishlint:ignore GOISH005 - bool to u64; goish has no call-cast from bool
}

// ─── internal state ────────────────────────────────────────────────────

#[derive(Clone)]
struct MacState {
    h: [u64; 3],
    r: [u64; 2],
    s: [u64; 2],
}

#[derive(Clone)]
pub(super) struct MacGeneric {
    state: MacState,
    buffer: [byte; TagSize],
    offset: usize,
}

// go: none — goish helper. Go writes
// binary.LittleEndian.Uint64(msg) inline at each use site.
fn read_u64_le(b: &[byte]) -> u64 {
    return u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go:106-111 initialize
// goishlint:ignore GOISH014 - the anchor names the GO symbol. `initialize` alone would read as a
//     constructor for the module rather than for macState, so the Rust
//     fn is `mac_initialize`.
fn mac_initialize(key: &[byte; 32], state: &mut MacState) {
    state.r[0] = read_u64_le(&key[0..8]) & R_MASK0;
    state.r[1] = read_u64_le(&key[8..16]) & R_MASK1;
    state.s[0] = read_u64_le(&key[16..24]);
    state.s[1] = read_u64_le(&key[24..32]);
    state.h = [0, 0, 0];
}

const MASK_LOW2: u64 = 0x0000000000000003;
const MASK_NOT_LOW2: u64 = !MASK_LOW2;

// 2^130 - 5 in little-endian limbs
const P0: u64 = 0xFFFFFFFFFFFFFFFB;
const P1: u64 = 0xFFFFFFFFFFFFFFFF;
const P2: u64 = 0x0000000000000003;

// go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go:146-265 updateGeneric
fn update_generic(state: &mut MacState, msg: &[byte]) {
    let mut h0 = state.h[0];
    let mut h1 = state.h[1];
    let mut h2 = state.h[2];
    let r0 = state.r[0];
    let r1 = state.r[1];

    let mut msg = msg;
    while !msg.is_empty() {
        if msg.len() >= TagSize {
            // h += msg (128-bit addition with carry chain)
            let (lo, c0) = adc(h0, read_u64_le(&msg[0..8]), 0);
            h0 = lo;
            let (hi, c1) = adc(h1, read_u64_le(&msg[8..16]), c0);
            h1 = hi;
            // The bit above 2^128 is +1 for full blocks (the "hi bit" in Poly1305)
            h2 = h2.wrapping_add(c1).wrapping_add(1);
            msg = &msg[TagSize..];
        } else {
            let mut buf = [0u8; TagSize];
            buf[..msg.len()].copy_from_slice(msg);
            buf[msg.len()] = 1;
            let (lo, c0) = adc(h0, read_u64_le(&buf[0..8]), 0);
            h0 = lo;
            let (hi, c1) = adc(h1, read_u64_le(&buf[8..16]), c0);
            h1 = hi;
            h2 = h2.wrapping_add(c1);
            msg = &[];
        }

        // Multiply h by r mod 2^130-5
        let h0r0 = mul64(h0, r0);
        let h1r0 = mul64(h1, r0);
        let h2r0 = mul64(h2, r0);
        let h0r1 = mul64(h0, r1);
        let h1r1 = mul64(h1, r1);
        let h2r1 = mul64(h2, r1);

        let m0 = h0r0;
        let m1 = add128(h1r0, h0r1);
        let m2 = add128(U128 { lo: h2r0.lo, hi: 0 }, h1r1);
        let m3 = U128 { lo: h2r1.lo, hi: 0 };

        let t0 = m0.lo;
        let (t1, c1) = adc(m1.lo, m0.hi, 0);
        let (t2, c2) = adc(m2.lo, m1.hi, c1);
        let (t3, _) = adc(m3.lo, m2.hi, c2);

        // Partial reduction mod 2^130 - 5
        h0 = t0;
        h1 = t1;
        h2 = t2 & MASK_LOW2;
        let cc = U128 {
            lo: t2 & MASK_NOT_LOW2,
            hi: t3,
        };

        let (lo, b1) = adc(h0, cc.lo, 0);
        h0 = lo;
        let (hi, b2) = adc(h1, cc.hi, b1);
        h1 = hi;
        h2 = h2.wrapping_add(b2);

        let cc2 = shift_right_by_2(cc);
        let (lo, b1) = adc(h0, cc2.lo, 0);
        h0 = lo;
        let (hi, b2) = adc(h1, cc2.hi, b1);
        h1 = hi;
        h2 = h2.wrapping_add(b2);
    }

    state.h[0] = h0;
    state.h[1] = h1;
    state.h[2] = h2;
}

#[inline(always)]
// go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go:273-273 select64
fn select64(v: u64, x: u64, y: u64) -> u64 {
    // v == 1 → x, v == 0 → y (constant-time)
    return (!v.wrapping_sub(1) & x) | (v.wrapping_sub(1) & y);
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go:285-312 finalize
fn finalize(out: &mut [byte; TagSize], h: &[u64; 3], s: &[u64; 2]) {
    let (h0, h1, h2) = (h[0], h[1], h[2]);

    // Compute hp = h - p with a proper borrow chain.
    // Reduction: if the subtraction underflows (b2 == 1), then h < p, use h;
    // otherwise use hp = h - p.
    let (hp0, b0) = sbb(h0, P0, 0);
    let (hp1, b1) = sbb(h1, P1, b0);
    let (_, b2) = sbb(h2, P2, b1);

    // select64(v=1, a, b) → a, select64(v=0, a, b) → b.
    // b2 == 1 means underflow (h < p) — keep h. Else use hp.
    let f0 = select64(b2, h0, hp0);
    let f1 = select64(b2, h1, hp1);

    // h + s mod 2^128
    let (r0, c) = adc(f0, s[0], 0);
    let (r1, _) = adc(f1, s[1], c);

    out[0..8].copy_from_slice(&r0.to_le_bytes());
    out[8..16].copy_from_slice(&r1.to_le_bytes());
}

impl MacGeneric {
    // go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go:37-41 newMACGeneric
// goishlint:ignore GOISH014 - the anchor names the GO symbol. Go's constructor returns a
//     macGeneric value; the Rust spelling is an associated
//     `MacGeneric::new_from_key`, which cannot be called newMACGeneric.
    pub(super) fn new_from_key(key: &[byte; 32]) -> Self {
        let mut m = MacGeneric {
            state: MacState {
                h: [0; 3],
                r: [0; 2],
                s: [0; 2],
            },
            buffer: [0u8; TagSize],
            offset: 0,
        };
        mac_initialize(key, &mut m.state);
        return m;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go:64-84 macGeneric.Write
    pub(super) fn write(&mut self, p: &[byte]) {
        let mut p = p;
        if self.offset > 0 {
            let n = if TagSize - self.offset < p.len() {
                TagSize - self.offset
            } else {
                p.len()
            };
            self.buffer[self.offset..self.offset + n].copy_from_slice(&p[..n]);
            p = &p[n..];
            self.offset += n;
            if self.offset == TagSize {
                let buf = self.buffer;
                update_generic(&mut self.state, &buf);
                self.offset = 0;
            }
        }
        if p.len() >= TagSize {
            let n = p.len() - (p.len() % TagSize);
            update_generic(&mut self.state, &p[..n]);
            p = &p[n..];
        }
        if !p.is_empty() {
            self.buffer[..p.len()].copy_from_slice(p);
            self.offset = p.len();
        }
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go:89-95 macGeneric.Sum
// goishlint:ignore GOISH014 - the anchor names the GO symbol. Go's `Sum` writes through an out
//     pointer; the Rust fn is `sum_into` so it does not collide with
//     the public `MAC::Sum`, which appends.
    pub(super) fn sum_into(&self, out: &mut [byte; TagSize]) {
        let mut state = self.state.clone();
        if self.offset > 0 {
            update_generic(&mut state, &self.buffer[..self.offset]);
        }
        finalize(out, &state.h, &state.s);
    }
}
