// crypto/ecdh — ECDH key agreement.
//
// v1 ships X25519 only (curve25519, RFC 7748).
//
// This implementation uses 10 × 26/25-bit limbs (radix 2^25.5),
// the same representation used by Go's crypto/internal/edwards25519/field.
//
// KAT (RFC 7748 §6.1):
//   scalar = a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
//   u_in   = e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
//   output = c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552

#![allow(non_snake_case, non_camel_case_types, dead_code)]

extern crate alloc;

use crate::types::byte;

// ─── Public key types ─────────────────────────────────────────────────

#[derive(Clone)]
pub struct X25519PrivateKey(pub [u8; 32]);

#[derive(Clone)]
pub struct X25519PublicKey(pub [u8; 32]);

// ─── Field arithmetic (radix 2^25.5, 10 limbs) ───────────────────────
//
// Elements are stored as [i32; 10] where:
//   f = f[0] + f[1]*2^26 + f[2]*2^51 + f[3]*2^77 + f[4]*2^102
//     + f[5]*2^128 + f[6]*2^153 + f[7]*2^179 + f[8]*2^204 + f[9]*2^230
//
// Odd-indexed limbs use 25-bit words, even-indexed use 26-bit words.
// This is the "ref10" representation from SUPERCOP/NaCl.

type Fe = [i64; 10];

fn fe_0() -> Fe { [0i64; 10] }
fn fe_1() -> Fe { let mut f = fe_0(); f[0] = 1; f }

/// Load 32 bytes into a field element.
fn fe_from_bytes(b: &[u8; 32]) -> Fe {
    let mut b2 = *b;
    // Per RFC 7748: mask the top bit of the last byte.
    b2[31] &= 0x7F;

    macro_rules! load4 {
        ($b:expr, $i:expr) => {
            ($b[$i] as i64) // goishlint:ignore GOISH005
            | (($b[$i+1] as i64) << 8) // goishlint:ignore GOISH005
            | (($b[$i+2] as i64) << 16) // goishlint:ignore GOISH005
            | (($b[$i+3] as i64) << 24) // goishlint:ignore GOISH005
        }
    }
    macro_rules! load3 {
        ($b:expr, $i:expr) => {
            ($b[$i] as i64) // goishlint:ignore GOISH005
            | (($b[$i+1] as i64) << 8) // goishlint:ignore GOISH005
            | (($b[$i+2] as i64) << 16) // goishlint:ignore GOISH005
        }
    }

    let h0 = load4!(b2, 0);
    let h1 = load3!(b2, 4) << 6;
    let h2 = load3!(b2, 7) << 5;
    let h3 = load3!(b2, 10) << 3;
    let h4 = load3!(b2, 13) << 2;
    let h5 = load4!(b2, 16);
    let h6 = load3!(b2, 20) << 7;
    let h7 = load3!(b2, 23) << 5;
    let h8 = load3!(b2, 26) << 4;
    let h9 = (load3!(b2, 29) & 0x7FFFFF) << 2;

    // Carry propagation to normalize limbs.
    fe_carry10([h0, h1, h2, h3, h4, h5, h6, h7, h8, h9])
}

/// Write a field element to 32 bytes in canonical form.
fn fe_to_bytes(f: &Fe) -> [u8; 32] {
    let h = fe_reduce(f);

    let mut out = [0u8; 32];
    out[0]  = (h[0])                        as u8; // goishlint:ignore GOISH005
    out[1]  = (h[0] >>  8)                  as u8; // goishlint:ignore GOISH005
    out[2]  = (h[0] >> 16)                  as u8; // goishlint:ignore GOISH005
    out[3]  = ((h[0] >> 24) | (h[1] << 2)) as u8; // goishlint:ignore GOISH005
    out[4]  = (h[1] >>  6)                  as u8; // goishlint:ignore GOISH005
    out[5]  = (h[1] >> 14)                  as u8; // goishlint:ignore GOISH005
    out[6]  = ((h[1] >> 22) | (h[2] << 3)) as u8; // goishlint:ignore GOISH005
    out[7]  = (h[2] >>  5)                  as u8; // goishlint:ignore GOISH005
    out[8]  = (h[2] >> 13)                  as u8; // goishlint:ignore GOISH005
    out[9]  = ((h[2] >> 21) | (h[3] << 5)) as u8; // goishlint:ignore GOISH005
    out[10] = (h[3] >>  3)                  as u8; // goishlint:ignore GOISH005
    out[11] = (h[3] >> 11)                  as u8; // goishlint:ignore GOISH005
    out[12] = ((h[3] >> 19) | (h[4] << 6)) as u8; // goishlint:ignore GOISH005
    out[13] = (h[4] >>  2)                  as u8; // goishlint:ignore GOISH005
    out[14] = (h[4] >> 10)                  as u8; // goishlint:ignore GOISH005
    out[15] = (h[4] >> 18)                  as u8; // goishlint:ignore GOISH005
    out[16] = (h[5])                        as u8; // goishlint:ignore GOISH005
    out[17] = (h[5] >>  8)                  as u8; // goishlint:ignore GOISH005
    out[18] = (h[5] >> 16)                  as u8; // goishlint:ignore GOISH005
    out[19] = ((h[5] >> 24) | (h[6] << 1)) as u8; // goishlint:ignore GOISH005
    out[20] = (h[6] >>  7)                  as u8; // goishlint:ignore GOISH005
    out[21] = (h[6] >> 15)                  as u8; // goishlint:ignore GOISH005
    out[22] = ((h[6] >> 23) | (h[7] << 3)) as u8; // goishlint:ignore GOISH005
    out[23] = (h[7] >>  5)                  as u8; // goishlint:ignore GOISH005
    out[24] = (h[7] >> 13)                  as u8; // goishlint:ignore GOISH005
    out[25] = ((h[7] >> 21) | (h[8] << 4)) as u8; // goishlint:ignore GOISH005
    out[26] = (h[8] >>  4)                  as u8; // goishlint:ignore GOISH005
    out[27] = (h[8] >> 12)                  as u8; // goishlint:ignore GOISH005
    out[28] = ((h[8] >> 20) | (h[9] << 6)) as u8; // goishlint:ignore GOISH005
    out[29] = (h[9] >>  2)                  as u8; // goishlint:ignore GOISH005
    out[30] = (h[9] >> 10)                  as u8; // goishlint:ignore GOISH005
    out[31] = (h[9] >> 18)                  as u8; // goishlint:ignore GOISH005
    out
}

/// Carry propagation for 10-limb representation.
/// Uses the NaCl/SUPERCOP carry order for fe_mul outputs.
/// Even limbs are 26-bit, odd limbs are 25-bit.
fn fe_carry10(h: Fe) -> Fe {
    let mut h = h;
    let mut c: i64;
    // First pass: interleaved 0↔1, 4↔5, 1↔2, 5↔6, 2↔3, 6↔7, 3↔4, 7↔8, 4↔5, 8↔9
    c=(h[0]+(1<<25))>>26; h[0]-=c<<26; h[1]+=c;
    c=(h[4]+(1<<25))>>26; h[4]-=c<<26; h[5]+=c;
    c=(h[1]+(1<<24))>>25; h[1]-=c<<25; h[2]+=c;
    c=(h[5]+(1<<24))>>25; h[5]-=c<<25; h[6]+=c;
    c=(h[2]+(1<<25))>>26; h[2]-=c<<26; h[3]+=c;
    c=(h[6]+(1<<25))>>26; h[6]-=c<<26; h[7]+=c;
    c=(h[3]+(1<<24))>>25; h[3]-=c<<25; h[4]+=c;
    c=(h[7]+(1<<24))>>25; h[7]-=c<<25; h[8]+=c;
    c=(h[4]+(1<<25))>>26; h[4]-=c<<26; h[5]+=c;
    c=(h[8]+(1<<25))>>26; h[8]-=c<<26; h[9]+=c;
    // h[9] wraps: its carry goes to h[0]*19
    c=(h[9]+(1<<24))>>25; h[9]-=c<<25; h[0]+=c*19;
    // final carry from h[0]
    c=(h[0]+(1<<25))>>26; h[0]-=c<<26; h[1]+=c;
    h
}

/// Reduce to canonical form in [0, p).
fn fe_reduce(f: &Fe) -> Fe {
    let mut h = *f;
    let mut c: i64;
    // First pass: normalize to bounded limbs.
    c=h[0]>>26; h[0]-=c<<26; h[1]+=c;
    c=h[1]>>25; h[1]-=c<<25; h[2]+=c;
    c=h[2]>>26; h[2]-=c<<26; h[3]+=c;
    c=h[3]>>25; h[3]-=c<<25; h[4]+=c;
    c=h[4]>>26; h[4]-=c<<26; h[5]+=c;
    c=h[5]>>25; h[5]-=c<<25; h[6]+=c;
    c=h[6]>>26; h[6]-=c<<26; h[7]+=c;
    c=h[7]>>25; h[7]-=c<<25; h[8]+=c;
    c=h[8]>>26; h[8]-=c<<26; h[9]+=c;
    c=h[9]>>25; h[9]-=c<<25; h[0]+=c*19;
    c=h[0]>>26; h[0]-=c<<26; h[1]+=c;
    // Determine q = floor((h + 19) / 2^255) to decide if we subtract p.
    let mut q = (19*h[9]+(1i64<<24))>>25;
    q=(q+h[0])>>26; q=(q+h[1])>>25; q=(q+h[2])>>26; q=(q+h[3])>>25;
    q=(q+h[4])>>26; q=(q+h[5])>>25; q=(q+h[6])>>26; q=(q+h[7])>>25;
    q=(q+h[8])>>26; q=(q+h[9])>>25;
    h[0]+=19*q;
    // Final carry propagation.
    c=h[0]>>26; h[0]-=c<<26; h[1]+=c;
    c=h[1]>>25; h[1]-=c<<25; h[2]+=c;
    c=h[2]>>26; h[2]-=c<<26; h[3]+=c;
    c=h[3]>>25; h[3]-=c<<25; h[4]+=c;
    c=h[4]>>26; h[4]-=c<<26; h[5]+=c;
    c=h[5]>>25; h[5]-=c<<25; h[6]+=c;
    c=h[6]>>26; h[6]-=c<<26; h[7]+=c;
    c=h[7]>>25; h[7]-=c<<25; h[8]+=c;
    c=h[8]>>26; h[8]-=c<<26; h[9]+=c;
    h
}

fn fe_add(f: &Fe, g: &Fe) -> Fe {
    let mut h: Fe = fe_0();
    for i in 0..10 { h[i] = f[i] + g[i]; }
    h
}

fn fe_sub(f: &Fe, g: &Fe) -> Fe {
    let mut h: Fe = fe_0();
    for i in 0..10 { h[i] = f[i] - g[i]; }
    h
}

/// Field multiplication: h = f * g.
/// Uses schoolbook multiplication with the "ref10" radix.
fn fe_mul(f: &Fe, g: &Fe) -> Fe {
    let f0 = f[0]; let f1 = f[1]; let f2 = f[2]; let f3 = f[3]; let f4 = f[4];
    let f5 = f[5]; let f6 = f[6]; let f7 = f[7]; let f8 = f[8]; let f9 = f[9];
    let g0 = g[0]; let g1 = g[1]; let g2 = g[2]; let g3 = g[3]; let g4 = g[4];
    let g5 = g[5]; let g6 = g[6]; let g7 = g[7]; let g8 = g[8]; let g9 = g[9];

    // Precompute 2*f for odd-indexed f (optimization from ref10).
    let f1_2 = 2*f1; let f3_2 = 2*f3; let f5_2 = 2*f5; let f7_2 = 2*f7; let f9_2 = 2*f9;
    // Precompute 19*g for wrapping terms.
    let g1_19 = 19*g1; let g2_19 = 19*g2; let g3_19 = 19*g3; let g4_19 = 19*g4;
    let g5_19 = 19*g5; let g6_19 = 19*g6; let g7_19 = 19*g7; let g8_19 = 19*g8;
    let g9_19 = 19*g9;

    // h[i] = sum of products f[j]*g[i-j] where for j > i we use the wrapped term (19*g[...]).
    // (All variables are already i64; no casts needed.)
    let h0 = f0*g0 + f1_2*g9_19 + f2*g8_19 + f3_2*g7_19 + f4*g6_19
           + f5_2*g5_19 + f6*g4_19 + f7_2*g3_19 + f8*g2_19 + f9_2*g1_19;
    let h1 = f0*g1 + f1*g0 + f2*g9_19 + f3*g8_19 + f4*g7_19
           + f5*g6_19 + f6*g5_19 + f7*g4_19 + f8*g3_19 + f9*g2_19;
    let h2 = f0*g2 + f1_2*g1 + f2*g0 + f3_2*g9_19 + f4*g8_19
           + f5_2*g7_19 + f6*g6_19 + f7_2*g5_19 + f8*g4_19 + f9_2*g3_19;
    let h3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g9_19
           + f5*g8_19 + f6*g7_19 + f7*g6_19 + f8*g5_19 + f9*g4_19;
    let h4 = f0*g4 + f1_2*g3 + f2*g2 + f3_2*g1 + f4*g0
           + f5_2*g9_19 + f6*g8_19 + f7_2*g7_19 + f8*g6_19 + f9_2*g5_19;
    let h5 = f0*g5 + f1*g4 + f2*g3 + f3*g2 + f4*g1
           + f5*g0 + f6*g9_19 + f7*g8_19 + f8*g7_19 + f9*g6_19;
    let h6 = f0*g6 + f1_2*g5 + f2*g4 + f3_2*g3 + f4*g2
           + f5_2*g1 + f6*g0 + f7_2*g9_19 + f8*g8_19 + f9_2*g7_19;
    let h7 = f0*g7 + f1*g6 + f2*g5 + f3*g4 + f4*g3
           + f5*g2 + f6*g1 + f7*g0 + f8*g9_19 + f9*g8_19;
    let h8 = f0*g8 + f1_2*g7 + f2*g6 + f3_2*g5 + f4*g4
           + f5_2*g3 + f6*g2 + f7_2*g1 + f8*g0 + f9_2*g9_19;
    let h9 = f0*g9 + f1*g8 + f2*g7 + f3*g6 + f4*g5
           + f5*g4 + f6*g3 + f7*g2 + f8*g1 + f9*g0;

    fe_carry10([h0, h1, h2, h3, h4, h5, h6, h7, h8, h9])
}

fn fe_sqr(f: &Fe) -> Fe {
    fe_mul(f, f)
}

/// Constant-time conditional swap.
fn cswap(swap: u32, a: &mut Fe, b: &mut Fe) {
    let mask = (swap as i64).wrapping_neg(); // goishlint:ignore GOISH005
    for i in 0..10 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// Compute a^(p-2) mod p (modular inverse via Fermat's little theorem).
/// Uses the standard addition chain for 2^255 - 21.
fn fe_invert(z: &Fe) -> Fe {
    // Addition chain from Go's field.Element.Invert().
    // z^(2^255-19-2) = z^(2^255-21)
    let z1    = *z;
    let z2    = fe_sqr(&z1);            // z^2
    let z8    = fe_sqr(&fe_sqr(&z2));   // z^8 via z4=z^4
    let z9    = fe_mul(&z1, &z8);       // z^9
    let z11   = fe_mul(&z2, &z9);       // z^11
    let z22   = fe_sqr(&z11);           // z^22
    let z_2_5_0 = fe_mul(&z9, &z22);   // z^(2^5 - 1) = z^31

    // z^(2^10 - 1)
    let t  = fe_pow2k(&z_2_5_0, 5);    // z^(2^10 - 2^5)
    let z_2_10_0 = fe_mul(&t, &z_2_5_0); // z^(2^10 - 1)

    // z^(2^20 - 1)
    let t  = fe_pow2k(&z_2_10_0, 10);
    let z_2_20_0 = fe_mul(&t, &z_2_10_0);

    // z^(2^40 - 1)
    let t  = fe_pow2k(&z_2_20_0, 20);
    let t  = fe_mul(&t, &z_2_20_0);
    let z_2_40_0 = fe_pow2k(&t, 10);
    let z_2_50_0 = fe_mul(&z_2_40_0, &z_2_10_0); // z^(2^50 - 1)

    // z^(2^100 - 1)
    let t  = fe_pow2k(&z_2_50_0, 50);
    let z_2_100_0 = fe_mul(&t, &z_2_50_0);

    // z^(2^200 - 1)
    let t  = fe_pow2k(&z_2_100_0, 100);
    let t  = fe_mul(&t, &z_2_100_0);

    // z^(2^250 - 1)
    let t  = fe_pow2k(&t, 50);
    let t  = fe_mul(&t, &z_2_50_0);

    // z^(2^255 - 21): square 5 more times, then multiply by z^11.
    let t  = fe_pow2k(&t, 5);
    fe_mul(&t, &z11)
}

/// Compute z^(2^k) by squaring k times.
fn fe_pow2k(z: &Fe, k: u32) -> Fe {
    let mut t = fe_sqr(z);
    for _ in 1..k {
        t = fe_sqr(&t);
    }
    t
}

// ─── Montgomery ladder (RFC 7748 §5) ─────────────────────────────────

/// X25519 scalar multiplication via the Montgomery ladder.
/// The scalar is clamped per RFC 7748 §5 before use.
pub fn x25519_scalarmult(scalar: &[u8; 32], u_in: &[u8; 32]) -> [u8; 32] {
    // Clamp the scalar per RFC 7748 §5.
    let mut k = *scalar;
    k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let u = fe_from_bytes(u_in);

    // a24 = 121665
    let a24: Fe = { let mut f = fe_0(); f[0] = 121665; f };

    let x_1 = u;
    let mut x_2 = fe_1();
    let mut z_2 = fe_0();
    let mut x_3 = u;
    let mut z_3 = fe_1();
    let mut swap: u32 = 0;

    // Process scalar bits from 254 down to 0.
    let mut t: i32 = 254;
    while t >= 0 {
        let k_t: u32 = ((k[(t as usize) / 8] >> ((t as usize) % 8)) & 1) as u32; // goishlint:ignore GOISH005

        swap ^= k_t;
        cswap(swap, &mut x_2, &mut x_3);
        cswap(swap, &mut z_2, &mut z_3);
        swap = k_t;

        // Double-and-add step from RFC 7748 §5.
        let a      = fe_add(&x_2, &z_2);
        let aa     = fe_sqr(&a);
        let b      = fe_sub(&x_2, &z_2);
        let bb     = fe_sqr(&b);
        let e      = fe_sub(&aa, &bb);
        let c      = fe_add(&x_3, &z_3);
        let d      = fe_sub(&x_3, &z_3);
        let da     = fe_mul(&d, &a);
        let cb     = fe_mul(&c, &b);
        let da_cb  = fe_add(&da, &cb);
        let da_cb2 = fe_sub(&da, &cb);
        x_3 = fe_sqr(&da_cb);
        z_3 = fe_mul(&x_1, &fe_sqr(&da_cb2));
        x_2 = fe_mul(&aa, &bb);
        let a24e   = fe_mul(&a24, &e);
        let aa_a24e= fe_add(&aa, &a24e);
        z_2 = fe_mul(&e, &aa_a24e);

        t -= 1;
    }

    // Final conditional swap.
    cswap(swap, &mut x_2, &mut x_3);
    cswap(swap, &mut z_2, &mut z_3);

    // Result = x_2 * z_2^(p-2) mod p.
    let z2_inv = fe_invert(&z_2);
    let result = fe_mul(&x_2, &z2_inv);
    fe_to_bytes(&result)
}

// ─── Public API ───────────────────────────────────────────────────────

fn x25519_base_point() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
}

/// Generate a fresh X25519 keypair using the system CSPRNG.
pub fn x25519_generate() -> (X25519PrivateKey, X25519PublicKey) {
    let mut sk = [0u8; 32];
    {
        let mut buf = crate::goslice::slice::<byte>::__from_vec(alloc::vec![0u8; 32]);
        let _ = crate::crypto::rand::Read(&mut buf);
        let v = buf.__into_vec();
        sk.copy_from_slice(&v[..32]);
    }
    // Clamp the scalar per RFC 7748 §5.
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    let pk = x25519_scalarmult(&sk, &x25519_base_point());
    (X25519PrivateKey(sk), X25519PublicKey(pk))
}

/// Compute the X25519 shared secret.
pub fn x25519_compute_shared(sk: &X25519PrivateKey, peer_pk: &X25519PublicKey) -> [u8; 32] {
    x25519_scalarmult(&sk.0, &peer_pk.0)
}
