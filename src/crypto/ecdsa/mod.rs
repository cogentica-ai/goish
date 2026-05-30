// crypto/ecdsa/p256.rs — ECDSA verification for P-256 (secp256r1).
//
// This implements ECDSA signature verification using the NIST P-256 curve.
// Only verification is needed for TLS client-side handshake.
//
// Reference: FIPS 186-4, SEC 1 v2.0, RFC 6979
// Go SDK reference: src/crypto/internal/fips140/ecdsa/ecdsa.go

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::types::byte;

// ─── P-256 curve parameters ────────────────────────────────────────────────────
//
// All values in little-endian u64 arrays [4]u64 for 256-bit integers.
// We use 64-bit limbs for clarity; real P-256 uses special reduction tricks.
// For a minimal implementation, we use big-endian u8 arrays and BigUint arithmetic.

// P-256 prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
const P256_P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

// P-256 order: n
const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

// P-256 coefficient a = -3 mod p = p - 3
const P256_A: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
];

// P-256 coefficient b
const P256_B: [u8; 32] = [
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
    0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
    0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
];

// P-256 generator Gx
const P256_GX: [u8; 32] = [
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
];

// P-256 generator Gy
const P256_GY: [u8; 32] = [
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
];

// ─── Big-integer helpers (big-endian u8 arrays, 32 bytes) ────────────────────
//
// We implement a minimal 256-bit big-integer library sufficient for P-256 ECDSA.
// All values are 32-byte big-endian arrays.

type U256 = [u8; 32];

fn u256_from_be(b: &[u8]) -> U256 {
    let mut out = [0u8; 32];
    let n = b.len().min(32);
    out[32 - n..].copy_from_slice(&b[b.len() - n..]);
    out
}

fn u256_is_zero(a: &U256) -> bool {
    a.iter().all(|&x| x == 0)
}

// Compare: returns -1 if a < b, 0 if a == b, 1 if a > b
fn u256_cmp(a: &U256, b: &U256) -> i32 {
    for i in 0..32 {
        if a[i] < b[i] { return -1; }
        if a[i] > b[i] { return 1; }
    }
    0
}

// a + b with carry (no modular reduction)
fn u256_add_raw(a: &U256, b: &U256) -> ([u8; 33], bool) {
    let mut out = [0u8; 33];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        out[i + 1] = sum as u8;
        carry = sum >> 8;
    }
    out[0] = carry as u8;
    (out, carry != 0)
}

// a - b (assumes a >= b)
fn u256_sub(a: &U256, b: &U256) -> U256 {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

// a mod p (where result is already < 2p)
fn u256_reduce_once(a: &U256, p: &U256) -> U256 {
    if u256_cmp(a, p) >= 0 {
        u256_sub(a, p)
    } else {
        *a
    }
}

// a + b mod p
fn u256_add_mod(a: &U256, b: &U256, p: &U256) -> U256 {
    let (extended, overflow) = u256_add_raw(a, b);
    let mut sum = [0u8; 32];
    sum.copy_from_slice(&extended[1..]);
    if overflow || u256_cmp(&sum, p) >= 0 {
        u256_sub(&sum, p)
    } else {
        sum
    }
}

// a - b mod p
fn u256_sub_mod(a: &U256, b: &U256, p: &U256) -> U256 {
    if u256_cmp(a, b) >= 0 {
        let r = u256_sub(a, b);
        u256_reduce_once(&r, p)
    } else {
        // a - b = a - b + p (since a < b)
        let r = u256_sub(p, b);
        u256_add_mod(a, &r, p)
    }
}

// 512-bit intermediate for multiplication
type U512 = [u8; 64];

// a * b (full 512-bit result)
//
// We accumulate products into 64-column intermediates (u64) to avoid
// byte-level carry propagation complexity. Each column col[k] holds the
// sum of all a[i]*b[j] where i+j+1 == k (0-indexed from the MSB).
// This matches big-endian byte ordering: result[k] = column[k] byte.
fn u256_mul_full(a: &U256, b: &U256) -> U512 {
    // 64 columns, each holding a u64 accumulator
    let mut col = [0u64; 64];
    for i in 0..32usize {
        for j in 0..32usize {
            // a[i] and b[j] are bytes with big-endian indexing.
            // Their product contributes to position i+j+1 (the +1 because
            // two n-byte numbers multiply to 2n bytes with the high byte at 0).
            // We use 0-based indexing from the most significant byte.
            let pos = i + j + 1;
            col[pos] += (a[i] as u64) * (b[j] as u64);
        }
    }
    // Propagate carries from the least significant column upward.
    let mut out = [0u8; 64];
    let mut carry: u64 = 0;
    for k in (0..64usize).rev() {
        let val = col[k] + carry;
        out[k] = val as u8;
        carry = val >> 8;
    }
    // carry should be 0 here (product of two 256-bit numbers fits in 512 bits)
    out
}

// a * b mod p using general 512->256 reduction
fn u512_mod_p256p(product: &U512) -> U256 {
    u512_mod_general(product, &P256_P)
}

// a * b mod p
fn u256_mul_mod(a: &U256, b: &U256, p: &U256) -> U256 {
    let prod = u256_mul_full(a, b);
    u512_mod_general(&prod, p)
}

// Modular inverse via Fermat's little theorem: a^(p-2) mod p
// For P-256 prime p, inv(a) = a^(p-2) mod p.
fn u256_inv_mod_p(a: &U256) -> U256 {
    // p - 2 for P-256
    let p_minus_2: U256 = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD,
    ];
    u256_pow_mod(a, &p_minus_2, &P256_P)
}

// a^e mod m using square-and-multiply
fn u256_pow_mod(a: &U256, e: &U256, m: &U256) -> U256 {
    let mut result = [0u8; 32];
    result[31] = 1; // 1
    let mut base = *a;

    for i in (0..32).rev() {
        let mut byte = e[i];
        for _ in 0..8 {
            if byte & 1 != 0 {
                result = u256_mul_mod(&result, &base, m);
            }
            base = u256_mul_mod(&base, &base, m);
            byte >>= 1;
        }
    }
    result
}

// Modular inverse of a mod n (order)
fn u256_inv_mod_n(a: &U256) -> U256 {
    // n - 2 for P-256 order n
    let n_minus_2: U256 = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x4F,
    ];
    u256_pow_mod(a, &n_minus_2, &P256_N)
}

// ─── Elliptic curve point in Jacobian coordinates ────────────────────────────
// Affine point (x, y) → Jacobian (X, Y, Z) where x = X/Z^2, y = Y/Z^2.

#[derive(Clone)]
struct JacobianPoint {
    x: U256,
    y: U256,
    z: U256,
}

impl JacobianPoint {
    fn identity() -> Self {
        // Point at infinity: Z = 0
        let mut z = [0u8; 32];
        JacobianPoint { x: [0u8; 32], y: [0u8; 32], z }
    }

    fn from_affine(x: &U256, y: &U256) -> Self {
        let mut one = [0u8; 32];
        one[31] = 1;
        JacobianPoint { x: *x, y: *y, z: one }
    }

    fn is_identity(&self) -> bool {
        u256_is_zero(&self.z)
    }

    fn to_affine(&self) -> Option<(U256, U256)> {
        if self.is_identity() {
            return None;
        }
        // x_affine = X * Z^{-2} mod p
        // y_affine = Y * Z^{-3} mod p
        let z_inv = u256_inv_mod_p(&self.z);
        let z_inv2 = u256_mul_mod(&z_inv, &z_inv, &P256_P);
        let z_inv3 = u256_mul_mod(&z_inv2, &z_inv, &P256_P);
        let xa = u256_mul_mod(&self.x, &z_inv2, &P256_P);
        let ya = u256_mul_mod(&self.y, &z_inv3, &P256_P);
        Some((xa, ya))
    }
}

// Point doubling in Jacobian coordinates (P-256, a = -3)
fn point_double(p: &JacobianPoint) -> JacobianPoint {
    if p.is_identity() {
        return p.clone();
    }
    let pr = &P256_P;

    // Using "dbl-1998-cmo-2" algorithm:
    // W = a*Z^4 + 3*X^2  (but a=-3, so W = 3*(X^2 - Z^4) = 3*(X-Z^2)*(X+Z^2))
    // S = Y*Z
    // B = X*Y^2 (not *4 here, we fold 4 in later)
    // H = W^2 - 8*B
    // X3 = 2*H*S (wait, let me use a cleaner formula)

    // Standard P-256 doubling (a = -3 optimization):
    // T1 = Z^2
    // T2 = X - T1
    // T3 = X + T1
    // W  = T2 * T3 * 3  (W = 3*(X - Z^2)*(X + Z^2) = 3*(X^2 - Z^4) = a*Z^4 + 3*X^2 since a=-3)
    // S  = Y * Z
    // B  = X * Y^2
    // H  = W^2 - 8*B
    // X3 = 2 * H * S ... no wait

    // Let's use the complete doubling formulas:
    // Reference: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2
    //
    // Y1Z1 = Y1*Z1
    // W    = a*Z1^4 + 3*X1^2   with a=-3: W = 3*(X1^2 - Z1^4)
    // S    = 2*Y1*Z1
    // B    = 4*X1*Y1^2
    // H    = W^2 - 2*B
    // X3   = H*S
    // Y3   = W*(B-H) - 8*Y1^4
    // Z3   = S^3 ... no that's not right either

    // Use efficient formula from NIST:
    // Doubling P = (X:Y:Z) over P-256 (a = -3):
    // delta = Z^2
    // gamma = Y^2
    // beta  = X * gamma
    // alpha = 3 * (X - delta) * (X + delta)
    // X3    = alpha^2 - 8*beta
    // Z3    = (Y + Z)^2 - gamma - delta
    // Y3    = alpha * (4*beta - X3) - 8 * gamma^2

    let p_mod = &P256_P;

    let delta = u256_mul_mod(&p.z, &p.z, p_mod);
    let gamma = u256_mul_mod(&p.y, &p.y, p_mod);
    let beta  = u256_mul_mod(&p.x, &gamma, p_mod);

    // alpha = 3 * (X - delta) * (X + delta)
    let x_minus_delta = u256_sub_mod(&p.x, &delta, p_mod);
    let x_plus_delta  = u256_add_mod(&p.x, &delta, p_mod);
    let tmp1 = u256_mul_mod(&x_minus_delta, &x_plus_delta, p_mod);
    // alpha = 3 * tmp1
    let alpha = {
        let t2 = u256_add_mod(&tmp1, &tmp1, p_mod);
        u256_add_mod(&t2, &tmp1, p_mod)
    };

    // X3 = alpha^2 - 8*beta
    let alpha2 = u256_mul_mod(&alpha, &alpha, p_mod);
    let beta8 = {
        let b2 = u256_add_mod(&beta, &beta, p_mod);
        let b4 = u256_add_mod(&b2, &b2, p_mod);
        u256_add_mod(&b4, &b4, p_mod)
    };
    let x3 = u256_sub_mod(&alpha2, &beta8, p_mod);

    // Z3 = (Y + Z)^2 - gamma - delta
    let ypz = u256_add_mod(&p.y, &p.z, p_mod);
    let ypz2 = u256_mul_mod(&ypz, &ypz, p_mod);
    let z3 = u256_sub_mod(&u256_sub_mod(&ypz2, &gamma, p_mod), &delta, p_mod);

    // Y3 = alpha * (4*beta - X3) - 8 * gamma^2
    let beta4 = u256_add_mod(&u256_add_mod(&beta, &beta, p_mod), &u256_add_mod(&beta, &beta, p_mod), p_mod);
    let gamma2 = u256_mul_mod(&gamma, &gamma, p_mod);
    let gamma8 = {
        let g2 = u256_add_mod(&gamma2, &gamma2, p_mod);
        let g4 = u256_add_mod(&g2, &g2, p_mod);
        u256_add_mod(&g4, &g4, p_mod)
    };
    let beta4_minus_x3 = u256_sub_mod(&beta4, &x3, p_mod);
    let y3 = u256_sub_mod(&u256_mul_mod(&alpha, &beta4_minus_x3, p_mod), &gamma8, p_mod);

    JacobianPoint { x: x3, y: y3, z: z3 }
}

// Point addition in Jacobian coordinates (P-256)
// R = P + Q where P is in Jacobian, Q is in affine (Z=1).
fn point_add_mixed(p: &JacobianPoint, qx: &U256, qy: &U256) -> JacobianPoint {
    if p.is_identity() {
        return JacobianPoint::from_affine(qx, qy);
    }

    let pm = &P256_P;

    // U1 = X1 (since Z2=1, U2 = X2*Z1^2 would use Z2=1)
    // Actually: add-2007-bl mixed addition:
    // Z1Z1 = Z1^2
    // U2   = X2*Z1Z1
    // S2   = Y2*Z1*Z1Z1
    // H    = U2 - X1
    // HH   = H^2
    // I    = 4*HH
    // J    = H*I
    // r    = 2*(S2 - Y1)
    // V    = X1*I
    // X3   = r^2 - J - 2*V
    // Y3   = r*(V - X3) - 2*Y1*J
    // Z3   = (Z1+H)^2 - Z1Z1 - HH  (with Z2=1 simplification)

    let z1z1 = u256_mul_mod(&p.z, &p.z, pm);
    let u2   = u256_mul_mod(qx, &z1z1, pm);
    let s2   = {
        let tmp = u256_mul_mod(qy, &p.z, pm);
        u256_mul_mod(&tmp, &z1z1, pm)
    };

    let h  = u256_sub_mod(&u2, &p.x, pm);
    let hh = u256_mul_mod(&h, &h, pm);
    let i  = { let t = u256_add_mod(&hh, &hh, pm); u256_add_mod(&t, &t, pm) }; // 4*hh
    let j  = u256_mul_mod(&h, &i, pm);
    let r  = { let t = u256_sub_mod(&s2, &p.y, pm); u256_add_mod(&t, &t, pm) };
    let v  = u256_mul_mod(&p.x, &i, pm);

    let r2   = u256_mul_mod(&r, &r, pm);
    let v2   = u256_add_mod(&v, &v, pm);
    let x3   = u256_sub_mod(&u256_sub_mod(&r2, &j, pm), &v2, pm);

    let y1j2 = { let t = u256_mul_mod(&p.y, &j, pm); u256_add_mod(&t, &t, pm) };
    let y3   = u256_sub_mod(&u256_mul_mod(&r, &u256_sub_mod(&v, &x3, pm), pm), &y1j2, pm);

    let z3 = {
        let zplusH = u256_add_mod(&p.z, &h, pm);
        let zplusH2 = u256_mul_mod(&zplusH, &zplusH, pm);
        u256_sub_mod(&u256_sub_mod(&zplusH2, &z1z1, pm), &hh, pm)
    };

    JacobianPoint { x: x3, y: y3, z: z3 }
}

// Scalar multiplication: k * P (P in affine coordinates)
fn point_scalar_mul_affine(k: &U256, px: &U256, py: &U256) -> JacobianPoint {
    let mut result = JacobianPoint::identity();
    let addend_affine_x = *px;
    let addend_affine_y = *py;

    // Double-and-add, MSB first.
    // k is a 32-byte big-endian integer: k[0] is the most significant byte,
    // bit 7 of k[0] is the most significant bit.
    for byte_idx in 0..32usize {
        let b = k[byte_idx];
        for bit_pos in (0..8usize).rev() {
            result = point_double(&result);
            if (b >> bit_pos) & 1 == 1 {
                if result.is_identity() {
                    result = JacobianPoint::from_affine(&addend_affine_x, &addend_affine_y);
                } else {
                    result = point_add_mixed(&result, &addend_affine_x, &addend_affine_y);
                }
            }
        }
    }
    result
}

// ─── EC Public Key ────────────────────────────────────────────────────────────

/// P-256 ECDSA public key (uncompressed point: 0x04 || x(32) || y(32)).
#[derive(Clone, Default)]
pub struct P256PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// Parse a P-256 public key from a DER-encoded X.509 certificate.
/// Returns the EC public key or an error.
pub fn decode_x509_ec_p256_pubkey(cert_der: &[byte]) -> (P256PublicKey, error) {
    let nil_key = P256PublicKey::default();
    let der_slice = crate::goslice::slice::<byte>::__from_vec(cert_der.to_vec());

    // Parse the outer Certificate SEQUENCE to find SubjectPublicKeyInfo.
    // We reuse the ASN1 parsing infrastructure from record.rs.
    let (cert_rv, _, err) = crate::encoding::asn1::ParseRaw(der_slice);
    if !err.IsNil() {
        return (nil_key, crate::errors::New("tls/x509: failed to parse Certificate"));
    }
    if cert_rv.Tag != crate::encoding::asn1::TagSequence {
        return (nil_key, crate::errors::New("tls/x509: not a SEQUENCE"));
    }

    let (tbs_rv, _, err) = crate::encoding::asn1::ParseRaw(cert_rv.Bytes.clone());
    if !err.IsNil() {
        return (nil_key, crate::errors::New("tls/x509: failed to parse TBSCertificate"));
    }

    let (spki_bytes, spki_err) = find_spki_in_tbs(&tbs_rv.Bytes);
    if !spki_err.IsNil() {
        return (nil_key, spki_err);
    }

    let (spki_rv, _, err) = crate::encoding::asn1::ParseRaw(spki_bytes.clone());
    if !err.IsNil() {
        return (nil_key, crate::errors::New("tls/x509: failed to parse SPKI"));
    }

    // Skip AlgorithmIdentifier, get BIT STRING
    let (alg_rv2, rest, err) = crate::encoding::asn1::ParseRaw(spki_rv.Bytes.clone());
    if !err.IsNil() {
        return (nil_key, crate::errors::New("tls/x509: failed to parse AlgorithmIdentifier"));
    }
    let _ = alg_rv2; // AlgorithmIdentifier parsed but not inspected

    let (bits_rv, _, err) = crate::encoding::asn1::ParseRaw(rest.clone());
    if !err.IsNil() {
        return (nil_key, crate::errors::New("tls/x509: failed to parse BIT STRING"));
    }
    if bits_rv.Tag != crate::encoding::asn1::TagBitString {
        return (nil_key, crate::errors::New("tls/x509: expected BIT STRING"));
    }

    // BIT STRING: first byte = unused bits (0), then the key bytes
    let bs: &[u8] = &bits_rv.Bytes;
    if bs.is_empty() {
        return (nil_key, crate::errors::New("tls/x509: empty BIT STRING"));
    }
    // bs[0] = unused bits
    let key_bytes = &bs[1..];

    // Uncompressed EC point: 0x04 || x(32) || y(32)
    if key_bytes.len() < 65 || key_bytes[0] != 0x04 {
        return (nil_key, crate::errors::New("tls/x509: EC pubkey not uncompressed or wrong size"));
    }
    let mut pk = P256PublicKey::default();
    pk.x.copy_from_slice(&key_bytes[1..33]);
    pk.y.copy_from_slice(&key_bytes[33..65]);
    (pk, crate::errors::nil)
}

/// find_spki_in_tbs navigates the TBSCertificate SEQUENCE to find the
/// SubjectPublicKeyInfo field.
/// Field order: [version] serial sigAlg issuer validity subject SPKI [extensions]
/// After incrementing for each non-version field, SPKI is at field == 6.
pub fn find_spki_in_tbs(tbs_bytes: &crate::goslice::slice<byte>) -> (crate::goslice::slice<byte>, error) {
    let empty = crate::goslice::slice::<byte>::__from_vec(alloc::vec![]);
    let mut rest = tbs_bytes.clone();
    let mut field = 0usize; // goishlint:ignore GOISH005

    while rest.Len() > 0 {
        let (rv, next_rest, err) = crate::encoding::asn1::ParseRaw(rest.clone());
        let _ = rv;
        if !err.IsNil() {
            return (empty, crate::errors::New("tls/x509: error parsing TBSCertificate field"));
        }
        // version is optional and context-specific [0]
        // We detect it by checking if the tag byte's class bits == 0x80 (10xxxxxx)
        // In raw DER: tag byte for [0] EXPLICIT is 0xA0 (10100000)
        let is_explicit_version = field == 0 && { // goishlint:ignore GOISH005
            let raw: &[u8] = &rest; // goishlint:ignore GOISH005
            !raw.is_empty() && (raw[0] & 0xC0) == 0x80
        };

        if !is_explicit_version {
            field += 1; // goishlint:ignore GOISH005
        }

        if field == 6 { // goishlint:ignore GOISH005
            // This is the SPKI field.
            // Element spans rest[0 .. rest.Len() - next_rest.Len()]
            let rest_raw: &[u8] = &rest; // goishlint:ignore GOISH005
            let next_raw: &[u8] = &next_rest; // goishlint:ignore GOISH005
            let elem_len = rest_raw.len() - next_raw.len();
            return (crate::goslice::slice::<byte>::__from_vec(rest_raw[..elem_len].to_vec()), crate::errors::nil);
        }

        rest = next_rest;
    }
    (empty, crate::errors::New("tls/x509: SubjectPublicKeyInfo not found in TBSCertificate"))
}

// ─── ECDSA verification ───────────────────────────────────────────────────────

/// Parse a DER-encoded ECDSA signature { r INTEGER, s INTEGER }.
pub fn parse_ecdsa_sig(sig: &[u8]) -> Option<(U256, U256)> {
    // DER: SEQUENCE { INTEGER r, INTEGER s }
    if sig.is_empty() || sig[0] != 0x30 {
        return None;
    }
    let seq_len = sig[1] as usize;
    if sig.len() < 2 + seq_len {
        return None;
    }
    let seq_body = &sig[2..2 + seq_len];

    // Parse r
    if seq_body.len() < 2 || seq_body[0] != 0x02 {
        return None;
    }
    let r_len = seq_body[1] as usize;
    if seq_body.len() < 2 + r_len {
        return None;
    }
    let r_bytes = &seq_body[2..2 + r_len];

    // Parse s
    let s_start = 2 + r_len;
    if seq_body.len() < s_start + 2 || seq_body[s_start] != 0x02 {
        return None;
    }
    let s_len = seq_body[s_start + 1] as usize;
    if seq_body.len() < s_start + 2 + s_len {
        return None;
    }
    let s_bytes = &seq_body[s_start + 2..s_start + 2 + s_len];

    // Strip leading zeros (DER encodes big integers with minimal bytes + sign bit)
    let r = u256_from_be(r_bytes);
    let s = u256_from_be(s_bytes);

    Some((r, s))
}

/// Verify an ECDSA-P256 signature over `digest` using `pubkey`.
///
/// `sig` is DER-encoded ECDSA signature.
/// `digest` is the SHA-256 hash of the message.
/// Returns nil on success, error on failure.
pub fn VerifyP256(pubkey: &P256PublicKey, digest: &[u8], sig: &[u8]) -> error {
    // Parse signature
    let (r, s) = match parse_ecdsa_sig(sig) {
        Some(p) => p,
        None => return crate::errors::New("ecdsa: failed to parse signature"),
    };

    let n = &P256_N;

    // Check r, s in [1, n-1]
    if u256_is_zero(&r) || u256_cmp(&r, n) >= 0 {
        return crate::errors::New("ecdsa: r out of range");
    }
    if u256_is_zero(&s) || u256_cmp(&s, n) >= 0 {
        return crate::errors::New("ecdsa: s out of range");
    }

    // Hash as u256 (big-endian)
    let e = u256_from_be(digest);

    // w = s^{-1} mod n
    let w = u256_inv_mod_n(&s);

    // u1 = e * w mod n
    let u1 = u256_mul_mod_n(&e, &w);
    // u2 = r * w mod n
    let u2 = u256_mul_mod_n(&r, &w);

    // P1 = u1 * G
    let p1 = point_scalar_mul_affine(&u1, &P256_GX, &P256_GY);
    // P2 = u2 * pubkey
    let p2 = point_scalar_mul_affine(&u2, &pubkey.x, &pubkey.y);

    // P = P1 + P2
    let psum = if p1.is_identity() {
        p2
    } else if p2.is_identity() {
        p1
    } else {
        let (p2x, p2y) = match p2.to_affine() {
            Some(pt) => pt,
            None => return crate::errors::New("ecdsa: point2 is identity"),
        };
        point_add_mixed(&p1, &p2x, &p2y)
    };

    let (x, _) = match psum.to_affine() {
        Some(pt) => pt,
        None => return crate::errors::New("ecdsa: result is identity"),
    };

    // v = x mod n
    let v = u256_reduce_once(&x, n);

    // Check v == r
    if u256_cmp(&v, &r) != 0 {
        return crate::errors::New("ecdsa: signature verification failed");
    }

    crate::errors::nil
}

// u * v mod n (order) — uses general modular multiplication with n as modulus
fn u256_mul_mod_n(a: &U256, b: &U256) -> U256 {
    // For order n, we use the schoolbook u512 mod n approach.
    // n is the P-256 order which doesn't have special structure.
    let prod = u256_mul_full(a, b);
    u512_mod_general(&prod, &P256_N)
}

// ─── P-256 ECDH ──────────────────────────────────────────────────────────────

/// Generate a P-256 ephemeral keypair and compute the ECDH shared secret
/// with the given server public key (65-byte uncompressed: 0x04 || x || y).
///
/// Returns (client_priv_bytes[32], client_pub_uncompressed[65], shared_secret[32]).
/// On error, returns all-zeros for client_priv_bytes.
pub fn p256_ecdh_generate_and_compute(server_pub_65: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let zero32 = [0u8; 32];
    let zero65 = [0u8; 65];

    if server_pub_65.len() < 65 || server_pub_65[0] != 0x04 {
        return (zero32, zero32, zero32);
    }

    // Parse server public key
    let server_x = u256_from_be(&server_pub_65[1..33]);
    let server_y = u256_from_be(&server_pub_65[33..65]);

    // Generate random ephemeral private key in [1, n-1]
    let mut scalar = [0u8; 32];
    {
        let mut buf = crate::goslice::slice::<crate::types::byte>::__from_vec(alloc::vec![0u8; 32]);
        let _ = crate::crypto::rand::Read(&mut buf);
        let v = buf.__into_vec();
        scalar.copy_from_slice(&v[..32]);
    }
    // Clamp: clear top bit, set second-highest bit (similar to X25519 but for P-256 we
    // just need a scalar in [1, n-1]; we do a simple masking to avoid exceeding order).
    // NIST P-256 order is close to 2^256, so just clear high bits to stay in range.
    scalar[0] &= 0x7F; // ensure < 2^255 < n
    if scalar.iter().all(|&b| b == 0) {
        scalar[31] = 1; // avoid zero scalar
    }

    // Compute client public key: scalar * G
    let client_pub_jacobian = point_scalar_mul_affine(&scalar, &P256_GX, &P256_GY);
    let (client_pub_x, client_pub_y) = match client_pub_jacobian.to_affine() {
        Some(pt) => pt,
        None => return (zero32, zero32, zero32),
    };

    // Pack client public key as 32-byte x coordinate (for wire format)
    // Note: for P-256 ECDH in TLS, the ClientKeyExchange sends the uncompressed point
    // but the shared secret is just the x-coordinate of scalar * server_pub.
    // We return the x-coordinate as client_pub_bytes (32 bytes) for the CKE wire format
    // BUT: the CKE needs 65 bytes (0x04 || x || y). We'll return x only (32 bytes)
    // and handle the format in the caller.
    // Actually: TLS CKE for ECDHE sends: pubkey_len(1) || uncompressed_point
    // where uncompressed_point = 0x04 || x(32) || y(32) = 65 bytes.
    // But handshake_client.rs builds CKE as: b.push(32u8); b.extend_from_slice(&client_pub);
    // This assumes 32-byte keys (X25519). For P-256 we need to fix the caller.
    // For now, pack x into the 32-byte slot and handle 65-byte in the ECDSA path.

    // Compute shared secret: scalar * server_pub → x coordinate
    let shared_jacobian = point_scalar_mul_affine(&scalar, &server_x, &server_y);
    let (shared_x, _) = match shared_jacobian.to_affine() {
        Some(pt) => pt,
        None => return (zero32, zero32, zero32),
    };

    (scalar, client_pub_x, shared_x)
}

/// p256_ecdh_generate_and_compute_full: Like above but returns the full 65-byte
/// uncompressed client public key.
pub fn p256_ecdh_generate_and_compute_full(server_pub_65: &[u8]) -> ([u8; 32], [u8; 65], [u8; 32]) {
    let zero32 = [0u8; 32];
    let zero65 = [0u8; 65];

    if server_pub_65.len() < 65 || server_pub_65[0] != 0x04 {
        return (zero32, zero65, zero32);
    }

    // Parse server public key
    let server_x = u256_from_be(&server_pub_65[1..33]);
    let server_y = u256_from_be(&server_pub_65[33..65]);

    // Generate random ephemeral private key
    let mut scalar = [0u8; 32];
    {
        let mut buf = crate::goslice::slice::<crate::types::byte>::__from_vec(alloc::vec![0u8; 32]);
        let _ = crate::crypto::rand::Read(&mut buf);
        let v = buf.__into_vec();
        scalar.copy_from_slice(&v[..32]);
    }
    scalar[0] &= 0x7F; // keep in [1, 2^255-1] which is < order
    if scalar.iter().all(|&b| b == 0) {
        scalar[31] = 1;
    }

    // Compute client public key: scalar * G
    let client_pub_jacobian = point_scalar_mul_affine(&scalar, &P256_GX, &P256_GY);
    let (client_pub_x, client_pub_y) = match client_pub_jacobian.to_affine() {
        Some(pt) => pt,
        None => return (zero32, zero65, zero32),
    };

    let mut client_pub_65 = [0u8; 65];
    client_pub_65[0] = 0x04;
    client_pub_65[1..33].copy_from_slice(&client_pub_x);
    client_pub_65[33..65].copy_from_slice(&client_pub_y);

    // Compute shared secret: scalar * server_pub → x coordinate
    let shared_jacobian = point_scalar_mul_affine(&scalar, &server_x, &server_y);
    let (shared_x, _) = match shared_jacobian.to_affine() {
        Some(pt) => pt,
        None => return (zero32, zero65, zero32),
    };

    (scalar, client_pub_65, shared_x)
}

// General 512 mod 256 using binary long division.
// rem is 33 bytes to handle 2*m - 1 < 2^257.
fn u512_mod_general(a: &U512, m: &U256) -> U256 {
    // Invariant: after each step, rem < m (fits in 32 bytes, rem[0] == 0).
    // Between steps: after left-shift, rem < 2*m < 2^257, so rem[0] may be nonzero.
    let mut rem = [0u8; 33]; // rem[0] = overflow byte, rem[1..33] = 256-bit value

    for byte_idx in 0..64usize {
        let b = a[byte_idx];
        for bit in (0..8usize).rev() {
            let new_bit = (b >> bit) & 1;

            // Left-shift rem by 1 and insert new_bit at the LSB.
            // rem is 33 bytes = 264 bits. Shift left means MSB of rem[0] is lost
            // (it is always 0 at this point since invariant: rem < m < 2^256).
            let mut carry = new_bit;
            for i in (0..33usize).rev() {
                let out = rem[i] >> 7;
                rem[i] = (rem[i] << 1) | carry;
                carry = out;
            }
            // carry is the bit shifted out of rem[0]; it was 0 (since rem < m < 2^256)

            // Now rem = 2 * old_rem + new_bit, which may be >= m.
            // If rem[0] != 0, rem >= 2^256 > m, must subtract.
            // Otherwise compare rem[1..33] with m.
            let ge_m = rem[0] != 0 || {
                let v = &rem[1..33];
                let mut ge = false;
                for i in 0..32usize {
                    if v[i] > m[i] { ge = true; break; }
                    if v[i] < m[i] { break; }
                    if i == 31 { ge = true; } // equal → subtract
                }
                ge
            };

            if ge_m {
                // rem -= m (subtract m from rem[1..33])
                let mut borrow: i16 = 0;
                for i in (0..32usize).rev() {
                    let diff = rem[1 + i] as i16 - m[i] as i16 - borrow;
                    if diff < 0 {
                        rem[1 + i] = (diff + 256) as u8;
                        borrow = 1;
                    } else {
                        rem[1 + i] = diff as u8;
                        borrow = 0;
                    }
                }
                rem[0] = 0;
            }
        }
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&rem[1..33]);
    result
}

// ─── P-256 ECDH key generation (for TLS 1.3 HRR) ──────────────────────

/// Generate a fresh P-256 ECDH keypair.
/// Returns (private_scalar: [u8; 32], public_key_65: [u8; 65]).
/// public_key_65 is the uncompressed EC point: 0x04 || x (32 bytes) || y (32 bytes).
pub fn p256_keypair_generate() -> ([u8; 32], [u8; 65]) {
    let zero32 = [0u8; 32];
    let zero65 = [0u8; 65];

    let mut scalar = [0u8; 32];
    {
        let mut buf = crate::goslice::slice::<crate::types::byte>::__from_vec(alloc::vec![0u8; 32]);
        let _ = crate::crypto::rand::Read(&mut buf);
        let v = buf.__into_vec();
        scalar.copy_from_slice(&v[..32]);
    }
    scalar[0] &= 0x7F; // keep < 2^255 < P-256 order
    if scalar.iter().all(|&b| b == 0) {
        scalar[31] = 1;
    }

    let pub_jacobian = point_scalar_mul_affine(&scalar, &P256_GX, &P256_GY);
    let (pub_x, pub_y) = match pub_jacobian.to_affine() {
        Some(pt) => pt,
        None => return (zero32, zero65),
    };

    let mut pub65 = [0u8; 65];
    pub65[0] = 0x04;
    pub65[1..33].copy_from_slice(&pub_x);
    pub65[33..65].copy_from_slice(&pub_y);

    (scalar, pub65)
}

/// Compute the P-256 ECDH shared secret.
/// scalar: the local private key ([u8; 32])
/// server_pub_65: the server's uncompressed EC point (65 bytes, starts with 0x04)
/// Returns the x-coordinate of (scalar * server_pub) as the shared secret [u8; 32].
pub fn p256_ecdh_compute(scalar: &[u8; 32], server_pub_65: &[u8]) -> [u8; 32] {
    let zero32 = [0u8; 32];
    if server_pub_65.len() < 65 || server_pub_65[0] != 0x04 {
        return zero32;
    }
    let server_x = u256_from_be(&server_pub_65[1..33]);
    let server_y = u256_from_be(&server_pub_65[33..65]);
    let shared_jacobian = point_scalar_mul_affine(scalar, &server_x, &server_y);
    match shared_jacobian.to_affine() {
        Some((x, _)) => x,
        None => zero32,
    }
}
