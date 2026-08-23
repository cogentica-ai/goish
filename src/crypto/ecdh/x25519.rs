// go: file crypto/ecdh/x25519.go decls: X25519, x25519Curve.String, x25519Curve.GenerateKey, x25519Curve.NewPrivateKey, x25519Curve.NewPublicKey, x25519Curve.ecdh, x25519ScalarMult, isZero
//
// Deviations from x25519[go] @ Go 1.25.5:
//
//   * `var x25519 = &x25519Curve{}` is a `static` here, so `X25519()`
//     returns `&'static (dyn Curve + Send + Sync)` — which preserves Go's
//     documented "multiple invocations return the same value, so it can be
//     used for equality checks".
//   * `field.Element` methods take `&Element` and the receiver may alias
//     an operand (`z2.Multiply(&z2, &tmp1)`). `Element` is `Copy`, so
//     those call sites take a copy first; the arithmetic is unchanged.
//
// This file replaces a goish-only X25519 that predated the port: a
// hand-written 10-limb radix-2^25.5 field with its own ladder. The
// arithmetic now comes from crypto/internal/fips140/edwards25519/field,
// which is 34/34 and cross-checked against Go, so the invented copy is
// gone. The three `x25519_*` helpers at the bottom are goish-only and kept
// because crypto/tls's TLS 1.3 handshake calls them; they now forward to
// the ported code.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::internal::fips140::edwards25519::field;
use crate::crypto::internal::fips140only;
use crate::crypto::internal::randutil;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::string;
use crate::types::byte;
use crate::{int, uint32};

use super::ecdh::{Curve, PrivateKey, PublicKey};

// Go: x25519.go:16-20 — `var ( x25519PublicKeySize = 32; … )`
const x25519PublicKeySize: usize = 32;
const x25519PrivateKeySize: usize = 32;
const x25519SharedSecretSize: usize = 32;

// Go: x25519.go:29-31 — `var x25519 = &x25519Curve{}` / `type x25519Curve struct{}`
pub struct x25519Curve {}

static x25519: x25519Curve = x25519Curve {};

// go: sdk 1.25.5 crypto/ecdh/x25519.go:22-27 X25519
/// Return a [Curve] which implements the X25519 function over Curve25519
/// (RFC 7748, Section 5).
///
/// Multiple invocations of this function will return the same value, so it
/// can be used for equality checks and switch statements.
pub fn X25519() -> &'static (dyn Curve + Send + Sync) {
    return &x25519;
}

impl Curve for x25519Curve {
    // go: sdk 1.25.5 crypto/ecdh/x25519.go:33-35 x25519Curve.String
    fn String(&self) -> string {
        return string::from_static("X25519");
    }

    // go: sdk 1.25.5 crypto/ecdh/x25519.go:37-47 x25519Curve.GenerateKey
    fn GenerateKey(
        &self,
        rand: &mut (dyn io::Reader + Send + Sync + 'static),
    ) -> (PrivateKey, error) {
        if fips140only::Enabled {
            return (
                zeroPrivateKey(),
                errors::New("crypto/ecdh: use of X25519 is not allowed in FIPS 140-only mode"),
            );
        }
        let mut key = slice::__from_vec(alloc::vec![0u8; x25519PrivateKeySize]);
        randutil::MaybeReadByte(rand);
        let (_, err) = io::ReadFull(rand, &mut key);
        if err != crate::nil {
            return (zeroPrivateKey(), err);
        }
        return self.NewPrivateKey(&key);
    }

    // go: sdk 1.25.5 crypto/ecdh/x25519.go:49-67 x25519Curve.NewPrivateKey
    fn NewPrivateKey(&self, key: &slice<byte>) -> (PrivateKey, error) {
        if fips140only::Enabled {
            return (
                zeroPrivateKey(),
                errors::New("crypto/ecdh: use of X25519 is not allowed in FIPS 140-only mode"),
            );
        }
        let raw: &[byte] = key;
        if raw.len() != x25519PrivateKeySize {
            return (
                zeroPrivateKey(),
                errors::New("crypto/ecdh: invalid private key size"),
            );
        }
        let mut publicKey = slice::__from_vec(alloc::vec![0u8; x25519PublicKeySize]);
        let mut x25519Basepoint = [0u8; 32];
        x25519Basepoint[0] = 9;
        x25519ScalarMult(
            &mut publicKey,
            key,
            &slice::__from_vec(x25519Basepoint.to_vec()),
        );
        // We don't check for the all-zero public key here because the
        // scalar is never zero because of clamping, and the basepoint is
        // not the identity in the prime-order subgroup(s).
        return (
            PrivateKey {
                curve: X25519(),
                privateKey: slice::__from_vec(raw.to_vec()),
                publicKey: PublicKey {
                    curve: X25519(),
                    publicKey,
                },
            },
            crate::nil.into(),
        );
    }

    // go: sdk 1.25.5 crypto/ecdh/x25519.go:69-80 x25519Curve.NewPublicKey
    fn NewPublicKey(&self, key: &slice<byte>) -> (PublicKey, error) {
        if fips140only::Enabled {
            return (
                zeroPublicKey(),
                errors::New("crypto/ecdh: use of X25519 is not allowed in FIPS 140-only mode"),
            );
        }
        let raw: &[byte] = key;
        if raw.len() != x25519PublicKeySize {
            return (
                zeroPublicKey(),
                errors::New("crypto/ecdh: invalid public key"),
            );
        }
        return (
            PublicKey {
                curve: X25519(),
                publicKey: slice::__from_vec(raw.to_vec()),
            },
            crate::nil.into(),
        );
    }

    // go: sdk 1.25.5 crypto/ecdh/x25519.go:82-89 x25519Curve.ecdh
    fn ecdh(&self, local: &PrivateKey, remote: &PublicKey) -> (slice<byte>, error) {
        let mut out = slice::__from_vec(alloc::vec![0u8; x25519SharedSecretSize]);
        x25519ScalarMult(&mut out, &local.privateKey, &remote.publicKey);
        if isZero(&out) {
            return (
                slice::__from_vec(Vec::<byte>::new()),
                errors::New("crypto/ecdh: bad X25519 remote ECDH input: low order point"),
            );
        }
        return (out, crate::nil.into());
    }

    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see __goish_as_dyn_any above.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 crypto/ecdh/x25519.go:91-141 x25519ScalarMult
pub(super) fn x25519ScalarMult(dst: &mut slice<byte>, scalar: &slice<byte>, point: &slice<byte>) {
    let mut e = [0u8; 32];

    {
        let s: &[byte] = scalar;
        e.copy_from_slice(&s[..32]);
        e[0] &= 248;
        e[31] &= 127;
        e[31] |= 64;
    }

    let mut x1 = field::Element::default();
    let mut x2 = field::Element::default();
    let mut z2 = field::Element::default();
    let mut x3 = field::Element::default();
    let mut z3 = field::Element::default();
    let mut tmp0 = field::Element::default();
    let mut tmp1 = field::Element::default();
    let _ = x1.SetBytes(point.clone());
    x2.One();
    let x1c = x1;
    x3.Set(&x1c);
    z3.One();

    let mut swap: int = 0;
    let mut pos: i32 = 254;
    while pos >= 0 {
        let mut b = e[(pos / 8) as usize] >> uint32(pos & 7);
        b &= 1;
        swap ^= int(b);
        x2.Swap(&mut x3, swap);
        z2.Swap(&mut z3, swap);
        swap = int(b);

        let (a, c) = (x3, z3);
        tmp0.Subtract(&a, &c);
        let (a, c) = (x2, z2);
        tmp1.Subtract(&a, &c);
        let (a, c) = (x2, z2);
        x2.Add(&a, &c);
        let (a, c) = (x3, z3);
        z2.Add(&a, &c);
        let (a, c) = (tmp0, x2);
        z3.Multiply(&a, &c);
        let (a, c) = (z2, tmp1);
        z2.Multiply(&a, &c);
        let a = tmp1;
        tmp0.Square(&a);
        let a = x2;
        tmp1.Square(&a);
        let (a, c) = (z3, z2);
        x3.Add(&a, &c);
        let (a, c) = (z3, z2);
        z2.Subtract(&a, &c);
        let (a, c) = (tmp1, tmp0);
        x2.Multiply(&a, &c);
        let (a, c) = (tmp1, tmp0);
        tmp1.Subtract(&a, &c);
        let a = z2;
        z2.Square(&a);

        let a = tmp1;
        z3.Mult32(&a, 121666);
        let a = x3;
        x3.Square(&a);
        let (a, c) = (tmp0, z3);
        tmp0.Add(&a, &c);
        let (a, c) = (x1, z2);
        z3.Multiply(&a, &c);
        let (a, c) = (tmp1, tmp0);
        z2.Multiply(&a, &c);

        pos -= 1;
    }

    x2.Swap(&mut x3, swap);
    z2.Swap(&mut z3, swap);

    let a = z2;
    z2.Invert(&a);
    let (a, c) = (x2, z2);
    x2.Multiply(&a, &c);
    let out = x2.Bytes();
    let src: &[byte] = &out;
    let d: &mut [byte] = dst;
    d.copy_from_slice(&src[..32]);
}

// go: sdk 1.25.5 crypto/ecdh/x25519.go:143-150 isZero
/// Report whether x is all zeroes in constant time.
fn isZero(x: &slice<byte>) -> bool {
    let mut acc: byte = 0;
    for (_, b) in crate::range!(x) {
        acc |= *b;
    }
    return acc == 0;
}

// go: none — Go returns a nil *PrivateKey on the error paths.
fn zeroPrivateKey() -> PrivateKey {
    return PrivateKey {
        curve: X25519(),
        privateKey: slice::__from_vec(Vec::<byte>::new()),
        publicKey: zeroPublicKey(),
    };
}

// go: none — the same, for *PublicKey.
fn zeroPublicKey() -> PublicKey {
    return PublicKey {
        curve: X25519(),
        publicKey: slice::__from_vec(Vec::<byte>::new()),
    };
}

// ─── goish-only compatibility shims ──────────────────────────────────
//
// crypto/tls's TLS 1.3 handshake was written against a goish-only X25519
// API that predated this port. These forward to the ported code so the
// handshake keeps working; they have no Go counterpart and should go away
// once crypto/tls is ported to the real `Curve` interface.

// go: none — goish-only: the fixed-size key wrapper crypto/tls uses.
#[derive(Clone)]
pub struct X25519PrivateKey(pub [u8; 32]);

// go: none — goish-only: see X25519PrivateKey.
#[derive(Clone)]
pub struct X25519PublicKey(pub [u8; 32]);

// go: none — goish-only: `x25519ScalarMult` with array-shaped operands.
pub fn x25519_scalarmult(scalar: &[u8; 32], u_in: &[u8; 32]) -> [u8; 32] {
    let mut dst = slice::__from_vec(alloc::vec![0u8; 32]);
    x25519ScalarMult(
        &mut dst,
        &slice::__from_vec(scalar.to_vec()),
        &slice::__from_vec(u_in.to_vec()),
    );
    let r: &[byte] = &dst;
    let mut out = [0u8; 32];
    out.copy_from_slice(r);
    return out;
}

// go: none — goish-only: generate a keypair from crypto/rand.
pub fn x25519_generate() -> (X25519PrivateKey, X25519PublicKey) {
    let mut sk = [0u8; 32];
    {
        let mut buf = slice::__from_vec(alloc::vec![0u8; 32]);
        let _ = crate::crypto::rand::Read(&mut buf);
        let r: &[byte] = &buf;
        sk.copy_from_slice(r);
    }
    // Clamp per RFC 7748 §5. x25519ScalarMult clamps its own copy too;
    // this one is stored, and callers expect the clamped scalar back.
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    let mut base = [0u8; 32];
    base[0] = 9;
    let pk = x25519_scalarmult(&sk, &base);
    return (X25519PrivateKey(sk), X25519PublicKey(pk));
}

// go: none — goish-only: the shared secret, array-shaped.
pub fn x25519_compute_shared(sk: &X25519PrivateKey, peer_pk: &X25519PublicKey) -> [u8; 32] {
    return x25519_scalarmult(&sk.0, &peer_pk.0);
}
