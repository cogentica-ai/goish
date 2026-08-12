// go: file crypto/internal/fips140/nistec/p256.go decls: NewP256Point, P256Point.SetGenerator, P256Point.Set, P256Point.SetBytes, p256B, p256Polynomial, p256CheckOnCurve, P256Point.Bytes, P256Point.bytes, P256Point.BytesX, P256Point.bytesX, P256Point.BytesCompressed, P256Point.bytesCompressed, P256Point.Add, P256Point.Double, p256AffinePoint.Projective, P256Point.AddAffine, P256Point.Select, p256OrdElement.SetBytes, p256OrdElement.Bytes, p256OrdElement.Rsh, p256Table.Select, p256Table.Compute, boothW5, P256Point.ScalarMult, P256Point.Negate, p256AffineTable.Select, boothW6, P256Point.ScalarBaseMult, p256AffinePoint.Negate, p256Sqrt, p256Square
//
// This is Go's p256.go, the purego/no-assembly P-256 — the file behind
// `//go:build (!amd64 && !arm64 && !ppc64le && !s390x) || purego`. goish
// implements the portable side of every such pair (see p256_asm.go, not
// ported). Unlike p224/p384/p521 it is not generated from the nistec
// template: it carries its own Booth-encoded scalar multiplication, an
// affine mixed-addition path, and a precomputed generator table.
//
// Deviations from p256[go] @ Go 1.25.5:
//
//   * `fiat.P256Element` is a `[u64; 4]` limb array and therefore `Copy`,
//     so field elements and points are taken **by value** where Go takes
//     pointers. Same deviation as `fiat/p256.rs` and the other curves.
//   * Go's methods that return `(*P256Point, error)` return just `error`
//     here and mutate the receiver only on success.
//   * `var p256GeneratorTables *[43]p256AffineTable` is filled by an
//     `init()` that reinterprets `p256PrecomputedEmbed` through
//     `unsafe.Pointer` on little-endian hosts and rebuilds it limb by limb
//     with `byteorder.LEUint64` on big-endian ones. goish takes Go's
//     *second* path unconditionally: it yields the same limbs on any host
//     and needs no pointer cast. The table is a `Lazy<Vec<…>>`, matching
//     the heap array Go points at.
//   * Go's `x << 64` yields 0; Rust's `<<` panics at that width. `shl64`
//     below restores Go's semantics for `Rsh`, the one place it matters.
//
// goishlint:ignore GOISH018 — `init` exists only to fill in
// p256GeneratorTables, which the `Lazy` initialiser below does; there is
// nothing else in its body.
// goishlint:ignore GOISH021 — `p256Precomputed` and `_p256BOnce` are, in
// order, an alias Go names inside a doc comment and the `sync.Once` guard
// for `_p256B`; `goish::lazy::Lazy` carries its own one-shot latch.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;

use super::fiat::P256Element;
use super::p256_table::p256PrecomputedEmbed;
use crate::crypto::internal::fips140::subtle;
use crate::crypto::internal::fips140deps::byteorder;
use crate::errors;
use crate::goslice::slice;
use crate::lazy::Lazy;
use crate::math::bits;
use crate::{byte, error, int, uint64};

// Go: p256.go:20-29
//   type P256Point struct { x, y, z fiat.P256Element }
/// A P-256 point. The zero value is NOT valid.
#[derive(Clone, Copy)]
pub struct P256Point {
    /// The point is represented in projective coordinates (X:Y:Z), where
    /// x = X/Z and y = Y/Z. Infinity is (0:1:0).
    ///
    /// fiat.P256Element is a base field element in [0, P-1] in the
    /// Montgomery domain (with R 2²⁵⁶ and P 2²⁵⁶ - 2²²⁴ + 2¹⁹² + 2⁹⁶ - 1)
    /// as four limbs in little-endian order value.
    x: P256Element,
    y: P256Element,
    z: P256Element,
}

/// Go: `const p256ElementLength = 32`
pub const p256ElementLength: usize = 32;
/// Go: `const p256UncompressedLength = 1 + 2*p256ElementLength`
pub const p256UncompressedLength: usize = 1 + 2 * p256ElementLength;
/// Go: `const p256CompressedLength = 1 + p256ElementLength`
pub const p256CompressedLength: usize = 1 + p256ElementLength;

// go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:31-36 NewP256Point
/// Return a new P256Point representing the point at infinity point.
pub fn NewP256Point() -> P256Point {
    let mut p = P256Point {
        x: P256Element::New(),
        y: P256Element::New(),
        z: P256Element::New(),
    };
    p.y.One();
    return p;
}

impl P256Point {
    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:38-44 P256Point.SetGenerator
    /// Set p to the canonical generator and return p.
    pub fn SetGenerator(&mut self) -> &mut Self {
        let _ = self.x.SetBytes(slice::__from_vec(alloc::vec![
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x3, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96
        ]));
        let _ = self.y.SetBytes(slice::__from_vec(alloc::vec![
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0xf,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5
        ]));
        self.z.One();
        return self;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:46-52 P256Point.Set
    /// Set p = q and return p.
    pub fn Set(&mut self, q: P256Point) -> &mut Self {
        self.x.Set(q.x);
        self.y.Set(q.y);
        self.z.Set(q.z);
        return self;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:58-114 P256Point.SetBytes
    /// Set p to the compressed, uncompressed, or infinity value encoded in
    /// b, as specified in SEC 1, Version 2.0, Section 2.3.4. If the point
    /// is not on the curve, it returns an error and the receiver is
    /// unchanged.
    pub fn SetBytes(&mut self, b: &slice<byte>) -> error {
        let raw: &[byte] = b;
        // Go: case len(b) == 1 && b[0] == 0: — point at infinity.
        if raw.len() == 1 && raw[0] == 0 {
            self.Set(NewP256Point());
            return crate::nil.into();
        }

        // Go: case len(b) == p256UncompressedLength && b[0] == 4:
        if raw.len() == p256UncompressedLength && raw[0] == 4 {
            let mut x = P256Element::New();
            let err = x.SetBytes(slice::__from_vec(raw[1..1 + p256ElementLength].to_vec()));
            if err != crate::nil {
                return err;
            }
            let mut y = P256Element::New();
            let err = y.SetBytes(slice::__from_vec(raw[1 + p256ElementLength..].to_vec()));
            if err != crate::nil {
                return err;
            }
            let err = p256CheckOnCurve(x, y);
            if err != crate::nil {
                return err;
            }
            self.x.Set(x);
            self.y.Set(y);
            self.z.One();
            return crate::nil.into();
        }

        // Go: case len(b) == p256CompressedLength && (b[0] == 2 || b[0] == 3):
        if raw.len() == p256CompressedLength && (raw[0] == 2 || raw[0] == 3) {
            let mut x = P256Element::New();
            let err = x.SetBytes(slice::__from_vec(raw[1..].to_vec()));
            if err != crate::nil {
                return err;
            }

            // y² = x³ - 3x + b
            let mut y = P256Element::New();
            p256Polynomial(&mut y, x);
            let y2 = y;
            if !p256Sqrt(&mut y, y2) {
                return errors::New("invalid P256 compressed point encoding");
            }

            // Select the positive or negative root, as indicated by the
            // least significant bit, based on the encoding type byte.
            let mut otherRoot = P256Element::New();
            otherRoot.Sub(otherRoot, y);
            let yb = y.Bytes();
            let ybr: &[byte] = &yb;
            let cond = ybr[p256ElementLength - 1] & 1 ^ raw[0] & 1;
            y.Select(otherRoot, y, int(cond));

            self.x.Set(x);
            self.y.Set(y);
            self.z.One();
            return crate::nil.into();
        }

        // Go: default:
        return errors::New("invalid P256 point encoding");
    }
}

// Go: p256.go:116-117 — `var _p256B *fiat.P256Element; var _p256BOnce sync.Once`
static _p256B: Lazy<P256Element> = Lazy::new(|| {
    let mut e = P256Element::New();
    let _ = e.SetBytes(slice::__from_vec(alloc::vec![
        0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86,
        0xbc, 0x65, 0x1d, 0x6, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2,
        0x60, 0x4b
    ]));
    return e;
});

// go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:119-124 p256B
fn p256B() -> P256Element {
    return *_p256B;
}

// go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:126-136 p256Polynomial
/// Set y2 to x³ - 3x + b, and return y2.
fn p256Polynomial(y2: &mut P256Element, x: P256Element) -> P256Element {
    y2.Square(x);
    y2.Mul(*y2, x);

    let mut threeX = P256Element::New();
    threeX.Add(x, x);
    threeX.Add(threeX, x);
    y2.Sub(*y2, threeX);

    y2.Add(*y2, p256B());
    return *y2;
}

// go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:138-146 p256CheckOnCurve
fn p256CheckOnCurve(x: P256Element, y: P256Element) -> error {
    // y² = x³ - 3x + b
    let mut rhs = P256Element::New();
    p256Polynomial(&mut rhs, x);
    let mut lhs = P256Element::New();
    lhs.Square(y);
    if rhs.Equal(lhs) != 1 {
        return errors::New("P256 point not on curve");
    }
    return crate::nil.into();
}

impl P256Point {
    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:148-156 P256Point.Bytes
    /// Return the uncompressed or infinity encoding of p, as specified in
    /// SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the
    /// point at infinity is shorter than all other encodings.
    pub fn Bytes(&self) -> slice<byte> {
        // This function is outlined to make the allocations inline in the
        // caller rather than happen on the heap.
        let mut out = [0u8; p256UncompressedLength];
        return self.bytes(&mut out);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:158-172 P256Point.bytes
    fn bytes(&self, out: &mut [byte; p256UncompressedLength]) -> slice<byte> {
        // The SEC 1 representation of the point at infinity is a single
        // zero byte, and only infinity has z = 0.
        if self.z.IsZero() == 1 {
            return slice::__from_vec(alloc::vec![0u8]);
        }

        let mut zinv = P256Element::New();
        zinv.Invert(&self.z);
        let mut x = P256Element::New();
        x.Mul(self.x, zinv);
        let mut y = P256Element::New();
        y.Mul(self.y, zinv);

        out[0] = 4;
        let xb = x.Bytes();
        let yb = y.Bytes();
        let xr: &[byte] = &xb;
        let yr: &[byte] = &yb;
        out[1..1 + p256ElementLength].copy_from_slice(xr);
        out[1 + p256ElementLength..].copy_from_slice(yr);
        return slice::__from_vec(out.to_vec());
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:174-181 P256Point.BytesX
    /// Return the encoding of the x-coordinate of p, as specified in SEC 1,
    /// Version 2.0, Section 2.3.5, or an error if p is the point at
    /// infinity.
    pub fn BytesX(&self) -> (slice<byte>, error) {
        // This function is outlined to make the allocations inline in the
        // caller rather than happen on the heap.
        let mut out = [0u8; p256ElementLength];
        return self.bytesX(&mut out);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:183-192 P256Point.bytesX
    fn bytesX(&self, out: &mut [byte; p256ElementLength]) -> (slice<byte>, error) {
        if self.z.IsZero() == 1 {
            return (
                slice::__from_vec(Vec::<byte>::new()),
                errors::New("P256 point is the point at infinity"),
            );
        }

        let mut zinv = P256Element::New();
        zinv.Invert(&self.z);
        let mut x = P256Element::New();
        x.Mul(self.x, zinv);

        let xb = x.Bytes();
        let xr: &[byte] = &xb;
        out.copy_from_slice(xr);
        return (slice::__from_vec(out.to_vec()), crate::nil.into());
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:194-202 P256Point.BytesCompressed
    /// Return the compressed or infinity encoding of p, as specified in
    /// SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the
    /// point at infinity is shorter than all other encodings.
    pub fn BytesCompressed(&self) -> slice<byte> {
        // This function is outlined to make the allocations inline in the
        // caller rather than happen on the heap.
        let mut out = [0u8; p256CompressedLength];
        return self.bytesCompressed(&mut out);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:204-219 P256Point.bytesCompressed
    fn bytesCompressed(&self, out: &mut [byte; p256CompressedLength]) -> slice<byte> {
        if self.z.IsZero() == 1 {
            return slice::__from_vec(alloc::vec![0u8]);
        }

        let mut zinv = P256Element::New();
        zinv.Invert(&self.z);
        let mut x = P256Element::New();
        x.Mul(self.x, zinv);
        let mut y = P256Element::New();
        y.Mul(self.y, zinv);

        // Encode the sign of the y coordinate (indicated by the least
        // significant bit) as the encoding type (2 or 3).
        let yb = y.Bytes();
        let ybr: &[byte] = &yb;
        out[0] = 2;
        out[0] |= ybr[p256ElementLength - 1] & 1;
        let xb = x.Bytes();
        let xr: &[byte] = &xb;
        out[1..].copy_from_slice(xr);
        return slice::__from_vec(out.to_vec());
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:221-274 P256Point.Add
    /// Set q = p1 + p2, and return q. The points may overlap.
    pub fn Add(&mut self, p1: P256Point, p2: P256Point) -> &mut Self {
        // Complete addition formula for a = -3 from "Complete addition
        // formulas for prime order elliptic curves"
        // (https://eprint.iacr.org/2015/1060), §A.2.

        let mut t0 = P256Element::New();
        t0.Mul(p1.x, p2.x); // t0 := X1 * X2
        let mut t1 = P256Element::New();
        t1.Mul(p1.y, p2.y); // t1 := Y1 * Y2
        let mut t2 = P256Element::New();
        t2.Mul(p1.z, p2.z); // t2 := Z1 * Z2
        let mut t3 = P256Element::New();
        t3.Add(p1.x, p1.y); // t3 := X1 + Y1
        let mut t4 = P256Element::New();
        t4.Add(p2.x, p2.y); // t4 := X2 + Y2
        t3.Mul(t3, t4); // t3 := t3 * t4
        t4.Add(t0, t1); // t4 := t0 + t1
        t3.Sub(t3, t4); // t3 := t3 - t4
        t4.Add(p1.y, p1.z); // t4 := Y1 + Z1
        let mut x3 = P256Element::New();
        x3.Add(p2.y, p2.z); // X3 := Y2 + Z2
        t4.Mul(t4, x3); // t4 := t4 * X3
        x3.Add(t1, t2); // X3 := t1 + t2
        t4.Sub(t4, x3); // t4 := t4 - X3
        x3.Add(p1.x, p1.z); // X3 := X1 + Z1
        let mut y3 = P256Element::New();
        y3.Add(p2.x, p2.z); // Y3 := X2 + Z2
        x3.Mul(x3, y3); // X3 := X3 * Y3
        y3.Add(t0, t2); // Y3 := t0 + t2
        y3.Sub(x3, y3); // Y3 := X3 - Y3
        let mut z3 = P256Element::New();
        z3.Mul(p256B(), t2); // Z3 := b * t2
        x3.Sub(y3, z3); // X3 := Y3 - Z3
        z3.Add(x3, x3); // Z3 := X3 + X3
        x3.Add(x3, z3); // X3 := X3 + Z3
        z3.Sub(t1, x3); // Z3 := t1 - X3
        x3.Add(t1, x3); // X3 := t1 + X3
        y3.Mul(p256B(), y3); // Y3 := b * Y3
        t1.Add(t2, t2); // t1 := t2 + t2
        t2.Add(t1, t2); // t2 := t1 + t2
        y3.Sub(y3, t2); // Y3 := Y3 - t2
        y3.Sub(y3, t0); // Y3 := Y3 - t0
        t1.Add(y3, y3); // t1 := Y3 + Y3
        y3.Add(t1, y3); // Y3 := t1 + Y3
        t1.Add(t0, t0); // t1 := t0 + t0
        t0.Add(t1, t0); // t0 := t1 + t0
        t0.Sub(t0, t2); // t0 := t0 - t2
        t1.Mul(t4, y3); // t1 := t4 * Y3
        t2.Mul(t0, y3); // t2 := t0 * Y3
        y3.Mul(x3, z3); // Y3 := X3 * Z3
        y3.Add(y3, t2); // Y3 := Y3 + t2
        x3.Mul(t3, x3); // X3 := t3 * X3
        x3.Sub(x3, t1); // X3 := X3 - t1
        z3.Mul(t4, z3); // Z3 := t4 * Z3
        t1.Mul(t3, t0); // t1 := t3 * t0
        z3.Add(z3, t1); // Z3 := Z3 + t1

        self.x.Set(x3);
        self.y.Set(y3);
        self.z.Set(z3);
        return self;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:276-320 P256Point.Double
    /// Set q = p + p, and return q. The points may overlap.
    pub fn Double(&mut self, p: P256Point) -> &mut Self {
        // Complete addition formula for a = -3 from "Complete addition
        // formulas for prime order elliptic curves"
        // (https://eprint.iacr.org/2015/1060), §A.2.

        let mut t0 = P256Element::New();
        t0.Square(p.x); // t0 := X ^ 2
        let mut t1 = P256Element::New();
        t1.Square(p.y); // t1 := Y ^ 2
        let mut t2 = P256Element::New();
        t2.Square(p.z); // t2 := Z ^ 2
        let mut t3 = P256Element::New();
        t3.Mul(p.x, p.y); // t3 := X * Y
        t3.Add(t3, t3); // t3 := t3 + t3
        let mut z3 = P256Element::New();
        z3.Mul(p.x, p.z); // Z3 := X * Z
        z3.Add(z3, z3); // Z3 := Z3 + Z3
        let mut y3 = P256Element::New();
        y3.Mul(p256B(), t2); // Y3 := b * t2
        y3.Sub(y3, z3); // Y3 := Y3 - Z3
        let mut x3 = P256Element::New();
        x3.Add(y3, y3); // X3 := Y3 + Y3
        y3.Add(x3, y3); // Y3 := X3 + Y3
        x3.Sub(t1, y3); // X3 := t1 - Y3
        y3.Add(t1, y3); // Y3 := t1 + Y3
        y3.Mul(x3, y3); // Y3 := X3 * Y3
        x3.Mul(x3, t3); // X3 := X3 * t3
        t3.Add(t2, t2); // t3 := t2 + t2
        t2.Add(t2, t3); // t2 := t2 + t3
        z3.Mul(p256B(), z3); // Z3 := b * Z3
        z3.Sub(z3, t2); // Z3 := Z3 - t2
        z3.Sub(z3, t0); // Z3 := Z3 - t0
        t3.Add(z3, z3); // t3 := Z3 + Z3
        z3.Add(z3, t3); // Z3 := Z3 + t3
        t3.Add(t0, t0); // t3 := t0 + t0
        t0.Add(t3, t0); // t0 := t3 + t0
        t0.Sub(t0, t2); // t0 := t0 - t2
        t0.Mul(t0, z3); // t0 := t0 * Z3
        y3.Add(y3, t0); // Y3 := Y3 + t0
        t0.Mul(p.y, p.z); // t0 := Y * Z
        t0.Add(t0, t0); // t0 := t0 + t0
        z3.Mul(t0, z3); // Z3 := t0 * Z3
        x3.Sub(x3, z3); // X3 := X3 - Z3
        z3.Mul(t0, t1); // Z3 := t0 * t1
        z3.Add(z3, z3); // Z3 := Z3 + Z3
        z3.Add(z3, z3); // Z3 := Z3 + Z3

        self.x.Set(x3);
        self.y.Set(y3);
        self.z.Set(z3);
        return self;
    }
}

// Go: p256.go:322-326
//   type p256AffinePoint struct { x, y fiat.P256Element }
/// A point in affine coordinates (x, y). x and y are still Montgomery
/// domain elements. The point can't be the point at infinity.
#[derive(Clone, Copy)]
struct p256AffinePoint {
    x: P256Element,
    y: P256Element,
}

impl p256AffinePoint {
    // go: none — Go writes `&p256AffinePoint{}`; this is that zero value.
    fn New() -> Self {
        return p256AffinePoint {
            x: P256Element::New(),
            y: P256Element::New(),
        };
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:328-332 p256AffinePoint.Projective
    fn Projective(&self) -> P256Point {
        let mut pp = P256Point {
            x: self.x,
            y: self.y,
            z: P256Element::New(),
        };
        pp.z.One();
        return pp;
    }
}

impl P256Point {
    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:334-386 P256Point.AddAffine
    /// Set q = p1 + p2, if infinity == 0, and to p1 if infinity == 1.
    /// p2 can't be the point at infinity as it can't be represented in
    /// affine coordinates; instead callers can set p2 to an arbitrary point
    /// and set infinity to 1.
    fn AddAffine(&mut self, p1: P256Point, p2: p256AffinePoint, infinity: int) -> &mut Self {
        // Complete mixed addition formula for a = -3 from "Complete
        // addition formulas for prime order elliptic curves"
        // (https://eprint.iacr.org/2015/1060), Algorithm 5.

        let mut t0 = P256Element::New();
        t0.Mul(p1.x, p2.x); // t0 ← X1 · X2
        let mut t1 = P256Element::New();
        t1.Mul(p1.y, p2.y); // t1 ← Y1 · Y2
        let mut t3 = P256Element::New();
        t3.Add(p2.x, p2.y); // t3 ← X2 + Y2
        let mut t4 = P256Element::New();
        t4.Add(p1.x, p1.y); // t4 ← X1 + Y1
        t3.Mul(t3, t4); // t3 ← t3 · t4
        t4.Add(t0, t1); // t4 ← t0 + t1
        t3.Sub(t3, t4); // t3 ← t3 − t4
        t4.Mul(p2.y, p1.z); // t4 ← Y2 · Z1
        t4.Add(t4, p1.y); // t4 ← t4 + Y1
        let mut y3 = P256Element::New();
        y3.Mul(p2.x, p1.z); // Y3 ← X2 · Z1
        y3.Add(y3, p1.x); // Y3 ← Y3 + X1
        let mut z3 = P256Element::New();
        z3.Mul(p256B(), p1.z); // Z3 ← b  · Z1
        let mut x3 = P256Element::New();
        x3.Sub(y3, z3); // X3 ← Y3 − Z3
        z3.Add(x3, x3); // Z3 ← X3 + X3
        x3.Add(x3, z3); // X3 ← X3 + Z3
        z3.Sub(t1, x3); // Z3 ← t1 − X3
        x3.Add(t1, x3); // X3 ← t1 + X3
        y3.Mul(p256B(), y3); // Y3 ← b  · Y3
        t1.Add(p1.z, p1.z); // t1 ← Z1 + Z1
        let mut t2 = P256Element::New();
        t2.Add(t1, p1.z); // t2 ← t1 + Z1
        y3.Sub(y3, t2); // Y3 ← Y3 − t2
        y3.Sub(y3, t0); // Y3 ← Y3 − t0
        t1.Add(y3, y3); // t1 ← Y3 + Y3
        y3.Add(t1, y3); // Y3 ← t1 + Y3
        t1.Add(t0, t0); // t1 ← t0 + t0
        t0.Add(t1, t0); // t0 ← t1 + t0
        t0.Sub(t0, t2); // t0 ← t0 − t2
        t1.Mul(t4, y3); // t1 ← t4 · Y3
        t2.Mul(t0, y3); // t2 ← t0 · Y3
        y3.Mul(x3, z3); // Y3 ← X3 · Z3
        y3.Add(y3, t2); // Y3 ← Y3 + t2
        x3.Mul(t3, x3); // X3 ← t3 · X3
        x3.Sub(x3, t1); // X3 ← X3 − t1
        z3.Mul(t4, z3); // Z3 ← t4 · Z3
        t1.Mul(t3, t0); // t1 ← t3 · t0
        z3.Add(z3, t1); // Z3 ← Z3 + t1

        self.x.Select(p1.x, x3, infinity);
        self.y.Select(p1.y, y3, infinity);
        self.z.Select(p1.z, z3, infinity);
        return self;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:388-394 P256Point.Select
    /// Set q to p1 if cond == 1, and to p2 if cond == 0.
    pub fn Select(&mut self, p1: P256Point, p2: P256Point, cond: int) -> &mut Self {
        self.x.Select(p1.x, p2.x, cond);
        self.y.Select(p1.y, p2.y, cond);
        self.z.Select(p1.z, p2.z, cond);
        return self;
    }
}

// Go: p256.go:396-398
//   type p256OrdElement [4]uint64
/// A P-256 scalar field element in [0, ord(G)-1] in the Montgomery domain
/// (with R 2²⁵⁶) as four uint64 limbs in little-endian order.
#[derive(Clone, Copy)]
struct p256OrdElement([uint64; 4]);

impl p256OrdElement {
    // go: none — Go writes `new(p256OrdElement)`; this is that zero value.
    fn New() -> Self {
        return p256OrdElement([0; 4]);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:400-424 p256OrdElement.SetBytes
    /// Set s to the big-endian value of x, reducing it as necessary.
    fn SetBytes(&mut self, x: &slice<byte>) -> error {
        let raw: &[byte] = x;
        if raw.len() != 32 {
            return errors::New("invalid scalar length");
        }

        self.0[0] = byteorder::BEUint64(slice::__from_vec(raw[24..].to_vec()));
        self.0[1] = byteorder::BEUint64(slice::__from_vec(raw[16..].to_vec()));
        self.0[2] = byteorder::BEUint64(slice::__from_vec(raw[8..].to_vec()));
        self.0[3] = byteorder::BEUint64(slice::__from_vec(raw[..].to_vec()));

        // Ensure s is in the range [0, ord(G)-1]. Since 2 * ord(G) > 2²⁵⁶,
        // we can just conditionally subtract ord(G), keeping the result if
        // it doesn't underflow.
        let (t0, b) = bits::Sub64(self.0[0], 0xf3b9cac2fc632551, 0);
        let (t1, b) = bits::Sub64(self.0[1], 0xbce6faada7179e84, b);
        let (t2, b) = bits::Sub64(self.0[2], 0xffffffffffffffff, b);
        let (t3, b) = bits::Sub64(self.0[3], 0xffffffff00000000, b);
        let tMask = b.wrapping_sub(1); // zero if subtraction underflowed
        self.0[0] ^= (t0 ^ self.0[0]) & tMask;
        self.0[1] ^= (t1 ^ self.0[1]) & tMask;
        self.0[2] ^= (t2 ^ self.0[2]) & tMask;
        self.0[3] ^= (t3 ^ self.0[3]) & tMask;

        return crate::nil.into();
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:426-433 p256OrdElement.Bytes
    // Unused inside the package: Go's callers are p256_ordinv.go (the
    // assembly side, not ported) and crypto/ecdsa.
    #[allow(dead_code)]
    fn Bytes(&self) -> slice<byte> {
        let mut out = slice::__from_vec(alloc::vec![0u8; 32]);
        let mut tail = slice::__from_vec(alloc::vec![0u8; 8]);
        let mut put = |at: usize, v: uint64| {
            byteorder::BEPutUint64(&mut tail, v);
            let t: &[byte] = &tail;
            let o: &mut [byte] = &mut out;
            o[at..at + 8].copy_from_slice(t);
        };
        put(24, self.0[0]);
        put(16, self.0[1]);
        put(8, self.0[2]);
        put(0, self.0[3]);
        return out;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:435-446 p256OrdElement.Rsh
    /// Return the 64 least significant bits of x >> n. n must be lower than
    /// 256. The value of n leaks through timing side-channels.
    fn Rsh(&self, n: int) -> uint64 {
        let i = (n / 64) as usize;
        let n = uint64(n % 64);
        let mut res = self.0[i] >> n;
        // Shift in the more significant limb, if present.
        let j = i + 1;
        if j < self.0.len() {
            res |= shl64(self.0[j], 64 - n);
        }
        return res;
    }
}

// go: none — Go's `x << 64` on a uint64 yields 0 while Rust's `<<`
// panics at the operand width. Rsh above shifts by `64 - n` with n zero
// whenever the requested bit index is a multiple of 64, so the Go
// semantics have to be spelled out rather than inherited.
fn shl64(x: uint64, n: uint64) -> uint64 {
    if n >= 64 {
        return 0;
    }
    return x << n;
}

// Go: p256.go:448-451
//   type p256Table [16]P256Point
/// A table of the first 16 multiples of a point. Points are stored at an
/// index offset of -1 so [8]P is at index 7, P is at 0, and [16]P is at
/// 15. [0]P is the point at infinity and it's not stored.
#[derive(Clone, Copy)]
struct p256Table([P256Point; 16]);

impl p256Table {
    // go: none — Go writes `new(p256Table)`; this is that zero value.
    fn New() -> Self {
        return p256Table([NewP256Point(); 16]);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:453-464 p256Table.Select
    /// Select the n-th multiple of the table base point into p. It works in
    /// constant time. n must be in [0, 16]. If n is 0, p is set to the
    /// identity point.
    fn Select(&self, p: &mut P256Point, n: byte) {
        if n > 16 {
            panic!("nistec: internal error: p256Table called with out-of-bounds value");
        }
        p.Set(NewP256Point());
        let mut i: byte = 1;
        while i <= 16 {
            let cond = subtle::ConstantTimeByteEq(i, n);
            let e = self.0[(i - 1) as usize];
            p.Select(e, *p, cond);
            i += 1;
        }
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:466-476 p256Table.Compute
    /// Populate the table to the first 16 multiples of q.
    fn Compute(&mut self, q: P256Point) -> &mut Self {
        self.0[0].Set(q);
        let mut i: usize = 1;
        while i < 16 {
            let half = self.0[i / 2];
            self.0[i].Double(half);
            if i + 1 < 16 {
                let prev = self.0[i];
                self.0[i + 1].Add(prev, q);
            }
            i += 2;
        }
        return self;
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:478-484 boothW5
fn boothW5(inv: uint64) -> (byte, int) {
    let s = !((inv >> 5).wrapping_sub(1));
    let mut d = (1u64 << 6).wrapping_sub(inv).wrapping_sub(1);
    d = (d & s) | (inv & (!s));
    d = (d >> 1) + (d & 1);
    return (byte(d), int(s & 1));
}

impl P256Point {
    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:489-534 P256Point.ScalarMult
    /// Set r = scalar * q, where scalar is a 32-byte big endian value, and
    /// return r. If scalar is not 32 bytes long, ScalarMult returns an
    /// error and the receiver is unchanged.
    pub fn ScalarMult(&mut self, q: P256Point, scalar: &slice<byte>) -> error {
        let mut s = p256OrdElement::New();
        let err = s.SetBytes(scalar);
        if err != crate::nil {
            return err;
        }

        // Start scanning the window from the most significant bits. We move
        // by 5 bits at a time and need to finish at -1, so -1 + 5 * 51 = 254.
        let mut index: int = 254;

        let (mut sel, mut sign) = boothW5(s.Rsh(index));
        // sign is always zero because the boothW5 input here is at most two
        // bits long, so the top bit is never set.
        let _ = sign;

        // Neither Select nor Add have exceptions for the point at infinity /
        // selector zero, so we don't need to check for it here or in the loop.
        let mut table = p256Table::New();
        table.Compute(q);
        table.Select(self, sel);

        let mut t = NewP256Point();
        while index >= 4 {
            index -= 5;

            let p = *self;
            self.Double(p);
            let p = *self;
            self.Double(p);
            let p = *self;
            self.Double(p);
            let p = *self;
            self.Double(p);
            let p = *self;
            self.Double(p);

            if index >= 0 {
                let (a, b) = boothW5(s.Rsh(index) & 0b111111);
                sel = a;
                sign = b;
            } else {
                // Booth encoding considers a virtual zero bit at index -1,
                // so we shift left the least significant limb.
                let wvalue = (s.0[0] << 1) & 0b111111;
                let (a, b) = boothW5(wvalue);
                sel = a;
                sign = b;
            }

            table.Select(&mut t, sel);
            t.Negate(sign);
            let p = *self;
            self.Add(p, t);
        }

        return crate::nil.into();
    }

    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:537-542 P256Point.Negate
    /// Set p to -p, if cond == 1, and to p if cond == 0.
    pub fn Negate(&mut self, cond: int) -> &mut Self {
        let mut negY = P256Element::New();
        negY.Sub(negY, self.y);
        self.y.Select(negY, self.y, cond);
        return self;
    }
}

// Go: p256.go:538-540
//   type p256AffineTable [32]p256AffinePoint
/// A table of the first 32 multiples of a point. Points are stored at an
/// index offset of -1 like in p256Table, and [0]P is not stored.
#[derive(Clone, Copy)]
struct p256AffineTable([p256AffinePoint; 32]);

impl p256AffineTable {
    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:551-560 p256AffineTable.Select
    /// Select the n-th multiple of the table base point into p. It works in
    /// constant time. n can be in [0, 32], but (unlike p256Table.Select) if
    /// n is 0, p is set to an undefined value.
    fn Select(&self, p: &mut p256AffinePoint, n: byte) {
        if n > 32 {
            panic!("nistec: internal error: p256AffineTable.Select called with out-of-bounds value");
        }
        let mut i: byte = 1;
        while i <= 32 {
            let cond = subtle::ConstantTimeByteEq(i, n);
            let e = self.0[(i - 1) as usize];
            p.x.Select(e.x, p.x, cond);
            p.y.Select(e.y, p.y, cond);
            i += 1;
        }
    }
}

// Go: p256.go:555-563 — `var p256GeneratorTables *[43]p256AffineTable`,
// filled by the `init` on p256.go:565-575.
//
/// A series of precomputed multiples of G, the canonical generator. The
/// first p256AffineTable contains multiples of G. The second one multiples
/// of [2⁶]G, the third one of [2¹²]G, and so on, where each successive
/// table is the previous table doubled six times. Six is the width of the
/// sliding window used in ScalarBaseMult, and having each table already
/// pre-doubled lets us avoid the doublings between windows entirely.
///
/// Go aliases this straight into p256PrecomputedEmbed with an
/// `unsafe.Pointer` cast on little-endian hosts, and rebuilds it with
/// `byteorder.LEUint64` on big-endian ones. This is that second path,
/// taken unconditionally: same limbs, no pointer cast.
static p256GeneratorTables: Lazy<Vec<p256AffineTable>> = Lazy::new(|| {
    let mut tables: Vec<p256AffineTable> = Vec::with_capacity(43);
    let mut off: usize = 0;
    let mut limb = || {
        let v = byteorder::LEUint64(slice::__from_vec(
            p256PrecomputedEmbed[off..off + 8].to_vec(),
        ));
        off += 8;
        return v;
    };
    let mut i: usize = 0;
    while i < 43 {
        let mut table = p256AffineTable([p256AffinePoint::New(); 32]);
        let mut j: usize = 0;
        while j < 32 {
            // Go reinterprets the same bytes as fiat.P256Element directly;
            // the limbs are already Montgomery-domain, so this writes them
            // in rather than going through SetBytes.
            table.0[j].x = P256Element {
                x: [limb(), limb(), limb(), limb()],
            };
            table.0[j].y = P256Element {
                x: [limb(), limb(), limb(), limb()],
            };
            j += 1;
        }
        tables.push(table);
        i += 1;
    }
    return tables;
});

// go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:583-589 boothW6
fn boothW6(inv: uint64) -> (byte, int) {
    let s = !((inv >> 6).wrapping_sub(1));
    let mut d = (1u64 << 7).wrapping_sub(inv).wrapping_sub(1);
    d = (d & s) | (inv & (!s));
    d = (d >> 1) + (d & 1);
    return (byte(d), int(s & 1));
}

impl P256Point {
    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:594-644 P256Point.ScalarBaseMult
    /// Set p = scalar * generator, where scalar is a 32-byte big endian
    /// value, and return r. If scalar is not 32 bytes long, ScalarBaseMult
    /// returns an error and the receiver is unchanged.
    pub fn ScalarBaseMult(&mut self, scalar: &slice<byte>) -> error {
        // This function works like ScalarMult above, but the table is fixed
        // and "pre-doubled" for each iteration, so instead of doubling we
        // move to the next table at each iteration.

        let mut s = p256OrdElement::New();
        let err = s.SetBytes(scalar);
        if err != crate::nil {
            return err;
        }

        // Start scanning the window from the most significant bits. We move
        // by 6 bits at a time and need to finish at -1, so -1 + 6 * 42 = 251.
        let mut index: int = 251;

        let (mut sel, mut sign) = boothW6(s.Rsh(index));
        // sign is always zero because the boothW6 input here is at most five
        // bits long, so the top bit is never set.
        let _ = sign;

        let mut t = p256AffinePoint::New();
        let tables = &*p256GeneratorTables;
        tables[((index + 1) / 6) as usize].Select(&mut t, sel);

        // Select's output is undefined if the selector is zero, when it
        // should be the point at infinity (because infinity can't be
        // represented in affine coordinates). Here we conditionally set p to
        // the infinity if sel is zero. In the loop, that's handled by
        // AddAffine.
        let selIsZero = subtle::ConstantTimeByteEq(sel, 0);
        self.Select(NewP256Point(), t.Projective(), selIsZero);

        while index >= 5 {
            index -= 6;

            if index >= 0 {
                let (a, b) = boothW6(s.Rsh(index) & 0b1111111);
                sel = a;
                sign = b;
            } else {
                // Booth encoding considers a virtual zero bit at index -1,
                // so we shift left the least significant limb.
                let wvalue = (s.0[0] << 1) & 0b1111111;
                let (a, b) = boothW6(wvalue);
                sel = a;
                sign = b;
            }

            tables[((index + 1) / 6) as usize].Select(&mut t, sel);
            t.Negate(sign);
            let selIsZero = subtle::ConstantTimeByteEq(sel, 0);
            let p = *self;
            self.AddAffine(p, t, selIsZero);
        }

        return crate::nil.into();
    }
}

impl p256AffinePoint {
    // go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:647-652 p256AffinePoint.Negate
    /// Set p to -p, if cond == 1, and to p if cond == 0.
    fn Negate(&mut self, cond: int) -> &mut Self {
        let mut negY = P256Element::New();
        negY.Sub(negY, self.y);
        self.y.Select(negY, self.y, cond);
        return self;
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:656-697 p256Sqrt
/// Set e to a square root of x. If x is not a square, p256Sqrt returns
/// false and e is unchanged. e and x can overlap.
fn p256Sqrt(e: &mut P256Element, x: P256Element) -> bool {
    let mut t0 = P256Element::New();
    let mut t1 = P256Element::New();

    // Since p = 3 mod 4, exponentiation by (p + 1) / 4 yields a square root
    // candidate.
    //
    // The sequence of 7 multiplications and 253 squarings is derived from
    // the following addition chain generated with
    // github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10       = 2*1
    //	_11       = 1 + _10
    //	_1100     = _11 << 2
    //	_1111     = _11 + _1100
    //	_11110000 = _1111 << 4
    //	_11111111 = _1111 + _11110000
    //	x16       = _11111111 << 8 + _11111111
    //	x32       = x16 << 16 + x16
    //	return      ((x32 << 32 + 1) << 96 + 1) << 94
    //
    p256Square(&mut t0, x, 1);
    t0.Mul(x, t0);
    p256Square(&mut t1, t0, 2);
    t0.Mul(t0, t1);
    p256Square(&mut t1, t0, 4);
    t0.Mul(t0, t1);
    p256Square(&mut t1, t0, 8);
    t0.Mul(t0, t1);
    p256Square(&mut t1, t0, 16);
    t0.Mul(t0, t1);
    let v = t0;
    p256Square(&mut t0, v, 32);
    t0.Mul(x, t0);
    let v = t0;
    p256Square(&mut t0, v, 96);
    t0.Mul(x, t0);
    let v = t0;
    p256Square(&mut t0, v, 94);

    // Check if the candidate t0 is indeed a square root of x.
    t1.Square(t0);
    if t1.Equal(x) != 1 {
        return false;
    }
    e.Set(t0);
    return true;
}

// go: sdk 1.25.5 crypto/internal/fips140/nistec/p256.go:700-705 p256Square
/// Set e to the square of x, repeated n times > 1.
fn p256Square(e: &mut P256Element, x: P256Element, n: int) {
    e.Square(x);
    let mut i: int = 1;
    while i < n {
        e.Square(*e);
        i += 1;
    }
}
