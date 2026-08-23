// go: file crypto/internal/fips140/mlkem/field.go decls: fieldCheckReduced, fieldReduceOnce, fieldAdd, fieldSub, fieldReduce, fieldMul, fieldMulSub, fieldAddMul, compress, decompress, polyAdd, polySub, polyByteEncode, polyByteDecode, sliceForAppend, ringCompressAndEncode1, ringDecodeAndDecompress1, ringCompressAndEncode4, ringDecodeAndDecompress4, ringCompressAndEncode10, ringDecodeAndDecompress10, ringCompressAndEncode, ringDecodeAndDecompress, ringCompressAndEncode5, ringDecodeAndDecompress5, ringCompressAndEncode11, ringDecodeAndDecompress11, samplePolyCBD, nttMul, ntt, inverseNTT, sampleNTT
//
// ML-KEM field and polynomial arithmetic (FIPS 203 §2.4.4 and §4).
//
// Deviations from field[go] @ Go 1.25.5:
//
//   * `type fieldElement uint16` is a Rust type alias, not a newtype.
//     Go's fieldElement has no methods and no operator overloads worth
//     preserving — every operation goes through fieldAdd/fieldMul/… —
//     and a newtype would force a `.0` on every one of the several
//     hundred coefficient accesses without buying any check Go has.
//   * `ringElement` and `nttElement` DO stay distinct newtypes: Go
//     relies on that distinction to keep NTT-domain and ring-domain
//     polynomials apart, and mixing them silently produces garbage.
//     Go's `[T ~[n]fieldElement]` constraint that unifies them for
//     polyAdd/polySub/polyByteEncode/polyByteDecode becomes the
//     `polyArray` trait.
//   * `sliceForAppend` returns `(head, offset)` rather than two aliasing
//     slices — the same shape the gcm port uses, since goish's slice
//     handles do not share mutable backing (AGENTS.md §2).

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::internal::fips140::sha3;
use crate::crypto::internal::fips140deps::byteorder;
use crate::errors;
use crate::goslice::slice;
use crate::types::byte;
use crate::{append, error, int, uint16, uint32, uint64, uint8};

use super::mlkem768::{
    encodingSize1, encodingSize10, encodingSize11, encodingSize12, encodingSize4, encodingSize5, n,
    q,
};

/// Go: `type fieldElement uint16` — an integer modulo q, an element of
/// ℤ_q. It is always reduced.
pub type fieldElement = uint16;

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:16-22 fieldCheckReduced
/// Check that a value `a` is < q.
pub fn fieldCheckReduced(a: uint16) -> (fieldElement, error) {
    // Go: if a >= q { return 0, errors.New("unreduced field element") }
    if a >= q {
        return (0, errors::New("unreduced field element"));
    }
    // Go: return fieldElement(a), nil
    return (a, crate::nil.into());
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:24-30 fieldReduceOnce
/// Reduce a value `a` < 2q.
pub fn fieldReduceOnce(a: uint16) -> fieldElement {
    // Go: x := a - q
    let mut x = a.wrapping_sub(q);
    // If x underflowed, then x >= 2¹⁶ - q > 2¹⁵, so the top bit is set.
    // Go: x += (x >> 15) * q
    x = x.wrapping_add((x >> 15).wrapping_mul(q));
    return x;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:32-35 fieldAdd
pub fn fieldAdd(a: fieldElement, b: fieldElement) -> fieldElement {
    // Go: x := uint16(a + b); return fieldReduceOnce(x)
    let x = a.wrapping_add(b);
    return fieldReduceOnce(x);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:37-40 fieldSub
pub fn fieldSub(a: fieldElement, b: fieldElement) -> fieldElement {
    // Go: x := uint16(a - b + q); return fieldReduceOnce(x)
    let x = a.wrapping_sub(b).wrapping_add(q);
    return fieldReduceOnce(x);
}

// Go: field.go:42-45
/// `2¹² * 2¹² / q`
const barrettMultiplier: uint64 = 5039;
/// `log₂(2¹² * 2¹²)`
const barrettShift: uint32 = 24;

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:47-52 fieldReduce
/// Reduce a value `a` < 2q² using Barrett reduction, to avoid
/// potentially variable-time division.
pub fn fieldReduce(a: uint32) -> fieldElement {
    // Go: quotient := uint32((uint64(a) * barrettMultiplier) >> barrettShift)
    let quotient = uint32(((uint64(a)).wrapping_mul(barrettMultiplier)) >> barrettShift);
    // Go: return fieldReduceOnce(uint16(a - quotient*q))
    return fieldReduceOnce(uint16(
        a.wrapping_sub(quotient.wrapping_mul(uint32(q))) & 0xffff,
    ));
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:54-57 fieldMul
pub fn fieldMul(a: fieldElement, b: fieldElement) -> fieldElement {
    // Go: x := uint32(a) * uint32(b); return fieldReduce(x)
    let x = uint32(a).wrapping_mul(uint32(b));
    return fieldReduce(x);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:59-63 fieldMulSub
/// Returns `a * (b - c)`. This operation is fused to save a
/// fieldReduceOnce after the subtraction.
pub fn fieldMulSub(a: fieldElement, b: fieldElement, c: fieldElement) -> fieldElement {
    // Go: x := uint32(a) * uint32(b-c+q)
    let x = uint32(a).wrapping_mul(uint32(b.wrapping_sub(c).wrapping_add(q)));
    return fieldReduce(x);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:68-72 fieldAddMul
/// Returns `a * b + c * d`. This operation is fused to save a
/// fieldReduceOnce and a fieldReduce.
pub fn fieldAddMul(
    a: fieldElement,
    b: fieldElement,
    c: fieldElement,
    d: fieldElement,
) -> fieldElement {
    // Go: x := uint32(a) * uint32(b); x += uint32(c) * uint32(d)
    let mut x = uint32(a).wrapping_mul(uint32(b));
    x = x.wrapping_add(uint32(c).wrapping_mul(uint32(d)));
    return fieldReduce(x);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:72-103 compress
/// Map a field element uniformly to the range 0 to 2ᵈ-1, according to
/// FIPS 203, Definition 4.7.
pub fn compress(x: fieldElement, d: uint8) -> uint16 {
    // We want to compute (x * 2ᵈ) / q, rounded to nearest integer, with
    // 1/2 rounding up (see FIPS 203, Section 2.3).

    // Barrett reduction produces a quotient and a remainder in the range
    // [0, 2q), such that dividend = quotient * q + remainder.
    // Go: dividend := uint32(x) << d
    let dividend: uint32 = uint32(x) << d;
    // Go: quotient := uint32(uint64(dividend) * barrettMultiplier >> barrettShift)
    let mut quotient = uint32((uint64(dividend)).wrapping_mul(barrettMultiplier) >> barrettShift);
    // Go: remainder := dividend - quotient*q
    let remainder = dividend.wrapping_sub(quotient.wrapping_mul(uint32(q)));

    // Since the remainder is in the range [0, 2q), not [0, q), we need to
    // portion it into three spans for rounding.
    //
    //     [ 0,       q/2     ) -> round to 0
    //     [ q/2,     q + q/2 ) -> round to 1
    //     [ q + q/2, 2q      ) -> round to 2
    //
    // We can convert that to the following logic: add 1 if
    // remainder > q/2, then add 1 again if remainder > q + q/2.
    //
    // Note that if remainder > x, then ⌊x⌋ - remainder underflows, and
    // the top bit of the difference will be set.
    let qq = uint32(q);
    // Go: quotient += (q/2 - remainder) >> 31 & 1
    quotient = quotient.wrapping_add(((qq / 2).wrapping_sub(remainder) >> 31) & 1);
    // Go: quotient += (q + q/2 - remainder) >> 31 & 1
    quotient = quotient.wrapping_add(((qq + qq / 2).wrapping_sub(remainder) >> 31) & 1);

    // quotient might have overflowed at this point, so reduce it by masking.
    // Go: var mask uint32 = (1 << d) - 1; return uint16(quotient & mask)
    let mask: uint32 = (1u32 << d) - 1;
    return uint16(quotient & mask & 0xffff);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:108-122 decompress
/// Map a number `y` between 0 and 2ᵈ-1 uniformly to the full range of
/// field elements, according to FIPS 203, Definition 4.8.
pub fn decompress(y: uint16, d: uint8) -> fieldElement {
    // We want to compute (y * q) / 2ᵈ, rounded to nearest integer, with
    // 1/2 rounding up (see FIPS 203, Section 2.3).

    // Go: dividend := uint32(y) * q
    let dividend = uint32(y).wrapping_mul(uint32(q));
    // Go: quotient := dividend >> d
    let mut quotient = dividend >> d;

    // The d'th least-significant bit of the dividend (the most
    // significant bit of the remainder) is 1 for the top half of the
    // values that divide to the same quotient, which are the ones that
    // round up.
    // Go: quotient += dividend >> (d - 1) & 1
    quotient += (dividend >> (d - 1)) & 1;

    // quotient is at most (2¹¹-1) * q / 2¹¹ + 1 = 3328, so it didn't overflow.
    return uint16(quotient & 0xffff);
}

// Go: field.go:122-126
//   type ringElement [n]fieldElement
/// A polynomial, an element of R_q, represented as an array according to
/// FIPS 203, Section 2.4.4.
#[derive(Clone, Copy)]
pub struct ringElement(pub [fieldElement; n]);

// Go: field.go:420-422
//   type nttElement [n]fieldElement
/// An NTT representation, an element of T_q, represented as an array
/// according to FIPS 203, Section 2.4.4.
#[derive(Clone, Copy)]
pub struct nttElement(pub [fieldElement; n]);

// go: none — the Rust stand-in for Go's `[T ~[n]fieldElement]` type
// constraint, which is what lets polyAdd/polySub/polyByteEncode/
// polyByteDecode accept both ringElement and nttElement.
pub trait polyArray: Copy {
    // go: none — accessor for the `polyArray` constraint stand-in; Go's
    // `~[n]fieldElement` needs no such method.
    fn coeffs(&self) -> &[fieldElement; n];
    // go: none — accessor for the `polyArray` constraint stand-in; Go's
    // `~[n]fieldElement` needs no such method.
    fn coeffs_mut(&mut self) -> &mut [fieldElement; n];
    // go: none — accessor for the `polyArray` constraint stand-in; Go's
    // `~[n]fieldElement` needs no such method.
    fn zero() -> Self;
}

impl polyArray for ringElement {
    // go: none — accessor for the `polyArray` constraint stand-in; Go's
    // `~[n]fieldElement` needs no such method.
    fn coeffs(&self) -> &[fieldElement; n] {
        return &self.0;
    }
    // go: none — accessor for the `polyArray` constraint stand-in; Go's
    // `~[n]fieldElement` needs no such method.
    fn coeffs_mut(&mut self) -> &mut [fieldElement; n] {
        return &mut self.0;
    }
    // go: none — accessor for the `polyArray` constraint stand-in; Go's
    // `~[n]fieldElement` needs no such method.
    fn zero() -> Self {
        return ringElement([0; n]);
    }
}

impl polyArray for nttElement {
    // go: none — accessor for the `polyArray` constraint stand-in; Go's
    // `~[n]fieldElement` needs no such method.
    fn coeffs(&self) -> &[fieldElement; n] {
        return &self.0;
    }
    // go: none — accessor for the `polyArray` constraint stand-in; Go's
    // `~[n]fieldElement` needs no such method.
    fn coeffs_mut(&mut self) -> &mut [fieldElement; n] {
        return &mut self.0;
    }
    // go: none — accessor for the `polyArray` constraint stand-in; Go's
    // `~[n]fieldElement` needs no such method.
    fn zero() -> Self {
        return nttElement([0; n]);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:128-135 polyAdd
/// Add two ringElements or nttElements.
pub fn polyAdd<T: polyArray>(a: T, b: T) -> T {
    // Go: for i := range s { s[i] = fieldAdd(a[i], b[i]) }
    let mut s = T::zero();
    let mut i: usize = 0;
    while i < n {
        s.coeffs_mut()[i] = fieldAdd(a.coeffs()[i], b.coeffs()[i]);
        i += 1;
    }
    return s;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:137-144 polySub
/// Subtract two ringElements or nttElements.
pub fn polySub<T: polyArray>(a: T, b: T) -> T {
    // Go: for i := range s { s[i] = fieldSub(a[i], b[i]) }
    let mut s = T::zero();
    let mut i: usize = 0;
    while i < n {
        s.coeffs_mut()[i] = fieldSub(a.coeffs()[i], b.coeffs()[i]);
        i += 1;
    }
    return s;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:146-160 polyByteEncode
/// Append the 384-byte encoding of `f` to `b`. Implements ByteEncode₁₂,
/// according to FIPS 203, Algorithm 5.
pub fn polyByteEncode<T: polyArray>(b: slice<byte>, f: T) -> slice<byte> {
    // Go: out, B := sliceForAppend(b, encodingSize12)
    let (mut out, off) = sliceForAppend(b, int(encodingSize12));
    let B: &mut [byte] = &mut out;
    // Go: for i := 0; i < n; i += 2 { … B = B[3:] }
    let mut i: usize = 0;
    let mut p = off;
    while i < n {
        let x = uint32(f.coeffs()[i]) | (uint32(f.coeffs()[i + 1]) << 12);
        B[p] = uint8(x & 0xff);
        B[p + 1] = uint8((x >> 8) & 0xff);
        B[p + 2] = uint8((x >> 16) & 0xff);
        p += 3;
        i += 2;
    }
    // Go: return out
    return out;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:162-186 polyByteDecode
/// Decode the 384-byte encoding of a polynomial, checking that all the
/// coefficients are properly reduced. This fulfills the "Modulus check"
/// step of ML-KEM Encapsulation. Implements ByteDecode₁₂, according to
/// FIPS 203, Algorithm 6.
pub fn polyByteDecode<T: polyArray>(b: slice<byte>) -> (T, error) {
    // Go: if len(b) != encodingSize12 { return T{}, errors.New(…) }
    if b.Len() != int(encodingSize12) {
        return (T::zero(), errors::New("mlkem: invalid encoding length"));
    }
    // Go: var f T
    let mut f = T::zero();
    let raw: &[byte] = &b;
    let mut i: usize = 0;
    let mut p: usize = 0;
    // Go: for i := 0; i < n; i += 2 { … b = b[3:] }
    while i < n {
        let d = uint32(raw[p]) | (uint32(raw[p + 1]) << 8) | (uint32(raw[p + 2]) << 16);
        const mask12: uint32 = 0b1111_1111_1111;
        // Go: if f[i], err = fieldCheckReduced(uint16(d & mask12)); err != nil { … }
        let (v, err) = fieldCheckReduced(uint16(d & mask12));
        if err != crate::nil {
            return (T::zero(), errors::New("mlkem: invalid polynomial encoding"));
        }
        f.coeffs_mut()[i] = v;
        // Go: if f[i+1], err = fieldCheckReduced(uint16(d >> 12)); err != nil { … }
        let (v, err) = fieldCheckReduced(uint16(d >> 12));
        if err != crate::nil {
            return (T::zero(), errors::New("mlkem: invalid polynomial encoding"));
        }
        f.coeffs_mut()[i + 1] = v;
        p += 3;
        i += 2;
    }
    // Go: return f, nil
    return (f, crate::nil.into());
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:188-198 sliceForAppend
/// Take a slice and a requested number of bytes, and return the slice
/// with that many zero bytes appended plus the offset at which they
/// start.
///
/// Go returns a second slice aliasing into the first; goish's slice
/// handles never share mutable backing, so the caller indexes from the
/// returned offset instead. Cap-reuse is likewise a Go-allocator detail
/// with no goish counterpart.
///
/// Go's parameter is named `n`, which here would shadow the ML-KEM
/// degree constant `n` (a const, so Rust reads it as a pattern, not a
/// binding); it is spelled `nBytes`.
pub fn sliceForAppend(inp: slice<byte>, nBytes: int) -> (slice<byte>, usize) {
    // Go: if total := len(in) + n; cap(in) >= total { head = in[:total] }
    //     else { head = make([]byte, total); copy(head, in) }
    let start = inp.Len() as usize;
    let mut head = slice::__into_vec(inp);
    head.resize(start + (nBytes as usize), 0);
    // Go: tail = head[len(in):]
    return (slice::__from_vec(head), start);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:200-213 ringCompressAndEncode1
/// Append a 32-byte encoding of a ring element to `s`, compressing one
/// coefficient per bit. Implements Compress₁ (FIPS 203, Definition 4.7)
/// followed by ByteEncode₁ (FIPS 203, Algorithm 5).
pub fn ringCompressAndEncode1(s: slice<byte>, f: ringElement) -> slice<byte> {
    // Go: s, b := sliceForAppend(s, encodingSize1)
    let (mut s, off) = sliceForAppend(s, int(encodingSize1));
    let b: &mut [byte] = &mut s;
    // Go: for i := range b { b[i] = 0 }
    let mut i: usize = 0;
    while i < encodingSize1 {
        b[off + i] = 0;
        i += 1;
    }
    // Go: for i := range f { b[i/8] |= uint8(compress(f[i], 1) << (i % 8)) }
    let mut i: usize = 0;
    while i < n {
        b[off + i / 8] |= uint8((compress(f.0[i], 1) << (i % 8)) & 0xff);
        i += 1;
    }
    return s;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:215-228 ringDecodeAndDecompress1
/// Decode a 32-byte slice to a ring element where each bit is mapped to
/// 0 or ⌈q/2⌋.
pub fn ringDecodeAndDecompress1(b: &[byte; encodingSize1]) -> ringElement {
    // Go: var f ringElement
    let mut f = ringElement([0; n]);
    let mut i: usize = 0;
    while i < n {
        // Go: b_i := b[i/8] >> (i % 8) & 1
        let b_i = (b[i / 8] >> (i % 8)) & 1;
        // ⌈q/2⌋, rounded up per FIPS 203, Section 2.3
        const halfQ: uint16 = (q + 1) / 2;
        // Go: f[i] = fieldElement(b_i) * halfQ
        //
        // 0 decompresses to 0, and 1 to ⌈q/2⌋.
        f.0[i] = uint16(b_i).wrapping_mul(halfQ);
        i += 1;
    }
    return f;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:230-240 ringCompressAndEncode4
/// Append a 128-byte encoding of a ring element to `s`, compressing two
/// coefficients per byte.
pub fn ringCompressAndEncode4(s: slice<byte>, f: ringElement) -> slice<byte> {
    // Go: s, b := sliceForAppend(s, encodingSize4)
    let (mut s, off) = sliceForAppend(s, int(encodingSize4));
    let b: &mut [byte] = &mut s;
    // Go: for i := 0; i < n; i += 2 { b[i/2] = uint8(compress(f[i], 4) | compress(f[i+1], 4)<<4) }
    let mut i: usize = 0;
    while i < n {
        b[off + i / 2] = uint8((compress(f.0[i], 4) | (compress(f.0[i + 1], 4) << 4)) & 0xff);
        i += 2;
    }
    return s;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:248-255 ringDecodeAndDecompress4
/// Decode a 128-byte encoding of a ring element where each four bits are
/// mapped to an equidistant distribution.
pub fn ringDecodeAndDecompress4(b: &[byte; encodingSize4]) -> ringElement {
    let mut f = ringElement([0; n]);
    let mut i: usize = 0;
    // Go: for i := 0; i < n; i += 2 { … }
    while i < n {
        f.0[i] = decompress(uint16(b[i / 2] & 0b1111), 4);
        f.0[i + 1] = decompress(uint16(b[i / 2] >> 4), 4);
        i += 2;
    }
    return f;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:262-278 ringCompressAndEncode10
/// Append a 320-byte encoding of a ring element to `s`, compressing four
/// coefficients per five bytes.
pub fn ringCompressAndEncode10(s: slice<byte>, f: ringElement) -> slice<byte> {
    // Go: s, b := sliceForAppend(s, encodingSize10)
    let (mut s, off) = sliceForAppend(s, int(encodingSize10));
    let b: &mut [byte] = &mut s;
    let mut i: usize = 0;
    let mut p = off;
    // Go: for i := 0; i < n; i += 4 { … b = b[5:] }
    while i < n {
        let mut x: uint64 = 0;
        x |= uint64(compress(f.0[i], 10));
        x |= uint64(compress(f.0[i + 1], 10)) << 10;
        x |= uint64(compress(f.0[i + 2], 10)) << 20;
        x |= uint64(compress(f.0[i + 3], 10)) << 30;
        b[p] = uint8(x & 0xff);
        b[p + 1] = uint8((x >> 8) & 0xff);
        b[p + 2] = uint8((x >> 16) & 0xff);
        b[p + 3] = uint8((x >> 24) & 0xff);
        b[p + 4] = uint8((x >> 32) & 0xff);
        p += 5;
        i += 4;
    }
    return s;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:285-297 ringDecodeAndDecompress10
/// Decode a 320-byte encoding of a ring element where each ten bits are
/// mapped to an equidistant distribution.
pub fn ringDecodeAndDecompress10(bb: &[byte; encodingSize10]) -> ringElement {
    // Go: b := bb[:]; var f ringElement
    let b: &[byte] = bb;
    let mut f = ringElement([0; n]);
    let mut i: usize = 0;
    let mut p: usize = 0;
    // Go: for i := 0; i < n; i += 4 { … b = b[5:] }
    while i < n {
        let x = uint64(b[p])
            | (uint64(b[p + 1]) << 8)
            | (uint64(b[p + 2]) << 16)
            | (uint64(b[p + 3]) << 24)
            | (uint64(b[p + 4]) << 32);
        p += 5;
        f.0[i] = decompress(uint16(x & 0b11_1111_1111), 10);
        f.0[i + 1] = decompress(uint16((x >> 10) & 0b11_1111_1111), 10);
        f.0[i + 2] = decompress(uint16((x >> 20) & 0b11_1111_1111), 10);
        f.0[i + 3] = decompress(uint16((x >> 30) & 0b11_1111_1111), 10);
        i += 4;
    }
    return f;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:304-326 ringCompressAndEncode
/// Append an encoding of a ring element to `s`, compressing each
/// coefficient to `d` bits.
pub fn ringCompressAndEncode(s: slice<byte>, f: ringElement, d: uint8) -> slice<byte> {
    // Go: var b byte; var bIdx uint8
    let mut s = s;
    let mut b: byte = 0;
    let mut bIdx: uint8 = 0;
    let mut i: usize = 0;
    // Go: for i := 0; i < n; i++ { … }
    while i < n {
        let c = compress(f.0[i], d);
        let mut cIdx: uint8 = 0;
        while cIdx < d {
            // Go: b |= byte(c>>cIdx) << bIdx
            b |= uint8((c >> cIdx) & 0xff) << bIdx;
            // Go: bits := min(8-bIdx, d-cIdx)
            let bits = if 8 - bIdx < d - cIdx {
                8 - bIdx
            } else {
                d - cIdx
            };
            bIdx += bits;
            cIdx += bits;
            if bIdx == 8 {
                // Go: s = append(s, b); b = 0; bIdx = 0
                s = append!(s, b);
                b = 0;
                bIdx = 0;
            }
        }
        i += 1;
    }
    // Go: if bIdx != 0 { panic("mlkem: internal error: bitsFilled != 0") }
    if bIdx != 0 {
        panic!("mlkem: internal error: bitsFilled != 0");
    }
    return s;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:333-356 ringDecodeAndDecompress
/// Decode an encoding of a ring element where each `d` bits are mapped
/// to an equidistant distribution.
pub fn ringDecodeAndDecompress(b: &[byte], d: uint8) -> ringElement {
    // Go: var f ringElement; var bIdx uint8
    let mut f = ringElement([0; n]);
    let mut bIdx: uint8 = 0;
    let mut p: usize = 0;
    let mut i: usize = 0;
    // Go: for i := 0; i < n; i++ { … }
    while i < n {
        let mut c: uint16 = 0;
        let mut cIdx: uint8 = 0;
        while cIdx < d {
            // Go: c |= uint16(b[0]>>bIdx) << cIdx; c &= (1 << d) - 1
            c |= uint16(b[p] >> bIdx) << cIdx;
            c &= (1u16 << d) - 1;
            let bits = if 8 - bIdx < d - cIdx {
                8 - bIdx
            } else {
                d - cIdx
            };
            bIdx += bits;
            cIdx += bits;
            if bIdx == 8 {
                // Go: b = b[1:]; bIdx = 0
                p += 1;
                bIdx = 0;
            }
        }
        f.0[i] = decompress(c, d);
        i += 1;
    }
    // Go: if len(b) != 0 { panic("mlkem: internal error: leftover bytes") }
    if p != b.len() {
        panic!("mlkem: internal error: leftover bytes");
    }
    return f;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:363-365 ringCompressAndEncode5
/// Append a 160-byte encoding of a ring element to `s`, compressing
/// eight coefficients per five bytes.
pub fn ringCompressAndEncode5(s: slice<byte>, f: ringElement) -> slice<byte> {
    // Go: return ringCompressAndEncode(s, f, 5)
    return ringCompressAndEncode(s, f, 5);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:372-374 ringDecodeAndDecompress5
/// Decode a 160-byte encoding of a ring element where each five bits are
/// mapped to an equidistant distribution.
pub fn ringDecodeAndDecompress5(bb: &[byte; encodingSize5]) -> ringElement {
    // Go: return ringDecodeAndDecompress(bb[:], 5)
    return ringDecodeAndDecompress(bb, 5);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:381-383 ringCompressAndEncode11
/// Append a 352-byte encoding of a ring element to `s`, compressing
/// eight coefficients per eleven bytes.
pub fn ringCompressAndEncode11(s: slice<byte>, f: ringElement) -> slice<byte> {
    // Go: return ringCompressAndEncode(s, f, 11)
    return ringCompressAndEncode(s, f, 11);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:390-392 ringDecodeAndDecompress11
/// Decode a 352-byte encoding of a ring element where each eleven bits
/// are mapped to an equidistant distribution.
pub fn ringDecodeAndDecompress11(bb: &[byte; encodingSize11]) -> ringElement {
    // Go: return ringDecodeAndDecompress(bb[:], 11)
    return ringDecodeAndDecompress(bb, 11);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:392-417 samplePolyCBD
/// Draw a ringElement from the special Dη distribution given a stream of
/// random bytes generated by the PRF function, according to FIPS 203,
/// Algorithm 8 and Definition 4.3.
pub fn samplePolyCBD(s: &[byte], b: byte) -> ringElement {
    // Go: prf := sha3.NewShake256(); prf.Write(s); prf.Write([]byte{b})
    let mut prf = sha3::NewShake256();
    let _ = prf.Write(slice::__from_vec(s.to_vec()));
    let _ = prf.Write(slice::__from_vec(alloc::vec![b]));
    // Go: B := make([]byte, 64*2) // η = 2
    let mut B: Vec<byte> = alloc::vec![0u8; 64 * 2];
    prf.Read(&mut B);

    // SamplePolyCBD simply draws four (2η) bits for each coefficient, and
    // adds the first two and subtracts the last two.
    let mut f = ringElement([0; n]);
    let mut i: usize = 0;
    // Go: for i := 0; i < n; i += 2 { … }
    while i < n {
        let b = B[i / 2];
        let (b_7, b_6, b_5, b_4) = (b >> 7, (b >> 6) & 1, (b >> 5) & 1, (b >> 4) & 1);
        let (b_3, b_2, b_1, b_0) = ((b >> 3) & 1, (b >> 2) & 1, (b >> 1) & 1, b & 1);
        f.0[i] = fieldSub(uint16(b_0 + b_1), uint16(b_2 + b_3));
        f.0[i + 1] = fieldSub(uint16(b_4 + b_5), uint16(b_6 + b_7));
        i += 2;
    }
    return f;
}

/// Go: `var gammas = [128]fieldElement{…}` — the values ζ^2BitRev7(i)+1
/// mod q for each index i, according to FIPS 203, Appendix A (with
/// negative values reduced to positive).
const gammas: [fieldElement; 128] = [
    17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409,
    1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626,
    1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390,
    2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298,
    1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319,
    3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237,
    403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117,
    1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
];

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:429-439 nttMul
/// Multiply two nttElements. Implements MultiplyNTTs, according to
/// FIPS 203, Algorithm 11.
pub fn nttMul(f: nttElement, g: nttElement) -> nttElement {
    // Go: var h nttElement
    let mut h = nttElement([0; n]);
    // We use i += 2 for bounds check elimination. See https://go.dev/issue/66826.
    let mut i: usize = 0;
    while i < 256 {
        let (a0, a1) = (f.0[i], f.0[i + 1]);
        let (b0, b1) = (g.0[i], g.0[i + 1]);
        h.0[i] = fieldAddMul(a0, b0, fieldMul(a1, b1), gammas[i / 2]);
        h.0[i + 1] = fieldAddMul(a0, b1, a1, b0);
        i += 2;
    }
    return h;
}

/// Go: `var zetas = [128]fieldElement{…}` — the values ζ^BitRev7(k) mod
/// q for each index k, according to FIPS 203, Appendix A.
const zetas: [fieldElement; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:445-464 ntt
/// Map a ringElement to its nttElement representation. Implements NTT,
/// according to FIPS 203, Algorithm 9.
pub fn ntt(f: ringElement) -> nttElement {
    // Go: k := 1
    let mut a = f.0;
    let mut k: usize = 1;
    // Go: for len := 128; len >= 2; len /= 2 { … }
    let mut ln: usize = 128;
    while ln >= 2 {
        let mut start: usize = 0;
        // Go: for start := 0; start < 256; start += 2 * len { … }
        while start < 256 {
            let zeta = zetas[k];
            k += 1;
            // Go: f, flen := f[start:start+len], f[start+len:start+len+len]
            let (lo, hi) = a[start..start + 2 * ln].split_at_mut(ln);
            let mut j: usize = 0;
            while j < ln {
                // Go: t := fieldMul(zeta, flen[j])
                let t = fieldMul(zeta, hi[j]);
                // Go: flen[j] = fieldSub(f[j], t); f[j] = fieldAdd(f[j], t)
                hi[j] = fieldSub(lo[j], t);
                lo[j] = fieldAdd(lo[j], t);
                j += 1;
            }
            start += 2 * ln;
        }
        ln /= 2;
    }
    // Go: return nttElement(f)
    return nttElement(a);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:466-487 inverseNTT
/// Map an nttElement back to the ringElement it represents. Implements
/// NTT⁻¹, according to FIPS 203, Algorithm 10.
pub fn inverseNTT(f: nttElement) -> ringElement {
    // Go: k := 127
    let mut a = f.0;
    let mut k: usize = 127;
    // Go: for len := 2; len <= 128; len *= 2 { … }
    let mut ln: usize = 2;
    while ln <= 128 {
        let mut start: usize = 0;
        while start < 256 {
            let zeta = zetas[k];
            if k > 0 {
                k -= 1;
            }
            // Go: f, flen := f[start:start+len], f[start+len:start+len+len]
            let (lo, hi) = a[start..start + 2 * ln].split_at_mut(ln);
            let mut j: usize = 0;
            while j < ln {
                // Go: t := f[j]
                let t = lo[j];
                // Go: f[j] = fieldAdd(t, flen[j])
                lo[j] = fieldAdd(t, hi[j]);
                // Go: flen[j] = fieldMulSub(zeta, flen[j], t)
                hi[j] = fieldMulSub(zeta, hi[j], t);
                j += 1;
            }
            start += 2 * ln;
        }
        ln *= 2;
    }
    // Go: for i := range f { f[i] = fieldMul(f[i], 3303) } // 3303 = 128⁻¹ mod q
    let mut i: usize = 0;
    while i < n {
        a[i] = fieldMul(a[i], 3303);
        i += 1;
    }
    // Go: return ringElement(f)
    return ringElement(a);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/field.go:489-550 sampleNTT
/// Draw a uniformly random nttElement from a stream of uniformly random
/// bytes generated by the XOF function, according to FIPS 203,
/// Algorithm 7.
pub fn sampleNTT(rho: &[byte], ii: byte, jj: byte) -> nttElement {
    // Go: B := sha3.NewShake128(); B.Write(rho); B.Write([]byte{ii, jj})
    let mut B = sha3::NewShake128();
    let _ = B.Write(slice::__from_vec(rho.to_vec()));
    let _ = B.Write(slice::__from_vec(alloc::vec![ii, jj]));

    // SampleNTT essentially draws 12 bits at a time from r, interprets
    // them in little-endian, and rejects values higher than q, until it
    // drew 256 values. (The rejection rate is approximately 19%.)
    //
    // To do this from a bytes stream, it draws three bytes at a time, and
    // splits them into two uint16 appropriately masked.
    //
    //               r₀              r₁              r₂
    //       |- - - - - - - -|- - - - - - - -|- - - - - - - -|
    //
    //               Uint16(r₀ || r₁)
    //       |- - - - - - - - - - - - - - - -|
    //       |- - - - - - - - - - - -|
    //                   d₁
    //
    //                                Uint16(r₁ || r₂)
    //                       |- - - - - - - - - - - - - - - -|
    //                               |- - - - - - - - - - - -|
    //                                           d₂
    //
    // Note that in little-endian, the rightmost bits are the most
    // significant bits (dropped with a mask) and the leftmost bits are
    // the least significant bits (dropped with a right shift).

    // Go: var a nttElement; var j int; var buf [24]byte; off := len(buf)
    let mut a = nttElement([0; n]);
    let mut j: usize = 0;
    let mut buf = [0u8; 24];
    let mut off: usize = 24;
    loop {
        if off >= 24 {
            B.Read(&mut buf);
            off = 0;
        }
        // Go: d1 := byteorder.LEUint16(buf[off:]) & 0b1111_1111_1111
        let d1 =
            byteorder::LEUint16(slice::__from_vec(buf[off..off + 2].to_vec())) & 0b1111_1111_1111;
        // Go: d2 := byteorder.LEUint16(buf[off+1:]) >> 4
        let d2 = byteorder::LEUint16(slice::__from_vec(buf[off + 1..off + 3].to_vec())) >> 4;
        off += 3;
        if d1 < q {
            a.0[j] = d1;
            j += 1;
        }
        if j >= n {
            break;
        }
        if d2 < q {
            a.0[j] = d2;
            j += 1;
        }
        if j >= n {
            break;
        }
    }
    return a;
}
