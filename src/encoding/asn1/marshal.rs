// go: file encoding/asn1/marshal.go decls: base128IntLength, appendBase128Int, appendLength, lengthLength, appendTagAndLength
//
// The DER *encoding* side of encoding/asn1. goish's asn1 has been
// parse-only; this is the first slice of the other half.
//
// Scope, stated plainly: these are the five non-reflective primitives —
// tag/length and base-128 integer encoding. Everything above them in Go's
// marshal.go (the `encoder` interface and its dozen implementations,
// `makeField`, `makeBody`, and `Marshal` itself) is reflection-driven and
// is NOT here. This file is the foundation those need, not a usable
// `Marshal`.
//
// Why it lands separately: `crypto/x509/pkix` — and behind it
// `crypto/x509` and `crypto/tls`, ~415 functions — is gated on
// `asn1.Marshal`. Every byte those emit is laid down by the functions
// below, so getting them checked against Go first means the reflective
// layer can be built on something already known to be right rather than
// debugged as one piece.
//
// Deviations from marshal[go] @ Go 1.25.5:
//
//   * Go's `dst = append(dst, …)` grows and returns the slice. goish's
//     `slice<T>` has no in-place append, so each function takes and
//     returns `slice<byte>` — the same signature Go has — with a `Vec`
//     scratch buffer inside, converted at the return site (AGENTS.md §3).
//   * Go's `tagAndLength` is unexported; goish's is `TagAndLength`, public
//     because ParseTagAndLength already returns it.

#![allow(non_snake_case)]

extern crate alloc;

use super::{isNumeric, isPrintable, BitString, StructuralError, TagAndLength};
use crate::math::big::Int;
use crate::errors::{error, nil};
use crate::gostring::string;
use crate::goslice::slice;
use crate::types::byte;
use crate::int;
use crate::{byte as tobyte, int64, uint};
use alloc::vec::Vec;

// go: sdk 1.25.5 encoding/asn1/marshal.go:166-177 base128IntLength
/// The number of bytes `n` occupies in base-128 (7 bits per byte) form.
pub fn base128IntLength(n: int64) -> int {
    if n == 0 {
        return 1;
    }

    let mut l: int = 0;
    let mut i = n;
    while i > 0 {
        l += 1;
        i >>= 7;
    }

    return l;
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:179-193 appendBase128Int
/// Append `n` to `dst` in base-128 form, high bit set on every byte but
/// the last. Used for OID components and for tag numbers >= 31.
pub fn appendBase128Int(dst: slice<byte>, n: int64) -> slice<byte> {
    let l = base128IntLength(n);
    let mut out: Vec<byte> = dst.__into_vec();

    let mut i = l - 1;
    while i >= 0 {
        let mut o = tobyte(n >> uint(i * 7));
        o &= 0x7f;
        if i != 0 {
            o |= 0x80;
        }
        out.push(o);
        i -= 1;
    }

    return slice::__from_vec(out);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:239-246 lengthLength
/// The number of bytes the long-form length encoding of `i` occupies.
pub fn lengthLength(i: int) -> int {
    let mut numBytes: int = 1;
    let mut i = i;
    while i > 255 {
        numBytes += 1;
        i >>= 8;
    }
    return numBytes;
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:229-237 appendLength
/// Append `i` big-endian in exactly `lengthLength(i)` bytes.
pub fn appendLength(dst: slice<byte>, i: int) -> slice<byte> {
    let mut n = lengthLength(i);
    let mut out: Vec<byte> = dst.__into_vec();

    while n > 0 {
        out.push(tobyte(i >> uint((n - 1) * 8)));
        n -= 1;
    }

    return slice::__from_vec(out);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:248-271 appendTagAndLength
/// Append the identifier and length octets described by `t`.
pub fn appendTagAndLength(dst: slice<byte>, t: &TagAndLength) -> slice<byte> {
    let mut b: byte = tobyte(t.class) << 6;
    if t.isCompound {
        b |= 0x20;
    }
    let mut dst = dst;
    if t.tag >= 31 {
        b |= 0x1f;
        dst = push(dst, b);
        dst = appendBase128Int(dst, int64(t.tag));
    } else {
        b |= tobyte(t.tag);
        dst = push(dst, b);
    }

    if t.length >= 128 {
        let l = lengthLength(t.length);
        dst = push(dst, 0x80 | tobyte(l));
        dst = appendLength(dst, t.length);
    } else {
        dst = push(dst, tobyte(t.length));
    }

    return dst;
}

// go: none — goish idiom: Go writes `dst = append(dst, b)`; `slice<T>` has
// no in-place append, so the one-byte case gets a name.
fn push(dst: slice<byte>, b: byte) -> slice<byte> {
    let mut v: Vec<byte> = dst.__into_vec();
    v.push(b);
    return slice::__from_vec(v);
}

// ─── encoder — marshal.go:24-29 ───────────────────────────────────────

// go: none — goish idiom: Go's `encoder` is an unexported interface with
// Len and Encode. goish spells it as a trait; the concrete types below
// implement it exactly as Go's do.
/// Go: `type encoder interface { Len() int; Encode(dst []byte) }`.
pub trait encoder {
    /// The number of bytes needed to marshal this element.
    fn Len(&self) -> int;
    /// Encode this element by writing `Len()` bytes to `dst`.
    fn Encode(&self, dst: &mut slice<byte>);
}

// Go: marshal.go:31 — `type byteEncoder byte`
pub struct byteEncoder(pub byte);

impl encoder for byteEncoder {
    // go: sdk 1.25.5 encoding/asn1/marshal.go:33-35 byteEncoder.Len
    fn Len(&self) -> int {
        return 1;
    }

    // go: sdk 1.25.5 encoding/asn1/marshal.go:37-39 byteEncoder.Encode
    fn Encode(&self, dst: &mut slice<byte>) {
        let d: &mut [byte] = dst;
        d[0] = self.0;
    }
}

// Go: marshal.go:41 — `type bytesEncoder []byte`
pub struct bytesEncoder(pub slice<byte>);

impl encoder for bytesEncoder {
    // go: sdk 1.25.5 encoding/asn1/marshal.go:43-45 bytesEncoder.Len
    fn Len(&self) -> int {
        return self.0.Len();
    }

    // go: sdk 1.25.5 encoding/asn1/marshal.go:47-51 bytesEncoder.Encode
    fn Encode(&self, dst: &mut slice<byte>) {
        let src: &[byte] = &self.0;
        let d: &mut [byte] = dst;
        if d.len() < src.len() {
            panic!("internal error");
        }
        d[..src.len()].copy_from_slice(src);
    }
}

// Go: marshal.go:53 — `type stringEncoder string`
pub struct stringEncoder(pub string);

impl encoder for stringEncoder {
    // go: sdk 1.25.5 encoding/asn1/marshal.go:55-57 stringEncoder.Len
    fn Len(&self) -> int {
        return self.0.Len();
    }

    // go: sdk 1.25.5 encoding/asn1/marshal.go:59-63 stringEncoder.Encode
    fn Encode(&self, dst: &mut slice<byte>) {
        let src = self.0.as_bytes();
        let d: &mut [byte] = dst;
        if d.len() < src.len() {
            panic!("internal error");
        }
        d[..src.len()].copy_from_slice(src);
    }
}

// Go: marshal.go:140 — `type int64Encoder int64`
pub struct int64Encoder(pub int64);

impl encoder for int64Encoder {
    // go: sdk 1.25.5 encoding/asn1/marshal.go:142-156 int64Encoder.Len
    fn Len(&self) -> int {
        let mut n: int = 1;
        let mut i = self.0;

        while i > 127 {
            n += 1;
            i >>= 8;
        }

        while i < -128 {
            n += 1;
            i >>= 8;
        }

        return n;
    }

    // go: sdk 1.25.5 encoding/asn1/marshal.go:158-164 int64Encoder.Encode
    fn Encode(&self, dst: &mut slice<byte>) {
        let n = self.Len();
        let d: &mut [byte] = dst;

        let mut j: int = 0;
        while j < n {
            d[j as usize] = tobyte(self.0 >> uint((n - 1 - j) * 8));
            j += 1;
        }
    }
}

// Go: marshal.go:273 — `type bitStringEncoder BitString`
pub struct bitStringEncoder(pub BitString);

impl encoder for bitStringEncoder {
    // go: sdk 1.25.5 encoding/asn1/marshal.go:275-277 bitStringEncoder.Len
    fn Len(&self) -> int {
        return self.0.Bytes.Len() + 1;
    }

    // go: sdk 1.25.5 encoding/asn1/marshal.go:279-284 bitStringEncoder.Encode
    fn Encode(&self, dst: &mut slice<byte>) {
        let src: &[byte] = &self.0.Bytes;
        let pad = tobyte((8 - self.0.BitLength % 8) % 8);
        let d: &mut [byte] = dst;
        d[0] = pad;
        if d.len() - 1 < src.len() {
            panic!("internal error");
        }
        d[1..1 + src.len()].copy_from_slice(src);
    }
}

// Go: marshal.go:286 — `type oidEncoder []int`
pub struct oidEncoder(pub slice<int>);

impl encoder for oidEncoder {
    // go: sdk 1.25.5 encoding/asn1/marshal.go:288-294 oidEncoder.Len
    fn Len(&self) -> int {
        let oid = &self.0;
        let mut l = base128IntLength(int64(oid[0] * 40 + oid[1]));
        let mut i: int = 2;
        while i < oid.Len() {
            l += base128IntLength(int64(oid[i]));
            i += 1;
        }
        return l;
    }

    // go: sdk 1.25.5 encoding/asn1/marshal.go:296-301 oidEncoder.Encode
    //
    // Go writes through `dst[:0]`, reusing the caller's backing array.
    // goish builds the run and copies it in, which is the same bytes.
    fn Encode(&self, dst: &mut slice<byte>) {
        let oid = &self.0;
        let mut out = slice::__from_vec(Vec::<byte>::new());
        out = appendBase128Int(out, int64(oid[0] * 40 + oid[1]));
        let mut i: int = 2;
        while i < oid.Len() {
            out = appendBase128Int(out, int64(oid[i]));
            i += 1;
        }
        let src: &[byte] = &out;
        let d: &mut [byte] = dst;
        d[..src.len()].copy_from_slice(src);
    }
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:303-309 makeObjectIdentifier
pub fn makeObjectIdentifier(oid: slice<int>) -> (oidEncoder, error) {
    if oid.Len() < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
        return (
            oidEncoder(slice::__from_vec(alloc::vec::Vec::new())),
            StructuralError {
                Msg: string::from_static("invalid object identifier"),
            }
            .into(),
        );
    }

    return (oidEncoder(oid), nil);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:311-325 makePrintableString
pub fn makePrintableString<S: Into<string>>(s: S) -> (stringEncoder, error) {
    let s = s.into();
    // The asterisk is often used in PrintableString, even though it is
    // invalid. If a PrintableString was specifically requested then the
    // asterisk is permitted by this code. Ampersand is allowed in parsing
    // due a handful of CA certificates, however when making new
    // certificates it is rejected.
    for b in s.as_bytes().iter() {
        // Go: isPrintable(s[i], allowAsterisk, rejectAmpersand). Those
        // two constants live in asn1.go, which goish's asn1 mod.rs ports
        // with the literals; spelled the same way here.
        if !isPrintable(*b, true, false) {
            return (
                stringEncoder(string::default()),
                StructuralError {
                    Msg: string::from_static("PrintableString contains invalid character"),
                }
                .into(),
            );
        }
    }

    return (stringEncoder(s), nil);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:327-335 makeIA5String
pub fn makeIA5String<S: Into<string>>(s: S) -> (stringEncoder, error) {
    let s = s.into();
    for b in s.as_bytes().iter() {
        if *b > 127 {
            return (
                stringEncoder(string::default()),
                StructuralError {
                    Msg: string::from_static("IA5String contains invalid character"),
                }
                .into(),
            );
        }
    }

    return (stringEncoder(s), nil);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:337-345 makeNumericString
pub fn makeNumericString<S: Into<string>>(s: S) -> (stringEncoder, error) {
    let s = s.into();
    for b in s.as_bytes().iter() {
        if !isNumeric(*b) {
            return (
                stringEncoder(string::default()),
                StructuralError {
                    Msg: string::from_static("NumericString contains invalid character"),
                }
                .into(),
            );
        }
    }

    return (stringEncoder(s), nil);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:347-349 makeUTF8String
pub fn makeUTF8String<S: Into<string>>(s: S) -> stringEncoder {
    return stringEncoder(s.into());
}

// ─── composite encoders — marshal.go:65-138 ───────────────────────────
//
// These three are the only place goish's asn1 marshal needs trait
// objects: Go's `multiEncoder` and `setEncoder` are `[]encoder`, and
// `taggedEncoder` holds two `encoder` fields. All three are unexported in
// Go, so `Box<dyn encoder>` here does not put a Rust trait object in any
// public Go-API struct (AGENTS.md §5 rule 3 targets the public surface).

// Go: marshal.go:65 — `type multiEncoder []encoder`
pub struct multiEncoder(Vec<alloc::boxed::Box<dyn encoder>>);

impl multiEncoder {
    // go: none — goish idiom: Go writes the conversion
    // `multiEncoder([]encoder{…})`; goish needs a constructor.
    pub fn New(v: slice<alloc::boxed::Box<dyn encoder>>) -> Self {
        return multiEncoder(v.__into_vec());
    }
}

impl encoder for multiEncoder {
    // go: sdk 1.25.5 encoding/asn1/marshal.go:67-73 multiEncoder.Len
    fn Len(&self) -> int {
        let mut size: int = 0;
        for e in self.0.iter() {
            size += e.Len();
        }
        return size;
    }

    // go: sdk 1.25.5 encoding/asn1/marshal.go:75-81 multiEncoder.Encode
    fn Encode(&self, dst: &mut slice<byte>) {
        let mut off: int = 0;
        for e in self.0.iter() {
            // Go: e.Encode(dst[off:]) — a window onto the caller's array.
            // goish encodes into a scratch run and copies it into place,
            // because `slice<T>` handles do not share a backing store.
            let n = e.Len();
            let mut win = slice::__from_vec(alloc::vec![0u8; n as usize]);
            e.Encode(&mut win);
            let src: &[byte] = &win;
            let d: &mut [byte] = dst;
            d[off as usize..(off + n) as usize].copy_from_slice(src);
            off += n;
        }
    }
}

// Go: marshal.go:83 — `type setEncoder []encoder`
pub struct setEncoder(Vec<alloc::boxed::Box<dyn encoder>>);

impl setEncoder {
    // go: none — goish idiom: see multiEncoder::New.
    pub fn New(v: slice<alloc::boxed::Box<dyn encoder>>) -> Self {
        return setEncoder(v.__into_vec());
    }
}

impl encoder for setEncoder {
    // go: sdk 1.25.5 encoding/asn1/marshal.go:85-91 setEncoder.Len
    fn Len(&self) -> int {
        let mut size: int = 0;
        for e in self.0.iter() {
            size += e.Len();
        }
        return size;
    }

    // go: sdk 1.25.5 encoding/asn1/marshal.go:93-121 setEncoder.Encode
    //
    // Per X690 Section 11.6: the encodings of the component values of a
    // set-of value shall appear in ascending order, the encodings being
    // compared as octet strings with the shorter components being padded
    // at their trailing end with 0-octets.
    //
    // Go's own note applies unchanged: because the comparison is over TLV
    // encodings, the padding step can be skipped — if one encoding is
    // shorter its length octet, the first determining byte, is inherently
    // smaller.
    //
    // Deviation: Go sorts with `slices.SortFunc`, which is unstable.
    // goish sorts with Rust's stable `sort_by`; that is a strictly
    // stronger guarantee and cannot change the byte output.
    fn Encode(&self, dst: &mut slice<byte>) {
        let mut l: Vec<slice<byte>> = Vec::with_capacity(self.0.len());
        for e in self.0.iter() {
            let mut b = slice::__from_vec(alloc::vec![0u8; e.Len() as usize]);
            e.Encode(&mut b);
            l.push(b);
        }

        l.sort_by(|a, b| {
            let c = crate::bytes::Compare(a.clone(), b.clone());
            return c.cmp(&0);
        });

        let mut off: int = 0;
        for b in l.iter() {
            let src: &[byte] = b;
            let d: &mut [byte] = dst;
            d[off as usize..off as usize + src.len()].copy_from_slice(src);
            off += int(src.len());
        }
    }
}

// Go: marshal.go:123-129
//   type taggedEncoder struct { scratch [8]byte; tag encoder; body encoder }
pub struct taggedEncoder {
    /// Go: temporary space for encoding the tag and length of an element
    /// in order to avoid extra allocations. Unread until makeField lands,
    /// but kept so the struct matches Go's layout (AGENTS.md §5).
    #[allow(dead_code)]
    scratch: [byte; 8],
    tag: alloc::boxed::Box<dyn encoder>,
    body: alloc::boxed::Box<dyn encoder>,
}

impl taggedEncoder {
    // go: none — goish idiom: Go builds it as a struct literal from
    // inside the package; the fields are private here.
    pub fn New(
        tag: alloc::boxed::Box<dyn encoder>,
        body: alloc::boxed::Box<dyn encoder>,
    ) -> Self {
        return taggedEncoder {
            scratch: [0u8; 8],
            tag,
            body,
        };
    }
}

impl encoder for taggedEncoder {
    // go: sdk 1.25.5 encoding/asn1/marshal.go:131-133 taggedEncoder.Len
    fn Len(&self) -> int {
        return self.tag.Len() + self.body.Len();
    }

    // go: sdk 1.25.5 encoding/asn1/marshal.go:135-138 taggedEncoder.Encode
    fn Encode(&self, dst: &mut slice<byte>) {
        // Go: t.tag.Encode(dst); t.body.Encode(dst[t.tag.Len():]).
        let tn = self.tag.Len();
        let bn = self.body.Len();

        let mut tbuf = slice::__from_vec(alloc::vec![0u8; tn as usize]);
        self.tag.Encode(&mut tbuf);
        let mut bbuf = slice::__from_vec(alloc::vec![0u8; bn as usize]);
        self.body.Encode(&mut bbuf);

        let (ts, bs): (&[byte], &[byte]) = (&tbuf, &bbuf);
        let d: &mut [byte] = dst;
        d[..tn as usize].copy_from_slice(ts);
        d[tn as usize..(tn + bn) as usize].copy_from_slice(bs);
    }
}

// ─── makeBigInt / stripTagAndLength ───────────────────────────────────

// go: none — goish idiom: Go declares these at marshal.go:19-20 as
// package-level `encoder` vars —
//   byte00Encoder encoder = byteEncoder(0x00)
//   byteFFEncoder encoder = byteEncoder(0xff)
// — and a trait object cannot be a `const`, so they are constructors.
fn byte00Encoder() -> alloc::boxed::Box<dyn encoder> {
    return alloc::boxed::Box::new(byteEncoder(0x00));
}

// go: none — goish idiom: see byte00Encoder.
fn byteFFEncoder() -> alloc::boxed::Box<dyn encoder> {
    return alloc::boxed::Box::new(byteEncoder(0xff));
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:195-227 makeBigInt
/// Encode a `big::Int` as a DER INTEGER body.
///
/// Deviation: Go takes `*big.Int` and opens with
/// `if n == nil { return StructuralError{"empty integer"} }` — a guard on
/// a nil *pointer*. goish's `Int` is a value type with no nil, so that
/// branch is unreachable and is not ported.
///
/// It must not be translated as `if *n == nil`: goish's
/// `PartialEq<Nil> for Int` is true for **zero**, so that spelling
/// rejects a legitimate `0` — which Go encodes as the single byte 0x00.
/// The first version of this function did exactly that, and the Go
/// reference row for "0" is what caught it.
pub fn makeBigInt(n: &Int) -> (alloc::boxed::Box<dyn encoder>, error) {
    if n.Sign() < 0 {
        // A negative number has to be converted to two's-complement form.
        // So we'll invert and subtract 1. If the most-significant-bit
        // isn't set then we'll need to pad the beginning with 0xff in
        // order to keep the number negative.
        let mut nMinus1 = Int::default();
        nMinus1.Neg(n);
        let one = crate::math::big::NewInt(1);
        let cur = nMinus1.clone();
        nMinus1.Sub(&cur, &one);
        let mut bytes = nMinus1.Bytes().__into_vec();
        for b in bytes.iter_mut() {
            *b ^= 0xff;
        }
        if bytes.is_empty() || bytes[0] & 0x80 == 0 {
            return (
                alloc::boxed::Box::new(multiEncoder::New(slice::__from_vec(alloc::vec![
                    byteFFEncoder(),
                    alloc::boxed::Box::new(bytesEncoder(slice::__from_vec(bytes)))
                        as alloc::boxed::Box<dyn encoder>,
                ]))),
                nil,
            );
        }
        return (
            alloc::boxed::Box::new(bytesEncoder(slice::__from_vec(bytes))),
            nil,
        );
    }
    if n.Sign() == 0 {
        // Zero is written as a single 0 zero rather than no bytes.
        return (byte00Encoder(), nil);
    }
    let bytes = n.Bytes().__into_vec();
    if !bytes.is_empty() && bytes[0] & 0x80 != 0 {
        // We'll have to pad this with 0x00 in order to stop it looking
        // like a negative number.
        return (
            alloc::boxed::Box::new(multiEncoder::New(slice::__from_vec(alloc::vec![
                byte00Encoder(),
                alloc::boxed::Box::new(bytesEncoder(slice::__from_vec(bytes)))
                    as alloc::boxed::Box<dyn encoder>,
            ]))),
            nil,
        );
    }
    return (
        alloc::boxed::Box::new(bytesEncoder(slice::__from_vec(bytes))),
        nil,
    );
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:659-665 stripTagAndLength
/// Drop the leading tag and length octets, returning the body. If the
/// input does not parse, it is returned unchanged.
pub fn stripTagAndLength(in_: slice<byte>) -> slice<byte> {
    let (_, offset, err) = super::ParseTagAndLength(in_.clone(), 0);
    if err != nil {
        return in_;
    }
    let raw: &[byte] = &in_;
    return slice::__from_vec(raw[offset as usize..].to_vec());
}
