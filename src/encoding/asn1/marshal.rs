// go: file encoding/asn1/marshal.go decls: base128IntLength, appendBase128Int, appendLength, lengthLength, appendTagAndLength, makeObjectIdentifier, makePrintableString, makeIA5String, makeNumericString, makeUTF8String, makeBigInt, stripTagAndLength, appendTwoDigits, appendFourDigits, outsideUTCRange, makeUTCTime, makeGeneralizedTime, appendUTCTime, appendGeneralizedTime, appendTimeCommon, makeBody, makeField, Marshal, MarshalWithParams
//
// The DER *encoding* side of encoding/asn1 — all of marshal.go.
//
// It was built in two passes, and the seam is still the useful way to
// read it. Everything down to `appendTimeCommon` is non-reflective: given
// a value whose type the caller already knows, lay down the bytes. Those
// landed first and were checked against Go on their own, so that the
// reflective layer on top of them — `makeBody`, `makeField`, `Marshal`,
// `MarshalWithParams` — could be built on a foundation already known to
// be right rather than debugged as one piece.
//
// Why any of it matters: `crypto/x509/pkix` — and behind it
// `crypto/x509` and `crypto/tls`, ~415 functions — is gated on
// `asn1.Marshal`, and pkix calls it exactly once, in
// `RDNSequence.String()`. Stubbing that call to error would still
// compile and still "work", while silently printing `oid=value` where Go
// prints `oid=#hex` for every unrecognised OID. That is why this is a
// real port and not a stub.
//
// Deviations from marshal[go] @ Go 1.25.5:
//
//   * Go's `dst = append(dst, …)` grows and returns the slice. goish's
//     `slice<T>` has no in-place append, so each function takes and
//     returns `slice<byte>` — the same signature Go has — with a `Vec`
//     scratch buffer inside, converted at the return site (AGENTS.md §3).
//   * Go's `tagAndLength` is unexported; goish's is `TagAndLength`, public
//     because ParseTagAndLength already returns it.
//   * Go's single `Marshal(val any)` is two functions here: `Marshal`
//     for a statically known `impl Reflect`, and `MarshalAny` for
//     goish's erased `interface{}` carrier. `Reflect` is not object
//     safe, so one signature cannot serve both. See the note above
//     `MarshalAny`.

#![allow(non_snake_case)]

extern crate alloc;

use super::{isNumeric, isPrintable, BitString, StructuralError, TagAndLength};
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::int;
use crate::math::big::Int;
use crate::types::byte;
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
    pub fn New(tag: alloc::boxed::Box<dyn encoder>, body: alloc::boxed::Box<dyn encoder>) -> Self {
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

// go: sdk 1.25.5 encoding/asn1/marshal.go:450-456 stripTagAndLength
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

// ─── time encoding — marshal.go:351-437 ───────────────────────────────

// go: sdk 1.25.5 encoding/asn1/marshal.go:351-353 appendTwoDigits
fn appendTwoDigits(dst: slice<byte>, v: int) -> slice<byte> {
    let mut out: Vec<byte> = dst.__into_vec();
    out.push(tobyte(int(b'0') + (v / 10) % 10));
    out.push(tobyte(int(b'0') + v % 10));
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:355-361 appendFourDigits
fn appendFourDigits(dst: slice<byte>, v: int) -> slice<byte> {
    let mut out: Vec<byte> = dst.__into_vec();
    out.push(tobyte(int(b'0') + (v / 1000) % 10));
    out.push(tobyte(int(b'0') + (v / 100) % 10));
    out.push(tobyte(int(b'0') + (v / 10) % 10));
    out.push(tobyte(int(b'0') + v % 10));
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:363-366 outsideUTCRange
pub fn outsideUTCRange(t: crate::time::Time) -> bool {
    let year = t.Year();
    return year < 1950 || year >= 2050;
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:368-376 makeUTCTime
pub fn makeUTCTime(t: crate::time::Time) -> (alloc::boxed::Box<dyn encoder>, error) {
    // Go: dst := make([]byte, 0, 18)
    let dst = slice::__from_vec(Vec::<byte>::with_capacity(18));

    let (dst, err) = appendUTCTime(dst, t);
    if err != nil {
        return (
            alloc::boxed::Box::new(bytesEncoder(slice::__from_vec(Vec::<byte>::new()))),
            err,
        );
    }

    return (alloc::boxed::Box::new(bytesEncoder(dst)), nil);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:379-388 makeGeneralizedTime
pub fn makeGeneralizedTime(t: crate::time::Time) -> (alloc::boxed::Box<dyn encoder>, error) {
    // Go: dst := make([]byte, 0, 20)
    let dst = slice::__from_vec(Vec::<byte>::with_capacity(20));

    let (dst, err) = appendGeneralizedTime(dst, t);
    if err != nil {
        return (
            alloc::boxed::Box::new(bytesEncoder(slice::__from_vec(Vec::<byte>::new()))),
            err,
        );
    }

    return (alloc::boxed::Box::new(bytesEncoder(dst)), nil);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:390-403 appendUTCTime
fn appendUTCTime(dst: slice<byte>, t: crate::time::Time) -> (slice<byte>, error) {
    let year = t.Year();

    let dst = if 1950 <= year && year < 2000 {
        appendTwoDigits(dst, year - 1900)
    } else if 2000 <= year && year < 2050 {
        appendTwoDigits(dst, year - 2000)
    } else {
        return (
            slice::__from_vec(Vec::<byte>::new()),
            StructuralError {
                Msg: string::from_static("cannot represent time as UTCTime"),
            }
            .into(),
        );
    };

    return (appendTimeCommon(dst, t), nil);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:405-414 appendGeneralizedTime
fn appendGeneralizedTime(dst: slice<byte>, t: crate::time::Time) -> (slice<byte>, error) {
    let year = t.Year();
    if year < 0 || year > 9999 {
        return (
            slice::__from_vec(Vec::<byte>::new()),
            StructuralError {
                Msg: string::from_static("cannot represent time as GeneralizedTime"),
            }
            .into(),
        );
    }

    let dst = appendFourDigits(dst, year);

    return (appendTimeCommon(dst, t), nil);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:416-448 appendTimeCommon
//
// Deviation, in reachability rather than code: goish's `time` is UTC-only
// — `Time::Zone()` returns ("UTC", 0) unconditionally and `time::Date`
// ignores its Location argument — so `offset` is always 0 and every
// encoded time ends in 'Z'. The '+'/'-' branches and the offset digits
// are ported as written and are correct, but cannot be exercised until
// goish's time grows zones. The Go reference rows for +0100, -0500 and
// +0130 are recorded in the smoke test's comment for when it can.
fn appendTimeCommon(dst: slice<byte>, t: crate::time::Time) -> slice<byte> {
    let (_, month, day) = t.Date();

    let dst = appendTwoDigits(dst, month);
    let dst = appendTwoDigits(dst, day);

    let (hour, min, sec) = t.Clock();

    let dst = appendTwoDigits(dst, hour);
    let dst = appendTwoDigits(dst, min);
    let mut dst = appendTwoDigits(dst, sec);

    let (_, offset) = t.Zone();

    if offset / 60 == 0 {
        let mut out: Vec<byte> = dst.__into_vec();
        out.push(b'Z');
        return slice::__from_vec(out);
    }
    if offset > 0 {
        let mut out: Vec<byte> = dst.__into_vec();
        out.push(b'+');
        dst = slice::__from_vec(out);
    } else if offset < 0 {
        let mut out: Vec<byte> = dst.__into_vec();
        out.push(b'-');
        dst = slice::__from_vec(out);
    }

    let mut offsetMinutes = offset / 60;
    if offsetMinutes < 0 {
        offsetMinutes = -offsetMinutes;
    }

    let dst = appendTwoDigits(dst, offsetMinutes / 60);
    let dst = appendTwoDigits(dst, offsetMinutes % 60);

    return dst;
}

// ─── makeBody / makeField / Marshal (marshal.go:458) ──────────────────
//
// The reflection-driven half. Everything above this line encodes a value
// whose type the caller already knows; these four walk a `reflect::Value`
// and decide what the value *is*.
//
// Two deviations run through all of them, both forced and both worth
// stating once rather than at every site.
//
//   * **`value.Interface().(T)` is not available.** Go re-extracts the
//     original typed value out of the reflected one five times — a
//     `time.Time`, a `BitString`, an `ObjectIdentifier`, a `*big.Int`, a
//     `RawValue`. goish's `reflect::Value::Interface()` boxes `()` for
//     every composite variant, so there is nothing to downcast. Each of
//     those five types instead carries its state in the `Value` itself
//     (`Struct { fields }` / `Slice { items }`), and the arms below read
//     the operands straight off it. The reconstruction for each is
//     pinned by examples/reflect_setint_smoke.rs.
//
//   * **`Marshal(val any)` becomes `Marshal(val: &impl Reflect)`.** Rust
//     has no universal runtime reflection: a value has to opt in by
//     implementing `reflect::Reflect`. Go's `reflect.ValueOf(val)` is
//     therefore `val.__reflect_value()`, and a type that has not opted
//     in fails at compile time rather than with Go's runtime
//     "unknown Go type".
//
// Type identity is matched by reflected *name*, since goish's
// `reflect::Type` compares on `(kind, name)` — see getUniversalType in
// common.rs, which does the same and for the same reason.

// go: none — goish idiom: Go compares `value.Type()` against the
// package-level `reflect.TypeFor[T]()` vars (asn1.go:690-697). goish's
// Type has no such identity, so the six are matched by name.
fn typeNameIs(v: &crate::reflect::Value, name: &str) -> bool {
    return v.Type().Name().as_bytes() == name.as_bytes();
}

// go: none — goish idiom: pull the i'th field out of a reflected struct
// without going through `Interface()`. See the banner above.
fn field(v: &crate::reflect::Value, i: int) -> crate::reflect::Value {
    return v.Field(i);
}

// go: none — goish idiom: rebuild a `time::Time` from the reflected
// form `time::Time::__reflect_value` produces — `[Int(Unix),
// Int(Nanosecond)]`. See the banner above.
fn timeFromValue(v: &crate::reflect::Value) -> crate::time::Time {
    let sec = field(v, 0).Int();
    let nsec = field(v, 1).Int();
    return crate::time::Unix(sec, nsec).UTC();
}

// go: none — goish idiom: rebuild a `BitString` from `[Bytes,
// Int(BitLength)]`. See the banner above.
fn bitStringFromValue(v: &crate::reflect::Value) -> BitString {
    return BitString {
        Bytes: field(v, 0).Bytes(),
        BitLength: field(v, 1).Int(),
    };
}

// go: none — goish idiom: rebuild an `ObjectIdentifier` from the
// reflected `Slice { items }`. See the banner above.
fn oidFromValue(v: &crate::reflect::Value) -> slice<int> {
    let mut out: Vec<int> = Vec::new();
    let n = v.Len();
    let mut i: int = 0;
    while i < n {
        out.push(v.Index(i).Int());
        i += 1;
    }
    return slice::__from_vec(out);
}

// go: none — goish idiom: rebuild a `big::Int` from `[Int(Sign),
// Bytes]`. See the banner above.
fn bigIntFromValue(v: &crate::reflect::Value) -> Int {
    let sign = field(v, 0).Int();
    let mag = field(v, 1).Bytes();
    let mut n = Int::default();
    n.SetBytes(mag);
    if sign < 0 {
        let m = n.clone();
        n.Neg(&m);
    }
    return n;
}

// go: none — goish idiom: rebuild a `RawValue` from its five reflected
// fields. See the banner above.
fn rawValueFromValue(v: &crate::reflect::Value) -> super::RawValue {
    return super::RawValue {
        Class: field(v, 0).Int(),
        Tag: field(v, 1).Int(),
        IsCompound: field(v, 2).Bool(),
        Bytes: field(v, 3).Bytes(),
        FullBytes: field(v, 4).Bytes(),
    };
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:458-574 makeBody
/// Build the encoder for an element's *contents* — everything inside the
/// tag and length, which [`makeField`] wraps around it.
pub fn makeBody(
    value: &crate::reflect::Value,
    params: &super::fieldParameters,
) -> (Option<alloc::boxed::Box<dyn encoder>>, error) {
    use crate::reflect::Kind;

    // Go: switch value.Type() { case flagType: … case bigIntType: … }
    if typeNameIs(value, "Flag") {
        return (
            Some(alloc::boxed::Box::new(bytesEncoder(slice::default()))),
            nil,
        );
    }
    if typeNameIs(value, "time.Time") {
        let t = timeFromValue(value);
        if params.timeType == super::TagGeneralizedTime || outsideUTCRange(t.clone()) {
            let (e, err) = makeGeneralizedTime(t);
            return (Some(e), err);
        }
        let (e, err) = makeUTCTime(t);
        return (Some(e), err);
    }
    if typeNameIs(value, "BitString") {
        return (
            Some(alloc::boxed::Box::new(bitStringEncoder(
                bitStringFromValue(value),
            ))),
            nil,
        );
    }
    if typeNameIs(value, "ObjectIdentifier") {
        let (e, err) = makeObjectIdentifier(oidFromValue(value));
        if err != nil {
            return (None, err);
        }
        return (Some(alloc::boxed::Box::new(e)), nil);
    }
    if typeNameIs(value, "Int") && value.Kind() == Kind::Struct {
        let n = bigIntFromValue(value);
        let (e, err) = makeBigInt(&n);
        if err != nil {
            return (None, err);
        }
        return (Some(e), nil);
    }

    // Go: switch v := value; v.Kind() { … }
    match value.Kind() {
        Kind::Bool => {
            if value.Bool() {
                return (Some(byteFFEncoder()), nil);
            }
            return (Some(byte00Encoder()), nil);
        }
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
            return (
                Some(alloc::boxed::Box::new(int64Encoder(int64(value.Int())))),
                nil,
            );
        }
        Kind::Struct => {
            let t = value.Type();

            // Go: for i := 0; i < t.NumField(); i++ { if !t.Field(i).IsExported() … }
            let nf = t.NumField();
            let mut i: int = 0;
            while i < nf {
                if !t.Field(i).PkgPath.is_empty() {
                    return (
                        None,
                        StructuralError {
                            Msg: string::from_static("struct contains unexported fields"),
                        }
                        .into(),
                    );
                }
                i += 1;
            }

            let mut startingField: int = 0;

            let n = t.NumField();
            if n == 0 {
                return (
                    Some(alloc::boxed::Box::new(bytesEncoder(slice::default()))),
                    nil,
                );
            }

            // Go: if t.Field(0).Type == rawContentsType { … }
            //
            // The RawContent carries the tag and length fields, and we
            // write those ourselves, so they are stripped back out.
            if (t.Field(0).Type)().Name().as_bytes() == b"RawContent" {
                let s = value.Field(0);
                if s.Len() > 0 {
                    let bytes = s.Bytes();
                    return (
                        Some(alloc::boxed::Box::new(bytesEncoder(stripTagAndLength(
                            bytes,
                        )))),
                        nil,
                    );
                }
                startingField = 1;
            }

            let n1 = n - startingField;
            if n1 == 0 {
                return (
                    Some(alloc::boxed::Box::new(bytesEncoder(slice::default()))),
                    nil,
                );
            }
            if n1 == 1 {
                let f = t.Field(startingField);
                return makeField(
                    &value.Field(startingField),
                    &super::parseFieldParameters(f.Tag.Get("asn1")),
                );
            }
            let mut m: Vec<alloc::boxed::Box<dyn encoder>> = Vec::new();
            let mut i: int = 0;
            while i < n1 {
                let f = t.Field(i + startingField);
                let (e, err) = makeField(
                    &value.Field(i + startingField),
                    &super::parseFieldParameters(f.Tag.Get("asn1")),
                );
                if err != nil {
                    return (None, err);
                }
                m.push(e.unwrap());
                i += 1;
            }
            return (
                Some(alloc::boxed::Box::new(multiEncoder::New(
                    slice::__from_vec(m),
                ))),
                nil,
            );
        }
        Kind::Slice => {
            let sliceType = value.Type();
            if sliceType.Elem().Kind() == Kind::Uint8 {
                return (
                    Some(alloc::boxed::Box::new(bytesEncoder(value.Bytes()))),
                    nil,
                );
            }

            let fp = super::fieldParameters::default();

            let l = value.Len();
            if l == 0 {
                return (
                    Some(alloc::boxed::Box::new(bytesEncoder(slice::default()))),
                    nil,
                );
            }
            if l == 1 {
                return makeField(&value.Index(0), &fp);
            }
            let mut m: Vec<alloc::boxed::Box<dyn encoder>> = Vec::new();
            let mut i: int = 0;
            while i < l {
                let (e, err) = makeField(&value.Index(i), &fp);
                if err != nil {
                    return (None, err);
                }
                m.push(e.unwrap());
                i += 1;
            }
            if params.set {
                return (
                    Some(alloc::boxed::Box::new(setEncoder::New(slice::__from_vec(
                        m,
                    )))),
                    nil,
                );
            }
            return (
                Some(alloc::boxed::Box::new(multiEncoder::New(
                    slice::__from_vec(m),
                ))),
                nil,
            );
        }
        Kind::String => {
            if params.stringType == super::TagIA5String {
                let (e, err) = makeIA5String(value.String());
                if err != nil {
                    return (None, err);
                }
                return (Some(alloc::boxed::Box::new(e)), nil);
            }
            if params.stringType == super::TagPrintableString {
                let (e, err) = makePrintableString(value.String());
                if err != nil {
                    return (None, err);
                }
                return (Some(alloc::boxed::Box::new(e)), nil);
            }
            if params.stringType == super::TagNumericString {
                let (e, err) = makeNumericString(value.String());
                if err != nil {
                    return (None, err);
                }
                return (Some(alloc::boxed::Box::new(e)), nil);
            }
            return (
                Some(alloc::boxed::Box::new(makeUTF8String(value.String()))),
                nil,
            );
        }
        _ => {}
    }

    return (
        None,
        StructuralError {
            Msg: string::from_static("unknown Go type"),
        }
        .into(),
    );
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:576-716 makeField
/// Build the encoder for a complete element — [`makeBody`]'s contents
/// wrapped in the tag and length its `fieldParameters` call for.
pub fn makeField(
    v: &crate::reflect::Value,
    params: &super::fieldParameters,
) -> (Option<alloc::boxed::Box<dyn encoder>>, error) {
    use crate::reflect::Kind;

    if !v.IsValid() {
        return (None, crate::errors::New("asn1: cannot marshal nil value"));
    }
    // Go: if v.Kind() == reflect.Interface && v.Type().NumMethod() == 0 {
    //         return makeField(v.Elem(), params) }
    //
    // goish has no reflected interface kind — a value reaching here is
    // always concrete. `Marshal` takes `&impl Reflect`, and `MarshalAny`
    // resolves the erased carrier to its *dynamic* value up front via
    // `reflect::ValueOfAny` (which is what this Go branch does, one
    // frame earlier). The recursion has nothing left to unwrap.

    if v.Kind() == Kind::Slice && v.Len() == 0 && params.omitEmpty {
        return (
            Some(alloc::boxed::Box::new(bytesEncoder(slice::default()))),
            nil,
        );
    }

    if params.optional && params.defaultValue.is_some() && super::canHaveDefaultValue(v.Kind()) {
        let mut defaultValue = crate::reflect::New(v.Type()).Elem();
        defaultValue.SetInt(params.defaultValue.unwrap());

        // Go: reflect.DeepEqual(v.Interface(), defaultValue.Interface()).
        // `Interface()` cannot round-trip here (see the banner), so the
        // reflected values are compared directly — which is what
        // `PartialEq for Value` exists for.
        if *v == defaultValue {
            return (
                Some(alloc::boxed::Box::new(bytesEncoder(slice::default()))),
                nil,
            );
        }
    }

    // If no default value is given then the zero value for the type is
    // assumed to be the default value. This isn't obviously the correct
    // behavior, but it's what Go has traditionally done.
    if params.optional && params.defaultValue.is_none() {
        // Go: reflect.DeepEqual(v.Interface(), reflect.Zero(v.Type()).Interface())
        if *v == crate::reflect::Zero(v.Type()) {
            return (
                Some(alloc::boxed::Box::new(bytesEncoder(slice::default()))),
                nil,
            );
        }
    }

    if typeNameIs(v, "RawValue") {
        let rv = rawValueFromValue(v);
        if rv.FullBytes.Len() != 0 {
            return (
                Some(alloc::boxed::Box::new(bytesEncoder(rv.FullBytes))),
                nil,
            );
        }

        let tag = bytesEncoder(appendTagAndLength(
            slice::default(),
            &TagAndLength {
                class: rv.Class,
                tag: rv.Tag,
                length: rv.Bytes.Len(),
                isCompound: rv.IsCompound,
            },
        ));
        let body = bytesEncoder(rv.Bytes);

        return (
            Some(alloc::boxed::Box::new(taggedEncoder::New(
                alloc::boxed::Box::new(tag),
                alloc::boxed::Box::new(body),
            ))),
            nil,
        );
    }

    let (matchAny, mut tag, isCompound, ok) = super::getUniversalType(&v.Type());
    if !ok || matchAny {
        return (
            None,
            StructuralError {
                Msg: string::from_static("unknown Go type"),
            }
            .into(),
        );
    }

    if params.timeType != 0 && tag != super::TagUTCTime {
        return (
            None,
            StructuralError {
                Msg: string::from_static("explicit time type given to non-time member"),
            }
            .into(),
        );
    }

    if params.stringType != 0 && tag != super::TagPrintableString {
        return (
            None,
            StructuralError {
                Msg: string::from_static("explicit string type given to non-string member"),
            }
            .into(),
        );
    }

    if tag == super::TagPrintableString {
        if params.stringType == 0 {
            // A string with no explicit string type: PrintableString if
            // the character set is limited enough, else UTF8String.
            let s = v.String();
            for (_, r) in crate::range!(s.clone()) {
                if crate::uint32(r) >= crate::uint32(crate::unicode::utf8::RuneSelf)
                    || !isPrintable(tobyte(r), false, false)
                {
                    if !crate::unicode::utf8::ValidString(s.clone()) {
                        return (None, crate::errors::New("asn1: string not valid UTF-8"));
                    }
                    tag = super::TagUTF8String;
                    break;
                }
            }
        } else {
            tag = params.stringType;
        }
    } else if tag == super::TagUTCTime {
        if params.timeType == super::TagGeneralizedTime || outsideUTCRange(timeFromValue(v)) {
            tag = super::TagGeneralizedTime;
        }
    }

    let mut params = params.clone();
    if params.set {
        if tag != super::TagSequence {
            return (
                None,
                StructuralError {
                    Msg: string::from_static("non sequence tagged as set"),
                }
                .into(),
            );
        }
        tag = super::TagSet;
    }

    // makeField can be called for a slice that should be treated as a
    // SET but doesn't have params.set set, for instance when using a
    // slice with the SET type name suffix. In this case getUniversalType
    // returns TagSet, but makeBody doesn't know about that so will treat
    // the slice as a sequence. To work around this we set params.set.
    if tag == super::TagSet && !params.set {
        params.set = true;
    }

    let (body, err) = makeBody(v, &params);
    if err != nil {
        return (None, err);
    }
    let body = body.unwrap();

    let bodyLen = body.Len();

    let mut class = super::ClassUniversal;
    if params.tag.is_some() {
        if params.application {
            class = super::ClassApplication;
        } else if params.private {
            class = super::ClassPrivate;
        } else {
            class = super::ClassContextSpecific;
        }

        if params.explicit {
            let innerTag = bytesEncoder(appendTagAndLength(
                slice::default(),
                &TagAndLength {
                    class: super::ClassUniversal,
                    tag,
                    length: bodyLen,
                    isCompound,
                },
            ));
            let innerTagLen = innerTag.Len();
            let t = taggedEncoder::New(alloc::boxed::Box::new(innerTag), body);

            let outerTag = bytesEncoder(appendTagAndLength(
                slice::default(),
                &TagAndLength {
                    class,
                    tag: params.tag.unwrap(),
                    length: bodyLen + innerTagLen,
                    isCompound: true,
                },
            ));

            return (
                Some(alloc::boxed::Box::new(taggedEncoder::New(
                    alloc::boxed::Box::new(outerTag),
                    alloc::boxed::Box::new(t),
                ))),
                nil,
            );
        }

        // implicit tag.
        tag = params.tag.unwrap();
    }

    let outer = bytesEncoder(appendTagAndLength(
        slice::default(),
        &TagAndLength {
            class,
            tag,
            length: bodyLen,
            isCompound,
        },
    ));

    return (
        Some(alloc::boxed::Box::new(taggedEncoder::New(
            alloc::boxed::Box::new(outer),
            body,
        ))),
        nil,
    );
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:718-733 Marshal
/// Return the ASN.1 encoding of `val`.
///
/// In addition to the struct tags recognized by Unmarshal, the following
/// can be used:
///
/// | tag | effect |
/// |---|---|
/// | `ia5` | marshal strings as IA5String |
/// | `omitempty` | skip empty slices |
/// | `printable` | marshal strings as PrintableString |
/// | `utf8` | marshal strings as UTF8String |
/// | `numeric` | marshal strings as NumericString |
/// | `utc` | marshal `time::Time` as UTCTime |
/// | `generalized` | marshal `time::Time` as GeneralizedTime |
///
/// Go takes `any`; goish takes `&impl Reflect` — see the banner above.
pub fn Marshal<T: crate::reflect::Reflect>(val: &T) -> (slice<byte>, error) {
    return MarshalWithParams(val, "");
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:735-745 MarshalWithParams
/// Allow field parameters to be specified for the top-level element.
/// The form of the params is the same as the field tags.
pub fn MarshalWithParams<T: crate::reflect::Reflect, S: Into<string>>(
    val: &T,
    params: S,
) -> (slice<byte>, error) {
    let v = crate::reflect::Reflect::__reflect_value(val);
    return marshalValue(&v, params);
}

// ─── the type-erased door: MarshalAny / MarshalAnyWithParams ─────────
//
// Go needs no such split. `func Marshal(val any) ([]byte, error)` is
// already the type-erased entry point, because Go's `any` carries its
// dynamic type descriptor and `reflect.ValueOf` reads it.
//
// goish's `Marshal` is generic over `Reflect`, and `Reflect` cannot be
// made into a trait object: `__reflect_type()` takes no `self`, so
// `dyn Reflect` is not a type Rust will build. `goish::Any` — the
// runtime's actual `interface{}` carrier — therefore cannot be passed
// to `Marshal` at all. These two functions are the missing half, and
// they are what `pkix.RDNSequence.String` calls: `tv.Value` is an
// `Any`, and Go's line is literally `asn1.Marshal(tv.Value)`.
//
// The reflection is fetched with `reflect::ValueOfAny`, whose comma-ok
// distinguishes "has no reflection at all" from "reflects to the
// invalid value". Both are errors here, but *different* errors, and
// the difference is not cosmetic: pkix falls back to
// `typeName = oidString` on any Marshal error and then prints
// `oid=<value>` instead of `oid=#<hex>`, so an unreflectable value
// that silently masqueraded as nil would produce plausible, wrong,
// user-visible output. Naming the type in the message is what makes
// that failure findable.

// go: none — goish idiom: Go's `Marshal(val any)` is already
// type-erased; goish's `Marshal` is generic over `Reflect`, which
// `dyn`/`goish::Any` cannot satisfy (`__reflect_type()` has no `self`,
// so the trait is not object safe). This is that same entry point for
// the erased carrier.
/// Return the ASN.1 encoding of the type-erased `val` — the `Marshal`
/// to call when the value arrived as Go's `any`.
///
/// Accepts the same struct tags as [`Marshal`]. Fails, rather than
/// encoding anything, when `val` carries a payload with no goish
/// reflection (`Any::new_fn` / `Any::new_opaque`).
pub fn MarshalAny(val: &crate::goany::Any) -> (slice<byte>, error) {
    return MarshalAnyWithParams(val, "");
}

// go: none — goish idiom: the params-carrying sibling of `MarshalAny`,
// standing in the same relation to it that `MarshalWithParams` does to
// `Marshal`.
/// Allow field parameters to be specified for the top-level element of
/// a type-erased value. The form of the params is the same as the
/// field tags.
pub fn MarshalAnyWithParams<S: Into<string>>(
    val: &crate::goany::Any,
    params: S,
) -> (slice<byte>, error) {
    let (v, ok) = crate::reflect::ValueOfAny(val);
    if !ok {
        // No reflection for this payload. Say so, and say which type —
        // this is NOT Go's "cannot marshal nil value", and reporting it
        // as such would send a reader hunting for a nil that is not
        // there.
        let mut msg = string::from_static("asn1: cannot marshal value of type ");
        msg += string::from(val.TypeName());
        msg += ": no goish reflection for that type";
        return (slice::default(), crate::errors::New(msg));
    }
    return marshalValue(&v, params);
}

// go: none — goish idiom: the tail Go writes twice, once in `Marshal`
// and once in `MarshalWithParams`. goish has four entry points into it
// (the `Any` pair as well), so it is a function.
/// Encode an already-reflected value under `params`.
fn marshalValue<S: Into<string>>(v: &crate::reflect::Value, params: S) -> (slice<byte>, error) {
    let (e, err) = makeField(v, &super::parseFieldParameters(params));
    if err != nil {
        return (slice::default(), err);
    }
    let e = e.unwrap();
    let mut b = crate::make!([]byte, e.Len());
    e.Encode(&mut b);
    return (b, nil);
}
