// encoding/asn1 — DER-encoded ASN.1 parsing primitives.
//
// Reference: /share/go/src/encoding/asn1/asn1.go +
//            /share/go/src/encoding/asn1/common.go (Go 1.25.5).
//
// What this v1 ports (foundational subset):
//
//   * Tag / Class constants (common.go:22-49).
//   * StructuralError / SyntaxError typed errors (asn1.go:39-50).
//   * parseBool, checkInteger, parseInt32, parseInt64 (asn1.go:56-131).
//   * BitString + At + RightAlign + parseBitString (asn1.go:162-211).
//   * NullRawValue, NullBytes (asn1.go:217-220).
//   * ObjectIdentifier + Equal + String + parseObjectIdentifier
//     (asn1.go:225-286).
//   * Enumerated, Flag (asn1.go:291-296).
//   * parseBase128Int (asn1.go:300-331).
//   * parseNumericString / parsePrintableString / parseIA5String /
//     parseT61String / parseUTF8String / parseBMPString
//     (asn1.go:382-533).
//   * RawValue, RawContent (asn1.go:536-546).
//   * parseTagAndLength + tagAndLength (asn1.go:551-627).
//
// What this v1 SKIPS (deferred):
//
//   * parseField / parseSequenceOf / Unmarshal / UnmarshalWithParams —
//     all of which dispatch through `reflect.Value` to fill struct
//     fields. The reflect-driven decode path lands when goish's
//     `reflect` gains setter dispatch for arbitrary user types.
//   * Marshal (marshal.go) — same reason.
//   * parseUTCTime / parseGeneralizedTime — Go uses `time.Parse` with
//     specific layouts; depends on the format-string interpreter
//     handling fractional-second + timezone bits.
//   * parseBigInt — needs `math/big`; not yet ported.
//   * fieldParameters / parseFieldParameters / getUniversalType —
//     reflection-driven struct-tag interpreter; pairs with the
//     reflect-driven decoder above.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::errors::{error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strconv;
use crate::strings;
use crate::types::{byte, int};
use crate::unicode::utf16;
use crate::unicode::utf8;

// ─── Tag constants (common.go:22-41) ──────────────────────────────────

pub const TagBoolean: int = 1;
pub const TagInteger: int = 2;
pub const TagBitString: int = 3;
pub const TagOctetString: int = 4;
pub const TagNull: int = 5;
pub const TagOID: int = 6;
pub const TagEnum: int = 10;
pub const TagUTF8String: int = 12;
pub const TagSequence: int = 16;
pub const TagSet: int = 17;
pub const TagNumericString: int = 18;
pub const TagPrintableString: int = 19;
pub const TagT61String: int = 20;
pub const TagIA5String: int = 22;
pub const TagUTCTime: int = 23;
pub const TagGeneralizedTime: int = 24;
pub const TagGeneralString: int = 27;
pub const TagBMPString: int = 30;

// ─── Class constants (common.go:44-49) ────────────────────────────────

pub const ClassUniversal: int = 0;
pub const ClassApplication: int = 1;
pub const ClassContextSpecific: int = 2;
pub const ClassPrivate: int = 3;

// ─── tagAndLength (common.go:51-54) ───────────────────────────────────

/// `tagAndLength` (common.go:51) — header preceding every DER object.
/// Public in goish so the smoke test can verify `parseTagAndLength`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TagAndLength {
    pub class: int,
    pub tag: int,
    pub length: int,
    pub isCompound: bool,
}

// ─── StructuralError / SyntaxError (asn1.go:39-50) ────────────────────

/// `asn1.StructuralError` (asn1.go:39) — ASN.1 data is valid but Go type
/// receiving it doesn't match.
#[derive(Clone)]
pub struct StructuralError {
    pub Msg: string,
}

impl ErrorTrait for StructuralError {
    fn Error(&self) -> string {
        // Go: asn1.go:43 — "asn1: structure error: " + e.Msg
        let mut b = strings::Builder::new();
        let _ = b.WriteString("asn1: structure error: ");
        let _ = b.WriteString(self.Msg.clone());
        b.String()
    }
}

/// `asn1.SyntaxError` (asn1.go:46) — ASN.1 data is invalid.
#[derive(Clone)]
pub struct SyntaxError {
    pub Msg: string,
}

impl ErrorTrait for SyntaxError {
    fn Error(&self) -> string {
        // Go: asn1.go:50 — "asn1: syntax error: " + e.Msg
        let mut b = strings::Builder::new();
        let _ = b.WriteString("asn1: syntax error: ");
        let _ = b.WriteString(self.Msg.clone());
        b.String()
    }
}

fn structural(msg: &'static str) -> error {
    crate::errors::Wrap(StructuralError {
        Msg: string::from_static(msg),
    })
}

fn syntax(msg: &'static str) -> error {
    crate::errors::Wrap(SyntaxError {
        Msg: string::from_static(msg),
    })
}

// ─── BOOLEAN (asn1.go:56) ─────────────────────────────────────────────

/// `parseBool` (asn1.go:56). Decodes a DER-encoded BOOLEAN.
pub fn ParseBool(bytes: slice<byte>) -> (bool, error) {
    // Go: if len(bytes) != 1 { err = SyntaxError{"invalid boolean"}; return }
    if bytes.Len() != 1 {
        return (false, syntax("invalid boolean"));
    }
    // Go: switch bytes[0] { case 0: ret = false … }
    match bytes[0 as int] {
        0 => (false, crate::errors::nil),
        0xff => (true, crate::errors::nil),
        _ => (false, syntax("invalid boolean")),
    }
}

// ─── INTEGER (asn1.go:79) ─────────────────────────────────────────────

/// `checkInteger` (asn1.go:81). nil iff `bytes` is a valid DER INTEGER.
pub fn CheckInteger(bytes: slice<byte>) -> error {
    // Go: if len(bytes) == 0 { return StructuralError{"empty integer"} }
    if bytes.Len() == 0 {
        return structural("empty integer");
    }
    if bytes.Len() == 1 {
        return crate::errors::nil;
    }
    // Go: if (bytes[0] == 0 && bytes[1]&0x80 == 0) ||
    //        (bytes[0] == 0xff && bytes[1]&0x80 == 0x80) { … }
    let b0 = bytes[0 as int];
    let b1 = bytes[1 as int];
    if (b0 == 0 && (b1 & 0x80) == 0) || (b0 == 0xff && (b1 & 0x80) == 0x80) {
        return structural("integer not minimally-encoded");
    }
    crate::errors::nil
}

/// `parseInt64` (asn1.go:96). Treats `bytes` as big-endian signed int.
pub fn ParseInt64(bytes: slice<byte>) -> (i64, error) {
    let err = CheckInteger(bytes.clone());
    if !err.IsNil() {
        return (0, err);
    }
    // Go: if len(bytes) > 8 { … "integer too large" }
    if bytes.Len() > 8 {
        return (0, structural("integer too large"));
    }
    let mut ret: i64 = 0;
    let n = bytes.Len();
    let mut i: int = 0;
    while i < n {
        // Go: ret <<= 8; ret |= int64(bytes[bytesRead])
        ret <<= 8;
        ret |= bytes[i] as i64;
        i += 1;
    }
    // Go: ret <<= 64 - uint8(len(bytes))*8
    //     ret >>= 64 - uint8(len(bytes))*8
    // Sign-extend by left-shifting bit (n*8 - 1) into bit 63 then doing
    // an arithmetic right shift. `wrapping_shl` lets the value pass
    // i64::MIN without panicking in debug builds.
    let shift: u32 = 64 - (n as u32) * 8;
    if shift > 0 {
        ret = (ret.wrapping_shl(shift)) >> shift;
    }
    (ret, crate::errors::nil)
}

/// `parseInt32` (asn1.go:119). Like `ParseInt64` but bounded to int32.
pub fn ParseInt32(bytes: slice<byte>) -> (i32, error) {
    let err = CheckInteger(bytes.clone());
    if !err.IsNil() {
        return (0, err);
    }
    let (ret64, err) = ParseInt64(bytes);
    if !err.IsNil() {
        return (0, err);
    }
    // Go: if ret64 != int64(int32(ret64)) { … "integer too large" }
    if ret64 != (ret64 as i32) as i64 {
        return (0, structural("integer too large"));
    }
    (ret64 as i32, crate::errors::nil)
}

// ─── BIT STRING (asn1.go:157) ─────────────────────────────────────────

/// `asn1.BitString` (asn1.go:162) — a bit string padded up to nearest
/// byte. `Bytes` holds the packed bits; `BitLength` records the number
/// of valid bits. Padding bits are zero.
#[derive(Clone)]
pub struct BitString {
    pub Bytes: slice<byte>,
    pub BitLength: int,
}

impl BitString {
    /// `BitString.At(i)` (asn1.go:169). Returns the i-th bit, or 0 if
    /// out of range.
    pub fn At(&self, i: int) -> int {
        // Go: if i < 0 || i >= b.BitLength { return 0 }
        if i < 0 || i >= self.BitLength {
            return 0;
        }
        // Go: x := i / 8; y := 7 - uint(i%8)
        let x = i / 8;
        let y = 7 - ((i % 8) as u32);
        // Go: return int(b.Bytes[x]>>y) & 1
        ((self.Bytes[x] >> y) as int) & 1
    }

    /// `BitString.RightAlign()` (asn1.go:180). Returns a slice with the
    /// padding bits at the start.
    pub fn RightAlign(&self) -> slice<byte> {
        // Go: shift := uint(8 - (b.BitLength % 8))
        let shift = (8 - (self.BitLength % 8)) as u32;
        // Go: if shift == 8 || len(b.Bytes) == 0 { return b.Bytes }
        if shift == 8 || self.Bytes.Len() == 0 {
            return self.Bytes.clone();
        }
        // Go: a := make([]byte, len(b.Bytes))
        let n = self.Bytes.Len();
        let mut a: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(n as usize);
        // Go: a[0] = b.Bytes[0] >> shift
        a.push(self.Bytes[0 as int] >> shift);
        // Go: for i := 1; i < len(b.Bytes); i++ { … }
        let mut i: int = 1;
        while i < n {
            // Go: a[i] = b.Bytes[i-1] << (8 - shift); a[i] |= b.Bytes[i] >> shift
            let v = (self.Bytes[i - 1] << (8 - shift)) | (self.Bytes[i] >> shift);
            a.push(v);
            i += 1;
        }
        slice::__from_vec(a)
    }
}

/// `parseBitString` (asn1.go:197). Parses an ASN.1 BIT STRING.
pub fn ParseBitString(bytes: slice<byte>) -> (BitString, error) {
    let empty = BitString {
        Bytes: slice::__from_vec(alloc::vec::Vec::new()),
        BitLength: 0,
    };
    // Go: if len(bytes) == 0 { … "zero length BIT STRING" }
    if bytes.Len() == 0 {
        return (empty, syntax("zero length BIT STRING"));
    }
    // Go: paddingBits := int(bytes[0])
    let paddingBits = bytes[0 as int] as int;
    // Go: if paddingBits > 7 || (len==1 && paddingBits>0) ||
    //         bytes[len-1]&((1<<bytes[0])-1) != 0 { … "invalid padding bits …" }
    let n = bytes.Len();
    let last = bytes[n - 1];
    let mask: byte = ((1u32 << bytes[0 as int]) - 1) as byte;
    if paddingBits > 7
        || (n == 1 && paddingBits > 0)
        || (last & mask) != 0
    {
        return (empty, syntax("invalid padding bits in BIT STRING"));
    }
    // Go: ret.BitLength = (len(bytes)-1)*8 - paddingBits
    let bit_length = (n - 1) * 8 - paddingBits;
    // Go: ret.Bytes = bytes[1:]
    //
    // Handcraft a fresh slice<byte> for `bytes[1:]` since goish's
    // slice doesn't expose Go-style sub-slicing through Index.
    let mut tail: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity((n - 1) as usize);
    let mut i: int = 1;
    while i < n {
        tail.push(bytes[i]);
        i += 1;
    }
    (
        BitString {
            Bytes: slice::__from_vec(tail),
            BitLength: bit_length,
        },
        crate::errors::nil,
    )
}

// ─── NULL (asn1.go:215) ───────────────────────────────────────────────

/// `NullRawValue` (asn1.go:217) — RawValue with Tag set to TagNull.
pub fn NullRawValue() -> RawValue {
    let empty = slice::__from_vec(alloc::vec::Vec::<byte>::new());
    RawValue {
        Class: 0,
        Tag: TagNull,
        IsCompound: false,
        Bytes: empty.clone(),
        FullBytes: empty,
    }
}

/// `NullBytes` (asn1.go:220) — `[TagNull, 0]` — DER NULL encoded.
pub fn NullBytes() -> slice<byte> {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(2);
    v.push(TagNull as byte);
    v.push(0);
    slice::__from_vec(v)
}

// ─── OBJECT IDENTIFIER (asn1.go:222) ──────────────────────────────────

/// `asn1.ObjectIdentifier` (asn1.go:225). A sequence of integers
/// identifying a node in the ASN.1 OID tree.
pub type ObjectIdentifier = slice<int>;

/// `ObjectIdentifier.Equal(other)` (asn1.go:228) — value equality.
pub fn OIDEqual(oi: &ObjectIdentifier, other: &ObjectIdentifier) -> bool {
    // Go: return slices.Equal(oi, other)
    crate::slices::Equal(oi, other)
}

/// `ObjectIdentifier.String()` (asn1.go:232) — dotted-decimal form.
pub fn OIDString(oi: &ObjectIdentifier) -> string {
    let mut s = strings::Builder::new();
    s.Grow(32);
    let n = oi.Len();
    let mut i: int = 0;
    while i < n {
        // Go: if i > 0 { s.WriteByte('.') }
        if i > 0 {
            let _ = s.WriteByte(b'.');
        }
        // Go: s.Write(strconv.AppendInt(buf, int64(v), 10))
        let _ = s.WriteString(strconv::Itoa(oi[i]));
        i += 1;
    }
    s.String()
}

/// `parseObjectIdentifier` (asn1.go:250) — decode a DER-encoded OID.
pub fn ParseObjectIdentifier(bytes: slice<byte>) -> (ObjectIdentifier, error) {
    // Go: if len(bytes) == 0 { … "zero length OBJECT IDENTIFIER" }
    if bytes.Len() == 0 {
        let empty: alloc::vec::Vec<int> = alloc::vec::Vec::new();
        return (slice::__from_vec(empty), syntax("zero length OBJECT IDENTIFIER"));
    }
    // Go: s = make([]int, len(bytes)+1)
    let mut s: alloc::vec::Vec<int> = alloc::vec::Vec::with_capacity((bytes.Len() + 1) as usize);
    // Pre-fill so we can index into it like Go.
    let target = (bytes.Len() + 1) as usize;
    while s.len() < target {
        s.push(0);
    }
    // Go: v, offset, err := parseBase128Int(bytes, 0)
    let (v, mut offset, err) = ParseBase128Int(bytes.clone(), 0);
    if !err.IsNil() {
        let empty: alloc::vec::Vec<int> = alloc::vec::Vec::new();
        return (slice::__from_vec(empty), err);
    }
    // Go: if v < 80 { s[0] = v/40; s[1] = v%40 } else { s[0] = 2; s[1] = v-80 }
    if v < 80 {
        s[0] = v / 40;
        s[1] = v % 40;
    } else {
        s[0] = 2;
        s[1] = v - 80;
    }

    // Go: i := 2; for ; offset < len(bytes); i++ { … }
    let n = bytes.Len();
    let mut i: int = 2;
    while offset < n {
        let (vv, new_off, e) = ParseBase128Int(bytes.clone(), offset);
        if !e.IsNil() {
            let empty: alloc::vec::Vec<int> = alloc::vec::Vec::new();
            return (slice::__from_vec(empty), e);
        }
        s[i as usize] = vv;
        offset = new_off;
        i += 1;
    }
    // Go: s = s[0:i]
    s.truncate(i as usize);
    (slice::__from_vec(s), crate::errors::nil)
}

// ─── ENUMERATED + FLAG (asn1.go:288) ──────────────────────────────────

/// `asn1.Enumerated` (asn1.go:291) — represented as plain int.
pub type Enumerated = int;

/// `asn1.Flag` (asn1.go:296) — set to true if present.
pub type Flag = bool;

// ─── parseBase128Int (asn1.go:300) ────────────────────────────────────

const MaxInt32: i64 = 0x7FFF_FFFF;

/// `parseBase128Int` (asn1.go:300) — decode a base-128 varint at
/// `bytes[init_offset..]`. Returns `(value, new_offset, err)`.
pub fn ParseBase128Int(bytes: slice<byte>, init_offset: int) -> (int, int, error) {
    // Go: offset = initOffset
    let mut offset = init_offset;
    let mut ret64: i64 = 0;
    // Go: for shifted := 0; offset < len(bytes); shifted++ { … }
    let mut shifted: int = 0;
    let n = bytes.Len();
    while offset < n {
        // Go: if shifted == 5 { … "base 128 integer too large" }
        if shifted == 5 {
            return (0, offset, structural("base 128 integer too large"));
        }
        // Go: ret64 <<= 7
        ret64 <<= 7;
        let b = bytes[offset];
        // Go: if shifted == 0 && b == 0x80 { … "integer is not minimally encoded" }
        if shifted == 0 && b == 0x80 {
            return (0, offset, syntax("integer is not minimally encoded"));
        }
        // Go: ret64 |= int64(b & 0x7f); offset++
        ret64 |= (b & 0x7f) as i64;
        offset += 1;
        // Go: if b&0x80 == 0 { … }
        if (b & 0x80) == 0 {
            // Go: ret = int(ret64); if ret64 > math.MaxInt32 { err = … }
            let ret = ret64 as int;
            if ret64 > MaxInt32 {
                return (ret, offset, structural("base 128 integer too large"));
            }
            return (ret, offset, crate::errors::nil);
        }
        shifted += 1;
    }
    // Go: err = SyntaxError{"truncated base 128 integer"}
    (0, offset, syntax("truncated base 128 integer"))
}

// ─── String parsers (asn1.go:382-533) ─────────────────────────────────

/// `parseNumericString` (asn1.go:382). Validates ASN.1 NumericString.
pub fn ParseNumericString(bytes: slice<byte>) -> (string, error) {
    let n = bytes.Len();
    let mut i: int = 0;
    while i < n {
        // Go: if !isNumeric(b) { … }
        if !isNumeric(bytes[i]) {
            return (
                string::from_static(""),
                syntax("NumericString contains invalid character"),
            );
        }
        i += 1;
    }
    (slice_to_string(&bytes), crate::errors::nil)
}

/// `isNumeric` (asn1.go:392). NumericString = digits + space.
fn isNumeric(b: byte) -> bool {
    (b'0' <= b && b <= b'9') || b == b' '
}

/// `parsePrintableString` (asn1.go:401). Validates PrintableString.
pub fn ParsePrintableString(bytes: slice<byte>) -> (string, error) {
    let n = bytes.Len();
    let mut i: int = 0;
    while i < n {
        // Go: !isPrintable(b, allowAsterisk, allowAmpersand)
        if !isPrintable(bytes[i], true, true) {
            return (
                string::from_static(""),
                syntax("PrintableString contains invalid character"),
            );
        }
        i += 1;
    }
    (slice_to_string(&bytes), crate::errors::nil)
}

/// `isPrintable` (asn1.go:426). PrintableString allowed-byte set, with
/// the historical asterisk/ampersand carve-outs Go grants for x509.
fn isPrintable(b: byte, allow_asterisk: bool, allow_ampersand: bool) -> bool {
    (b'a' <= b && b <= b'z')
        || (b'A' <= b && b <= b'Z')
        || (b'0' <= b && b <= b'9')
        || (b'\'' <= b && b <= b')')
        || (b'+' <= b && b <= b'/')
        || b == b' '
        || b == b':'
        || b == b'='
        || b == b'?'
        || (allow_asterisk && b == b'*')
        || (allow_ampersand && b == b'&')
}

/// `parseIA5String` (asn1.go:451). Validates IA5String (ASCII).
pub fn ParseIA5String(bytes: slice<byte>) -> (string, error) {
    let n = bytes.Len();
    let mut i: int = 0;
    while i < n {
        // Go: if b >= utf8.RuneSelf { … }
        if bytes[i] >= utf8::RuneSelf {
            return (
                string::from_static(""),
                syntax("IA5String contains invalid character"),
            );
        }
        i += 1;
    }
    (slice_to_string(&bytes), crate::errors::nil)
}

/// `parseT61String` (asn1.go:466). Treats input as Latin-1 and re-encodes
/// to UTF-8 (matches Go and BoringSSL).
pub fn ParseT61String(bytes: slice<byte>) -> (string, error) {
    // Go: buf := make([]byte, 0, len(bytes))
    let mut buf: slice<byte> = slice::__from_vec(alloc::vec::Vec::with_capacity(bytes.Len() as usize));
    let n = bytes.Len();
    let mut i: int = 0;
    while i < n {
        // Go: buf = utf8.AppendRune(buf, rune(v))
        buf = utf8::AppendRune(buf, bytes[i] as crate::types::rune);
        i += 1;
    }
    (slice_to_string(&buf), crate::errors::nil)
}

/// `parseUTF8String` (asn1.go:488). Validates UTF-8 input.
pub fn ParseUTF8String(bytes: slice<byte>) -> (string, error) {
    // Go: if !utf8.Valid(bytes) { return "", errors.New("asn1: invalid UTF-8 string") }
    let raw = slice_to_bytes(&bytes);
    if !utf8::Valid(&raw) {
        return (
            string::from_static(""),
            crate::errors::New("asn1: invalid UTF-8 string"),
        );
    }
    (slice_to_string(&bytes), crate::errors::nil)
}

/// `parseBMPString` (asn1.go:499). UCS-2-encoded; rejects out-of-BMP
/// surrogate / non-character code points.
pub fn ParseBMPString(bytes: slice<byte>) -> (string, error) {
    let mut bmp = bytes.clone();
    // Go: if len(bmpString)%2 != 0 { … "invalid BMPString" }
    if (bmp.Len() % 2) != 0 {
        return (
            string::from_static(""),
            crate::errors::New("invalid BMPString"),
        );
    }
    // Go: strip 0,0 terminator if present
    let mut n = bmp.Len();
    if n >= 2 && bmp[n - 1] == 0 && bmp[n - 2] == 0 {
        let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity((n - 2) as usize);
        let mut i: int = 0;
        while i < n - 2 {
            v.push(bmp[i]);
            i += 1;
        }
        bmp = slice::__from_vec(v);
        n = bmp.Len();
    }
    // Go: s := make([]uint16, 0, len(bmpString)/2)
    let mut s: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity((n / 2) as usize);
    let mut i: int = 0;
    while i < n {
        // Go: point := uint16(bmpString[0])<<8 + uint16(bmpString[1])
        let point: u16 = ((bmp[i] as u16) << 8) + bmp[i + 1] as u16;
        // Go: reject 0xfffe, 0xffff, 0xfdd0..=0xfdef, 0xd800..=0xdfff
        if point == 0xfffe
            || point == 0xffff
            || (point >= 0xfdd0 && point <= 0xfdef)
            || (point >= 0xd800 && point <= 0xdfff)
        {
            return (
                string::from_static(""),
                crate::errors::New("invalid BMPString"),
            );
        }
        s.push(point);
        i += 2;
    }
    // Go: return string(utf16.Decode(s))
    let runes = utf16::Decode(slice::__from_vec(s));
    let mut out = strings::Builder::new();
    let rn = runes.Len();
    let mut k: int = 0;
    while k < rn {
        let _ = out.WriteRune(runes[k]);
        k += 1;
    }
    (out.String(), crate::errors::nil)
}

// ─── RawValue / RawContent (asn1.go:535) ──────────────────────────────

/// `asn1.RawValue` (asn1.go:536) — undecoded ASN.1 object.
#[derive(Clone)]
pub struct RawValue {
    pub Class: int,
    pub Tag: int,
    pub IsCompound: bool,
    pub Bytes: slice<byte>,
    /// includes the tag and length
    pub FullBytes: slice<byte>,
}

/// `asn1.RawContent` (asn1.go:546) — opaque DER bytes preserved
/// verbatim across (un)marshal.
pub type RawContent = slice<byte>;

// ─── parseTagAndLength (asn1.go:551) ──────────────────────────────────

/// `parseTagAndLength` (asn1.go:554) — decode a DER tag + length pair.
/// Returns `(parsed, new_offset, err)`.
pub fn ParseTagAndLength(bytes: slice<byte>, init_offset: int) -> (TagAndLength, int, error) {
    let mut ret = TagAndLength {
        class: 0,
        tag: 0,
        length: 0,
        isCompound: false,
    };
    let mut offset = init_offset;
    let n = bytes.Len();
    // Go: if offset >= len(bytes) { err = errors.New("…internal error…") }
    if offset >= n {
        return (
            ret,
            offset,
            crate::errors::New("asn1: internal error in parseTagAndLength"),
        );
    }
    // Go: b := bytes[offset]; offset++
    let mut b = bytes[offset];
    offset += 1;
    // Go: ret.class = int(b >> 6)
    ret.class = (b >> 6) as int;
    // Go: ret.isCompound = b&0x20 == 0x20
    ret.isCompound = (b & 0x20) == 0x20;
    // Go: ret.tag = int(b & 0x1f)
    ret.tag = (b & 0x1f) as int;

    // Go: if ret.tag == 0x1f { high-tag-number form }
    if ret.tag == 0x1f {
        let (t, off, err) = ParseBase128Int(bytes.clone(), offset);
        if !err.IsNil() {
            return (ret, off, err);
        }
        ret.tag = t;
        offset = off;
        // Go: if ret.tag < 0x1f { err = SyntaxError{"non-minimal tag"} }
        if ret.tag < 0x1f {
            return (ret, offset, syntax("non-minimal tag"));
        }
    }
    // Go: if offset >= len(bytes) { err = SyntaxError{"truncated tag or length"} }
    if offset >= n {
        return (ret, offset, syntax("truncated tag or length"));
    }
    // Go: b = bytes[offset]; offset++
    b = bytes[offset];
    offset += 1;
    // Go: if b&0x80 == 0 { ret.length = int(b & 0x7f) } else { … }
    if (b & 0x80) == 0 {
        ret.length = (b & 0x7f) as int;
    } else {
        let numBytes = (b & 0x7f) as int;
        // Go: if numBytes == 0 { err = SyntaxError{"indefinite length found (not DER)"} }
        if numBytes == 0 {
            return (ret, offset, syntax("indefinite length found (not DER)"));
        }
        ret.length = 0;
        // Go: for i := 0; i < numBytes; i++ { … }
        let mut i: int = 0;
        while i < numBytes {
            if offset >= n {
                return (ret, offset, syntax("truncated tag or length"));
            }
            b = bytes[offset];
            offset += 1;
            // Go: if ret.length >= 1<<23 { err = StructuralError{"length too large"} }
            if ret.length >= (1 << 23) {
                return (ret, offset, structural("length too large"));
            }
            // Go: ret.length <<= 8; ret.length |= int(b)
            ret.length <<= 8;
            ret.length |= b as int;
            // Go: if ret.length == 0 { err = StructuralError{"superfluous leading zeros in length"} }
            if ret.length == 0 {
                return (ret, offset, structural("superfluous leading zeros in length"));
            }
            i += 1;
        }
        // Go: if ret.length < 0x80 { err = StructuralError{"non-minimal length"} }
        if ret.length < 0x80 {
            return (ret, offset, structural("non-minimal length"));
        }
    }
    (ret, offset, crate::errors::nil)
}

// ─── helpers ──────────────────────────────────────────────────────────

fn slice_to_string(s: &slice<byte>) -> string {
    let n = s.Len();
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(n as usize);
    let mut i: int = 0;
    while i < n {
        v.push(s[i]);
        i += 1;
    }
    string::from_bytes(&v)
}

fn slice_to_bytes(s: &slice<byte>) -> alloc::vec::Vec<byte> {
    let n = s.Len();
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(n as usize);
    let mut i: int = 0;
    while i < n {
        v.push(s[i]);
        i += 1;
    }
    v
}
