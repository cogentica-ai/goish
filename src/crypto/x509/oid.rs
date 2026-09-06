// go: file crypto/x509/oid.go decls: ParseOID, newOIDFromDER, OIDFromInts, base128IntLength, appendBase128Int, base128BigIntLength, appendBase128BigInt, OID.AppendText, OID.MarshalText, OID.UnmarshalText, OID.unmarshalOIDText, OID.AppendBinary, OID.MarshalBinary, OID.UnmarshalBinary, OID.Equal, parseBase128Int, OID.EqualASN1OID, OID.String, OID.toASN1OID
//
// `x509.OID` — an Object Identifier held in its DER encoding rather than
// as a component slice, which is what lets it represent components too
// large for `asn1.ObjectIdentifier`'s `int`.
//
// The first file of crypto/x509 to be ported as a unit. It is
// self-contained: of x509's twelve files this one reaches only bytes,
// encoding/asn1, math, math/big, math/bits, strconv and strings, all of
// which goish has. `verify.go` is the file that needs `net/netip`, not
// this one.
//
// Deviations from oid[go] @ Go 1.25.5:
//
//   * Go's `der []byte` field is unexported and `OID` is compared with
//     `bytes.Equal`, never `==`. goish keeps the field private the same
//     way and derives no PartialEq, so `Equal` stays the only comparison
//     — matching Go, where OID is deliberately not `==`-comparable in a
//     meaningful sense.
//   * Go's `AppendText`/`AppendBinary` implement `encoding.TextAppender`
//     and `encoding.BinaryAppender`. goish has no such interfaces yet, so
//     these are inherent methods with the same signatures; the four
//     Marshal/Unmarshal entry points behave identically.
//   * `(*big.Int).Bits()` returns Go's `[]Word`; goish's returns the same
//     limb slice, and `appendBase128BigInt` reads limb 0 exactly as Go
//     does after the shift.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::encoding::asn1;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io::Writer;
use crate::math::big;
use crate::math::big::Int;
use crate::strings;
use crate::types::{byte, int};

goish::var! {
    errInvalidOID: error = "invalid oid";
}

// Go: oid.go:23-25 — `type OID struct { der []byte }`
/// An ASN.1 OBJECT IDENTIFIER, stored in its DER encoding.
///
/// Unlike `asn1::ObjectIdentifier`, a component may exceed what an `int`
/// holds — `String` falls back to `big::Int` when one does.
#[derive(Clone, Default)]
pub struct OID {
    pub(super) der: slice<byte>,
}

// go: sdk 1.25.5 crypto/x509/oid.go:27-31 ParseOID
/// Parse an Object Identifier string — ASCII numbers separated by dots.
pub fn ParseOID<S: Into<string>>(oid: S) -> (OID, error) {
    let mut o = OID::default();
    let err = o.unmarshalOIDText(oid.into());
    return (o, err);
}

// go: sdk 1.25.5 crypto/x509/oid.go:33-53 newOIDFromDER
/// Wrap already-encoded DER, rejecting a non-minimal or truncated
/// encoding. Returns `(oid, ok)`.
pub(super) fn newOIDFromDER(der: slice<byte>) -> (OID, bool) {
    let d = der.as_ref();
    if d.is_empty() || d[d.len() - 1] & 0x80 != 0 {
        return (OID::default(), false);
    }

    let mut start: int = 0;
    for (i, v) in crate::range!(der.clone()) {
        // ITU-T X.690, section 8.19.2: the subidentifier shall be encoded
        // in the fewest possible octets, so the leading octet shall not
        // have the value 0x80.
        if i == start && *v == 0x80 {
            return (OID::default(), false);
        }
        if *v & 0x80 == 0 {
            start = i + 1;
        }
    }

    return (OID { der }, true);
}

// go: sdk 1.25.5 crypto/x509/oid.go:55-71 OIDFromInts
/// Build an OID from its components, one integer per component.
pub fn OIDFromInts(oid: slice<u64>) -> (OID, error) {
    let o = oid.as_ref();
    if o.len() < 2 || o[0] > 2 || (o[0] < 2 && o[1] >= 40) {
        return (OID::default(), errInvalidOID.into());
    }

    let mut length = base128IntLength(o[0] * 40 + o[1]);
    for v in o[2..].iter() {
        length += base128IntLength(*v);
    }

    let mut der: Vec<byte> = Vec::with_capacity(length as usize);
    der = appendBase128Int(der, o[0] * 40 + o[1]);
    for v in o[2..].iter() {
        der = appendBase128Int(der, *v);
    }
    return (
        OID {
            der: slice::__from_vec(der),
        },
        nil.into(),
    );
}

// go: sdk 1.25.5 crypto/x509/oid.go:73-78 base128IntLength
fn base128IntLength(n: u64) -> int {
    if n == 0 {
        return 1;
    }
    return (crate::math::bits::Len64(n) + 6) / 7;
}

// go: sdk 1.25.5 crypto/x509/oid.go:80-90 appendBase128Int
fn appendBase128Int(dst: Vec<byte>, n: u64) -> Vec<byte> {
    let mut dst = dst;
    let mut i = base128IntLength(n) - 1;
    while i >= 0 {
        let mut o = crate::byte(n >> crate::uint(i * 7));
        o &= 0x7f;
        if i != 0 {
            o |= 0x80;
        }
        dst.push(o);
        i -= 1;
    }
    return dst;
}

// go: sdk 1.25.5 crypto/x509/oid.go:92-97 base128BigIntLength
fn base128BigIntLength(n: &Int) -> int {
    if n.Cmp(&big::NewInt(0)) == 0 {
        return 1;
    }
    return (n.BitLen() + 6) / 7;
}

// go: sdk 1.25.5 crypto/x509/oid.go:99-114 appendBase128BigInt
fn appendBase128BigInt(dst: Vec<byte>, n: &Int) -> Vec<byte> {
    let mut dst = dst;
    if n.Cmp(&big::NewInt(0)) == 0 {
        dst.push(0);
        return dst;
    }

    let mut i = base128BigIntLength(n) - 1;
    while i >= 0 {
        let mut shifted = Int::default();
        shifted.Rsh(n, crate::uint(i) * 7);
        let limbs = shifted.Bits();
        let w = if limbs.Len() == 0 { 0 } else { limbs[0] };
        let mut o = crate::byte(w);
        o &= 0x7f;
        if i != 0 {
            o |= 0x80;
        }
        dst.push(o);
        i -= 1;
    }
    return dst;
}

impl OID {
    // go: sdk 1.25.5 crypto/x509/oid.go:116-119 OID.AppendText
    /// Go: implements `encoding.TextAppender`.
    pub fn AppendText(&self, b: slice<byte>) -> (slice<byte>, error) {
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(self.String().as_bytes());
        return (slice::__from_vec(out), nil.into());
    }

    // go: sdk 1.25.5 crypto/x509/oid.go:121-124 OID.MarshalText
    /// Go: implements `encoding.TextMarshaler`.
    pub fn MarshalText(&self) -> (slice<byte>, error) {
        return self.AppendText(slice::default());
    }

    // go: sdk 1.25.5 crypto/x509/oid.go:126-129 OID.UnmarshalText
    /// Go: implements `encoding.TextUnmarshaler`.
    pub fn UnmarshalText(&mut self, text: slice<byte>) -> error {
        return self.unmarshalOIDText(string::from_bytes(text.as_ref()));
    }

    // go: sdk 1.25.5 crypto/x509/oid.go:130-186 OID.unmarshalOIDText
    fn unmarshalOIDText(&mut self, oid: string) -> error {
        // `(*big.Int).SetString` allows +/- signs, but the string form of
        // an Object Identifier must not, so reject those encodings.
        for (_, c) in crate::range!(oid.clone()) {
            let isDigit = c >= crate::int32(b'0') && c <= crate::int32(b'9');
            if !isDigit && c != crate::int32(b'.') {
                return errInvalidOID.into();
            }
        }

        let (firstNum, rest, mut nextComponentExists) = strings::Cut(oid, ".");
        if !nextComponentExists {
            return errInvalidOID.into();
        }
        let (secondNum, mut oid, nce) = strings::Cut(rest, ".");
        nextComponentExists = nce;

        let mut first = big::NewInt(0);
        let mut second = big::NewInt(0);

        if !first.SetString(firstNum, 10).1 {
            return errInvalidOID.into();
        }
        if !second.SetString(secondNum, 10).1 {
            return errInvalidOID.into();
        }

        if first.Cmp(&big::NewInt(2)) > 0
            || (first.Cmp(&big::NewInt(2)) < 0 && second.Cmp(&big::NewInt(40)) >= 0)
        {
            return errInvalidOID.into();
        }

        let firstCopy = first.clone();
        first.Mul(&firstCopy, &big::NewInt(40));
        let firstMul = first.clone();
        let mut firstComponent = Int::default();
        firstComponent.Add(&firstMul, &second);

        let mut der = appendBase128BigInt(Vec::with_capacity(32), &firstComponent);

        while nextComponentExists {
            let (strNum, restN, nce) = strings::Cut(oid, ".");
            oid = restN;
            nextComponentExists = nce;
            let mut b = big::NewInt(0);
            if !b.SetString(strNum, 10).1 {
                return errInvalidOID.into();
            }
            der = appendBase128BigInt(der, &b);
        }

        self.der = slice::__from_vec(der);
        return nil.into();
    }

    // go: sdk 1.25.5 crypto/x509/oid.go:188-191 OID.AppendBinary
    /// Go: implements `encoding.BinaryAppender`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(self.der.as_ref());
        return (slice::__from_vec(out), nil.into());
    }

    // go: sdk 1.25.5 crypto/x509/oid.go:193-196 OID.MarshalBinary
    /// Go: implements `encoding.BinaryMarshaler`.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        return self.AppendBinary(slice::default());
    }

    // go: sdk 1.25.5 crypto/x509/oid.go:198-206 OID.UnmarshalBinary
    /// Go: implements `encoding.BinaryUnmarshaler`.
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let (oid, ok) = newOIDFromDER(crate::bytes::Clone(b));
        if !ok {
            return errInvalidOID.into();
        }
        *self = oid;
        return nil.into();
    }

    // go: sdk 1.25.5 crypto/x509/oid.go:208-213 OID.Equal
    /// True when `self` and `other` represent the same Object Identifier.
    pub fn Equal(&self, other: &OID) -> bool {
        // There is only one possible DER encoding of each unique Object
        // Identifier.
        return crate::bytes::Equal(self.der.clone(), other.der.clone());
    }

    // go: sdk 1.25.5 crypto/x509/oid.go:251-286 OID.EqualASN1OID
    /// Whether `self` equals an `asn1::ObjectIdentifier`. If the OID
    /// cannot be represented as one — a component needing more than 31
    /// bits — this is false.
    pub fn EqualASN1OID(&self, other: &asn1::ObjectIdentifier) -> bool {
        if other.Len() < 2 {
            return false;
        }
        let (v, mut offset, failed) = parseBase128Int(&self.der, 0);
        if failed {
            // Should never happen: the OID is already parsed. Just in case.
            return false;
        }
        if v < 80 {
            let (a, b) = (v / 40, v % 40);
            if other[0] != a || other[1] != b {
                return false;
            }
        } else {
            let (a, b) = (2, v - 80);
            if other[0] != a || other[1] != b {
                return false;
            }
        }

        let mut i: int = 2;
        while offset < self.der.Len() {
            let (v2, off2, failed2) = parseBase128Int(&self.der, offset);
            offset = off2;
            if failed2 {
                // Again, shouldn't happen — the OID is already parsed.
                return false;
            }
            if i >= other.Len() || v2 != other[i] {
                return false;
            }
            i += 1;
        }

        return i == other.Len();
    }

    // go: sdk 1.25.5 crypto/x509/oid.go:288-355 OID.String
    /// The string representation of the Object Identifier.
    pub fn String(&self) -> string {
        let mut b = strings::Builder::new();
        b.Grow(32);
        // size in bits of val, and the shift ceiling before it overflows.
        const valSize: int = 64;
        const bitsPerByte: int = 7;
        const maxValSafeShift: u64 = (1u64 << (valSize - bitsPerByte)) - 1;

        let mut start: int = 0;
        let mut val: u64 = 0;
        let mut numBuf: slice<byte> = slice::default();
        let mut bigVal: Option<Int> = None;
        let mut overflow = false;

        for (i, v) in crate::range!(self.der.clone()) {
            let curVal = v & 0x7F;
            let valEnd = v & 0x80 == 0;
            if valEnd {
                if start != 0 {
                    let _ = b.WriteByte(b'.');
                }
            }
            if !overflow && val > maxValSafeShift {
                let mut bv = match bigVal.take() {
                    Some(x) => x,
                    None => Int::default(),
                };
                bv.SetUint64(val);
                bigVal = Some(bv);
                overflow = true;
            }
            if overflow {
                let mut bv = bigVal.take().unwrap();
                let shifted = bv.clone();
                bv.Lsh(&shifted, crate::uint(bitsPerByte));
                let ored = bv.clone();
                bv.Or(&ored, &big::NewInt(crate::int64(curVal)));
                if valEnd {
                    if start == 0 {
                        let _ = b.WriteString("2.");
                        let subbed = bv.clone();
                        bv.Sub(&subbed, &big::NewInt(80));
                    }
                    numBuf = bv.Append(numBuf, 10);
                    let _ = b.Write(numBuf.clone());
                    numBuf = slice::default();
                    val = 0;
                    start = i + 1;
                    overflow = false;
                }
                bigVal = Some(bv);
                continue;
            }
            val <<= bitsPerByte;
            val |= crate::uint64(curVal);
            if valEnd {
                if start == 0 {
                    if val < 80 {
                        let _ = b.Write(crate::strconv::AppendUint(numBuf.clone(), val / 40, 10));
                        let _ = b.WriteByte(b'.');
                        let _ = b.Write(crate::strconv::AppendUint(numBuf.clone(), val % 40, 10));
                    } else {
                        let _ = b.WriteString("2.");
                        let _ = b.Write(crate::strconv::AppendUint(numBuf.clone(), val - 80, 10));
                    }
                } else {
                    let _ = b.Write(crate::strconv::AppendUint(numBuf.clone(), val, 10));
                }
                val = 0;
                start = i + 1;
            }
        }
        return b.String();
    }

    // go: sdk 1.25.5 crypto/x509/oid.go:357-395 OID.toASN1OID
    /// Convert to an `asn1::ObjectIdentifier`, or `ok=false` if any
    /// component needs more than 31 bits.
    pub(crate) fn toASN1OID(&self) -> (asn1::ObjectIdentifier, bool) {
        let mut out: Vec<int> = Vec::with_capacity(self.der.Len() as usize + 1);

        // amount of usable bits of val for OIDs.
        const valSize: int = 31;
        const bitsPerByte: int = 7;
        const maxValSafeShift: int = (1 << (valSize - bitsPerByte)) - 1;

        let mut val: int = 0;

        for (_, v) in crate::range!(self.der.clone()) {
            if val > maxValSafeShift {
                return (asn1::ObjectIdentifier::default(), false);
            }

            val <<= bitsPerByte;
            val |= crate::int(v & 0x7F);

            if v & 0x80 == 0 {
                if out.is_empty() {
                    if val < 80 {
                        out.push(val / 40);
                        out.push(val % 40);
                    } else {
                        out.push(2);
                        out.push(val - 80);
                    }
                } else {
                    out.push(val);
                }
                val = 0;
            }
        }

        return (asn1::ObjectIdentifier::New(slice::__from_vec(out)), true);
    }
}

// go: sdk 1.25.5 crypto/x509/oid.go:215-246 parseBase128Int
/// Decode one base-128 component at `bytes[initOffset..]`. Returns
/// `(ret, offset, failed)`.
fn parseBase128Int(bytes: &slice<byte>, initOffset: int) -> (int, int, bool) {
    let mut offset = initOffset;
    let mut ret64: i64 = 0;
    let b = bytes.as_ref();
    let mut shifted: int = 0;
    while offset < crate::int(b.len()) {
        // 5 * 7 bits per byte == 35 bits of data, so the representation is
        // either non-minimal or too large for an int32.
        if shifted == 5 {
            return (0, offset, true);
        }
        ret64 <<= 7;
        let v = b[offset as usize];
        // Integers should be minimally encoded, so the leading octet
        // should never be 0x80.
        if shifted == 0 && v == 0x80 {
            return (0, offset, true);
        }
        ret64 |= crate::int64(v & 0x7f);
        offset += 1;
        if v & 0x80 == 0 {
            let ret = crate::int(ret64);
            // Ensure the returned value fits in an int on all platforms.
            if ret64 > crate::int64(crate::math::MaxInt32) {
                return (ret, offset, true);
            }
            return (ret, offset, false);
        }
        shifted += 1;
    }
    return (0, offset, true);
}

// go: none — goish idiom: Go's `fmt` finds `String()` by structural
// assertion, so `%%v` and `%%s` on a value whose METHOD SET includes it
// print through it. goish's printer dispatches on `Format`, which a
// type reaches through `Stringer`, and these did not implement it —
// so `fmt.Printf("%%v", x)`, entirely ordinary Go, did not compile.
//
// Only VALUE-receiver String methods are bridged. Go puts a
// pointer-receiver String in the POINTER's method set only, so
// printing the value prints the struct instead; goish has no
// value/pointer distinction, and implementing Stringer for those types
// would print where Go does not. net.IPNet, url.URL, url.Userinfo,
// http.Cookie, mail.Address and regexp.Regexp are left alone for that
// reason.
impl crate::fmt::Stringer for OID {
    // go: none — goish idiom: see the note above.
    fn String(&self) -> crate::gostring::string {
        let v = self;
        return OID::String(v);
    }
}
