// go: file vendor/golang.org/x/crypto/cryptobyte/asn1.go decls: Builder.AddASN1, String.ReadASN1Boolean, String.ReadASN1Integer, String.ReadOptionalASN1Integer, String.readASN1BigInt, String.readASN1Bytes, String.readASN1Int64, asn1Signed, String.readASN1Uint64, asn1Unsigned, String.ReadASN1Int64WithTag, String.ReadASN1Enum, String.readBase128Int, String.ReadASN1ObjectIdentifier, String.ReadASN1GeneralizedTime, String.ReadASN1UTCTime, String.ReadASN1BitString, String.ReadASN1BitStringAsBytes, String.ReadASN1Bytes, String.ReadASN1, String.ReadASN1Element, String.ReadAnyASN1, String.ReadAnyASN1Element, String.PeekASN1Tag, String.SkipASN1, String.ReadOptionalASN1, String.SkipOptionalASN1, String.ReadOptionalASN1OctetString, String.ReadOptionalASN1Boolean, String.readASN1, checkASN1Integer
//
// The ASN.1 DER layer over Builder and String.
//
// **Partial port — the whole String (parsing) half is here; the Builder
// half is not.** Go's asn1.go is 862 lines. Every `func (s *String)`
// reader is ported below, which is what `crypto/x509/parser.go` needs;
// of the `func (b *Builder)` writers only `AddASN1` is ported, the one
// `crypto/ecdsa`'s encodeSignature reaches. What is here is verbatim;
// the rest is absent, not stubbed.
//
// Deviations:
//
//   * Go's `ReadASN1Integer(out interface{})` dispatches on the pointee
//     type with a type switch and `reflect`. goish spells the same
//     dispatch statically, as `ReadASN1Integer<T: ASN1Integer>(&mut T)`
//     with one `impl ASN1Integer` per arm. Go's `*int, *int8, *int16,
//     *int32, *int64` arm collapses to two goish impls — `int` and
//     `int64` are both `i64`, `uint` and `uint64` both `u64` — so the
//     `OverflowInt`/`OverflowUint` re-check those arms perform is a
//     no-op here and is not written. `ReadOptionalASN1Integer` takes
//     the same bound, which is why its `panic("invalid integer type")`
//     default arm has no counterpart: the type system rejects those
//     calls at compile time.
//   * `readASN1`'s `outTag *asn1.Tag` and `ReadOptionalASN1`'s
//     `outPresent *bool` are nil-able in Go; here they are
//     `Option<&mut _>`.
//   * `ReadASN1UTCTime` / `ReadASN1GeneralizedTime` call goish's
//     `time::Parse`, whose slim layout support was extended with the
//     two ASN.1 layouts (`060102150405Z0700`, `0601021504Z0700`,
//     `20060102150405Z0700`). It accepts only the `Z` zone form, never
//     a numeric `±hhmm` offset; Go's round-trip `Format` check would
//     reject an offset here anyway, because goish's `Format` always
//     emits `Z`, so the observable behaviour is unchanged.
//   * `PeekASN1Tag`'s receiver is `String` (by value) in Go and `&self`
//     here — it does not advance, and goish has no reason to copy.
//
// goishlint:ignore GOISH015 — Go's file is `asn1.go`, which would collide
// with the `asn1/` tag subpackage directory beside it; the module is
// `asn1_file` and the anchor above names the real Go file.
// goishlint:ignore GOISH018 AddASN1Int64, AddASN1Int64WithTag, AddASN1Enum, addASN1Signed, AddASN1Uint64, AddASN1BigInt, AddASN1OctetString, AddASN1GeneralizedTime, AddASN1UTCTime, AddASN1BitString, addBase128Int, isValidOID, AddASN1ObjectIdentifier, AddASN1Boolean, AddASN1NULL, MarshalASN1 — the Builder half; see the note above.
// goishlint:ignore GOISH021 bigOne, defaultUTCTimeFormatStr, generalizedTimeFormatStr — `bigOne` is `big.NewInt(1)`, constructed at its single use site in readASN1BigInt because goish has no const big.Int; the two layout strings are likewise passed as literals where Go's `const` would land after inlining.

#![allow(non_snake_case)]

extern crate alloc;

use super::asn1::{self as asn1_tags, Tag};
use super::builder::Builder;
use super::string::String as CBString;
use crate::encoding::asn1 as encoding_asn1;
use crate::goslice::slice;
use crate::math::big;
use crate::time;
use crate::types::byte;
use crate::{int, int64, uint64, uint32, uint8};

impl Builder {
    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:21-33 AddASN1
    /// Append an ASN.1 object. The object is prefixed with the given tag.
    /// Tags greater than 30 are not supported and result in an error (i.e.
    /// low-tag-number form only). The child builder passed to the
    /// [BuilderContinuation] can be used to build the content of the ASN.1
    /// object.
    pub fn AddASN1<F: FnOnce(&mut Builder)>(&mut self, tag: Tag, f: F) {
        if self.hasError() {
            return;
        }
        // Identifiers with the low five bits set indicate high-tag-number
        // format (two or more octets), which we don't support.
        if tag.0 & 0x1f == 0x1f {
            self.SetError(crate::fmt::Errorf!(
                "cryptobyte: high-tag number identifier octets not supported: 0x%x",
                tag.0
            ));
            return;
        }
        self.AddUint8(tag.0);
        self.addLengthPrefixed(1, true, f);
    }
}

impl CBString {
    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:249-265 ReadASN1Boolean
    /// Decode an ASN.1 BOOLEAN and advance. It reports whether the read
    /// was successful.
    pub fn ReadASN1Boolean(&mut self, out: &mut bool) -> bool {
        let mut bytes = CBString::default();
        if !self.ReadASN1(&mut bytes, asn1_tags::BOOLEAN) || bytes.0.Len() != 1 {
            return false;
        }

        let b: &[byte] = &bytes.0;
        match b[0] {
            0 => *out = false,
            0xff => *out = true,
            _ => return false,
        }

        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:273-296 ReadASN1Integer
    /// Decode an ASN.1 INTEGER into out and advance. Only positive and
    /// zero values can be decoded into `slice<byte>`, and they are
    /// returned as big-endian binary values. Positive values will have
    /// no leading zeroes, and zero will be returned as a single zero
    /// byte. It reports whether the read was successful.
    ///
    /// Go's `out interface{}` type switch is the `ASN1Integer` bound
    /// here; see the file banner.
    pub fn ReadASN1Integer<T: ASN1Integer>(&mut self, out: &mut T) -> bool {
        return T::__readASN1Integer(self, out);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:315-333 readASN1BigInt
    fn readASN1BigInt(&mut self, out: &mut big::Int) -> bool {
        let mut bytes = CBString::default();
        if !self.ReadASN1(&mut bytes, asn1_tags::INTEGER) || !checkASN1Integer(&bytes.0) {
            return false;
        }
        let b: &[byte] = &bytes.0;
        if b[0] & 0x80 == 0x80 {
            // Negative number.
            let mut neg: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(b.len());
            for (_, v) in crate::range!(&bytes.0) {
                neg.push(!*v);
            }
            out.SetBytes(slice::__from_vec(neg));
            let one = big::NewInt(1);
            let sum = out.clone();
            out.Add(&sum, &one);
            let mag = out.clone();
            out.Neg(&mag);
        } else {
            out.SetBytes(bytes.0.clone());
        }
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:335-348 readASN1Bytes
    fn readASN1Bytes(&mut self, out: &mut slice<byte>) -> bool {
        let mut bytes = CBString::default();
        if !self.ReadASN1(&mut bytes, asn1_tags::INTEGER) || !checkASN1Integer(&bytes.0) {
            return false;
        }
        let b: &[byte] = &bytes.0;
        if b[0] & 0x80 == 0x80 {
            return false;
        }
        let mut start: usize = 0;
        while b.len() - start > 1 && b[start] == 0 {
            start += 1;
        }
        *out = slice::__from_vec(b[start..].to_vec());
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:350-356 readASN1Int64
    fn readASN1Int64(&mut self, out: &mut int64) -> bool {
        let mut bytes = CBString::default();
        if !self.ReadASN1(&mut bytes, asn1_tags::INTEGER)
            || !checkASN1Integer(&bytes.0)
            || !asn1Signed(out, &bytes.0)
        {
            return false;
        }
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:373-379 readASN1Uint64
    fn readASN1Uint64(&mut self, out: &mut uint64) -> bool {
        let mut bytes = CBString::default();
        if !self.ReadASN1(&mut bytes, asn1_tags::INTEGER)
            || !checkASN1Integer(&bytes.0)
            || !asn1Unsigned(out, &bytes.0)
        {
            return false;
        }
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:401-404 ReadASN1Int64WithTag
    /// Decode an ASN.1 INTEGER with the given tag into out and advance.
    /// It reports whether the read was successful and resulted in a
    /// value that can be represented in an int64.
    pub fn ReadASN1Int64WithTag(&mut self, out: &mut int64, tag: Tag) -> bool {
        let mut bytes = CBString::default();
        return self.ReadASN1(&mut bytes, tag)
            && checkASN1Integer(&bytes.0)
            && asn1Signed(out, &bytes.0);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:408-419 ReadASN1Enum
    /// Decode an ASN.1 ENUMERATION into out and advance. It reports
    /// whether the read was successful.
    pub fn ReadASN1Enum(&mut self, out: &mut int) -> bool {
        let mut bytes = CBString::default();
        let mut i: int64 = 0;
        if !self.ReadASN1(&mut bytes, asn1_tags::ENUM)
            || !checkASN1Integer(&bytes.0)
            || !asn1Signed(&mut i, &bytes.0)
        {
            return false;
        }
        // Go re-checks `int64(int(i)) != i`; goish's `int` is `int64`, so
        // the conversion is the identity and the check cannot fail.
        *out = i;
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:421-449 readBase128Int
    fn readBase128Int(&mut self, out: &mut int) -> bool {
        let mut ret: int = 0;
        let mut i: int = 0;
        while self.0.Len() > 0 {
            if i == 5 {
                return false;
            }
            // Avoid overflowing int on a 32-bit platform.
            // We don't want different behavior based on the architecture.
            if ret >= 1 << (31 - 7) {
                return false;
            }
            ret <<= 7;
            let one = match self.read(1) {
                None => return false,
                Some(v) => v,
            };
            let b: byte = one[int(0)];

            // ITU-T X.690, section 8.19.2:
            // The subidentifier shall be encoded in the fewest possible octets,
            // that is, the leading octet of the subidentifier shall not have the value 0x80.
            if i == 0 && b == 0x80 {
                return false;
            }

            ret |= int(b & 0x7f);
            if b & 0x80 == 0 {
                *out = ret;
                return true;
            }
            i += 1;
        }
        return false; // truncated
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:453-488 ReadASN1ObjectIdentifier
    /// Decode an ASN.1 OBJECT IDENTIFIER into out and advance. It reports
    /// whether the read was successful.
    pub fn ReadASN1ObjectIdentifier(
        &mut self,
        out: &mut encoding_asn1::ObjectIdentifier,
    ) -> bool {
        let mut bytes = CBString::default();
        if !self.ReadASN1(&mut bytes, asn1_tags::OBJECT_IDENTIFIER) || bytes.0.Len() == 0 {
            return false;
        }

        // In the worst case, we get two elements from the first byte (which is
        // encoded differently) and then every varint is a single byte long.
        let mut components: alloc::vec::Vec<int> =
            alloc::vec![0; usize::try_from(bytes.0.Len() + 1).unwrap_or(0)];

        // The first varint is 40*value1 + value2:
        // According to this packing, value1 can take the values 0, 1 and 2 only.
        // When value1 = 0 or value1 = 1, then value2 is <= 39. When value1 = 2,
        // then there are no restrictions on value2.
        let mut v: int = 0;
        if !bytes.readBase128Int(&mut v) {
            return false;
        }
        if v < 80 {
            components[0] = v / 40;
            components[1] = v % 40;
        } else {
            components[0] = 2;
            components[1] = v - 80;
        }

        let mut i: usize = 2;
        while bytes.0.Len() > 0 {
            if !bytes.readBase128Int(&mut v) {
                return false;
            }
            components[i] = v;
            i += 1;
        }
        components.truncate(i);
        *out = encoding_asn1::ObjectIdentifier(slice::__from_vec(components));
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:492-507 ReadASN1GeneralizedTime
    /// Decode an ASN.1 GENERALIZEDTIME into out and advance. It reports
    /// whether the read was successful.
    pub fn ReadASN1GeneralizedTime(&mut self, out: &mut time::Time) -> bool {
        let mut bytes = CBString::default();
        if !self.ReadASN1(&mut bytes, asn1_tags::GeneralizedTime) {
            return false;
        }
        let t = crate::gostring::string::from_bytes(&bytes.0);
        let (res, err) = time::Parse("20060102150405Z0700", t.clone());
        if !err.IsNil() {
            return false;
        }
        let serialized = res.Format("20060102150405Z0700");
        if serialized != t {
            return false;
        }
        *out = res;
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:513-546 ReadASN1UTCTime
    /// Decode an ASN.1 UTCTime into out and advance. It reports whether
    /// the read was successful.
    pub fn ReadASN1UTCTime(&mut self, out: &mut time::Time) -> bool {
        let mut bytes = CBString::default();
        if !self.ReadASN1(&mut bytes, asn1_tags::UTCTime) {
            return false;
        }
        let t = crate::gostring::string::from_bytes(&bytes.0);

        let mut formatStr = crate::gostring::string::from("060102150405Z0700");
        let (mut res, mut err) = time::Parse(formatStr.clone(), t.clone());
        if !err.IsNil() {
            // Fallback to minute precision if we can't parse second
            // precision. If we are following X.509 or X.690 we shouldn't
            // support this, but we do.
            formatStr = crate::gostring::string::from("0601021504Z0700");
            let (r, e) = time::Parse(formatStr.clone(), t.clone());
            res = r;
            err = e;
        }
        if !err.IsNil() {
            return false;
        }

        let serialized = res.Format(formatStr);
        if serialized != t {
            return false;
        }

        if res.Year() >= 2050 {
            // UTCTime interprets the low order digits 50-99 as 1950-99.
            // This only applies to its use in the X.509 profile.
            // See https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
            res = res.AddDate(-100, 0, 0);
        }
        *out = res;
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:550-568 ReadASN1BitString
    /// Decode an ASN.1 BIT STRING into out and advance. It reports
    /// whether the read was successful.
    pub fn ReadASN1BitString(&mut self, out: &mut encoding_asn1::BitString) -> bool {
        let mut bytes = CBString::default();
        // Go also guards `len(bytes)*8/8 != len(bytes)`, an overflow check
        // for the multiplication below; on a 64-bit target a byte slice
        // long enough to overflow cannot be allocated.
        if !self.ReadASN1(&mut bytes, asn1_tags::BIT_STRING) || bytes.0.Len() == 0 {
            return false;
        }

        let paddingBits: byte = bytes.0[int(0)];
        let rest: &[byte] = &bytes.0;
        let rest = slice::__from_vec(rest[1..].to_vec());
        if paddingBits > 7
            || rest.Len() == 0 && paddingBits != 0
            || rest.Len() > 0 && rest[rest.Len() - 1] & ((1 << paddingBits) - 1) != 0
        {
            return false;
        }

        out.BitLength = rest.Len() * 8 - int(paddingBits);
        out.Bytes = rest;
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:573-585 ReadASN1BitStringAsBytes
    /// Decode an ASN.1 BIT STRING into out and advance. It is an error if
    /// the BIT STRING is not a whole number of bytes. It reports whether
    /// the read was successful.
    pub fn ReadASN1BitStringAsBytes(&mut self, out: &mut slice<byte>) -> bool {
        let mut bytes = CBString::default();
        if !self.ReadASN1(&mut bytes, asn1_tags::BIT_STRING) || bytes.0.Len() == 0 {
            return false;
        }

        let paddingBits: byte = bytes.0[int(0)];
        if paddingBits != 0 {
            return false;
        }
        let b: &[byte] = &bytes.0;
        *out = slice::__from_vec(b[1..].to_vec());
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:590-592 ReadASN1Bytes
    /// Read the contents of a DER-encoded ASN.1 element (not including
    /// tag and length bytes) into out, and advance. The element must
    /// match the given tag. It reports whether the read was successful.
    pub fn ReadASN1Bytes(&mut self, out: &mut slice<byte>, tag: Tag) -> bool {
        let mut child = CBString::default();
        if !self.ReadASN1(&mut child, tag) {
            return false;
        }
        *out = child.0;
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:599-605 ReadASN1
    /// Read the contents of a DER-encoded ASN.1 element (not including tag
    /// and length bytes) into out, and advance. It reports whether the
    /// read was successful and the element had the given tag.
    pub fn ReadASN1(&mut self, out: &mut Self, tag: Tag) -> bool {
        let mut t = Tag::default();
        if !self.ReadAnyASN1(out, &mut t) || t != tag {
            return false;
        }
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:612-618 ReadASN1Element
    /// Read the contents of a DER-encoded ASN.1 element (including tag and
    /// length bytes) into out, and advance. The element must match the
    /// given tag. It reports whether the read was successful.
    ///
    /// Tags greater than 30 are not supported (i.e. low-tag-number format
    /// only).
    pub fn ReadASN1Element(&mut self, out: &mut Self, tag: Tag) -> bool {
        let mut t = Tag::default();
        if !self.ReadAnyASN1Element(out, &mut t) || t != tag {
            return false;
        }
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:625-627 ReadAnyASN1
    /// Read the contents of a DER-encoded ASN.1 element (not including tag
    /// and length bytes) into out, sets outTag to its tag, and advances.
    pub fn ReadAnyASN1(&mut self, out: &mut Self, outTag: &mut Tag) -> bool {
        return self.readASN1(out, Some(outTag), true /* skip header */);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:634-636 ReadAnyASN1Element
    /// Read the contents of a DER-encoded ASN.1 element (including tag and
    /// length bytes) into out, sets outTag to its tag, and advances.
    pub fn ReadAnyASN1Element(&mut self, out: &mut Self, outTag: &mut Tag) -> bool {
        return self.readASN1(out, Some(outTag), false /* include header */);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:640-645 PeekASN1Tag
    /// Report whether the next ASN.1 value on the string starts with the
    /// given tag.
    pub fn PeekASN1Tag(&self, tag: Tag) -> bool {
        if self.0.Len() == 0 {
            return false;
        }
        return Tag(self.0[int(0)]) == tag;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:649-652 SkipASN1
    /// Read and discard an ASN.1 element with the given tag. It reports
    /// whether the operation was successful.
    pub fn SkipASN1(&mut self, tag: Tag) -> bool {
        let mut unused = CBString::default();
        return self.ReadASN1(&mut unused, tag);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:658-667 ReadOptionalASN1
    /// Attempt to read the contents of a DER-encoded ASN.1 element (not
    /// including tag and length bytes) tagged with the given tag into out.
    /// It stores whether an element with the tag was found in outPresent,
    /// unless outPresent is None. It reports whether the read was
    /// successful.
    pub fn ReadOptionalASN1(
        &mut self,
        out: &mut Self,
        outPresent: Option<&mut bool>,
        tag: Tag,
    ) -> bool {
        let present = self.PeekASN1Tag(tag);
        if let Some(p) = outPresent {
            *p = present;
        }
        if present && !self.ReadASN1(out, tag) {
            return false;
        }
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:671-677 SkipOptionalASN1
    /// Advance s over an ASN.1 element with the given tag, or else leave s
    /// unchanged. It reports whether the operation was successful.
    pub fn SkipOptionalASN1(&mut self, tag: Tag) -> bool {
        if !self.PeekASN1Tag(tag) {
            return true;
        }
        let mut unused = CBString::default();
        return self.ReadASN1(&mut unused, tag);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:683-709 ReadOptionalASN1Integer
    /// Attempt to read an optional ASN.1 INTEGER explicitly tagged with tag
    /// into out and advance. If no element with a matching tag is present,
    /// it writes defaultValue into out instead. Otherwise, it behaves like
    /// [ReadASN1Integer].
    pub fn ReadOptionalASN1Integer<T: ASN1Integer + Clone>(
        &mut self,
        out: &mut T,
        tag: Tag,
        defaultValue: T,
    ) -> bool {
        let mut present = false;
        let mut i = CBString::default();
        if !self.ReadOptionalASN1(&mut i, Some(&mut present), tag) {
            return false;
        }
        if !present {
            *out = defaultValue;
            return true;
        }
        if !i.ReadASN1Integer(out) || !i.Empty() {
            return false;
        }
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:715-734 ReadOptionalASN1OctetString
    /// Attempt to read an optional ASN.1 OCTET STRING explicitly tagged
    /// with tag into out and advance. If no element with a matching tag is
    /// present, it sets out to the empty slice instead. It reports whether
    /// the read was successful.
    pub fn ReadOptionalASN1OctetString(
        &mut self,
        out: &mut slice<byte>,
        outPresent: Option<&mut bool>,
        tag: Tag,
    ) -> bool {
        let mut present = false;
        let mut child = CBString::default();
        if !self.ReadOptionalASN1(&mut child, Some(&mut present), tag) {
            return false;
        }
        if let Some(p) = outPresent {
            *p = present;
        }
        if present {
            let mut oct = CBString::default();
            if !child.ReadASN1(&mut oct, asn1_tags::OCTET_STRING) || !child.Empty() {
                return false;
            }
            *out = oct.0;
        } else {
            // Go writes `*out = nil`; `slice<byte>` has no nil, and its
            // zero value is the empty slice, which `len` reads the same.
            *out = slice::__from_vec(alloc::vec::Vec::<byte>::new());
        }
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:740-753 ReadOptionalASN1Boolean
    /// Attempt to read an optional ASN.1 BOOLEAN explicitly tagged with tag
    /// into out and advance. If no element with a matching tag is present,
    /// it sets out to defaultValue instead. It reports whether the read was
    /// successful.
    pub fn ReadOptionalASN1Boolean(
        &mut self,
        out: &mut bool,
        tag: Tag,
        defaultValue: bool,
    ) -> bool {
        let mut present = false;
        let mut child = CBString::default();
        if !self.ReadOptionalASN1(&mut child, Some(&mut present), tag) {
            return false;
        }

        if !present {
            *out = defaultValue;
            return true;
        }

        return child.ReadASN1Boolean(out);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:755-825 readASN1
    fn readASN1(&mut self, out: &mut Self, outTag: Option<&mut Tag>, skipHeader: bool) -> bool {
        let s: &[byte] = &self.0;
        if s.len() < 2 {
            return false;
        }
        let (tag, lenByte) = (s[0], s[1]);

        if tag & 0x1f == 0x1f {
            // ITU-T X.690 section 8.1.2
            //
            // An identifier octet with a tag part of 0x1f indicates a
            // high-tag-number form identifier with two or more octets. We
            // only support tags less than 31 (i.e. low-tag-number form,
            // single octet identifier).
            return false;
        }

        if let Some(t) = outTag {
            *t = Tag(tag);
        }

        // ITU-T X.690 section 8.1.3
        //
        // Bit 8 of the first length byte indicates whether the length is
        // short- or long-form.
        let length: uint32;
        let headerLen: uint32; // length includes headerLen
        if lenByte & 0x80 == 0 {
            // Short-form length (section 8.1.3.4), encoded in bits 1-7.
            length = uint32(lenByte) + 2;
            headerLen = 2;
        } else {
            // Long-form length (section 8.1.3.5). Bits 1-7 encode the
            // number of octets used to encode the length.
            let lenLen = lenByte & 0x7f;
            let mut len32: uint32 = 0;

            if lenLen == 0 || lenLen > 4 || s.len() < (2 + lenLen) as usize {
                return false;
            }

            let mut lenBytes =
                CBString::New(slice::__from_vec(s[2..(2 + lenLen) as usize].to_vec()));
            if !lenBytes.readUnsigned(&mut len32, int(lenLen)) {
                return false;
            }

            // ITU-T X.690 section 10.1 (DER length forms) requires
            // encoding the length with the minimum number of octets.
            if len32 < 128 {
                // Length should have used short-form encoding.
                return false;
            }
            if len32 >> ((lenLen - 1) * 8) == 0 {
                // Leading octet is 0. Length should have been at least one
                // byte shorter.
                return false;
            }

            headerLen = 2 + uint32(lenLen);
            if headerLen + len32 < len32 {
                // Overflow.
                return false;
            }
            length = headerLen + len32;
        }

        let mut raw = slice::__from_vec(alloc::vec::Vec::<byte>::new());
        if !self.ReadBytes(&mut raw, int(length)) {
            return false;
        }
        *out = CBString::New(raw);
        if skipHeader && !out.Skip(int(headerLen)) {
            panic!("cryptobyte: internal error");
        }

        return true;
    }
}

// go: none — the static spelling of Go's `ReadASN1Integer(out
// interface{})` type switch. One impl per arm of that switch; see the
// file banner for why the `*int`/`*int8`/… and `*uint`/… arms collapse
// to a single impl each.
pub trait ASN1Integer: Sized {
    // go: none - the trait method behind the type switch.
    fn __readASN1Integer(s: &mut CBString, out: &mut Self) -> bool;
}

// go: none — the `case *big.Int` arm.
impl ASN1Integer for big::Int {
    // go: none - see the impl anchor above.
    fn __readASN1Integer(s: &mut CBString, out: &mut Self) -> bool {
        return s.readASN1BigInt(out);
    }
}

// go: none — the `case *[]byte` arm.
impl ASN1Integer for slice<byte> {
    // go: none - see the impl anchor above.
    fn __readASN1Integer(s: &mut CBString, out: &mut Self) -> bool {
        return s.readASN1Bytes(out);
    }
}

// go: none — the `case *int, *int8, *int16, *int32, *int64` arm.
impl ASN1Integer for int64 {
    // go: none - see the impl anchor above.
    fn __readASN1Integer(s: &mut CBString, out: &mut Self) -> bool {
        return s.readASN1Int64(out);
    }
}

// go: none — the `case *uint, *uint8, *uint16, *uint32, *uint64` arm.
impl ASN1Integer for uint64 {
    // go: none - see the impl anchor above.
    fn __readASN1Integer(s: &mut CBString, out: &mut Self) -> bool {
        return s.readASN1Uint64(out);
    }
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:358-371 asn1Signed
fn asn1Signed(out: &mut int64, n: &slice<byte>) -> bool {
    let b: &[byte] = n;
    let length = b.len();
    if length > 8 {
        return false;
    }
    let mut i: usize = 0;
    while i < length {
        *out <<= 8;
        *out |= int64(b[i]);
        i += 1;
    }
    // Shift up and down in order to sign extend the result.
    *out <<= 64 - uint8(uint32(length)) * 8;
    *out >>= 64 - uint8(uint32(length)) * 8;
    return true;
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:381-396 asn1Unsigned
fn asn1Unsigned(out: &mut uint64, n: &slice<byte>) -> bool {
    let b: &[byte] = n;
    let length = b.len();
    if length > 9 || length == 9 && b[0] != 0 {
        // Too large for uint64.
        return false;
    }
    if b[0] & 0x80 != 0 {
        // Negative number.
        return false;
    }
    let mut i: usize = 0;
    while i < length {
        *out <<= 8;
        *out |= uint64(b[i]);
        i += 1;
    }
    return true;
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:298-311 checkASN1Integer
fn checkASN1Integer(bytes: &slice<byte>) -> bool {
    let b: &[byte] = bytes;
    if b.is_empty() {
        // An INTEGER is encoded with at least one octet.
        return false;
    }
    if b.len() == 1 {
        return true;
    }
    if b[0] == 0 && b[1] & 0x80 == 0 || b[0] == 0xff && b[1] & 0x80 == 0x80 {
        // Value is not minimally encoded.
        return false;
    }
    return true;
}

// Keep the uint8 import honest: tags are one.
const _: fn(u32) -> byte = uint8;
