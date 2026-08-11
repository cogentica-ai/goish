// go: file vendor/golang.org/x/crypto/cryptobyte/asn1.go decls: Builder.AddASN1, String.readASN1Bytes, String.ReadASN1, String.ReadAnyASN1, String.readASN1, checkASN1Integer
//
// The ASN.1 DER layer over Builder and String.
//
// **Partial port.** Go's asn1.go is 825 lines covering BOOLEAN, BIT
// STRING, OCTET STRING, OBJECT IDENTIFIER, UTCTime/GeneralizedTime,
// optional/explicit tagging, and a `reflect`-driven
// `ReadASN1Integer(interface{})`. This file ports the INTEGER/SEQUENCE
// path — everything `crypto/ecdsa`'s encodeSignature and parseSignature
// touch (ecdsa.go:468-548) — and nothing else yet. What is here is
// verbatim; the rest is absent, not stubbed.
//
// Deviations:
//
//   * Go's `ReadASN1Integer(out interface{})` dispatches on the pointee
//     type with a type switch and `reflect`. Only the `*[]byte` arm is
//     ported, as `ReadASN1Integer(&mut slice<byte>)`; it forwards to
//     `readASN1Bytes` exactly as Go's arm does. The integer and big.Int
//     arms need their own entry points when a caller wants them —
//     `reflect`-driven dispatch has no goish equivalent.
//   * `readASN1`'s `outTag *asn1.Tag` is nil-able in Go; here it is
//     `Option<&mut Tag>`.
//
// goishlint:ignore GOISH015 — Go's file is `asn1.go`, which would collide
// with the `asn1/` tag subpackage directory beside it; the module is
// `asn1_file` and the anchor above names the real Go file.
// goishlint:ignore GOISH018 — partial port, scoped to the INTEGER and
// SEQUENCE path; see the note above.
// goishlint:ignore GOISH021 — `bigOne`, `defaultUTCTimeFormatStr` and
// `generalizedTimeFormatStr` belong to the big.Int and time paths, which
// are part of the same not-yet-ported remainder.

#![allow(non_snake_case)]

extern crate alloc;

use super::asn1::{self as asn1_tags, Tag};
use super::builder::Builder;
use super::string::String as CBString;
use crate::goslice::slice;
use crate::types::byte;
use crate::{int, uint32, uint8};

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
    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:401-415 readASN1Bytes
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

    // go: none — Go's `ReadASN1Integer(out interface{})` type-switches on
    // the pointee; this is its `*[]byte` arm, the one crypto/ecdsa uses.
    // The others are absent rather than wrong (see the file header).
    pub fn ReadASN1Integer(&mut self, out: &mut slice<byte>) -> bool {
        return self.readASN1Bytes(out);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:707-714 ReadASN1
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

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:729-732 ReadAnyASN1
    /// Read the contents of a DER-encoded ASN.1 element (not including tag
    /// and length bytes) into out, sets outTag to its tag, and advances.
    pub fn ReadAnyASN1(&mut self, out: &mut Self, outTag: &mut Tag) -> bool {
        return self.readASN1(out, Some(outTag), true /* skip header */);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:772-846 readASN1
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

// go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1.go:848-862 checkASN1Integer
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
