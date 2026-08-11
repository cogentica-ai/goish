// go: file vendor/golang.org/x/crypto/cryptobyte/asn1/asn1.go decls: Tag.Constructed, Tag.ContextSpecific
//
// Package asn1 contains supporting types for parsing and building ASN.1
// messages with the cryptobyte package.
//
// Deviation: Go's `type Tag uint8` is a newtype here so the two methods
// have somewhere to live; the constants keep their Go names and values.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::types::uint8;

// Go: asn1.go:12 — `type Tag uint8`
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Tag(pub uint8);

// Go: asn1.go:14-17 — `const ( classConstructed = 0x20; classContextSpecific = 0x80 )`
const classConstructed: uint8 = 0x20;
const classContextSpecific: uint8 = 0x80;

impl Tag {
    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1/asn1.go:20-22 Constructed
    /// Return t with the constructed class bit set.
    pub fn Constructed(&self) -> Tag {
        return Tag(self.0 | classConstructed);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/asn1/asn1.go:25-27 ContextSpecific
    /// Return t with the context-specific class bit set.
    pub fn ContextSpecific(&self) -> Tag {
        return Tag(self.0 | classContextSpecific);
    }
}

// Go: asn1.go:29-46 — the universal tag constants.
pub const BOOLEAN: Tag = Tag(1);
pub const INTEGER: Tag = Tag(2);
pub const BIT_STRING: Tag = Tag(3);
pub const OCTET_STRING: Tag = Tag(4);
pub const NULL: Tag = Tag(5);
pub const OBJECT_IDENTIFIER: Tag = Tag(6);
pub const ENUM: Tag = Tag(10);
pub const UTF8String: Tag = Tag(12);
pub const SEQUENCE: Tag = Tag(16 | classConstructed);
pub const SET: Tag = Tag(17 | classConstructed);
pub const PrintableString: Tag = Tag(19);
pub const T61String: Tag = Tag(20);
pub const IA5String: Tag = Tag(22);
pub const UTCTime: Tag = Tag(23);
pub const GeneralizedTime: Tag = Tag(24);
pub const GeneralString: Tag = Tag(27);
