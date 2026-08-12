// go: file encoding/asn1/common.go decls: parseFieldParameters, getUniversalType
//
// The struct-tag interpreter shared by asn1's encode and decode paths.
//
// Both of common.go's functions. `parseFieldParameters` is plain string
// work; `getUniversalType` switches on a `reflect.Type` and became
// portable once all six types it matches by identity gained a
// `reflect::Reflect` impl (8bf3e78, 78ec1f5).
//
// This lands ahead of that layer deliberately. Go's marshal and unmarshal
// both start by parsing a field's tag string, and the parse is plain
// string work with no reflect in it — so it can be checked against Go on
// its own, which is what examples/asn1_marshal_smoke.rs does across all
// 32 tag forms.
//
// Deviations from common[go] @ Go 1.25.5:
//
//   * Go's `defaultValue *int64` and `tag *int` are nilable pointers
//     whose nil-ness is load-bearing — `explicit` allocates a zero tag
//     only when one is not already set. goish spells them
//     `Option<int64>` / `Option<int>`, which is the same three-state
//     logic without a pointer.
//   * Go returns the struct by named result and mutates it; goish builds
//     a `ret` local and returns it, which reads the same.

#![allow(non_snake_case)]

extern crate alloc;

use super::{
    TagBitString, TagBoolean, TagEnum, TagGeneralizedTime, TagIA5String, TagInteger,
    TagNumericString, TagOID, TagOctetString, TagPrintableString, TagSequence, TagSet,
    TagUTCTime, TagUTF8String,
};
use crate::reflect::{Kind, Type};
use crate::gostring::string;
use crate::int64;
use crate::types::int;
use crate::{strconv, strings};

// Go: common.go:74-88
//   type fieldParameters struct { optional, explicit, application, private bool
//                                 defaultValue *int64; tag *int
//                                 stringType, timeType int; set, omitEmpty bool }
/// The parsed representation of a tag string from a structure field.
///
/// Invariant, carried over from Go: if `explicit` is set, `tag` is `Some`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct fieldParameters {
    /// true iff the field is OPTIONAL
    pub optional: bool,
    /// true iff an EXPLICIT tag is in use.
    pub explicit: bool,
    /// true iff an APPLICATION tag is in use.
    pub application: bool,
    /// true iff a PRIVATE tag is in use.
    pub private: bool,
    /// a default value for INTEGER typed fields (maybe None).
    pub defaultValue: Option<int64>,
    /// the EXPLICIT or IMPLICIT tag (maybe None).
    pub tag: Option<int>,
    /// the string tag to use when marshaling.
    pub stringType: int,
    /// the time tag to use when marshaling.
    pub timeType: int,
    /// true iff this should be encoded as a SET
    pub set: bool,
    /// true iff this should be omitted if empty when marshaling.
    pub omitEmpty: bool,
}

// go: sdk 1.25.5 encoding/asn1/common.go:94-147 parseFieldParameters
/// Given a tag string with the format specified in the package comment,
/// parse it into a [`fieldParameters`], ignoring unknown parts of the
/// string.
pub fn parseFieldParameters<S: Into<string>>(str: S) -> fieldParameters {
    let mut ret = fieldParameters::default();
    let mut str = str.into();

    while str.Len() > 0 {
        let (part, rest, _) = strings::Cut(str.clone(), ",");
        str = rest;

        let p = part.as_bytes();
        if p == b"optional" {
            ret.optional = true;
        } else if p == b"explicit" {
            ret.explicit = true;
            if ret.tag.is_none() {
                ret.tag = Some(0);
            }
        } else if p == b"generalized" {
            ret.timeType = TagGeneralizedTime;
        } else if p == b"utc" {
            ret.timeType = TagUTCTime;
        } else if p == b"ia5" {
            ret.stringType = TagIA5String;
        } else if p == b"printable" {
            ret.stringType = TagPrintableString;
        } else if p == b"numeric" {
            ret.stringType = TagNumericString;
        } else if p == b"utf8" {
            ret.stringType = TagUTF8String;
        } else if strings::HasPrefix(part.clone(), "default:") {
            // Go: strconv.ParseInt(part[8:], 10, 64)
            let (i, err) = strconv::ParseInt(tail(&part, 8), 10, 64);
            if err == crate::nil {
                ret.defaultValue = Some(int64(i));
            }
        } else if strings::HasPrefix(part.clone(), "tag:") {
            // Go: strconv.Atoi(part[4:])
            let (i, err) = strconv::Atoi(tail(&part, 4));
            if err == crate::nil {
                ret.tag = Some(i);
            }
        } else if p == b"set" {
            ret.set = true;
        } else if p == b"application" {
            ret.application = true;
            if ret.tag.is_none() {
                ret.tag = Some(0);
            }
        } else if p == b"private" {
            ret.private = true;
            if ret.tag.is_none() {
                ret.tag = Some(0);
            }
        } else if p == b"omitempty" {
            ret.omitEmpty = true;
        }
    }

    return ret;
}

// go: none — goish idiom: Go slices the string as `part[8:]`. goish's
// `string` indexes by byte, so the tail is taken explicitly.
fn tail(s: &string, n: usize) -> string {
    let b = s.as_bytes();
    if b.len() <= n {
        return string::default();
    }
    return string::from_bytes(&b[n..]);
}

// go: sdk 1.25.5 encoding/asn1/common.go:149-185 getUniversalType
/// Given a reflected type, return the default tag number and expected
/// compound flag.
///
/// Returns `(matchAny, tagNumber, isCompound, ok)`.
///
/// Deviations:
///
///   * Go's first switch compares `reflect.Type` values against six
///     package-level `reflect.TypeOf(...)` vars. goish's `reflect::Type`
///     compares by `(kind, name)`, so the identities are matched by name —
///     the same test, since each of the six is a distinct named type.
///   * Go's `bigIntType` is `reflect.TypeOf(new(big.Int))`, a *pointer*,
///     because Go's asn1 stores `*big.Int`. goish's `big::Int` is a value
///     type, so the identity matched here is the struct itself.
///   * The `strings.HasSuffix(t.Name(), "SET")` branch selects TagSet for
///     a *named* slice type such as `type RDNSequenceSET []T`. goish has
///     no named slice types yet — `slice<T>`'s descriptor carries a
///     generic name — so that branch is reachable only once a port
///     declares one. It is ported as written rather than dropped.
pub fn getUniversalType(t: &Type) -> (bool, int, bool, bool) {
    let name = t.Name();
    let n = name.as_bytes();

    // Go: switch t { case rawValueType: … case bigIntType: … }
    if n == b"RawValue" {
        return (true, -1, false, true);
    }
    if n == b"ObjectIdentifier" {
        return (false, TagOID, false, true);
    }
    if n == b"BitString" {
        return (false, TagBitString, false, true);
    }
    if n == b"time.Time" {
        return (false, TagUTCTime, false, true);
    }
    if n == b"Enumerated" {
        return (false, TagEnum, false, true);
    }
    if n == b"Int" && t.Kind() == Kind::Struct {
        return (false, TagInteger, false, true);
    }

    // Go: switch t.Kind() { … }
    match t.Kind() {
        Kind::Bool => {
            return (false, TagBoolean, false, true);
        }
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 => {
            return (false, TagInteger, false, true);
        }
        Kind::Struct => {
            return (false, TagSequence, true, true);
        }
        Kind::Slice => {
            if t.Elem().Kind() == Kind::Uint8 {
                return (false, TagOctetString, false, true);
            }
            if crate::strings::HasSuffix(name.clone(), "SET") {
                return (false, TagSet, true, true);
            }
            return (false, TagSequence, true, true);
        }
        Kind::String => {
            return (false, TagPrintableString, false, true);
        }
        _ => {}
    }

    // Go: the switch has no default; control falls through to here.
    return (false, 0, false, false);
}
