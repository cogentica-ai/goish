// go: file encoding/asn1/common.go decls: parseFieldParameters
//
// The struct-tag interpreter shared by asn1's encode and decode paths.
//
// Scope: `parseFieldParameters` only. `getUniversalType`, the other
// function in common.go, switches on a `reflect.Type` and belongs with
// the reflective layer; `fieldParameters` itself is a type, not a decl
// port_coverage counts.
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
    TagGeneralizedTime, TagIA5String, TagNumericString, TagPrintableString, TagUTCTime,
    TagUTF8String,
};
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

// go: sdk 1.25.5 encoding/asn1/common.go:92-142 parseFieldParameters
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
