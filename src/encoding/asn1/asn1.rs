// go: file encoding/asn1/asn1.go decls: parseUTCTime, parseGeneralizedTime, parseSequenceOf, invalidLength, parseField, setDefaultValue, Unmarshal, invalidUnmarshalError.Error, UnmarshalWithParams
//
// The DER *decoding* half of encoding/asn1 — the reflective layer of
// asn1.go that mod.rs deliberately left out.
//
// mod.rs holds the non-reflective readers (parseBool, parseInt64,
// parseBitString, parseObjectIdentifier, parseTagAndLength, the six
// string parsers …). Those were checked against Go on their own. What is
// here is the layer above them: the dispatch that decides *which* of
// those to call for a given Go type, and writes the result back into the
// caller's value.
//
// ─── The one deviation that shapes this whole file ────────────────────
//
// Go's `parseField(v reflect.Value, …)` writes *through* `v`: a
// `reflect.Value` there is a (type, pointer, flags) triple, so
// `v.SetInt(n)` mutates the struct field the Value was derived from, and
// `val.Field(i)` yields another addressable Value pointing into the same
// object.
//
// goish's `reflect::Value` is an **owned enum** — a copy of the data,
// with no pointer and no addressability (the reason is stated in
// reflect/mod.rs above the enum, and the setter consequences in
// reflect/value.rs). So the port takes `&mut Value` and fills a Value
// *tree*, and `Unmarshal` converts that tree back into the caller's `T`
// with `FromReflectValue` — the mirror of the `Reflect` impl `Marshal`
// reads on the way out. Concretely:
//
//   Go                              goish
//   ------------------------------  --------------------------------
//   parseField(v, …)                parseField(&mut v, …)
//   val.Field(i)  (addressable)     fieldMut(v, i) -> &mut Value
//   val.SetInt(n) / SetBool / …     the same methods, on &mut Value
//   v.Set(newSlice)                 v.Set(newSlice)
//   reflect.Zero(elemType)          zeroOf(&elemType)
//
// Everything else follows Go line for line.
//
// ─── The other deviations, in full ────────────────────────────────────
//
//   * `Unmarshal(b []byte, val any)` is `Unmarshal(b, val: &mut T)` with
//     `T: Reflect + FromReflectValue`. Go's `any` is a non-nil pointer;
//     `&mut T` is that minus the nil case, which is why
//     `invalidUnmarshalError` below is declared (Go has the type) but
//     unreachable — there is no nil `&mut T` to report. The same reason
//     `Marshal` is `Marshal(val: &impl Reflect)`: `Reflect` is not object
//     safe, so one signature cannot serve both the typed and erased
//     forms.
//
//   * `parseSequenceOf` drops Go's `saferio.SliceCapWithSize` guard.
//     That guard bounds a *pre-allocation* by `elemType.Size()` so a
//     hostile length cannot make Go reserve gigabytes before reading the
//     elements. goish's `reflect::Type` has no `Size()` — it is a
//     descriptor, not a layout — and the port allocates element by
//     element as it parses rather than reserving up front, so the
//     over-allocation the guard exists to prevent cannot happen here.
//     The element *count* is still bounded by the input length, exactly
//     as in Go: the counting loop that precedes it walks real TLVs.
//
//   * `parseField`'s integer arm switches on `val.Type().Size() == 4` to
//     choose parseInt32 over parseInt64. With no `Size()`, the port
//     switches on `Kind::Int32`, which is the same test: Int32 is the
//     only 4-byte signed kind Go reaches there.
//
//   * Go's `switch v.Addr().Interface().(type)` recovers the concrete Go
//     type behind the Value. goish cannot round-trip `Interface()` back
//     to a type, so — exactly as `makeBody` already does on the encode
//     side — the seven identities are matched by reflected type *name*.
//     Each is a distinct named type, so the test is the same one.
//
//   * KNOWN DIVERGENCE — `parseUTCTime` and `parseGeneralizedTime`
//     reject a *numeric* zone offset (`910506234540-0700`,
//     `20100102030405+0607`) where Go accepts it. Both bodies are
//     verbatim; the difference is under them, in `time`: goish's `Time`
//     carries no Location (`Zone()` is hard-wired to `("UTC", 0)`), so
//     an offset cannot be retained, and Go's own re-`Format`-and-compare
//     guard — which both functions run — could never pass for one. The
//     `Z` forms, the minute-precision UTCTime fallback, the >= 2050
//     century rollback and fractional seconds all match Go exactly.
//     RFC 5280 §4.1.2.5.1/2 requires `Z` in certificates, so no
//     conforming certificate reaches it. Pinned by two explicit
//     assertions in examples/x509_keys_smoke.rs rather than left
//     untested.
//
//   * The ANY arm (`fieldType.Kind() == Interface`) is ported as written
//     and is reachable — goish's `Any` reflects as `Kind::Interface`. It
//     does not *round-trip*, though: `Unmarshal`'s write-back needs
//     `FromReflectValue for goany::Any`, which does not exist. A struct
//     with an `any` field therefore parses and then fails at the
//     write-back with a type-mismatch error rather than silently
//     producing a zero. Ports that need it should add that impl.
//
// goishlint:ignore GOISH018 parseBool, checkInteger, parseInt64, parseInt32, parseBigInt, At, RightAlign, parseBitString, Equal, String, parseObjectIdentifier, parseBase128Int, parseNumericString, isNumeric, parsePrintableString, isPrintable, parseIA5String, parseT61String, parseUTF8String, parseBMPString, parseTagAndLength, canHaveDefaultValue — asn1.go's non-reflective half. Those are ported, in this package's mod.rs (which predates the one-.rs-per-.go split); this file is asn1.go's reflective half only. Named individually so a genuinely dropped decode function still shows up.
// goishlint:ignore GOISH021 StructuralError, SyntaxError, bigOne, BitString, NullRawValue, NullBytes, ObjectIdentifier, Enumerated, Flag, asteriskFlag, ampersandFlag, allowAsterisk, rejectAsterisk, allowAmpersand, rejectAmpersand, RawValue, RawContent — same split: asn1.go's type surface lives in mod.rs alongside the functions that use it. `asteriskFlag`/`ampersandFlag` and their four constants are modelled there as two `bool` parameters on `isPrintable`, which is the whole of what Go's two one-member enums do.
// goishlint:ignore GOISH021 bitStringType, objectIdentifierType, enumeratedType, flagType, timeType, rawValueType, rawContentsType, bigIntType — Go's asn1.go:688-697 caches eight `reflect.TypeFor[T]()` vars purely to compare type identity in the switch above. goish has no `TypeFor`, and compares identity by `reflect::Type` name (the idiom common.rs's getUniversalType already uses), so there is nothing to cache.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{
    canHaveDefaultValue, fieldParameters, getUniversalType, parseFieldParameters, structural,
    syntax, BitString, ClassApplication, ClassContextSpecific, ClassPrivate, ClassUniversal,
    Enumerated, Flag, ObjectIdentifier, ParseBMPString, ParseBitString, ParseBool, ParseIA5String,
    ParseInt32, ParseInt64, ParseNumericString, ParseObjectIdentifier, ParsePrintableString,
    ParseT61String, ParseTagAndLength, ParseUTF8String, RawContent, RawValue, TagAndLength,
    TagBMPString, TagBitString, TagBoolean, TagGeneralString, TagGeneralizedTime, TagIA5String,
    TagInteger, TagNumericString, TagOID, TagOctetString, TagPrintableString, TagSet, TagT61String,
    TagUTCTime, TagUTF8String,
};
use crate::errors::{error, nil, ErrorTrait};
use crate::fmt;
use crate::goslice::slice;
use crate::gostring::string;
use crate::math::big;
use crate::reflect::{FromReflectValue, Kind, Reflect, Type, Value};
use crate::time;
use crate::types::byte;
use crate::{int, int64};

// ─── UTCTime / GeneralizedTime (asn1.go:333) ──────────────────────────

// go: sdk 1.25.5 encoding/asn1/asn1.go:335-359 parseUTCTime
/// Parse an ASN.1 UTCTime.
pub fn ParseUTCTime(bytes: slice<byte>) -> (time::Time, error) {
    // Go: s := string(bytes)
    let s = string::from_bytes(&bytes.clone().__into_vec());

    // Go: formatStr := "0601021504Z0700"
    let mut formatStr = string::from_static("0601021504Z0700");
    let (mut ret, mut err) = time::Parse(formatStr.clone(), s.clone());
    if err != nil {
        formatStr = string::from_static("060102150405Z0700");
        let (r, e) = time::Parse(formatStr.clone(), s.clone());
        ret = r;
        err = e;
    }
    if err != nil {
        return (ret, err);
    }

    // Go: if serialized := ret.Format(formatStr); serialized != s { … }
    let serialized = ret.Format(formatStr);
    if serialized != s {
        return (
            ret,
            fmt::Errorf!(
                "asn1: time did not serialize back to the original value and may be invalid: given %q, but serialized as %q",
                s,
                serialized
            ),
        );
    }

    // Go: if ret.Year() >= 2050 { ret = ret.AddDate(-100, 0, 0) }
    //
    // UTCTime only encodes times prior to 2050.
    // See https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
    if ret.Year() >= 2050 {
        ret = ret.AddDate(-100, 0, 0);
    }

    return (ret, nil);
}

// go: sdk 1.25.5 encoding/asn1/asn1.go:363-376 parseGeneralizedTime
/// Parse the GeneralizedTime from the given byte slice and return the
/// resulting time.
pub fn ParseGeneralizedTime(bytes: slice<byte>) -> (time::Time, error) {
    // Go: const formatStr = "20060102150405.999999999Z0700"
    let formatStr = string::from_static("20060102150405.999999999Z0700");
    let s = string::from_bytes(&bytes.clone().__into_vec());

    let (ret, err) = time::Parse(formatStr.clone(), s.clone());
    if err != nil {
        return (ret, err);
    }

    // Go: if serialized := ret.Format(formatStr); serialized != s { … }
    let serialized = ret.Format(formatStr);
    if serialized != s {
        return (
            ret,
            fmt::Errorf!(
                "asn1: time did not serialize back to the original value and may be invalid: given %q, but serialized as %q",
                s,
                serialized
            ),
        );
    }

    return (ret, nil);
}

// ─── invalidLength (asn1.go:699) ──────────────────────────────────────

// go: sdk 1.25.5 encoding/asn1/asn1.go:702-704 invalidLength
/// Report whether `offset + length > sliceLength`, or if the addition
/// would overflow.
///
/// Go relies on Go's wrapping signed addition to detect the overflow
/// (`offset+length < offset`); Rust panics on signed overflow in debug
/// builds, so the sum is taken with `wrapping_add`. The test is the same.
pub fn invalidLength(offset: int, length: int, sliceLength: int) -> bool {
    let sum = offset.wrapping_add(length);
    return sum < offset || sum > sliceLength;
}

// ─── parseSequenceOf (asn1.go:629) ────────────────────────────────────

// go: sdk 1.25.5 encoding/asn1/asn1.go:632-687 parseSequenceOf
/// Used for SEQUENCE OF and SET OF values. Parses a number of ASN.1
/// values out of `bytes` and returns them as a slice `Value` of
/// `sliceType`.
pub fn parseSequenceOf(bytes: slice<byte>, sliceType: &Type, elemType: &Type) -> (Value, error) {
    let (matchAny, expectedTag, compoundType, ok) = getUniversalType(elemType);
    if !ok {
        return (Value::Invalid, structural("unknown Go type for slice"));
    }

    // First we iterate over the input and count the number of elements,
    // checking that the types are correct in each case.
    let mut numElements: int = 0;
    let n = bytes.Len();
    let mut offset: int = 0;
    while offset < n {
        let (mut t, off, err) = ParseTagAndLength(bytes.clone(), offset);
        if err != nil {
            return (Value::Invalid, err);
        }
        offset = off;
        // Go: switch t.tag { case TagIA5String, …: t.tag = TagPrintableString … }
        //
        // We pretend that various other string types are PRINTABLE
        // STRINGs so that a sequence of them can be parsed into a
        // []string. Likewise, both time types are treated the same.
        match t.tag {
            TagIA5String | TagGeneralString | TagT61String | TagUTF8String | TagNumericString
            | TagBMPString => {
                t.tag = TagPrintableString;
            }
            TagGeneralizedTime | TagUTCTime => {
                t.tag = TagUTCTime;
            }
            _ => {}
        }

        if !matchAny
            && (t.class != ClassUniversal || t.isCompound != compoundType || t.tag != expectedTag)
        {
            return (Value::Invalid, structural("sequence tag mismatch"));
        }
        if invalidLength(offset, t.length, n) {
            return (Value::Invalid, syntax("truncated sequence"));
        }
        offset += t.length;
        numElements += 1;
    }

    // Go: elemSize := uint64(elemType.Size()); safeCap := saferio.…
    //
    // Dropped — see the banner. The count above is already bounded by
    // the input, and the loop below allocates as it parses.
    let mut items: Vec<Value> = Vec::new();
    let params = fieldParameters::default();
    let mut offset: int = 0;
    let mut i: int = 0;
    while i < numElements {
        // Go: ret = reflect.Append(ret, reflect.Zero(elemType))
        items.push(zeroOf(elemType));
        // Go: offset, err = parseField(ret.Index(i), bytes, offset, params)
        let idx = i as usize;
        let (off, err) = parseField(&mut items[idx], bytes.clone(), offset, &params);
        if err != nil {
            return (Value::Invalid, err);
        }
        offset = off;
        i += 1;
    }

    // Go: ret = reflect.MakeSlice(sliceType, 0, safeCap) — the result
    // carries `sliceType`, name included, so a named slice type stays
    // named. goish spells "named, non-struct" as `Value::Named`.
    let elem_type = match sliceType.__elem_fn() {
        Some(f) => f,
        None => return (Value::Invalid, structural("unknown Go type for slice")),
    };
    let ret = Value::Slice { elem_type, items };
    if sliceType.Name().Len() > 0 {
        return (
            Value::Named {
                ty: *sliceType,
                inner: Box::new(ret),
            },
            nil,
        );
    }
    return (ret, nil);
}

// ─── parseField (asn1.go:706) ─────────────────────────────────────────

// go: sdk 1.25.5 encoding/asn1/asn1.go:709-1034 parseField
/// The main parsing function. Given a byte slice and an offset into it,
/// parse a suitable ASN.1 value out and store it in the given `Value`.
pub fn parseField(
    v: &mut Value,
    bytes: slice<byte>,
    initOffset: int,
    params: &fieldParameters,
) -> (int, error) {
    let mut offset = initOffset;
    let fieldType = v.Type();
    let blen = bytes.Len();

    // If we have run out of data, it may be that there are optional
    // elements at the end.
    if offset == blen {
        if !setDefaultValue(v, params) {
            return (offset, syntax("sequence truncated"));
        }
        return (offset, nil);
    }

    // Deal with the ANY type.
    if fieldType.Kind() == Kind::Interface && fieldType.NumField() == 0 {
        let (t, off, err) = ParseTagAndLength(bytes.clone(), offset);
        offset = off;
        if err != nil {
            return (offset, err);
        }
        if invalidLength(offset, t.length, blen) {
            return (offset, syntax("data truncated"));
        }
        let mut result = Value::Invalid;
        let mut err: error = nil;
        if !t.isCompound && t.class == ClassUniversal {
            let innerBytes = bytes.slice(offset, offset + t.length);
            match t.tag {
                TagBoolean => {
                    let (x, e) = ParseBool(innerBytes);
                    result = Value::Bool(x);
                    err = e;
                }
                TagPrintableString => {
                    let (x, e) = ParsePrintableString(innerBytes);
                    result = Value::String(x);
                    err = e;
                }
                TagNumericString => {
                    let (x, e) = ParseNumericString(innerBytes);
                    result = Value::String(x);
                    err = e;
                }
                TagIA5String => {
                    let (x, e) = ParseIA5String(innerBytes);
                    result = Value::String(x);
                    err = e;
                }
                TagT61String => {
                    let (x, e) = ParseT61String(innerBytes);
                    result = Value::String(x);
                    err = e;
                }
                TagUTF8String => {
                    let (x, e) = ParseUTF8String(innerBytes);
                    result = Value::String(x);
                    err = e;
                }
                TagInteger => {
                    let (x, e) = ParseInt64(innerBytes);
                    result = Value::Int(x);
                    err = e;
                }
                TagBitString => {
                    let (x, e) = ParseBitString(innerBytes);
                    result = Reflect::__reflect_value(&x);
                    err = e;
                }
                TagOID => {
                    let (x, e) = ParseObjectIdentifier(innerBytes);
                    result = Reflect::__reflect_value(&x);
                    err = e;
                }
                TagUTCTime => {
                    let (x, e) = ParseUTCTime(innerBytes);
                    result = Reflect::__reflect_value(&x);
                    err = e;
                }
                TagGeneralizedTime => {
                    let (x, e) = ParseGeneralizedTime(innerBytes);
                    result = Reflect::__reflect_value(&x);
                    err = e;
                }
                TagOctetString => {
                    result = Reflect::__reflect_value(&innerBytes);
                }
                TagBMPString => {
                    let (x, e) = ParseBMPString(innerBytes);
                    result = Value::String(x);
                    err = e;
                }
                _ => {
                    // If we don't know how to handle the type, we just
                    // leave Value as nil.
                }
            }
        }
        offset += t.length;
        if err != nil {
            return (offset, err);
        }
        if result.IsValid() {
            v.Set(result);
        }
        return (offset, nil);
    }

    let (mut t, off, err) = ParseTagAndLength(bytes.clone(), offset);
    offset = off;
    if err != nil {
        return (offset, err);
    }
    if params.explicit {
        let mut expectedClass = ClassContextSpecific;
        if params.application {
            expectedClass = ClassApplication;
        }
        if offset == blen {
            return (offset, structural("explicit tag has no child"));
        }
        if t.class == expectedClass
            && t.tag == params.tag.unwrap_or(0)
            && (t.length == 0 || t.isCompound)
        {
            if fieldType.Name().as_bytes() == b"RawValue" {
                // The inner element should not be parsed for RawValues.
            } else if t.length > 0 {
                let (t2, off2, err2) = ParseTagAndLength(bytes.clone(), offset);
                t = t2;
                offset = off2;
                if err2 != nil {
                    return (offset, err2);
                }
            } else {
                if fieldType.Name().as_bytes() != b"Flag" {
                    return (
                        offset,
                        structural("zero length explicit tag was not an asn1.Flag"),
                    );
                }
                v.SetBool(true);
                return (offset, nil);
            }
        } else {
            // The tags didn't match, it might be an optional element.
            let ok = setDefaultValue(v, params);
            if ok {
                return (initOffset, nil);
            }
            return (offset, structural("explicitly tagged member didn't match"));
        }
    }

    let (matchAny, universalTagIn, compoundType, ok1) = getUniversalType(&fieldType);
    if !ok1 {
        return (
            offset,
            fmt::Errorf!(
                "asn1: structure error: unknown Go type: %v",
                fieldType.String()
            ),
        );
    }
    let mut universalTag = universalTagIn;

    // Special case for strings: all the ASN.1 string types map to the Go
    // type string. getUniversalType returns the tag for PrintableString
    // when it sees a string, so if we see a different string type on the
    // wire, we change the universal type to match.
    if universalTag == TagPrintableString {
        if t.class == ClassUniversal {
            match t.tag {
                TagIA5String | TagGeneralString | TagT61String | TagUTF8String
                | TagNumericString | TagBMPString => {
                    universalTag = t.tag;
                }
                _ => {}
            }
        } else if params.stringType != 0 {
            universalTag = params.stringType;
        }
    }

    // Special case for time: UTCTime and GeneralizedTime both map to the
    // Go type time.Time. getUniversalType returns the tag for UTCTime
    // when it sees a time.Time, so if we see a different time type on the
    // wire, or the field is tagged with a different type, we change the
    // universal type to match.
    if universalTag == TagUTCTime {
        if t.class == ClassUniversal {
            if t.tag == TagGeneralizedTime {
                universalTag = t.tag;
            }
        } else if params.timeType != 0 {
            universalTag = params.timeType;
        }
    }

    if params.set {
        universalTag = TagSet;
    }

    let mut matchAnyClassAndTag = matchAny;
    let mut expectedClass = ClassUniversal;
    let mut expectedTag = universalTag;

    if !params.explicit && params.tag.is_some() {
        expectedClass = ClassContextSpecific;
        expectedTag = params.tag.unwrap_or(0);
        matchAnyClassAndTag = false;
    }

    if !params.explicit && params.application && params.tag.is_some() {
        expectedClass = ClassApplication;
        expectedTag = params.tag.unwrap_or(0);
        matchAnyClassAndTag = false;
    }

    if !params.explicit && params.private && params.tag.is_some() {
        expectedClass = ClassPrivate;
        expectedTag = params.tag.unwrap_or(0);
        matchAnyClassAndTag = false;
    }

    // We have unwrapped any explicit tagging at this point.
    if (!matchAnyClassAndTag && (t.class != expectedClass || t.tag != expectedTag))
        || (!matchAny && t.isCompound != compoundType)
    {
        // Tags don't match. Again, it could be an optional element.
        let ok = setDefaultValue(v, params);
        if ok {
            return (initOffset, nil);
        }
        return (
            offset,
            fmt::Errorf!(
                "asn1: structure error: tags don't match (%d vs %v) %v %s @%d",
                expectedTag,
                tagAndLengthString(&t),
                fieldParametersString(params),
                fieldType.Name(),
                offset
            ),
        );
    }
    if invalidLength(offset, t.length, blen) {
        return (offset, syntax("data truncated"));
    }
    let innerBytes = bytes.slice(offset, offset + t.length);
    offset += t.length;

    // We deal with the structures defined in this package first.
    //
    // Go: switch v := v.Addr().Interface().(type) { case *RawValue: … }
    // goish matches the seven identities by reflected type name; see the
    // banner.
    if fieldType.Name().as_bytes() == b"RawValue" {
        let rv = RawValue {
            Class: t.class,
            Tag: t.tag,
            IsCompound: t.isCompound,
            Bytes: innerBytes,
            FullBytes: bytes.slice(initOffset, offset),
        };
        v.Set(Reflect::__reflect_value(&rv));
        return (offset, nil);
    }
    if fieldType.Name().as_bytes() == b"ObjectIdentifier" {
        let (oid, err) = ParseObjectIdentifier(innerBytes);
        v.Set(Reflect::__reflect_value(&oid));
        return (offset, err);
    }
    if fieldType.Name().as_bytes() == b"BitString" {
        let (bs, err) = ParseBitString(innerBytes);
        v.Set(Reflect::__reflect_value(&bs));
        return (offset, err);
    }
    if fieldType.Name().as_bytes() == b"time.Time" {
        if universalTag == TagUTCTime {
            let (tm, err) = ParseUTCTime(innerBytes);
            v.Set(Reflect::__reflect_value(&tm));
            return (offset, err);
        }
        let (tm, err) = ParseGeneralizedTime(innerBytes);
        v.Set(Reflect::__reflect_value(&tm));
        return (offset, err);
    }
    if fieldType.Name().as_bytes() == b"Enumerated" {
        let (parsedInt, err1) = ParseInt32(innerBytes);
        if err1 == nil {
            v.Set(Reflect::__reflect_value(&Enumerated(int(parsedInt))));
        }
        return (offset, err1);
    }
    if fieldType.Name().as_bytes() == b"Flag" {
        v.Set(Reflect::__reflect_value(&Flag(true)));
        return (offset, nil);
    }
    if fieldType.Name().as_bytes() == b"Int" && fieldType.Kind() == Kind::Struct {
        let (parsedInt, err1) = super::ParseBigInt(innerBytes);
        if err1 == nil {
            v.Set(Reflect::__reflect_value(&parsedInt));
        }
        return (offset, err1);
    }

    // Go: switch val := v; val.Kind() { … }
    match v.Kind() {
        Kind::Bool => {
            let (parsedBool, err1) = ParseBool(innerBytes);
            if err1 == nil {
                v.SetBool(parsedBool);
            }
            return (offset, err1);
        }
        Kind::Int | Kind::Int32 | Kind::Int64 => {
            // Go: if val.Type().Size() == 4 { parseInt32 } else { parseInt64 }
            if v.Kind() == Kind::Int32 {
                let (parsedInt, err1) = ParseInt32(innerBytes);
                if err1 == nil {
                    v.SetInt(int64(parsedInt));
                }
                return (offset, err1);
            }
            let (parsedInt, err1) = ParseInt64(innerBytes);
            if err1 == nil {
                v.SetInt(parsedInt);
            }
            return (offset, err1);
        }
        // TODO(dfc) Add support for the remaining integer types
        Kind::Struct => {
            let structType = fieldType;

            let nf = structType.NumField();
            let mut i: int = 0;
            while i < nf {
                if !structType.Field(i).PkgPath.is_empty() {
                    return (offset, structural("struct contains unexported fields"));
                }
                i += 1;
            }

            if nf > 0 && (structType.Field(0).Type)().Name().as_bytes() == b"RawContent" {
                let raw = bytes.slice(initOffset, offset);
                let rc = RawContent(raw);
                match fieldMut(v, 0) {
                    Some(f) => f.Set(Reflect::__reflect_value(&rc)),
                    None => return (offset, structural("struct field not addressable")),
                }
            }

            let mut innerOffset: int = 0;
            let mut i: int = 0;
            while i < nf {
                let field = structType.Field(i);
                if i == 0 && (field.Type)().Name().as_bytes() == b"RawContent" {
                    i += 1;
                    continue;
                }
                let fp = parseFieldParameters(field.Tag.Get("asn1"));
                let fv = match fieldMut(v, i) {
                    Some(f) => f,
                    None => return (offset, structural("struct field not addressable")),
                };
                let (off2, err2) = parseField(fv, innerBytes.clone(), innerOffset, &fp);
                innerOffset = off2;
                if err2 != nil {
                    return (offset, err2);
                }
                i += 1;
            }
            // We allow extra bytes at the end of the SEQUENCE because
            // adding elements to the end has been used in X.509 as the
            // version numbers have increased.
            return (offset, nil);
        }
        Kind::Slice => {
            let sliceType = fieldType;
            if sliceType.Elem().Kind() == Kind::Uint8 {
                v.Set(Reflect::__reflect_value(&innerBytes));
                return (offset, nil);
            }
            let elem = sliceType.Elem();
            let (newSlice, err1) = parseSequenceOf(innerBytes, &sliceType, &elem);
            if err1 == nil {
                v.Set(newSlice);
            }
            return (offset, err1);
        }
        Kind::String => {
            let mut sv = string::default();
            let err: error;
            match universalTag {
                TagPrintableString => {
                    let (x, e) = ParsePrintableString(innerBytes);
                    sv = x;
                    err = e;
                }
                TagNumericString => {
                    let (x, e) = ParseNumericString(innerBytes);
                    sv = x;
                    err = e;
                }
                TagIA5String => {
                    let (x, e) = ParseIA5String(innerBytes);
                    sv = x;
                    err = e;
                }
                TagT61String => {
                    let (x, e) = ParseT61String(innerBytes);
                    sv = x;
                    err = e;
                }
                TagUTF8String => {
                    let (x, e) = ParseUTF8String(innerBytes);
                    sv = x;
                    err = e;
                }
                TagGeneralString => {
                    // GeneralString is specified in ISO-2022/ECMA-35.
                    // A brief review suggests that it includes structures
                    // that allow the encoding to change midstring and
                    // such. We give up and pass it as an 8-bit string.
                    let (x, e) = ParseT61String(innerBytes);
                    sv = x;
                    err = e;
                }
                TagBMPString => {
                    let (x, e) = ParseBMPString(innerBytes);
                    sv = x;
                    err = e;
                }
                _ => {
                    err = fmt::Errorf!(
                        "asn1: syntax error: internal error: unknown string type %d",
                        universalTag
                    );
                }
            }
            if err == nil {
                v.SetString(sv);
            }
            return (offset, err);
        }
        _ => {}
    }
    let mut msg = crate::strings::Builder::new();
    let _ = msg.WriteString("unsupported: ");
    let _ = msg.WriteString(v.Type().String());
    return (offset, super::StructuralError { Msg: msg.String() }.into());
}

// ─── setDefaultValue (asn1.go:1047) ───────────────────────────────────

// go: sdk 1.25.5 encoding/asn1/asn1.go:1050-1062 setDefaultValue
/// Install a default value, from a tag string, into a `Value`. Successful
/// if the field was optional, even if a default value wasn't provided or
/// it failed to install.
pub fn setDefaultValue(v: &mut Value, params: &fieldParameters) -> bool {
    if !params.optional {
        return false;
    }
    let ok = true;
    let dv = match params.defaultValue {
        Some(d) => d,
        None => return ok,
    };
    if canHaveDefaultValue(v.Kind()) {
        v.SetInt(dv);
    }
    return ok;
}

// ─── Unmarshal (asn1.go:1064) ─────────────────────────────────────────

// Go: asn1.go:1146-1148
//   type invalidUnmarshalError struct { Type reflect.Type }
//
/// Describes an invalid argument passed to [`Unmarshal`].
///
/// Declared for fidelity; **unreachable in goish**. Go's recipient is
/// `val any`, which can be nil, a non-pointer, or a nil pointer — the
/// three cases this error names. goish's recipient is `&mut T`, which is
/// none of them, so nothing constructs this. It is kept so that a reader
/// diffing against Go finds the type where Go has it, and so a future
/// erased `UnmarshalAny` (the mirror of `MarshalAny`) has it ready.
#[derive(Clone)]
pub struct invalidUnmarshalError {
    pub Type: Type,
}

impl ErrorTrait for invalidUnmarshalError {
    // go: sdk 1.25.5 encoding/asn1/asn1.go:1150-1159 invalidUnmarshalError.Error
    fn Error(&self) -> string {
        // Go's first branch is `e.Type == nil`; goish's `reflect::Type`
        // is a value type with no nil, and its zero is Kind::Invalid.
        if self.Type.Kind() == Kind::Invalid {
            return string::from_static("asn1: Unmarshal recipient value is nil");
        }

        let mut b = crate::strings::Builder::new();
        if self.Type.Kind() != Kind::Pointer {
            let _ = b.WriteString("asn1: Unmarshal recipient value is non-pointer ");
            let _ = b.WriteString(self.Type.String());
            return b.String();
        }
        let _ = b.WriteString("asn1: Unmarshal recipient value is nil ");
        let _ = b.WriteString(self.Type.String());
        return b.String();
    }
}

// go: sdk 1.25.5 encoding/asn1/asn1.go:1140-1142 Unmarshal
/// Parse the DER-encoded ASN.1 data structure `b` and fill in the value
/// `val` points at.
///
/// After parsing `b`, any bytes that were leftover and not used to fill
/// `val` are returned in `rest`. When parsing a SEQUENCE into a struct,
/// any trailing elements of the SEQUENCE that do not have matching fields
/// in `val` are not included in `rest`, as these are considered valid
/// elements of the SEQUENCE and not trailing data.
///
///   - An ASN.1 INTEGER can be written to an int, int32, int64 or a
///     `big::Int`.
///   - An ASN.1 BIT STRING can be written to a [`BitString`].
///   - An ASN.1 OCTET STRING can be written to a `slice<byte>`.
///   - An ASN.1 OBJECT IDENTIFIER can be written to an
///     [`ObjectIdentifier`].
///   - An ASN.1 ENUMERATED can be written to an [`Enumerated`].
///   - An ASN.1 UTCTIME or GENERALIZEDTIME can be written to a
///     `time::Time`.
///   - Any of the above ASN.1 values can be written to a [`RawValue`].
///   - An ASN.1 SEQUENCE OF x or SET OF x can be written to a slice if an
///     x can be written to the slice's element type.
///   - An ASN.1 SEQUENCE or SET can be written to a struct if each of the
///     elements in the sequence can be written to the corresponding
///     element of the struct.
///
/// See [`UnmarshalWithParams`] for the deviation in the recipient's type.
pub fn Unmarshal<T: Reflect + FromReflectValue>(
    b: slice<byte>,
    val: &mut T,
) -> (slice<byte>, error) {
    return UnmarshalWithParams(b, val, "");
}

// go: sdk 1.25.5 encoding/asn1/asn1.go:1163-1173 UnmarshalWithParams
/// Allow field parameters to be specified for the top-level element. The
/// form of the params is the same as the field tags.
///
/// Deviation: Go's `val any` is checked at runtime for being a non-nil
/// pointer and rejected with [`invalidUnmarshalError`]. goish takes
/// `&mut T` — the same thing, statically — and its `T: Reflect +
/// FromReflectValue` bound is what replaces Go's reflect dispatch: the
/// first supplies the Value tree `parseField` fills, the second writes it
/// back. `#[goish::reflect]` emits both.
pub fn UnmarshalWithParams<T: Reflect + FromReflectValue, S: Into<string>>(
    b: slice<byte>,
    val: &mut T,
    params: S,
) -> (slice<byte>, error) {
    // Go: v := reflect.ValueOf(val); if v.Kind() != Pointer || v.IsNil() { … }
    //
    // Statically impossible for `&mut T`; see the doc comment.
    let mut v = Reflect::__reflect_value(&*val);
    let (offset, err) = parseField(&mut v, b.clone(), 0, &parseFieldParameters(params));
    if err != nil {
        return (slice::default(), err);
    }
    // Go's parseField wrote through `v` into the caller's object. goish
    // filled an owned tree, so the write-back is here.
    let (out, err) = T::from_reflect_value(v);
    if err != nil {
        return (slice::default(), err);
    }
    *val = out;
    return (b.slice(offset, b.Len()), nil);
}

// ─── goish-only support ───────────────────────────────────────────────

// go: none — goish idiom: Go's `val.Field(i)` yields an *addressable*
// sub-Value that writes back into the parent. goish's `Value::Field(i)`
// returns a copy, so recursion into a struct field needs the `&mut`
// borrow directly. See this file's banner.
fn fieldMut(v: &mut Value, i: int) -> Option<&mut Value> {
    return match v {
        Value::Named { inner, .. } => fieldMut(inner, i),
        Value::Struct { fields, .. } => fields.get_mut(i as usize),
        _ => None,
    };
}

// go: none — goish idiom: Go writes `reflect.Zero(elemType)`; goish's
// `reflect::Zero` takes the `Type` by value. It grew its Struct and Slice
// arms for this call — see the note above `Zero` in reflect/mod.rs.
fn zeroOf(t: &Type) -> Value {
    return crate::reflect::Zero(*t);
}

// go: none — goish idiom: Go interpolates `t` with `%+v` on a struct with
// unexported fields, which goish's fmt cannot reach. Spelled out so the
// "tags don't match" message keeps its diagnostic content.
fn tagAndLengthString(t: &TagAndLength) -> string {
    return fmt::Sprintf!(
        "{class:%d tag:%d length:%d isCompound:%v}",
        t.class,
        t.tag,
        t.length,
        t.isCompound
    );
}

// go: none — goish idiom: the `%+v` of `params` in the same message.
fn fieldParametersString(p: &fieldParameters) -> string {
    return fmt::Sprintf!(
        "{optional:%v explicit:%v application:%v private:%v defaultValue:%v tag:%v stringType:%d timeType:%d set:%v omitEmpty:%v}",
        p.optional,
        p.explicit,
        p.application,
        p.private,
        p.defaultValue.unwrap_or(0),
        p.tag.unwrap_or(0),
        p.stringType,
        p.timeType,
        p.set,
        p.omitEmpty
    );
}

// ─── FromReflectValue for asn1's own named types ──────────────────────
//
// go: none — goish-only, and the exact mirror of the `Reflect` impls at
// the foot of mod.rs.
//
// `Reflect` is the read half — it is what let `Marshal` walk a value.
// `FromReflectValue` is the write half, and `Unmarshal` needs it for the
// same six types plus the two `getUniversalType` matches by identity
// (`big::Int`, `time::Time`, which live in their own packages). Without
// it, a struct with an ObjectIdentifier field parses correctly and then
// fails at the write-back, because the macro-emitted `FromReflectValue`
// for the struct dispatches per field type.

// go: none — goish-only: the write half of the reflect descriptor.
impl FromReflectValue for ObjectIdentifier {
    // go: none — goish-only: the write half of the reflect descriptor.
    fn from_reflect_value(v: Value) -> (Self, error) {
        let (s, err) = <slice<int> as FromReflectValue>::from_reflect_value(unwrapNamed(v));
        return (ObjectIdentifier(s), err);
    }
}

// go: none — goish-only: the write half of the reflect descriptor.
impl FromReflectValue for Enumerated {
    // go: none — goish-only: the write half of the reflect descriptor.
    fn from_reflect_value(v: Value) -> (Self, error) {
        let (n, err) = <int as FromReflectValue>::from_reflect_value(unwrapNamed(v));
        return (Enumerated(n), err);
    }
}

// go: none — goish-only: the write half of the reflect descriptor.
impl FromReflectValue for Flag {
    // go: none — goish-only: the write half of the reflect descriptor.
    fn from_reflect_value(v: Value) -> (Self, error) {
        let (b, err) = <bool as FromReflectValue>::from_reflect_value(unwrapNamed(v));
        return (Flag(b), err);
    }
}

// go: none — goish-only: the write half of the reflect descriptor.
impl FromReflectValue for RawContent {
    // go: none — goish-only: the write half of the reflect descriptor.
    fn from_reflect_value(v: Value) -> (Self, error) {
        let (b, err) = <slice<byte> as FromReflectValue>::from_reflect_value(unwrapNamed(v));
        return (RawContent(b), err);
    }
}

// go: none — goish-only: the write half of the reflect descriptor.
impl FromReflectValue for BitString {
    // go: none — goish-only: the write half of the reflect descriptor.
    fn from_reflect_value(v: Value) -> (Self, error) {
        let v = unwrapNamed(v);
        if v.Kind() != Kind::Struct {
            return (
                BitString::default(),
                crate::errors::New("asn1: expected BitString"),
            );
        }
        return (
            BitString {
                Bytes: v.Field(0).Bytes(),
                BitLength: v.Field(1).Int(),
            },
            nil,
        );
    }
}

// go: none — goish-only: the write half of the reflect descriptor.
impl FromReflectValue for RawValue {
    // go: none — goish-only: the write half of the reflect descriptor.
    fn from_reflect_value(v: Value) -> (Self, error) {
        let v = unwrapNamed(v);
        if v.Kind() != Kind::Struct {
            return (
                RawValue::default(),
                crate::errors::New("asn1: expected RawValue"),
            );
        }
        return (
            RawValue {
                Class: v.Field(0).Int(),
                Tag: v.Field(1).Int(),
                IsCompound: v.Field(2).Bool(),
                Bytes: v.Field(3).Bytes(),
                FullBytes: v.Field(4).Bytes(),
            },
            nil,
        );
    }
}

// go: none — goish idiom: `Value::Named` is transparent for everything
// but `Type()`, so a converter that wants the payload strips it first.
fn unwrapNamed(v: Value) -> Value {
    return match v {
        Value::Named { inner, .. } => *inner,
        other => other,
    };
}

// go: none — goish-only: the write half of `big::Int`'s reflect
// descriptor, which `getUniversalType` matches by identity. It lives here
// rather than in math/big because it exists only for asn1's decode path;
// the crate-internal `FromReflectValue` trait imposes no orphan rule.
impl FromReflectValue for big::Int {
    // go: none — goish-only: the write half of the reflect descriptor.
    fn from_reflect_value(v: Value) -> (Self, error) {
        let v = unwrapNamed(v);
        if v.Kind() != Kind::Struct {
            return (
                big::Int::new(),
                crate::errors::New("asn1: expected big.Int"),
            );
        }
        let sign = v.Field(0).Int();
        let mag = v.Field(1).Bytes();
        let mut n = big::Int::new();
        n.SetBytes(mag);
        if sign < 0 {
            let m = n.clone();
            n.Neg(&m);
        }
        return (n, nil);
    }
}

// go: none — goish-only: the write half of `time::Time`'s reflect
// descriptor. Same placement rationale as `big::Int` above.
impl FromReflectValue for time::Time {
    // go: none — goish-only: the write half of the reflect descriptor.
    fn from_reflect_value(v: Value) -> (Self, error) {
        let v = unwrapNamed(v);
        if v.Kind() != Kind::Struct {
            return (
                time::Time::default(),
                crate::errors::New("asn1: expected time.Time"),
            );
        }
        // The reflected fields are INTERNAL seconds — from year 1, the
        // frame `Time.sec` uses — so this cannot go through
        // `time::Unix`, which would shift them a second time.
        let sec = v.Field(0).Int();
        let nsec = v.Field(1).Int();
        return (time::Time::__from_internal(sec, nsec).UTC(), nil);
    }
}
