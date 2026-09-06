// encoding/json — Go's encoding/json package, ported.
//
// v1 surface:
//
//   pub enum Value { Null, Bool(bool), Number(f64), String(string),
//                    Array(slice<Value>), Object(map<string, Value>) }
//   pub fn Marshal(v: &Value) -> (slice<byte>, error);
//   pub fn MarshalIndent(v: &Value, prefix, indent) -> (slice<byte>, error);
//   pub fn Unmarshal(data) -> (Value, error);
//   pub fn NewEncoder(w) -> Encoder<W>;  Encoder::Encode/SetIndent.
//   pub fn NewDecoder(r) -> Decoder<R>;  Decoder::Decode.
//   pub trait Marshaler / Unmarshaler.
//   pub fn ErrSyntax() / ErrUnexpectedEnd().
//
// v1 deviations from Go (doc'd in wip_json.md):
//   * No reflection — user structs serialize via `Marshaler` trait;
//     dynamic JSON uses the `Value` enum.
//   * Object keys iterate sorted (BTreeMap-backed map<K, V>).

// goishlint:ignore GOISH015 — this package is 1885 lines in one mod.rs and predates the one-.rs-per-.go split. Splitting encoding/json is its own unit; `appendString` is anchored here because its BEHAVIOUR changed and the provenance line is worth more than the file boundary is. Claiming an encode.go manifest in a new file would instead demand all 77 of that file's other declarations, which would be a larger lie than this waiver.
#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::strconv;
use crate::types::{byte, float64, int};

pub mod jsontext;
pub mod v2;

// ─── Value ─────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    Number(float64),
    String(string),
    Array(slice<Value>),
    Object(map<string, Value>),
}

impl Value {
    pub fn IsNull(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn AsBool(&self) -> Option<bool> {
        if let Value::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    pub fn AsNumber(&self) -> Option<float64> {
        if let Value::Number(n) = self {
            Some(*n)
        } else {
            None
        }
    }

    pub fn AsString(&self) -> Option<&string> {
        if let Value::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn AsArray(&self) -> Option<&slice<Value>> {
        if let Value::Array(a) = self {
            Some(a)
        } else {
            None
        }
    }

    pub fn AsObject(&self) -> Option<&map<string, Value>> {
        if let Value::Object(o) = self {
            Some(o)
        } else {
            None
        }
    }
}

// ─── ergonomic From impls — `obj.Set("k", "v")` Just Works ──────────
//
// Map.Set is generic over `Into<V>` where V = Value, so any type that
// `From`-coerces to Value becomes a one-arg literal at the call site.
// Mirrors Go's untyped map/JSON literals (`map[string]any{"k": "v"}`).

impl From<&str> for Value {
    #[inline]
    fn from(s: &str) -> Self {
        Value::String(string::from(s))
    }
}

impl From<string> for Value {
    #[inline]
    fn from(s: string) -> Self {
        Value::String(s)
    }
}

impl From<bool> for Value {
    #[inline]
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<f64> for Value {
    #[inline]
    fn from(n: f64) -> Self {
        Value::Number(n)
    }
}

impl From<int> for Value {
    #[inline]
    fn from(n: int) -> Self {
        Value::Number(n as f64)
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Number(a), Value::Number(b)) => {
                // NaN-tolerant equality: bit-equal NaN counts as equal.
                if a.is_nan() && b.is_nan() {
                    true
                } else {
                    a == b
                }
            }
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => {
                let av: &[Value] = a;
                let bv: &[Value] = b;
                av == bv
            }
            (Value::Object(a), Value::Object(b)) => {
                if a.Len() != b.Len() {
                    return false;
                }
                for (k, va) in a.__iter() {
                    let (vb, ok) = b.Get(k.clone());
                    if !ok || vb != *va {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }
}

// ─── Token / Delim — streaming decoder API ─────────────────────────────

/// A `Token` is one of the JSON lexical tokens returned by [Decoder::Token].
/// Mirrors Go's `json.Token` interface values (`Delim`, `bool`, `float64`,
/// `string`, `nil`).  Goish uses an explicit enum because Rust has no `any`.
#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    Delim(Delim),
    Bool(bool),
    Number(float64),
    String(string),
    Null,
}

/// `json.Delim` — one of the four JSON structural characters `{ } [ ]`.
/// In Go this is `type Delim rune`; goish stores it as a `byte` since all
/// four delimiters are ASCII.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delim(pub byte);

impl Delim {
    pub fn as_byte(&self) -> byte {
        self.0
    }
}

impl core::fmt::Display for Delim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0 as char)
    }
}

impl PartialEq<Delim> for Token {
    fn eq(&self, other: &Delim) -> bool {
        matches!(self, Token::Delim(d) if d.0 == other.0)
    }
}

/// `json.Number` — Go's `type Number string`. Surfaces when a Decoder
/// is configured with `UseNumber()`, so JSON numbers preserve their
/// original textual form (avoiding f64 precision loss for large ints
/// or trailing-zero arbitrary-precision values). Convertible to int64
/// or float64 on demand.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Number(pub string);

impl Number {
    /// `(Number).String() string` — the textual form, identity.
    #[allow(non_snake_case)]
    pub fn String(&self) -> string {
        self.0.clone()
    }

    /// `(Number).Int64() (int64, error)` — parse as signed 64-bit.
    /// Returns Go's err on syntax/range failure.
    #[allow(non_snake_case)]
    pub fn Int64(&self) -> (int, error) {
        strconv::ParseInt(self.0.clone(), 10, 64)
    }

    /// `(Number).Float64() (float64, error)` — parse as IEEE-754
    /// double. Returns Go's err on syntax/range failure.
    #[allow(non_snake_case)]
    pub fn Float64(&self) -> (float64, error) {
        strconv::ParseFloat(self.0.clone(), 64)
    }
}

impl From<string> for Number {
    fn from(s: string) -> Self {
        Number(s)
    }
}

impl From<&str> for Number {
    fn from(s: &str) -> Self {
        Number(string::from(s))
    }
}

impl core::fmt::Display for Number {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<Token> for Delim {
    fn eq(&self, other: &Token) -> bool {
        matches!(other, Token::Delim(d) if d.0 == self.0)
    }
}

// ─── Sentinel errors ───────────────────────────────────────────────────

crate::var! {
    pub ErrSyntax: error       = "json: invalid syntax";
    pub ErrUnexpectedEnd: error = "json: unexpected end of input";
}

// ─── Internal helpers ─────────────────────────────────────────────────

/// Internal helper used by `#[goish::reflect]`'s generated `FromValue`
/// impl. Parses a raw `json:"foo,opt1,opt2"` tag value into
/// `(effective_key, skip)`. `skip == true` if the tag is `"-"`. When
/// `effective_key` is empty, the macro falls back to the field name.
#[doc(hidden)]
pub fn __parse_json_tag(tag: &string) -> (string, bool) {
    let raw = tag.as_bytes();
    if raw == b"-" {
        return (string::new(), true);
    }
    let name_seg: &[u8] = match raw.iter().position(|&c| c == b',') {
        Some(i) => &raw[..i],
        None => raw,
    };
    if name_seg == b"-" {
        return (string::new(), true);
    }
    (string::from_bytes(name_seg), false)
}

// ─── FromValue — typed Unmarshal protocol ─────────────────────────────
//
// `json.Unmarshal(data, &mut dest)` parses to a dynamic `Value`, then
// dispatches to `FromValue::from_value` to convert into the target.
// Built-in impls cover primitives, `Value` (identity for the dynamic
// case), `slice<T>`, and `map<string, V>`. The `#[goish::reflect]` proc-
// macro emits the impl for user structs, walking each field with its
// JSON tag-derived key.

// go: none — goish idiom: Go's decoder writes through a reflect.Value,
// so it can decline to write at all — which is exactly what it does for
// a null into a primitive (decode.go, literalStore: "otherwise, ignore
// null for primitives"). goish's `FromValue` RETURNS a value, so "do
// not write" has to be signalled instead. This private sentinel does
// that: `Unmarshal` recognises it, skips the assignment, and reports
// success. Without it a document with an explicit null field failed to
// decode at all, where Go leaves the field as it found it.
crate::var! {
    ERR_NULL_NOOP: error = "json: null is a no-op";
}

pub trait FromValue: Sized {
    /// Convert a JSON `Value` into `Self`. Returns `(Self, error)` —
    /// typical Go-shape, with the second value carrying the type-mismatch
    /// or out-of-range error if any.
    fn from_value(v: &Value) -> (Self, error);

    // go: none — goish-only: the OWNING form, so `Unmarshal` can hand
    // the parsed tree over instead of copying it.
    /// Same conversion, consuming the parsed `Value`.
    ///
    /// The default borrows and delegates, which is right for every
    /// type that reads a few fields out of the tree. `Value` overrides
    /// it to MOVE, and that override is what the nesting limit turns
    /// on: `Unmarshal(data, &mut Value)` used to finish with
    /// `v.clone()`, one stack frame per level over the whole tree,
    /// which put the ceiling in the same place the recursive parser
    /// had it.
    fn from_value_owned(v: Value) -> (Self, error) {
        return Self::from_value(&v);
    }
}

// Identity — lets `Unmarshal(data, &mut json::Value)` work for the
// dynamic case (replacing the old `(Value, error)` shape).
impl FromValue for Value {
    fn from_value(v: &Value) -> (Self, error) {
        (v.clone(), nil)
    }
    // The identity case, and the one that matters for depth: moving
    // costs nothing per level where cloning cost a frame.
    fn from_value_owned(v: Value) -> (Self, error) {
        return (v, nil);
    }
}

impl FromValue for bool {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Bool(b) => (*b, nil),
            // Go: null is ignored for a primitive — see the note on
            // ERR_NULL_NOOP.
            Value::Null => (false, ERR_NULL_NOOP.into()),
            _ => (false, errors::New("json: cannot unmarshal into bool")),
        }
    }
}

/// `Option<T>` — Go `*T` optionality: JSON null (or absence) is
/// `None`, anything else decodes into `Some(T)`.
impl<T: FromValue> FromValue for Option<T> {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Null => (None, nil),
            other => {
                let (val, err) = T::from_value(other);
                if err != nil {
                    (None, err)
                } else {
                    (Some(val), nil)
                }
            }
        }
    }
}

/// `nilable<T>` — Go `*T`: null/absent stays nil, anything else
/// decodes into a fresh value.
impl<T: FromValue> FromValue for crate::gonilable::nilable<T> {
    fn from_value(v: &Value) -> (Self, error) {
        let (opt, err) = <Option<T> as FromValue>::from_value(v);
        if err != nil {
            return (crate::gonilable::nilable::default(), err);
        }
        match opt {
            Some(val) => (crate::gonilable::nilable::new(val), nil),
            None => (crate::gonilable::nilable::default(), nil),
        }
    }
}

// go: none — goish idiom: Go decodes a number by running
// strconv.ParseInt over the ORIGINAL literal text, so "1.5" and "1.0"
// both fail for an integer target and the error names the literal.
// goish's `Value::Number` holds an f64 and has already lost the text,
// so the integrality and range checks are done on the value instead;
// the refusal is Go's, the literal in the message is goish's rendering
// of it. Truncating instead — which is what `n as int` did — turns a
// document Go REJECTS into a different number, silently, which is the
// worst of the three possible behaviours.
fn number_to_int(n: crate::types::float64, lo: f64, hi: f64, ty: &str) -> (i64, error) {
    if n != crate::math::Trunc(n) || !(lo..=hi).contains(&n) {
        return (
            0,
            errors::New(
                string::from("json: cannot unmarshal number ")
                    + crate::fmt::Sprintf!("%v", n)
                    + string::from(" into Go value of type ")
                    + string::from(ty),
            ),
        );
    }
    // The upper bound is 2^63 as an f64, which is what the max int64
    // LITERAL rounds to — 9223372036854775807 is not representable, and
    // `Value::Number` is an f64, so the digits are gone by the time we
    // get here. Go never has this problem: its decoder parses the
    // digits with ParseInt and answers 9223372036854775807 exactly.
    //
    // Falling through to `convert::int64` would answer i64::MIN, since
    // that now implements amd64's CVTTSD2SQ — the integer-indefinite
    // result for anything >= 2^63 — rather than Rust's saturation.
    // That conversion is right, and this boundary is the one place the
    // v1 decoder must not use it. json_decode_ref_smoke pins Go's
    // answer for exactly this input.
    //
    // The proper fix is for Value::Number to keep the literal so an
    // integer target can parse the digits; that is a change to the
    // Value type and is recorded in the ROADMAP rather than smuggled
    // in here.
    if n >= 9223372036854775808.0 {
        return (i64::MAX, nil);
    }
    return (crate::convert::int64(n), nil);
}

impl FromValue for crate::types::int {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) => {
                let (i, err) =
                    number_to_int(*n, -9.223372036854776e18, 9.223372036854776e18, "int");
                return (i as crate::types::int, err);
            }
            // Go (decode.go, literalStore): a null into a primitive is
            // IGNORED — the target keeps whatever it held and no error
            // is reported. Only interface, pointer, map and slice
            // targets are zeroed.
            Value::Null => (0, ERR_NULL_NOOP.into()),
            _ => (0, errors::New("json: cannot unmarshal into int")),
        }
    }
}

impl FromValue for crate::types::uint {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) => {
                let (i, err) = number_to_int(*n, 0.0, 1.8446744073709552e19, "uint");
                return (i as crate::types::uint, err);
            }
            // Go: null is ignored for a primitive — see `int` above.
            Value::Null => (0, ERR_NULL_NOOP.into()),
            _ => (0, errors::New("json: cannot unmarshal into uint")),
        }
    }
}

impl FromValue for crate::types::float64 {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) => (*n, nil),
            // Go: null is ignored for a primitive — see `int` above.
            Value::Null => (0.0, ERR_NULL_NOOP.into()),
            _ => (0.0, errors::New("json: cannot unmarshal into float64")),
        }
    }
}

impl FromValue for crate::types::float32 {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) => (*n as crate::types::float32, nil),
            // Go: null is ignored for a primitive — see `int` above.
            Value::Null => (0.0, ERR_NULL_NOOP.into()),
            _ => (0.0, errors::New("json: cannot unmarshal into float32")),
        }
    }
}

impl FromValue for crate::types::byte {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) => {
                let (i, err) = number_to_int(*n, 0.0, 255.0, "uint8");
                return (i as crate::types::byte, err);
            }
            // Go: null is ignored for a primitive — see `int` above.
            Value::Null => (0, ERR_NULL_NOOP.into()),
            _ => (0, errors::New("json: cannot unmarshal into byte")),
        }
    }
}

impl FromValue for crate::types::rune {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) => {
                let (i, err) = number_to_int(*n, -2147483648.0, 2147483647.0, "int32");
                return (i as crate::types::rune, err);
            }
            // Go: null is ignored for a primitive — see `int` above.
            Value::Null => (0, ERR_NULL_NOOP.into()),
            _ => (0, errors::New("json: cannot unmarshal into rune")),
        }
    }
}

impl FromValue for string {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::String(s) => (s.clone(), nil),
            // Go: null is ignored for a primitive — see the note on
            // ERR_NULL_NOOP.
            Value::Null => (string::new(), ERR_NULL_NOOP.into()),
            _ => (
                string::new(),
                errors::New("json: cannot unmarshal into string"),
            ),
        }
    }
}

impl<T: FromValue + Default + Clone> FromValue for slice<T> {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Array(items) => {
                let mut out: Vec<T> = Vec::with_capacity(items.Len() as usize);
                for i in 0..items.Len() {
                    let (elem, err) = T::from_value(&items[i]);
                    if err != nil {
                        return (slice::__from_vec(Vec::new()), err);
                    }
                    out.push(elem);
                }
                (slice::__from_vec(out), nil)
            }
            Value::Null => (slice::__from_vec(Vec::new()), nil),
            _ => (
                slice::__from_vec(Vec::new()),
                errors::New("json: cannot unmarshal into slice"),
            ),
        }
    }
}

// Map: string-keyed only for v1. Non-string keys would need
// strconv-style parsing to mirror Go.
impl<V: FromValue + Default + Clone> FromValue for map<string, V> {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Object(o) => {
                let mut out = map::<string, V>::new();
                for (k, val) in o.__iter() {
                    let (vv, err) = V::from_value(val);
                    if err != nil {
                        return (out, err);
                    }
                    out.Set(k.clone(), vv);
                }
                (out, nil)
            }
            Value::Null => (map::<string, V>::new(), nil),
            _ => (
                map::<string, V>::new(),
                errors::New("json: cannot unmarshal into map"),
            ),
        }
    }
}

// ─── Marshaler / Unmarshaler traits ────────────────────────────────────

#[goish::interface]
pub trait Marshaler {
    fn MarshalJSON(&self) -> (slice<byte>, error);
}

#[goish::interface]
pub trait Unmarshaler {
    fn UnmarshalJSON(&mut self, data: &[byte]) -> error;
}

// Blanket: Value impls Marshaler — calling json::Marshal on a Value
// goes through the same code path as user-typed Marshalers.
impl Marshaler for Value {
    fn MarshalJSON(&self) -> (slice<byte>, error) {
        let mut out: Vec<byte> = Vec::new();
        encode_value(&mut out, self, None, "", 0);
        (slice::__from_vec(out), nil)
    }
}

// json::Value impls reflect::Reflect so it can flow through the
// generic `Marshal<T: Reflect>` path. Object → reflect::Value::Map
// (string keys), Array → reflect::Value::Slice, Number → Float64.
// Null collapses to reflect::Value::Invalid (encoded as "null").
impl crate::reflect::Reflect for Value {
    fn __reflect_type() -> crate::reflect::Type {
        crate::reflect::Type::__new(crate::reflect::Kind::Invalid, "", &[])
    }
    fn __reflect_value(&self) -> crate::reflect::Value {
        use crate::reflect::Value as RV;
        match self {
            Value::Null => RV::Invalid,
            Value::Bool(b) => RV::Bool(*b),
            Value::Number(n) => RV::Float64(*n),
            Value::String(s) => RV::String(s.clone()),
            Value::Array(a) => {
                let mut items: Vec<RV> = Vec::with_capacity(a.Len() as usize);
                for i in 0..a.Len() {
                    items.push(<Value as crate::reflect::Reflect>::__reflect_value(&a[i]));
                }
                RV::Slice {
                    elem_type: <Value as crate::reflect::Reflect>::__reflect_type,
                    items,
                }
            }
            Value::Object(o) => {
                let mut entries: Vec<(RV, RV)> = Vec::with_capacity(o.Len() as usize);
                for (k, v) in o.__iter() {
                    entries.push((
                        RV::String(k.clone()),
                        <Value as crate::reflect::Reflect>::__reflect_value(v),
                    ));
                }
                RV::Map {
                    key_type: <string as crate::reflect::Reflect>::__reflect_type,
                    value_type: <Value as crate::reflect::Reflect>::__reflect_type,
                    entries,
                }
            }
        }
    }
}

// ─── Marshal / MarshalIndent ───────────────────────────────────────────

/// `json.Marshal(v)` — encode any `Reflect` value as JSON. Struct
/// fields are renamed via `Tag.Get("json")` (with `omitempty` and `-`
/// support); maps with string keys become JSON objects in sorted-key
/// order; slices become arrays. The Go `Marshaler` trait is honored
/// for `json::Value` directly via this generic path.
pub fn Marshal<T: crate::reflect::Reflect + ?Sized>(v: &T) -> (slice<byte>, error) {
    let rv = crate::reflect::ValueOf(v);
    let mut out: Vec<byte> = Vec::new();
    encode_reflect(&mut out, &rv);
    (slice::__from_vec(out), nil)
}

/// `json.Valid(data)` (stream.go:484) — report whether `data` is a
/// well-formed JSON value (any of object / array / number / string /
/// bool / null with optional surrounding whitespace).
///
/// Slim: routes through the existing recursive-descent parser.
/// Returns `false` for any syntax error (matching Go); empty input
/// is invalid because Go's scanner requires at least one value.
pub fn Valid(data: slice<byte>) -> bool {
    // Go: scan := newScanner(); defer freeScanner(scan)
    //     return checkValid(data, scan) == nil
    let bs: &[byte] = &data;
    let (_, err) = parse_to_value(bs);
    err.IsNil()
}

/// `json.Compact(dst, src)` (indent.go:13) — append a compact form
/// of `src` to `dst` and return `(extended_dst, err)`. Compact strips
/// insignificant whitespace between tokens; quoted strings are
/// preserved verbatim.
///
/// Slim: parse to a Value then re-encode (the existing encoder
/// already produces compact output). Faithful for valid input;
/// returns `(dst, ErrSyntax)` for invalid input.  Differs from Go
/// only in that whitespace inside string literals is preserved
/// (Go's Compact is byte-level — neither version touches string
/// contents).
pub fn Compact(dst: slice<byte>, src: slice<byte>) -> (slice<byte>, error) {
    // Go: scan := newScanner(); ...
    //     return compact(dst, src, false, scan)
    let bs: &[byte] = &src;
    let (v, err) = parse_to_value(bs);
    if !err.IsNil() {
        return (dst, err);
    }
    let mut out: Vec<byte> = dst.__into_vec();
    encode_value(&mut out, &v, None, "", 0);
    (slice::__from_vec(out), nil)
}

/// `json.Indent(dst, src, prefix, indent)` (indent.go:120) — append an
/// indented form of `src` to `dst`. Each element in a JSON object or
/// array begins on a new, indented line beginning with `prefix` followed
/// by one or more copies of `indent` according to the indentation
/// nesting. The data appended to `dst` does not begin with the prefix
/// nor any indentation, to make it easier to embed inside other
/// formatted JSON data.
///
/// Slim: parse to a `Value` then re-encode through the existing
/// indent-aware encoder. Faithful for valid input; returns
/// `(dst, ErrSyntax)` on parse error.
pub fn Indent(
    dst: slice<byte>,
    src: slice<byte>,
    prefix: &str,
    indent: &str,
) -> (slice<byte>, error) {
    // Go: scan := newScanner(); ...
    //     b, err := appendIndent(b, src, prefix, indent)
    let bs: &[byte] = &src;
    let (v, err) = parse_to_value(bs);
    if !err.IsNil() {
        return (dst, err);
    }
    let mut out: Vec<byte> = dst.__into_vec();
    let cfg = IndentCfg { prefix, indent };
    encode_value(&mut out, &v, Some(&cfg), "", 0);
    (slice::__from_vec(out), nil)
}

/// `json.HTMLEscape(dst, src)` (indent.go:16) — append `src` to `dst`
/// with `<`, `>`, `&`, U+2028 and U+2029 inside string literals
/// changed to `<`, `>`, `&`, ` `, ` ` so that
/// the JSON will be safe to embed inside HTML `<script>` tags.
///
/// Slim note: the byte-level escape matches Go exactly; it does not
/// distinguish bytes inside vs outside JSON string literals (Go's
/// implementation does the same byte-level scan).
pub fn HTMLEscape(dst: slice<byte>, src: slice<byte>) -> slice<byte> {
    // Go: dst.Grow(len(src))
    //     dst.Write(appendHTMLEscape(dst.AvailableBuffer(), src))
    let s: &[byte] = &src;
    let mut out: Vec<byte> = dst.__into_vec();
    // Go: start := 0
    let mut start: usize = 0;
    // Go: for i, c := range src
    let mut i: usize = 0;
    while i < s.len() {
        let c = s[i];
        // Go: if c == '<' || c == '>' || c == '&'
        if c == b'<' || c == b'>' || c == b'&' {
            // Go: dst = append(dst, src[start:i]...)
            out.extend_from_slice(&s[start..i]);
            // Go: dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xF])
            out.extend_from_slice(b"\\u00");
            out.push(hex_digit(c >> 4));
            out.push(hex_digit(c & 0xF));
            // Go: start = i + 1
            start = i + 1;
        }
        // Go: if c == 0xE2 && i+2 < len(src) && src[i+1] == 0x80 && src[i+2]&^1 == 0xA8
        if c == 0xE2 && i + 2 < s.len() && s[i + 1] == 0x80 && (s[i + 2] & !1) == 0xA8 {
            // Go: dst = append(dst, src[start:i]...)
            out.extend_from_slice(&s[start..i]);
            // Go: dst = append(dst, '\\', 'u', '2', '0', '2', hex[src[i+2]&0xF])
            out.extend_from_slice(b"\\u202");
            out.push(hex_digit(s[i + 2] & 0xF));
            // Go: start = i + len(" ")  // 3 bytes
            start = i + 3;
        }
        i += 1;
    }
    // Go: return append(dst, src[start:]...)
    if start < s.len() {
        out.extend_from_slice(&s[start..]);
    }
    slice::__from_vec(out)
}

/// `json.MarshalIndent(v, prefix, indent)` — pretty-printed variant.
pub fn MarshalIndent<T: crate::reflect::Reflect + ?Sized>(
    v: &T,
    prefix: &str,
    indent: &str,
) -> (slice<byte>, error) {
    let rv = crate::reflect::ValueOf(v);
    let mut out: Vec<byte> = Vec::new();
    let cfg = IndentCfg { prefix, indent };
    encode_reflect_indent(&mut out, &rv, &cfg, 0);
    (slice::__from_vec(out), nil)
}

// ─── Reflect-driven encoder (used by Marshal / MarshalIndent) ─────────

use crate::reflect;

fn encode_reflect(out: &mut Vec<byte>, v: &reflect::Value) {
    use reflect::Kind as K;
    match v.Kind() {
        K::Invalid => out.extend_from_slice(b"null"),
        K::Bool => out.extend_from_slice(if v.Bool() { b"true" } else { b"false" }),
        K::Int | K::Int8 | K::Int16 | K::Int32 => {
            let s = strconv::FormatInt(v.Int(), 10);
            out.extend_from_slice(s.as_bytes());
        }
        K::Uint | K::Uint8 | K::Uint16 | K::Uint32 => {
            let s = strconv::FormatUint(v.Uint(), 10);
            out.extend_from_slice(s.as_bytes());
        }
        K::Float32 | K::Float64 => encode_number(out, v.Float()),
        K::String => encode_string(out, v.String().as_bytes()),
        K::Slice => {
            let n = v.Len();
            if n == 0 {
                out.extend_from_slice(b"[]");
                return;
            }
            out.push(b'[');
            for i in 0..n {
                if i > 0 {
                    out.push(b',');
                }
                encode_reflect(out, &v.Index(i));
            }
            out.push(b']');
        }
        K::Map => encode_map(out, v, None, 0),
        K::Struct => encode_struct(out, v, None, 0),
        _ => out.extend_from_slice(b"null"),
    }
}

fn encode_reflect_indent(out: &mut Vec<byte>, v: &reflect::Value, cfg: &IndentCfg, depth: usize) {
    use reflect::Kind as K;
    match v.Kind() {
        K::Slice => {
            let n = v.Len();
            if n == 0 {
                out.extend_from_slice(b"[]");
                return;
            }
            out.push(b'[');
            for i in 0..n {
                if i > 0 {
                    out.push(b',');
                }
                write_newline_indent(out, cfg, depth + 1);
                encode_reflect_indent(out, &v.Index(i), cfg, depth + 1);
            }
            write_newline_indent(out, cfg, depth);
            out.push(b']');
        }
        K::Map => encode_map(out, v, Some(cfg), depth),
        K::Struct => encode_struct(out, v, Some(cfg), depth),
        _ => encode_reflect(out, v),
    }
}

fn encode_map(out: &mut Vec<byte>, v: &reflect::Value, cfg: Option<&IndentCfg>, depth: usize) {
    let mut keys = v.MapKeys();
    if keys.is_empty() {
        out.extend_from_slice(b"{}");
        return;
    }
    // Go's encoding/json marshals map keys in sorted order.
    keys.sort_by(|a, b| {
        let as_ = match a {
            reflect::Value::String(s) => s.as_bytes(),
            _ => b"",
        };
        let bs = match b {
            reflect::Value::String(s) => s.as_bytes(),
            _ => b"",
        };
        as_.cmp(bs)
    });
    out.push(b'{');
    let inner = depth + 1;
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        if let Some(c) = cfg {
            write_newline_indent(out, c, inner);
        }
        // String-keyed maps emit the key as-is. Non-string keys would
        // need stringification (Go calls `json.Marshaler` or `TextMarshaler`
        // on the key). v1 just emits the kind label as a string so output
        // stays valid JSON; later iterations will handle this faithfully.
        let key_str = match k {
            reflect::Value::String(s) => s.clone(),
            _ => k.Kind().String(),
        };
        encode_string(out, key_str.as_bytes());
        out.push(b':');
        if cfg.is_some() {
            out.push(b' ');
        }
        let fv = v.MapIndex(k);
        match cfg {
            Some(c) => encode_reflect_indent(out, &fv, c, inner),
            None => encode_reflect(out, &fv),
        }
    }
    if let Some(c) = cfg {
        write_newline_indent(out, c, depth);
    }
    out.push(b'}');
}

fn encode_struct(out: &mut Vec<byte>, v: &reflect::Value, cfg: Option<&IndentCfg>, depth: usize) {
    let ty = match v {
        reflect::Value::Struct { ty, .. } => *ty,
        _ => unreachable!("encode_struct on non-struct"),
    };
    let n = ty.NumField();

    // Resolve effective name + omitempty for each field; collect those
    // that should be emitted.
    let mut keys: Vec<(string, reflect::Value)> = Vec::with_capacity(n as usize);
    for i in 0..n {
        let f = ty.Field(i);
        let tag = f.Tag.Get("json");
        let raw = tag.as_bytes();
        // "-" alone means skip entirely.
        if raw == b"-" {
            continue;
        }
        // Split on ',' — first segment is name, rest are options.
        let (name_seg, opts) = split_first_comma(raw);
        let mut omitempty = false;
        for opt in opts {
            if opt == b"omitempty" {
                omitempty = true;
            }
        }
        let key: string = if name_seg.is_empty() {
            string::from_static(f.Name)
        } else {
            string::from_bytes(name_seg)
        };
        let fv = v.Field(i);
        if omitempty && fv.IsZero() {
            continue;
        }
        keys.push((key, fv));
    }

    if keys.is_empty() {
        out.extend_from_slice(b"{}");
        return;
    }
    out.push(b'{');
    let inner = depth + 1;
    for (i, (k, fv)) in keys.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        if let Some(c) = cfg {
            write_newline_indent(out, c, inner);
        }
        encode_string(out, k.as_bytes());
        out.push(b':');
        if cfg.is_some() {
            out.push(b' ');
        }
        match cfg {
            Some(c) => encode_reflect_indent(out, fv, c, inner),
            None => encode_reflect(out, fv),
        }
    }
    if let Some(c) = cfg {
        write_newline_indent(out, c, depth);
    }
    out.push(b'}');
}

/// Split `b"name,opt1,opt2"` → `(b"name", [b"opt1", b"opt2"])`.
fn split_first_comma(s: &[u8]) -> (&[u8], alloc::vec::Vec<&[u8]>) {
    let mut iter = s.split(|&c| c == b',');
    let first = iter.next().unwrap_or(&[]);
    let rest: alloc::vec::Vec<&[u8]> = iter.collect();
    (first, rest)
}

struct IndentCfg<'a> {
    prefix: &'a str,
    indent: &'a str,
}

// go: none — goish-only: the iterative encoder. Go recurses here and
// can afford to, because its own limit is enforced on the way IN.
/// Encode one `Value`, using an EXPLICIT stack for composites.
///
/// This used to recurse — `encode_value` into `encode_array`, back
/// into `encode_value` — one frame per level. Measured in a DEBUG
/// build on an 8 MiB goroutine stack, a depth-3500 tree encoded and
/// 4000 faulted, which is LESS THAN HALF what the recursive parser
/// managed. That made the encoder, not the parser, what
/// `maxNestingDepth` was really protecting, and it is why raising the
/// limit needed this as well as the parse and clone work.
///
/// The output is byte-for-byte what the recursive version produced:
/// the same sorted keys, the same separators, the same indentation at
/// the same depths. `Task::Lit` and `Task::Indent` exist so the
/// closing bracket and its indent can be QUEUED when a composite is
/// opened, which is the part recursion was doing implicitly on the
/// way back up.
fn encode_value(out: &mut Vec<byte>, v: &Value, cfg: Option<&IndentCfg>, _: &str, depth: usize) {
    enum Task<'a> {
        Val(&'a Value, usize),
        Lit(&'static [u8]),
        Indent(usize),
        Key(&'a string),
    }
    // Reverse order: the stack pops what should be emitted first.
    let mut stack: Vec<Task> = alloc::vec![Task::Val(v, depth)];
    while let Some(t) = stack.pop() {
        match t {
            Task::Lit(b) => out.extend_from_slice(b),
            Task::Indent(d) => {
                if let Some(c) = cfg {
                    write_newline_indent(out, c, d);
                }
            }
            Task::Key(k) => {
                encode_string(out, k.as_bytes());
                out.push(b':');
                if cfg.is_some() {
                    out.push(b' ');
                }
            }
            Task::Val(v, d) => match v {
                Value::Null => out.extend_from_slice(b"null"),
                Value::Bool(true) => out.extend_from_slice(b"true"),
                Value::Bool(false) => out.extend_from_slice(b"false"),
                Value::Number(n) => encode_number(out, *n),
                Value::String(s) => encode_string(out, s.as_bytes()),
                Value::Array(a) => {
                    let raw: &[Value] = a;
                    if raw.is_empty() {
                        out.extend_from_slice(b"[]");
                        continue;
                    }
                    out.push(b'[');
                    let inner = d + 1;
                    stack.push(Task::Lit(b"]"));
                    stack.push(Task::Indent(d));
                    for (i, item) in raw.iter().enumerate().rev() {
                        stack.push(Task::Val(item, inner));
                        stack.push(Task::Indent(inner));
                        if i > 0 {
                            stack.push(Task::Lit(b","));
                        }
                    }
                }
                Value::Object(o) => {
                    if o.Len() == 0 {
                        out.extend_from_slice(b"{}");
                        continue;
                    }
                    // Go's encoding/json marshals map keys in sorted order.
                    let mut pairs: alloc::vec::Vec<(&string, &Value)> = o.__iter().collect();
                    pairs.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
                    out.push(b'{');
                    let inner = d + 1;
                    stack.push(Task::Lit(b"}"));
                    stack.push(Task::Indent(d));
                    for (i, (k, val)) in pairs.iter().enumerate().rev() {
                        stack.push(Task::Val(val, inner));
                        stack.push(Task::Key(k));
                        stack.push(Task::Indent(inner));
                        if i > 0 {
                            stack.push(Task::Lit(b","));
                        }
                    }
                }
            },
        }
    }
}

fn encode_number(out: &mut Vec<byte>, n: f64) {
    if n.is_nan() || n.is_infinite() {
        // JSON doesn't have NaN/Infinity. Emit "null" — Go does the
        // same in its dynamic-Value path. Strictly speaking Go errors
        // for typed-Marshal; we choose "null" to keep round-trip simple.
        out.extend_from_slice(b"null");
        return;
    }
    // Go formats JSON numbers with the ES6 conversion, not 'g'
    // (encoding/json floatEncoder / jsonwire.AppendFloat).
    jsontext::AppendFloat(out, n, 64);
}

// go: sdk 1.25.5 encoding/json/encode.go:1010-1077 appendString
/// Go: the string encoder, with `escapeHTML` true — which is what
/// `Marshal` always uses and what an `Encoder` uses unless
/// `SetEscapeHTML(false)` says otherwise.
///
/// This used to escape only the seven characters JSON itself requires,
/// which left three problems, all of them silent:
///
///   * `<`, `>` and `&` went through RAW. Go escapes them as `\u003c`,
///     `\u003e` and `\u0026` for one documented reason: "so that the
///     JSON will be safe to embed inside HTML <script> tags". A
///     marshalled string containing `</script>` closed the enclosing
///     script block. goish already had `HTMLEscape`, correctly ported;
///     `Marshal` simply never called it.
///   * U+2028 and U+2029 went through raw. They are valid JSON and are
///     LINE TERMINATORS in JavaScript, so a string containing one
///     changes how the surrounding script parses.
///   * Invalid UTF-8 went through raw, producing output that is not
///     valid JSON at all and that a conformant parser rejects. Go
///     replaces each bad byte with U+FFFD and succeeds.
fn encode_string(out: &mut Vec<byte>, s: &[byte]) {
    out.push(b'"');
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i < s.len() {
        let b = s[i];
        if b < 0x80 {
            // Go: if htmlSafeSet[b] { i++; continue }
            if b >= 0x20 && b != b'"' && b != b'\\' && b != b'<' && b != b'>' && b != b'&' {
                i += 1;
                continue;
            }
            out.extend_from_slice(&s[start..i]);
            match b {
                b'\\' | b'"' => {
                    out.push(b'\\');
                    out.push(b);
                }
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b'\x08' => out.extend_from_slice(b"\\b"),
                b'\x0c' => out.extend_from_slice(b"\\f"),
                _ => {
                    // Go: `\u00` + hex — which is also how `<`, `>` and
                    // `&` come out.
                    out.extend_from_slice(b"\\u00");
                    out.push(hex_digit(b >> 4));
                    out.push(hex_digit(b & 0xF));
                }
            }
            i += 1;
            start = i;
            continue;
        }
        let (c, size) = crate::unicode::utf8::DecodeRune(&s[i..]);
        let size = size.unsigned_abs() as usize;
        // Go: if c == utf8.RuneError && size == 1 — an invalid byte.
        if c == crate::unicode::utf8::RuneError && size == 1 {
            out.extend_from_slice(&s[start..i]);
            out.extend_from_slice(b"\\ufffd");
            i += size;
            start = i;
            continue;
        }
        // Go: U+2028 and U+2029.
        if c == 0x2028 || c == 0x2029 {
            out.extend_from_slice(&s[start..i]);
            out.extend_from_slice(b"\\u202");
            out.push(hex_digit((c & 0xF) as u8)); // goishlint:ignore GOISH005 - c is 0x2028 or 0x2029 here, so the low nibble is 8 or 9.
            i += size;
            start = i;
            continue;
        }
        i += size;
    }
    out.extend_from_slice(&s[start..]);
    out.push(b'"');
}

// go: none — goish idiom: Go indexes the package-level string
//     `const hex = "0123456789abcdef"`; goish spells the lookup as the
//     arithmetic it is.
fn hex_digit(n: u8) -> u8 {
    if n < 10 {
        return b'0' + n;
    }
    return b'a' + n - 10;
}

fn write_newline_indent(out: &mut Vec<byte>, cfg: &IndentCfg, depth: usize) {
    out.push(b'\n');
    out.extend_from_slice(cfg.prefix.as_bytes());
    for _ in 0..depth {
        out.extend_from_slice(cfg.indent.as_bytes());
    }
}

// ─── Unmarshal — recursive-descent parser ──────────────────────────────
//
// Goish form mirrors Go: `Unmarshal(data, &v)`. The destination may be
// any `T: FromValue` — `json::Value` for the dynamic case, or a typed
// struct produced by `#[goish::reflect]`. The macro emits a tag-driven
// `FromValue` impl that walks the parsed `Value::Object` and assigns
// fields by `Tag.Get("json")` (falling back to the field name).

/// `json.Unmarshal(data, &v)` — typed unmarshal. The destination type
/// chooses how the parsed JSON is interpreted.
pub fn Unmarshal<T: FromValue>(data: &[byte], dest: &mut T) -> error {
    let (raw, err) = parse_to_value(data);
    if err != nil {
        return err;
    }
    // Owning form: for `T = Value` this MOVES the parsed tree rather
    // than cloning it, which is what keeps a deeply nested document
    // off the stack. Every other T takes the borrowing default.
    let (v, err) = T::from_value_owned(raw);
    // Go: a null into a primitive leaves the target alone and reports
    // no error. See the note on ERR_NULL_NOOP.
    if err == ERR_NULL_NOOP {
        return nil;
    }
    if err != nil {
        return err;
    }
    *dest = v;
    nil
}

/// Internal: parse bytes into a dynamic `Value`. Used by `Unmarshal`
/// and by `Decoder.Decode`. Mirrors Go's package-private parsing path.

// go: sdk 1.25.5 encoding/json/scanner.go:600-612 quoteChar
/// Go: "special cases - different from quoted strings" — a single quote
/// is `'\''` and a double quote is `'"'`; everything else is
/// strconv.Quote's rendering with the outer quotes swapped for single
/// ones.
fn quote_char(c: crate::types::byte) -> string {
    if c == b'\'' {
        return string::from("'\\''");
    }
    if c == b'"' {
        return string::from("'\"'");
    }
    // Go: s := strconv.Quote(string(c)); return "'" + s[1:len(s)-1] + "'"
    let q = crate::strconv::Quote(string::from_bytes(&[c]));
    let qb = q.as_bytes();
    let inner = string::from_bytes(&qb[1..qb.len() - 1]);
    return string::from("'") + inner + string::from("'");
}

// go: none — goish idiom: Go's scanner builds a `*SyntaxError` whose msg
// is "invalid character " + quoteChar(c) + " " + <what it was looking
// for>. goish's parser is recursive descent rather than a state
// machine, so the context is the call site's own words instead of a
// state name — but the SENTENCE is Go's, because that sentence is what
// a caller reads when a document fails to parse. Answering "invalid
// syntax" to all of them, as this did, says only that something is
// wrong somewhere.
fn syntax_err(c: crate::types::byte, context: &str) -> error {
    return errors::New(
        string::from("invalid character ")
            + quote_char(c)
            + string::from(" ")
            + string::from(context),
    );
}

// go: none — goish idiom: Go's scanner substitutes a SPACE for the
// end of input when it is part-way through a literal or a number, so
// "1e" reports "invalid character ' ' in exponent of numeric literal"
// rather than a truncation. Inside a container it reports the
// truncation instead; see `unexpected_end`.
fn syntax_err_eof(context: &str) -> error {
    return syntax_err(b' ', context);
}

// go: none — goish idiom: Go's `Unmarshal` reports a truncated document
// as "unexpected end of JSON input" (SyntaxError, encoding/json), not
// as an invalid character.
fn unexpected_end() -> error {
    return errors::New(string::from("unexpected end of JSON input"));
}

fn parse_to_value(data: &[byte]) -> (Value, error) {
    let mut p = Parser { data, pos: 0, depth: 0 };
    p.skip_ws();
    let (v, err) = p.parse_value();
    if err != nil {
        return (Value::Null, err);
    }
    p.skip_ws();
    if p.pos != data.len() {
        // Go: "invalid character 'x' after top-level value"
        return (
            Value::Null,
            syntax_err(data[p.pos], "after top-level value"),
        );
    }
    (v, nil)
}

// go: sdk 1.25.5 encoding/json/scanner.go:148 maxNestingDepth
/// Go: "This limits the max nesting depth to prevent stack overflow.
/// This is permitted by RFC 7159 section 9." Go's value is 10000.
///
/// goish's is 2000, and there are THREE recursions behind that number,
/// not the one the note here used to name. Measured in a DEBUG build —
/// which is what `make e2e` runs — on an 8 MiB goroutine stack.
///
///   PARSE — fixed. `parse_value` recursed into
///   `parse_array`/`parse_object` where Go's scanner keeps an explicit
///   `parseState` slice. Depth 8000 SIGSEGVd without a `maybe_grow`
///   pivot, 8500 with one. It is an explicit frame stack now and the
///   pivot is gone.
///
///   CLONE — avoided. `Unmarshal` ended with `T::from_value(&raw)`,
///   and for `T = Value` that is `v.clone()`: one frame per level over
///   the whole tree, failing between 8000 and 9000. `from_value_owned`
///   moves the tree instead, so this path costs nothing per level.
///
///   ENCODE (Value) — fixed. `encode_value` recursed through
///   `encode_array`/`encode_object`; it is a work stack now and those
///   two are gone. This is the encoder behind `Compact`, `Indent` and
///   `Value::String`.
///
///   ENCODE (reflect) — still recursive, and the BINDING one.
///   `Marshal` does not go through `encode_value` at all: it is
///   generic over `reflect::Reflect` and walks `encode_reflect`, which
///   recurses per level. Measured: a depth-3500 tree marshals, 4000
///   faults. That is less than half the parser's old ceiling, so the
///   limit was never really about the parser at all.
///
/// So 2000 stays, and the margin it buys is about 1.8x against
/// `encode_reflect` — not the 4x this note once claimed against the
/// parser. That number was measured on the wrong path.
///
/// Raising it to Go's 10000 needs `encode_reflect` iterative too.
/// Until then a REFUSAL is the right failure: rejecting a document Go
/// accepts is a divergence, and parsing one that then crashes on
/// re-encode is a denial of service with an extra step.
///
/// Checked and NOT a constraint: dropping a deep tree. Rust's Drop
/// glue recurses, but its frames are small — 2000, 5000 and 10000 all
/// drop cleanly.
const maxNestingDepth: usize = 2000;

struct Parser<'a> {
    data: &'a [byte],
    pos: usize,
    /// Nesting depth of the composite currently being parsed.
    ///
    /// Go: encoding/json/scanner.go:148 —
    ///   `// This limits the max nesting depth to prevent stack
    ///    overflow. This is permitted by RFC 7159 section 9.
    ///    const maxNestingDepth = 10000`
    ///
    /// Go's v1 scanner keeps an explicit parseState stack and checks
    /// its length; this parser recurses, so the same bound is not an
    /// optimisation but the only thing standing between a document and
    /// the stack. Measured without it: depth 10001 parsed where Go
    /// refuses, and 500000 printed "goish: runtime error: stack
    /// overflow".
    depth: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<byte> {
        if self.pos < self.data.len() {
            Some(self.data[self.pos])
        } else {
            None
        }
    }

    fn advance(&mut self) -> Option<byte> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn skip_ws(&mut self) {
        while self.pos < self.data.len() {
            match self.data[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn expect_ctx(&mut self, c: byte, context: &str) -> error {
        match self.peek() {
            Some(b) if b == c => {
                self.pos += 1;
                nil
            }
            Some(b) => syntax_err(b, context),
            None => unexpected_end(),
        }
    }

    // go: none — goish-only: the iterative driver Go's v1 scanner gets
    // from its explicit `parseState` stack.
    /// Parse one value, using an EXPLICIT stack for composites.
    ///
    /// This used to recurse — `parse_value` called `parse_array`, which
    /// called `parse_value` — where Go's scanner keeps a `parseState`
    /// slice and does not. That is why Go affords maxNestingDepth =
    /// 10000 at no stack cost and goish could not: 10000 recursive
    /// frames overrun an 8 MiB goroutine stack in a debug build
    /// (measured: without a pivot, depth 8000 SIGSEGVs), so the limit
    /// was 2000 and a `maybe_grow` pivot onto a fresh stack propped it
    /// up. With the stack explicit, depth costs a heap frame instead of
    /// a call frame.
    ///
    /// Checked BEFORE the change, because it would otherwise have moved
    /// the crash rather than removed it: a deep `Value` tree is also
    /// dropped recursively by Rust's glue. Built one iteratively and
    /// dropped it at 2000, 5000 and 10000 — all fine. Drop frames are
    /// small; the parser's were the fat ones.
    fn parse_value(&mut self) -> (Value, error) {
        enum Frame {
            Arr(Vec<Value>),
            Obj(map<string, Value>, string),
        }
        let mut stack: Vec<Frame> = Vec::new();
        let mut done: Value;

        'outer: loop {
            self.skip_ws();
            match self.peek() {
                Some(b'[') | Some(b'{') => {
                    // Go: scanner.go pushes onto parseState and refuses
                    // past maxNestingDepth. The stack height IS the
                    // depth, so the check is the same one.
                    if stack.len() >= maxNestingDepth {
                        let b = self.peek().unwrap_or(b'[');
                        return (Value::Null, syntax_err(b, "exceeded max depth"));
                    }
                    let open = self.peek().unwrap_or(b'[');
                    self.pos += 1;
                    self.skip_ws();
                    if open == b'[' {
                        if self.peek() == Some(b']') {
                            self.pos += 1;
                            done = Value::Array(slice::__from_vec(Vec::new()));
                        } else {
                            stack.push(Frame::Arr(Vec::new()));
                            continue 'outer;
                        }
                    } else if self.peek() == Some(b'}') {
                        self.pos += 1;
                        done = Value::Object(map::new());
                    } else {
                        let (k, err) = self.read_object_key();
                        if err != nil {
                            return (Value::Null, err);
                        }
                        stack.push(Frame::Obj(map::new(), k));
                        continue 'outer;
                    }
                }
                Some(b'"') => {
                    let (v, e) = self.parse_string_value();
                    if e != nil {
                        return (Value::Null, e);
                    }
                    done = v;
                }
                Some(b't') | Some(b'f') => {
                    let (v, e) = self.parse_bool();
                    if e != nil {
                        return (Value::Null, e);
                    }
                    done = v;
                }
                Some(b'n') => {
                    let (v, e) = self.parse_null();
                    if e != nil {
                        return (Value::Null, e);
                    }
                    done = v;
                }
                Some(b'-') | Some(b'0'..=b'9') => {
                    let (v, e) = self.parse_number();
                    if e != nil {
                        return (Value::Null, e);
                    }
                    done = v;
                }
                // Go: "invalid character 'x' looking for beginning of value"
                Some(b) => return (Value::Null, syntax_err(b, "looking for beginning of value")),
                None => return (Value::Null, unexpected_end()),
            }

            // `done` is finished. Attach it to the frame beneath and
            // keep closing frames that end here.
            loop {
                let mut frame = match stack.pop() {
                    None => return (done, nil),
                    Some(f) => f,
                };
                match &mut frame {
                    Frame::Arr(items) => {
                        items.push(done);
                        self.skip_ws();
                        match self.peek() {
                            Some(b',') => {
                                self.pos += 1;
                                self.skip_ws();
                                stack.push(frame);
                                continue 'outer;
                            }
                            Some(b']') => {
                                self.pos += 1;
                                match frame {
                                    Frame::Arr(v) => done = Value::Array(slice::__from_vec(v)),
                                    _ => unreachable!(),
                                }
                            }
                            // Go: "invalid character 'x' after array element"
                            Some(b) => return (Value::Null, syntax_err(b, "after array element")),
                            None => return (Value::Null, unexpected_end()),
                        }
                    }
                    Frame::Obj(m, key) => {
                        m.Set(key.clone(), done);
                        self.skip_ws();
                        match self.peek() {
                            Some(b',') => {
                                self.pos += 1;
                                let (k, err) = self.read_object_key();
                                if err != nil {
                                    return (Value::Null, err);
                                }
                                *key = k;
                                stack.push(frame);
                                continue 'outer;
                            }
                            Some(b'}') => {
                                self.pos += 1;
                                match frame {
                                    Frame::Obj(m, _) => done = Value::Object(m),
                                    _ => unreachable!(),
                                }
                            }
                            // Go: "invalid character 'x' after object key:value pair"
                            Some(b) => {
                                return (Value::Null, syntax_err(b, "after object key:value pair"))
                            }
                            None => return (Value::Null, unexpected_end()),
                        }
                    }
                }
            }
        }
    }

    // go: none — goish-only: the key half of Go's object loop, split so
    // the driver above can read a key at its two points (the first, and
    // after each comma) without duplicating the parse.
    fn read_object_key(&mut self) -> (string, error) {
        self.skip_ws();
        let (key_bytes, err) = self.parse_string_bytes();
        if err != nil {
            return (string::new(), err);
        }
        let key = string::__from_vec(key_bytes);
        self.skip_ws();
        // Go: "invalid character 'x' after object key"
        let err = self.expect_ctx(b':', "after object key");
        if err != nil {
            return (string::new(), err);
        }
        self.skip_ws();
        (key, nil)
    }

    fn parse_null(&mut self) -> (Value, error) {
        if self.literal_match(b"null") {
            (Value::Null, nil)
        } else {
            // Go: "invalid character 'x' in literal null (expecting 'u')"
            // — the byte reported is the first one that did NOT match,
            // and at end of input Go substitutes a space.
            return (Value::Null, self.literal_err(b"null"));
        }
    }

    fn parse_bool(&mut self) -> (Value, error) {
        if self.literal_match(b"true") {
            (Value::Bool(true), nil)
        } else if self.literal_match(b"false") {
            (Value::Bool(false), nil)
        } else {
            let lit: &[byte] = if self.peek() == Some(b'f') {
                b"false"
            } else {
                b"true"
            };
            return (Value::Null, self.literal_err(lit));
        }
    }

    // go: none — goish idiom: Go's scanner walks a literal byte by byte
    // and names the first one that does not fit, together with the one
    // it wanted: "invalid character 'p' in literal true (expecting 'e')".
    // At end of input it substitutes a space, which is why "tru" reports
    // ' ' rather than a truncation.
    fn literal_err(&self, lit: &[byte]) -> error {
        let mut i = 0usize;
        while i < lit.len() {
            let got = if self.pos + i < self.data.len() {
                Some(self.data[self.pos + i])
            } else {
                None
            };
            match got {
                Some(b) if b == lit[i] => i += 1,
                Some(b) => {
                    return errors::New(
                        string::from("invalid character ")
                            + quote_char(b)
                            + string::from(" in literal ")
                            + string::from_bytes(lit)
                            + string::from(" (expecting ")
                            + quote_char(lit[i])
                            + string::from(")"),
                    );
                }
                None => {
                    return errors::New(
                        string::from("invalid character ")
                            + quote_char(b' ')
                            + string::from(" in literal ")
                            + string::from_bytes(lit)
                            + string::from(" (expecting ")
                            + quote_char(lit[i])
                            + string::from(")"),
                    );
                }
            }
        }
        return unexpected_end();
    }

    fn literal_match(&mut self, lit: &[byte]) -> bool {
        if self.data.len() - self.pos < lit.len() {
            return false;
        }
        if &self.data[self.pos..self.pos + lit.len()] != lit {
            return false;
        }
        self.pos += lit.len();
        true
    }

    // go: none — goish idiom: the byte the parser is looking at, in
    // Go's sentence. At end of input Go substitutes a space, which is
    // what makes "1e" report "invalid character ' ' in exponent of
    // numeric literal" rather than a truncation.
    fn here_err(&self, context: &str) -> error {
        let e = match self.peek() {
            Some(b) => syntax_err(b, context),
            None => syntax_err_eof(context),
        };
        return e;
    }

    fn parse_number(&mut self) -> (Value, error) {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // Integer part
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            // Go: "invalid character 'x' in numeric literal"
            _ => return (Value::Null, self.here_err("in numeric literal")),
        }
        // Fraction
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                // Go: "invalid character 'x' after decimal point in
                // numeric literal"
                return (
                    Value::Null,
                    self.here_err("after decimal point in numeric literal"),
                );
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        // Exponent
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                // Go: "invalid character 'x' in exponent of numeric
                // literal"
                return (Value::Null, self.here_err("in exponent of numeric literal"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let lit = &self.data[start..self.pos];
        // SAFETY: literal is ASCII digits + '.' / 'e' / sign.
        let s = match core::str::from_utf8(lit) {
            Ok(s) => s,
            Err(_) => return (Value::Null, self.here_err("in numeric literal")),
        };
        let owned = string::from_bytes(s.as_bytes());
        let (n, err) = strconv::ParseFloat(owned, 64);
        if err != nil {
            return (Value::Null, self.here_err("in numeric literal"));
        }
        (Value::Number(n), nil)
    }

    fn parse_string_value(&mut self) -> (Value, error) {
        let (s, err) = self.parse_string_bytes();
        if err != nil {
            return (Value::Null, err);
        }
        (Value::String(string::__from_vec(s)), nil)
    }

    fn parse_string_bytes(&mut self) -> (Vec<byte>, error) {
        // Go: an object key that is not a string is
        // "invalid character 'x' looking for beginning of object key
        // string" — the only place a string is REQUIRED rather than
        // merely one of the possible values.
        if self.peek() != Some(b'"') {
            let e = match self.peek() {
                Some(b) => syntax_err(b, "looking for beginning of object key string"),
                None => unexpected_end(),
            };
            return (Vec::new(), e);
        }
        self.pos += 1;
        let mut out: Vec<byte> = Vec::new();
        loop {
            let c = match self.advance() {
                Some(c) => c,
                None => return (Vec::new(), unexpected_end()),
            };
            match c {
                b'"' => return (out, nil),
                b'\\' => {
                    let esc = match self.advance() {
                        Some(c) => c,
                        None => return (Vec::new(), unexpected_end()),
                    };
                    match esc {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(b'\x08'),
                        b'f' => out.push(b'\x0c'),
                        b'u' => {
                            let cp = match self.parse_hex4() {
                                Some(v) => v,
                                // Go: "invalid character 'Z' in \u
                                // hexadecimal character escape"
                                None => {
                                    return (
                                        Vec::new(),
                                        self.here_err("in \\u hexadecimal character escape"),
                                    )
                                }
                            };
                            // Handle surrogate pairs for UTF-16.
                            if (0xD800..=0xDBFF).contains(&cp) {
                                // Go's `unquoteBytes`: a high surrogate is
                                // followed by a LOOKAHEAD for `\uXXXX`, and
                                // if that is not a valid low surrogate the
                                // rune becomes U+FFFD and the lookahead is
                                // NOT consumed — Go never errors here.
                                //
                                // goish used to require the pair and reject
                                // the string otherwise, so `"\uD800"` was a
                                // syntax error where Go decodes it to U+FFFD.
                                // A document carrying one lone surrogate —
                                // and real-world JSON does — was rejected
                                // whole.
                                let save = self.pos;
                                let mut paired = false;
                                if self.advance() == Some(b'\\') && self.advance() == Some(b'u') {
                                    if let Some(lo) = self.parse_hex4() {
                                        if (0xDC00..=0xDFFF).contains(&lo) {
                                            let combined = 0x10000
                                                + (crate::uint32(cp - 0xD800) << 10)
                                                + crate::uint32(lo - 0xDC00);
                                            encode_utf8(&mut out, combined as i32);
                                            paired = true;
                                        }
                                    }
                                }
                                if !paired {
                                    // Go: "Invalid surrogate; fall back to
                                    // replacement rune." The lookahead is
                                    // rewound so those bytes are re-read as
                                    // whatever they actually are.
                                    self.pos = save;
                                    encode_utf8(&mut out, 0xFFFD);
                                }
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                // Lone low surrogate — replace with U+FFFD per WHATWG.
                                encode_utf8(&mut out, 0xFFFD);
                            } else {
                                encode_utf8(&mut out, cp as i32);
                            }
                        }
                        // Go: "invalid character 'x' in string escape code"
                        _ => return (Vec::new(), syntax_err(esc, "in string escape code")),
                    }
                }
                _ => out.push(c),
            }
        }
    }

    fn parse_hex4(&mut self) -> Option<u32> {
        if self.data.len() - self.pos < 4 {
            return None;
        }
        let mut n: u32 = 0;
        for i in 0..4 {
            let c = self.data[self.pos + i];
            let d = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' => (c - b'a' + 10) as u32,
                b'A'..=b'F' => (c - b'A' + 10) as u32,
                _ => return None,
            };
            n = n * 16 + d;
        }
        self.pos += 4;
        Some(n)
    }
}

fn encode_utf8(out: &mut Vec<byte>, cp: i32) {
    let mut tmp = [0u8; 4];
    let n = crate::unicode::utf8::EncodeRune(&mut tmp, cp);
    out.extend_from_slice(&tmp[..n as usize]);
}

// ─── Encoder / Decoder over io ─────────────────────────────────────────

pub struct Encoder<W: io::Writer> {
    w: W,
    prefix: alloc::string::String,
    indent: alloc::string::String,
}

pub fn NewEncoder<W: io::Writer>(w: W) -> Encoder<W> {
    Encoder {
        w,
        prefix: alloc::string::String::new(),
        indent: alloc::string::String::new(),
    }
}

impl<W: io::Writer> Encoder<W> {
    pub fn SetIndent(&mut self, prefix: &string, indent: &string) {
        self.prefix.clear();
        // SAFETY: `string` carries valid UTF-8 by construction.
        unsafe {
            self.prefix.push_str(core::str::from_utf8_unchecked(
                crate::gostring::__crate_as_bytes(prefix),
            ));
            self.indent.clear();
            self.indent.push_str(core::str::from_utf8_unchecked(
                crate::gostring::__crate_as_bytes(indent),
            ));
        }
    }

    pub fn Encode(&mut self, v: &Value) -> error {
        let bytes = if self.indent.is_empty() && self.prefix.is_empty() {
            let (b, _) = Marshal(v);
            b
        } else {
            let (b, _) = MarshalIndent(v, &self.prefix, &self.indent);
            b
        };
        let mut buf = bytes.__into_vec();
        buf.push(b'\n'); // Encoder appends a newline like Go.
        let (_, err) = self.w.Write(slice::__from_vec(buf));
        err
    }
}

pub struct Decoder {
    r: alloc::boxed::Box<dyn io::Reader>,
    buf: Vec<byte>,
    scan_pos: usize,
    token_state: u8,
    token_stack: Vec<u8>,
    use_number: bool,
}

/// Cloning a Decoder shallow-copies the buffer + scan state but
/// resets the underlying reader to empty. Mirrors what user-defined
/// structs that embed `json.Decoder` expect from goishc's blanket
/// `#[derive(Clone)]`. Semantically lossy at a real mid-stream
/// position; in practice only the Default-shaped Decoders that come
/// from struct initializers get cloned this way.
impl Clone for Decoder {
    fn clone(&self) -> Self {
        struct EmptyReader;
        impl io::Reader for EmptyReader {
            fn Read(&mut self, _p: &mut crate::goslice::slice<byte>) -> (int, error) {
                (0, errors::New(crate::gostring::string::from("EOF")))
            }
        }
        Decoder {
            r: alloc::boxed::Box::new(EmptyReader),
            buf: self.buf.clone(),
            scan_pos: self.scan_pos,
            token_state: self.token_state,
            token_stack: self.token_stack.clone(),
            use_number: self.use_number,
        }
    }
}

impl Default for Decoder {
    /// Default decoder wraps an empty byte source. Lets the Goish-
    /// embedding pattern `struct UserDecoder { json::Decoder, … }`
    /// derive `Default` without manually unwrapping the inner state.
    fn default() -> Self {
        // Empty reader — yields EOF on first Read. Suitable for
        // struct-default initialization; the consumer will typically
        // overwrite via assignment.
        struct EmptyReader;
        impl io::Reader for EmptyReader {
            fn Read(&mut self, _p: &mut crate::goslice::slice<byte>) -> (int, error) {
                (0, errors::New(crate::gostring::string::from("EOF")))
            }
        }
        Decoder {
            r: alloc::boxed::Box::new(EmptyReader),
            buf: Vec::new(),
            scan_pos: 0,
            token_state: TOKEN_TOP_VALUE,
            token_stack: Vec::new(),
            use_number: false,
        }
    }
}

// Token-state constants — mirror Go's tokenTopValue .. tokenObjectComma.
const TOKEN_TOP_VALUE: u8 = 0;
const TOKEN_ARRAY_START: u8 = 1;
const TOKEN_ARRAY_VALUE: u8 = 2;
const TOKEN_ARRAY_COMMA: u8 = 3;
const TOKEN_OBJECT_START: u8 = 4;
const TOKEN_OBJECT_KEY: u8 = 5;
const TOKEN_OBJECT_COLON: u8 = 6;
const TOKEN_OBJECT_VALUE: u8 = 7;
const TOKEN_OBJECT_COMMA: u8 = 8;

pub fn NewDecoder<R: io::Reader + 'static>(r: R) -> Decoder {
    Decoder {
        r: alloc::boxed::Box::new(r),
        buf: Vec::new(),
        scan_pos: 0,
        token_state: TOKEN_TOP_VALUE,
        token_stack: Vec::new(),
        use_number: false,
    }
}

impl Decoder {
    /// `(*Decoder) UseNumber()` — tells the Decoder to surface JSON
    /// numbers as `Number` (the textual form) rather than `float64`.
    /// State flag only; the Value-emit path consults it when assembling
    /// number tokens. Returns `&mut Self` to chain Go-style.
    #[allow(non_snake_case)]
    pub fn UseNumber(&mut self) -> &mut Self {
        self.use_number = true;
        self
    }

    /// Read all available bytes from the underlying reader and decode
    /// them as a single JSON value. v1: streaming-token decoding lands
    /// later; for now Decode reads to EOF and parses the whole buffer.
    pub fn Decode(&mut self) -> (Value, error) {
        // Drain reader into self.buf.
        let mut chunk = slice::__from_vec({
            let mut v: Vec<byte> = Vec::with_capacity(4096);
            v.resize(4096, 0);
            v
        });
        loop {
            let (n, err) = self.r.Read(&mut chunk);
            if n > 0 {
                let raw: &[byte] = &chunk;
                self.buf.extend_from_slice(&raw[..n as usize]);
            }
            if err != nil {
                if errors::Is(err.clone(), io::EOF) {
                    break;
                }
                return (Value::Null, err);
            }
            if n == 0 {
                break;
            }
        }
        parse_to_value(&self.buf)
    }

    /// Return the next JSON token from the input stream.
    /// At EOF returns `(Token::Null, io::EOF)`.
    pub fn Token(&mut self) -> (Token, error) {
        self.fill_buf();
        loop {
            let c = match self.peek() {
                Some(b) => b,
                None => return (Token::Null, io::EOF.into()),
            };
            match c {
                b'[' => {
                    if !self.token_value_allowed() {
                        return self.token_error(c);
                    }
                    self.scan_pos += 1;
                    self.token_stack.push(self.token_state);
                    self.token_state = TOKEN_ARRAY_START;
                    return (Token::Delim(Delim(b'[')), nil);
                }
                b']' => {
                    if self.token_state != TOKEN_ARRAY_START
                        && self.token_state != TOKEN_ARRAY_COMMA
                    {
                        return self.token_error(c);
                    }
                    self.scan_pos += 1;
                    self.token_state = self.token_stack.pop().unwrap_or(TOKEN_TOP_VALUE);
                    self.token_value_end();
                    return (Token::Delim(Delim(b']')), nil);
                }
                b'{' => {
                    if !self.token_value_allowed() {
                        return self.token_error(c);
                    }
                    self.scan_pos += 1;
                    self.token_stack.push(self.token_state);
                    self.token_state = TOKEN_OBJECT_START;
                    return (Token::Delim(Delim(b'{')), nil);
                }
                b'}' => {
                    if self.token_state != TOKEN_OBJECT_START
                        && self.token_state != TOKEN_OBJECT_COMMA
                    {
                        return self.token_error(c);
                    }
                    self.scan_pos += 1;
                    self.token_state = self.token_stack.pop().unwrap_or(TOKEN_TOP_VALUE);
                    self.token_value_end();
                    return (Token::Delim(Delim(b'}')), nil);
                }
                b':' => {
                    if self.token_state != TOKEN_OBJECT_COLON {
                        return self.token_error(c);
                    }
                    self.scan_pos += 1;
                    self.token_state = TOKEN_OBJECT_VALUE;
                    continue;
                }
                b',' => {
                    if self.token_state == TOKEN_ARRAY_COMMA {
                        self.scan_pos += 1;
                        self.token_state = TOKEN_ARRAY_VALUE;
                        continue;
                    }
                    if self.token_state == TOKEN_OBJECT_COMMA {
                        self.scan_pos += 1;
                        self.token_state = TOKEN_OBJECT_KEY;
                        continue;
                    }
                    return self.token_error(c);
                }
                b'"' => {
                    // Object key detection: when the decoder is in object-start
                    // or object-key state, the next string is an object key.
                    let is_key = self.token_state == TOKEN_OBJECT_START
                        || self.token_state == TOKEN_OBJECT_KEY;
                    let old_state = self.token_state;
                    self.token_state = TOKEN_TOP_VALUE; // let scan_string think we're parsing a value
                    let (s, err) = self.scan_string_bytes();
                    self.token_state = old_state;
                    if err != nil {
                        return (Token::Null, err);
                    }
                    if is_key {
                        self.token_state = TOKEN_OBJECT_COLON;
                        return (Token::String(string::__from_vec(s)), nil);
                    }
                    // Regular string value
                    self.token_value_end();
                    return (Token::String(string::__from_vec(s)), nil);
                }
                _ => {
                    if !self.token_value_allowed() {
                        return self.token_error(c);
                    }
                    // Parse a literal value: true / false / null / number
                    let (tok, err) = self.scan_literal_or_number();
                    if err != nil {
                        return (Token::Null, err);
                    }
                    self.token_value_end();
                    return (tok, nil);
                }
            }
        }
    }

    /// More reports whether there are more elements in the current
    /// array or object being parsed.
    pub fn More(&mut self) -> bool {
        self.fill_buf();
        match self.peek() {
            Some(b']') | Some(b'}') => false,
            Some(_) => true,
            None => false,
        }
    }

    // ─── Token helpers ───────────────────────────────────────────────────

    fn fill_buf(&mut self) {
        if self.scan_pos >= self.buf.len() {
            let mut chunk = slice::__from_vec({
                let mut v: Vec<byte> = Vec::with_capacity(4096);
                v.resize(4096, 0);
                v
            });
            loop {
                let (n, err) = self.r.Read(&mut chunk);
                if n > 0 {
                    let raw: &[byte] = &chunk;
                    self.buf.extend_from_slice(&raw[..n as usize]);
                }
                if err != nil {
                    break;
                }
                if n == 0 {
                    break;
                }
            }
        }
    }

    fn peek(&mut self) -> Option<byte> {
        while self.scan_pos < self.buf.len() {
            let c = self.buf[self.scan_pos];
            if c != b' ' && c != b'\t' && c != b'\n' && c != b'\r' {
                return Some(c);
            }
            self.scan_pos += 1;
        }
        None
    }

    fn token_value_allowed(&self) -> bool {
        matches!(
            self.token_state,
            TOKEN_TOP_VALUE | TOKEN_ARRAY_START | TOKEN_ARRAY_VALUE | TOKEN_OBJECT_VALUE
        )
    }

    fn token_value_end(&mut self) {
        match self.token_state {
            TOKEN_ARRAY_START | TOKEN_ARRAY_VALUE => self.token_state = TOKEN_ARRAY_COMMA,
            TOKEN_OBJECT_VALUE => self.token_state = TOKEN_OBJECT_COMMA,
            _ => {}
        }
    }

    fn token_error(&self, _c: byte) -> (Token, error) {
        let msg = match self.token_state {
            TOKEN_TOP_VALUE => "json: invalid character: looking for beginning of value",
            TOKEN_ARRAY_START | TOKEN_ARRAY_VALUE | TOKEN_OBJECT_VALUE => {
                "json: invalid character: looking for beginning of value"
            }
            TOKEN_ARRAY_COMMA => "json: invalid character: after array element",
            TOKEN_OBJECT_KEY => {
                "json: invalid character: looking for beginning of object key string"
            }
            TOKEN_OBJECT_COLON => "json: invalid character: after object key",
            TOKEN_OBJECT_COMMA => "json: invalid character: after object key:value pair",
            _ => "json: invalid character",
        };
        (Token::Null, errors::New(string::from(msg)))
    }

    fn scan_string_bytes(&mut self) -> (Vec<byte>, error) {
        if self.scan_pos >= self.buf.len() || self.buf[self.scan_pos] != b'"' {
            return (Vec::new(), ErrSyntax.into());
        }
        self.scan_pos += 1; // consume opening quote
        let mut out: Vec<byte> = Vec::new();
        while self.scan_pos < self.buf.len() {
            let c = self.buf[self.scan_pos];
            self.scan_pos += 1;
            match c {
                b'"' => return (out, nil),
                b'\\' => {
                    if self.scan_pos >= self.buf.len() {
                        return (Vec::new(), ErrUnexpectedEnd.into());
                    }
                    let esc = self.buf[self.scan_pos];
                    self.scan_pos += 1;
                    match esc {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(b'\x08'),
                        b'f' => out.push(b'\x0c'),
                        b'u' => {
                            let cp = match self.scan_hex4() {
                                Some(v) => v,
                                None => return (Vec::new(), ErrSyntax.into()),
                            };
                            if (0xD800..=0xDBFF).contains(&cp) {
                                if self.scan_pos >= self.buf.len()
                                    || self.buf[self.scan_pos] != b'\\'
                                {
                                    return (Vec::new(), ErrSyntax.into());
                                }
                                self.scan_pos += 1;
                                if self.scan_pos >= self.buf.len()
                                    || self.buf[self.scan_pos] != b'u'
                                {
                                    return (Vec::new(), ErrSyntax.into());
                                }
                                self.scan_pos += 1;
                                let lo = match self.scan_hex4() {
                                    Some(v) => v,
                                    None => return (Vec::new(), ErrSyntax.into()),
                                };
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return (Vec::new(), ErrSyntax.into());
                                }
                                let combined =
                                    0x10000 + (((cp - 0xD800) as u32) << 10) + (lo - 0xDC00) as u32;
                                encode_utf8(&mut out, combined as i32);
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                encode_utf8(&mut out, 0xFFFD);
                            } else {
                                encode_utf8(&mut out, cp as i32);
                            }
                        }
                        _ => return (Vec::new(), ErrSyntax.into()),
                    }
                }
                _ => out.push(c),
            }
        }
        (Vec::new(), ErrUnexpectedEnd.into())
    }

    fn scan_hex4(&mut self) -> Option<u32> {
        if self.buf.len() - self.scan_pos < 4 {
            return None;
        }
        let mut n: u32 = 0;
        for i in 0..4 {
            let c = self.buf[self.scan_pos + i];
            let digit = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' => (c - b'a' + 10) as u32,
                b'A'..=b'F' => (c - b'A' + 10) as u32,
                _ => return None,
            };
            n = n * 16 + digit;
        }
        self.scan_pos += 4;
        Some(n)
    }

    fn scan_literal_or_number(&mut self) -> (Token, error) {
        let start = self.scan_pos;
        // true
        if self.buf.len() - self.scan_pos >= 4
            && &self.buf[self.scan_pos..self.scan_pos + 4] == b"true"
        {
            self.scan_pos += 4;
            return (Token::Bool(true), nil);
        }
        // false
        if self.buf.len() - self.scan_pos >= 5
            && &self.buf[self.scan_pos..self.scan_pos + 5] == b"false"
        {
            self.scan_pos += 5;
            return (Token::Bool(false), nil);
        }
        // null
        if self.buf.len() - self.scan_pos >= 4
            && &self.buf[self.scan_pos..self.scan_pos + 4] == b"null"
        {
            self.scan_pos += 4;
            return (Token::Null, nil);
        }
        // number
        self.scan_pos = start;
        self.scan_number()
    }

    fn scan_number(&mut self) -> (Token, error) {
        let start = self.scan_pos;
        if self.peek_at(start) == Some(b'-') {
            self.scan_pos = start + 1;
        }
        match self.peek_at(self.scan_pos) {
            Some(b'0') => self.scan_pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek_at(self.scan_pos), Some(b'0'..=b'9')) {
                    self.scan_pos += 1;
                }
            }
            _ => return (Token::Null, ErrSyntax.into()),
        }
        if self.peek_at(self.scan_pos) == Some(b'.') {
            self.scan_pos += 1;
            if !matches!(self.peek_at(self.scan_pos), Some(b'0'..=b'9')) {
                return (Token::Null, ErrSyntax.into());
            }
            while matches!(self.peek_at(self.scan_pos), Some(b'0'..=b'9')) {
                self.scan_pos += 1;
            }
        }
        if let Some(b'e') | Some(b'E') = self.peek_at(self.scan_pos) {
            self.scan_pos += 1;
            if let Some(b'+') | Some(b'-') = self.peek_at(self.scan_pos) {
                self.scan_pos += 1;
            }
            if !matches!(self.peek_at(self.scan_pos), Some(b'0'..=b'9')) {
                return (Token::Null, ErrSyntax.into());
            }
            while matches!(self.peek_at(self.scan_pos), Some(b'0'..=b'9')) {
                self.scan_pos += 1;
            }
        }
        let num_str = string::__from_vec(self.buf[start..self.scan_pos].to_vec());
        let (n, err) = strconv::ParseFloat(&num_str, 64);
        if err != nil {
            return (Token::Null, err);
        }
        (Token::Number(n), nil)
    }

    fn peek_at(&self, pos: usize) -> Option<byte> {
        if pos < self.buf.len() {
            Some(self.buf[pos])
        } else {
            None
        }
    }
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `json::Value` into the `Marshaler` registry. Idempotent;
/// called from `goish::init()`.
pub fn register_json_impls() {
    __goish_register_Marshaler_impl::<Value>();
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
impl crate::fmt::Stringer for Number {
    // go: none — goish idiom: see the note above.
    fn String(&self) -> crate::gostring::string {
        let v = self;
        return Number::String(v);
    }
}
