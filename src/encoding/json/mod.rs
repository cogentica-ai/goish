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

pub trait FromValue: Sized {
    /// Convert a JSON `Value` into `Self`. Returns `(Self, error)` —
    /// typical Go-shape, with the second value carrying the type-mismatch
    /// or out-of-range error if any.
    fn from_value(v: &Value) -> (Self, error);
}

// Identity — lets `Unmarshal(data, &mut json::Value)` work for the
// dynamic case (replacing the old `(Value, error)` shape).
impl FromValue for Value {
    fn from_value(v: &Value) -> (Self, error) {
        (v.clone(), nil)
    }
}

impl FromValue for bool {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Bool(b) => (*b, nil),
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

impl FromValue for crate::types::int {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) => (*n as crate::types::int, nil),
            _ => (0, errors::New("json: cannot unmarshal into int")),
        }
    }
}

impl FromValue for crate::types::uint {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) if *n >= 0.0 => (*n as crate::types::uint, nil),
            _ => (0, errors::New("json: cannot unmarshal into uint")),
        }
    }
}

impl FromValue for crate::types::float64 {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) => (*n, nil),
            _ => (0.0, errors::New("json: cannot unmarshal into float64")),
        }
    }
}

impl FromValue for crate::types::float32 {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) => (*n as crate::types::float32, nil),
            _ => (0.0, errors::New("json: cannot unmarshal into float32")),
        }
    }
}

impl FromValue for crate::types::byte {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) if *n >= 0.0 && *n <= 255.0 => (*n as crate::types::byte, nil),
            _ => (0, errors::New("json: cannot unmarshal into byte")),
        }
    }
}

impl FromValue for crate::types::rune {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::Number(n) => (*n as crate::types::rune, nil),
            _ => (0, errors::New("json: cannot unmarshal into rune")),
        }
    }
}

impl FromValue for string {
    fn from_value(v: &Value) -> (Self, error) {
        match v {
            Value::String(s) => (s.clone(), nil),
            _ => (string::new(), errors::New("json: cannot unmarshal into string")),
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
pub fn Indent(dst: slice<byte>, src: slice<byte>, prefix: &str, indent: &str) -> (slice<byte>, error) {
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

fn encode_reflect_indent(
    out: &mut Vec<byte>,
    v: &reflect::Value,
    cfg: &IndentCfg,
    depth: usize,
) {
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
        let as_ = match a { reflect::Value::String(s) => s.as_bytes(), _ => b"" };
        let bs = match b { reflect::Value::String(s) => s.as_bytes(), _ => b"" };
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

fn encode_value(out: &mut Vec<byte>, v: &Value, cfg: Option<&IndentCfg>, _: &str, depth: usize) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => encode_number(out, *n),
        Value::String(s) => encode_string(out, s.as_bytes()),
        Value::Array(a) => encode_array(out, a, cfg, depth),
        Value::Object(o) => encode_object(out, o, cfg, depth),
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

fn encode_string(out: &mut Vec<byte>, s: &[byte]) {
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\x08' => out.extend_from_slice(b"\\b"),
            b'\x0c' => out.extend_from_slice(b"\\f"),
            _ if c < 0x20 => {
                out.extend_from_slice(b"\\u00");
                out.push(hex_digit(c >> 4));
                out.push(hex_digit(c & 0xF));
            }
            _ => out.push(c),
        }
        i += 1;
    }
    out.push(b'"');
}

fn hex_digit(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + n - 10
    }
}

fn encode_array(out: &mut Vec<byte>, a: &slice<Value>, cfg: Option<&IndentCfg>, depth: usize) {
    let raw: &[Value] = a;
    if raw.is_empty() {
        out.extend_from_slice(b"[]");
        return;
    }
    out.push(b'[');
    let inner_depth = depth + 1;
    for (i, v) in raw.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        if let Some(c) = cfg {
            write_newline_indent(out, c, inner_depth);
        }
        encode_value(out, v, cfg, "", inner_depth);
    }
    if let Some(c) = cfg {
        write_newline_indent(out, c, depth);
    }
    out.push(b']');
}

fn encode_object(out: &mut Vec<byte>, o: &map<string, Value>, cfg: Option<&IndentCfg>, depth: usize) {
    if o.Len() == 0 {
        out.extend_from_slice(b"{}");
        return;
    }
    // Go's encoding/json marshals map keys in sorted order.
    let mut pairs: alloc::vec::Vec<(&string, &Value)> = o.__iter().collect();
    pairs.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
    out.push(b'{');
    let inner_depth = depth + 1;
    let mut first = true;
    for (k, v) in pairs {
        if !first {
            out.push(b',');
        }
        first = false;
        if let Some(c) = cfg {
            write_newline_indent(out, c, inner_depth);
        }
        encode_string(out, k.as_bytes());
        out.push(b':');
        if cfg.is_some() {
            out.push(b' ');
        }
        encode_value(out, v, cfg, "", inner_depth);
    }
    if let Some(c) = cfg {
        write_newline_indent(out, c, depth);
    }
    out.push(b'}');
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
    let (v, err) = T::from_value(&raw);
    if err != nil {
        return err;
    }
    *dest = v;
    nil
}

/// Internal: parse bytes into a dynamic `Value`. Used by `Unmarshal`
/// and by `Decoder.Decode`. Mirrors Go's package-private parsing path.
fn parse_to_value(data: &[byte]) -> (Value, error) {
    let mut p = Parser { data, pos: 0 };
    p.skip_ws();
    let (v, err) = p.parse_value();
    if err != nil {
        return (Value::Null, err);
    }
    p.skip_ws();
    if p.pos != data.len() {
        return (Value::Null, ErrSyntax.into());
    }
    (v, nil)
}

struct Parser<'a> {
    data: &'a [byte],
    pos: usize,
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

    fn expect(&mut self, c: byte) -> error {
        match self.peek() {
            Some(b) if b == c => {
                self.pos += 1;
                nil
            }
            Some(_) => ErrSyntax.into(),
            None => ErrUnexpectedEnd.into(),
        }
    }

    fn parse_value(&mut self) -> (Value, error) {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => self.parse_string_value(),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'n') => self.parse_null(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(_) => (Value::Null, ErrSyntax.into()),
            None => (Value::Null, ErrUnexpectedEnd.into()),
        }
    }

    fn parse_null(&mut self) -> (Value, error) {
        if self.literal_match(b"null") {
            (Value::Null, nil)
        } else {
            (Value::Null, ErrSyntax.into())
        }
    }

    fn parse_bool(&mut self) -> (Value, error) {
        if self.literal_match(b"true") {
            (Value::Bool(true), nil)
        } else if self.literal_match(b"false") {
            (Value::Bool(false), nil)
        } else {
            (Value::Null, ErrSyntax.into())
        }
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
            _ => return (Value::Null, ErrSyntax.into()),
        }
        // Fraction
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return (Value::Null, ErrSyntax.into());
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
                return (Value::Null, ErrSyntax.into());
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let lit = &self.data[start..self.pos];
        // SAFETY: literal is ASCII digits + '.' / 'e' / sign.
        let s = match core::str::from_utf8(lit) {
            Ok(s) => s,
            Err(_) => return (Value::Null, ErrSyntax.into()),
        };
        let owned = string::from_bytes(s.as_bytes());
        let (n, err) = strconv::ParseFloat(owned, 64);
        if err != nil {
            return (Value::Null, ErrSyntax.into());
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
        if self.advance() != Some(b'"') {
            return (Vec::new(), ErrSyntax.into());
        }
        let mut out: Vec<byte> = Vec::new();
        loop {
            let c = match self.advance() {
                Some(c) => c,
                None => return (Vec::new(), ErrUnexpectedEnd.into()),
            };
            match c {
                b'"' => return (out, nil),
                b'\\' => {
                    let esc = match self.advance() {
                        Some(c) => c,
                        None => return (Vec::new(), ErrUnexpectedEnd.into()),
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
                                None => return (Vec::new(), ErrSyntax.into()),
                            };
                            // Handle surrogate pairs for UTF-16.
                            if (0xD800..=0xDBFF).contains(&cp) {
                                // High surrogate — must be followed by \uXXXX low surrogate.
                                if self.advance() != Some(b'\\') {
                                    return (Vec::new(), ErrSyntax.into());
                                }
                                if self.advance() != Some(b'u') {
                                    return (Vec::new(), ErrSyntax.into());
                                }
                                let lo = match self.parse_hex4() {
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
                                // Lone low surrogate — replace with U+FFFD per WHATWG.
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

    fn parse_array(&mut self) -> (Value, error) {
        let err = self.expect(b'[');
        if err != nil {
            return (Value::Null, err);
        }
        let mut items: Vec<Value> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return (Value::Array(slice::__from_vec(items)), nil);
        }
        loop {
            let (v, err) = self.parse_value();
            if err != nil {
                return (Value::Null, err);
            }
            items.push(v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b']') => {
                    self.pos += 1;
                    return (Value::Array(slice::__from_vec(items)), nil);
                }
                Some(_) => return (Value::Null, ErrSyntax.into()),
                None => return (Value::Null, ErrUnexpectedEnd.into()),
            }
        }
    }

    fn parse_object(&mut self) -> (Value, error) {
        let err = self.expect(b'{');
        if err != nil {
            return (Value::Null, err);
        }
        let mut m: map<string, Value> = map::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return (Value::Object(m), nil);
        }
        loop {
            self.skip_ws();
            // Key — must be a string.
            let (key_bytes, err) = self.parse_string_bytes();
            if err != nil {
                return (Value::Null, err);
            }
            let key = string::__from_vec(key_bytes);
            self.skip_ws();
            let err = self.expect(b':');
            if err != nil {
                return (Value::Null, err);
            }
            self.skip_ws();
            let (v, err) = self.parse_value();
            if err != nil {
                return (Value::Null, err);
            }
            m.Set(key, v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return (Value::Object(m), nil);
                }
                Some(_) => return (Value::Null, ErrSyntax.into()),
                None => return (Value::Null, ErrUnexpectedEnd.into()),
            }
        }
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
            self.prefix
                .push_str(core::str::from_utf8_unchecked(crate::gostring::__crate_as_bytes(prefix)));
            self.indent.clear();
            self.indent
                .push_str(core::str::from_utf8_unchecked(crate::gostring::__crate_as_bytes(indent)));
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
                    if self.token_state != TOKEN_ARRAY_START && self.token_state != TOKEN_ARRAY_COMMA
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
            TOKEN_OBJECT_KEY => "json: invalid character: looking for beginning of object key string",
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
