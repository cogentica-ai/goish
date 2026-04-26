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
//   * No `json.Number` (numbers always f64).
//   * Object keys iterate sorted (BTreeMap-backed map<K, V>).

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::runtime::spin::SpinLock;
use crate::strconv;
use crate::types::{byte, float64};

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

// ─── Sentinel errors ───────────────────────────────────────────────────

fn cached_error(slot: &SpinLock<Option<error>>, init: fn() -> error) -> error {
    let mut g = slot.lock();
    if g.is_none() {
        *g = Some(init());
    }
    g.as_ref().unwrap().clone()
}

pub fn ErrSyntax() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || errors::New("json: invalid syntax"))
}

pub fn ErrUnexpectedEnd() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || errors::New("json: unexpected end of input"))
}

// ─── Marshaler / Unmarshaler traits ────────────────────────────────────

pub trait Marshaler {
    fn MarshalJSON(&self) -> (slice<byte>, error);
}

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
    let keys = v.MapKeys();
    if keys.is_empty() {
        out.extend_from_slice(b"{}");
        return;
    }
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
    let s = strconv::FormatFloat(n, b'g', -1, 64);
    out.extend_from_slice(s.as_bytes());
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
    out.push(b'{');
    let inner_depth = depth + 1;
    let mut first = true;
    for (k, v) in o.__iter() {
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

pub fn Unmarshal(data: &[byte]) -> (Value, error) {
    let mut p = Parser { data, pos: 0 };
    p.skip_ws();
    let (v, err) = p.parse_value();
    if err != nil {
        return (Value::Null, err);
    }
    p.skip_ws();
    if p.pos != data.len() {
        return (Value::Null, ErrSyntax());
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
            Some(_) => ErrSyntax(),
            None => ErrUnexpectedEnd(),
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
            Some(_) => (Value::Null, ErrSyntax()),
            None => (Value::Null, ErrUnexpectedEnd()),
        }
    }

    fn parse_null(&mut self) -> (Value, error) {
        if self.literal_match(b"null") {
            (Value::Null, nil)
        } else {
            (Value::Null, ErrSyntax())
        }
    }

    fn parse_bool(&mut self) -> (Value, error) {
        if self.literal_match(b"true") {
            (Value::Bool(true), nil)
        } else if self.literal_match(b"false") {
            (Value::Bool(false), nil)
        } else {
            (Value::Null, ErrSyntax())
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
            _ => return (Value::Null, ErrSyntax()),
        }
        // Fraction
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return (Value::Null, ErrSyntax());
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
                return (Value::Null, ErrSyntax());
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let lit = &self.data[start..self.pos];
        // SAFETY: literal is ASCII digits + '.' / 'e' / sign.
        let s = match core::str::from_utf8(lit) {
            Ok(s) => s,
            Err(_) => return (Value::Null, ErrSyntax()),
        };
        let owned = string::from_bytes(s.as_bytes());
        let (n, err) = strconv::ParseFloat(owned, 64);
        if err != nil {
            return (Value::Null, ErrSyntax());
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
            return (Vec::new(), ErrSyntax());
        }
        let mut out: Vec<byte> = Vec::new();
        loop {
            let c = match self.advance() {
                Some(c) => c,
                None => return (Vec::new(), ErrUnexpectedEnd()),
            };
            match c {
                b'"' => return (out, nil),
                b'\\' => {
                    let esc = match self.advance() {
                        Some(c) => c,
                        None => return (Vec::new(), ErrUnexpectedEnd()),
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
                                None => return (Vec::new(), ErrSyntax()),
                            };
                            // Handle surrogate pairs for UTF-16.
                            if (0xD800..=0xDBFF).contains(&cp) {
                                // High surrogate — must be followed by \uXXXX low surrogate.
                                if self.advance() != Some(b'\\') {
                                    return (Vec::new(), ErrSyntax());
                                }
                                if self.advance() != Some(b'u') {
                                    return (Vec::new(), ErrSyntax());
                                }
                                let lo = match self.parse_hex4() {
                                    Some(v) => v,
                                    None => return (Vec::new(), ErrSyntax()),
                                };
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return (Vec::new(), ErrSyntax());
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
                        _ => return (Vec::new(), ErrSyntax()),
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
                Some(_) => return (Value::Null, ErrSyntax()),
                None => return (Value::Null, ErrUnexpectedEnd()),
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
                Some(_) => return (Value::Null, ErrSyntax()),
                None => return (Value::Null, ErrUnexpectedEnd()),
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
    pub fn SetIndent(&mut self, prefix: &str, indent: &str) {
        self.prefix.clear();
        self.prefix.push_str(prefix);
        self.indent.clear();
        self.indent.push_str(indent);
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

pub struct Decoder<R: io::Reader> {
    r: R,
    buf: Vec<byte>,
}

pub fn NewDecoder<R: io::Reader>(r: R) -> Decoder<R> {
    Decoder { r, buf: Vec::new() }
}

impl<R: io::Reader> Decoder<R> {
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
                if errors::Is(err.clone(), io::EOF()) {
                    break;
                }
                return (Value::Null, err);
            }
            if n == 0 {
                break;
            }
        }
        Unmarshal(&self.buf)
    }
}
