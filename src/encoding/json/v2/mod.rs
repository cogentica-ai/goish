// encoding/json/v2 — semantic JSON layer (Go 1.25 GOEXPERIMENT=
// jsonv2, src/encoding/json/v2/).
//
// Where Go v2 dispatches through reflection (arshal_default.go) with
// `MarshalerTo` / `UnmarshalerFrom` as the custom-codec escape hatch
// (arshal_methods.go), goish inverts the mechanism while keeping the
// semantics: the two interfaces become the universal dispatch traits,
// implemented here for every builtin type, generated for user structs
// by `#[goish::reflect]` (the compile-time equivalent of v2's cached
// reflection codec), and hand-written for custom-codec types exactly
// as in Go (e.g. an OrderedMap walking decoder tokens).
//
// Go anchors:
//   - Marshal / MarshalWrite / MarshalEncode:      v2/arshal.go
//   - Unmarshal / UnmarshalRead / UnmarshalDecode: v2/arshal.go
//   - MarshalerTo / UnmarshalerFrom:               v2/arshal_methods.go
//   - Default per-type behavior:                   v2/arshal_default.go
//   - Deterministic:                               v2/options.go
//
// Goish v1 simplifications (documented deviations):
//   - `opts ...Options` lowers to a trailing `impl AsRef<[Options]>`
//     (pass `[]` for none) on the top-level entry points only;
//     `MarshalEncode` / `UnmarshalDecode` use the coder's own options
//     (which is where Go reads formatting flags from anyway).
//   - Map marshaling always emits sorted keys (Go sorts only under
//     `Deterministic(true)`; typescript-go passes Deterministic for
//     its stable outputs, and stable-by-default costs little here).
//   - `null` unmarshals to the target's `Default` zero value
//     (matching Go's zero-ing behavior for non-pointer targets).

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int};

use super::jsontext;

pub use super::jsontext::Options;

/// `json.Deterministic(v)` (v2/options.go) — request deterministic
/// output. Goish map marshaling is already deterministic (see module
/// header); the option is accepted for API compatibility.
pub fn Deterministic(v: bool) -> Options {
    Options {
        deterministic: Some(v),
        ..Options::default()
    }
}

// ─── The two codec traits (arshal_methods.go) ───────────────────────

/// `json.MarshalerTo` — `MarshalJSONTo(enc *jsontext.Encoder) error`.
pub trait MarshalerTo {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error;
}

/// `json.UnmarshalerFrom` — `UnmarshalJSONFrom(dec *jsontext.Decoder)
/// error`.
pub trait UnmarshalerFrom {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error;
}

impl<T: MarshalerTo + ?Sized> MarshalerTo for &T {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        (**self).MarshalJSONTo(enc)
    }
}

/// Backend of `omitempty` / `omitzero` for generated struct codecs
/// (Go: fields.go isEmpty / IsZero checks in arshal_default.go).
/// `__json_empty` — the marshaled form would be an empty JSON value
/// (null, `""`, `{}`, `[]`); `__json_zero` — the value is its type's
/// zero value. Defaults are `false` (never omitted); builtins below
/// and `#[goish::reflect]` structs override as appropriate.
pub trait JsonOmit {
    fn __json_empty(&self) -> bool {
        false
    }
    fn __json_zero(&self) -> bool {
        false
    }
}

impl JsonOmit for string {
    fn __json_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }
    fn __json_zero(&self) -> bool {
        self.as_bytes().is_empty()
    }
}

impl JsonOmit for bool {
    fn __json_zero(&self) -> bool {
        !*self
    }
}

impl<T: Clone> JsonOmit for slice<T> {
    fn __json_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
    fn __json_zero(&self) -> bool {
        self.as_ref().is_empty()
    }
}

impl<K, V> JsonOmit for crate::gomap::map<K, V>
where
    K: crate::gomap::GoHash + PartialEq,
{
    fn __json_empty(&self) -> bool {
        self.Len() == 0
    }
    fn __json_zero(&self) -> bool {
        self.Len() == 0
    }
}

impl<T> JsonOmit for Option<T> {
    fn __json_empty(&self) -> bool {
        self.is_none()
    }
    fn __json_zero(&self) -> bool {
        self.is_none()
    }
}

impl JsonOmit for jsontext::Value {
    fn __json_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }
    fn __json_zero(&self) -> bool {
        self.0.as_ref().is_empty()
    }
}

macro_rules! impl_json_omit_num {
    ($($t:ty),*) => {$(
        impl JsonOmit for $t {
            fn __json_zero(&self) -> bool {
                *self == 0 as $t
            }
        }
    )*};
}
impl_json_omit_num!(i8, i16, i32, i64, u8, u16, u32, u64, f32, f64);

// ─── Entry points (arshal.go) ────────────────────────────────────────

/// `json.Marshal(in, opts...)` (arshal.go) — encode to bytes.
pub fn Marshal<T: MarshalerTo + ?Sized>(
    v: &T,
    opts: impl AsRef<[Options]>,
) -> (slice<byte>, error) {
    let mut enc = jsontext::Encoder::__buffered(Options::__merged(opts.as_ref()));
    let err = v.MarshalJSONTo(&mut enc);
    if err != nil {
        return (slice::__from_vec(Vec::new()), err);
    }
    (slice::__from_vec(enc.__take_buf()), nil)
}

/// `json.MarshalWrite(out, in, opts...)` (arshal.go) — encode to an
/// `io::Writer`.
pub fn MarshalWrite<W, T>(out: W, v: &T, opts: impl AsRef<[Options]>) -> error
where
    W: crate::io::Writer + Send + 'static,
    T: MarshalerTo + ?Sized,
{
    let mut enc = jsontext::NewEncoder(out, opts);
    v.MarshalJSONTo(&mut enc)
}

/// `json.MarshalEncode(out, in)` (arshal.go) — encode onto an
/// existing encoder, using its options.
pub fn MarshalEncode<T: MarshalerTo + ?Sized>(out: &mut jsontext::Encoder, v: &T) -> error {
    v.MarshalJSONTo(out)
}

/// Convenience mirroring v1's `json.MarshalIndent` shape via
/// jsontext's `WithIndent` / `WithIndentPrefix`.
pub fn MarshalIndent<T, P, I>(v: &T, prefix: P, indent: I) -> (slice<byte>, error)
where
    T: MarshalerTo + ?Sized,
    P: Into<string>,
    I: Into<string>,
{
    Marshal(
        v,
        [
            jsontext::WithIndentPrefix(prefix),
            jsontext::WithIndent(indent),
        ],
    )
}

/// After a full top-level decode, the input must hold nothing but
/// whitespace (Go v2 Unmarshal rejects trailing data).
fn expect_input_end(dec: &mut jsontext::Decoder) -> error {
    let (_, err) = dec.ReadToken();
    if err == crate::io::EOF {
        return nil;
    }
    if err != nil {
        return err;
    }
    errors::New("json: unexpected data after top-level value")
}

/// `json.Unmarshal(in, out, opts...)` (arshal.go) — decode from
/// bytes. The whole input must be one JSON value.
pub fn Unmarshal<T: UnmarshalerFrom + ?Sized>(
    data: impl AsRef<[byte]>,
    v: &mut T,
    opts: impl AsRef<[Options]>,
) -> error {
    let mut dec = jsontext::Decoder::__from_bytes(data.as_ref(), Options::__merged(opts.as_ref()));
    let err = v.UnmarshalJSONFrom(&mut dec);
    if err != nil {
        return err;
    }
    expect_input_end(&mut dec)
}

/// `json.UnmarshalRead(in, out, opts...)` (arshal.go) — decode a
/// single value from an `io::Reader`, verifying EOF follows.
pub fn UnmarshalRead<R, T>(r: R, v: &mut T, opts: impl AsRef<[Options]>) -> error
where
    R: crate::io::Reader + Send + 'static,
    T: UnmarshalerFrom + ?Sized,
{
    let mut dec = jsontext::NewDecoder(r, opts);
    let err = v.UnmarshalJSONFrom(&mut dec);
    if err != nil {
        return err;
    }
    expect_input_end(&mut dec)
}

/// `json.UnmarshalDecode(in, out)` (arshal.go) — decode the next
/// value from an existing decoder, using its options. Unlike
/// `Unmarshal`, more values may follow.
pub fn UnmarshalDecode<T: UnmarshalerFrom + ?Sized>(
    dec: &mut jsontext::Decoder,
    v: &mut T,
) -> error {
    v.UnmarshalJSONFrom(dec)
}

// ─── Builtin impls (compile-time arshal_default.go) ──────────────────

impl MarshalerTo for bool {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        enc.WriteToken(jsontext::Bool(*self))
    }
}

impl UnmarshalerFrom for bool {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        let (t, err) = dec.ReadToken();
        if err != nil {
            return err;
        }
        match t.Kind().0 {
            b't' => *self = true,
            b'f' => *self = false,
            b'n' => *self = false,
            _ => return errors::New("json: cannot unmarshal non-bool into bool"),
        }
        nil
    }
}

impl MarshalerTo for string {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        enc.WriteToken(jsontext::String(self.clone()))
    }
}

impl UnmarshalerFrom for string {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        let (t, err) = dec.ReadToken();
        if err != nil {
            return err;
        }
        match t.Kind().0 {
            b'"' => *self = t.String(),
            b'n' => *self = string::new(),
            _ => return errors::New("json: cannot unmarshal non-string into string"),
        }
        nil
    }
}

/// Signed/unsigned integers (covers the goish aliases int / int8… /
/// uint / byte / rune, which alias these primitives).
macro_rules! impl_json_int {
    ($($t:ty, $bits:expr, $signed:expr, $name:expr);* $(;)?) => {$(
        impl MarshalerTo for $t {
            fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
                enc.WriteToken(jsontext::Int(*self as int))
            }
        }
        impl UnmarshalerFrom for $t {
            fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
                let (t, err) = dec.ReadToken();
                if err != nil {
                    return err;
                }
                match t.Kind().0 {
                    b'0' => {
                        // Go parses the RAW LITERAL as an integer, so a
                        // number that is merely integer-VALUED — `1.0`,
                        // `1e2` — is rejected as "invalid syntax", and
                        // one past the target's width as "value out of
                        // range". Parsing a float and truncating, which
                        // this used to do, silently accepted both.
                        let raw = t.__number_text();
                        let e = if $signed {
                            let (v, e) = crate::strconv::ParseInt(raw.clone(), 10, $bits);
                            if e == nil { *self = v as $t; }
                            e
                        } else {
                            let (v, e) = crate::strconv::ParseUint(raw.clone(), 10, $bits);
                            if e == nil { *self = v as $t; }
                            e
                        };
                        if e != nil {
                            return errors::New(
                                crate::gostring::string::from_static(
                                    "json: unable to unmarshal JSON number ")
                                    + raw
                                    + " into Go "
                                    + $name
                                    + ": "
                                    + numeric_reason(&e),
                            );
                        }
                    }
                    b'n' => *self = 0,
                    _ => {
                        return errors::New(
                            crate::gostring::string::from_static(
                                "json: unable to unmarshal JSON ")
                                + t.Kind().String()
                                + " into Go "
                                + $name,
                        )
                    }
                }
                nil
            }
        }
    )*};
}

/// Go appends strconv's reason to the message: "invalid syntax" for a
/// literal that is not a plain integer, "value out of range" for one
/// that does not fit. goish's strconv errors carry the same two texts,
/// so the tail of the message is what distinguishes them.
fn numeric_reason(e: &error) -> crate::gostring::string {
    let text = e.Error();
    if crate::strings::Contains(text.clone(), "out of range") {
        crate::gostring::string::from_static("value out of range")
    } else {
        crate::gostring::string::from_static("invalid syntax")
    }
}

// NOTE the type names: Go reports its own spelling ("int", "int32"),
// and goish cannot tell the `int` alias from `i64`, so the message
// names the underlying Rust primitive. The BEHAVIOUR — which inputs
// are accepted, which rejected, and with which of the two reasons — is
// Go's, and that is what examples/json_int_diff.rs compares.
impl_json_int!(
    i8, 8, true, "i8";
    i16, 16, true, "i16";
    i32, 32, true, "i32";
    i64, 64, true, "i64";
    u8, 8, false, "u8";
    u16, 16, false, "u16";
    u32, 32, false, "u32";
);

/// u64 keeps full range via the Uint token.
impl MarshalerTo for u64 {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        enc.WriteToken(jsontext::Uint(*self))
    }
}

impl UnmarshalerFrom for u64 {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        let (t, err) = dec.ReadToken();
        if err != nil {
            return err;
        }
        match t.Kind().0 {
            b'0' => *self = t.Int() as u64,
            b'n' => *self = 0,
            _ => return errors::New("json: cannot unmarshal non-number into integer"),
        }
        nil
    }
}

macro_rules! impl_json_float {
    ($($t:ty),*) => {$(
        impl MarshalerTo for $t {
            fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
                enc.WriteToken(jsontext::Float(*self as f64))
            }
        }
        impl UnmarshalerFrom for $t {
            fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
                let (t, err) = dec.ReadToken();
                if err != nil {
                    return err;
                }
                match t.Kind().0 {
                    b'0' => *self = t.Float() as $t,
                    b'n' => *self = 0.0,
                    _ => {
                        return errors::New(
                            "json: cannot unmarshal non-number into float",
                        )
                    }
                }
                nil
            }
        }
    )*};
}
impl_json_float!(f32, f64);

/// `slice<T>` ⇄ JSON array.
impl<T: MarshalerTo + Clone> MarshalerTo for slice<T> {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        let err = enc.WriteToken(jsontext::BeginArray);
        if err != nil {
            return err;
        }
        for v in self.as_ref() {
            let err = v.MarshalJSONTo(enc);
            if err != nil {
                return err;
            }
        }
        enc.WriteToken(jsontext::EndArray)
    }
}

impl<T: UnmarshalerFrom + Default + Clone> UnmarshalerFrom for slice<T> {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        if dec.PeekKind() == 'n' {
            let (_, err) = dec.ReadToken();
            if err != nil {
                return err;
            }
            *self = slice::__from_vec(Vec::new());
            return nil;
        }
        let (t, err) = dec.ReadToken();
        if err != nil {
            return err;
        }
        if t.Kind() != '[' {
            return errors::New("json: cannot unmarshal non-array into slice");
        }
        let mut out: Vec<T> = Vec::new();
        while dec.PeekKind() != ']' {
            if dec.PeekKind() == jsontext::Kind(0) {
                return crate::io::ErrUnexpectedEOF.into();
            }
            let mut elem = T::default();
            let err = elem.UnmarshalJSONFrom(dec);
            if err != nil {
                return err;
            }
            out.push(elem);
        }
        let (_, err) = dec.ReadToken(); // consume ']'
        if err != nil {
            return err;
        }
        *self = slice::__from_vec(out);
        nil
    }
}

/// `map<string, V>` ⇄ JSON object (sorted keys; see module header).
impl<V> MarshalerTo for crate::gomap::map<string, V>
where
    V: MarshalerTo + Clone,
{
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        let err = enc.WriteToken(jsontext::BeginObject);
        if err != nil {
            return err;
        }
        let mut pairs: Vec<(string, V)> = Vec::new();
        for (k, v) in self.__iter() {
            pairs.push((k.clone(), v.clone()));
        }
        pairs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        for (k, v) in &pairs {
            let err = enc.WriteToken(jsontext::String(k.clone()));
            if err != nil {
                return err;
            }
            let err = v.MarshalJSONTo(enc);
            if err != nil {
                return err;
            }
        }
        enc.WriteToken(jsontext::EndObject)
    }
}

impl<V> UnmarshalerFrom for crate::gomap::map<string, V>
where
    V: UnmarshalerFrom + Default + Clone,
{
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        if dec.PeekKind() == 'n' {
            let (_, err) = dec.ReadToken();
            return err;
        }
        let (t, err) = dec.ReadToken();
        if err != nil {
            return err;
        }
        if t.Kind() != '{' {
            return errors::New("json: cannot unmarshal non-object into map");
        }
        while dec.PeekKind() != '}' {
            if dec.PeekKind() == jsontext::Kind(0) {
                return crate::io::ErrUnexpectedEOF.into();
            }
            let (name, err) = dec.ReadToken();
            if err != nil {
                return err;
            }
            // Go stores the key with its ZERO value before decoding,
            // so a failed value decode leaves the key PRESENT and empty
            // and the walk stops there — `{"a":1}` into a
            // map[string]string yields {"a": ""} plus an error, not an
            // empty map. packagejson's Expected[T] keeps the partially
            // decoded value, so this is observable, not just internal.
            let key = name.String();
            self.Set(key.clone(), V::default());
            let mut val = V::default();
            let err = val.UnmarshalJSONFrom(dec);
            if err != nil {
                return err;
            }
            self.Set(key, val);
        }
        let (_, err) = dec.ReadToken(); // consume '}'
        err
    }
}

/// `Option<T>` — goish-side optionality (Go `*T`): `None` ⇄ null.
impl<T: MarshalerTo> MarshalerTo for Option<T> {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        match self {
            Some(v) => v.MarshalJSONTo(enc),
            None => enc.WriteToken(jsontext::Null),
        }
    }
}

impl<T: UnmarshalerFrom + Default> UnmarshalerFrom for Option<T> {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        if dec.PeekKind() == 'n' {
            let (_, err) = dec.ReadToken();
            *self = None;
            return err;
        }
        let mut v = T::default();
        let err = v.UnmarshalJSONFrom(dec);
        if err != nil {
            return err;
        }
        *self = Some(v);
        nil
    }
}

/// `nilable<T>` — Go `*T` fields (the goish nilable pointer): nil ⇄
/// JSON null, non-nil ⇄ the pointee's encoding (arshal_default.go's
/// pointer handling). Unmarshal allocates a fresh value like Go's
/// `new(T)` + decode.
impl<T: MarshalerTo> MarshalerTo for crate::gonilable::nilable<T> {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        if self.IsNil() {
            return enc.WriteToken(jsontext::Null);
        }
        self.Must().MarshalJSONTo(enc)
    }
}

impl<T: UnmarshalerFrom + Default> UnmarshalerFrom for crate::gonilable::nilable<T> {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        if dec.PeekKind() == 'n' {
            let (_, err) = dec.ReadToken();
            *self = crate::gonilable::nilable::default();
            return err;
        }
        let mut v = T::default();
        let err = v.UnmarshalJSONFrom(dec);
        if err != nil {
            return err;
        }
        *self = crate::gonilable::nilable::new(v);
        nil
    }
}

impl<T: ?Sized> JsonOmit for crate::gonilable::nilable<T> {
    fn __json_empty(&self) -> bool {
        self.IsNil()
    }
    fn __json_zero(&self) -> bool {
        self.IsNil()
    }
}

/// `jsontext::Value` — raw passthrough in both directions
/// (arshal_default.go's RawValue handling).
impl MarshalerTo for jsontext::Value {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        if self.0.as_ref().is_empty() {
            return enc.WriteToken(jsontext::Null);
        }
        enc.WriteValue(self.clone())
    }
}

impl UnmarshalerFrom for jsontext::Value {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        let (v, err) = dec.ReadValue();
        if err != nil {
            return err;
        }
        *self = v;
        nil
    }
}
