// goishlint:ignore GOISH015 — builtin codecs share this existing semantic-layer module; array codecs extend the same reflection-to-trait dispatch.
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
//   - Fixed arrays use const-generic codecs instead of reflection. `Any`
//     identifies the built-in byte array (base64 in v2); named byte types
//     retain their element codecs. This requires 'static array elements.
//     Array errors retain Go's state/consumption order but omit reflected
//     Go type names and JSON-pointer context, like the other builtin codecs.
//   - Slice decoding retains the decoded prefix on failure, including the
//     failing element's partial value. Goish slices own their storage, so
//     unused capacity/backing-array aliases are not exposed by this codec.
//   - Option is the exclusive nullable-pointer representation: allocate before
//     decoding, merge into existing pointees, and retain partial mutations.
//     Box provides the owned non-null indirection for recursive decode trees;
//     Option<Box<T>> uses the same nullable-pointer codec without copying T.
//   - Default float decode consumes raw values and clamps overflow to the
//     finite maximum before returning an error (jsonwire.ParseFloat). Legacy
//     stringify/non-finite format options are not implemented by this codec.
//   - Builtin maps merge existing values and store partial decoded values
//     before returning errors. Null replaces the map with an empty owned
//     representation; the pre-existing map type has no distinct nil header
//     or shared backing-map aliases, so this does not add those semantics.
//   - GetOption uses typed bool/string dispatch for the existing supported
//     setters instead of reflection, calling the setter once with zero.
//     Marshal preserves partial output on error; legacy error modes remain
//     unimplemented. Non-finite floats fail before writing their delimiter.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::goarray::array;
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int};

use super::jsontext;

pub use super::jsontext::Options;

// go: sdk 1.25.5 encoding/json/v2/options.go:95-97 GetOption
// DEVIATION: typed dispatch covers the bool/string setters supported by the
// existing Options representation. The setter is called once with zero, as
// internal/jsonopts/options.go:70-110 requires; no function-address matching.
pub fn GetOption<T: __JSONOptionValue, F: FnOnce(T) -> Options>(opts: Options, setter: F) -> (T, bool) {
    let marker = setter(T::default());
    return T::__get_option(&opts, &marker);
}

// Reflection replacement for the supported option-value types; not a Go item.
#[doc(hidden)]
pub trait __JSONOptionValue: Default {
    fn __get_option(opts: &Options, marker: &Options) -> (Self, bool);
}
impl __JSONOptionValue for bool {
    // goishlint:ignore GOISH014 — typed reflection adapter for GetOption, anchored above.
    fn __get_option(opts: &Options, marker: &Options) -> (Self, bool) {
        let values = [marker.allow_duplicate_names, marker.allow_invalid_utf8, marker.deterministic];
        if values.iter().filter(|v| v.is_some()).count() != 1 || marker.indent.is_some() || marker.indent_prefix.is_some() { panic!("unknown JSON option"); }
        if marker.allow_duplicate_names.is_some() { return (opts.allow_duplicate_names.unwrap_or(false), opts.allow_duplicate_names.is_some()); }
        if marker.allow_invalid_utf8.is_some() { return (opts.allow_invalid_utf8.unwrap_or(false), opts.allow_invalid_utf8.is_some()); }
        return (opts.deterministic.unwrap_or(false), opts.deterministic.is_some());
    }
}
impl __JSONOptionValue for string {
    // goishlint:ignore GOISH014 — typed reflection adapter for GetOption, anchored above.
    fn __get_option(opts: &Options, marker: &Options) -> (Self, bool) {
        if marker.allow_duplicate_names.is_some() || marker.allow_invalid_utf8.is_some() || marker.deterministic.is_some()
            || marker.indent.is_some() == marker.indent_prefix.is_some() { panic!("unknown JSON option"); }
        if marker.indent.is_some() { return (opts.indent.clone().unwrap_or_default(), opts.indent.is_some()); }
        return (opts.indent_prefix.clone().unwrap_or_default(), opts.indent_prefix.is_some());
    }
}

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

// Go: encoding/json/v2/arshal_default.go:1529 — makeArrayArshaler;
// omitzero checks the array's elements, not merely its fixed length.
impl<T: JsonOmit, const N: usize> JsonOmit for array<T, N> {
    // goishlint:ignore GOISH014 — Rust trait hook for Go's JSON-empty array check; provenance is on the impl.
    fn __json_empty(&self) -> bool {
        return N == 0;
    }
    // goishlint:ignore GOISH014 — Rust trait hook for Go's reflected array zero-value check; provenance is on the impl.
    fn __json_zero(&self) -> bool {
        return self.iter().all(JsonOmit::__json_zero);
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

// go: sdk 1.25.5 encoding/json/v2/arshal.go:173-183 Marshal
/// `json.Marshal(in, opts...)` (arshal.go) — encode to bytes.
pub fn Marshal<T: MarshalerTo + ?Sized>(
    v: &T,
    opts: impl AsRef<[Options]>,
) -> (slice<byte>, error) {
    let mut enc = jsontext::Encoder::__buffered(Options::__merged(opts.as_ref()));
    let err = v.MarshalJSONTo(&mut enc);
    // The v2 entry point returns the bytes written before an error, too.
    // Only the unimplemented legacy-error mode discards that prefix in Go.
    (slice::__from_vec(enc.__take_buf()), err)
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
        // Go makeStringArshaler (arshal_default.go:198) reads a whole value,
        // even for rejected composites. Strings/null retain the equivalent
        // token path so the existing JSON unquote implementation is reused.
        if dec.PeekKind() != '"' && dec.PeekKind() != 'n' {
            let (_, err) = dec.ReadValue();
            if err != nil { return err; }
            return errors::New("json: cannot unmarshal non-string into string");
        }
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
                // Go: arshal_default.go:461 — makeIntArshaler reads a complete
                // raw value, even when rejecting a composite type.
                let (t, err) = dec.ReadValue();
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
                        let raw = string::from_bytes(&t.0);
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

// go: sdk 1.25.5 encoding/json/v2/arshal_default.go:595-698 makeFloatArshaler
macro_rules! impl_json_float {
    ($($t:ty => $bits:expr),*) => {$(
        impl MarshalerTo for $t {
            fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
                // makeFloatArshaler rejects non-finite values before writing
                // a token/delimiter; preserve the preceding partial output.
                if !self.is_finite() { return errors::New("json: cannot marshal non-finite float"); }
                enc.WriteToken(jsontext::Float(*self as f64))
            }
        }
        impl UnmarshalerFrom for $t {
            fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
                let (value, err) = dec.ReadValue();
                if err != nil {
                    return err;
                }
                match value.Kind().0 {
                    b'0' => {
                        let (mut number, err) = crate::strconv::ParseFloat(string::from_bytes(&value.0), $bits);
                        // Go jsonwire/decode.go:614-630 clamps +/-Inf to
                        // +/-MaxFloat, retaining the range error. The v2
                        // decoder assigns this value BEFORE returning it.
                        if number == f64::INFINITY { number = <$t>::MAX as f64; }
                        if number == f64::NEG_INFINITY { number = -(<$t>::MAX as f64); }
                        *self = number as $t;
                        if err != nil { return err; }
                    }
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
impl_json_float!(f32 => 32, f64 => 64);

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

// Go: encoding/json/v2/arshal_default.go:1388 — func makeSliceArshaler(t reflect.Type) *arshaler
impl<T: UnmarshalerFrom + Default + Clone> UnmarshalerFrom for slice<T> {
    // goishlint:ignore GOISH014 — trait body ports makeSliceArshaler's unmarshal closure; provenance is on the impl.
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        let (t, err) = dec.ReadToken();
        if err != nil {
            return err;
        }
        if t.Kind() == 'n' {
            *self = slice::new();
            return nil;
        }
        if t.Kind() != '[' {
            return errors::New("json: cannot unmarshal non-array into slice");
        }
        // Go zeroes each slot before decode and sets Len(i) even when the
        // element decoder fails (arshal_default.go:1490-1508). An owned
        // output vector represents that visible prefix; there are no shared
        // backing-array views in Goish's current slice representation.
        let mut out: Vec<T> = Vec::new();
        while dec.PeekKind() != ']' {
            let mut elem = T::default();
            let err = elem.UnmarshalJSONFrom(dec);
            out.push(elem);
            if err != nil {
                *self = slice::__from_vec(out);
                return err;
            }
        }
        *self = slice::__from_vec(out);
        let (_, err) = dec.ReadToken(); // consume ']'
        return err;
    }
}

// Go: encoding/json/v2/arshal_default.go:1529 — func makeArrayArshaler(t reflect.Type) *arshaler
// Byte dispatch ports makeBytesArshaler at arshal_default.go:298.
impl<T: MarshalerTo + 'static, const N: usize> MarshalerTo for array<T, N> {
    // goishlint:ignore GOISH014 — trait implementation of the marshal closure inside makeArrayArshaler (anchor on impl).
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        // Reflection's exact byte-type dispatch, without inspecting or cloning
        // user elements (which could have side-effecting custom codecs).
        if let Some(bytes) = (self as &dyn ::core::any::Any).downcast_ref::<array<byte, N>>() {
            let value = crate::encoding::base64::StdEncoding.EncodeToString(bytes);
            return enc.WriteToken(jsontext::String(value));
        }
        let err = enc.WriteToken(jsontext::BeginArray);
        if err != nil {
            return err;
        }
        for value in self.iter() {
            let err = value.MarshalJSONTo(enc);
            if err != nil {
                return err;
            }
        }
        return enc.WriteToken(jsontext::EndArray);
    }
}

// Go: encoding/json/v2/arshal_default.go:1563 — makeArrayArshaler unmarshal closure
impl<T: UnmarshalerFrom + Default + 'static, const N: usize> UnmarshalerFrom for array<T, N> {
    // goishlint:ignore GOISH014 — trait implementation of the unmarshal closure inside makeArrayArshaler (anchor on impl).
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        // Byte arrays are JSON strings, not JSON arrays (Go v2 default).
        if let Some(bytes) = (self as &mut dyn ::core::any::Any).downcast_mut::<array<byte, N>>() {
            // Go: arshal_default.go:375-427 — makeBytesArshaler unmarshal.
            let (value, err) = dec.ReadValue();
            if err != nil {
                return err;
            }
            if value.Kind() == 'n' {
                *bytes = array::default();
                return nil;
            }
            if value.Kind() != '"' {
                return errors::New("json: cannot unmarshal non-string into byte array");
            }
            let mut encoded = string::new();
            let err = Unmarshal(&value.0, &mut encoded, []);
            if err != nil {
                return err;
            }
            // Go decodes into the old array's backing storage if it fits,
            // including a partial prefix on failure. If capacity is too small,
            // AppendDecode allocates instead; failure then leaves it untouched.
            // base64.go:412-423 grows using decodedLen after trimming padding.
            let mut unpadded = encoded.as_bytes().len();
            while unpadded > 0 && encoded.as_bytes()[unpadded - 1] == b'=' {
                unpadded -= 1;
            }
            let max_len = unpadded / 4 * 3 + unpadded % 4 * 6 / 8;
            let fits = max_len <= N;
            // Goish subslicing copies. Decode into that view, then publish ALL
            // writes before checking the error, including wide-store bytes past
            // n. Go base64.go:555-565 writes four bytes while advancing by three.
            let mut decoded = if fits {
                bytes.slice(0, crate::int(max_len))
            } else {
                crate::make!([]byte, crate::int(max_len))
            };
            let (n, err) = crate::encoding::base64::StdEncoding.Decode(
                &mut decoded, crate::convert::bytes(encoded.clone()),
            );
            if fits {
                for i in 0..max_len {
                    bytes[i] = decoded[i];
                }
            }
            if err != nil {
                return err;
            }
            if crate::int(encoded.as_bytes().len()) != crate::encoding::base64::StdEncoding.EncodedLen(n) {
                return errors::New("json: illegal character in base64 string");
            }
            for i in 0..N {
                bytes[i] = if crate::int(i) < n { decoded[i] } else { 0 };
            }
            if n != crate::int(N) {
                return errors::New("json: decoded length mismatches array length");
            }
            return nil;
        }
        let (token, err) = dec.ReadToken();
        if err != nil {
            return err;
        }
        if token.Kind() == 'n' {
            *self = array::default();
            return nil;
        }
        if token.Kind() != '[' {
            return errors::New("json: cannot unmarshal non-array into array");
        }
        let mut i = 0;
        let mut length_error = nil;
        while dec.PeekKind() != ']' {
            if i >= N {
                let err = dec.SkipValue();
                if err != nil {
                    return err;
                }
                length_error = errors::New("json: too many array elements");
                continue;
            }
            // Go resets each visited element BEFORE calling its codec and
            // stops on failure. Unvisited elements keep their previous state.
            self[i] = T::default();
            let err = self[i].UnmarshalJSONFrom(dec);
            if err != nil {
                return err;
            }
            i += 1;
        }
        while i < N {
            self[i] = T::default();
            length_error = errors::New("json: too few array elements");
            i += 1;
        }
        let (_, err) = dec.ReadToken();
        if err != nil {
            return err;
        }
        return length_error;
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

// Go: encoding/json/v2/arshal_default.go:700 — func makeMapArshaler(t reflect.Type) *arshaler
impl<V> UnmarshalerFrom for crate::gomap::map<string, V>
where
    V: UnmarshalerFrom + Default + Clone,
{
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        if dec.PeekKind() == 'n' {
            let (_, err) = dec.ReadToken();
            if err != nil { return err; }
            *self = crate::gomap::map::new();
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
            // Go arshal_default.go:963-985 copies an existing value (or
            // zero for a new key), decodes, then stores EVEN ON ERROR.
            // An error may leave a partially decoded composite, not zero.
            let key = name.String();
            let (mut val, _) = self.Get(key.clone());
            let err = val.UnmarshalJSONFrom(dec);
            self.Set(key, val);
            if err != nil {
                return err;
            }
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

// Go: encoding/json/v2/arshal_default.go:1624 — func makePointerArshaler(t reflect.Type) *arshaler
impl<T: UnmarshalerFrom + Default> UnmarshalerFrom for Option<T> {
    // goishlint:ignore GOISH014 — trait body ports makePointerArshaler's unmarshal closure; provenance is on the impl.
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        if dec.PeekKind() == 'n' {
            let (_, err) = dec.ReadToken();
            if err != nil { return err; }
            *self = None;
            return nil;
        }
        // Go installs a newly allocated pointee before invoking its decoder,
        // and reuses a non-nil pointee (arshal_default.go:1669-1674).
        return self.get_or_insert_with(T::default).UnmarshalJSONFrom(dec);
    }
}

// Go: encoding/json/v2/arshal_default.go:1624 — func makePointerArshaler(t reflect.Type) *arshaler
// DEVIATION: Box owns a non-null pointee; Option<Box<T>> supplies Go's nil slot.
impl<T: MarshalerTo + ?Sized> MarshalerTo for alloc::boxed::Box<T> {
    // goishlint:ignore GOISH014 — dereference dispatch from makePointerArshaler's marshal closure, anchored on impl.
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        return (**self).MarshalJSONTo(enc);
    }
}

// Go: encoding/json/v2/arshal_default.go:1672-1674 — decode the existing pointee in place.
impl<T: UnmarshalerFrom + ?Sized> UnmarshalerFrom for alloc::boxed::Box<T> {
    // goishlint:ignore GOISH014 — dereference dispatch from makePointerArshaler's unmarshal closure, anchored on impl.
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        return (**self).UnmarshalJSONFrom(dec);
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
