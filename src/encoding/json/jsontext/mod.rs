// goishlint:ignore GOISH015 — delimiter lookahead extends the existing Decoder in this combined syntax-layer module.
// encoding/json/jsontext — streaming JSON syntax layer (Go 1.25
// GOEXPERIMENT=jsonv2, src/encoding/json/jsontext/).
//
// This is the token-level half of json/v2: a `Decoder` that yields
// `Token`s / raw `Value`s from an `io::Reader` (or byte buffer), and
// an `Encoder` that writes them with automatic separator + indent
// handling. The semantic layer (`encoding/json/v2` — Marshal /
// Unmarshal / MarshalerTo / UnmarshalerFrom) builds on this module.
//
// Go anchors:
//   - Token / Kind:        jsontext/token.go (Token :42, Kind :491)
//   - Value:               jsontext/value.go (`type Value []byte`)
//   - Decoder:             jsontext/decode.go (NewDecoder :122,
//                          PeekKind :307, SkipValue :406,
//                          ReadToken :461, ReadValue :667)
//   - Encoder:             jsontext/encode.go (NewEncoder :91,
//                          WriteToken :345, WriteValue :523)
//   - Options:             jsontext/options.go (AllowDuplicateNames
//                          :54, AllowInvalidUTF8 :68, WithIndent
//                          :232, WithIndentPrefix :265)
//
// Goish v1 simplifications (documented deviations):
//   - `AllowInvalidUTF8` is accepted and recorded but not enforced:
//     the tokenizer always passes byte content through verbatim (i.e.
//     behaves as AllowInvalidUTF8(true)), which is the option
//     typescript-go's json shim sets globally
//     (internal/json/json.go:12).
//     `AllowDuplicateNames` IS enforced by the Decoder: names are
//     tracked per open object frame and a repeat is an error unless
//     the option is true. An earlier version of this note claimed
//     typescript-go set that option globally too — it does not, and a
//     package.json with a repeated key was being silently accepted
//     where tsc rejects it.
//   - `WriteValue` emits the raw value verbatim (compact reformat /
//     re-indent of nested values is not performed).
//   - StackPointer / StackIndex / OutputOffset / AvailableBuffer /
//     UnreadBuffer are not ported (unused by the target workloads).
//   - Delimiter lookahead keeps the comma unconsumed on error, rather than
//     caching Go's peekErr, so repeated PeekKind and the following read agree.
//   - Raw-value scanning keeps local object namespaces and JSON-pointer paths
//     rather than publishing token frames. Duplicate-name validation therefore
//     matches the token path without changing the decoder's public StackDepth.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, float64, int, uint};

// ─── Kind ────────────────────────────────────────────────────────────

/// `jsontext.Kind` (token.go:491) — the kind of a token or value,
/// represented by its first byte:
///
///   'n' null    't' true    'f' false
///   '"' string  '0' number
///   '{' / '}'   begin/end object
///   '[' / ']'   begin/end array
///
/// The zero Kind is invalid. Comparisons against byte and char
/// literals both work: `dec.PeekKind() == '}'` reads like the Go.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Kind(pub byte);

impl Kind {
    /// Go `Kind.String()` (token.go:496) — human-readable name.
    pub fn String(&self) -> string {
        string::from_static(match self.0 {
            b'n' => "null",
            b'f' => "false",
            b't' => "true",
            b'"' => "string",
            b'0' => "number",
            b'{' => "{",
            b'}' => "}",
            b'[' => "[",
            b']' => "]",
            _ => "<invalid jsontext.Kind>",
        })
    }
}

impl PartialEq<byte> for Kind {
    fn eq(&self, other: &byte) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Kind> for byte {
    fn eq(&self, other: &Kind) -> bool {
        *self == other.0
    }
}

impl PartialEq<char> for Kind {
    fn eq(&self, other: &char) -> bool {
        (self.0 as char) == *other
    }
}

impl PartialEq<Kind> for char {
    fn eq(&self, other: &Kind) -> bool {
        *self == (other.0 as char)
    }
}

/// Map the first byte of a JSON value to its Kind (0 = invalid).
/// Quote `s` as a JSON string literal. Go's jsontext puts the member
/// name and the JSON pointer into its error messages this way, which is
/// NOT `strconv.Quote`: a name like "é" stays raw UTF-8 here where
/// strconv.Quote would render it `\xc3\xa9`.
fn json_quote(s: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len() + 2);
    out.push(b'"');
    for &b in s {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0C => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            c if c < 0x20 => {
                let hex = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(hex[(c >> 4) as usize]);
                out.push(hex[(c & 0xf) as usize]);
            }
            c => out.push(c),
        }
    }
    out.push(b'"');
    out
}

fn kind_of_byte(b: byte) -> Kind {
    Kind(match b {
        b'n' => b'n',
        b't' => b't',
        b'f' => b'f',
        b'"' => b'"',
        b'-' | b'0'..=b'9' => b'0',
        b'{' => b'{',
        b'}' => b'}',
        b'[' => b'[',
        b']' => b']',
        _ => 0,
    })
}

// ─── Token ───────────────────────────────────────────────────────────

/// Internal token payload. `Raw` covers the fixed literals + the
/// structural tokens (const-constructible, so `jsontext::Null`,
/// `jsontext::BeginObject` etc. can be `pub const` like Go's package
/// vars, token.go:94). `Str` holds a decoded string; `Num` holds the
/// verbatim number text (parsed lazily by `Int`/`Float`, mirroring
/// Go's raw-token representation).
#[derive(Clone, Debug)]
enum Repr {
    Raw(&'static str),
    Str(string),
    Num(string),
}

/// `jsontext.Token` (token.go:42) — a lexical JSON token. Cheap to
/// clone (string payloads are goish strings).
#[derive(Clone, Debug)]
pub struct Token {
    repr: Repr,
}

/// `jsontext.Null` (token.go:95).
pub const Null: Token = Token {
    repr: Repr::Raw("null"),
};
/// `jsontext.False` (token.go:96).
pub const False: Token = Token {
    repr: Repr::Raw("false"),
};
/// `jsontext.True` (token.go:97).
pub const True: Token = Token {
    repr: Repr::Raw("true"),
};
/// `jsontext.BeginObject` (token.go:99).
pub const BeginObject: Token = Token {
    repr: Repr::Raw("{"),
};
/// `jsontext.EndObject` (token.go:100).
pub const EndObject: Token = Token {
    repr: Repr::Raw("}"),
};
/// `jsontext.BeginArray` (token.go:101).
pub const BeginArray: Token = Token {
    repr: Repr::Raw("["),
};
/// `jsontext.EndArray` (token.go:102).
pub const EndArray: Token = Token {
    repr: Repr::Raw("]"),
};

/// `jsontext.Bool(b)` (token.go:117).
pub fn Bool(b: bool) -> Token {
    if b {
        True
    } else {
        False
    }
}

/// `jsontext.String(s)` (token.go:127).
pub fn String<S: Into<string>>(s: S) -> Token {
    Token {
        repr: Repr::Str(s.into()),
    }
}

/// `jsontext.Float(f)` (token.go:175). The textual form comes from
/// [`AppendFloat`], not `strconv.FormatFloat(_, 'g', ...)` — JSON
/// numbers use the ES6 conversion (token.go:312 formats num tokens
/// through `jsonwire.AppendFloat`).
pub fn Float(n: float64) -> Token {
    Token {
        repr: Repr::Num(AppendFloatString(n, 64)),
    }
}

/// `jsontext.AppendFloat(dst, src, bits)` (value.go:32) ->
/// `jsonwire.AppendFloat` (internal/jsonwire/encode.go:213).
///
/// Appends `src` to `dst` as a JSON number per RFC 7159, section 6.
/// It formats numbers similar to the ES6 number-to-string conversion.
/// See https://go.dev/issue/14135.
///
/// The output is identical to ECMA-262, 6th edition, section 7.1.12.1
/// and with RFC 8785, section 3.2.2.3 for 64-bit floating-point numbers
/// except for -0, which is formatted as -0 instead of just 0.
///
/// For 32-bit floating-point numbers, the output is a 32-bit equivalent
/// of the algorithm.
pub fn AppendFloat(dst: &mut alloc::vec::Vec<crate::types::byte>, src: float64, bits: int) {
    dst.extend_from_slice(AppendFloatString(src, bits).as_bytes());
}

/// The formatting core shared by [`Float`] and [`AppendFloat`].
fn AppendFloatString(src: float64, bits: int) -> string {
    let src = if bits == 32 {
        src as crate::types::float32 as float64
    } else {
        src
    };

    let abs = crate::math::Abs(src);
    let mut fmt = b'f';
    if abs != 0.0
        && (bits == 64 && (abs < 1e-6 || abs >= 1e21)
            || bits == 32
                && ((abs as crate::types::float32) < 1e-6f32
                    || (abs as crate::types::float32) >= 1e21f32))
    {
        fmt = b'e';
    }
    let s = crate::strconv::FormatFloat(src, fmt, -1, bits);
    if fmt == b'e' {
        // Clean up e-09 to e-9.
        let b = s.as_bytes();
        let n = b.len();
        if n >= 4 && b[n - 4] == b'e' && b[n - 3] == b'-' && b[n - 2] == b'0' {
            let mut out = alloc::vec::Vec::with_capacity(n - 1);
            out.extend_from_slice(&b[..n - 2]);
            out.push(b[n - 1]);
            return string::from_bytes(out.as_slice());
        }
    }
    s
}

/// `jsontext.Int(i)` (token.go:152).
pub fn Int(n: int) -> Token {
    Token {
        repr: Repr::Num(crate::strconv::FormatInt(n, 10)),
    }
}

/// `jsontext.Uint(u)` (token.go:160).
pub fn Uint(n: uint) -> Token {
    Token {
        repr: Repr::Num(crate::strconv::FormatUint(n, 10)),
    }
}

impl Token {
    /// `Token.Kind()` (token.go:458).
    pub fn Kind(&self) -> Kind {
        match &self.repr {
            Repr::Raw(s) => kind_of_byte(s.as_bytes()[0]),
            Repr::Str(_) => Kind(b'"'),
            Repr::Num(_) => Kind(b'0'),
        }
    }

    /// `Token.Bool()` (token.go:203). Panics if the token is not a
    /// bool (Go panics too).
    pub fn Bool(&self) -> bool {
        match &self.repr {
            Repr::Raw("true") => true,
            Repr::Raw("false") => false,
            _ => panic!(
                "invalid jsontext.Token.Bool call on {:?}",
                self.Kind().String()
            ),
        }
    }

    /// `Token.String()` (token.go:237) — for string tokens, the
    /// decoded value; for anything else, the raw text (Go behaves
    /// the same: `String` returns the unquoted representation).
    pub fn String(&self) -> string {
        match &self.repr {
            Repr::Raw(s) => string::from_static(s),
            Repr::Str(s) => s.clone(),
            Repr::Num(s) => s.clone(),
        }
    }

    /// `Token.Float()` (token.go:308).
    pub fn Float(&self) -> float64 {
        match &self.repr {
            Repr::Num(s) => {
                let (f, _) = crate::strconv::ParseFloat(s.clone(), 64);
                f
            }
            _ => panic!("invalid jsontext.Token.Float call"),
        }
    }

    /// `Token.Int()` (token.go:351). Integral text parses exactly;
    /// non-integral numbers truncate via float (Go clamps/rounds
    /// similarly for representable values).
    /// The RAW number literal, as it appeared in the input. Go's
    /// integer decoders need it: `1.0` and `1e2` are "invalid syntax"
    /// for an int target, not 1 and 100, so the decision cannot be made
    /// from a parsed float.
    pub fn __number_text(&self) -> string {
        match &self.repr {
            Repr::Num(s) => s.clone(),
            _ => panic!("invalid jsontext.Token.__number_text call"),
        }
    }

    pub fn Int(&self) -> int {
        match &self.repr {
            Repr::Num(s) => {
                let (v, err) = crate::strconv::ParseInt(s.clone(), 10, 64);
                if err == nil {
                    v
                } else {
                    let (f, _) = crate::strconv::ParseFloat(s.clone(), 64);
                    f as int
                }
            }
            _ => panic!("invalid jsontext.Token.Int call"),
        }
    }

    /// Append this token's serialized text to `out`.
    fn append_text(&self, out: &mut Vec<u8>) {
        match &self.repr {
            Repr::Raw(s) => out.extend_from_slice(s.as_bytes()),
            Repr::Str(s) => append_quoted(out, s.as_bytes()),
            Repr::Num(s) => out.extend_from_slice(s.as_bytes()),
        }
    }
}

// ─── Value ───────────────────────────────────────────────────────────

/// `jsontext.Value` (value.go) — a raw JSON value (`type Value
/// []byte` in Go). Holds verbatim JSON text; `Kind` inspects the
/// first non-whitespace byte.
#[derive(Clone, Default)]
pub struct Value(pub slice<byte>);

impl core::fmt::Debug for Value {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "jsontext.Value({:?})",
            core::str::from_utf8(self.0.as_ref()).unwrap_or("<invalid utf8>")
        )
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Value {
    /// `Value.Kind()` — kind of the contained value (0 = invalid /
    /// empty).
    pub fn Kind(&self) -> Kind {
        for &b in self.0.as_ref() {
            if !is_ws(b) {
                return kind_of_byte(b);
            }
        }
        Kind(0)
    }

    /// `Value.IsValid()` (value.go) — whether the value is a single
    /// syntactically-complete JSON value.
    pub fn IsValid(&self) -> bool {
        let mut dec = Decoder::__from_bytes(self.0.as_ref(), Options::default());
        if dec.SkipValue() != crate::errors::nil {
            return false;
        }
        let (_, err) = dec.ReadToken();
        err == crate::io::EOF
    }

    /// Raw text as a goish string (Go: `string(v)`).
    pub fn String(&self) -> string {
        string::from_bytes(self.0.as_ref())
    }

    /// Length in bytes (mirrors `len(v)` on the Go []byte).
    pub fn Len(&self) -> int {
        self.0.as_ref().len() as int
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value(slice::__from_vec(s.as_bytes().to_vec()))
    }
}

impl From<slice<byte>> for Value {
    fn from(s: slice<byte>) -> Self {
        Value(s)
    }
}

impl From<crate::nilval::Nil> for Value {
    fn from(_: crate::nilval::Nil) -> Self {
        Value(slice::__from_vec(Vec::new()))
    }
}

impl PartialEq<crate::nilval::Nil> for Value {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.0.as_ref().is_empty()
    }
}

impl PartialEq<Value> for crate::nilval::Nil {
    fn eq(&self, other: &Value) -> bool {
        other.0.as_ref().is_empty()
    }
}

// ─── Options ─────────────────────────────────────────────────────────

/// `jsontext.Options` (options.go) — Go models each option as an
/// opaque interface value merged into a flag set; goish models the
/// merged set directly. Constructors below mirror the Go names, and
/// option-accepting functions take `impl AsRef<[Options]>` (the
/// settled goish lowering of `opts ...Options`).
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub(crate) allow_duplicate_names: Option<bool>,
    pub(crate) allow_invalid_utf8: Option<bool>,
    pub(crate) indent: Option<string>,
    pub(crate) indent_prefix: Option<string>,
    /// json/v2-layer flag (json.Deterministic); carried here so one
    /// options type flows through the whole stack like Go's.
    pub(crate) deterministic: Option<bool>,
}

impl Options {
    pub(crate) fn __merge(&mut self, other: &Options) {
        if other.allow_duplicate_names.is_some() {
            self.allow_duplicate_names = other.allow_duplicate_names;
        }
        if other.allow_invalid_utf8.is_some() {
            self.allow_invalid_utf8 = other.allow_invalid_utf8;
        }
        if other.indent.is_some() {
            self.indent = other.indent.clone();
        }
        if other.indent_prefix.is_some() {
            self.indent_prefix = other.indent_prefix.clone();
        }
        if other.deterministic.is_some() {
            self.deterministic = other.deterministic;
        }
    }

    pub(crate) fn __merged(opts: &[Options]) -> Options {
        let mut merged = Options::default();
        for o in opts {
            merged.__merge(o);
        }
        merged
    }
}

/// `jsontext.AllowDuplicateNames(v)` (options.go:54).
pub fn AllowDuplicateNames(v: bool) -> Options {
    Options {
        allow_duplicate_names: Some(v),
        ..Options::default()
    }
}

/// `jsontext.AllowInvalidUTF8(v)` (options.go:68).
pub fn AllowInvalidUTF8(v: bool) -> Options {
    Options {
        allow_invalid_utf8: Some(v),
        ..Options::default()
    }
}

/// `jsontext.WithIndent(indent)` (options.go:232).
pub fn WithIndent<S: Into<string>>(indent: S) -> Options {
    Options {
        indent: Some(indent.into()),
        ..Options::default()
    }
}

/// `jsontext.WithIndentPrefix(prefix)` (options.go:265).
pub fn WithIndentPrefix<S: Into<string>>(prefix: S) -> Options {
    Options {
        indent_prefix: Some(prefix.into()),
        ..Options::default()
    }
}

// ─── shared syntax helpers ───────────────────────────────────────────

fn is_ws(b: byte) -> bool {
    b == b' ' || b == b'\t' || b == b'\n' || b == b'\r'
}

/// Append `s` as a quoted JSON string with the standard escapes
/// (jsontext quote.go). Non-ASCII bytes pass through verbatim
/// (AllowInvalidUTF8-true behavior; see module header).
fn append_quoted(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'"');
    for &b in s {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0C => out.extend_from_slice(b"\\f"),
            b if b < 0x20 => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(b >> 4) as usize]);
                out.push(HEX[(b & 0xF) as usize]);
            }
            b => out.push(b),
        }
    }
    out.push(b'"');
}

/// Encode a Unicode scalar as UTF-8 into `out`.
fn push_utf8(out: &mut Vec<u8>, cp: u32) {
    let mut buf = [0u8; 4];
    let c = char::from_u32(cp).unwrap_or('\u{FFFD}');
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

// ─── Encoder ─────────────────────────────────────────────────────────

/// `jsontext.Encoder` (encode.go:52) — streaming token writer.
/// Separators (`,` / `:`) and indentation are inserted automatically
/// from the container state, exactly like Go's. A concrete type (the
/// sink is a private box, AGENTS rule 5.4) so `MarshalJSONTo(&mut
/// Encoder)` keeps Go's non-generic signature.
pub struct Encoder {
    sink: Option<Box<dyn crate::io::Writer + Send>>,
    buf: Vec<u8>,
    /// Open containers: b'{' / b'['.
    stack: Vec<u8>,
    /// Tokens written per open container (objects count names and
    /// values separately; even count ⇒ name position).
    counts: Vec<u64>,
    /// Top-level values completed (streaming mode separates them
    /// with a newline, encode.go WriteToken).
    top_values: u64,
    opts: Options,
}

/// `jsontext.NewEncoder(w, opts...)` (encode.go:91).
pub fn NewEncoder<W: crate::io::Writer + Send + 'static>(
    w: W,
    opts: impl AsRef<[Options]>,
) -> Encoder {
    Encoder {
        sink: Some(Box::new(w)),
        buf: Vec::new(),
        stack: Vec::new(),
        counts: Vec::new(),
        top_values: 0,
        opts: Options::__merged(opts.as_ref()),
    }
}

impl Encoder {
    /// Buffer-only encoder (no sink) — backs `json::Marshal`.
    pub(crate) fn __buffered(opts: Options) -> Encoder {
        Encoder {
            sink: None,
            buf: Vec::new(),
            stack: Vec::new(),
            counts: Vec::new(),
            top_values: 0,
            opts,
        }
    }

    /// Options in effect (Go `Encoder.Options()`, encode.go:144).
    pub fn Options(&self) -> Options {
        self.opts.clone()
    }

    /// `Encoder.StackDepth()` (encode.go:935).
    pub fn StackDepth(&self) -> int {
        self.stack.len() as int
    }

    fn indented(&self) -> bool {
        self.opts.indent.is_some()
    }

    fn write_newline_indent(&mut self, depth: usize) {
        let indent = match &self.opts.indent {
            Some(i) => i.clone(),
            None => return,
        };
        self.buf.push(b'\n');
        if let Some(p) = &self.opts.indent_prefix {
            self.buf.extend_from_slice(p.as_bytes());
        }
        for _ in 0..depth {
            self.buf.extend_from_slice(indent.as_bytes());
        }
    }

    /// Insert the separator/indent owed before the next token of
    /// kind `k`, and validate basic grammar position.
    fn before_token(&mut self, k: Kind) -> error {
        match self.stack.last().copied() {
            Some(b'{') => {
                let count = *self.counts.last().unwrap();
                if k == Kind(b'}') {
                    if count % 2 == 1 {
                        return errors::New("jsontext: object name without value");
                    }
                    if count > 0 && self.indented() {
                        let d = self.stack.len() - 1;
                        self.write_newline_indent(d);
                    }
                } else if count % 2 == 0 {
                    // Name position: only strings are legal names.
                    if k != Kind(b'"') {
                        return errors::New("jsontext: missing string for object name");
                    }
                    if count > 0 {
                        self.buf.push(b',');
                    }
                    if self.indented() {
                        let d = self.stack.len();
                        self.write_newline_indent(d);
                    }
                } else {
                    self.buf.push(b':');
                    if self.indented() {
                        self.buf.push(b' ');
                    }
                }
            }
            Some(b'[') => {
                let count = *self.counts.last().unwrap();
                if k == Kind(b']') {
                    if count > 0 && self.indented() {
                        let d = self.stack.len() - 1;
                        self.write_newline_indent(d);
                    }
                } else {
                    if count > 0 {
                        self.buf.push(b',');
                    }
                    if self.indented() {
                        let d = self.stack.len();
                        self.write_newline_indent(d);
                    }
                }
            }
            _ => {
                if k == Kind(b'}') || k == Kind(b']') {
                    return errors::New("jsontext: unexpected end token at top level");
                }
                if self.top_values > 0 {
                    // Streaming mode: newline-delimit top-level values.
                    self.buf.push(b'\n');
                }
            }
        }
        nil
    }

    /// Track container state after a token of kind `k` landed.
    fn after_token(&mut self, k: Kind) {
        match k.0 {
            b'{' | b'[' => {
                self.stack.push(k.0);
                self.counts.push(0);
            }
            b'}' | b']' => {
                self.stack.pop();
                self.counts.pop();
                self.bump_count();
            }
            _ => self.bump_count(),
        }
    }

    fn bump_count(&mut self) {
        match self.counts.last_mut() {
            Some(c) => *c += 1,
            None => self.top_values += 1,
        }
    }

    /// Flush the buffer to the sink once a top-level value is
    /// complete (Go's Encoder flushes per top-level value too).
    fn maybe_flush(&mut self) -> error {
        if !self.stack.is_empty() || self.sink.is_none() {
            return nil;
        }
        let out = slice::__from_vec(core::mem::take(&mut self.buf));
        let w = self.sink.as_mut().unwrap();
        let (_, err) = w.Write(out);
        err
    }

    /// `Encoder.WriteToken(t)` (encode.go:345).
    pub fn WriteToken(&mut self, t: Token) -> error {
        let k = t.Kind();
        let err = self.before_token(k);
        if err != nil {
            return err;
        }
        t.append_text(&mut self.buf);
        self.after_token(k);
        self.maybe_flush()
    }

    /// `Encoder.WriteValue(v)` (encode.go:523) — write a whole raw
    /// value in one call. The value text is emitted verbatim (see
    /// module header).
    pub fn WriteValue(&mut self, v: Value) -> error {
        let k = v.Kind();
        if k == Kind(0) {
            return errors::New("jsontext: invalid empty Value");
        }
        let err = self.before_token(k);
        if err != nil {
            return err;
        }
        // Trim surrounding whitespace so separators stay tight.
        let raw = v.0.as_ref();
        let start = raw.iter().position(|&b| !is_ws(b)).unwrap_or(0);
        let end = raw
            .iter()
            .rposition(|&b| !is_ws(b))
            .map(|i| i + 1)
            .unwrap_or(raw.len());
        self.buf.extend_from_slice(&raw[start..end]);
        // A whole value occupies exactly one slot at this level.
        self.bump_count();
        self.maybe_flush()
    }

    /// Drain the accumulated buffer (buffer-mode encoders only) —
    /// backs `json::Marshal`.
    pub(crate) fn __take_buf(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.buf)
    }
}

// ─── Decoder ─────────────────────────────────────────────────────────

/// `jsontext.Decoder` (decode.go:79) — streaming token reader over an
/// `io::Reader` or byte buffer. Fills on demand; consumed bytes are
/// compacted away at each top-level value boundary so long-lived
/// stream decoders (LSP stdin) stay bounded by message size.
pub struct Decoder {
    src: Option<Box<dyn crate::io::Reader + Send>>,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
    stack: Vec<u8>,
    counts: Vec<u64>,
    /// Member names seen so far in each OPEN OBJECT frame, so a
    /// duplicate can be rejected (decode.go's `namespaces`). One entry
    /// per frame in `stack`, `None` for an array frame. Only populated
    /// when duplicates are disallowed, which is the default.
    names: Vec<Option<BTreeSet<Vec<u8>>>>,
    /// Most recent member name read in each open object frame. With
    /// `counts` (the element index for array frames) this is the JSON
    /// pointer Go appends to a duplicate-name error as `within "..."`.
    cur_name: Vec<Option<Vec<u8>>>,
    /// Separator for the upcoming token has been consumed (PeekKind
    /// runs the same preparation as ReadToken; this keeps it
    /// idempotent for the strict `:` case).
    sep_done: bool,
    opts: Options,
}

/// `jsontext.NewDecoder(r, opts...)` (decode.go:122).
pub fn NewDecoder<R: crate::io::Reader + Send + 'static>(
    r: R,
    opts: impl AsRef<[Options]>,
) -> Decoder {
    Decoder {
        src: Some(Box::new(r)),
        buf: Vec::new(),
        pos: 0,
        eof: false,
        stack: Vec::new(),
        counts: Vec::new(),
        names: Vec::new(),
        cur_name: Vec::new(),
        sep_done: false,
        opts: Options::__merged(opts.as_ref()),
    }
}

impl Decoder {
    /// Decoder over an in-memory buffer — backs `json::Unmarshal`.
    pub(crate) fn __from_bytes(data: &[u8], opts: Options) -> Decoder {
        Decoder {
            src: None,
            buf: data.to_vec(),
            pos: 0,
            eof: true,
            stack: Vec::new(),
            counts: Vec::new(),
            names: Vec::new(),
            cur_name: Vec::new(),
            sep_done: false,
            opts,
        }
    }

    /// Options in effect (Go `Decoder.Options()`, decode.go:160).
    pub fn Options(&self) -> Options {
        self.opts.clone()
    }

    /// `Decoder.StackDepth()` (decode.go:1131).
    pub fn StackDepth(&self) -> int {
        self.stack.len() as int
    }

    /// Pull more bytes from the source. Returns false at EOF.
    fn fill(&mut self) -> bool {
        if self.eof {
            return false;
        }
        let src = match self.src.as_mut() {
            Some(s) => s,
            None => {
                self.eof = true;
                return false;
            }
        };
        let mut chunk = slice::__from_vec(alloc::vec![0u8; 4096]);
        let (n, err) = src.Read(&mut chunk);
        if n > 0 {
            self.buf.extend_from_slice(&chunk.as_ref()[..n as usize]);
            return true;
        }
        // n == 0: EOF or error — either way no more bytes will come.
        let _ = err;
        self.eof = true;
        false
    }

    /// Byte at `pos + off`, filling as needed.
    fn peek_at(&mut self, off: usize) -> Option<byte> {
        while self.pos + off >= self.buf.len() {
            if !self.fill() {
                return None;
            }
        }
        Some(self.buf[self.pos + off])
    }

    fn skip_ws(&mut self) {
        loop {
            match self.peek_at(0) {
                Some(b) if is_ws(b) => self.pos += 1,
                _ => return,
            }
        }
    }

    /// Consume the separator owed before the next token, per
    /// container state. Idempotent via `sep_done`.
    fn prepare_next(&mut self) -> error {
        if self.sep_done {
            return nil;
        }
        self.skip_ws();
        match self.stack.last().copied() {
            Some(b'{') => {
                let count = *self.counts.last().unwrap();
                if count % 2 == 1 {
                    // Value position: a ':' must separate name and value.
                    match self.peek_at(0) {
                        Some(b':') => {
                            self.pos += 1;
                            self.skip_ws();
                        }
                        Some(_) => return errors::New("jsontext: missing ':' after object name"),
                        None => return crate::io::ErrUnexpectedEOF.into(),
                    }
                } else if count > 0 {
                    // Between members: ',' unless the object ends.
                    match self.peek_at(0) {
                        Some(b',') => {
                            let err = self.consume_comma();
                            if err != nil {
                                return err;
                            }
                        }
                        Some(b'}') => {}
                        Some(_) => return errors::New("jsontext: missing ',' after object value"),
                        None => return crate::io::ErrUnexpectedEOF.into(),
                    }
                }
            }
            Some(b'[') => {
                let count = *self.counts.last().unwrap();
                if count > 0 {
                    match self.peek_at(0) {
                        Some(b',') => {
                            let err = self.consume_comma();
                            if err != nil {
                                return err;
                            }
                        }
                        Some(b']') => {}
                        Some(_) => return errors::New("jsontext: missing ',' after array element"),
                        None => return crate::io::ErrUnexpectedEOF.into(),
                    }
                }
            }
            _ => {}
        }
        self.sep_done = true;
        nil
    }

    // Go: encoding/json/jsontext/decode.go:311-357 — decoderState.PeekKind
    // goishlint:ignore GOISH014 — delimiter portion of Go's PeekKind, factored for shared token/value/skip preparation.
    fn consume_comma(&mut self) -> error {
        // Do not advance pos until lookahead succeeds. Go keeps peekErr after
        // failed lookahead; retaining the delimiter reproduces that error on
        // the following read without accepting a trailing comma as an end.
        let mut offset = 1;
        loop {
            match self.peek_at(offset) {
                Some(c) if is_ws(c) => offset += 1,
                Some(b']' | b'}') => return errors::New("jsontext: trailing comma in composite"),
                None => return crate::io::ErrUnexpectedEOF.into(),
                Some(_) => break,
            }
        }
        self.pos += offset;
        return nil;
    }

    /// `Decoder.PeekKind()` (decode.go:307) — kind of the next token
    /// without consuming it. Returns the invalid Kind (0) on EOF or
    /// syntax error, like Go.
    pub fn PeekKind(&mut self) -> Kind {
        if self.prepare_next() != nil {
            return Kind(0);
        }
        match self.peek_at(0) {
            Some(b) => kind_of_byte(b),
            None => Kind(0),
        }
    }

    /// True when the next token at this level is an OBJECT MEMBER NAME
    /// rather than a value: inside an object frame, with an even number
    /// of tokens consumed so far (name and value alternate). Same test
    /// the "object name without value" check uses from the other side.
    fn expecting_name(&self) -> bool {
        self.stack.last() == Some(&b'{') && self.counts.last().is_some_and(|c| c % 2 == 0)
    }

    /// Go: decode.go's duplicate-name check. Records `name` in the
    /// current object's namespace, or reports it as a duplicate.
    /// A no-op when `AllowDuplicateNames(true)` is in effect.
    fn record_name(&mut self, name: &[u8]) -> error {
        if let Some(slot) = self.cur_name.last_mut() {
            *slot = Some(name.to_vec());
        }
        if self.opts.allow_duplicate_names.unwrap_or(false) {
            return nil;
        }
        let fresh = match self.names.last_mut() {
            Some(Some(set)) => set.insert(name.to_vec()),
            // No object frame — not a member name after all.
            _ => true,
        };
        if fresh {
            return nil;
        }
        // Go quotes the name as a JSON string, and appends the JSON
        // pointer of the CONTAINING object when it is not the root.
        let mut msg = string::from_static("jsontext: duplicate object member name ")
            + string::from_bytes(&json_quote(name));
        let ptr = self.stack_pointer_to_parent();
        if !ptr.is_empty() {
            msg = msg + " within " + string::from_bytes(&json_quote(&ptr));
        }
        errors::New(msg)
    }

    /// The JSON pointer of the object the CURRENT frame is, built from
    /// the frames above it: each object contributes its current member
    /// name, each array its current element index. Empty at the root,
    /// which is where Go omits the `within` clause.
    fn stack_pointer_to_parent(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        if self.stack.len() < 2 {
            return out;
        }
        for i in 0..self.stack.len() - 1 {
            out.push(b'/');
            if self.stack[i] == b'{' {
                if let Some(Some(n)) = self.cur_name.get(i) {
                    // Go escapes `~` as `~0` and `/` as `~1`
                    // (RFC 6901), so a name containing either does not
                    // fake a path separator.
                    for &b in n {
                        match b {
                            b'~' => out.extend_from_slice(b"~0"),
                            b'/' => out.extend_from_slice(b"~1"),
                            _ => out.push(b),
                        }
                    }
                }
            } else {
                let idx = self.counts.get(i).copied().unwrap_or(0);
                out.extend_from_slice(crate::strconv::FormatUint(idx, 10).as_bytes());
            }
        }
        out
    }

    /// Decode the member name at `pos` WITHOUT consuming it, so
    /// ReadValue and SkipValue can record it before scanning the raw
    /// bytes. Decoding matters: `{"a":1,"\u0061":2}` is a duplicate,
    /// and comparing the raw literals would miss it.
    fn record_name_at_pos(&mut self) -> error {
        if !self.expecting_name() || self.peek_at(0) != Some(b'"') {
            return nil;
        }
        let saved = self.pos;
        let decoded = self.scan_string_decoded();
        self.pos = saved;
        match decoded {
            Ok(name) => self.record_name(name.as_bytes()),
            // A malformed name: let the normal scan report it.
            Err(_) => nil,
        }
    }

    /// Book-keeping after one whole value (or structural token) was
    /// consumed at the current level.
    fn after_token(&mut self, k: Kind) {
        self.sep_done = false;
        match k.0 {
            b'{' | b'[' => {
                self.stack.push(k.0);
                self.counts.push(0);
                // One namespace per frame, kept in lockstep with
                // `stack` so the pop below cannot get out of step.
                self.names.push(if k.0 == b'{' {
                    Some(BTreeSet::new())
                } else {
                    None
                });
                self.cur_name.push(None);
            }
            b'}' | b']' => {
                self.stack.pop();
                self.counts.pop();
                self.names.pop();
                self.cur_name.pop();
                self.bump_count();
            }
            _ => self.bump_count(),
        }
        if self.stack.is_empty() {
            // Top-level value boundary: compact consumed bytes.
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn bump_count(&mut self) {
        if let Some(c) = self.counts.last_mut() {
            *c += 1;
        }
    }

    /// Expect the literal `word` at the cursor (for null/true/false).
    fn expect_literal(&mut self, word: &'static str) -> error {
        for (i, &w) in word.as_bytes().iter().enumerate() {
            match self.peek_at(i) {
                Some(b) if b == w => {}
                Some(_) => return errors::New("jsontext: invalid literal"),
                None => return crate::io::ErrUnexpectedEOF.into(),
            }
        }
        self.pos += word.len();
        nil
    }

    /// `Decoder.ReadToken()` (decode.go:461). At the top level with
    /// only whitespace left, returns `io::EOF` (Go does the same).
    pub fn ReadToken(&mut self) -> (Token, error) {
        let invalid = Token {
            repr: Repr::Raw("null"),
        };
        let err = self.prepare_next();
        if err != nil {
            return (invalid, err);
        }
        let b = match self.peek_at(0) {
            Some(b) => b,
            None => {
                if self.stack.is_empty() {
                    return (invalid, crate::io::EOF.into());
                }
                return (invalid, crate::io::ErrUnexpectedEOF.into());
            }
        };
        match b {
            b'{' | b'[' => {
                self.pos += 1;
                let k = kind_of_byte(b);
                self.after_token(k);
                (if b == b'{' { BeginObject } else { BeginArray }, nil)
            }
            b'}' | b']' => {
                if self.stack.last().copied() != Some(if b == b'}' { b'{' } else { b'[' }) {
                    return (invalid, errors::New("jsontext: mismatched end token"));
                }
                if b == b'}' && *self.counts.last().unwrap() % 2 == 1 {
                    return (invalid, errors::New("jsontext: object name without value"));
                }
                self.pos += 1;
                self.after_token(kind_of_byte(b));
                (if b == b'}' { EndObject } else { EndArray }, nil)
            }
            b'n' => {
                let err = self.expect_literal("null");
                if err != nil {
                    return (invalid, err);
                }
                self.after_token(Kind(b'n'));
                (Null, nil)
            }
            b't' => {
                let err = self.expect_literal("true");
                if err != nil {
                    return (invalid, err);
                }
                self.after_token(Kind(b't'));
                (True, nil)
            }
            b'f' => {
                let err = self.expect_literal("false");
                if err != nil {
                    return (invalid, err);
                }
                self.after_token(Kind(b'f'));
                (False, nil)
            }
            b'"' => match self.scan_string_decoded() {
                Ok(s) => {
                    if self.expecting_name() {
                        let err = self.record_name(s.as_bytes());
                        if err != nil {
                            return (invalid, err);
                        }
                    }
                    self.after_token(Kind(b'"'));
                    (Token { repr: Repr::Str(s) }, nil)
                }
                Err(e) => (invalid, e),
            },
            b'-' | b'0'..=b'9' => match self.scan_number() {
                Ok(raw) => {
                    self.after_token(Kind(b'0'));
                    (
                        Token {
                            repr: Repr::Num(raw),
                        },
                        nil,
                    )
                }
                Err(e) => (invalid, e),
            },
            _ => (
                invalid,
                errors::New("jsontext: invalid character at start of value"),
            ),
        }
    }

    /// Scan a quoted string starting at `pos`, decoding escapes.
    /// Leaves `pos` after the closing quote.
    fn scan_string_decoded(&mut self) -> Result<string, error> {
        debug_assert_eq!(self.buf[self.pos], b'"');
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let b = match self.peek_at(0) {
                Some(b) => b,
                None => return Err(crate::io::ErrUnexpectedEOF.into()),
            };
            self.pos += 1;
            match b {
                b'"' => return Ok(string::from_bytes(&out)),
                b'\\' => {
                    let e = match self.peek_at(0) {
                        Some(e) => e,
                        None => return Err(crate::io::ErrUnexpectedEOF.into()),
                    };
                    self.pos += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hi = self.read_hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                // Surrogate pair: expect \uDC00-\uDFFF.
                                if self.peek_at(0) == Some(b'\\') && self.peek_at(1) == Some(b'u') {
                                    self.pos += 2;
                                    let lo = self.read_hex4()?;
                                    if (0xDC00..0xE000).contains(&lo) {
                                        0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                    } else {
                                        0xFFFD
                                    }
                                } else {
                                    0xFFFD
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                0xFFFD // unpaired low surrogate
                            } else {
                                hi
                            };
                            push_utf8(&mut out, cp);
                        }
                        _ => {
                            return Err(errors::New("jsontext: invalid escape sequence in string"))
                        }
                    }
                }
                b => out.push(b),
            }
        }
    }

    fn read_hex4(&mut self) -> Result<u32, error> {
        let mut v: u32 = 0;
        for i in 0..4 {
            let c = match self.peek_at(i) {
                Some(c) => c,
                None => return Err(crate::io::ErrUnexpectedEOF.into()),
            };
            let nib = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' => (c - b'a' + 10) as u32,
                b'A'..=b'F' => (c - b'A' + 10) as u32,
                _ => return Err(errors::New("jsontext: invalid \\u escape")),
            };
            v = (v << 4) | nib;
        }
        self.pos += 4;
        Ok(v)
    }

    /// Scan a JSON number, returning its verbatim text.
    fn scan_number(&mut self) -> Result<string, error> {
        let start = self.pos;
        if self.peek_at(0) == Some(b'-') {
            self.pos += 1;
        }
        let mut saw_digit = false;
        // Go jsonwire/decode.go:472-514 (ConsumeNumberResumable): the
        // integer part is either exactly zero or a nonzero-leading digit
        // sequence. Streaming "01" reads 0, leaving 1 for the next value.
        if self.peek_at(0) == Some(b'0') {
            saw_digit = true;
            self.pos += 1;
        } else {
            while let Some(b'0'..=b'9') = self.peek_at(0) {
                saw_digit = true;
                self.pos += 1;
            }
        }
        if !saw_digit {
            return Err(errors::New("jsontext: invalid number"));
        }
        if self.peek_at(0) == Some(b'.') {
            self.pos += 1;
            let mut frac = false;
            while let Some(b @ b'0'..=b'9') = self.peek_at(0) {
                let _ = b;
                frac = true;
                self.pos += 1;
            }
            if !frac {
                return Err(errors::New("jsontext: invalid number fraction"));
            }
        }
        if matches!(self.peek_at(0), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek_at(0), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            let mut exp = false;
            while let Some(b @ b'0'..=b'9') = self.peek_at(0) {
                let _ = b;
                exp = true;
                self.pos += 1;
            }
            if !exp {
                return Err(errors::New("jsontext: invalid number exponent"));
            }
        }
        Ok(string::from_bytes(&self.buf[start..self.pos]))
    }

    /// `Decoder.ReadValue()` (decode.go:667) — read the next whole
    /// value verbatim (a name string counts as a value at name
    /// position, matching Go).
    pub fn ReadValue(&mut self) -> (Value, error) {
        let err = self.prepare_next();
        if err != nil {
            return (Value::default(), err);
        }
        if self.peek_at(0).is_none() {
            if self.stack.is_empty() {
                return (Value::default(), crate::io::EOF.into());
            }
            return (Value::default(), crate::io::ErrUnexpectedEOF.into());
        }
        let err = self.record_name_at_pos();
        if err != nil {
            return (Value::default(), err);
        }
        let start = self.pos;
        let err = self.scan_whole_value();
        if err != nil {
            return (Value::default(), err);
        }
        let raw = self.buf[start..self.pos].to_vec();
        self.sep_done = false;
        self.bump_count();
        if self.stack.is_empty() {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        (Value(slice::__from_vec(raw)), nil)
    }

    // Go: encoding/json/jsontext/decode.go:409-431 — decoderState.SkipValue
    // goishlint:ignore GOISH014 — public adapter ports the decoderState method directly.
    pub fn SkipValue(&mut self) -> error {
        match self.PeekKind().0 {
            b'{' | b'[' => {
                let depth = self.StackDepth();
                loop {
                    let (_, err) = self.ReadToken();
                    if err != nil {
                        return err;
                    }
                    if depth >= self.StackDepth() {
                        return nil;
                    }
                }
            }
            _ => {
                let (_, err) = self.ReadValue();
                return err;
            }
        }
    }

    /// Structural scan over one whole value (no token
    /// materialization). Assumes `prepare_next` ran.
    fn scan_whole_value(&mut self) -> error {
        let mut path = self.stack_pointer_to_parent();
        if let Some(open) = self.stack.last() {
            path.push(b'/');
            if *open == b'{' {
                if let Some(Some(name)) = self.cur_name.last() {
                    for &b in name {
                        match b {
                            b'~' => path.extend_from_slice(b"~0"),
                            b'/' => path.extend_from_slice(b"~1"),
                            _ => path.push(b),
                        }
                    }
                }
            } else {
                let index = self.counts.last().copied().unwrap_or(0);
                path.extend_from_slice(crate::strconv::FormatUint(index, 10).as_bytes());
            }
        }
        return self.scan_whole_value_at(&mut path);
    }

    // Go: encoding/json/jsontext/decode.go:950 — decoderState.consumeObject
    // goishlint:ignore GOISH014 — raw-value recursive scanner combines Go's consumeValue/consumeObject/consumeArray; provenance is above.
    fn scan_whole_value_at(&mut self, path: &mut Vec<u8>) -> error {
        let b = match self.peek_at(0) {
            Some(b) => b,
            None => return crate::io::ErrUnexpectedEOF.into(),
        };
        match b {
            b'n' => self.expect_literal("null"),
            b't' => self.expect_literal("true"),
            b'f' => self.expect_literal("false"),
            b'"' => match self.scan_string_raw() {
                Ok(()) => nil,
                Err(e) => e,
            },
            b'-' | b'0'..=b'9' => match self.scan_number() {
                Ok(_) => nil,
                Err(e) => e,
            },
            b'{' | b'[' => {
                let open = b;
                let close = if b == b'{' { b'}' } else { b']' };
                self.pos += 1;
                let mut first = true;
                let mut names: BTreeSet<Vec<u8>> = BTreeSet::new();
                let mut index = 0;
                loop {
                    self.skip_ws();
                    match self.peek_at(0) {
                        Some(c) if c == close => {
                            self.pos += 1;
                            return nil;
                        }
                        Some(_) => {}
                        None => return crate::io::ErrUnexpectedEOF.into(),
                    }
                    if !first {
                        match self.peek_at(0) {
                            Some(b',') => {
                                self.pos += 1;
                                self.skip_ws();
                            }
                            _ => return errors::New("jsontext: missing ',' in composite"),
                        }
                    }
                    first = false;
                    let mut name = string::new();
                    if open == b'{' {
                        // name : value
                        match self.peek_at(0) {
                            Some(b'"') => {}
                            _ => return errors::New("jsontext: missing object name"),
                        }
                        name = match self.scan_string_decoded() {
                            Ok(name) => name,
                            Err(err) => return err,
                        };
                        if !self.opts.allow_duplicate_names.unwrap_or(false)
                            && !names.insert(name.as_bytes().to_vec()) {
                            let mut msg = string::from_static("jsontext: duplicate object member name ")
                                + string::from_bytes(&json_quote(name.as_bytes()));
                            if !path.is_empty() {
                                msg = msg + " within " + string::from_bytes(&json_quote(path));
                            }
                            return errors::New(msg);
                        }
                        self.skip_ws();
                        match self.peek_at(0) {
                            Some(b':') => self.pos += 1,
                            _ => return errors::New("jsontext: missing ':' in object"),
                        }
                        self.skip_ws();
                    }
                    let parent_len = path.len();
                    path.push(b'/');
                    if open == b'{' {
                        for &b in name.as_bytes() {
                            match b {
                                b'~' => path.extend_from_slice(b"~0"),
                                b'/' => path.extend_from_slice(b"~1"),
                                _ => path.push(b),
                            }
                        }
                    } else {
                        path.extend_from_slice(crate::strconv::FormatUint(index, 10).as_bytes());
                    }
                    let err = self.scan_whole_value_at(path);
                    path.truncate(parent_len);
                    if err != nil {
                        return err;
                    }
                    index += 1;
                }
            }
            _ => return errors::New("jsontext: invalid character at start of value"),
        }
    }

    /// Scan past a quoted string without decoding escapes.
    fn scan_string_raw(&mut self) -> Result<(), error> {
        debug_assert_eq!(self.buf[self.pos], b'"');
        self.pos += 1;
        loop {
            let b = match self.peek_at(0) {
                Some(b) => b,
                None => return Err(crate::io::ErrUnexpectedEOF.into()),
            };
            self.pos += 1;
            match b {
                b'"' => return Ok(()),
                b'\\' => {
                    if self.peek_at(0).is_none() {
                        return Err(crate::io::ErrUnexpectedEOF.into());
                    }
                    self.pos += 1;
                }
                _ => {}
            }
        }
    }
}
