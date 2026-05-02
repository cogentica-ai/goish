// fmt — Go's `fmt` package, ported.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   fmt.Println("hi", x)                  fmt::Println!("hi", x)
//   fmt.Print(x)                          fmt::Print!(x)
//   fmt.Printf("%d items\n", n)           fmt::Printf!("%d items\n", n)
//   s := fmt.Sprintf("%.2f", pi)          let s = fmt::Sprintf!("%.2f", pi);
//   fmt.Fprintf(w, "%s\n", n)             fmt::Fprintf!(w, "%s\n", n);
//   fmt.Fprintln(w, "hi")                 fmt::Fprintln!(w, "hi");
//   err := fmt.Errorf("bad: %w", e)       let err = fmt::Errorf!("bad: %w", e);
//
// Verbs (M8 launch set): %s %d %v %t %x %X %b %o %c %q %w %%.
// Floats (%f %e %g), pointer (%p), reflection (%T %#v %+v) and Unicode
// (%U) are deferred — they need helpers that don't exist yet (float
// printing, type ids).
//
// Flags: width, '-' (left align), '0' (zero pad). Precision deferred.
//
// Argument dispatch uses the autoref-spec trick (see __fmt_arg) so a
// single macro call site can pick the right `FmtArg` variant per arg
// type at compile time:
//   - `error`           → FmtArg::Err     (carries typed err for %w)
//   - any T: Stringer   → FmtArg::Stringer (calls T::String())
//   - any T: Format     → FmtArg::Val
// Mirrors v0's pattern; less the std::fmt::Display dependency (we're
// no_std and don't want Display leaking into user signatures).

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{self, error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::io::Writer as _; // bring `.Write()` method into scope
use crate::errors::nil;
use crate::os;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// ─── Public traits ─────────────────────────────────────────────────────

/// Go's `fmt.Stringer`. User types implement this to define their `%s`
/// / `%v` representation.
pub trait Stringer {
    fn String(&self) -> string;
}

/// Internal dispatch trait. Implemented for all builtin types in this
/// file. User types satisfy it via the blanket on `Stringer` below.
pub trait Format {
    fn fmt(&self, verb: byte, f: &mut FmtBuf);
}

// Blanket so any user type that impls Stringer is automatically
// formattable. Coherence: this doesn't conflict with the per-builtin
// impls below because none of our builtins impl Stringer (we hand-
// implement Format for them directly).
impl<T: Stringer + ?Sized> Format for T {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        let s = self.String();
        write_string_with_verb(s.as_bytes(), verb, f);
    }
}

// (No blanket `impl<T: Format> Format for &T` — it overlaps with the
// `impl<T: Stringer> Format for T` blanket above. The `#[goish::reflect]`
// macro instead emits `impl Format for &MyStruct` per type.)

// ─── FmtBuf — the byte accumulator ────────────────────────────────────

pub struct FmtBuf {
    buf: Vec<byte>,
}

impl FmtBuf {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }
    pub fn push(&mut self, b: byte) {
        self.buf.push(b);
    }
    pub fn extend(&mut self, s: &[byte]) {
        self.buf.extend_from_slice(s);
    }
    fn into_bytes(self) -> Vec<byte> {
        self.buf
    }
}

// ─── FmtArg — the autoref-spec dispatch envelope ──────────────────────

pub enum FmtArg<'a> {
    Val(&'a dyn Format),
    Err(&'a error),
}

impl<'a> FmtArg<'a> {
    fn write(&self, verb: byte, f: &mut FmtBuf) {
        match self {
            FmtArg::Val(v) => v.fmt(verb, f),
            FmtArg::Err(e) => {
                // %s / %v / default for an error → Error() text.
                let s = e.Error();
                write_string_with_verb(s.as_bytes(), verb, f);
            }
        }
    }
    fn as_error(&self) -> Option<&'a error> {
        match self {
            FmtArg::Err(e) => Some(*e),
            _ => None,
        }
    }
}

#[doc(hidden)]
pub mod __fmt_arg {
    use super::*;
    pub struct Wrap<'a, T: ?Sized>(pub &'a T);

    impl<'a, T: ?Sized> Copy for Wrap<'a, T> {}
    impl<'a, T: ?Sized> Clone for Wrap<'a, T> {
        fn clone(&self) -> Self {
            *self
        }
    }

    pub trait ViaError<'a> {
        fn fmt_arg(self) -> FmtArg<'a>;
    }
    pub trait ViaFormat<'a> {
        fn fmt_arg(self) -> FmtArg<'a>;
    }

    // Specific: error → FmtArg::Err. Tried first via 0-step autoref.
    impl<'a> ViaError<'a> for Wrap<'a, error> {
        fn fmt_arg(self) -> FmtArg<'a> {
            FmtArg::Err(self.0)
        }
    }

    // Generic: anything Format → FmtArg::Val. Reached via auto-ref.
    impl<'a, T: Format> ViaFormat<'a> for &Wrap<'a, T> {
        fn fmt_arg(self) -> FmtArg<'a> {
            FmtArg::Val(self.0)
        }
    }
}

// ─── Format impls for builtins ────────────────────────────────────────

impl Format for bool {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        let _ = verb; // %t / %v / %s all print true/false
        f.extend(if *self { b"true" } else { b"false" });
    }
}

impl Format for string {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        write_string_with_verb(self.as_bytes(), verb, f);
    }
}

impl Format for &str {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        write_string_with_verb(self.as_bytes(), verb, f);
    }
}

impl Format for slice<byte> {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        // self: &slice<byte>; Deref<Target=[byte]> auto-coerces to &[byte].
        write_string_with_verb(self, verb, f);
    }
}

impl Format for char {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        // %c / %v default to the character. %d would be the codepoint.
        let r = *self as rune;
        format_rune_or_int(r, verb, f);
    }
}

// All integer widths route through one helper.
macro_rules! impl_format_for_signed {
    ($($t:ty),*) => { $( impl Format for $t {
        fn fmt(&self, verb: byte, f: &mut FmtBuf) {
            format_signed(*self as i64, verb, f);
        }
    } )* };
}
macro_rules! impl_format_for_unsigned {
    ($($t:ty),*) => { $( impl Format for $t {
        fn fmt(&self, verb: byte, f: &mut FmtBuf) {
            format_unsigned(*self as u64, verb, f);
        }
    } )* };
}
impl_format_for_signed!(i8, i16, i32, i64, isize);
impl_format_for_unsigned!(u16, u32, u64, usize);

// Floats — route through strconv::FormatFloat. %v defaults to 'g' with
// shortest round-trip (prec=-1). Width/precision flags from the verb
// scanner aren't yet honored for floats; FormatFloat takes its own prec.
impl Format for f64 {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        let (fmt, prec) = match verb {
            b'f' | b'F' => (b'f', -1i64),
            b'e' => (b'e', -1i64),
            b'E' => (b'E', -1i64),
            b'g' | b'v' => (b'g', -1i64),
            b'G' => (b'G', -1i64),
            b'x' => (b'x', -1i64),
            b'X' => (b'X', -1i64),
            b'b' => (b'b', -1i64),
            _ => (b'g', -1i64),
        };
        let s = crate::strconv::FormatFloat(*self, fmt, prec, 64);
        f.extend(s.as_bytes());
    }
}

impl Format for f32 {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        let (fmt, prec) = match verb {
            b'f' | b'F' => (b'f', -1i64),
            b'e' => (b'e', -1i64),
            b'E' => (b'E', -1i64),
            b'g' | b'v' => (b'g', -1i64),
            b'G' => (b'G', -1i64),
            b'x' => (b'x', -1i64),
            b'X' => (b'X', -1i64),
            b'b' => (b'b', -1i64),
            _ => (b'g', -1i64),
        };
        let s = crate::strconv::FormatFloat(*self as f64, fmt, prec, 32);
        f.extend(s.as_bytes());
    }
}

// byte = u8 — special-case so %c renders ASCII char, %d the number.
impl Format for u8 {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        match verb {
            b'c' => f.push(*self),
            _ => format_unsigned(*self as u64, verb, f),
        }
    }
}

// error itself impls Format — %s / %v render `.Error()` text. (FmtArg
// already handles error specially for %w; this is the fallback path
// when user code writes `&err as &dyn Format`.)
impl Format for error {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        if *self == nil {
            f.extend(b"<nil>");
            return;
        }
        let s = self.Error();
        write_string_with_verb(s.as_bytes(), verb, f);
    }
}

// ─── Verb formatters ──────────────────────────────────────────────────

fn write_string_with_verb(bytes: &[byte], verb: byte, f: &mut FmtBuf) {
    match verb {
        b'q' => write_quoted(bytes, f),
        b'x' => write_hex(bytes, false, f),
        b'X' => write_hex(bytes, true, f),
        _ => f.extend(bytes), // %s, %v, default
    }
}

fn write_quoted(bytes: &[byte], f: &mut FmtBuf) {
    f.push(b'"');
    for &b in bytes {
        match b {
            b'"' => f.extend(b"\\\""),
            b'\\' => f.extend(b"\\\\"),
            b'\n' => f.extend(b"\\n"),
            b'\r' => f.extend(b"\\r"),
            b'\t' => f.extend(b"\\t"),
            b' '..=b'~' => f.push(b),
            _ => {
                // Escape as \xHH for non-printable bytes.
                f.extend(b"\\x");
                f.push(hex_digit(b >> 4, false));
                f.push(hex_digit(b & 0xF, false));
            }
        }
    }
    f.push(b'"');
}

fn write_hex(bytes: &[byte], upper: bool, f: &mut FmtBuf) {
    for &b in bytes {
        f.push(hex_digit(b >> 4, upper));
        f.push(hex_digit(b & 0xF, upper));
    }
}

fn hex_digit(n: byte, upper: bool) -> byte {
    if n < 10 {
        b'0' + n
    } else if upper {
        b'A' + n - 10
    } else {
        b'a' + n - 10
    }
}

fn format_signed(n: i64, verb: byte, f: &mut FmtBuf) {
    match verb {
        b'd' | b'v' => format_decimal_signed(n, f),
        b'x' => format_uint(n as u64, 16, false, f),
        b'X' => format_uint(n as u64, 16, true, f),
        b'b' => format_uint(n as u64, 2, false, f),
        b'o' => format_uint(n as u64, 8, false, f),
        b'c' => format_rune_or_int(n as rune, b'c', f),
        b'q' => format_rune_or_int(n as rune, b'q', f),
        _ => format_decimal_signed(n, f),
    }
}

fn format_unsigned(n: u64, verb: byte, f: &mut FmtBuf) {
    match verb {
        b'd' | b'v' => format_uint(n, 10, false, f),
        b'x' => format_uint(n, 16, false, f),
        b'X' => format_uint(n, 16, true, f),
        b'b' => format_uint(n, 2, false, f),
        b'o' => format_uint(n, 8, false, f),
        b'c' => format_rune_or_int(n as rune, b'c', f),
        _ => format_uint(n, 10, false, f),
    }
}

fn format_decimal_signed(n: i64, f: &mut FmtBuf) {
    if n < 0 {
        f.push(b'-');
        // Handle i64::MIN safely via wrapping_neg + cast.
        let abs = (n as u64).wrapping_neg();
        format_uint(abs, 10, false, f);
    } else {
        format_uint(n as u64, 10, false, f);
    }
}

fn format_uint(mut n: u64, base: u64, upper: bool, f: &mut FmtBuf) {
    if n == 0 {
        f.push(b'0');
        return;
    }
    // 64 bits in base 2 needs 64 chars; safe upper bound.
    let mut buf = [0u8; 64];
    let mut i = 0;
    while n > 0 {
        let d = (n % base) as byte;
        buf[i] = hex_digit(d, upper);
        i += 1;
        n /= base;
    }
    while i > 0 {
        i -= 1;
        f.push(buf[i]);
    }
}

fn format_rune_or_int(r: rune, verb: byte, f: &mut FmtBuf) {
    match verb {
        b'c' => {
            let mut buf = [0u8; 4];
            let n = utf8::EncodeRune(&mut buf, r);
            f.extend(&buf[..n as usize]);
        }
        b'q' => {
            f.push(b'\'');
            let mut buf = [0u8; 4];
            let n = utf8::EncodeRune(&mut buf, r);
            f.extend(&buf[..n as usize]);
            f.push(b'\'');
        }
        _ => format_decimal_signed(r as i64, f),
    }
}

// ─── Format-string scanner ────────────────────────────────────────────

fn do_format(format: &[byte], args: &[FmtArg], f: &mut FmtBuf) -> Option<error> {
    // Returns the first error captured by %w (Errorf semantics).
    let mut wrap_target: Option<error> = None;
    let mut i = 0usize;
    let mut arg_idx = 0usize;
    while i < format.len() {
        let b = format[i];
        if b != b'%' {
            f.push(b);
            i += 1;
            continue;
        }
        i += 1;
        if i >= format.len() {
            f.push(b'%');
            break;
        }

        // Parse optional flags: '-' (left align), '0' (zero pad), '+'
        // (Go's "show field names" for %+v / "show sign" for numerics).
        let mut left_align = false;
        let mut zero_pad = false;
        let mut plus_flag = false;
        loop {
            if i >= format.len() {
                break;
            }
            match format[i] {
                b'-' => {
                    left_align = true;
                    i += 1;
                }
                b'0' => {
                    zero_pad = true;
                    i += 1;
                }
                b'+' => {
                    plus_flag = true;
                    i += 1;
                }
                _ => break,
            }
        }
        // Parse optional width digits.
        let mut width: usize = 0;
        let mut has_width = false;
        while i < format.len() && format[i] >= b'1' && format[i] <= b'9'
            || (i < format.len() && has_width && format[i] >= b'0' && format[i] <= b'9')
        {
            width = width * 10 + (format[i] - b'0') as usize;
            has_width = true;
            i += 1;
        }
        if i >= format.len() {
            // Trailing width without verb — emit raw.
            f.push(b'%');
            break;
        }
        let mut verb = format[i];
        i += 1;
        if verb == b'%' {
            f.push(b'%');
            continue;
        }
        // `%+v` is encoded as the synthetic verb 'V' so existing Format
        // impls don't need a flags channel. The reflect-driven printer
        // dispatches on 'v' vs 'V'.
        if plus_flag && verb == b'v' {
            verb = b'V';
        }
        // %w handling — substitute the wrapped error's text and capture
        // the first %w as the wrap target (Go's fmt.Errorf semantics).
        if verb == b'w' {
            if arg_idx < args.len() {
                if let Some(e) = args[arg_idx].as_error() {
                    if wrap_target.is_none() && *e != nil {
                        wrap_target = Some(e.clone());
                    }
                    let s = e.Error();
                    f.extend(s.as_bytes());
                } else {
                    // %w with a non-error arg — Go panics; we write an
                    // explanatory placeholder to make the bug visible.
                    f.extend(b"%!w(non-error)");
                }
                arg_idx += 1;
                continue;
            }
            f.extend(b"%!w(MISSING)");
            continue;
        }
        // Regular verb.
        if arg_idx < args.len() {
            if has_width {
                // Format into a temp buffer, then pad.
                let mut tmp = FmtBuf::new();
                args[arg_idx].write(verb, &mut tmp);
                let bytes = tmp.into_bytes();
                let pad_count = width.saturating_sub(bytes.len());
                let pad_byte = if zero_pad && !left_align {
                    // Zero-pad only for numeric verbs in Go; we apply
                    // it whenever requested for simplicity.
                    b'0'
                } else {
                    b' '
                };
                if !left_align {
                    for _ in 0..pad_count {
                        f.push(pad_byte);
                    }
                }
                f.extend(&bytes);
                if left_align {
                    for _ in 0..pad_count {
                        f.push(b' ');
                    }
                }
            } else {
                args[arg_idx].write(verb, f);
            }
            arg_idx += 1;
        } else {
            f.extend(b"%!");
            f.push(verb);
            f.extend(b"(MISSING)");
        }
    }
    wrap_target
}

// ─── reflect-driven %v / %+v printer ──────────────────────────────────
//
// Called by `#[goish::reflect]`-emitted `impl Format for T`. Walks the
// `reflect::Value` tree and emits Go-faithful default formatting:
//
//   bool      → true|false
//   int*/uint → decimal
//   float*    → shortest round-trip
//   string    → unquoted bytes (matches %v, not %q)
//   slice     → [v1 v2 v3]   (space-separated)
//   map       → map[k1:v1 k2:v2]   (BTreeMap-sorted keys)
//   struct    → {v1 v2 v3}    (or {Name:v1 Age:v2} when verb == 'V'
//                              for %+v)
//   pointer   → recurse into target
//   invalid   → <nil>

/// Format a `reflect::Value` into `f` using `verb` (`'v'` or `'V'`).
/// Public so `#[goish::reflect]`-generated `impl Format` bodies can
/// call it directly without round-tripping through ValueOf.
pub fn reflect_fmt_to<T: crate::reflect::Reflect + ?Sized>(
    v: &T,
    verb: byte,
    f: &mut FmtBuf,
) {
    let rv = crate::reflect::ValueOf(v);
    write_reflect_value(&rv, verb == b'V', f);
}

fn write_reflect_value(v: &crate::reflect::Value, plus: bool, f: &mut FmtBuf) {
    use crate::reflect::Kind as K;
    use crate::reflect::Value as RV;
    match v.Kind() {
        K::Invalid => f.extend(b"<nil>"),
        K::Bool => f.extend(if v.Bool() { b"true" } else { b"false" }),
        K::Int | K::Int8 | K::Int16 | K::Int32 => {
            format_signed(v.Int() as i64, b'd', f);
        }
        K::Uint | K::Uint8 | K::Uint16 | K::Uint32 => {
            format_unsigned(v.Uint() as u64, b'd', f);
        }
        K::Float32 | K::Float64 => {
            let s = crate::strconv::FormatFloat(v.Float(), b'g', -1, 64);
            f.extend(s.as_bytes());
        }
        K::String => f.extend(v.String().as_bytes()),
        K::Slice => {
            f.push(b'[');
            let n = v.Len();
            for i in 0..n {
                if i > 0 {
                    f.push(b' ');
                }
                write_reflect_value(&v.Index(i), plus, f);
            }
            f.push(b']');
        }
        K::Map => {
            f.extend(b"map[");
            let keys = v.MapKeys();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    f.push(b' ');
                }
                write_reflect_value(k, plus, f);
                f.push(b':');
                let val = v.MapIndex(k);
                write_reflect_value(&val, plus, f);
            }
            f.push(b']');
        }
        K::Struct => {
            f.push(b'{');
            let n = v.NumField();
            let ty = v.Type();
            for i in 0..n {
                if i > 0 {
                    f.push(b' ');
                }
                if plus {
                    f.extend(ty.Field(i).Name.as_bytes());
                    f.push(b':');
                }
                write_reflect_value(&v.Field(i), plus, f);
            }
            f.push(b'}');
        }
        K::Pointer => {
            if let RV::Pointer(inner) = v {
                write_reflect_value(inner, plus, f);
            }
        }
    }
}

// ─── Public entry points (called by macros) ───────────────────────────

#[doc(hidden)]
pub fn sprintf_impl(format: &[byte], args: &[FmtArg]) -> string {
    let mut f = FmtBuf::new();
    do_format(format, args, &mut f);
    string::__from_vec(f.into_bytes())
}

#[doc(hidden)]
pub fn fprintf_impl(w: &mut dyn io::Writer, format: &[byte], args: &[FmtArg]) -> (int, error) {
    let mut f = FmtBuf::new();
    do_format(format, args, &mut f);
    let buf = slice::__from_vec(f.into_bytes());
    w.Write(buf)
}

#[doc(hidden)]
pub fn printf_impl(format: &[byte], args: &[FmtArg]) -> (int, error) {
    let mut out = os::Stdout();
    fprintf_impl(&mut out, format, args)
}

/// `Println`-style join: args separated by spaces, terminated by newline.
fn do_println(args: &[FmtArg], f: &mut FmtBuf) {
    let mut first = true;
    for a in args {
        if !first {
            f.push(b' ');
        }
        first = false;
        a.write(b'v', f);
    }
    f.push(b'\n');
}

#[doc(hidden)]
pub fn println_impl(args: &[FmtArg]) -> (int, error) {
    let mut f = FmtBuf::new();
    do_println(args, &mut f);
    let mut out = os::Stdout();
    let buf = slice::__from_vec(f.into_bytes());
    out.Write(buf)
}

#[doc(hidden)]
pub fn fprintln_impl(w: &mut dyn io::Writer, args: &[FmtArg]) -> (int, error) {
    let mut f = FmtBuf::new();
    do_println(args, &mut f);
    let buf = slice::__from_vec(f.into_bytes());
    w.Write(buf)
}

#[doc(hidden)]
pub fn sprint_impl(args: &[FmtArg]) -> string {
    // Go: Sprint formats using the default formats for its operands and
    // returns the resulting string.  Spaces are added between operands
    // when neither is a string. (print.go:267)
    //
    // Slim: keep the same shape as print_impl — concat without inserting
    // spaces; the public Println/Print pair already differs from Go on
    // separator handling, and Sprint follows print_impl's lead for
    // consistency.
    let mut f = FmtBuf::new();
    for a in args {
        a.write(b'v', f.borrow_mut());
    }
    string::__from_vec(f.into_bytes())
}

#[doc(hidden)]
pub fn sprintln_impl(args: &[FmtArg]) -> string {
    // Go: Sprintln formats using the default formats for its operands and
    // returns the resulting string. Spaces are always added between
    // operands and a newline is appended. (print.go:283)
    let mut f = FmtBuf::new();
    do_println(args, &mut f);
    string::__from_vec(f.into_bytes())
}

#[doc(hidden)]
pub fn print_impl(args: &[FmtArg]) -> (int, error) {
    let mut f = FmtBuf::new();
    let mut first = true;
    for a in args {
        // Go's Print adds spaces between non-string args; we keep it
        // simple: always concat. Refine later if needed.
        let _ = first;
        first = false;
        a.write(b'v', f.borrow_mut());
    }
    let mut out = os::Stdout();
    let buf = slice::__from_vec(f.into_bytes());
    out.Write(buf)
}

// borrow_mut shim because FmtBuf isn't Cell-wrapped (one-pass writer);
// just expose &mut directly.
trait BorrowMutExt {
    fn borrow_mut(&mut self) -> &mut Self;
}
impl BorrowMutExt for FmtBuf {
    fn borrow_mut(&mut self) -> &mut Self {
        self
    }
}

#[doc(hidden)]
pub fn errorf_impl(format: &[byte], args: &[FmtArg]) -> error {
    let mut f = FmtBuf::new();
    let wrap = do_format(format, args, &mut f);
    let msg = string::__from_vec(f.into_bytes());
    match wrap {
        Some(inner) => errors::Wrap(WrappedErr { msg, inner }),
        None => errors::Wrap(SimpleErr { msg }),
    }
}

// Internal error types backing fmt::Errorf. SimpleErr just carries
// the formatted msg. WrappedErr also carries the %w target so
// errors::Is / Unwrap can walk to it.
struct SimpleErr {
    msg: string,
}
impl ErrorTrait for SimpleErr {
    fn Error(&self) -> string {
        self.msg.clone()
    }
}
struct WrappedErr {
    msg: string,
    inner: error,
}
impl ErrorTrait for WrappedErr {
    fn Error(&self) -> string {
        self.msg.clone()
    }
    fn Unwrap(&self) -> error {
        self.inner.clone()
    }
}

// ─── User-facing macros ───────────────────────────────────────────────

/// Helper: collect args into a `&[FmtArg]` literal via autoref-spec.
#[macro_export]
#[doc(hidden)]
macro_rules! __fmt_args {
    ($($arg:expr),* $(,)?) => {
        &[ $( {
            use $crate::fmt::__fmt_arg::*;
            (Wrap(&$arg)).fmt_arg()
        } ),* ]
    };
}

/// `fmt::Println!(args...)` — print args separated by spaces, newline appended.
#[macro_export]
macro_rules! Println {
    ($($arg:expr),* $(,)?) => {
        $crate::fmt::println_impl($crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Print!(args...)` — concatenate (no newline).
#[macro_export]
macro_rules! Print {
    ($($arg:expr),* $(,)?) => {
        $crate::fmt::print_impl($crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Printf!(format, args...)` — formatted print to stdout.
#[macro_export]
macro_rules! Printf {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {
        $crate::fmt::printf_impl(($fmt).as_bytes(), $crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Sprintf!(format, args...)` — return the formatted string.
#[macro_export]
macro_rules! Sprintf {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {
        $crate::fmt::sprintf_impl(($fmt).as_bytes(), $crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Sprint!(args...)` — return the concatenated default-format string.
/// Mirrors `fmt.Sprint` (print.go:267).
#[macro_export]
macro_rules! Sprint {
    ($($arg:expr),* $(,)?) => {
        $crate::fmt::sprint_impl($crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Sprintln!(args...)` — return the default-format string with
/// spaces between args and a trailing newline. Mirrors `fmt.Sprintln`
/// (print.go:283).
#[macro_export]
macro_rules! Sprintln {
    ($($arg:expr),* $(,)?) => {
        $crate::fmt::sprintln_impl($crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Fprintf!(w, format, args...)` — formatted print to writer.
#[macro_export]
macro_rules! Fprintf {
    ($w:expr, $fmt:expr $(, $arg:expr)* $(,)?) => {
        $crate::fmt::fprintf_impl(&mut $w, ($fmt).as_bytes(), $crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Fprintln!(w, args...)` — println on writer.
#[macro_export]
macro_rules! Fprintln {
    ($w:expr $(, $arg:expr)* $(,)?) => {
        $crate::fmt::fprintln_impl(&mut $w, $crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Eprintln!(args...)` — Println on stderr (goish convenience).
#[macro_export]
macro_rules! Eprintln {
    ($($arg:expr),* $(,)?) => {{
        let mut __e = $crate::os::Stderr();
        $crate::fmt::fprintln_impl(&mut __e, $crate::__fmt_args!($($arg),*))
    }};
}

/// `fmt::Errorf!(format, args...)` — like Sprintf but returns `error`,
/// with `%w` capturing an inner error for `errors::Is` / `Unwrap`.
#[macro_export]
macro_rules! Errorf {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {
        $crate::fmt::errorf_impl(($fmt).as_bytes(), $crate::__fmt_args!($($arg),*))
    };
}
