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
// Flags: width, precision (`%.3f`), '-' (left align), '0' (zero pad).
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
use crate::errors::nil;
use crate::os;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// ─── Public traits ─────────────────────────────────────────────────────

/// Go's `fmt.Stringer`. User types implement this to define their `%s`
/// / `%v` representation.
#[goish::interface]
pub trait Stringer {
    fn String(&self) -> string;
}

/// Go's `fmt.State` (fmt/print.go) — passed to `Formatter.Format`
/// implementations. Carries the underlying writer plus the parsed
/// width / precision / flags so a custom Format can render itself
/// according to the verb's modifiers.
///
/// Method shapes mirror Go: `Write([]byte) (int, error)`, `Width()
/// (int, bool)`, `Precision() (int, bool)`, `Flag(int) bool`.
///
/// The `int` arg to `Flag` is a flag character (`'+'`, `'-'`, `'#'`,
/// `' '`, `'0'`); Goish keeps the Go `int` widening so call sites
/// like `f.Flag(b'+' as int)` (or `f.Flag('+' as int)`) compile.
pub trait State: crate::io::Writer {
    fn Width(&self) -> (crate::types::int, bool);
    fn Precision(&self) -> (crate::types::int, bool);
    fn Flag(&self, c: crate::types::int) -> bool;
}

/// Go's `fmt.ScanState` interface — passed to types that implement
/// `Scanner` so they can drive their own parse over the input. Goish
/// stub matches the Go shape; a full impl is deferred until a port
/// actually reads input through this path. Surfaced by gopkg.in/
/// inf.v0's `Dec.Scan(s fmt.ScanState, ch rune) error`.
#[goish::interface]
pub trait ScanState {
    fn ReadRune(&mut self) -> (crate::types::rune, crate::types::int, crate::error);
    fn UnreadRune(&mut self) -> crate::error;
    fn SkipSpace(&mut self);
    fn Token(&mut self, skipSpace: bool, f: alloc::sync::Arc<dyn Fn(crate::types::rune) -> bool + Send + Sync>) -> (crate::slice<crate::types::byte>, crate::error);
    fn Width(&self) -> (crate::types::int, bool);
}

/// Go's `fmt.Scanner` interface — implemented by types that drive
/// their own scanning. The `state` arg is a `&mut dyn ScanState` and
/// `verb` is the format verb being scanned.
#[goish::interface]
pub trait Scanner {
    fn Scan(&mut self, state: &mut dyn ScanState, verb: crate::types::rune) -> crate::error;
}

/// Go's `fmt.Formatter` interface — implemented by types that want
/// custom verb-aware formatting (e.g. `multiError.Format(f, 'v')`
/// switches on the `+` flag for the `%+v` multi-line variant).
///
/// Goish's verb-formatting fast path checks for this trait via the
/// reflect-aware `%v` printer; types that don't impl Formatter fall
/// back to Stringer / Format / the default `%v` walker.
#[goish::interface]
pub trait Formatter {
    fn Format(&self, f: &mut dyn State, c: crate::types::rune);
}

/// Internal dispatch trait. Implemented for all builtin types in this
/// file. User types satisfy it via the blanket on `Stringer` below.
pub trait Format {
    fn fmt(&self, verb: byte, f: &mut FmtBuf);

    // go: none — goish idiom: Go's fmt carries width/precision/flags in
    // its `pp` printer state; goish's Format trait takes the verb byte
    // only, so precision arrives as an explicit parameter with a
    // default body that ignores it.
    /// Render with an explicit precision from the verb (`%.3f` → 3).
    ///
    /// `prec < 0` means the format string gave none, which is the
    /// shortest-round-trip default for floats and "no truncation" for
    /// strings. Defaulting to `fmt` keeps every existing impl correct
    /// without change: precision only means something for a handful of
    /// types, and the rest are entitled to ignore it — which is also
    /// what Go does, since `%.2d` is not a thing.
    fn fmt_prec(&self, verb: byte, _prec: i64, f: &mut FmtBuf) {
        self.fmt(verb, f);
    }
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
    pub(crate) fn as_slice(&self) -> &[byte] {
        &self.buf
    }
}

// ─── FmtArg — the autoref-spec dispatch envelope ──────────────────────

pub enum FmtArg<'a> {
    Val(&'a dyn Format),
    Err(&'a error),
}

impl<'a> FmtArg<'a> {
    // go: none — goish idiom: dispatch envelope for the autoref-spec
    // trick; no Go counterpart.
    fn write(&self, verb: byte, f: &mut FmtBuf) {
        self.write_prec(verb, -1, f);
    }

    // go: none — goish idiom: as `write`, threading the verb's
    // precision to the value.
    fn write_prec(&self, verb: byte, prec: i64, f: &mut FmtBuf) {
        match self {
            FmtArg::Val(v) => v.fmt_prec(verb, prec, f),
            FmtArg::Err(e) => {
                // %s / %v / default for an error → Error() text.
                // Go: nil error formats as "<nil>".
                if e.IsNil() {
                    write_string_with_verb(b"<nil>", verb, f);
                } else {
                    let s = e.Error();
                    write_string_with_verb(s.as_bytes(), verb, f);
                }
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

// `&string` arises from `range!(&slice<string>)` (Phase 4 borrowed-
// range): the iterator yields `(int, &string)` per element, and a
// downstream `fmt::Fprintf!("%s", line)` would then fail with E0599
// because the blanket `impl<T: Stringer> Format for T` doesn't cover
// references (Stringer isn't impl'd for `&string` either). Thread an
// explicit forwarder so the borrowed iteration value formats directly
// without a `.clone()` at the call site.
impl Format for &string {
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

// Same shape as `&string` — `range!(&slice<slice<byte>>)` yields
// `&slice<byte>` per iteration. Without this `Fprintf!("%s", b)` on
// the borrowed slot would fail E0599.
impl Format for &slice<byte> {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        write_string_with_verb(self, verb, f);
    }
}

impl Format for char {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        // %c / %v default to the character. %d would be the codepoint.
        let r = crate::rune(*self);
        format_rune_or_int(r, verb, f);
    }
}

// `Arc<dyn Any + Send + Sync>` — Goish's `interface{}` representation.
// xid's `fmt.Errorf("xid: scanning unsupported type: %T", value)` lands
// here when `value` is the type-switch scrutinee. v1 prints a
// placeholder; %T's full Go semantics (concrete type name) need
// runtime type-id lookup which is deferred per the module doc.
//
// This impl lets the call-site type-check; the user-visible string
// is "<any>" (or runs a downcast probe for known builtins). Future
// work registers a TypeId → name table populated by `goish::reflect`.
impl Format for alloc::sync::Arc<dyn core::any::Any + Send + Sync> {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        // %T on a raw `Arc<dyn Any>` (no AnyVal type-name slot): name the known
        // builtins, else "<any>". (`goish::Any` — the `interface{}` newtype most
        // code uses — carries the real concrete name; prefer that path.) Must
        // short-circuit before the value-formatting probes below.
        if verb == b'T' {
            let name = if self.is::<crate::gostring::string>() {
                "string"
            } else if self.is::<crate::goslice::slice<byte>>() {
                "[]uint8"
            } else if self.is::<i64>() {
                "int64"
            } else if self.is::<u64>() {
                "uint64"
            } else if self.is::<i32>() {
                "int32"
            } else if self.is::<u32>() {
                "uint32"
            } else if self.is::<bool>() {
                "bool"
            } else {
                "<any>"
            };
            f.extend(name.as_bytes());
            return;
        }
        // Probe a small set of common built-in concrete types so the
        // common Goish format calls produce something user-readable.
        // Falls back to "<any>" when the wrapped type isn't in the
        // probe list.
        if let Some(s) = self.downcast_ref::<crate::gostring::string>() {
            return s.fmt(verb, f);
        }
        if let Some(b) = self.downcast_ref::<crate::goslice::slice<byte>>() {
            return b.fmt(verb, f);
        }
        if let Some(n) = self.downcast_ref::<i64>() {
            return n.fmt(verb, f);
        }
        if let Some(n) = self.downcast_ref::<u64>() {
            return n.fmt(verb, f);
        }
        if let Some(n) = self.downcast_ref::<i32>() {
            return n.fmt(verb, f);
        }
        if let Some(n) = self.downcast_ref::<u32>() {
            return n.fmt(verb, f);
        }
        if let Some(b) = self.downcast_ref::<bool>() {
            return b.fmt(verb, f);
        }
        // Unknown concrete type — placeholder. %T should print the
        // type's Go name; we don't have a name table yet.
        let _ = verb;
        f.extend(b"<any>");
    }
}

// `goish::Any` (interface{} newtype) — runs the same downcast probe
// list as the raw-Arc impl above. We can't directly forward to the
// raw-Arc impl because `Any` now wraps `Arc<dyn AnyVal>` (with the
// dyn_eq slot) rather than `Arc<dyn core::any::Any + Send + Sync>`;
// the probe set is small, so inlining is cheaper than a shim trait.
impl Format for crate::goany::Any {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        // %T — Go's `fmt.Sprintf("%T", v)`: the wrapped value's concrete type
        // name, captured at wrap time (best-effort Rust path; see
        // `goany::AnyVal::__goish_type_name`). Must short-circuit BEFORE the
        // value-formatting probes below, which would otherwise print the value.
        if verb == b'T' {
            f.extend(self.TypeName().as_bytes());
            return;
        }
        let inner = self.as_any();
        if let Some(s) = inner.downcast_ref::<crate::gostring::string>() {
            return s.fmt(verb, f);
        }
        if let Some(b) = inner.downcast_ref::<crate::goslice::slice<byte>>() {
            return b.fmt(verb, f);
        }
        if let Some(n) = inner.downcast_ref::<i64>() {
            return n.fmt(verb, f);
        }
        if let Some(n) = inner.downcast_ref::<u64>() {
            return n.fmt(verb, f);
        }
        if let Some(n) = inner.downcast_ref::<i32>() {
            return n.fmt(verb, f);
        }
        if let Some(n) = inner.downcast_ref::<u32>() {
            return n.fmt(verb, f);
        }
        if let Some(b) = inner.downcast_ref::<bool>() {
            return b.fmt(verb, f);
        }
        let _ = verb;
        f.extend(b"<any>");
    }
}

// `Option<T>` — Goish's nullable carrier for some stdlib returns
// (notably `context::Context::Value`, which mirrors Go's `any` return
// with explicit absence). `None` prints as the Go-flavored "<nil>";
// `Some(v)` forwards to the inner Format. Coherence: Option<T> has no
// Stringer impl, so the `impl<T: Stringer> Format for T` blanket
// doesn't apply.
impl<T: Format> Format for Option<T> {
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        match self {
            Some(v) => v.fmt(verb, f),
            None => {
                let _ = verb;
                f.extend(b"<nil>");
            }
        }
    }
}

// `nilable_ref<'_, T>` / `nilable_refmut<'_, T>` — Goish's borrow-shaped
// `*T` wrappers. `nilable<T>` already inherits a `Stringer` impl from
// `#[goish::interface]`'s auto-forward (see goish-macros §6.6), but the
// borrow shapes don't, so wire them up here. `nil` prints as Go's
// `<nil>`; non-nil forwards `String()` to the inner `T: Stringer`.
// Routing through `Stringer` (not a direct `Format` impl) avoids
// overlap with the `impl<T: Stringer> Format for T` blanket above —
// `nilable_ref` / `nilable_refmut` are local types and coherence would
// reject a `Format`-bounded blanket on them.
impl<'a, T: ?Sized + Stringer> Stringer for crate::gonilable_ref::nilable_ref<'a, T> {
    fn String(&self) -> string {
        // `Try` consumes by-value (Copy via Option<&T>).
        match (*self).Try() {
            Some(t) => t.String(),
            None => string::from("<nil>"),
        }
    }
}

impl<'a, T: ?Sized + Stringer> Stringer for crate::gonilable_ref::nilable_refmut<'a, T> {
    fn String(&self) -> string {
        if self.IsNil() {
            string::from("<nil>")
        } else {
            self.Must().String()
        }
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

// Floats — route through strconv::FormatFloat.
//
// Go: "For floating-point values, width sets the minimum width of the
// field and precision sets the number of places after the decimal
// point, if appropriate. For example %6.2f prints 123.45. The default
// precision is the smallest number of digits necessary to represent the
// value uniquely" — i.e. FormatFloat's prec = -1. A verb that gives a
// precision passes it straight through.
impl Format for f64 {
    // go: none — goish idiom: no-precision form defers to fmt_prec.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        self.fmt_prec(verb, -1, f);
    }

    fn fmt_prec(&self, verb: byte, prec: i64, f: &mut FmtBuf) {
        let fmt = match verb {
            b'f' | b'F' => b'f',
            b'e' => b'e',
            b'E' => b'E',
            b'g' | b'v' => b'g',
            b'G' => b'G',
            b'x' => b'x',
            b'X' => b'X',
            b'b' => b'b',
            _ => b'g',
        };
        let s = crate::strconv::FormatFloat(*self, fmt, prec, 64);
        f.extend(s.as_bytes());
    }
}

impl Format for f32 {
    // go: none — goish idiom: no-precision form defers to fmt_prec.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        self.fmt_prec(verb, -1, f);
    }

    fn fmt_prec(&self, verb: byte, prec: i64, f: &mut FmtBuf) {
        let fmt = match verb {
            b'f' | b'F' => b'f',
            b'e' => b'e',
            b'E' => b'E',
            b'g' | b'v' => b'g',
            b'G' => b'G',
            b'x' => b'x',
            b'X' => b'X',
            b'b' => b'b',
            _ => b'g',
        };
        let s = crate::strconv::FormatFloat(*self as f64, fmt, prec, 32);
        f.extend(s.as_bytes());
    }
}

// `complex64` and `complex128` are aliases for `(f32, f32)` / `(f64, f64)`
// in goish v1 (no native complex arithmetic; the runtime models them as
// tuples so `reflect::Value::Complex()` and `Sprintf!("%v", complex)` in
// ports compile). Go formats `complex128(1+2i)` as `(1+2i)` for `%v`;
// we follow the same shape.
impl Format for (f64, f64) {
    fn fmt(&self, _verb: byte, f: &mut FmtBuf) {
        let re = crate::strconv::FormatFloat(self.0, b'g', -1, 64);
        let im = crate::strconv::FormatFloat(self.1, b'g', -1, 64);
        f.push(b'(');
        f.extend(re.as_bytes());
        if self.1 >= 0.0 {
            f.push(b'+');
        }
        f.extend(im.as_bytes());
        f.extend(b"i)");
    }
}

impl Format for (f32, f32) {
    fn fmt(&self, _verb: byte, f: &mut FmtBuf) {
        let re = crate::strconv::FormatFloat(self.0 as f64, b'g', -1, 32);
        let im = crate::strconv::FormatFloat(self.1 as f64, b'g', -1, 32);
        f.push(b'(');
        f.extend(re.as_bytes());
        if self.1 >= 0.0 {
            f.push(b'+');
        }
        f.extend(im.as_bytes());
        f.extend(b"i)");
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
        // Parse optional `.precision`. Go: "For floating-point values,
        // width sets the minimum width of the field and precision sets
        // the number of places after the decimal point, if appropriate.
        // For example %6.2f prints 123.45." A bare '.' means precision
        // zero, as in Go (`%.f` == `%.0f`).
        //
        // Before this existed the '.' and its digits were left in the
        // format string, so `%.2f` consumed the argument as `%` + junk
        // and emitted `3.141592f` — the default rendering with a
        // stray verb letter glued on. Anything using `%.2f` was
        // silently wrong, not just unformatted.
        let mut precision: usize = 0;
        let mut has_precision = false;
        if i < format.len() && format[i] == b'.' {
            i += 1;
            has_precision = true;
            while i < format.len() && format[i] >= b'0' && format[i] <= b'9' {
                precision = precision * 10 + (format[i] - b'0') as usize;
                i += 1;
            }
        }
        if i >= format.len() {
            // Trailing width/precision without verb — emit raw.
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
                    if wrap_target.is_none() && !e.IsNil() {
                        wrap_target = Some(e.clone());
                    }
                    // Go: nil error formats as "<nil>".
                    if e.IsNil() {
                        f.extend(b"<nil>");
                    } else {
                        let s = e.Error();
                        f.extend(s.as_bytes());
                    }
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
        let prec_arg: i64 = if has_precision { precision as i64 } else { -1 };
        if arg_idx < args.len() {
            if has_width {
                // Format into a temp buffer, then pad.
                let mut tmp = FmtBuf::new();
                args[arg_idx].write_prec(verb, prec_arg, &mut tmp);
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
                args[arg_idx].write_prec(verb, prec_arg, f);
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
            // Go's fmt.Sprintf("%v"/"%+v") sorts map keys deterministically
            // (since Go 1.12). Sort the goish reflect-MapKeys output by
            // formatted-key bytes so output matches Go semantics regardless
            // of gomap's randomized iteration order.
            let keys = v.MapKeys();
            let mut key_strs: alloc::vec::Vec<(usize, FmtBuf)> = keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    let mut buf = FmtBuf::new();
                    write_reflect_value(k, plus, &mut buf);
                    (i, buf)
                })
                .collect();
            key_strs.sort_by(|a, b| a.1.as_slice().cmp(b.1.as_slice()));
            for (n, (orig_idx, key_buf)) in key_strs.iter().enumerate() {
                if n > 0 {
                    f.push(b' ');
                }
                f.extend(key_buf.as_slice());
                f.push(b':');
                let val = v.MapIndex(&keys[*orig_idx as int]);
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
        K::Interface => {
            // The downcast already happened inside __reflect_value, so
            // a Kind::Interface that survives to here means an unknown
            // dynamic type. Render Go's customary placeholder.
            f.extend(b"<interface>");
        }
        K::Int64 | K::Uint64 | K::Uintptr | K::Func | K::Chan
        | K::UnsafePointer | K::Array | K::Complex64 | K::Complex128 => {
            // Fallback rendering for variants whose `__reflect_value`
            // doesn't yet produce a typed Value (placeholder for parity
            // with Go's reflect.Kind universe).
            f.extend(b"<");
            let s = v.Kind().String();
            f.extend(s.as_bytes());
            f.extend(b">");
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

/// Translate a `slice<Arc<dyn Any + ...>>` (the runtime shape of Go's
/// `args ...interface{}`) to the `&[FmtArg]` that `*_impl` consumes.
/// Each arg is downcast to a known formattable type; unsupported types
/// render as `"<unsupported %T>"`.
///
/// Shared by all `*v` (variadic-spread) entry points so adding a new
/// supported concrete type touches one place. The lifetime of the
/// returned `Vec<FmtArg>` is tied to `args` — callers must keep `args`
/// alive across the call. The placeholder string has `'static`
/// lifetime, which trivially outlives any caller's `'a`.
fn __any_args_to_fmtargs<'a>(
    args: &'a slice<crate::goany::Any>,
) -> Vec<FmtArg<'a>> {
    static PLACEHOLDER: &str = "<unsupported %T>";
    let mut fa: Vec<FmtArg<'a>> = Vec::with_capacity(args.Len() as usize);
    for a in args.iter() {
        let any: &(dyn core::any::Any + Send + Sync) = a.as_any();
        if let Some(v) = any.downcast_ref::<string>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<&str>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<i64>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<i32>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<isize>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<u64>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<u32>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<usize>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<f64>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<f32>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<bool>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<u8>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<char>() {
            fa.push(FmtArg::Val(v as &dyn Format));
        } else if let Some(v) = any.downcast_ref::<error>() {
            fa.push(FmtArg::Err(v));
        } else {
            fa.push(FmtArg::Val(&PLACEHOLDER as &dyn Format));
        }
    }
    fa
}

/// Runtime variadic-spread Sprintf — for the Go pattern
/// `fmt.Sprintf(format, args...)` where `args ...interface{}` becomes a
/// goish `slice<Arc<dyn Any + Send + Sync>>`. Each arg is runtime-
/// downcast to a known formattable type and dispatched as `FmtArg::Val`.
///
/// Supported concrete types: `string`, `&str`, `i64`/`i32`/`isize`,
/// `u64`/`u32`/`usize`, `f64`/`f32`, `bool`, `byte` (u8), `char`, `error`.
/// Unrecognised types render as `"<unsupported %T>"`.
pub fn Sprintv<S: Into<string>>(
    format: S,
    args: slice<crate::goany::Any>,
) -> string {
    let format = format.into();
    let fa = __any_args_to_fmtargs(&args);
    sprintf_impl(format.as_bytes(), &fa)
}

/// Runtime variadic-spread Errorf — `fmt.Errorf(format, args...)`.
pub fn Errorv<S: Into<string>>(
    format: S,
    args: slice<crate::goany::Any>,
) -> error {
    let format = format.into();
    let fa = __any_args_to_fmtargs(&args);
    errorf_impl(format.as_bytes(), &fa)
}

/// Runtime variadic-spread Printf — `fmt.Printf(format, args...)`.
pub fn Printv<S: Into<string>>(
    format: S,
    args: slice<crate::goany::Any>,
) -> (int, error) {
    let format = format.into();
    let fa = __any_args_to_fmtargs(&args);
    printf_impl(format.as_bytes(), &fa)
}

/// Runtime variadic-spread Fprintf — `fmt.Fprintf(w, format, args...)`.
pub fn Fprintv<W: io::Writer, S: Into<string>>(
    w: &mut W,
    format: S,
    args: slice<crate::goany::Any>,
) -> (int, error) {
    let format = format.into();
    let fa = __any_args_to_fmtargs(&args);
    fprintf_impl(w, format.as_bytes(), &fa)
}

/// `fmt.Sprint(args...)` as a function value — for sites that pass
/// fmt.Sprint as a function pointer (e.g.,
/// `formatter[reflect.TypeOf(time.Time{})] = fmt.Sprint`).
/// The macro `fmt::Sprint!` is still preferred for direct calls
/// because it captures static FmtArg types; this fn shape lifts the
/// variadic into a single slice<Any> arg for value-passing contexts.
pub fn Sprint(args: slice<crate::goany::Any>) -> string {
    let fa = __any_args_to_fmtargs(&args);
    sprint_impl(&fa)
}

/// `fmt.Sprintln(args...)` as a function value. See `Sprint` for
/// the macro-vs-fn dichotomy.
pub fn Sprintln(args: slice<crate::goany::Any>) -> string {
    let fa = __any_args_to_fmtargs(&args);
    sprintln_impl(&fa)
}

/// `fmt.Fprint(w, args...)` as a function value.
pub fn Fprint<W: io::Writer>(w: &mut W, args: slice<crate::goany::Any>) -> (int, error) {
    let fa = __any_args_to_fmtargs(&args);
    let mut f = FmtBuf::new();
    for a in &fa {
        a.write(b'v', f.borrow_mut());
    }
    let buf = slice::__from_vec(f.into_bytes());
    w.Write(buf)
}

/// `fmt.Fprintln(w, args...)` as a function value.
pub fn Fprintln<W: io::Writer>(w: &mut W, args: slice<crate::goany::Any>) -> (int, error) {
    let fa = __any_args_to_fmtargs(&args);
    fprintln_impl(w, &fa)
}

/// `fmt.Print(args...)` as a function value.
pub fn Print(args: slice<crate::goany::Any>) -> (int, error) {
    let fa = __any_args_to_fmtargs(&args);
    print_impl(&fa)
}

/// `fmt.Println(args...)` as a function value.
pub fn Println(args: slice<crate::goany::Any>) -> (int, error) {
    let fa = __any_args_to_fmtargs(&args);
    println_impl(&fa)
}

// ─── Sscanf ──────────────────────────────────────────────────────────
//
// Go's `fmt.Sscanf(input, format, args...)` scans values from `input`
// guided by `format` directives. v1 surfaces the limited subset that
// real ports exercise: a single scan target with a single directive
// (`%f`, `%d`, `%s`). The polymorphism is via the `ScanTarget` trait;
// each impl knows how to consume the trimmed input for its directive.
//
// The transpiler emits `&mut <target>` at call sites tagged with
// `Mutates: []int{2}` in stdlib_registry, so callers like
// `fmt.Sscanf(num, "%f", val)` lower to
// `fmt::Sscanf(num, string("%f"), &mut val)` — the receiver is borrowed
// mutably so the side effect on `val` is visible afterwards.

/// Anything that can be filled by `fmt::Sscanf` for a given directive
/// in `format`. The directive is the byte after `%` (e.g. `b'f'`).
pub trait ScanTarget {
    fn __scan_one(&mut self, input: &str, verb: u8) -> bool;
}

impl ScanTarget for crate::math::big::Rat {
    fn __scan_one(&mut self, input: &str, verb: u8) -> bool {
        match verb {
            b'f' | b'g' | b'e' | b'v' => {
                crate::math::big::parse_decimal_into_rat(input, self)
            }
            _ => false,
        }
    }
}

impl ScanTarget for int {
    fn __scan_one(&mut self, input: &str, verb: u8) -> bool {
        match verb {
            b'd' | b'v' => match input.trim().parse::<int>() {
                Ok(n) => { *self = n; true }
                Err(_) => false,
            },
            _ => false,
        }
    }
}

impl ScanTarget for f64 {
    fn __scan_one(&mut self, input: &str, verb: u8) -> bool {
        match verb {
            b'f' | b'g' | b'e' | b'v' => match input.trim().parse::<f64>() {
                Ok(n) => { *self = n; true }
                Err(_) => false,
            },
            _ => false,
        }
    }
}

impl ScanTarget for string {
    fn __scan_one(&mut self, input: &str, verb: u8) -> bool {
        match verb {
            b's' | b'v' => {
                *self = string::from(input.trim_start().split_whitespace().next().unwrap_or(""));
                true
            }
            _ => false,
        }
    }
}

/// `fmt.Sscanf(input, format, target)` — scan a single value from
/// `input` per the directive in `format`. Returns `(n, err)` where
/// `n` is 1 on success (matching Go's scanned-count contract) and
/// `err` is non-nil on parse failure or directive mismatch.
///
/// v1 limitation: only single-directive formats are supported. Real
/// Go's Sscanf walks multiple verbs over whitespace-separated tokens;
/// add multi-verb support when a port surfaces a real need.
pub fn Sscanf<S1, S2, T>(input: S1, format: S2, target: &mut T) -> (int, error)
where
    S1: Into<string>,
    S2: Into<string>,
    T: ScanTarget + ?Sized,
{
    let input = input.into();
    let format = format.into();
    let fb = format.as_bytes();
    // Find the `%X` directive. Skip any prefix-literal handling — Go
    // allows literal text in the format that must match the input;
    // v1 ports only exercise pure directive formats.
    let mut i = 0;
    while i < fb.len() && fb[i] != b'%' {
        i += 1;
    }
    if i + 1 >= fb.len() {
        return (0, errors::New(string::from(
            "fmt::Sscanf: format has no directive",
        )));
    }
    let verb = fb[i + 1];
    let s: &str = input.as_ref();
    if target.__scan_one(s, verb) {
        (1, crate::errors::nil.into())
    } else {
        (0, errors::New(string::from("fmt::Sscanf: parse error")))
    }
}

/// `fmt.Sscan(input, args...)` — placeholder, defaults to a single
/// `%v` directive. Provided for forward symmetry; not yet exercised.
pub fn Sscan<S, T>(input: S, target: &mut T) -> (int, error)
where
    S: Into<string>,
    T: ScanTarget + ?Sized,
{
    let input = input.into();
    let s: &str = input.as_ref();
    if target.__scan_one(s, b'v') {
        (1, crate::errors::nil.into())
    } else {
        (0, errors::New(string::from("fmt::Sscan: parse error")))
    }
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
    let out = os::Stdout();
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
    let out = os::Stdout();
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

// ─── Re-export macros under `fmt::` so callers write `fmt::Println!` ──
//
// `#[macro_export]` only registers macros at the crate root, but Go's
// idiom is `fmt.Println(...)` → `fmt::Println!(...)`. Re-exporting here
// makes the qualified path work: `use goish::fmt; fmt::Println!(…)`.
pub use crate::{
    Eprintln, Errorf, Fprintf, Fprintln, Print, Printf, Println, Sprint, Sprintf, Sprintln,
};
