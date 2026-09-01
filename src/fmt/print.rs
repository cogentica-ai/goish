// go: file fmt/print.go decls: Sprint, Sprintln, Fprint, Fprintln, Print, Println, pp.doPrint
//
// print.go — the Stringer/Formatter/State interfaces, the output
// buffer, the printer itself, and every Print/Sprint/Fprint entry
// point.

extern crate alloc;
#[allow(unused_imports)]
use alloc::vec::Vec;

#[allow(unused_imports)]
use crate::convert::{
    byte as tobyte, int as toint, int32 as toint32, int64 as toint64, uint as touint,
    uint32 as touint32, uint64 as touint64,
};
#[allow(unused_imports)]
use crate::errors::nil;
#[allow(unused_imports)]
use crate::errors::{self, error, ErrorTrait};
#[allow(unused_imports)]
use crate::goslice::slice;
#[allow(unused_imports)]
use crate::gostring::string;
#[allow(unused_imports)]
use crate::io;
#[allow(unused_imports)]
use crate::os;
#[allow(unused_imports)]
use crate::types::{byte, int, rune};
#[allow(unused_imports)]
use crate::unicode::utf8;

#[allow(unused_imports)]
use super::format::{
    format_decimal_signed, format_rune_or_int, format_signed, format_uint, format_unsigned,
    hex_digit, truncate_string, write_hex, write_quoted, write_string_with_verb,
};
#[allow(unused_imports)]
use super::*;

// ─── Public traits ─────────────────────────────────────────────────────

/// Go's `fmt.Stringer`. User types implement this to define their `%s`
/// / `%v` representation.
#[goish::interface]
pub trait Stringer {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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
// go: sdk 1.25.5 fmt/print.go:36-52 State
pub trait State: crate::io::Writer {
    // go: none — goish idiom: a method of Go's `State` interface; the
    //     interface itself carries the anchor. Go's implementation of
    //     it lives on `*pp`, which goish has no counterpart for.
    fn Width(&self) -> (crate::types::int, bool);
    // go: none — goish idiom: see the note on `Width`.
    fn Precision(&self) -> (crate::types::int, bool);
    // go: none — goish idiom: see the note on `Width`.
    fn Flag(&self, c: crate::types::int) -> bool;
}

/// Go's `fmt.ScanState` interface — passed to types that implement
/// `Scanner` so they can drive their own parse over the input. Goish
/// stub matches the Go shape; a full impl is deferred until a port
/// actually reads input through this path. Surfaced by gopkg.in/
/// inf.v0's `Dec.Scan(s fmt.ScanState, ch rune) error`.
#[goish::interface]
pub trait ScanState {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn ReadRune(&mut self) -> (crate::types::rune, crate::types::int, crate::error);
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn UnreadRune(&mut self) -> crate::error;
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn SkipSpace(&mut self);
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn Token(
        &mut self,
        skipSpace: bool,
        f: alloc::sync::Arc<dyn Fn(crate::types::rune) -> bool + Send + Sync>,
    ) -> (crate::slice<crate::types::byte>, crate::error);
    // go: none — goish idiom: a method of Go's `ScanState` interface;
    //     the interface itself carries the anchor.
    fn Width(&self) -> (crate::types::int, bool);
}

/// Go's `fmt.Scanner` interface — implemented by types that drive
/// their own scanning. The `state` arg is a `&mut dyn ScanState` and
/// `verb` is the format verb being scanned.
#[goish::interface]
pub trait Scanner {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn Format(&self, f: &mut dyn State, c: crate::types::rune);
}

/// Internal dispatch trait. Implemented for all builtin types in this
/// file. User types satisfy it via the blanket on `Stringer` below.
pub trait Format {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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
    // go: none — goish idiom: Go's `doPrint` asks
    //     `reflect.TypeOf(arg).Kind() == reflect.String` to decide
    //     whether to put a space between two operands. goish's printer
    //     has no reflect at that point, so the question is a trait
    //     method with a `false` default.
    fn __is_string(&self) -> bool {
        return false;
    }

    // go: none — goish idiom: Go's fmt carries width/precision/flags in
    //     its `pp` printer state; goish's `Format` trait takes the verb
    //     byte only, so precision arrives as an explicit parameter with a
    //     default body that ignores it.
    fn fmt_prec(&self, verb: byte, _prec: i64, f: &mut FmtBuf) {
        self.fmt(verb, f);
    }
}

// Blanket so any user type that impls Stringer is automatically
// formattable. Coherence: this doesn't conflict with the per-builtin
// impls below because none of our builtins impl Stringer (we hand-
// implement Format for them directly).
impl<T: Stringer + ?Sized> Format for T {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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
    // go: none — goish idiom: Go's `buffer` is a `[]byte` with methods, so its
    //     zero value needs no constructor.
    pub(crate) fn new() -> Self {
        return Self { buf: Vec::new() };
    }
    // go: none — goish idiom: Go's `(*buffer).writeByte` (print.go:111).
    pub fn push(&mut self, b: byte) {
        self.buf.push(b);
    }
    // go: none — goish idiom: Go's `(*buffer).write` (print.go:103).
    pub fn extend(&mut self, s: &[byte]) {
        self.buf.extend_from_slice(s);
    }
    // go: none — goish idiom: Go's `buffer` IS the byte slice, so there is nothing
    //     to unwrap.
    fn __into_vec(self) -> Vec<byte> {
        return self.buf;
    }
    // go: none — goish idiom: see the note on `__into_vec`.
    pub(crate) fn as_slice(&self) -> &[byte] {
        return &self.buf;
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
    // go: none — goish idiom: Go's `doPrint` reflects on the operand's
    //     kind; goish asks the value, through `Format::__is_string`.
    fn __is_string(&self) -> bool {
        return match self {
            FmtArg::Val(v) => v.__is_string(),
            FmtArg::Err(_) => false,
        };
    }

    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn as_error(&self) -> Option<&'a error> {
        return match self {
            FmtArg::Err(e) => Some(*e),
            _ => None,
        };
    }
}

#[doc(hidden)]
pub mod __fmt_arg {
    use super::*;
    pub struct Wrap<'a, T: ?Sized>(pub &'a T);

    impl<'a, T: ?Sized> Copy for Wrap<'a, T> {}
    impl<'a, T: ?Sized> Clone for Wrap<'a, T> {
        // go: none — goish idiom: goish's printer dispatches on the `Format` trait
        //     where Go's reflects over `any`, so the per-type rendering lives in
        //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
        fn clone(&self) -> Self {
            return *self;
        }
    }

    pub trait ViaError<'a> {
        // go: none — goish idiom: goish's printer dispatches on the `Format` trait
        //     where Go's reflects over `any`, so the per-type rendering lives in
        //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
        fn fmt_arg(self) -> FmtArg<'a>;
    }
    pub trait ViaFormat<'a> {
        // go: none — goish idiom: goish's printer dispatches on the `Format` trait
        //     where Go's reflects over `any`, so the per-type rendering lives in
        //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
        fn fmt_arg(self) -> FmtArg<'a>;
    }

    // Specific: error → FmtArg::Err. Tried first via 0-step autoref.
    impl<'a> ViaError<'a> for Wrap<'a, error> {
        // go: none — goish idiom: goish's printer dispatches on the `Format` trait
        //     where Go's reflects over `any`, so the per-type rendering lives in
        //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
        fn fmt_arg(self) -> FmtArg<'a> {
            return FmtArg::Err(self.0);
        }
    }

    // Generic: anything Format → FmtArg::Val. Reached via auto-ref.
    impl<'a, T: Format> ViaFormat<'a> for &Wrap<'a, T> {
        // go: none — goish idiom: goish's printer dispatches on the `Format` trait
        //     where Go's reflects over `any`, so the per-type rendering lives in
        //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
        fn fmt_arg(self) -> FmtArg<'a> {
            return FmtArg::Val(self.0);
        }
    }
}

// ─── Format impls for builtins ────────────────────────────────────────

impl Format for bool {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        let _ = verb; // %t / %v / %s all print true/false
        f.extend(if *self { b"true" } else { b"false" });
    }
}

impl Format for string {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        write_string_with_verb(self.as_bytes(), verb, f);
    }

    // go: none — goish idiom: Go asks reflect for the operand's kind;
    //     see the note on `Format::__is_string`.
    fn __is_string(&self) -> bool {
        return true;
    }

    // go: none — goish idiom: Go's `(*fmt).truncateString` (format.go:327)
    //     trims the INPUT to `prec` RUNES before the verb renders it, so
    //     `%.2q` of "abc" is `"ab"` quoted and `%.2x` is the hex of "ab".
    //     goish ignored precision for strings entirely: `%.1s` of "abc"
    //     came back "abc".
    fn fmt_prec(&self, verb: byte, prec: i64, f: &mut FmtBuf) {
        write_string_with_verb(truncate_string(self.as_bytes(), prec), verb, f);
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
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        write_string_with_verb(self.as_bytes(), verb, f);
    }

    // go: none — goish idiom: Go asks reflect for the operand's kind;
    //     see the note on `Format::__is_string`.
    fn __is_string(&self) -> bool {
        return true;
    }

    // go: none — goish idiom: Go's `(*fmt).truncateString` (format.go:327)
    //     trims the INPUT to `prec` RUNES before the verb renders it, so
    //     `%.2q` of "abc" is `"ab"` quoted and `%.2x` is the hex of "ab".
    //     goish ignored precision for strings entirely: `%.1s` of "abc"
    //     came back "abc".
    fn fmt_prec(&self, verb: byte, prec: i64, f: &mut FmtBuf) {
        write_string_with_verb(truncate_string(self.as_bytes(), prec), verb, f);
    }
}

impl Format for &str {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        write_string_with_verb(self.as_bytes(), verb, f);
    }
    // go: none — goish idiom: Go asks reflect for the operand's kind;
    //     see the note on `Format::__is_string`.
    fn __is_string(&self) -> bool {
        return true;
    }

    // go: none — goish idiom: Go's `(*fmt).truncateString` (format.go:327)
    //     trims the INPUT to `prec` RUNES before the verb renders it, so
    //     `%.2q` of "abc" is `"ab"` quoted and `%.2x` is the hex of "ab".
    //     goish ignored precision for strings entirely: `%.1s` of "abc"
    //     came back "abc".
    fn fmt_prec(&self, verb: byte, prec: i64, f: &mut FmtBuf) {
        write_string_with_verb(truncate_string(self.as_bytes(), prec), verb, f);
    }
}

impl Format for slice<byte> {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        // self: &slice<byte>; Deref<Target=[byte]> auto-coerces to &[byte].
        write_string_with_verb(self, verb, f);
    }
}

// Same shape as `&string` — `range!(&slice<slice<byte>>)` yields
// `&slice<byte>` per iteration. Without this `Fprintf!("%s", b)` on
// the borrowed slot would fail E0599.
impl Format for &slice<byte> {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        write_string_with_verb(self, verb, f);
    }
}

impl Format for char {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn String(&self) -> string {
        // `Try` consumes by-value (Copy via Option<&T>).
        return match (*self).Try() {
            Some(t) => t.String(),
            None => string::from("<nil>"),
        };
    }
}

impl<'a, T: ?Sized + Stringer> Stringer for crate::gonilable_ref::nilable_refmut<'a, T> {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn String(&self) -> string {
        return if self.IsNil() {
            string::from("<nil>")
        } else {
            self.Must().String()
        };
    }
}

// All integer widths route through one helper.
macro_rules! impl_format_for_signed {
    ($($t:ty),*) => { $( impl Format for $t {
        // go: none — goish idiom: goish's printer dispatches on the `Format` trait
        //     where Go's reflects over `any`, so the per-type rendering lives in
        //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
        fn fmt(&self, verb: byte, f: &mut FmtBuf) {
            format_signed(toint64(*self), verb, f);
        }
    } )* };
}
macro_rules! impl_format_for_unsigned {
    ($($t:ty),*) => { $( impl Format for $t {
        // go: none — goish idiom: goish's printer dispatches on the `Format` trait
        //     where Go's reflects over `any`, so the per-type rendering lives in
        //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
        fn fmt(&self, verb: byte, f: &mut FmtBuf) {
            format_unsigned(touint64(*self), verb, f);
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

    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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

    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
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
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        match verb {
            b'c' => f.push(*self),
            _ => format_unsigned(touint64(*self), verb, f),
        }
    }
}

// error itself impls Format — %s / %v render `.Error()` text. (FmtArg
// already handles error specially for %w; this is the fallback path
// when user code writes `&err as &dyn Format`.)
impl Format for error {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        if *self == nil {
            f.extend(b"<nil>");
            return;
        }
        let s = self.Error();
        write_string_with_verb(s.as_bytes(), verb, f);
    }
}

// ─── Format-string scanner ────────────────────────────────────────────

// go: none — goish idiom: Go's `(*pp).doPrintf` (print.go:1019) walks the
//     format string against a `[]any`; goish walks it against the
//     `&[FmtArg]` the macro built, so the signature has no counterpart.
//     The verb vocabulary and the flag handling below are Go's.
pub(crate) fn do_format(format: &[byte], args: &[FmtArg], f: &mut FmtBuf) -> Option<error> {
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
            // Go: `%` with nothing after it is `%!(NOVERB)`.
            f.extend(b"%!(NOVERB)");
            break;
        }

        // Parse optional flags: '-' (left align), '0' (zero pad), '+'
        // (Go's "show field names" for %+v / "show sign" for numerics).
        let mut left_align = false;
        let mut zero_pad = false;
        let mut plus_flag = false;
        let mut space_flag = false;
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
                b' ' => {
                    space_flag = true;
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
            // Trailing flags/width/precision with no verb.
            f.extend(b"%!(NOVERB)");
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
        // ...and `%+q` as 'Q', which is Go's ASCIIonly quoting.
        if plus_flag && verb == b'q' {
            verb = b'Q';
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
        let prec_arg: i64 = if has_precision {
            toint64(precision)
        } else {
            -1
        };
        if arg_idx < args.len() {
            // Render into a temp buffer whenever a flag or a width can
            // still change the result. Go's printer carries the flags
            // in `pp.fmt` and applies them as it writes; goish's
            // `Format` impls take only the verb, so the sign and the
            // padding are applied here, over the rendered bytes.
            let numeric = is_numeric_verb(verb);
            if has_width
                || ((plus_flag || space_flag) && numeric)
                || (has_precision && is_integer_verb(verb))
            {
                let mut tmp = FmtBuf::new();
                args[arg_idx].write_prec(verb, prec_arg, &mut tmp);
                let mut bytes = tmp.__into_vec();

                // Go: for the INTEGER verbs, precision is the minimum
                // number of digits — "%.5d" of 42 is "00042" — where
                // for the float verbs it is the number of places after
                // the point, which the value itself already applied.
                if has_precision && is_integer_verb(verb) {
                    let sign = if !bytes.is_empty() && (bytes[0] == b'-' || bytes[0] == b'+') {
                        1usize
                    } else {
                        0usize
                    };
                    let digits = bytes.len() - sign;
                    if digits < precision {
                        let mut padded: Vec<byte> = Vec::with_capacity(sign + precision);
                        padded.extend_from_slice(&bytes[..sign]);
                        for _ in 0..(precision - digits) {
                            padded.push(b'0');
                        }
                        padded.extend_from_slice(&bytes[sign..]);
                        bytes = padded;
                    }
                }

                // Go: the '+' flag always prints a sign for a numeric
                // verb; ' ' prints a space where '+' would print a
                // plus. '+' wins when both are given.
                if numeric && !bytes.is_empty() && bytes[0] != b'-' && bytes[0] != b'+' {
                    if plus_flag {
                        bytes.insert(0, b'+');
                    } else if space_flag {
                        bytes.insert(0, b' ');
                    }
                }

                let pad_count = width.saturating_sub(bytes.len());
                // Go zero-pads only for numeric verbs, and the zeros go
                // AFTER the sign — "%05d" of -42 is "-0042", not
                // "00-42".
                let zero = zero_pad && !left_align && numeric;
                if zero {
                    let mut k = 0usize;
                    if !bytes.is_empty()
                        && (bytes[0] == b'-' || bytes[0] == b'+' || bytes[0] == b' ')
                    {
                        f.push(bytes[0]);
                        k = 1;
                    }
                    for _ in 0..pad_count {
                        f.push(b'0');
                    }
                    f.extend(&bytes[k..]);
                } else {
                    if !left_align {
                        for _ in 0..pad_count {
                            f.push(b' ');
                        }
                    }
                    f.extend(&bytes);
                    if left_align {
                        for _ in 0..pad_count {
                            f.push(b' ');
                        }
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
    return wrap_target;
}

// go: none — goish idiom: Go asks its `fmt` flag struct whether the
//     verb it is about to print is one the sign and zero-padding flags
//     apply to; goish has no such struct, so the verb set is spelled
//     out.
fn is_numeric_verb(verb: byte) -> bool {
    return match verb {
        b'd' | b'b' | b'o' | b'x' | b'X' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G' => true,
        _ => false,
    };
}

// go: none — goish idiom: the subset of `is_numeric_verb` for which
//     precision means "minimum digits" rather than "places after the
//     point".
fn is_integer_verb(verb: byte) -> bool {
    return match verb {
        b'd' | b'b' | b'o' | b'x' | b'X' => true,
        _ => false,
    };
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

// go: none — goish idiom: the entry point a `#[derive(Reflect)]` type uses to
//     reach the reflect printer. Go's printer gets there through
//     `printArg`'s `reflect.ValueOf`.
/// Format a `reflect::Value` into `f` using `verb` (`'v'` or `'V'`).
/// Public so `#[goish::reflect]`-generated `impl Format` bodies can
/// call it directly without round-tripping through ValueOf.
pub fn reflect_fmt_to<T: crate::reflect::Reflect + ?Sized>(v: &T, verb: byte, f: &mut FmtBuf) {
    let rv = crate::reflect::ValueOf(v);
    write_reflect_value(&rv, verb == b'V', f);
}

// go: none — goish idiom: Go's `(*pp).printValue` (print.go:766) walks a
//     `reflect.Value`; goish's reflect exposes a `Value` enum instead of
//     a kind-plus-accessors interface, so the walk is a match on it.
fn write_reflect_value(v: &crate::reflect::Value, plus: bool, f: &mut FmtBuf) {
    use crate::reflect::Kind as K;
    use crate::reflect::Value as RV;
    match v.Kind() {
        K::Invalid => f.extend(b"<nil>"),
        K::Bool => f.extend(if v.Bool() { b"true" } else { b"false" }),
        K::Int | K::Int8 | K::Int16 | K::Int32 => {
            format_signed(toint64(v.Int()), b'd', f);
        }
        K::Uint | K::Uint8 | K::Uint16 | K::Uint32 => {
            format_unsigned(touint64(v.Uint()), b'd', f);
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
                let val = v.MapIndex(&keys[*orig_idx]);
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
        K::Int64
        | K::Uint64
        | K::Uintptr
        | K::Func
        | K::Chan
        | K::UnsafePointer
        | K::Array
        | K::Complex64
        | K::Complex128 => {
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

// go: none — goish idiom: goish's printer dispatches on the `Format` trait
//     where Go's reflects over `any`, so the per-type rendering lives in
//     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
#[doc(hidden)]
pub fn sprintf_impl(format: &[byte], args: &[FmtArg]) -> string {
    let mut f = FmtBuf::new();
    do_format(format, args, &mut f);
    return string::__from_vec(f.__into_vec());
}

// go: none — goish idiom: Go's variadic `...any` arrives as a `[]any` the
//     printer indexes directly. goish's runtime-variadic entry points
//     take a `slice<Any>` and have to re-wrap each element as a
//     `FmtArg` before the shared printer can use it.
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
fn __any_args_to_fmtargs<'a>(args: &'a slice<crate::goany::Any>) -> Vec<FmtArg<'a>> {
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
    return fa;
}

// go: none — goish idiom: Go's `Sprintf` is variadic, so one function serves
//     both call shapes. goish has two — the macro form, which resolves
//     each argument's type at compile time, and this one, for a
//     `slice<Any>` built at run time. `sprintf_impl` carries the anchor.
/// Runtime variadic-spread Sprintf — for the Go pattern
/// `fmt.Sprintf(format, args...)` where `args ...interface{}` becomes a
/// goish `slice<Arc<dyn Any + Send + Sync>>`. Each arg is runtime-
/// downcast to a known formattable type and dispatched as `FmtArg::Val`.
///
/// Supported concrete types: `string`, `&str`, `i64`/`i32`/`isize`,
/// `u64`/`u32`/`usize`, `f64`/`f32`, `bool`, `byte` (u8), `char`, `error`.
/// Unrecognised types render as `"<unsupported %T>"`.
pub fn Sprintv<S: Into<string>>(format: S, args: slice<crate::goany::Any>) -> string {
    let format = format.into();
    let fa = __any_args_to_fmtargs(&args);
    return sprintf_impl(format.as_bytes(), &fa);
}

// go: none — goish idiom: see the note on `Sprintv`.
/// Runtime variadic-spread Errorf — `fmt.Errorf(format, args...)`.
pub fn Errorv<S: Into<string>>(format: S, args: slice<crate::goany::Any>) -> error {
    let format = format.into();
    let fa = __any_args_to_fmtargs(&args);
    return errorf_impl(format.as_bytes(), &fa);
}

// go: none — goish idiom: see the note on `Sprintv`.
/// Runtime variadic-spread Printf — `fmt.Printf(format, args...)`.
pub fn Printv<S: Into<string>>(format: S, args: slice<crate::goany::Any>) -> (int, error) {
    let format = format.into();
    let fa = __any_args_to_fmtargs(&args);
    return printf_impl(format.as_bytes(), &fa);
}

// go: none — goish idiom: see the note on `Sprintv`.
/// Runtime variadic-spread Fprintf — `fmt.Fprintf(w, format, args...)`.
pub fn Fprintv<W: io::Writer, S: Into<string>>(
    w: &mut W,
    format: S,
    args: slice<crate::goany::Any>,
) -> (int, error) {
    let format = format.into();
    let fa = __any_args_to_fmtargs(&args);
    return fprintf_impl(w, format.as_bytes(), &fa);
}

// go: sdk 1.25.5 fmt/print.go:277-283 Sprint
/// `fmt.Sprint(args...)` as a function value — for sites that pass
/// fmt.Sprint as a function pointer (e.g.,
/// `formatter[reflect.TypeOf(time.Time{})] = fmt.Sprint`).
/// The macro `fmt::Sprint!` is still preferred for direct calls
/// because it captures static FmtArg types; this fn shape lifts the
/// variadic into a single slice<Any> arg for value-passing contexts.
pub fn Sprint(args: slice<crate::goany::Any>) -> string {
    let fa = __any_args_to_fmtargs(&args);
    return sprint_impl(&fa);
}

// go: sdk 1.25.5 fmt/print.go:319-325 Sprintln
/// `fmt.Sprintln(args...)` as a function value. See `Sprint` for
/// the macro-vs-fn dichotomy.
pub fn Sprintln(args: slice<crate::goany::Any>) -> string {
    let fa = __any_args_to_fmtargs(&args);
    return sprintln_impl(&fa);
}

// go: sdk 1.25.5 fmt/print.go:260-266 Fprint
/// `fmt.Fprint(w, args...)` as a function value.
pub fn Fprint<W: io::Writer>(w: &mut W, args: slice<crate::goany::Any>) -> (int, error) {
    let fa = __any_args_to_fmtargs(&args);
    let mut f = FmtBuf::new();
    for a in &fa {
        a.write(b'v', f.borrow_mut());
    }
    let buf = slice::__from_vec(f.__into_vec());
    return w.Write(buf);
}

// go: sdk 1.25.5 fmt/print.go:302-308 Fprintln
/// `fmt.Fprintln(w, args...)` as a function value.
pub fn Fprintln<W: io::Writer>(w: &mut W, args: slice<crate::goany::Any>) -> (int, error) {
    let fa = __any_args_to_fmtargs(&args);
    return fprintln_impl(w, &fa);
}

// go: sdk 1.25.5 fmt/print.go:271-273 Print
/// `fmt.Print(args...)` as a function value.
pub fn Print(args: slice<crate::goany::Any>) -> (int, error) {
    let fa = __any_args_to_fmtargs(&args);
    return print_impl(&fa);
}

// go: sdk 1.25.5 fmt/print.go:313-315 Println
/// `fmt.Println(args...)` as a function value.
pub fn Println(args: slice<crate::goany::Any>) -> (int, error) {
    let fa = __any_args_to_fmtargs(&args);
    return println_impl(&fa);
}

// go: none — goish idiom: goish's printer dispatches on the `Format` trait
//     where Go's reflects over `any`, so the per-type rendering lives in
//     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
#[doc(hidden)]
pub fn fprintf_impl(w: &mut dyn io::Writer, format: &[byte], args: &[FmtArg]) -> (int, error) {
    let mut f = FmtBuf::new();
    do_format(format, args, &mut f);
    let buf = slice::__from_vec(f.__into_vec());
    return w.Write(buf);
}

// go: none — goish idiom: goish's printer dispatches on the `Format` trait
//     where Go's reflects over `any`, so the per-type rendering lives in
//     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
#[doc(hidden)]
pub fn printf_impl(format: &[byte], args: &[FmtArg]) -> (int, error) {
    let mut out = os::Stdout();
    return fprintf_impl(&mut out, format, args);
}

// go: none — goish idiom: Go's `(*pp).doPrintln` (print.go:1215) over the
//     macro's `&[FmtArg]`.
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

// go: none — goish idiom: goish's printer dispatches on the `Format` trait
//     where Go's reflects over `any`, so the per-type rendering lives in
//     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
#[doc(hidden)]
pub fn println_impl(args: &[FmtArg]) -> (int, error) {
    let mut f = FmtBuf::new();
    do_println(args, &mut f);
    let out = os::Stdout();
    let buf = slice::__from_vec(f.__into_vec());
    return out.Write(buf);
}

// go: none — goish idiom: goish's printer dispatches on the `Format` trait
//     where Go's reflects over `any`, so the per-type rendering lives in
//     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
#[doc(hidden)]
pub fn fprintln_impl(w: &mut dyn io::Writer, args: &[FmtArg]) -> (int, error) {
    let mut f = FmtBuf::new();
    do_println(args, &mut f);
    let buf = slice::__from_vec(f.__into_vec());
    return w.Write(buf);
}

// go: none — goish idiom: goish's printer dispatches on the `Format` trait
//     where Go's reflects over `any`, so the per-type rendering lives in
//     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
#[doc(hidden)]
pub fn sprint_impl(args: &[FmtArg]) -> string {
    let mut f = FmtBuf::new();
    do_print(args, &mut f);
    return string::__from_vec(f.__into_vec());
}

// go: sdk 1.25.5 fmt/print.go:1198-1212 pp.doPrint
/// Go: "Spaces are added between operands when neither is a string."
/// goish concatenated unconditionally, so `Sprint(1, 2)` was "12" where
/// Go gives "1 2" — and `Sprint("a", 1)` was right by accident, because
/// that pair takes no space either way.
fn do_print(args: &[FmtArg], f: &mut FmtBuf) {
    let mut prev_string = false;
    let mut arg_num = 0usize;
    while arg_num < args.len() {
        let is_string = args[arg_num].__is_string();
        // Add a space between two non-string arguments.
        if arg_num > 0 && !is_string && !prev_string {
            f.push(b' ');
        }
        args[arg_num].write(b'v', f);
        prev_string = is_string;
        arg_num += 1;
    }
}

// go: none — goish idiom: goish's printer dispatches on the `Format` trait
//     where Go's reflects over `any`, so the per-type rendering lives in
//     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
#[doc(hidden)]
pub fn sprintln_impl(args: &[FmtArg]) -> string {
    // Go: Sprintln formats using the default formats for its operands and
    // returns the resulting string. Spaces are always added between
    // operands and a newline is appended. (print.go:283)
    let mut f = FmtBuf::new();
    do_println(args, &mut f);
    return string::__from_vec(f.__into_vec());
}

// go: none — goish idiom: goish's printer dispatches on the `Format` trait
//     where Go's reflects over `any`, so the per-type rendering lives in
//     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
#[doc(hidden)]
pub fn print_impl(args: &[FmtArg]) -> (int, error) {
    let mut f = FmtBuf::new();
    do_print(args, &mut f);
    let out = os::Stdout();
    let buf = slice::__from_vec(f.__into_vec());
    return out.Write(buf);
}

// borrow_mut shim because FmtBuf isn't Cell-wrapped (one-pass writer);
// just expose &mut directly.
trait BorrowMutExt {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn borrow_mut(&mut self) -> &mut Self;
}
impl BorrowMutExt for FmtBuf {
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn borrow_mut(&mut self) -> &mut Self {
        return self;
    }
}
