// go: file fmt/print.go decls: Sprint, Sprintln, Fprint, Fprintln, Print, Println, pp.doPrint, pp.badVerb, intFromArg
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
    hex_digit, truncate_string, write_hex, write_quoted, write_string_with_verb, SHARP,
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

// go: sdk 1.25.5 fmt/print.go:36-52 State
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

    // go: none — goish idiom: Go's printer carries the width in its `pp`
    //     state, so `printValue` applies it to each ELEMENT as it
    //     recurses into a compound value: `Printf("%8.3f", []float64{…})`
    //     is `[   1.500    2.500]`, not a padded `[1.500 2.500]`. goish's
    //     `Format` trait takes no width, so a compound announces itself
    //     here and pads its own elements; everything else returns false
    //     and is padded whole by the caller, which is what Go does for a
    //     scalar and for the string-like renderings of a byte slice.
    /// Render as a compound with `width` applied per element, returning
    /// true if this type is one. The default is false: not a compound.
    fn __fmt_elem_width(
        &self,
        _verb: byte,
        _prec: i64,
        _width: usize,
        _left: bool,
        _f: &mut FmtBuf,
    ) -> bool {
        return false;
    }

    // go: none — goish idiom: Go's printer reflects over the operand,
    //     so `%T` and the `%!verb(type=value)` marker both read the
    //     type's name straight off the value. goish's printer has no
    //     reflect at that point, so the name is a trait method.
    /// Go's `%T` — the type's Go name, e.g. "string", "int", "[]uint8".
    ///
    /// The empty string means "this type does not know its Go name",
    /// which switches BOTH `%T` and the bad-verb marker off for it:
    /// a wrong marker is worse than none.
    fn __go_type(&self) -> string {
        return string::from_static("");
    }

    // go: none — goish idiom: Go's `(*pp).badVerb` is reached from each
    //     `fmt*` method's `default:` arm — the verb table is spelled out
    //     once per kind there. goish's is spelled out once per kind
    //     here, for the same reason and with the same contents.
    /// Whether this type renders under `verb`. `false` produces Go's
    /// `%!verb(type=value)` marker instead of a rendering.
    ///
    /// The default is `true`, so a type that has not declared its verbs
    /// keeps rendering exactly as it did.
    fn __accepts(&self, _verb: byte) -> bool {
        return true;
    }

    // go: none — goish idiom: Go's `intFromArg` (print.go:294) type-
    //     asserts the operand to `int` and, failing that, reflects over
    //     it for any integer Kind. goish's printer has no reflect at
    //     that point, so the question is a trait method with a `None`
    //     default — "this type is not an integer", which is Go's
    //     `default:` arm.
    /// The operand as an integer, for `%*d` and `%.*f`, where the width
    /// or the precision comes from an ARGUMENT rather than from the
    /// format string.
    ///
    /// `None` means the operand is not an integer, which is Go's
    /// `%!(BADWIDTH)` / `%!(BADPREC)`.
    fn __as_fmt_int(&self) -> Option<i64> {
        return None;
    }
}

// go: sdk 1.25.5 fmt/print.go:381-400 pp.badVerb
// goishlint:ignore GOISH020 badVerb — Go's is a method on `*pp`, which
//     carries the verb, the writer and the argument in its own state;
//     goish has no `pp`, so the three arrive as parameters.
/// Go: "%!verb(type=value)" — what Go prints instead of a value when
/// the verb is one the type does not take.
///
/// goish had no such machinery anywhere in its printer. `%d` of a
/// string printed the string; `%s` of an int printed the int; `%z` of
/// anything printed the value. Every one of those is a bug in the
/// caller that Go makes visible in the output and goish made invisible.
fn bad_verb(v: &dyn Format, verb: byte, ty: &string, f: &mut FmtBuf) {
    f.extend(b"%!");
    // The marker names the verb the CALLER wrote, so the synthetic
    // stand-ins for `%+v` and `%+q` map back to their real letters.
    f.push(match verb {
        b'V' => b'v',
        b'Q' => b'q',
        other => other,
    });
    f.push(b'(');
    f.extend(ty.as_bytes());
    f.push(b'=');
    // Go: "p.printArg(arg, 'v')" — the marker carries the value's
    // ordinary rendering.
    v.fmt_prec(b'v', -1, f);
    f.push(b')');
}

// go: none — goish idiom: the three questions Go's `printArg` asks
//     before it renders anything — is the verb 'T', does the type take
//     this verb, and only then render. It lives in a free function
//     because the composite impls have to ask them too: Go's marker
//     appears per ELEMENT inside a slice or a map, which is where a
//     wrong verb over a `[]string` shows up.
// go: none — goish idiom: the verb sets Go spells out in each `fmt*`
//     method's switch, collected. `%T` is handled before the check, so
//     it is not in any of them; `%v` is in all of them.
//
//   string / []byte     v s q x X            (fmtString)
//   integers            v d b o O x X c q U  (fmtInteger)
//   floats              v b e E f F g G x X  (fmtFloat)
//   bool                v t                  (fmtBool)
//
// 'V' and 'Q' are goish's synthetic verbs for `%+v` and `%+q` — see the
// scanner — so wherever Go accepts 'v' or 'q', the synthetic stands in
// for it. Leaving them out marked every `%+v` of an int as a bad verb,
// which is how they came to be listed.
// go: none — goish idiom: see the table above.
fn verb_ok_string(verb: byte) -> bool {
    return matches!(verb, b'v' | b'V' | b's' | b'q' | b'Q' | b'x' | b'X');
}

// go: none — goish idiom: see the table above.
fn verb_ok_int(verb: byte) -> bool {
    return matches!(
        verb,
        b'v' | b'V' | b'd' | b'b' | b'o' | b'O' | b'x' | b'X' | b'c' | b'q' | b'Q' | b'U'
    );
}

// go: none — goish idiom: see the table above.
fn verb_ok_float(verb: byte) -> bool {
    return matches!(
        verb,
        b'v' | b'V' | b'b' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'x' | b'X'
    );
}

// go: none — goish idiom: see the table above.
fn verb_ok_bool(verb: byte) -> bool {
    return matches!(verb, b'v' | b'V' | b't');
}

// go: none — goish idiom: the three questions Go's `printArg` asks
//     before it renders anything — is the verb 'T', does the type take
//     this verb, and only then render. It lives in a free function
//     because the composite impls have to ask them too: Go's marker
//     appears per ELEMENT inside a slice or a map, which is where a
//     wrong verb over a `[]string` shows up.
pub(crate) fn fmt_one(v: &dyn Format, verb: byte, prec: i64, f: &mut FmtBuf) {
    let ty = v.__go_type();
    if ty.Len() > 0 {
        // Go: "case 'T': p.fmt.fmtS(reflect.TypeOf(arg).String())".
        if verb & !SHARP == b'T' {
            f.extend(ty.as_bytes());
            return;
        }
        if !v.__accepts(verb & !SHARP) {
            bad_verb(v, verb & !SHARP, &ty, f);
            return;
        }
    }
    v.fmt_prec(verb, prec, f);
}

// go: none — goish idiom: the verb list from Go's `handleMethods`
//     (fmt/print.go), which goish's trait dispatch has to apply by
//     hand at each type that is both a Stringer and a number.
//
/// Whether a type's `String()` serves this verb.
///
/// Go's `handleMethods` consults a Stringer for exactly `%v`, `%s`,
/// `%q`, `%x` and `%X`, and formats the underlying VALUE for every
/// other verb. So a `time.Duration` prints `1m30s` for %v and
/// 90000000000 for %d — and `316d333073` for %x, which is the hex of
/// "1m30s" rather than of the number, because %x is on this list.
///
/// A type that is both a Stringer and a number must apply this split
/// itself, because goish's printer dispatches on a trait rather than
/// reflecting: the blanket below sends every verb through the string,
/// which is right for a type with no numeric identity and wrong for
/// one that has it. `time::Duration`, `time::Month`, `time::Weekday`
/// and `fs::FileMode` are the four in this tree.
pub fn __stringer_serves(verb: byte) -> bool {
    return matches!(verb, b'v' | b's' | b'q' | b'x' | b'X');
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

    // go: none — goish idiom: the operand half of Go's `intFromArg`
    //     (print.go:294). Go asks the `any` for an `int`; goish asks
    //     the `Format` impl, and an `error` operand is never one.
    fn as_fmt_int(&self) -> Option<i64> {
        if let FmtArg::Val(v) = self {
            return v.__as_fmt_int();
        }
        return None;
    }

    // go: none — goish idiom: as `write`, threading the verb's
    // precision to the value.
    fn write_prec(&self, verb: byte, prec: i64, f: &mut FmtBuf) {
        match self {
            FmtArg::Val(v) => fmt_one(*v, verb, prec, f),
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
    // go: none — goish idiom: ask the operand whether it is a compound
    //     that wants the width applied to each ELEMENT. See
    //     `Format::__fmt_elem_width`.
    fn try_elem_width(
        &self,
        verb: byte,
        prec: i64,
        width: usize,
        left: bool,
        f: &mut FmtBuf,
    ) -> bool {
        let handled = match self {
            FmtArg::Val(v) => v.__fmt_elem_width(verb, prec, width, left, f),
            FmtArg::Err(_) => false,
        };
        return handled;
    }

    // go: none — goish idiom: Go's `doPrint` reflects on the operand's
    //     kind; goish asks the value, through `Format::__is_string`.
    fn __is_string(&self) -> bool {
        return match self {
            FmtArg::Val(v) => v.__is_string(),
            FmtArg::Err(_) => false,
        };
    }

    // go: none — goish idiom: whether the argument's type takes this
    //     verb, so the caller can skip the flag decorations it would
    //     otherwise wrap around a bad-verb marker.
    fn __accepts_verb(&self, verb: byte) -> bool {
        return match self {
            FmtArg::Val(v) => v.__go_type().Len() == 0 || v.__accepts(verb),
            FmtArg::Err(_) => true,
        };
    }

    // go: none — goish idiom: one entry of Go's `%!(EXTRA …)` list,
    //     which is `type=value` — or the value alone when the type is
    //     one goish cannot name.
    fn write_extra(&self, f: &mut FmtBuf) {
        if let FmtArg::Val(v) = self {
            let ty = v.__go_type();
            if ty.Len() > 0 {
                f.extend(ty.as_bytes());
                f.push(b'=');
            }
        }
        self.write_prec(b'v', -1, f);
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
    // go: none — goish idiom: see `Format::__go_type`.
    fn __go_type(&self) -> string {
        return string::from_static("bool");
    }
    // go: none — goish idiom: see `Format::__accepts`.
    fn __accepts(&self, verb: byte) -> bool {
        return verb_ok_bool(verb);
    }
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        let _ = verb; // %t / %v / %s all print true/false
        f.extend(if *self { b"true" } else { b"false" });
    }
}

impl Format for string {
    // go: none — goish idiom: see `Format::__go_type`.
    fn __go_type(&self) -> string {
        return string::from_static("string");
    }
    // go: none — goish idiom: see `Format::__accepts`.
    fn __accepts(&self, verb: byte) -> bool {
        return verb_ok_string(verb);
    }
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
    // go: none — goish idiom: see `Format::__go_type`.
    fn __go_type(&self) -> string {
        return string::from_static("string");
    }
    // go: none — goish idiom: see `Format::__accepts`.
    fn __accepts(&self, verb: byte) -> bool {
        return verb_ok_string(verb);
    }
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
    // go: none — goish idiom: see `Format::__go_type`.
    fn __go_type(&self) -> string {
        return string::from_static("string");
    }
    // go: none — goish idiom: see `Format::__accepts`.
    fn __accepts(&self, verb: byte) -> bool {
        return verb_ok_string(verb);
    }
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

// go: none — goish idiom: Go's printer reflects over the value and
//     reaches `fmtBytes`, which switches on the verb. goish dispatches
//     on the `Format` trait, so the same switch lives here.
//
//     `%v` and `%d` of a `[]byte` print the NUMBERS — Go's `printValue`
//     falls through to the integer case for both — and only `%s`, `%q`,
//     `%x` and `%X` treat the bytes as text. goish sent every verb to
//     the text path, so `fmt.Println(b)` on `[]byte("abc")` printed
//     "abc" where Go prints "[97 98 99]", and a byte slice that is not
//     valid UTF-8 printed replacement characters where Go prints a list
//     of numbers.
fn write_bytes_with_verb(b: &[byte], verb: byte, f: &mut FmtBuf) {
    // Go: `%s`, `%q`, `%x` and `%X` treat the bytes as text; EVERY
    // other verb — `%v` and `%d` included, but also `%b`, `%o`, `%c`,
    // `%U` and the float verbs — goes through `printValue`, which walks
    // the slice and lets each element's own table answer. That is why
    // `%e` of a []byte is "[%!e(uint8=97) …]" and not one marker.
    match verb & !SHARP {
        b's' | b'q' | b'Q' | b'x' | b'X' => write_string_with_verb(b, verb, f),
        _ => write_byte_list(b, verb, f),
    }
}

// go: none — goish idiom: the `[e e e]` rendering Go's `printValue`
//     produces for a slice or an array, with the verb applied to each
//     ELEMENT. An empty or nil slice is "[]" in Go, not "".
fn write_byte_list(b: &[byte], verb: byte, f: &mut FmtBuf) {
    write_byte_list_w(b, verb, 0, false, f);
}

// go: none — goish idiom: as `write_byte_list`, with a per-element width.
// Only the LIST rendering takes one: Go's `%x`, `%s` and `%q` over a byte
// slice produce a single string and are padded whole, which is why this
// is not reached from those paths.
fn write_byte_list_w(b: &[byte], verb: byte, width: usize, left: bool, f: &mut FmtBuf) {
    f.push(b'[');
    let mut i = 0usize;
    while i < b.len() {
        if i > 0 {
            f.push(b' ');
        }
        write_elem(&b[i], verb, -1, width, left, f);
        i += 1;
    }
    f.push(b']');
}

impl Format for slice<byte> {
    // go: none — goish idiom: see `Format::__go_type`. Go's name for a
    //     byte slice is `[]uint8`, not `[]byte` — `byte` is an alias.
    fn __go_type(&self) -> string {
        return string::from_static("[]uint8");
    }
    // go: none — goish idiom: a byte slice takes every verb: the four
    //     text ones directly, and the rest per element, where the
    //     element's own table decides.
    fn __accepts(&self, _verb: byte) -> bool {
        return true;
    }
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        // self: &slice<byte>; Deref<Target=[byte]> auto-coerces to &[byte].
        write_bytes_with_verb(self, verb, f);
    }

    // go: none — goish idiom: see `Format::__fmt_elem_width`. Only the
    // LIST verbs take a per-element width; `%s`, `%q`, `%x` and `%X`
    // render the slice as one string and are padded whole, exactly as
    // Go does.
    fn __fmt_elem_width(
        &self,
        verb: byte,
        _prec: i64,
        width: usize,
        left: bool,
        f: &mut FmtBuf,
    ) -> bool {
        match verb & !SHARP {
            b's' | b'q' | b'Q' | b'x' | b'X' => return false,
            _ => {}
        }
        write_byte_list_w(self, verb, width, left, f);
        return true;
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
        write_bytes_with_verb(self, verb, f);
    }
}

// go: none — goish idiom: Go's printer reflects over any value, so a
//     `[]string` or a `[][]int` needs no per-type support; goish's
//     dispatches on a trait, and `slice<T>` had an impl for exactly one
//     T — `byte`. Every other slice failed to compile at the CALL:
//     `fmt.Println(names)` on a `[]string`, which is about as ordinary
//     as Go gets, was a type error.
//
//     `ListElem` is what makes the generic impl possible at all.
//     `impl<T: Format> Format for slice<T>` would overlap the
//     `slice<byte>` impl above, and `[]byte` is genuinely special in
//     Go — `%s` renders it as text — so the two cannot be merged.
//     A type opts in by implementing this marker; `slice<byte>` opts in
//     too, which is what makes `[][]byte` render as `[[97 98]]` the way
//     Go does.
pub trait ListElem: Format {}

macro_rules! impl_list_elem {
    ($($t:ty),*) => { $( impl ListElem for $t {} )* };
}
impl_list_elem!(
    bool,
    string,
    &string,
    &str,
    char,
    i8,
    i16,
    i32,
    i64,
    isize,
    u16,
    u32,
    u64,
    usize,
    f32,
    f64,
    error,
    crate::goany::Any,
    slice<byte>,
    &slice<byte>
);
impl<T: ListElem> ListElem for slice<T> {}
impl<T: ListElem> ListElem for Option<T> {}

// go: none — goish idiom: Go's printer reflects over a map, sorts the
//     keys with `internal/fmtsort` and renders `map[k:v k:v]`. goish had
//     no impl at all, so `fmt.Println(m)` on any map was a type error.
//
//     Go sorts so that the output is deterministic — a map's iteration
//     order is randomised, and a printer that followed it would produce
//     a different string on every run. `K: Ord` is what makes that
//     possible here; a map whose key type has no ordering simply is not
//     printable, which is the same restriction goish already had (only
//     more of it).
impl<K, V> Format for crate::gomap::map<K, V>
where
    K: crate::gomap::GoHash + PartialEq + Ord + Clone + ListElem,
    V: Clone + ListElem,
{
    // go: none — goish idiom: see above.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        self.fmt_prec(verb, -1, f);
    }

    // go: none — goish idiom: see above.
    fn fmt_prec(&self, verb: byte, prec: i64, f: &mut FmtBuf) {
        let mut pairs: Vec<(K, V)> = Vec::with_capacity(self.Len() as usize);
        for (k, v) in self.__iter() {
            pairs.push((k.clone(), v.clone()));
        }
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        f.extend(b"map[");
        let mut i = 0usize;
        while i < pairs.len() {
            if i > 0 {
                f.push(b' ');
            }
            fmt_one(&pairs[i].0, verb, prec, f);
            f.push(b':');
            fmt_one(&pairs[i].1, verb, prec, f);
            i += 1;
        }
        f.push(b']');
    }

    // go: none — goish idiom: see `Format::__fmt_elem_width`. Go's
    // `printValue` recurses into a map's keys AND values, so a width
    // applies to each of them, not to the `map[…]` as a whole.
    fn __fmt_elem_width(
        &self,
        verb: byte,
        prec: i64,
        width: usize,
        left: bool,
        f: &mut FmtBuf,
    ) -> bool {
        let mut pairs: Vec<(K, V)> = Vec::with_capacity(self.Len() as usize);
        for (k, v) in self.__iter() {
            pairs.push((k.clone(), v.clone()));
        }
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        f.extend(b"map[");
        let mut i = 0usize;
        while i < pairs.len() {
            if i > 0 {
                f.push(b' ');
            }
            write_elem(&pairs[i].0, verb, prec, width, left, f);
            f.push(b':');
            write_elem(&pairs[i].1, verb, prec, width, left, f);
            i += 1;
        }
        f.push(b']');
        return true;
    }
}

impl<T: ListElem> Format for slice<T> {
    // go: none — goish idiom: see `ListElem` above.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        self.fmt_prec(verb, -1, f);
    }

    // go: none — goish idiom: Go's printer passes its flags down to
    //     each element, so `%.2f` over a `[]float64` applies the
    //     precision per element and not to the bracketed whole.
    fn fmt_prec(&self, verb: byte, prec: i64, f: &mut FmtBuf) {
        f.push(b'[');
        let mut i = 0usize;
        while i < self.len() {
            if i > 0 {
                f.push(b' ');
            }
            fmt_one(&self[i], verb, prec, f);
            i += 1;
        }
        f.push(b']');
    }

    // go: none — goish idiom: see `Format::__fmt_elem_width`.
    fn __fmt_elem_width(
        &self,
        verb: byte,
        prec: i64,
        width: usize,
        left: bool,
        f: &mut FmtBuf,
    ) -> bool {
        f.push(b'[');
        let mut i = 0usize;
        while i < self.len() {
            if i > 0 {
                f.push(b' ');
            }
            write_elem(&self[i], verb, prec, width, left, f);
            i += 1;
        }
        f.push(b']');
        return true;
    }
}

impl Format for char {
    // go: none — goish idiom: goish's Rust `char` stands in for a Go
    //     `rune`, which is an int32 — hence the name and the verb set.
    fn __go_type(&self) -> string {
        return string::from_static("int32");
    }
    // go: none — goish idiom: see `Format::__accepts`.
    fn __accepts(&self, verb: byte) -> bool {
        return verb_ok_int(verb);
    }
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
    ($($t:ty : $n:literal),*) => { $( impl Format for $t {
        // go: none — goish idiom: see `Format::__go_type`.
        fn __go_type(&self) -> string {
            return string::from_static($n);
        }
        // go: none — goish idiom: see `Format::__accepts`.
        fn __accepts(&self, verb: byte) -> bool {
            return verb_ok_int(verb);
        }
        // go: none — goish idiom: goish's printer dispatches on the `Format` trait
        //     where Go's reflects over `any`, so the per-type rendering lives in
        //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
        fn fmt(&self, verb: byte, f: &mut FmtBuf) {
            format_signed(toint64(*self), verb, f);
        }
        // go: none — goish idiom: see `Format::__as_fmt_int`.
        fn __as_fmt_int(&self) -> Option<i64> {
            return Some(toint64(*self));
        }
    } )* };
}
macro_rules! impl_format_for_unsigned {
    ($($t:ty : $n:literal),*) => { $( impl Format for $t {
        // go: none — goish idiom: see `Format::__go_type`.
        fn __go_type(&self) -> string {
            return string::from_static($n);
        }
        // go: none — goish idiom: see `Format::__accepts`.
        fn __accepts(&self, verb: byte) -> bool {
            return verb_ok_int(verb);
        }
        // go: none — goish idiom: goish's printer dispatches on the `Format` trait
        //     where Go's reflects over `any`, so the per-type rendering lives in
        //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
        fn fmt(&self, verb: byte, f: &mut FmtBuf) {
            format_unsigned(touint64(*self), verb, f);
        }
        // go: none — goish idiom: see `Format::__as_fmt_int`. Go's
        //     `intFromArg` takes an unsigned operand only when it fits
        //     an `int`, which is what the `try_into` says here.
        fn __as_fmt_int(&self) -> Option<i64> {
            return i64::try_from(touint64(*self)).ok();
        }
    } )* };
}
// The names are Go's. Note that several Go types share one Rust type —
// goish's `int` and `int64` are both `i64`, and `uint`, `uint64` and
// `uintptr` are all `u64` — so `%T` cannot tell them apart and prints
// the unqualified name, the one goish's own `int`/`uint` resolve to.
// A Go `int64` therefore reports "int". There is no information left in
// the value to do better with.
impl_format_for_signed!(i8: "int8", i16: "int16", i32: "int32", i64: "int", isize: "int");
impl_format_for_unsigned!(u16: "uint16", u32: "uint32", u64: "uint", usize: "uint");

// Floats — route through strconv::FormatFloat.
//

// go: none — goish idiom: the padding half of Go's `(*fmt).pad`, split
// out so a compound value can apply it to each element.
fn pad_runes(f: &mut FmtBuf, b: &[u8], width: usize, left: bool) {
    let padn = width.saturating_sub(rune_count(b));
    if !left {
        for _ in 0..padn {
            f.push(b' ');
        }
    }
    f.extend(b);
    if left {
        for _ in 0..padn {
            f.push(b' ');
        }
    }
}

// go: none — goish idiom: one element of a compound, padded to `width`.
// A nested compound pads its OWN elements and is not padded again, which
// is how Go's `printValue` recursion behaves: `%4d` over [][]int{{1},{2,3}}
// is `[[   1] [   2    3]]`.
pub(crate) fn write_elem(
    v: &dyn Format,
    verb: byte,
    prec: i64,
    width: usize,
    left: bool,
    f: &mut FmtBuf,
) {
    let mut tmp = FmtBuf::new();
    if v.__fmt_elem_width(verb, prec, width, left, &mut tmp) {
        let inner = tmp.__into_vec();
        f.extend(&inner);
        return;
    }
    fmt_one(v, verb, prec, &mut tmp);
    let mut bytes = tmp.__into_vec();
    // Go's `#` flag, and the `O` verb, put their base prefix on EACH
    // element too: `%O` of []byte("ab") is "[0o141 0o142]", not
    // "0o[141 142]". The prefix goes after the sign, exactly as the
    // scalar path below does it.
    // A bad-verb marker is not a number and takes no prefix: Go's
    // `%O` over a map[string]int gives `map[%!O(string=a):0o10]`, with
    // the prefix on the value and not on the key's marker.
    let is_marker = bytes.len() >= 2 && bytes[0] == b'%' && bytes[1] == b'!';
    if is_integer_verb(verb) && !is_marker {
        let sign = if !bytes.is_empty() && (bytes[0] == b'-' || bytes[0] == b'+') {
            1usize
        } else {
            0usize
        };
        let pre = alt_prefix(verb, &bytes[sign..]);
        if !pre.is_empty() {
            let mut with: Vec<byte> = Vec::with_capacity(bytes.len() + pre.len());
            with.extend_from_slice(&bytes[..sign]);
            with.extend_from_slice(pre);
            with.extend_from_slice(&bytes[sign..]);
            bytes = with;
        }
    }
    pad_runes(f, &bytes, width, left);
}

// go: none — goish idiom: Go's `(*fmt).pad` counts the
// field width with `utf8.RuneCount`. goish inlines the same count over
// `&[u8]` rather than calling `utf8::RuneCount`, which takes an
// `AsRef<[byte]>` and would have the fmt hot path build a `slice<byte>`
// for every padded field.
// Erroneous and short encodings count as one rune each, exactly as
// Go's does — which is what makes it safe on whatever bytes a verb
// happened to produce.
fn rune_count(b: &[u8]) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c < 0x80 {
            i += 1;
        } else {
            // Width of the encoding, or 1 for an invalid leading byte.
            let size = if c < 0xC0 {
                1
            } else if c < 0xE0 {
                2
            } else if c < 0xF0 {
                3
            } else {
                4
            };
            i += size;
        }
        n += 1;
    }
    return n;
}

// Go: "For floating-point values, width sets the minimum width of the
// field and precision sets the number of places after the decimal
// point, if appropriate. For example %6.2f prints 123.45. The default
// precision is the smallest number of digits necessary to represent the
// value uniquely" — i.e. FormatFloat's prec = -1. A verb that gives a
// precision passes it straight through.
impl Format for f64 {
    // go: none — goish idiom: see `Format::__go_type`.
    fn __go_type(&self) -> string {
        return string::from_static("float64");
    }
    // go: none — goish idiom: see `Format::__accepts`.
    fn __accepts(&self, verb: byte) -> bool {
        return verb_ok_float(verb);
    }
    // go: none — goish idiom: no-precision form defers to fmt_prec.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        self.fmt_prec(verb, -1, f);
    }

    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt_prec(&self, verb: byte, prec: i64, f: &mut FmtBuf) {
        let (fmt, prec) = float_verb(verb, prec);
        let s = crate::strconv::FormatFloat(*self, fmt, prec, 64);
        f.extend(s.as_bytes());
    }
}

// go: none — goish idiom: Go's `(*pp).fmtFloat` reads the default
//     precision off the verb — "prec := -1; switch verb { case 'v':
//     … case 'e','E','f','F': prec = 6 …" — before handing the value to
//     `strconv.AppendFloat`. goish passed -1 for every verb, so `%f` of
//     1.5 printed "1.5" where Go prints "1.500000" and `%e` of 0
//     printed "0e+00" where Go prints "0.000000e+00". Every
//     column-aligned numeric report a port produced was misaligned, and
//     nothing about the output looked wrong on its own.
//
//     `%v`, `%g` and `%G` keep -1: their default IS the shortest
//     round-trip. An explicit precision always wins.
fn float_verb(verb: byte, prec: i64) -> (byte, i64) {
    let fmt = match verb & !SHARP {
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
    if prec >= 0 {
        return (fmt, prec);
    }
    // Go: "%e, %E, %f, %F default to a precision of 6."
    return match verb & !SHARP {
        b'e' | b'E' | b'f' | b'F' => (fmt, 6),
        _ => (fmt, -1),
    };
}

impl Format for f32 {
    // go: none — goish idiom: see `Format::__go_type`.
    fn __go_type(&self) -> string {
        return string::from_static("float32");
    }
    // go: none — goish idiom: see `Format::__accepts`.
    fn __accepts(&self, verb: byte) -> bool {
        return verb_ok_float(verb);
    }
    // go: none — goish idiom: no-precision form defers to fmt_prec.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        self.fmt_prec(verb, -1, f);
    }

    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt_prec(&self, verb: byte, prec: i64, f: &mut FmtBuf) {
        let (fmt, prec) = float_verb(verb, prec);
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
    // go: none — goish idiom: see `Format::__go_type`.
    fn __go_type(&self) -> string {
        return string::from_static("uint8");
    }
    // go: none — goish idiom: see `Format::__accepts`.
    fn __accepts(&self, verb: byte) -> bool {
        return verb_ok_int(verb);
    }
    // go: none — goish idiom: goish's printer dispatches on the `Format` trait
    //     where Go's reflects over `any`, so the per-type rendering lives in
    //     a trait impl rather than in one of `(*pp)`'s `fmt*` methods.
    fn fmt(&self, verb: byte, f: &mut FmtBuf) {
        match verb {
            b'c' => f.push(*self),
            _ => format_unsigned(touint64(*self), verb, f),
        }
    }
    // go: none — goish idiom: see `Format::__as_fmt_int`.
    fn __as_fmt_int(&self) -> Option<i64> {
        return Some(toint64(*self));
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

// go: sdk 1.25.5 fmt/print.go:934-964 intFromArg
/// Go: "intFromArg gets the argNumth element of a. On return, isInt
/// reports whether the argument has integer type."
///
/// This is what `%*d` reads its WIDTH from. Two details of Go's that
/// are easy to drop: the operand is consumed whether or not it turns
/// out to be an integer — a `%!(BADWIDTH)` still moves on to the next
/// argument — and a magnitude past a million is refused outright, so a
/// bad value cannot ask the printer for a gigabyte of padding.
fn int_from_arg(args: &[FmtArg], arg_num: &mut usize) -> Option<i64> {
    if *arg_num >= args.len() {
        return None;
    }
    let num = args[*arg_num].as_fmt_int();
    *arg_num += 1;
    // Go: "func tooLarge(x int) bool { const max int = 1e6; return x >
    // max || x < -max }".
    if let Some(n) = num {
        if n > 1_000_000 || n < -1_000_000 {
            return None;
        }
    }
    return num;
}

// go: none — goish idiom: Go's `(*pp).doPrintf` (print.go:1019) walks the
//     format string against a `[]any`; goish walks it against the
//     `&[FmtArg]` the macro built, so the signature has no counterpart.
//     The verb vocabulary and the flag handling below are Go's.
pub(crate) fn do_format(
    format: &[byte],
    args: &[FmtArg],
    f: &mut FmtBuf,
) -> crate::goslice::slice<error> {
    // Returns EVERY error captured by %w, in format order. Go collects
    // them all (fmt/errors.go:19-52) and picks the result type by
    // count: one gives a `wrapError` with `Unwrap() error`, two or
    // more give a `wrapErrors` with `Unwrap() []error`. Returning only
    // the first — which this did — made `errors.Is` miss every target
    // after the first %w.
    let mut wrap_targets = crate::goslice::slice::<error>::new();
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
        let mut sharp_flag = false;
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
                // Go's "alternate format" flag. goish did not know it
                // was a flag at all, so `%#x` parsed '#' as the VERB:
                // the argument was consumed by a verb that means
                // nothing, and the real 'x' was copied out as a literal.
                // Every `%#x` in a port printed garbage.
                b'#' => {
                    sharp_flag = true;
                    i += 1;
                }
                _ => break,
            }
        }
        let mut width: usize = 0;
        let mut has_width = false;
        // Go: "if i < end && format[i] == '*' { … p.fmt.wid,
        // p.fmt.widPresent, argNum = intFromArg(a, argNum) … }" — the
        // width comes from an ARGUMENT.
        //
        // goish did not know `*` at all. It was not a flag, not a
        // width, not a precision, so it fell through to the VERB slot:
        // `%*d` of (6, 42) consumed the 6 as the operand, rendered it
        // under the meaningless verb `*`, and copied the `d` out as a
        // literal — printing "6d". The value it was asked to pad never
        // appeared, and neither did any padding.
        if i < format.len() && format[i] == b'*' {
            i += 1;
            match int_from_arg(args, &mut arg_idx) {
                Some(n) => {
                    has_width = true;
                    // Go: "We have a negative width, so take its value
                    // and ensure that the minus flag is set." The zero
                    // flag is dropped with it — "Do not pad with zeros
                    // to the right."
                    if n < 0 {
                        left_align = true;
                        zero_pad = false;
                        width = usize::try_from(-n).unwrap_or(0);
                    } else {
                        width = usize::try_from(n).unwrap_or(0);
                    }
                }
                None => {
                    f.extend(b"%!(BADWIDTH)");
                }
            }
        }
        // Parse optional width digits. Go's is the `else` arm of the
        // `*` test above, not a second chance after it, so `%*5d` reads
        // its width from the argument and leaves the `5` to be the
        // verb — the guard here is that `else`.
        if !has_width {
            while i < format.len() && format[i] >= b'1' && format[i] <= b'9'
                || (i < format.len() && has_width && format[i] >= b'0' && format[i] <= b'9')
            {
                width = width * 10 + (format[i] - b'0') as usize;
                has_width = true;
                i += 1;
            }
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
            // Go: "if i+1 < end && format[i+1] == '*'" — the precision
            // comes from an argument too.
            if i + 1 < format.len() && format[i + 1] == b'*' {
                i += 2;
                // Go: "if p.fmt.prec < 0 { p.fmt.prec = 0;
                // p.fmt.precPresent = false }", and an absent precision
                // then writes the BADPREC marker. So a NEGATIVE `*`
                // precision is not "no precision given" — the verb
                // falls back to its OWN default, which for `%f` is six
                // places: `%.*f` of (-1, 3.14159) is
                // "%!(BADPREC)3.141590", not "3.14159".
                match int_from_arg(args, &mut arg_idx) {
                    Some(n) if n >= 0 => {
                        has_precision = true;
                        precision = usize::try_from(n).unwrap_or(0);
                    }
                    _ => {
                        f.extend(b"%!(BADPREC)");
                    }
                }
            } else {
                i += 1;
                has_precision = true;
                while i < format.len() && format[i] >= b'0' && format[i] <= b'9' {
                    precision = precision * 10 + (format[i] - b'0') as usize;
                    i += 1;
                }
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
        // `#` rides in the high bit — see the note on `format::SHARP`.
        // Only `%#q` and `%#U` read it in the formatters; the integer
        // prefixes are applied below, where the width is known.
        if sharp_flag {
            verb |= SHARP;
        }
        // %w handling — substitute the wrapped error's text and capture
        // the first %w as the wrap target (Go's fmt.Errorf semantics).
        if verb == b'w' {
            if arg_idx < args.len() {
                if let Some(e) = args[arg_idx].as_error() {
                    if !e.IsNil() {
                        wrap_targets = crate::append!(wrap_targets, e.clone());
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
            // A '#' on an integer verb also needs the temp buffer: the
            // prefix goes between the sign and the digits, so the
            // rendered bytes have to be split apart first.
            let prefixed = is_integer_verb(verb) && !alt_prefix(verb, b"1").is_empty();
            if has_width
                || prefixed
                || ((plus_flag || space_flag) && numeric)
                || (has_precision && is_integer_verb(verb))
            {
                let mut tmp = FmtBuf::new();
                // Go's `printValue` carries the width down into a
                // compound and applies it to each ELEMENT; only a scalar
                // is padded whole. Ask the operand which it is.
                // A compound wants the element treatment when there is
                // a width to distribute OR a base prefix to repeat.
                let elem_padded = (has_width || prefixed)
                    && args[arg_idx].try_elem_width(verb, prec_arg, width, left_align, &mut tmp);
                if !elem_padded {
                    args[arg_idx].write_prec(verb, prec_arg, &mut tmp);
                }
                let mut bytes = tmp.__into_vec();
                if elem_padded {
                    // Already padded element by element — padding the
                    // bracketed whole again would be Go's answer to a
                    // different question.
                    f.extend(&bytes);
                    arg_idx += 1;
                    continue;
                }

                // Go: for the INTEGER verbs, precision is the minimum
                // number of digits — "%.5d" of 42 is "00042" — where
                // for the float verbs it is the number of places after
                // the point, which the value itself already applied.
                //
                // Go's `fmtInteger` also turns a zero-padding WIDTH into
                // exactly this digit precision — "else if f.zero &&
                // !f.minus && f.widPresent { prec = f.wid; if negative
                // || f.plus || f.space { prec-- } }" — which is why the
                // base prefix does not count toward it: `%#08x` of 255
                // is "0x000000ff", ten characters wide, not eight.
                let sign = if !bytes.is_empty() && (bytes[0] == b'-' || bytes[0] == b'+') {
                    1usize
                } else {
                    0usize
                };
                let int_verb = is_integer_verb(verb);
                let mut digit_prec = 0usize;
                if has_precision && int_verb {
                    digit_prec = precision;
                } else if int_verb && zero_pad && !left_align && has_width {
                    digit_prec = width;
                    if sign == 1 || plus_flag || space_flag {
                        digit_prec = digit_prec.saturating_sub(1);
                    }
                }
                if digit_prec > 0 {
                    let digits = bytes.len() - sign;
                    if digits < digit_prec {
                        let mut padded: Vec<byte> = Vec::with_capacity(sign + digit_prec);
                        padded.extend_from_slice(&bytes[..sign]);
                        for _ in 0..(digit_prec - digits) {
                            padded.push(b'0');
                        }
                        padded.extend_from_slice(&bytes[sign..]);
                        bytes = padded;
                    }
                }

                // The base prefix: after the sign, before the digits.
                // For a string or byte slice rendered by `%#x` the
                // "digits" are the hex pairs and an EMPTY value takes no
                // prefix — Go prints "" for `%#x` of "", not "0x".
                // A bad-verb marker is not a number: Go's `%O` of a
                // string is "%!O(string=ab)", with no "0o" in front of
                // it, because `badVerb` writes the marker instead of
                // ever reaching `fmtInteger`.
                let pfx = if args[arg_idx].__accepts_verb(verb & !SHARP) {
                    alt_prefix(verb, &bytes[sign..])
                } else {
                    b""
                };
                if !pfx.is_empty() && bytes.len() > sign {
                    let mut withpfx: Vec<byte> = Vec::with_capacity(bytes.len() + pfx.len());
                    withpfx.extend_from_slice(&bytes[..sign]);
                    withpfx.extend_from_slice(pfx);
                    withpfx.extend_from_slice(&bytes[sign..]);
                    bytes = withpfx;
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

                // Go's `(*fmt).pad`: `width := f.wid - utf8.RuneCount(b)`.
                // The field width is counted in RUNES, not bytes — so
                // "%-8s" of "日本語" pads by five, not by none. goish
                // subtracted the BYTE length, which silently produced
                // short fields for every non-ASCII value in every
                // padded column in the library.
                let pad_count = width.saturating_sub(rune_count(&bytes));
                // Go zero-pads only for numeric verbs, and the zeros go
                // AFTER the sign — "%05d" of -42 is "-0042", not
                // "00-42". For the INTEGER verbs the padding was just
                // done as a digit precision above, so this is the float
                // path only.
                let zero = zero_pad && !left_align && numeric && !is_integer_verb(verb);
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
            f.push(verb & !SHARP);
            f.extend(b"(MISSING)");
        }
    }
    // Go: doPrintf's tail, print.go:1185-1201 — "Check for extra
    // arguments unless the call accessed the arguments out of order,
    // in which case it's too expensive to detect if they've all been
    // used."
    //
    // goish dropped them silently, so `Sprintf("%d", 1, 2)` gave "1"
    // where Go gives "1%!(EXTRA int=2)" — the marker being the only
    // sign that an argument went nowhere.
    if arg_idx < args.len() {
        f.extend(b"%!(EXTRA ");
        let mut first = true;
        while arg_idx < args.len() {
            if !first {
                f.extend(b", ");
            }
            first = false;
            args[arg_idx].write_extra(f);
            arg_idx += 1;
        }
        f.push(b')');
    }
    return wrap_targets;
}

// go: none — goish idiom: Go asks its `fmt` flag struct whether the
//     verb it is about to print is one the sign and zero-padding flags
//     apply to; goish has no such struct, so the verb set is spelled
//     out.
fn is_numeric_verb(verb: byte) -> bool {
    return match verb & !SHARP {
        b'd' | b'b' | b'o' | b'O' | b'x' | b'X' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G' => true,
        _ => false,
    };
}

// go: none — goish idiom: the subset of `is_numeric_verb` for which
//     precision means "minimum digits" rather than "places after the
//     point".
fn is_integer_verb(verb: byte) -> bool {
    return match verb & !SHARP {
        b'd' | b'b' | b'o' | b'O' | b'x' | b'X' => true,
        _ => false,
    };
}

// go: none — goish idiom: Go's `fmtInteger` writes the base prefix into
//     its own buffer between the zero padding and the sign. goish's
//     `Format` impls render the digits and never see the width, so the
//     prefix is spliced in here instead. The bytes are Go's, from
//     format.go's `if f.sharp { switch base { … } }` plus the
//     unconditional "0o" the 'O' verb carries.
//
//     `%#o` is the odd one: its prefix is a single '0', and Go adds it
//     only when the first digit is not already a zero — which is why
//     `%#o` of 0 is "0" and not "00".
fn alt_prefix(verb: byte, digits: &[byte]) -> &'static [byte] {
    let sharp = verb & SHARP != 0;
    return match verb & !SHARP {
        b'b' if sharp => b"0b",
        b'x' if sharp => b"0x",
        b'X' if sharp => b"0X",
        b'o' if sharp => {
            if digits.first() == Some(&b'0') {
                b""
            } else {
                b"0"
            }
        }
        b'O' if sharp => {
            if digits.first() == Some(&b'0') {
                b"0o"
            } else {
                b"0o0"
            }
        }
        b'O' => b"0o",
        _ => b"",
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
