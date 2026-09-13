// go: file flag/flag.go decls: FlagSet.Uint64, Uint64, Arg, FlagSet.Func, FlagSet.BoolFunc, Func, BoolFunc, FlagSet.sprintf, FlagSet.failf, FlagSet.Int64, FlagSet.Uint, FlagSet.Duration, Parsed, Bool, Int, Int64, Uint, String, Duration, Parse, Set, FlagSet.Lookup, FlagSet.VisitAll, numError, UnquoteUsage, isZeroValue, FlagSet.Parse, FlagSet.parseOne, FlagSet.usage, FlagSet.NFlag, FlagSet.Visit, FlagSet.set, FlagSet.PrintDefaults, FlagSet.SetOutput, NewFlagSet, FlagSet.Name, FlagSet.ErrorHandling, FlagSet.Var, Var, FlagSet.TextVar, TextVar, textValue.String, textValue.Set
//
// flag — the package-level CommandLine set, and the flag types goish's
// hand-written FlagSet did not have.
//
// **Partial port.** The FlagSet itself, its parser and the rest of its
// surface are hand-written in mod[rs] and are not ports. This file
// holds what has been ported verbatim, kept separate because GOISH015
// forbids anchored code in a module root.
//
// goishlint:ignore GOISH018 Func, BoolFunc, Args, NArg, Arg, Usage, Init, Output, defaultUsage, sortFlags, newBoolValue, newIntValue, newInt64Value, newUintValue, newUint64Value, newStringValue, newFloat64Value, newDurationValue, newTextValue, newFuncValue, newBoolFuncValue, Get, IsBoolFlag, Float64, Uint64, BoolVar, IntVar, Int64Var, UintVar, Uint64Var, StringVar, Float64Var, DurationVar, failf, panicOnError, commandLineUsage, Error— the FlagSet parser is hand-written; these are the declarations of Go's flag.go that goish does not have. Twelve names that WERE on this list — Parse, parseOne, PrintDefaults, UnquoteUsage, isZeroValue, numError, usage, NFlag, Visit, Set, String, SetOutput — are ported AND anchored in this file, so the waiver was suppressing GOISH018 over declarations that exist. Re-checked 2026-09-06. Three MORE came off on 2026-09-13 — NewFlagSet, Name and ErrorHandling — when §2o gave NewFlagSet Go's two parameters; the waiver was again naming declarations that exist. And one MORE on the same day — Var — when §2p opened the kind enum. `IsBoolFlag` stays waived on purpose: Go declares it on a SEPARATE optional interface (`boolFlag`), and Rust has no optional-interface test on a `dyn`, so goish folds it into `Value` as a defaulted method. There is no separate declaration to anchor — only the behaviour, which flag_var_smoke pins. Three separate passes have now found this waiver naming things the file has; it is worth re-deriving rather than trusting. A fifth: TextVar, when §2p finished. `newTextValue` also went — Go needs it to reflect a pointer and copy a default; goish takes the value already holding its default, so there is nothing to construct.
// goishlint:ignore GOISH021 Getter, ErrorHandling, ContinueOnError, ExitOnError, PanicOnError, FlagSet, boolValue, intValue, int64Value, uintValue, uint64Value, stringValue, float64Value, durationValue, textValue, funcValue, boolFuncValue, errParse, errRange, ErrHelp, Usage, numError, boolFlag, commandLineUsage — same.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;

use crate::errors::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::runtime::spin::SpinLock;
use crate::types::int;

use alloc::vec::Vec;

use crate::errors::{self, nil};
use crate::strconv;
use crate::types::byte;

use super::{FlagDef, FlagHandle, FlagKind, FlagSet};

impl FlagSet {
    // go: sdk 1.25.5 flag/flag.go:812-816 FlagSet.Int64
    /// Go: "Int64 defines an int64 flag with specified name, default
    /// value, and usage string."
    pub fn Int64<N: Into<string>, U: Into<string>>(
        &mut self,
        name: N,
        default: crate::types::int64,
        usage: U,
    ) -> FlagHandle<crate::types::int64> {
        let cell = Arc::new(SpinLock::new(default));
        self.__define(name.into(), usage.into(), FlagKind::Int64(cell.clone()));
        return FlagHandle { cell };
    }

    // go: sdk 1.25.5 flag/flag.go:979-981 FlagSet.Func
    /// Go: "Func defines a flag with the specified name and usage
    /// string. Each time the flag is seen, fn is called with the value
    /// of the flag. If fn returns a non-nil error, it will be treated
    /// as a flag value parsing error."
    ///
    /// Go passes `func(string) error`; goish takes the same shape as a
    /// closure. There is no cell and no FlagHandle to return — the
    /// callback IS the storage, which is the point of this form.
    pub fn Func<N: Into<string>, U: Into<string>, F>(&mut self, name: N, usage: U, fn_: F)
    where
        F: Fn(string) -> error + Send + Sync + 'static,
    {
        let f: Arc<dyn Fn(string) -> error + Send + Sync> = Arc::new(fn_);
        self.__define(name.into(), usage.into(), FlagKind::Func(f));
    }

    // go: sdk 1.25.5 flag/flag.go:993-995 FlagSet.BoolFunc
    /// Go: "BoolFunc defines a flag with the specified name and usage
    /// string without requiring values." `-v` alone calls fn with
    /// "true"; `-v=false` calls it with "false".
    pub fn BoolFunc<N: Into<string>, U: Into<string>, F>(&mut self, name: N, usage: U, fn_: F)
    where
        F: Fn(string) -> error + Send + Sync + 'static,
    {
        let f: Arc<dyn Fn(string) -> error + Send + Sync> = Arc::new(fn_);
        self.__define(name.into(), usage.into(), FlagKind::BoolFunc(f));
    }

    // go: sdk 1.25.5 flag/flag.go:864-868 FlagSet.Uint64
    /// Go: "Uint64 defines a uint64 flag with specified name, default
    /// value, and usage string."
    ///
    /// Go returns `*uint64` — the address of the variable the flag
    /// writes into. goish returns the same thing in the shape it has:
    /// a FlagHandle over the cell the parser sets. That is why the
    /// `*Var` family has no counterpart here; the handle IS the
    /// pointer Go hands back.
    pub fn Uint64<N: Into<string>, U: Into<string>>(
        &mut self,
        name: N,
        default: crate::types::uint64,
        usage: U,
    ) -> FlagHandle<crate::types::uint64> {
        let cell = Arc::new(SpinLock::new(default));
        self.__define(name.into(), usage.into(), FlagKind::Uint64(cell.clone()));
        return FlagHandle { cell };
    }

    // go: sdk 1.25.5 flag/flag.go:838-842 FlagSet.Uint
    /// Go: "Uint defines a uint flag with specified name, default
    /// value, and usage string."
    pub fn Uint<N: Into<string>, U: Into<string>>(
        &mut self,
        name: N,
        default: crate::types::uint,
        usage: U,
    ) -> FlagHandle<crate::types::uint> {
        let cell = Arc::new(SpinLock::new(default));
        self.__define(name.into(), usage.into(), FlagKind::Uint(cell.clone()));
        return FlagHandle { cell };
    }

    // go: sdk 1.25.5 flag/flag.go:945-949 FlagSet.Duration
    /// Go: "Duration defines a time.Duration flag with specified name,
    /// default value, and usage string. The argument p points to a
    /// time.Duration variable in which to store the value of the flag."
    pub fn Duration<N: Into<string>, U: Into<string>>(
        &mut self,
        name: N,
        default: crate::time::Duration,
        usage: U,
    ) -> FlagHandle<crate::time::Duration> {
        let cell = Arc::new(SpinLock::new(default));
        self.__define(name.into(), usage.into(), FlagKind::Duration(cell.clone()));
        return FlagHandle { cell };
    }

    // go: sdk 1.25.5 flag/flag.go:1192-1194 Parsed
    /// Go: "Parsed reports whether f.Parse has been called."
    ///
    /// `testing` calls this to catch code that reads `Short()` or
    /// `Verbose()` from a TestMain that forgot to call flag.Parse.
    pub fn Parsed(&self) -> bool {
        return self.parsed;
    }
}

// go: sdk 1.25.5 flag/flag.go:375-375 ErrorHandling
/// Go: "ErrorHandling defines how [FlagSet.Parse] behaves if the parse
/// fails."
///
/// Go declares the type at flag.go line 375 and its three values in a
/// separate `const` block at lines 378-381; a Rust enum is one
/// declaration, so the anchor names the type and the values ride with
/// it. The discriminants are Go's, measured rather than assumed:
/// ContinueOnError=0, ExitOnError=1, PanicOnError=2.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ErrorHandling {
    /// Go: "Return a descriptive error."
    ContinueOnError = 0,
    /// Go: "Call os.Exit(2) or for -h/-help Exit(0)."
    ExitOnError = 1,
    /// Go: "Call panic with a descriptive error."
    PanicOnError = 2,
}

// go: sdk 1.25.5 flag/flag.go:1223-1232 NewFlagSet
/// Go: "NewFlagSet returns a new, empty flag set with the specified
/// name and error handling property. If the name is not empty, it will
/// be printed in the default usage message and in error messages."
///
/// Both parameters were missing. `errorHandling` is the behavioural
/// one — see `ErrorHandling` — and `name` is what `defaultUsage`
/// prints, so an unnamed set was the only kind goish could make.
pub fn NewFlagSet<N: Into<string>>(name: N, errorHandling: ErrorHandling) -> FlagSet {
    return FlagSet {
        defs: alloc::vec::Vec::new(),
        args: alloc::vec::Vec::new(),
        parsed: false,
        name: Some(name.into()),
        errorHandling: errorHandling,
        output: None,
    };
}

// go: none — goish-only: `CommandLine` is a `static`, so it needs a
//     const initialiser, and `NewFlagSet` cannot be one — Go itself
//     only learns the name from `os.Args[0]` at package init.
/// The empty set behind `CommandLine`: ExitOnError, as Go's is. The
/// name is filled in by the package-level `Parse`, which is the first
/// moment goish knows it and still before any usage line can print.
pub(crate) const fn command_line_set() -> FlagSet {
    return FlagSet {
        defs: alloc::vec::Vec::new(),
        args: alloc::vec::Vec::new(),
        parsed: false,
        name: None,
        errorHandling: ErrorHandling::ExitOnError,
        output: None,
    };
}

impl FlagSet {
    // go: sdk 1.25.5 flag/flag.go:1050-1054 FlagSet.sprintf
    /// Go: "sprintf formats the message, prints it to output, and
    /// returns it." The printing is not incidental — every definition
    /// panic below is preceded by the same text on Output, so a user
    /// sees it even if the panic is recovered.
    pub(crate) fn __sprintf(&self, msg: string) -> string {
        let mut line: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        line.extend_from_slice(msg.as_bytes());
        line.push(b'\n');
        self.__write_output(line);
        return msg;
    }

    // go: none — goish-only: in Go EVERY definer routes through `Var`,
    //     so all of them inherit its three panics. goish's ten definers
    //     each pushed onto `defs` directly and validated nothing, so
    //     `flag.Bool("-x", …)` and a duplicate name both succeeded
    //     silently where Go panics. This is the shared path they now
    //     take. See ROADMAP §2p.
    /// Register one flag, with Go's definition-time checks.
    ///
    /// Measured against Go 1.25.5 — the messages are verbatim, and each
    /// is written to Output before the panic, as `sprintf` does:
    ///
    ///     flag "-x" begins with -
    ///     flag "a=b" contains =
    ///     prog flag redefined: dup      (named set)
    ///     flag redefined: dup           (unnamed set)
    pub(crate) fn __define(&mut self, name: string, usage: string, kind: FlagKind) {
        let n: &str = name.as_ref();
        if n.starts_with('-') {
            let m = string::from_static("flag \"") + name.clone()
                + string::from_static("\" begins with -");
            let m = self.__sprintf(m);
            panic!("{}", m.as_ref() as &str);
        }
        if n.contains('=') {
            let m = string::from_static("flag \"") + name.clone()
                + string::from_static("\" contains =");
            let m = self.__sprintf(m);
            panic!("{}", m.as_ref() as &str);
        }
        if self.find_def(&name).is_some() {
            // Go prefixes the set's name when it has one.
            let m = match &self.name {
                Some(sn) if sn.Len() > 0 => {
                    sn.clone() + string::from_static(" flag redefined: ") + name.clone()
                }
                _ => string::from_static("flag redefined: ") + name.clone(),
            };
            let m = self.__sprintf(m);
            panic!("{}", m.as_ref() as &str);
        }
        let defvalue = __defstr(&kind);
        self.defs.push(FlagDef {
            name: name,
            usage: usage,
            kind: kind,
            defvalue: defvalue,
            actual: false,
        });
    }
}

// go: none — goish-only: Go's `Var` takes a POINTER the caller already
//     holds (`var v MyType; flag.Var(&v, …)`) and keeps using. Rust
//     ownership does not allow that: the value moves into the FlagSet.
//     So `Var` hands a handle back, which is the same shape every other
//     goish definer already uses (`FlagHandle<T>`).
/// A live handle on a flag defined with [`FlagSet::Var`]. Lock it to
/// read or inspect the caller's own value after `Parse`.
pub type ValueHandle = alloc::sync::Arc<crate::runtime::spin::SpinLock<alloc::boxed::Box<dyn Value>>>;

impl FlagSet {
    // go: sdk 1.25.5 flag/flag.go:1010-1043 FlagSet.Var
    /// Go: "Var defines a flag with the specified name and usage
    /// string. The type and value of the flag are represented by the
    /// first argument, of type [Value], which typically holds a
    /// user-defined implementation of [Value]."
    ///
    /// This is the package's extension point, and goish had no
    /// counterpart: every flag was one arm of a CLOSED enum, so a
    /// caller could not add a type of their own. See ROADMAP §2p.
    ///
    /// Go panics on a name that begins with `-`, contains `=`, or is
    /// already defined. Those checks live in `Var` there because every
    /// other definer routes through it; here they live in `__define`,
    /// which every definer takes.
    pub fn Var<N: Into<string>, U: Into<string>>(
        &mut self,
        value: alloc::boxed::Box<dyn Value>,
        name: N,
        usage: U,
    ) -> ValueHandle {
        let cell: ValueHandle =
            alloc::sync::Arc::new(crate::runtime::spin::SpinLock::new(value));
        // Go's three checks live in `Var` because every other definer
        // routes through it; goish's live in `__define`, which every
        // definer now takes.
        self.__define(name.into(), usage.into(), FlagKind::Custom(cell.clone()));
        return cell;
    }
}

// go: none — goish-only: Go's `textValue` wraps a POINTER and reads it
//     back through reflection. goish shares an `Arc<SpinLock<T>>` with
//     the caller instead, so the caller keeps a typed handle on their
//     own value rather than a `dyn Value` they cannot downcast.
/// A live, TYPED handle on a flag defined with [`FlagSet::TextVar`].
pub type TextHandle<T> = alloc::sync::Arc<crate::runtime::spin::SpinLock<T>>;

// go: sdk 1.25.5 flag/flag.go:299-299 textValue
/// Go's `textValue` — the `flag.Value` adapter over an
/// `encoding.TextUnmarshaler`.
struct textValue<T> {
    p: TextHandle<T>,
}

impl<T> Value for textValue<T>
where
    T: crate::encoding::TextMarshaler + crate::encoding::TextUnmarshaler + Send + Sync,
{
    // go: sdk 1.25.5 flag/flag.go:325-332 textValue.String
    /// Go: marshals, and returns "" if the type does not marshal or the
    /// marshal fails. goish's bound makes the first half unreachable —
    /// a `T` that cannot marshal will not compile — but the error half
    /// is real and behaves the same.
    fn String(&self) -> string {
        let (b, err) = self.p.lock().MarshalText();
        if err != crate::errors::nil {
            return string::new();
        }
        return string::from_bytes(b.as_ref());
    }

    // go: sdk 1.25.5 flag/flag.go:317-319 textValue.Set
    /// Go: `return v.p.UnmarshalText([]byte(s))` — the caller's own
    /// parser, and its error verbatim.
    fn Set(&mut self, s: string) -> error {
        let bytes = crate::convert::bytes(s);
        return self.p.lock().UnmarshalText(bytes);
    }
}

impl FlagSet {
    // go: sdk 1.25.5 flag/flag.go:963-965 FlagSet.TextVar
    /// Go: "TextVar defines a flag with a specified name, default value,
    /// and usage string. The argument p must be a pointer to a variable
    /// that will hold the value of the flag, and p must implement
    /// encoding.TextUnmarshaler."
    ///
    /// TWO OF GO'S FOUR PARAMETERS ARE GONE, and both for the same
    /// reason: they exist to police at runtime what Rust settles at
    /// compile time.
    ///
    /// Go takes a separate `value` default and copies it into `*p` by
    /// reflection, panicking if the two types differ
    /// ("default type does not match variable type") or if `p` is not a
    /// pointer ("variable value type must be a pointer"). goish's
    /// caller passes a `T` that already holds its default, and a type
    /// mismatch is a compile error — so there is nothing left to check
    /// and nothing to copy.
    ///
    /// Like [`FlagSet::Var`], the value moves in and a handle comes
    /// back; here it is TYPED, so the caller reads their own `T` rather
    /// than the text form.
    pub fn TextVar<T, N: Into<string>, U: Into<string>>(
        &mut self,
        p: T,
        name: N,
        usage: U,
    ) -> TextHandle<T>
    where
        T: crate::encoding::TextMarshaler + crate::encoding::TextUnmarshaler + Send + Sync + 'static,
    {
        let cell: TextHandle<T> = alloc::sync::Arc::new(crate::runtime::spin::SpinLock::new(p));
        let adapter = textValue { p: cell.clone() };
        let _ = self.Var(alloc::boxed::Box::new(adapter), name, usage);
        return cell;
    }
}

// go: sdk 1.25.5 flag/flag.go:972-974 TextVar
/// Go: "TextVar defines a flag with a specified name, default value,
/// and usage string." The package-level form, on `CommandLine`.
pub fn TextVar<T, N: Into<string>, U: Into<string>>(p: T, name: N, usage: U) -> TextHandle<T>
where
    T: crate::encoding::TextMarshaler + crate::encoding::TextUnmarshaler + Send + Sync + 'static,
{
    return CommandLine.Lock().TextVar(p, name, usage);
}

// go: sdk 1.25.5 flag/flag.go:1045-1048 Var
/// Go: "Var defines a flag with the specified name and usage string."
/// The package-level form, on `CommandLine`.
pub fn Var<N: Into<string>, U: Into<string>>(
    value: alloc::boxed::Box<dyn Value>,
    name: N,
    usage: U,
) -> ValueHandle {
    return CommandLine.Lock().Var(value, name, usage);
}

// ─── package-level CommandLine ───────────────────────────────────────
//
// Go's `flag` keeps a default FlagSet in `CommandLine` and exposes
// `flag.Bool` / `flag.Parse` / `flag.Parsed` as thin wrappers over it.
// `testing.Init` registers ~25 `-test.*` flags on exactly that set, and
// `testing.Short` / `Verbose` panic if `flag.Parsed()` is false — so
// none of it is portable without the global.
//
// goish holds it in a Mutex rather than a bare mutable static: the
// scheduler is M:N and `flag.Bool` may run from `init()`-style code on
// any thread. Go relies on registration happening before main; the
// Mutex costs nothing and removes the assumption.

// go: sdk 1.25.5 flag/flag.go:1199-1199 CommandLine
/// Go: "CommandLine is the default set of command-line flags, parsed
/// from os.Args."
///
/// A plain `static`, deliberately NOT `goish::var!`. `var!`'s fallback
/// arm lowers to `pub const`, and a `const` is substituted at each use
/// site — so every `CommandLine.Lock()` would have built and locked a
/// *fresh, empty* FlagSet. `testing.Init` would register 12 flags into
/// a temporary that is dropped on the next line, and the parse would
/// then reject `-test.short` as undefined. It compiles, it type-checks,
/// and it is silently useless.
#[allow(non_upper_case_globals)]
pub static CommandLine: crate::sync::Mutex<FlagSet> =
    crate::sync::Mutex::new(command_line_set());

// go: sdk 1.25.5 flag/flag.go:768-772 Bool
/// Go: "Bool defines a bool flag with specified name, default value,
/// and usage string."
pub fn Bool<N: Into<string>, U: Into<string>>(
    name: N,
    default: bool,
    usage: U,
) -> FlagHandle<bool> {
    return CommandLine.Lock().Bool(name, default, usage);
}

// go: sdk 1.25.5 flag/flag.go:794-798 Int
/// Go: "Int defines an int flag with specified name, default value,
/// and usage string."
pub fn Int<N: Into<string>, U: Into<string>>(name: N, default: int, usage: U) -> FlagHandle<int> {
    return CommandLine.Lock().Int(name, default, usage);
}

// go: sdk 1.25.5 flag/flag.go:820-824 Int64
/// Go: "Int64 defines an int64 flag with specified name, default
/// value, and usage string."
pub fn Int64<N: Into<string>, U: Into<string>>(
    name: N,
    default: crate::types::int64,
    usage: U,
) -> FlagHandle<crate::types::int64> {
    return CommandLine.Lock().Int64(name, default, usage);
}

// go: sdk 1.25.5 flag/flag.go:846-850 Uint
/// Go: "Uint defines a uint flag with specified name, default value,
/// and usage string."
pub fn Uint<N: Into<string>, U: Into<string>>(
    name: N,
    default: crate::types::uint,
    usage: U,
) -> FlagHandle<crate::types::uint> {
    return CommandLine.Lock().Uint(name, default, usage);
}

// ─── Go's Value types, and what replaces them ───────────────────────
//
// Go gives each flag type its own `Value` implementation — boolValue,
// intValue, stringValue and the rest — with String, Set and Get
// methods, built by a `new*Value` constructor. The FlagSet holds them
// behind the `Value` interface.
//
// goish holds a `FlagKind` instead: one closed enum whose arms ARE
// those implementations. `FlagKind::Uint64(cell)` is uint64Value;
// the `String()` match arm is uint64Value.String; the `Set` and
// `apply_value` arms are its Set. The constructors build the arm
// inline, so `new*Value` has nothing to be.
//
// This is waived from experience rather than inspection: two of these
// arms were written today (Uint64 and Func/BoolFunc), each pinned
// against a generated Go reference, which is what makes the mapping a
// fact rather than a claim.
//
// go: waived boolValue.String — the FlagKind::Bool arm of String().
// go: waived boolValue.Set — the FlagKind::Bool arm of Set().
// go: waived boolValue.Get — FlagHandle::Get reads the cell.
// go: waived boolValue.IsBoolFlag — the `isBool` test in parseOne,
// which asks the same question Go asks of the Value.
// go: waived intValue.String — the FlagKind::Int arm.
// go: waived intValue.Set — same.
// go: waived intValue.Get — FlagHandle::Get.
// go: waived int64Value.String — the FlagKind::Int64 arm.
// go: waived int64Value.Set — same.
// go: waived int64Value.Get — FlagHandle::Get.
// go: waived uintValue.String — the FlagKind::Uint arm.
// go: waived uintValue.Set — same.
// go: waived uintValue.Get — FlagHandle::Get.
// go: waived uint64Value.String — the FlagKind::Uint64 arm.
// go: waived uint64Value.Set — same.
// go: waived uint64Value.Get — FlagHandle::Get.
// go: waived float64Value.String — the FlagKind::Float64 arm.
// go: waived float64Value.Set — same.
// go: waived float64Value.Get — FlagHandle::Get.
// go: waived durationValue.String — the FlagKind::Duration arm.
// go: waived durationValue.Set — same.
// go: waived durationValue.Get — FlagHandle::Get.
// go: waived stringValue.String — the FlagKind::String arm.
// go: waived stringValue.Set — same.
// go: waived stringValue.Get — FlagHandle::Get.
// go: waived funcValue.String — the FlagKind::Func arm, which returns
// "" as Go's does.
// go: waived funcValue.Set — the arm that calls the closure.
// go: waived boolFuncValue.String — the FlagKind::BoolFunc arm.
// go: waived boolFuncValue.Set — same.
// go: waived boolFuncValue.IsBoolFlag — BoolFunc joins the `isBool`
// test, which is why `-v` does not eat the next argument.
// go: waived newBoolValue — FlagSet::Bool builds the arm inline.
// go: waived newIntValue — FlagSet::Int.
// go: waived newInt64Value — FlagSet::Int64.
// go: waived newUintValue — FlagSet::Uint.
// go: waived newUint64Value — FlagSet::Uint64.
// go: waived newFloat64Value — FlagSet::Float64.
// go: waived newDurationValue — FlagSet::Duration.
// go: waived newStringValue — FlagSet::String.
// go: waived sortFlags — VisitAll and Visit sort their names before
// walking, which is where Go uses it (both were checked).
//
// newTextValue and textValue.* are NOT here: there is no textValue arm
// and no Text handle, so that family is unported, not replaced. See
// ROADMAP §2p.

// ─── Go's *Var family, and what replaces it ─────────────────────────
//
// Go pairs every typed constructor with a `*Var` form: `Int` returns
// `*int`, `IntVar` writes into a caller's variable. Both hand the
// FlagSet somewhere to store the parsed value; the pointer IS the
// storage.
//
// goish's constructors return a `FlagHandle<T>` over an
// `Arc<SpinLock<T>>`, which is that same storage in the shape Rust
// can express — the caller holds it while the FlagSet mutates it, and
// reads with `Get()`. So the `*Var` half has no counterpart to port:
// it would be the same cell handed in rather than out. Verified by
// building three flag types through this design today (Uint64, Func,
// BoolFunc) rather than by assuming it.
//
// Waived for the eight types that HAVE a handle form. TextVar and Var
// are deliberately NOT here — see the note below them.
//
// go: waived BoolVar — FlagHandle<bool> from Bool is the storage.
// go: waived FlagSet.BoolVar — same.
// go: waived IntVar — FlagHandle<int> from Int.
// go: waived FlagSet.IntVar — same.
// go: waived Int64Var — FlagHandle<int64> from Int64.
// go: waived FlagSet.Int64Var — same.
// go: waived UintVar — FlagHandle<uint> from Uint.
// go: waived FlagSet.UintVar — same.
// go: waived Uint64Var — FlagHandle<uint64> from Uint64.
// go: waived FlagSet.Uint64Var — same.
// go: waived StringVar — FlagHandle<string> from String.
// go: waived FlagSet.StringVar — same.
// go: waived Float64Var — FlagHandle<float64> from Float64.
// go: waived FlagSet.Float64Var — same.
// go: waived DurationVar — FlagHandle<Duration> from Duration.
// go: waived FlagSet.DurationVar — same.
//
// NOT waived, because they are real gaps rather than a different
// spelling:
//
//   * `Var`/`FlagSet.Var` take a caller-implemented `flag.Value`. That
//     is the extension point of the package — how a program defines a
//     flag type Go never shipped. goish's FlagKind is a CLOSED enum,
//     so there is nothing to implement. `Func`/`BoolFunc` cover the
//     callback half of what people use Var for; a custom type with its
//     own String() does not.
//   * `TextVar`/`textValue` parse into an encoding.TextUnmarshaler,
//     and unlike the eight above there is no handle form either — this
//     one is simply unported.

// go: sdk 1.25.5 flag/flag.go:986-988 Func
/// Go: "Func defines a flag with the specified name and usage string.
/// Each time the flag is seen, fn is called with the value of the
/// flag."
pub fn Func<N: Into<string>, U: Into<string>, F>(name: N, usage: U, fn_: F)
where
    F: Fn(string) -> error + Send + Sync + 'static,
{
    CommandLine.Lock().Func(name, usage, fn_);
}

// go: sdk 1.25.5 flag/flag.go:1000-1002 BoolFunc
/// Go: "BoolFunc defines a flag with the specified name and usage
/// string without requiring values."
pub fn BoolFunc<N: Into<string>, U: Into<string>, F>(name: N, usage: U, fn_: F)
where
    F: Fn(string) -> error + Send + Sync + 'static,
{
    CommandLine.Lock().BoolFunc(name, usage, fn_);
}

// go: sdk 1.25.5 flag/flag.go:872-874 Uint64
/// Go: "Uint64 defines a uint64 flag with specified name, default
/// value, and usage string." The one integer width goish's flag set
/// could not express — a Go program calling `flag.Uint64` had nothing
/// to call.
pub fn Uint64<N: Into<string>, U: Into<string>>(
    name: N,
    default: crate::types::uint64,
    usage: U,
) -> FlagHandle<crate::types::uint64> {
    return CommandLine.Lock().Uint64(name, default, usage);
}

// go: sdk 1.25.5 flag/flag.go:730-732 Arg
/// Go: "Arg returns the i'th command-line argument. Arg(0) is the
/// first remaining argument after flags have been processed. Arg
/// returns an empty string if the requested element does not exist."
pub fn Arg(i: crate::types::int) -> string {
    return CommandLine.Lock().Arg(i);
}

// go: sdk 1.25.5 flag/flag.go:898-902 String
/// Go: "String defines a string flag with specified name, default
/// value, and usage string."
pub fn String<N: Into<string>, D: Into<string>, U: Into<string>>(
    name: N,
    default: D,
    usage: U,
) -> FlagHandle<string> {
    return CommandLine.Lock().String(name, default, usage);
}

// go: sdk 1.25.5 flag/flag.go:954-958 Duration
/// Go: "Duration defines a time.Duration flag with specified name,
/// default value, and usage string."
pub fn Duration<N: Into<string>, U: Into<string>>(
    name: N,
    default: crate::time::Duration,
    usage: U,
) -> FlagHandle<crate::time::Duration> {
    return CommandLine.Lock().Duration(name, default, usage);
}

// go: sdk 1.25.5 flag/flag.go:1186-1190 Parse
/// Go: "Parse parses the command-line flags from os.Args[1:]. Must be
/// called after all flags are defined and before flags are accessed by
/// the program."
pub fn Parse() -> error {
    let args = crate::os::Args();
    let n = args.Len();
    let rest = if n > 1 {
        args.slice(1, n)
    } else {
        slice::new()
    };
    let mut cl = CommandLine.Lock();
    // Go builds `CommandLine = NewFlagSet(os.Args[0], ExitOnError)` at
    // package init, so its usage header names the program. goish's is a
    // `static` with a const initialiser and cannot read argv there, so
    // the name is filled in HERE — the first moment goish knows it, and
    // still before anything can print a usage line.
    if cl.__name_unset() && n > 0 {
        cl.__set_name(args[0i64].clone());
    }
    return cl.Parse(&rest);
}

// go: sdk 1.25.5 flag/flag.go:1192-1194 Parsed
/// Go: "Parsed reports whether the command-line flags have been
/// parsed."
pub fn Parsed() -> bool {
    return CommandLine.Lock().Parsed();
}

// go: sdk 1.25.5 flag/flag.go:532-534 Set
/// Go: "Set sets the value of the named command-line flag."
pub fn Set(name: string, value: string) -> error {
    return CommandLine.Lock().Set(name, value);
}

// ─── The Value interface and the Flag struct ───────────────────────────

// go: sdk 1.25.5 flag/flag.go:360-363 Value
/// Go: "Value is the interface to the dynamic value stored in a flag."
///
/// This is the real `flag.Value`, and it had been absent: the name
/// `Flag` was occupied by a goish-invented generic handle (now
/// `FlagHandle<T>`), and no Value interface existed at all. Downstream
/// ports that wrap the stdlib flag package — spf13-pflag's
/// golangflag.go bridge — need both.
pub trait Value: Send + Sync {
    fn String(&self) -> string;
    fn Set(&mut self, s: string) -> error;

    // go: none — goish-only: Go declares this on a SEPARATE optional
    //     interface, `boolFlag` (flag.go lines 150-153), which a Value
    //     may also implement. Rust has no optional-interface test on a
    //     `dyn`, so the two interfaces fuse and this becomes a
    //     defaulted method. There is no Go declaration that maps to it
    //     one-to-one, which is why it stays on the GOISH018 waiver.
    /// Go: `boolFlag` is a SEPARATE optional interface —
    /// `if fv, ok := flag.Value.(boolFlag); ok && fv.IsBoolFlag()`.
    /// Rust has no optional-interface test on a `dyn`, so it is a
    /// defaulted method here: answering false is what a type that does
    /// not implement Go's `boolFlag` does.
    ///
    /// A true answer is what lets `-v` stand alone without eating the
    /// next argument.
    fn IsBoolFlag(&self) -> bool {
        return false;
    }
}

// goishlint:ignore GOISH019 — Go recovers a flag's TYPE by
// type-switching on the concrete `Value` (`*stringValue`,
// `*durationValue`, …), which `UnquoteUsage` and `PrintDefaults` both
// need. goish's Value is one type over a kind enum, so the kind is
// carried on the Flag instead. The four Go fields are all present and
// in order.
// go: sdk 1.25.5 flag/flag.go:408-413 Flag
/// Go: "A Flag represents the state of a flag."
pub struct Flag {
    /// name as it appears on command line
    pub Name: string,
    /// help message
    pub Usage: string,
    /// value as set
    pub Value: alloc::boxed::Box<dyn Value>,
    /// default value (as text); for usage message
    pub DefValue: string,
    /// goish-only: the typed cell's kind, which Go recovers by
    /// type-switching on `Value`.
    #[doc(hidden)]
    pub __kind: FlagKind,
}

// go: none — Goish glue: adapts one of the FlagSet's typed cells to the
// `Value` interface, so Lookup/VisitAll can hand out Go-shaped Flags.
// Go stores a Value in every flag directly; goish stores a typed cell,
// so the adaptation happens here rather than at definition time.
pub(crate) struct kindValue {
    pub(crate) kind: FlagKind,
}

impl Value for kindValue {
    // go: none — Goish glue; the per-kind formatting Go gets for free
    // because each of its Values carries its own String method.
    fn String(&self) -> string {
        let out = match self.kind {
            FlagKind::Bool(ref c) => {
                if *c.lock() {
                    string::from_static("true")
                } else {
                    string::from_static("false")
                }
            }
            FlagKind::Int(ref c) => crate::strconv::Itoa(*c.lock()),
            FlagKind::Int64(ref c) => crate::strconv::FormatInt(*c.lock(), 10),
            FlagKind::Uint(ref c) => crate::strconv::FormatUint(*c.lock(), 10),
            FlagKind::Uint64(ref c) => crate::strconv::FormatUint(*c.lock(), 10),
            // Go: funcValue.String and boolFuncValue.String both return
            // "" — a callback flag has no value to show.
            FlagKind::Func(_) | FlagKind::BoolFunc(_) => string::new(),
            FlagKind::Duration(ref c) => (*c.lock()).String(),
            FlagKind::Float64(ref c) => crate::strconv::FormatFloat(*c.lock(), b'g', -1, 64),
            FlagKind::String(ref c) => (*c.lock()).clone(),
            FlagKind::Custom(ref c) => c.lock().String(),
        };
        return out;
    }

    // go: none — Goish glue; the parse-into-the-cell half of the same
    // adaptation. Mirrors what Go's per-type Values do in their Set.
    fn Set(&mut self, s: string) -> error {
        match self.kind {
            // The caller's own Value: goish parses nothing, it just
            // hands the string over, which is exactly Go's `Var`.
            FlagKind::Custom(ref c) => {
                return c.lock().Set(s);
            }
            FlagKind::Bool(ref c) => {
                let (v, err) = crate::strconv::ParseBool(s);
                if err != crate::nil {
                    return err;
                }
                *c.lock() = v;
            }
            FlagKind::Int(ref c) => {
                let (v, err) = crate::strconv::Atoi(s);
                if err != crate::nil {
                    return err;
                }
                *c.lock() = v;
            }
            FlagKind::Int64(ref c) => {
                let (v, err) = crate::strconv::ParseInt(s, 0, 64);
                if err != crate::nil {
                    return err;
                }
                *c.lock() = v;
            }
            FlagKind::Uint(ref c) => {
                let (v, err) = crate::strconv::ParseUint(s, 0, 64);
                if err != crate::nil {
                    return err;
                }
                *c.lock() = v;
            }
            FlagKind::Uint64(ref c) => {
                let (v, err) = crate::strconv::ParseUint(s, 0, 64);
                if err != crate::nil {
                    return err;
                }
                *c.lock() = v;
            }
            // Go: `func (f funcValue) Set(s string) error { return f(s) }`
            FlagKind::Func(ref f) | FlagKind::BoolFunc(ref f) => {
                return f(s);
            }
            FlagKind::Duration(ref c) => {
                let (v, err) = crate::time::ParseDuration(s);
                if err != crate::nil {
                    return err;
                }
                *c.lock() = v;
            }
            FlagKind::Float64(ref c) => {
                let (v, err) = crate::strconv::ParseFloat(s, 64);
                if err != crate::nil {
                    return err;
                }
                *c.lock() = v;
            }
            FlagKind::String(ref c) => {
                *c.lock() = s;
            }
        }
        return crate::nil.into();
    }
}

impl Flag {
    // go: none — Goish glue: Go's `UnquoteUsage` reaches the type name
    //     by type-switching on the concrete `Value`; goish's Value is
    //     one type over a kind enum, so the switch is on the kind.
    pub(crate) fn __type_name(&self) -> &'static str {
        return match &self.__kind {
            FlagKind::Bool(_) => "",
            FlagKind::Duration(_) => "duration",
            FlagKind::Float64(_) => "float",
            FlagKind::Int(_) | FlagKind::Int64(_) => "int",
            FlagKind::String(_) => "string",
            FlagKind::Uint(_) => "uint",
            FlagKind::Uint64(_) => "uint64",
            // Go's UnquoteUsage: a funcValue reports "value", and a
            // boolFuncValue reports "" because it takes none.
            FlagKind::Func(_) => "value",
            FlagKind::BoolFunc(_) => "",
            // Go's UnquoteUsage falls through to "value" for any Value
            // it does not recognise, which is every user type.
            FlagKind::Custom(_) => "value",
        };
    }
}

impl FlagSet {
    // go: none — Goish glue: builds a Go-shaped Flag from the port's
    // typed FlagDef. Go's flags ARE Flags; goish's are typed cells, so
    // the Flag is constructed on demand and returned owned rather than
    // as the *Flag pointer Go hands out of its `formal` map.
    pub(crate) fn __as_flag(d: &FlagDef) -> Flag {
        let v = kindValue {
            kind: d.kind.clone(),
        };
        let def_value = Value::String(&v);
        let f = Flag {
            Name: d.name.clone(),
            Usage: d.usage.clone(),
            Value: alloc::boxed::Box::new(v),
            DefValue: d.defvalue.clone(),
            __kind: d.kind.clone(),
        };
        let _ = def_value;
        return f;
    }

    // go: sdk 1.25.5 flag/flag.go:483-485 FlagSet.Lookup
    /// Go: "Lookup returns the Flag structure of the named flag,
    /// returning nil if none exists."
    ///
    /// Go returns `*Flag` and uses a nil pointer for "absent"; goish
    /// builds the Flag on demand, so absence is `None`.
    pub fn Lookup<N: Into<string>>(&self, name: N) -> Option<Flag> {
        let name = name.into();
        for d in self.defs.iter() {
            if d.name == name {
                return Some(Self::__as_flag(d));
            }
        }
        return None;
    }

    // go: sdk 1.25.5 flag/flag.go:456-460 FlagSet.VisitAll
    /// Go: "VisitAll visits the flags in lexicographical order, calling
    /// fn for each. It visits all flags, even those not set."
    pub fn VisitAll<F: FnMut(&Flag)>(&self, mut fn_: F) {
        let mut names: alloc::vec::Vec<string> = self.defs.iter().map(|d| d.name.clone()).collect();
        names.sort();
        for n in names.iter() {
            if let Some(d) = self.defs.iter().find(|d| &d.name == n) {
                fn_(&Self::__as_flag(d));
            }
        }
    }
}

// ─── Parser and usage ────────────────────────────────────────────────

// go: sdk 1.25.5 flag/flag.go:104-107 errParse
/// Go's sentinel for "the value did not parse", used where the
/// underlying error text is not worth showing.
crate::var! {
    errParse: error = "parse error";
}

// go: sdk 1.25.5 flag/flag.go:111-123 numError
/// Go unwraps a `*strconv.NumError` to its bare cause, so the message
/// reads "parse error" or "value out of range" rather than repeating
/// the function name and the input.
fn numError(err: error) -> string {
    if crate::errors::Is(err.clone(), crate::strconv::ErrSyntax) {
        return string::from("parse error");
    }
    if crate::errors::Is(err.clone(), crate::strconv::ErrRange) {
        return string::from("value out of range");
    }
    return err.Error();
}

// go: sdk 1.25.5 flag/flag.go:101-101 ErrHelp
// The error returned when the `-help` or `-h` flag is invoked but no
// such flag is defined.
//
// Go declares this a package-level `var`, and checking for it after
// Parse is a documented idiom — flag.go:1168 does it itself, `if err ==
// ErrHelp { os.Exit(0) }`. goish's `error` compares by Arc::ptr_eq, so
// the sentinel has to be ONE value; `var!` caches it behind a lazy
// slot. This was a fn returning a fresh `errors::New` until 2026-09-06,
// so every such comparison was false, and the type is exported.
crate::var! {
    pub ErrHelp: error = "flag: help requested";
}

// go: none — goish idiom: Go's `failf` formats with Printf, prints to
//     the FlagSet's output and returns the error. goish's FlagSet is
//     ContinueOnError only and hands the error straight back, so this
//     just builds the message.
/// Go formats the message, prints it and returns it as an error.
/// goish's FlagSet has no output writer, so this only builds it —
/// `Parse` hands it back to the caller, which is what
/// `ContinueOnError` does with it in Go too.
fn failf2(prefix: &[byte], rest: &[byte]) -> error {
    let mut msg: Vec<byte> = Vec::new();
    msg.extend_from_slice(prefix);
    msg.extend_from_slice(rest);
    return errors::New(string::__from_vec(msg));
}

// go: none — goish idiom: the `invalid value %q for flag -%s: %v` and
//     `invalid boolean value %q for -%s: %v` messages, which Go builds
//     with Printf. The quoting is `strconv::Quote`, as `%q` is.
fn failf_invalid(
    prefix: &[byte],
    value: &[byte],
    mid: &[byte],
    name: &[byte],
    inner: error,
) -> error {
    let mut msg: Vec<byte> = Vec::new();
    msg.extend_from_slice(prefix);
    msg.extend_from_slice(crate::strconv::Quote(string::from_bytes(value)).as_bytes());
    msg.extend_from_slice(mid);
    msg.extend_from_slice(name);
    msg.extend_from_slice(b": ");
    msg.extend_from_slice(numError(inner).as_bytes());
    return errors::New(string::__from_vec(msg));
}

// go: sdk 1.25.5 flag/flag.go:568-602 UnquoteUsage
/// Extract a back-quoted name from the usage string and return it
/// with the quotes removed, or the flag's type name when there is no
/// back-quoted name. A bool flag has no name at all — `-b\ta bool`,
/// not `-b value`.
pub fn UnquoteUsage(fl: &Flag) -> (string, string) {
    let u = fl.Usage.as_bytes();
    let mut i = 0usize;
    while i < u.len() {
        if u[i] == b'`' {
            let mut j = i + 1;
            while j < u.len() {
                if u[j] == b'`' {
                    let name = string::from_bytes(&u[i + 1..j]);
                    let mut usage: Vec<byte> = Vec::new();
                    usage.extend_from_slice(&u[..i]);
                    usage.extend_from_slice(name.as_bytes());
                    usage.extend_from_slice(&u[j + 1..]);
                    return (name, string::__from_vec(usage));
                }
                j += 1;
            }
            break; // Only one back quote; use the type name.
        }
        i += 1;
    }
    return (string::from_static(fl.__type_name()), fl.Usage.clone());
}

// go: sdk 1.25.5 flag/flag.go:538-561 isZeroValue
/// Whether `value` is the zero value for the flag's type. Go builds a
/// zero of the Value's concrete type by reflection and compares its
/// String(); goish's kinds are a closed enum, so the zeros are spelled
/// out.
fn isZeroValue(kind: Option<&FlagKind>, value: &string) -> bool {
    let z: &str = match kind {
        Some(FlagKind::Bool(_)) => "false",
        Some(FlagKind::Int(_))
        | Some(FlagKind::Int64(_))
        | Some(FlagKind::Uint(_))
        | Some(FlagKind::Uint64(_)) => "0",
        Some(FlagKind::Float64(_)) => "0",
        Some(FlagKind::String(_)) => "",
        // A callback flag has no default to compare against; Go's
        // isZeroValue builds a zero Value and asks it, which for these
        // is "".
        Some(FlagKind::Func(_)) | Some(FlagKind::BoolFunc(_)) => "",
        Some(FlagKind::Duration(_)) => "0s",
        // Go builds a fresh zero of the Value's concrete type and
        // compares its String(). goish cannot construct the caller's
        // type, so it asks the same question the only way it can: a
        // custom flag's default is whatever it rendered at definition
        // time, and `PrintDefaults` shows it. Reporting false here
        // means "always show the default", which is the safe answer —
        // Go omits a default only when it is provably the zero.
        Some(FlagKind::Custom(_)) => return false,
        None => return false,
    };
    return *value == string::from_static(z);
}

// go: none — goish idiom: Go's `Flag.DefValue` is captured at
//     definition time as `value.String()`; goish's typed cells are
//     mutated in place by the parser, so the definition-time rendering
//     has to be taken and stored before the parse can change it.
pub(crate) fn __defstr(kind: &FlagKind) -> string {
    let v = kindValue { kind: kind.clone() };
    return Value::String(&v);
}

impl FlagSet {
    // go: sdk 1.25.5 flag/flag.go:1153-1177 FlagSet.Parse
    /// Parse flag definitions from the argument list, which should not
    /// include the command name. Must be called after all flags are
    /// defined and before flags are accessed by the program.
    pub fn Parse(&mut self, args: &slice<string>) -> error {
        // Go sets `parsed` FIRST and keeps the un-consumed arguments in
        // `f.args` as it goes, so a caller that gets an error can still
        // see what was left. goish set `parsed` only on success and
        // never populated `args` on the error path.
        self.parsed = true;
        self.args = args.iter().cloned().collect();
        loop {
            let (seen, err) = self.parseOne();
            if seen {
                continue;
            }
            if err == nil {
                break;
            }
            // Go: `switch f.errorHandling` (flag.go line 1164). This
            // used to `return err` unconditionally, which is
            // ContinueOnError for every set — including `CommandLine`,
            // which Go makes ExitOnError. A program with a bad flag
            // therefore ran on with a default value where Go stops.
            match self.errorHandling {
                ErrorHandling::ContinueOnError => return err,
                ErrorHandling::ExitOnError => {
                    // Go: `if err == ErrHelp { os.Exit(0) }; os.Exit(2)`
                    // — -h is a request that was honoured, not a failure.
                    if crate::errors::Is(err.clone(), ErrHelp.clone()) {
                        crate::os::Exit(0);
                    }
                    crate::os::Exit(2);
                }
                ErrorHandling::PanicOnError => {
                    // Go panics with the error VALUE; goish's panic
                    // carries a string, so it carries the error's text.
                    let msg = err.Error();
                    panic!("{}", msg.as_ref() as &str);
                }
            }
        }
        return nil;
    }

    // go: sdk 1.25.5 flag/flag.go:1075-1147 FlagSet.parseOne
    /// Parse one flag. Reports whether a flag was seen, and the error
    /// if one stopped the parse.
    fn parseOne(&mut self) -> (bool, error) {
        if self.args.is_empty() {
            return (false, nil);
        }
        let s = self.args[0].clone();
        let sb = s.as_bytes();
        if sb.len() < 2 || sb[0] != b'-' {
            return (false, nil);
        }
        let mut numMinuses = 1usize;
        if sb[1] == b'-' {
            numMinuses += 1;
            if sb.len() == 2 {
                // "--" terminates the flags.
                self.args.remove(0);
                return (false, nil);
            }
        }
        let mut name: alloc::vec::Vec<byte> = sb[numMinuses..].to_vec();
        if name.is_empty() || name[0] == b'-' || name[0] == b'=' {
            return (false, self.failf(b"bad flag syntax: ", sb));
        }

        // It's a flag. Does it have an argument?
        self.args.remove(0);
        let mut hasValue = false;
        let mut value: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
        // Equals cannot be first.
        let mut i = 1usize;
        while i < name.len() {
            if name[i] == b'=' {
                value = name[i + 1..].to_vec();
                hasValue = true;
                name.truncate(i);
                break;
            }
            i += 1;
        }

        let nm = string::from_bytes(&name);
        let def_idx = match self.find_def(&nm) {
            Some(k) => k,
            None => {
                // Go's special case for a nice help message.
                if name == b"help" || name == b"h" {
                    self.usage();
                    return (false, ErrHelp.into());
                }
                return (false, self.failf(b"flag provided but not defined: -", &name));
            }
        };

        // Go asks the Value: `if fv, ok := flag.Value.(boolFlag); ok &&
        // fv.IsBoolFlag()`. Both boolValue and boolFuncValue answer
        // true, which is what lets `-v` stand alone without eating the
        // next argument.
        let isBool = match &self.defs[def_idx].kind {
            FlagKind::Bool(_) | FlagKind::BoolFunc(_) => true,
            // Go asks the Value itself, so a user type that implements
            // `boolFlag` gets the same standalone-flag treatment.
            FlagKind::Custom(c) => c.lock().IsBoolFlag(),
            _ => false,
        };
        if isBool {
            // Special case: a bool flag does not need an argument, and
            // it never CONSUMES the next one. goish consumed it, so
            // `-b true` swallowed "true" instead of leaving it as a
            // positional, and `-b arg` failed to parse "arg" as a bool.
            if hasValue {
                let err = self.apply_value(def_idx, &value);
                if err != nil {
                    return (
                        false,
                        failf_invalid(b"invalid boolean value ", &value, b" for -", &name, err),
                    );
                }
            } else {
                let err = self.apply_value(def_idx, b"true");
                if err != nil {
                    return (false, self.failf(b"invalid boolean flag ", &name));
                }
            }
        } else {
            // It must have a value, which might be the next argument —
            // whatever that argument looks like. Go does not skip an
            // argument that starts with '-', which is what makes
            // `-n -7` parse as minus seven.
            if !hasValue && !self.args.is_empty() {
                hasValue = true;
                value = self.args[0].as_bytes().to_vec();
                self.args.remove(0);
            }
            if !hasValue {
                return (false, self.failf(b"flag needs an argument: -", &name));
            }
            let err = self.apply_value(def_idx, &value);
            if err != nil {
                return (
                    false,
                    failf_invalid(b"invalid value ", &value, b" for flag -", &name, err),
                );
            }
        }
        self.defs[def_idx].actual = true;
        return (true, nil);
    }

    // go: sdk 1.25.5 flag/flag.go:1050-1054 FlagSet.sprintf
    /// goishlint:ignore GOISH020 sprintf — Go's is
    ///     `sprintf(format string, a ...any)`: a format plus variadic
    ///     arguments. Every caller here has already built its message
    ///     (the parser knows the flag name), so this takes the finished
    ///     bytes. The dropped parameter is Go's formatting, not
    ///     information.
    /// Go: format the message, write it to Output with a newline, and
    /// return it. The WRITE is the point — a parse failure explains
    /// itself on the output, it does not only travel as an error value.
    fn sprintf(&self, msg: &[byte]) -> string {
        let mut line: Vec<byte> = Vec::new();
        line.extend_from_slice(msg);
        line.push(b'\n');
        self.__write_output(line);
        return string::from_bytes(msg);
    }

    // go: sdk 1.25.5 flag/flag.go:1058-1062 FlagSet.failf
    /// Go: "failf prints to standard error a formatted error and usage
    /// message and returns the error." goish built the error and
    /// printed NOTHING, so a user who mistyped a flag saw silence
    /// where Go prints the reason and the flag list.
    fn failf(&self, prefix: &[byte], rest: &[byte]) -> error {
        let mut msg: Vec<byte> = Vec::new();
        msg.extend_from_slice(prefix);
        msg.extend_from_slice(rest);
        let text = self.sprintf(&msg);
        self.usage();
        return errors::New(text);
    }

    // go: sdk 1.25.5 flag/flag.go:1066-1072 FlagSet.usage
    /// Go calls the FlagSet's Usage func, which defaults to
    /// `defaultUsage`. goish has no settable Usage hook, so this IS
    /// defaultUsage.
    ///
    /// The header line is not decoration: Go prints "Usage of <name>:"
    /// or, for an unnamed set, "Usage:" BEFORE the flag list
    /// (flag.go:684-690). goish printed only the list, so `-h` output
    /// differed from Go's on its very first line. This FlagSet carries
    /// no name — see the ErrorHandling note in mod.rs, where the same
    /// missing NewFlagSet parameter is the cause — so it always takes
    /// Go's empty-name branch.
    fn usage(&self) {
        // Go: "Usage of <name>:" for a named set, "Usage:" otherwise
        // (flag.go lines 684-690). goish could only produce the second,
        // because `NewFlagSet` took no name; it takes one now.
        match &self.name {
            Some(n) if n.Len() > 0 => {
                let mut line: alloc::vec::Vec<u8> = b"Usage of ".to_vec();
                line.extend_from_slice(n.as_bytes());
                line.extend_from_slice(b":\n");
                self.__write_output(line);
            }
            _ => self.__write_output(b"Usage:\n".to_vec()),
        }
        self.PrintDefaults();
    }

    // go: sdk 1.25.5 flag/flag.go:438-441 FlagSet.Name
    /// Go: "Name returns the name of the flag set."
    pub fn Name(&self) -> string {
        return match &self.name {
            Some(n) => n.clone(),
            None => string::new(),
        };
    }

    // go: sdk 1.25.5 flag/flag.go:443-446 FlagSet.ErrorHandling
    /// Go: "ErrorHandling returns the error handling behavior of the
    /// flag set."
    pub fn ErrorHandling(&self) -> ErrorHandling {
        return self.errorHandling;
    }

    // go: none — goish-only: `CommandLine` is const-initialised and
    //     cannot read `os.Args[0]` there; the package-level `Parse`
    //     fills the name in on first use.
    #[doc(hidden)]
    pub fn __name_unset(&self) -> bool {
        return self.name.is_none();
    }

    // go: none — goish-only: see `__name_unset`.
    #[doc(hidden)]
    pub fn __set_name(&mut self, n: string) {
        self.name = Some(n);
    }

    // go: sdk 1.25.5 flag/flag.go:712-712 FlagSet.NFlag
    /// The number of flags that have been set.
    pub fn NFlag(&self) -> int {
        let mut n: int = 0;
        for d in self.defs.iter() {
            if d.actual {
                n += 1;
            }
        }
        return n;
    }

    // go: sdk 1.25.5 flag/flag.go:470-474 FlagSet.Visit
    /// Visit the flags that have been SET, in lexicographical order.
    pub fn Visit<F: FnMut(&Flag)>(&self, mut fun: F) {
        let mut names: Vec<string> = self
            .defs
            .iter()
            .filter(|d| d.actual)
            .map(|d| d.name.clone())
            .collect();
        names.sort();
        for n in names.iter() {
            if let Some(d) = self.defs.iter().find(|d| &d.name == n) {
                fun(&Self::__as_flag(d));
            }
        }
    }

    // go: sdk 1.25.5 flag/flag.go:497-529 FlagSet.set
    /// Set the value of the named flag. Go's message for an unknown
    /// name is "no such flag -x", not the parser's "flag provided but
    /// not defined"; and a successful Set marks the flag as SET, so
    /// `Visit` and `NFlag` see it. goish did neither.
    pub fn Set(&mut self, name: string, value: string) -> error {
        let Some(index) = self.find_def(&name) else {
            let mut message: Vec<byte> = Vec::new();
            message.extend_from_slice(b"no such flag -");
            message.extend_from_slice(name.as_bytes());
            return errors::New(string::__from_vec(message));
        };
        let err = self.apply_value(index, value.as_bytes());
        if err != nil {
            return err;
        }
        self.defs[index].actual = true;
        return nil;
    }

    // go: none — goish idiom: Go gives every flag type its own
    //     `Value.Set` (intValue.Set, boolValue.Set, …); goish's kinds are
    //     a closed enum, so the six are one match.
    /// The `Set` half of every `flag.Value` in Go, over goish's kind
    /// enum.
    ///
    /// Go assigns the parsed value **unconditionally** — `*i =
    /// intValue(v)` runs whether or not ParseInt failed — so a flag
    /// given a bad value ends up holding the zero, and one given an
    /// out-of-range value ends up holding the clamped bound. goish
    /// returned early and left the DEFAULT in place, which is the more
    /// dangerous answer: a program that ignores the error then runs
    /// with a value the user never asked for.
    ///
    /// The error is also normalised the way Go's is: `bool` and
    /// `Duration` report a bare "parse error" (Go's `errParse`), and
    /// the numeric kinds go through `numError`.
    // goishlint:ignore GOISH023 — every arm of the match returns
    // explicitly; there is no tail expression to convert.
    fn apply_value(&mut self, idx: usize, val: &[byte]) -> error {
        let s = string::from_bytes(val);
        match &self.defs[idx].kind {
            // The caller's own Value parses its own string, and its
            // error is returned verbatim — Go's `Var` does no more.
            FlagKind::Custom(cell) => {
                return cell.lock().Set(s);
            }
            FlagKind::String(cell) => {
                *cell.lock() = s;
                return nil;
            }
            FlagKind::Int(cell) => {
                // Go: strconv.ParseInt(s, 0, strconv.IntSize)
                let (n, err) = strconv::ParseInt(s, 0, 64);
                *cell.lock() = n;
                return err;
            }
            FlagKind::Bool(cell) => {
                let (b, err) = strconv::ParseBool(s);
                *cell.lock() = b;
                return err;
            }
            FlagKind::Float64(cell) => {
                let (f, err) = strconv::ParseFloat(s, 64);
                *cell.lock() = f;
                return err;
            }
            FlagKind::Int64(cell) => {
                let (n, err) = strconv::ParseInt(s, 0, 64);
                *cell.lock() = n;
                return err;
            }
            FlagKind::Uint(cell) => {
                // Go: strconv.ParseUint(value, 0, strconv.IntSize)
                let (n, err) = strconv::ParseUint(s, 0, 64);
                *cell.lock() = n as crate::types::uint;
                return err;
            }
            FlagKind::Uint64(cell) => {
                // Go: strconv.ParseUint(value, 0, 64)
                let (n, err) = strconv::ParseUint(s, 0, 64);
                *cell.lock() = n;
                return err;
            }
            // Go: the Value IS the function — `funcValue.Set` calls it
            // and a non-nil result "will be treated as a flag value
            // parsing error", so it propagates exactly like a bad int.
            FlagKind::Func(f) | FlagKind::BoolFunc(f) => {
                let f = f.clone();
                return f(s);
            }
            FlagKind::Duration(cell) => {
                let (d, err) = crate::time::ParseDuration(s);
                *cell.lock() = d;
                if err != nil {
                    // Go: `err = errParse` — the ParseDuration message
                    // is discarded.
                    return errParse.into();
                }
                return nil;
            }
        }
    }

    // go: sdk 1.25.5 flag/flag.go:607-651 FlagSet.PrintDefaults
    /// Print, to standard error, the default values of all defined
    /// flags in the set. goish's rendering was `  -name  usage` on one
    /// line; Go's puts the TYPE after the name, the usage on its own
    /// indented line unless the whole prefix fits in four columns, and
    /// the default in parentheses unless it is the type's zero.
    pub fn PrintDefaults(&self) {
        let mut out: Vec<byte> = Vec::new();
        self.VisitAll(|fl| {
            let mut b: Vec<byte> = Vec::new();
            b.extend_from_slice(b"  -");
            b.extend_from_slice(fl.Name.as_bytes());
            let (name, usage) = UnquoteUsage(fl);
            if !name.as_bytes().is_empty() {
                b.push(b' ');
                b.extend_from_slice(name.as_bytes());
            }
            // Boolean flags of one ASCII letter are common enough that
            // Go puts their usage on the same line.
            if b.len() <= 4 {
                b.push(b'\t');
            } else {
                // Four spaces before the tab aligns for both 4- and
                // 8-space tab stops.
                b.extend_from_slice(b"\n    \t");
            }
            for c in usage.as_bytes().iter() {
                if *c == b'\n' {
                    b.extend_from_slice(b"\n    \t");
                } else {
                    b.push(*c);
                }
            }
            let def = self.__defvalue_of(&fl.Name);
            if !isZeroValue(self.__kind_of(&fl.Name), &def) {
                b.extend_from_slice(b" (default ");
                if self.__is_string_flag(&fl.Name) {
                    b.extend_from_slice(crate::strconv::Quote(def.clone()).as_bytes());
                } else {
                    b.extend_from_slice(def.as_bytes());
                }
                b.push(b')');
            }
            b.push(b'\n');
            out.extend_from_slice(&b);
        });
        self.__write_output(out);
    }

    // go: sdk 1.25.5 flag/flag.go:450-452 FlagSet.SetOutput
    /// Set the destination for usage and error messages. `PrintDefaults`
    /// writes there; the default is standard error.
    pub fn SetOutput<W: crate::io::Writer + Send + 'static>(&mut self, w: W) {
        self.output = Some(Arc::new(crate::sync::Mutex::new(
            core::cell::UnsafeCell::new(
                alloc::boxed::Box::new(w) as alloc::boxed::Box<dyn crate::io::Writer + Send>
            ),
        )));
    }

    // go: none — goish idiom: Go's `Output()` returns the io.Writer, or
    //     os.Stderr when none was set. goish's writer lives behind a
    //     Mutex, so the write is done here rather than the writer
    //     handed out.
    fn __write_output(&self, buf: Vec<byte>) {
        match &self.output {
            Some(m) => {
                let g = m.Lock();
                let w: &mut alloc::boxed::Box<dyn crate::io::Writer + Send> =
                    unsafe { &mut *g.get() };
                let _ = w.Write(slice::__from_vec(buf));
            }
            None => {
                let e = crate::os::Stderr();
                let _ = e.Write(slice::__from_vec(buf));
            }
        }
    }

    // go: none — goish idiom: Go reads `flag.DefValue` off the *Flag it
    //     hands the callback; goish builds the Flag on demand, so the
    //     definition-time value is looked up here.
    fn __defvalue_of(&self, name: &string) -> string {
        for d in self.defs.iter() {
            if d.name == *name {
                return d.defvalue.clone();
            }
        }
        return string::new();
    }

    // go: none — goish idiom: see the note on `__defvalue_of`.
    fn __kind_of(&self, name: &string) -> Option<&FlagKind> {
        for d in self.defs.iter() {
            if d.name == *name {
                return Some(&d.kind);
            }
        }
        return None;
    }

    // go: none — goish idiom: Go asks `flag.Value.(*stringValue)`;
    //     goish's Value is one type over a kind enum.
    fn __is_string_flag(&self, name: &string) -> bool {
        return matches!(self.__kind_of(name), Some(FlagKind::String(_)));
    }
}
