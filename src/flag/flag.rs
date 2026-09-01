// go: file flag/flag.go decls: FlagSet.Int64, FlagSet.Uint, FlagSet.Duration, Parsed, Bool, Int, Int64, Uint, String, Duration, Parse, Set, FlagSet.Lookup, FlagSet.VisitAll, errParse, numError, ErrHelp, UnquoteUsage, isZeroValue, FlagSet.Parse, FlagSet.parseOne, FlagSet.usage, FlagSet.NFlag, FlagSet.Visit, FlagSet.set, FlagSet.PrintDefaults, FlagSet.SetOutput
//
// flag — the package-level CommandLine set, and the flag types goish's
// hand-written FlagSet did not have.
//
// **Partial port.** The FlagSet itself, its parser and the rest of its
// surface are hand-written in mod[rs] and are not ports. This file
// holds what has been ported verbatim, kept separate because GOISH015
// forbids anchored code in a module root.
//
// goishlint:ignore GOISH018 NewFlagSet, Var, Func, BoolFunc, TextVar, Set, Args, NArg, NFlag, Arg, Visit, PrintDefaults, Usage, Init, Output, Name, SetOutput, UnquoteUsage, isZeroValue, defaultUsage, sortFlags, newBoolValue, newIntValue, newInt64Value, newUintValue, newUint64Value, newStringValue, newFloat64Value, newDurationValue, newTextValue, newFuncValue, newBoolFuncValue, Get, IsBoolFlag, Float64, Uint64, BoolVar, IntVar, Int64Var, UintVar, Uint64Var, StringVar, Float64Var, DurationVar, parseOne, failf, usage, panicOnError, numError, sprintf, commandLineUsage, Error, ErrorHandling, Parse, PrintDefaults, String, Set, Visit — FlagSet and its parser are hand-written in mod[rs]; only the declarations in this file are ports.
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

use super::{FlagDef, FlagHandle, FlagKind, FlagSet, NewFlagSet};

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
        self.defs.push(FlagDef {
            name: name.into(),
            usage: usage.into(),
            kind: FlagKind::Int64(cell.clone()),
            defvalue: __defstr(&FlagKind::Int64(cell.clone())),
            actual: false,
        });
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
        self.defs.push(FlagDef {
            name: name.into(),
            usage: usage.into(),
            kind: FlagKind::Uint(cell.clone()),
            defvalue: __defstr(&FlagKind::Uint(cell.clone())),
            actual: false,
        });
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
        self.defs.push(FlagDef {
            name: name.into(),
            usage: usage.into(),
            kind: FlagKind::Duration(cell.clone()),
            defvalue: __defstr(&FlagKind::Duration(cell.clone())),
            actual: false,
        });
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
pub static CommandLine: crate::sync::Mutex<FlagSet> = crate::sync::Mutex::new(NewFlagSet());

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
    return CommandLine.Lock().Parse(&rest);
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
            FlagKind::Duration(ref c) => (*c.lock()).String(),
            FlagKind::Float64(ref c) => crate::strconv::FormatFloat(*c.lock(), b'g', -1, 64),
            FlagKind::String(ref c) => (*c.lock()).clone(),
        };
        return out;
    }

    // go: none — Goish glue; the parse-into-the-cell half of the same
    // adaptation. Mirrors what Go's per-type Values do in their Set.
    fn Set(&mut self, s: string) -> error {
        match self.kind {
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
fn errParse() -> error {
    return errors::New("parse error");
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
/// The error returned when the `-help` or `-h` flag is invoked but no
/// such flag is defined.
pub fn ErrHelp() -> error {
    return errors::New("flag: help requested");
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
        Some(FlagKind::Int(_)) | Some(FlagKind::Int64(_)) | Some(FlagKind::Uint(_)) => "0",
        Some(FlagKind::Float64(_)) => "0",
        Some(FlagKind::String(_)) => "",
        Some(FlagKind::Duration(_)) => "0s",
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
            // goish's FlagSet is ContinueOnError only — there is no
            // ErrorHandling field to switch on, so the error comes back
            // to the caller rather than exiting the process.
            return err;
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
            return (false, failf2(b"bad flag syntax: ", sb));
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
                    return (false, ErrHelp());
                }
                return (false, failf2(b"flag provided but not defined: -", &name));
            }
        };

        let isBool = matches!(self.defs[def_idx].kind, FlagKind::Bool(_));
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
                    return (false, failf2(b"invalid boolean flag ", &name));
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
                return (false, failf2(b"flag needs an argument: -", &name));
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

    // go: sdk 1.25.5 flag/flag.go:1066-1072 FlagSet.usage
    /// Go calls the FlagSet's Usage func, which defaults to printing
    /// the defaults. goish has no settable Usage hook, so this is
    /// `defaultUsage` directly.
    fn usage(&self) {
        self.PrintDefaults();
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
            FlagKind::Duration(cell) => {
                let (d, err) = crate::time::ParseDuration(s);
                *cell.lock() = d;
                if err != nil {
                    // Go: `err = errParse` — the ParseDuration message
                    // is discarded.
                    return errParse();
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
