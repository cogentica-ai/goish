// go: file flag/flag.go decls: FlagSet.Int64, FlagSet.Uint, FlagSet.Duration, FlagSet.Parsed, FlagSet.Lookup, FlagSet.VisitAll, Bool, Int, Int64, Uint, String, Duration, Parse, Parsed
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

// go: sdk 1.25.5 flag/flag.go:519-526 Set
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
}

// go: none — Goish glue: adapts one of the FlagSet's typed cells to the
// `Value` interface, so Lookup/VisitAll can hand out Go-shaped Flags.
// Go stores a Value in every flag directly; goish stores a typed cell,
// so the adaptation happens here rather than at definition time.
pub(crate) struct kindValue {
    kind: FlagKind,
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

impl FlagSet {
    // go: none — Goish glue: builds a Go-shaped Flag from the port's
    // typed FlagDef. Go's flags ARE Flags; goish's are typed cells, so
    // the Flag is constructed on demand and returned owned rather than
    // as the *Flag pointer Go hands out of its `formal` map.
    fn __as_flag(d: &FlagDef) -> Flag {
        let v = kindValue {
            kind: d.kind.clone(),
        };
        let def_value = Value::String(&v);
        let f = Flag {
            Name: d.name.clone(),
            Usage: d.usage.clone(),
            Value: alloc::boxed::Box::new(v),
            DefValue: def_value,
        };
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
