// flag — Go's `flag` package, ported (Parser-based, no global state).
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   var name = flag.String(...)          let name = fs.String(...);
//   flag.Parse()                         fs.Parse(&os::Args());
//   fmt.Println(*name)                   Println!(name.Get());
//
// v1 surface:
//
//   pub struct FlagSet { ... }
//   pub fn NewFlagSet() -> FlagSet;
//   impl FlagSet {
//     pub fn String(name, default, usage) -> FlagHandle<string>;
//     pub fn Int(name, default, usage) -> FlagHandle<int>;
//     pub fn Bool(name, default, usage) -> FlagHandle<bool>;
//     pub fn Float64(name, default, usage) -> FlagHandle<float64>;
//     pub fn Parse(&mut self, args: &slice<string>) -> error;
//     pub fn Args(&self) -> &slice<string>;
//     pub fn NArg(&self) -> int;
//     pub fn PrintDefaults(&self);
//   }
//
// **No ErrorHandling, and that is a behavioural divergence, not a
// missing accessor.** Go's `NewFlagSet(name, errorHandling)` takes a
// policy that `Parse` acts on: ContinueOnError returns the error,
// ExitOnError calls `os.Exit(2)` (or 0 for -help), PanicOnError
// panics. goish's `NewFlagSet()` takes neither argument and always
// behaves as ContinueOnError — the error comes back and the process
// keeps running. A program ported from Go that relied on ExitOnError
// to stop on a bad flag will CARRY ON here, which is the sort of
// difference that shows up as odd behaviour rather than a compile
// error. `flag.CommandLine` is Go's ExitOnError set, so this applies
// to top-level `flag.Parse()` too.
//
// Each `String/Int/Bool/Float64` returns a typed `FlagHandle<T>` whose `Get()`
// reads the parsed value. Internally backed by `Arc<SpinLock<T>>` so the
// caller can hold the handle while the `FlagSet` mutates state.
//
// Recognized syntax: `--name`, `--name=value`, `--name value`, `-name`,
// `-name=value`, `-name value`. After `--` the rest is positional args.
//
// v1 deviations from Go:
//   * No global `flag.String` / `flag.Parse` — user constructs a FlagSet.
//   * No type-safe Var() with custom Value interface (defer until traits
//     stabilize for goish).
//   * Bool flags require explicit value (`--verbose=true` or `--verbose true`).
//     Go allows bare `--verbose` to mean true; for v1 we require `=true`
//     after the flag for clarity. (Bare `--verbose` followed by another
//     flag-looking arg works too.)
//   * Usage / PrintDefaults output is minimal — no formatted column.
//   * No SetOutput / SetUsage hooks.

#![allow(non_snake_case)]

mod flag;
pub(crate) use flag::__defstr;
pub use flag::{ErrorHandling, NewFlagSet, Var, ValueHandle};
// `Arg`, `BoolFunc`, `Func` and `Uint64` were ported, anchored and
// counted, and then left out of this list — so `flag::Arg(0)` did not
// compile even though the function existed and worked. `port_coverage`
// counts a declaration by name and cannot see reachability, which is
// exactly the gap ROADMAP §2e is about. Found by removing this file's
// `#![allow(dead_code)]`: a `pub fn` that nothing can reach is dead
// code, and the suppression was the only reason the compiler stayed
// quiet about it.
pub use flag::{
    Arg, Bool, BoolFunc, CommandLine, Duration, ErrHelp, Flag, Func, Int, Int64, Parse, Parsed,
    Set, String, Uint, Uint64, UnquoteUsage, Value,
};

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::gostring::string;
use crate::runtime::spin::SpinLock;
use crate::types::{float64, int};

// ─── FlagHandle<T> handle ────────────────────────────────────────────────────

pub struct FlagHandle<T: Clone> {
    cell: Arc<SpinLock<T>>,
}

impl<T: Clone> FlagHandle<T> {
    pub fn Get(&self) -> T {
        self.cell.lock().clone()
    }
}

impl<T: Clone> Clone for FlagHandle<T> {
    fn clone(&self) -> Self {
        Self {
            cell: self.cell.clone(),
        }
    }
}

// ─── Internal flag entry ───────────────────────────────────────────────

pub enum FlagKind {
    Bool(Arc<SpinLock<bool>>),
    Int(Arc<SpinLock<int>>),
    Int64(Arc<SpinLock<crate::types::int64>>),
    Uint(Arc<SpinLock<crate::types::uint>>),
    Uint64(Arc<SpinLock<crate::types::uint64>>),
    /// Go's `funcValue` — a flag whose "value" is a callback. There is
    /// no cell: the parser hands each occurrence to the function and
    /// the function keeps whatever state it wants.
    Func(Arc<dyn Fn(string) -> crate::errors::error + Send + Sync>),
    /// Go's `boolFuncValue`: the same, but `IsBoolFlag` is true, so
    /// `-v` is legal without a value and the callback gets "true".
    BoolFunc(Arc<dyn Fn(string) -> crate::errors::error + Send + Sync>),
    Duration(Arc<SpinLock<crate::time::Duration>>),
    Float64(Arc<SpinLock<float64>>),
    String(Arc<SpinLock<string>>),
    /// Go's `Var` — a flag whose value is the CALLER's type, supplied
    /// as a `flag.Value`. Every other arm here is a type goish chose;
    /// this is the one that makes the enum open, which is what Go's
    /// extension point requires. See ROADMAP §2p.
    Custom(Arc<SpinLock<alloc::boxed::Box<dyn flag::Value>>>),
}

impl Clone for FlagKind {
    // go: none — Goish glue: FlagKind is goish's own typed-cell enum, so
    // cloning it is cloning the Arcs. Go has no equivalent — its flags
    // hold a Value interface directly and are shared as *Flag.
    fn clone(&self) -> Self {
        let out = match self {
            FlagKind::Bool(c) => FlagKind::Bool(c.clone()),
            FlagKind::Int(c) => FlagKind::Int(c.clone()),
            FlagKind::Int64(c) => FlagKind::Int64(c.clone()),
            FlagKind::Uint(c) => FlagKind::Uint(c.clone()),
            FlagKind::Uint64(c) => FlagKind::Uint64(c.clone()),
            FlagKind::Func(f) => FlagKind::Func(f.clone()),
            FlagKind::BoolFunc(f) => FlagKind::BoolFunc(f.clone()),
            FlagKind::Duration(c) => FlagKind::Duration(c.clone()),
            FlagKind::Float64(c) => FlagKind::Float64(c.clone()),
            FlagKind::String(c) => FlagKind::String(c.clone()),
            FlagKind::Custom(c) => FlagKind::Custom(c.clone()),
        };
        return out;
    }
}

pub(crate) struct FlagDef {
    pub(crate) name: string,
    pub(crate) usage: string,
    pub(crate) kind: FlagKind,
    /// The value the flag was defined with, rendered as Go renders it.
    /// `PrintDefaults` shows it and `isZeroValue` suppresses it. Go
    /// captures this as `Flag.DefValue` at definition time; goish's
    /// typed cells are mutated in place by the parser, so the
    /// definition-time rendering has to be taken before the parse can
    /// change it.
    pub(crate) defvalue: string,
    /// Go keeps a separate `actual` map of the flags that were Set;
    /// `Visit` walks it and `NFlag` counts it.
    pub(crate) actual: bool,
}

// ─── FlagSet ───────────────────────────────────────────────────────────

pub struct FlagSet {
    pub(crate) defs: Vec<FlagDef>,
    pub(crate) args: Vec<string>, // positional, after parse
    pub(crate) parsed: bool,
    /// Go's `name`, which `defaultUsage` prints as "Usage of <name>:".
    ///
    /// `Option` because `CommandLine` is a `static` needing a const
    /// initialiser and goish's `string` is an `Arc<[u8]>`, which has no
    /// const empty. `None` and `Some("")` both mean Go's unnamed set.
    pub(crate) name: Option<string>,
    /// Go's `errorHandling`, which `Parse` acts on. Without it every
    /// set behaved as ContinueOnError — including `CommandLine`, which
    /// Go makes ExitOnError, so a bad flag left the program running on
    /// a default value.
    pub(crate) errorHandling: flag::ErrorHandling,
    /// Go's `output io.Writer`, nil meaning os.Stderr.
    pub(crate) output: Option<
        Arc<
            crate::sync::Mutex<
                core::cell::UnsafeCell<alloc::boxed::Box<dyn crate::io::Writer + Send>>,
            >,
        >,
    >,
}

impl Default for FlagSet {
    /// Go's zero `FlagSet` is ContinueOnError — the zero
    /// `ErrorHandling` — with an empty name.
    fn default() -> Self {
        return flag::NewFlagSet(string::new(), flag::ErrorHandling::ContinueOnError);
    }
}

impl FlagSet {
    pub fn String<N: Into<string>, D: Into<string>, U: Into<string>>(
        &mut self,
        name: N,
        default: D,
        usage: U,
    ) -> FlagHandle<string> {
        let cell = Arc::new(SpinLock::new(default.into()));
        self.__define(name.into(), usage.into(), FlagKind::String(cell.clone()));
        FlagHandle { cell }
    }

    pub fn Int<N: Into<string>, U: Into<string>>(
        &mut self,
        name: N,
        default: int,
        usage: U,
    ) -> FlagHandle<int> {
        let cell = Arc::new(SpinLock::new(default));
        self.__define(name.into(), usage.into(), FlagKind::Int(cell.clone()));
        FlagHandle { cell }
    }

    pub fn Bool<N: Into<string>, U: Into<string>>(
        &mut self,
        name: N,
        default: bool,
        usage: U,
    ) -> FlagHandle<bool> {
        let cell = Arc::new(SpinLock::new(default));
        self.__define(name.into(), usage.into(), FlagKind::Bool(cell.clone()));
        FlagHandle { cell }
    }

    pub fn Float64<N: Into<string>, U: Into<string>>(
        &mut self,
        name: N,
        default: float64,
        usage: U,
    ) -> FlagHandle<float64> {
        let cell = Arc::new(SpinLock::new(default));
        self.__define(name.into(), usage.into(), FlagKind::Float64(cell.clone()));
        FlagHandle { cell }
    }

    pub fn Args(&self) -> slice<string> {
        slice::__from_vec(self.args.clone())
    }

    pub fn NArg(&self) -> int {
        self.args.len() as int
    }

    // go: none — goish-only placement: this FlagSet is hand-written
    // and lives in a module root, where GOISH015 forbids an anchored
    // port. Go's is FlagSet.Arg, flag.go line 720.
    /// `(*FlagSet).Arg(i)` — the i'th remaining
    /// argument, or "" when out of range. Go returns the empty string
    /// rather than panicking, which is what lets `flag.Arg(0)` be read
    /// unguarded.
    pub fn Arg(&self, i: int) -> string {
        if i < 0 || i >= crate::int(self.args.len()) {
            return string::new();
        }
        return self.args[i as usize].clone();
    }

    pub(crate) fn find_def(&self, name: &string) -> Option<usize> {
        for (i, d) in self.defs.iter().enumerate() {
            if d.name == *name {
                return Some(i);
            }
        }
        None
    }
}
