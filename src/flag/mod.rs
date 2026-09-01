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
pub use flag::{
    Bool, CommandLine, Duration, ErrHelp, Flag, Int, Int64, Parse, Parsed, Set, String, Uint,
    UnquoteUsage, Value,
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
    Duration(Arc<SpinLock<crate::time::Duration>>),
    Float64(Arc<SpinLock<float64>>),
    String(Arc<SpinLock<string>>),
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
            FlagKind::Duration(c) => FlagKind::Duration(c.clone()),
            FlagKind::Float64(c) => FlagKind::Float64(c.clone()),
            FlagKind::String(c) => FlagKind::String(c.clone()),
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
    /// Go's `output io.Writer`, nil meaning os.Stderr.
    pub(crate) output: Option<
        Arc<
            crate::sync::Mutex<
                core::cell::UnsafeCell<alloc::boxed::Box<dyn crate::io::Writer + Send>>,
            >,
        >,
    >,
}

pub const fn NewFlagSet() -> FlagSet {
    FlagSet {
        defs: Vec::new(),
        args: Vec::new(),
        parsed: false,
        output: None,
    }
}

impl Default for FlagSet {
    fn default() -> Self {
        NewFlagSet()
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
        self.defs.push(FlagDef {
            name: name.into(),
            usage: usage.into(),
            kind: FlagKind::String(cell.clone()),
            defvalue: __defstr(&FlagKind::String(cell.clone())),
            actual: false,
        });
        FlagHandle { cell }
    }

    pub fn Int<N: Into<string>, U: Into<string>>(
        &mut self,
        name: N,
        default: int,
        usage: U,
    ) -> FlagHandle<int> {
        let cell = Arc::new(SpinLock::new(default));
        self.defs.push(FlagDef {
            name: name.into(),
            usage: usage.into(),
            kind: FlagKind::Int(cell.clone()),
            defvalue: __defstr(&FlagKind::Int(cell.clone())),
            actual: false,
        });
        FlagHandle { cell }
    }

    pub fn Bool<N: Into<string>, U: Into<string>>(
        &mut self,
        name: N,
        default: bool,
        usage: U,
    ) -> FlagHandle<bool> {
        let cell = Arc::new(SpinLock::new(default));
        self.defs.push(FlagDef {
            name: name.into(),
            usage: usage.into(),
            kind: FlagKind::Bool(cell.clone()),
            defvalue: __defstr(&FlagKind::Bool(cell.clone())),
            actual: false,
        });
        FlagHandle { cell }
    }

    pub fn Float64<N: Into<string>, U: Into<string>>(
        &mut self,
        name: N,
        default: float64,
        usage: U,
    ) -> FlagHandle<float64> {
        let cell = Arc::new(SpinLock::new(default));
        self.defs.push(FlagDef {
            name: name.into(),
            usage: usage.into(),
            kind: FlagKind::Float64(cell.clone()),
            defvalue: __defstr(&FlagKind::Float64(cell.clone())),
            actual: false,
        });
        FlagHandle { cell }
    }

    pub fn Args(&self) -> slice<string> {
        slice::__from_vec(self.args.clone())
    }

    pub fn NArg(&self) -> int {
        self.args.len() as int
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
