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
pub use flag::{
    Bool, CommandLine, Duration, Flag, Int, Int64, Parse, Parsed, Set, String, Uint, Value,
};

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::runtime::spin::SpinLock;
use crate::strconv;
use crate::types::{byte, float64, int};

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

pub(crate) enum FlagKind {
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
    name: string,
    usage: string,
    kind: FlagKind,
}

// ─── FlagSet ───────────────────────────────────────────────────────────

pub struct FlagSet {
    defs: Vec<FlagDef>,
    args: Vec<string>, // positional, after parse
    parsed: bool,
}

pub const fn NewFlagSet() -> FlagSet {
    FlagSet {
        defs: Vec::new(),
        args: Vec::new(),
        parsed: false,
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
        });
        FlagHandle { cell }
    }

    pub fn Args(&self) -> slice<string> {
        slice::__from_vec(self.args.clone())
    }

    pub fn NArg(&self) -> int {
        self.args.len() as int
    }

    /// Set assigns a named flag through the same conversion path used by
    /// Parse. It matches Go's FlagSet.Set behavior and is useful when an
    /// embedding command has already parsed its own flag set.
    pub fn Set(&mut self, name: string, value: string) -> error {
        let Some(index) = self.find_def(&name) else {
            let mut message: Vec<byte> = Vec::new();
            message.extend_from_slice(b"flag provided but not defined: -");
            message.extend_from_slice(name.as_bytes());
            return errors::New(string::__from_vec(message));
        };
        return self.apply_value(index, value.as_bytes());
    }

    /// Parse `args` as a command line. Skips arg[0] (program name)
    /// only if you want — typically pass `os::Args().slice(1, len)`.
    pub fn Parse(&mut self, args: &slice<string>) -> error {
        let raw: &[string] = args;
        let mut i = 0usize;
        let n = raw.len();
        while i < n {
            let cur = raw[i].clone();
            let bytes = cur.as_bytes();
            // Stop conditions: no `--` prefix, or bare `--`, or single `-`.
            if bytes.is_empty() || bytes[0] != b'-' {
                break;
            }
            if bytes.len() == 1 {
                break; // bare `-` is a positional
            }
            if bytes == b"--" {
                i += 1; // everything after is positional
                break;
            }
            // Strip leading `-` or `--`.
            let strip = if bytes.len() >= 2 && bytes[1] == b'-' {
                2
            } else {
                1
            };
            let body = &bytes[strip..];
            // Look for `=value`.
            let mut eq_pos: Option<usize> = None;
            for (k, &c) in body.iter().enumerate() {
                if c == b'=' {
                    eq_pos = Some(k);
                    break;
                }
            }
            let (name_b, attached_val): (&[byte], Option<&[byte]>) = match eq_pos {
                Some(k) => (&body[..k], Some(&body[k + 1..])),
                None => (body, None),
            };
            let name = string::from_bytes(name_b);
            // Find matching def.
            let def_idx = match self.find_def(&name) {
                Some(k) => k,
                None => {
                    let mut msg: Vec<byte> = Vec::new();
                    msg.extend_from_slice(b"flag provided but not defined: -");
                    msg.extend_from_slice(name_b);
                    return errors::New(string::__from_vec(msg));
                }
            };
            // Determine the value bytes.
            let val_bytes: Vec<byte> = if let Some(av) = attached_val {
                av.to_vec()
            } else {
                // Consume next arg unless it looks like a flag.
                if i + 1 < n {
                    let nxt = raw[i + 1].clone();
                    let nb = nxt.as_bytes();
                    if !nb.is_empty() && nb[0] == b'-' {
                        // No value; for Bool default to "true".
                        if matches!(self.defs[def_idx].kind, FlagKind::Bool(_)) {
                            b"true".to_vec()
                        } else {
                            let mut msg: Vec<byte> = Vec::new();
                            msg.extend_from_slice(b"flag needs an argument: -");
                            msg.extend_from_slice(name_b);
                            return errors::New(string::__from_vec(msg));
                        }
                    } else {
                        i += 1;
                        nb.to_vec()
                    }
                } else {
                    // No more args.
                    if matches!(self.defs[def_idx].kind, FlagKind::Bool(_)) {
                        b"true".to_vec()
                    } else {
                        let mut msg: Vec<byte> = Vec::new();
                        msg.extend_from_slice(b"flag needs an argument: -");
                        msg.extend_from_slice(name_b);
                        return errors::New(string::__from_vec(msg));
                    }
                }
            };
            // Apply value to the slot.
            let err = self.apply_value(def_idx, &val_bytes);
            if err != nil {
                return err;
            }
            i += 1;
        }
        // Remaining args are positional.
        while i < n {
            self.args.push(raw[i].clone());
            i += 1;
        }
        self.parsed = true;
        nil
    }

    fn find_def(&self, name: &string) -> Option<usize> {
        for (i, d) in self.defs.iter().enumerate() {
            if d.name == *name {
                return Some(i);
            }
        }
        None
    }

    fn apply_value(&mut self, idx: usize, val: &[byte]) -> error {
        match &self.defs[idx].kind {
            FlagKind::String(cell) => {
                *cell.lock() = string::from_bytes(val);
                nil
            }
            FlagKind::Int(cell) => {
                let s = string::from_bytes(val);
                let (n, err) = strconv::Atoi(s);
                if err != nil {
                    return err;
                }
                *cell.lock() = n;
                nil
            }
            FlagKind::Bool(cell) => {
                let s = string::from_bytes(val);
                let (b, err) = strconv::ParseBool(s);
                if err != nil {
                    return err;
                }
                *cell.lock() = b;
                nil
            }
            FlagKind::Float64(cell) => {
                let s = string::from_bytes(val);
                let (f, err) = strconv::ParseFloat(s, 64);
                if err != nil {
                    return err;
                }
                *cell.lock() = f;
                nil
            }
            FlagKind::Int64(cell) => {
                let s = string::from_bytes(val);
                // Go: strconv.ParseInt(value, 0, 64) — base 0, so
                // "0x10" and "0b1010" parse as Go's flag package
                // accepts them, not just decimal.
                let (n, err) = strconv::ParseInt(s, 0, 64);
                if err != nil {
                    return err;
                }
                *cell.lock() = n;
                nil
            }
            FlagKind::Uint(cell) => {
                let s = string::from_bytes(val);
                // Go: strconv.ParseUint(value, 0, strconv.IntSize)
                let (n, err) = strconv::ParseUint(s, 0, 64);
                if err != nil {
                    return err;
                }
                *cell.lock() = n as crate::types::uint;
                nil
            }
            FlagKind::Duration(cell) => {
                let s = string::from_bytes(val);
                // Go: time.ParseDuration(value) — so "-test.timeout=30s"
                // takes a unit suffix, not a bare number.
                let (d, err) = crate::time::ParseDuration(s);
                if err != nil {
                    return err;
                }
                *cell.lock() = d;
                nil
            }
        }
    }

    /// Print one line per registered flag: `  -name  usage` to Stderr.
    /// Minimal — no type/default columns yet.
    pub fn PrintDefaults(&self) {
        let e = crate::os::Stderr();
        for d in &self.defs {
            let mut buf: Vec<byte> = Vec::new();
            buf.extend_from_slice(b"  -");
            buf.extend_from_slice(d.name.as_bytes());
            buf.extend_from_slice(b"  ");
            buf.extend_from_slice(d.usage.as_bytes());
            buf.push(b'\n');
            let _ = e.Write(slice::__from_vec(buf));
        }
    }
}
