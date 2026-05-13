// log/slog — Go's `log/slog` structured-logging package (Go 1.21+).
//
// Minimal Goish surface stub. The full Go API is sprawling; this file
// carries just enough to round-trip the types used by external loggers
// (logr, klog, etc.) that bridge to slog. Real slog consumption inside
// goish code routes through `goish::log::Println`/`Printf`; the slog
// surface here is for *interop* — letting ported code accept and
// forward slog handlers without redefining them.
//
// What's stubbed (signatures match Go, bodies are no-ops or pass-through):
//
//   slog::Level             // type alias for int (Info=0, Warn=4, Error=8 …)
//   slog::LevelInfo etc.    // canonical level constants
//   slog::Kind              // attribute-value tag
//   slog::Attr              // {Key, Value}
//   slog::Value             // typed value carrier
//   slog::Record            // Time + Level + Message + PC + iter(Attr)
//   slog::Handler trait     // Enabled/Handle/WithAttrs/WithGroup
//   slog::Logger            // wraps a Handler; bridges to logr
//   slog::New(handler)      // Logger constructor
//   slog::NewRecord(...)    // Record constructor
//   slog::String/Any/...    // typed Attr constructors
//
// Deliberately deferred: actual JSON/text rendering, source-line
// capture, group-prefix bookkeeping. Ports that bridge to slog use
// these stubs to satisfy types; the receiving end is the slog impl
// in the *consumer*, not goish-side.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::sync::Arc;

use crate::context;
use crate::errors::error;
use crate::goany::Any as GoishAny;
use crate::goslice::slice;
use crate::gostring::string;
use crate::time;
use crate::types::int;

// ─── Level ──────────────────────────────────────────────────────────
//
// Go's `slog.Level` is `int` with named constants. We use a transparent
// tuple-struct wrapper so it carries a distinct type identity at the
// type system (vs raw `int`), matching what goishc emits for named
// scalar types.

#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct Level(pub int);

impl From<int> for Level {
    fn from(v: int) -> Self {
        Level(v)
    }
}

pub const LevelDebug: Level = Level(-4);
pub const LevelInfo: Level = Level(0);
pub const LevelWarn: Level = Level(4);
pub const LevelError: Level = Level(8);

// ─── Kind ───────────────────────────────────────────────────────────
//
// The tag identifying a slog.Value's inner type. Defined as named
// constants on a `Kind` newtype (matching Go's `slog.Kind`).

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Kind(pub int);

pub const KindAny: Kind = Kind(0);
pub const KindBool: Kind = Kind(1);
pub const KindDuration: Kind = Kind(2);
pub const KindFloat64: Kind = Kind(3);
pub const KindInt64: Kind = Kind(4);
pub const KindString: Kind = Kind(5);
pub const KindTime: Kind = Kind(6);
pub const KindUint64: Kind = Kind(7);
pub const KindGroup: Kind = Kind(8);
pub const KindLogValuer: Kind = Kind(9);

// ─── Value ──────────────────────────────────────────────────────────
//
// Go's slog.Value is a tagged-union over the supported scalar/group
// types. For Goish we carry it as a Kind + a raw Any payload — full
// fidelity isn't required here since the only thing logr does with
// values is forward them to a downstream handler that owns the
// rendering.

#[derive(Default, Clone)]
pub struct Value {
    pub kind: Kind,
    pub any: GoishAny,
}

impl Value {
    pub fn Kind(&self) -> Kind {
        self.kind
    }
    pub fn Any(&self) -> GoishAny {
        self.any.clone()
    }
}

// ─── Attr ───────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct Attr {
    pub Key: string,
    pub Value: Value,
}

// Typed constructors. The trailing `Value` field carries the
// payload; `Kind` is set per-constructor to match Go's slog.

pub fn String<S1: Into<string>, S2: Into<string>>(key: S1, val: S2) -> Attr {
    let v = val.into();
    Attr {
        Key: key.into(),
        Value: Value {
            kind: KindString,
            any: GoishAny::new(v),
        },
    }
}

pub fn Int<S: Into<string>>(key: S, val: int) -> Attr {
    Attr {
        Key: key.into(),
        Value: Value {
            kind: KindInt64,
            any: GoishAny::new(val),
        },
    }
}

pub fn Bool<S: Into<string>>(key: S, val: bool) -> Attr {
    Attr {
        Key: key.into(),
        Value: Value {
            kind: KindBool,
            any: GoishAny::new(val),
        },
    }
}

pub fn Any<S: Into<string>>(key: S, val: error) -> Attr {
    // Go's slog.Any takes `any`; logr only uses it with errors via
    // `slog.Any("error", err)`. Specialising to `error` here matches
    // the call sites we've seen; widen if needed.
    Attr {
        Key: key.into(),
        Value: Value {
            kind: KindAny,
            any: GoishAny::new(val),
        },
    }
}

// ─── Record ─────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct Record {
    pub Time: time::Time,
    pub Level: Level,
    pub Message: string,
    pub PC: crate::types::uintptr,
    attrs: slice<Attr>,
}

impl Record {
    /// Append attributes to the record's attribute list.
    pub fn AddAttrs(&mut self, attr: Attr) {
        self.attrs = crate::append!(self.attrs.clone(), attr);
    }

    /// Iterate the record's attributes, calling `f` for each. Go's
    /// signature is `func(yield func(Attr) bool)` (range-over-func);
    /// we accept a plain `FnMut(Attr)` because the only goish-side
    /// consumer (logr's slogHandler.Handle) doesn't use the bool
    /// short-circuit.
    pub fn Attrs<F: FnMut(Attr)>(&self, mut f: F) {
        let n = self.attrs.Len();
        let mut i: int = 0;
        while i < n {
            f(self.attrs[i].clone());
            i += 1;
        }
    }

    pub fn NumAttrs(&self) -> int {
        self.attrs.Len()
    }
}

/// Construct a fresh Record. Mirrors Go's `slog.NewRecord(t, level, msg, pc)`.
pub fn NewRecord<S: Into<string>>(
    t: time::Time,
    level: Level,
    msg: S,
    pc: crate::types::uintptr,
) -> Record {
    Record {
        Time: t,
        Level: level,
        Message: msg.into(),
        PC: pc,
        attrs: slice::new(),
    }
}

// ─── Handler trait ──────────────────────────────────────────────────
//
// Auto-trait bounds (Send + Sync) so the Arc<dyn Handler + Send + Sync>
// carry shape Goishc emits resolves cleanly.

#[crate::interface]
pub trait Handler: Send + Sync {
    fn Enabled(&self, ctx: &dyn context::Context, level: Level) -> bool;
    fn Handle(&self, ctx: &dyn context::Context, record: Record) -> error;
    fn WithAttrs(&self, attrs: slice<Attr>) -> Arc<dyn Handler + Send + Sync>;
    fn WithGroup(&self, name: string) -> Arc<dyn Handler + Send + Sync>;
}

// ─── discardHandler — internal Default carrier ──────────────────────
//
// Trait-object fields like `handler: Arc<dyn Handler + Send + Sync>`
// can't `#[derive(Default)]` (no Default impl for the trait object).
// We provide one by wrapping a no-op Handler so `Logger::default()`
// works at struct-literal sites that omit the handler — matching
// what goishc emits for `slog.Logger{}` composite literals.

#[derive(Default, Clone)]
struct discardHandler;

impl Handler for discardHandler {
    fn Enabled(&self, _: &dyn context::Context, _: Level) -> bool {
        false
    }
    fn Handle(&self, _: &dyn context::Context, _: Record) -> error {
        crate::errors::nil
    }
    fn WithAttrs(&self, _: slice<Attr>) -> Arc<dyn Handler + Send + Sync> {
        Arc::new(discardHandler)
    }
    fn WithGroup(&self, _: string) -> Arc<dyn Handler + Send + Sync> {
        Arc::new(discardHandler)
    }
}

// ─── Logger ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Logger {
    handler: Arc<dyn Handler + Send + Sync>,
}

impl Default for Logger {
    fn default() -> Self {
        Logger {
            handler: Arc::new(discardHandler),
        }
    }
}

impl Logger {
    pub fn Handler(&self) -> Arc<dyn Handler + Send + Sync> {
        self.handler.clone()
    }
}

/// `slog.New(h)` — bind a Logger to a Handler.
pub fn New(handler: Arc<dyn Handler + Send + Sync>) -> Logger {
    Logger { handler }
}
