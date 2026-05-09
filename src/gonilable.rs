// nilable — Goish's `*T` representation for pointer types that may
// carry nil.
//
// Why this exists
// ───────────────
//
// Go's `*T` is "either a pointer to a T, or nil". Goish previously
// mapped `*T` to Rust's `&T`/`&mut T`, which has no null state. That
// works for non-nil pointer flows (method receivers, owned-then-passed
// args) but breaks the common `func F() (*T, error) { return nil,
// err }` pattern — there's no Rust value to put in the pointer slot
// when the construction failed.
//
// `nilable<T>` is a thin newtype around `Option<T>` with a Go-idiomatic
// API surface — `IsNil`, equality with `Nil`, Deref<Target=T> that
// panics on nil (matching Go's runtime nil-deref behaviour). Keeps the
// `*T` shape without exposing Rust's `Option`/`is_some`/`if let
// Some(x)` idioms at user-visible call sites.
//
// API surface (mirrors Go's `*T` behaviour where possible):
//
//   nilable::new(t)       — wrap an owned T (non-nil)
//   nilable::nil()        — the nil pointer (alias of Default::default)
//   x.IsNil()             — does this hold nil?
//   *x                    — Deref<Target=T>, panics on nil (matches
//                           Go's `*p` runtime panic for nil p)
//   x == nil / nil == x   — false unless x.IsNil()
//   x.field, x.Method(…)  — auto-deref through Deref chain
//
// Panic-bearing extractors (Go-style `Must` prefix — only the
// transpiler emits these inside scopes it has flow-proven non-nil;
// hand-written Goish code generally uses `Try`/`IfNotNil`/`OrDefault`
// instead). Naming follows Go's `regexp.MustCompile` convention: the
// `Must` prefix signals "panics if the precondition fails":
//
//   x.Must()         — &T, panics on nil (paired with Try)
//   x.MustMut()      — &mut T, panics on nil (paired with TryMut)
//   x.MustTake()     — T (consuming), panics on nil (paired with Take)
//
// Goro: Go-idioms-first — call sites read like Go (`if id == nil`,
// `id.Method()`, `*id = …`), Rust idioms (Some/None, ?, etc.) stay
// behind the wrapper.

#![allow(non_snake_case, non_camel_case_types)]

use core::ops::{Deref, DerefMut};

use crate::nilval::Nil;

/// `nilable<T>` — Goish's `*T` shape with a Go-idiomatic API.
#[repr(transparent)]
#[derive(Clone)]
pub struct nilable<T>(Option<T>);

impl<T> nilable<T> {
    /// Wrap an owned T as a non-nil nilable. Mirrors Go's `&T{…}`
    /// construction.
    #[inline]
    pub fn new(value: T) -> Self {
        nilable(Some(value))
    }

    /// The nil nilable. Alias of `Default::default()` — kept as a
    /// const-callable construction path for sentinel-style usage.
    #[inline]
    pub const fn nil() -> Self {
        nilable(None)
    }

    /// Is this the nil pointer?
    #[inline]
    pub fn IsNil(&self) -> bool {
        self.0.is_none()
    }

    /// Borrow the inner T, panicking on nil. Go-style `Must` prefix
    /// signals that the precondition (non-nil) is asserted by the
    /// caller; failure crashes loudly. Pairs with `Try()` (which
    /// returns `Option<&T>`). Transpiler emits this inside scopes
    /// it has flow-proven non-nil — never as auto-deref.
    #[inline]
    #[track_caller]
    pub fn Must(&self) -> &T {
        match &self.0 {
            Some(t) => t,
            None => nil_deref_panic(),
        }
    }

    /// Mutably borrow the inner T, panicking on nil. Pairs with
    /// `TryMut()`. Same `Must` rationale as `Must()`.
    #[inline]
    #[track_caller]
    pub fn MustMut(&mut self) -> &mut T {
        match &mut self.0 {
            Some(t) => t,
            None => nil_deref_panic(),
        }
    }

    /// Consume the nilable and return the inner T, panicking on nil.
    /// Pairs with `Take()` (which returns `Option<T>`). Useful when
    /// the caller wants ownership of the inner value.
    #[inline]
    #[track_caller]
    pub fn MustTake(self) -> T {
        match self.0 {
            Some(t) => t,
            None => nil_deref_panic(),
        }
    }

    // ─── Safe (non-panicking) accessors ───────────────────────────
    //
    // The canonical Go-idiomatic pattern for nil-safety is:
    //
    //     if !p.IsNil() {
    //         use(*p);  // Deref panics, but we just guarded
    //     }
    //
    // The helpers below cover the cases where that pattern is
    // cumbersome. None of them panic — pick whichever fits the call
    // site's shape.

    /// Safe shared borrow — `Some(&T)` if non-nil, `None` if nil.
    /// Use with `if let Some(t) = p.Try() { … }` for pattern-match
    /// style, or `p.Try().map(|t| …)` for chained transforms.
    #[inline]
    pub fn Try(&self) -> Option<&T> {
        self.0.as_ref()
    }

    /// Safe mutable borrow — `Some(&mut T)` if non-nil, `None` if nil.
    #[inline]
    pub fn TryMut(&mut self) -> Option<&mut T> {
        self.0.as_mut()
    }

    /// Cloned-or-default — return a clone of the inner T, or
    /// `T::default()` if nil. Mirrors Go's "nil-tolerant" idiom
    /// where reads from a nil pointer return the zero value (NOT
    /// what Go does at the language level, but what user-defined
    /// methods on pointer types often do).
    #[inline]
    pub fn OrDefault(&self) -> T
    where
        T: Default + Clone,
    {
        self.0.clone().unwrap_or_default()
    }

    /// Cloned-or-fallback — return a clone of the inner T, or call
    /// `f()` if nil. Lets the caller compute a fallback lazily.
    #[inline]
    pub fn OrElse<F>(&self, f: F) -> T
    where
        T: Clone,
        F: FnOnce() -> T,
    {
        self.0.clone().unwrap_or_else(f)
    }

    /// Apply `f` if non-nil, returning `Some(f(&t))`; `None` if nil.
    /// Useful for read-only transforms: `p.If(|t| t.Len()).
    /// unwrap_or(0)`.
    #[inline]
    pub fn If<R, F>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        self.0.as_ref().map(f)
    }

    /// Apply `f` if non-nil, mutating in place; no-op if nil.
    /// Returns `true` when the closure ran (non-nil), `false` on nil
    /// — handy for `if !p.IfMut(|t| …) { handle_nil(); }`.
    #[inline]
    pub fn IfMut<F>(&mut self, f: F) -> bool
    where
        F: FnOnce(&mut T),
    {
        match &mut self.0 {
            Some(t) => {
                f(t);
                true
            }
            None => false,
        }
    }

    /// Take the inner T, leaving nil behind. Returns `None` if
    /// already nil, `Some(t)` otherwise. Mirrors `Option::take`.
    #[inline]
    pub fn Take(&mut self) -> Option<T> {
        self.0.take()
    }
}

#[cold]
#[inline(never)]
#[track_caller]
fn nil_deref_panic() -> ! {
    panic!("nil-pointer deref")
}

impl<T> Default for nilable<T> {
    #[inline]
    fn default() -> Self {
        nilable(None)
    }
}

// `*x` — Go's pointer deref. Panics on nil to match Go's runtime
// behaviour. Auto-deref through this lets `x.field`, `x.Method(...)`,
// and method dispatch flow naturally. The Go-style `Must` prefix on
// helpers signals the panic-on-precondition shape — no collision with
// user-Go method names like `Get` / `Unwrap`.
//
// NOTE (2026-05-09): the user-directive policy is to remove these
// `Deref`/`DerefMut` impls in a later slice so unguarded `*p` /
// `p.field` becomes a Rust compile error. Until then, transpiler-
// emitted code goes through `Must`/`MustMut` explicitly, and the
// auto-deref path remains for hand-written runtime call sites that
// haven't been migrated yet.
impl<T> Deref for nilable<T> {
    type Target = T;
    #[inline]
    #[track_caller]
    fn deref(&self) -> &T {
        self.Must()
    }
}

impl<T> DerefMut for nilable<T> {
    #[inline]
    #[track_caller]
    fn deref_mut(&mut self) -> &mut T {
        self.MustMut()
    }
}

// Equality with the universal Nil sentinel — `if x == nil { … }` and
// `if nil == x { … }`. Symmetric impls.
impl<T> PartialEq<Nil> for nilable<T> {
    #[inline]
    fn eq(&self, _: &Nil) -> bool {
        self.IsNil()
    }
}

impl<T> PartialEq<nilable<T>> for Nil {
    #[inline]
    fn eq(&self, other: &nilable<T>) -> bool {
        other.IsNil()
    }
}

// `nilable<T> == nilable<T>` — needed when user code holds two
// pointers and compares them. Only delegates to T's PartialEq when
// both are non-nil; two nils are equal; mixed nil/non-nil are not.
impl<T: PartialEq> PartialEq for nilable<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Eq> Eq for nilable<T> {}

// `From<T>` is intentionally NOT implemented here — it would conflict
// with the blanket `From<T> for T` (instantiating T = nilable<T>) and
// with `From<Nil> for nilable<T>` when T = Nil. The transpiler emits
// `nilable::new(<expr>)` explicitly at constructor sites.

// `From<Nil>` — `let x: nilable<T> = nil.into();` and the auto-coerce
// at `nil` literals in nilable<T>-typed slots.
impl<T> From<Nil> for nilable<T> {
    #[inline]
    fn from(_: Nil) -> Self {
        nilable::nil()
    }
}

// Display / Debug forwarders — delegate to the inner T so user
// formatting code (println, fmt::Errorf with %v) prints something
// useful. nil prints as "<nil>" matching Go's fmt %v on nil pointers.
impl<T: core::fmt::Debug> core::fmt::Debug for nilable<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Some(t) => t.fmt(f),
            None => f.write_str("<nil>"),
        }
    }
}

impl<T: core::fmt::Display> core::fmt::Display for nilable<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Some(t) => t.fmt(f),
            None => f.write_str("<nil>"),
        }
    }
}
