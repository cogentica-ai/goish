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
// API surface — `IsNil`, `Get`, equality with `Nil`, Deref<Target=T>
// that panics on nil (matching Go's runtime nil-deref behaviour).
// Keeps the `*T` shape without exposing Rust's `Option`/`is_some`/
// `if let Some(x)` idioms at user-visible call sites.
//
// API surface (mirrors Go's `*T` behaviour where possible):
//
//   nilable::new(t)       — wrap an owned T (non-nil)
//   nilable::nil()        — the nil pointer (alias of Default::default)
//   x.IsNil()             — does this hold nil?
//   x.Get()               — &T, panics on nil (read-side dispatch)
//   x.GetMut()            — &mut T, panics on nil (write-side dispatch)
//   x.Unwrap()            — T (consuming), panics on nil
//   *x                    — Deref<Target=T>, panics on nil (matches
//                           Go's `*p` runtime panic for nil p)
//   x == nil / nil == x   — false unless x.IsNil()
//   x.field, x.Method(…)  — auto-deref through Deref chain
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

    /// Borrow the inner T, panicking on nil. Mirrors Go's runtime
    /// nil-pointer deref panic.
    #[inline]
    #[track_caller]
    pub fn Get(&self) -> &T {
        match &self.0 {
            Some(t) => t,
            None => nil_deref_panic(),
        }
    }

    /// Mutably borrow the inner T, panicking on nil.
    #[inline]
    #[track_caller]
    pub fn GetMut(&mut self) -> &mut T {
        match &mut self.0 {
            Some(t) => t,
            None => nil_deref_panic(),
        }
    }

    /// Consume the nilable and return the inner T, panicking on nil.
    /// Useful when the user asserts non-nil and wants ownership.
    #[inline]
    #[track_caller]
    pub fn Unwrap(self) -> T {
        match self.0 {
            Some(t) => t,
            None => nil_deref_panic(),
        }
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
// and method dispatch flow naturally without explicit `.Get()` calls.
impl<T> Deref for nilable<T> {
    type Target = T;
    #[inline]
    #[track_caller]
    fn deref(&self) -> &T {
        self.Get()
    }
}

impl<T> DerefMut for nilable<T> {
    #[inline]
    #[track_caller]
    fn deref_mut(&mut self) -> &mut T {
        self.GetMut()
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
