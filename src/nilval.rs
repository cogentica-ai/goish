//! `Nil` — Goish's polymorphic zero-value sentinel.
//!
//! Mirrors Go's untyped `nil` constant: a single identifier that
//! flows into any nilable type via `From<Nil>` impls living in each
//! type's own module. Stable Rust forces one concession — `.into()`
//! is mandatory at return / let / struct-field positions because
//! the language doesn't auto-call `From` there.
//!
//! ## Where bare `nil` works (no `.into()` needed)
//!
//! - **Function arg with `impl Into<T>`**: `mux.Handle("/", nil)`
//!   if the parameter is `H: Into<…>`.
//! - **Equality**: `if err == nil { … }` and `if nil != err { … }`
//!   via per-type `PartialEq<Nil>` impls.
//! - **Generic over `From<Nil>`**: `fn zero<T: From<Nil>>() -> T`.
//!
//! ## Where `.into()` is required
//!
//! - **Return**: `fn foo() -> error { nil.into() }`.
//! - **Let binding**: `let e: error = nil.into();`.
//! - **Struct field**: `Cookie { name: nil.into(), … }`.
//! - **Match arm value**: `match x { _ => nil.into() }`.
//!
//! ## Crate-internal access to the typed nil-error
//!
//! Goish's own `errors` module needs the **typed** `error(None)`
//! sentinel for chain walking, ErrorTrait::Unwrap defaults, etc.
//! That value is still `errors::nil: error` — kept as a typed
//! constant. External callers should use the polymorphic `nil`
//! (this module) plus `.into()` instead.

#![allow(non_upper_case_globals, non_camel_case_types)]

/// The polymorphic-nil sentinel type. Zero-sized; users never
/// construct it directly — they use the `nil` constant.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct Nil;

/// `nil` — Goish's polymorphic zero value.
pub const nil: Nil = Nil;

// ─── Polymorphic nil for Arc<dyn Any + Send + Sync> ───────────────────
//
// Goish models Go's `interface{}` as `Arc<dyn core::any::Any + Send +
// Sync>`. Go lets `var x interface{} = nil; if x == nil` work
// directly; the goish equivalent needs the standard polymorphic-nil
// triple (From / PartialEq both directions) on the Arc-of-Any type.
// Lives here rather than per-module because Nil is defined here and
// the impls coherence-wise belong with the upstream type.

extern crate alloc;

/// `nil` → `Arc<dyn Any>` materialises as a `__NilMarker` Arc — a
/// distinguishable shape that PartialEq can recognise. Used in
/// `let x: Arc<dyn Any> = nil.into();` returns and tuple slots.
impl From<Nil> for alloc::sync::Arc<dyn core::any::Any + Send + Sync> {
    fn from(_: Nil) -> Self {
        alloc::sync::Arc::new(__NilMarker)
    }
}

/// Compare an `Arc<dyn Any>` against bare `nil`. True when the
/// underlying Any is `__NilMarker` (the nil-built shape) or `()` (a
/// common stub payload other places use to mean "no real value").
impl PartialEq<Nil> for alloc::sync::Arc<dyn core::any::Any + Send + Sync> {
    fn eq(&self, _: &Nil) -> bool {
        let any: &(dyn core::any::Any + Send + Sync) = self.as_ref();
        any.is::<__NilMarker>() || any.is::<()>()
    }
}
impl PartialEq<alloc::sync::Arc<dyn core::any::Any + Send + Sync>> for Nil {
    fn eq(&self, other: &alloc::sync::Arc<dyn core::any::Any + Send + Sync>) -> bool {
        other.eq(self)
    }
}

/// Internal marker carried by the `nil → Arc<dyn Any>` conversion so
/// PartialEq can recognise the nil-shape Arc at runtime. Never exposed
/// to user code.
struct __NilMarker;
