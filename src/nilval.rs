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
///
/// `Nil` doubles as the payload sentinel for `Arc<dyn Any>` /
/// `goish::Any` / `Arc<dyn AnyReflect>` shapes. Putting `Nil` inside
/// the Arc means `is::<Nil>()` recognises the nil-shape — there's
/// exactly one nil concept in the runtime, no separate marker types.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct Nil;

/// `nil` — Goish's polymorphic zero value. Single source of truth for
/// every nil-shape construction in the crate; per-type `From<Nil>`
/// and `PartialEq<Nil>` impls route everything through this constant.
pub const nil: Nil = Nil;

// ─── Polymorphic nil for Arc<dyn Any + Send + Sync> ───────────────────
//
// Goish models Go's `interface{}` as `Arc<dyn core::any::Any + Send +
// Sync>` (or the `goish::Any` newtype around it). Go lets
// `var x interface{} = nil; if x == nil` work directly; the goish
// equivalent needs `From<Nil>` + `PartialEq<Nil>` (both directions)
// on the Arc-of-Any type. The Arc payload IS `Nil` itself — single
// nil semantics, no separate `__NilMarker` ZST.

extern crate alloc;

/// `nil.into()` at an `Arc<dyn Any>` slot materialises as
/// `Arc::new(Nil)` — the wrapped value is the universal `Nil`
/// sentinel itself. `is::<Nil>()` then recognises the nil-shape.
impl From<Nil> for alloc::sync::Arc<dyn core::any::Any + Send + Sync> {
    fn from(_: Nil) -> Self {
        alloc::sync::Arc::new(nil)
    }
}

/// Compare an `Arc<dyn Any>` against bare `nil`. True when the
/// underlying Any is `Nil` (built from `nil.into()`) or `()` (a
/// stub payload other places use to mean "no real value").
impl PartialEq<Nil> for alloc::sync::Arc<dyn core::any::Any + Send + Sync> {
    fn eq(&self, _: &Nil) -> bool {
        let any: &(dyn core::any::Any + Send + Sync) = self.as_ref();
        any.is::<Nil>() || any.is::<()>()
    }
}
impl PartialEq<alloc::sync::Arc<dyn core::any::Any + Send + Sync>> for Nil {
    fn eq(&self, other: &alloc::sync::Arc<dyn core::any::Any + Send + Sync>) -> bool {
        other.eq(self)
    }
}

// Reflect for `Nil` — lets it sit inside `Arc<dyn AnyReflect>` and
// `goish::Any` while reporting `Kind::Invalid` (matches Go's
// `reflect.ValueOf(nil).Kind() == Invalid`).
impl crate::reflect::Reflect for Nil {
    fn __reflect_type() -> crate::reflect::Type {
        crate::reflect::Type::__new(crate::reflect::Kind::Invalid, "", &[])
    }
    fn __reflect_value(&self) -> crate::reflect::Value {
        crate::reflect::Value::Invalid
    }
}

// ─── Polymorphic nil for `Arc<dyn AnyReflect + Send + Sync>` ─────────
//
// Mirrors the `Arc<dyn Any + Send + Sync>` flavour above; same
// `Nil` payload, same recognition predicate. Used by ports that
// take `interface{}` arguments via the reflection-capable carrier
// (typeutils.IsZero, jsonname.GetJSONName, …).

impl From<Nil> for alloc::sync::Arc<dyn crate::reflect::AnyReflect + Send + Sync> {
    fn from(_: Nil) -> Self {
        alloc::sync::Arc::new(nil)
    }
}

impl PartialEq<Nil> for alloc::sync::Arc<dyn crate::reflect::AnyReflect + Send + Sync> {
    fn eq(&self, _: &Nil) -> bool {
        let any: &dyn core::any::Any = (**self).as_any();
        any.is::<Nil>() || any.is::<()>()
    }
}
impl PartialEq<alloc::sync::Arc<dyn crate::reflect::AnyReflect + Send + Sync>> for Nil {
    fn eq(&self, other: &alloc::sync::Arc<dyn crate::reflect::AnyReflect + Send + Sync>) -> bool {
        other.eq(self)
    }
}

// ─── Polymorphic nil for `Arc<dyn Fn(...) -> R + Send + Sync>` ────────
//
// Go function values are nilable; `var f func() error` defaults to nil
// and `if f != nil` is idiomatic. Goish models function values as
// `Arc<dyn Fn(...)>` which is never nil — so the equality is degenerate
// (always returns false / `!=` always returns true). This matches
// observable Go semantics IF no caller passes a nil function value
// across the boundary; with goish Arc, nil-construction isn't even
// expressible, so the user-side check just becomes a constant-true.
//
// For higher-arity / generic-return Fn shapes the user crate can add
// the same impls per-instance — these cover the most common arities
// (0-4 args, generic return).
macro_rules! impl_arc_fn_nil_eq {
    ($($A:ident),*) => {
        impl<$($A: 'static,)* R: 'static> PartialEq<Nil>
            for alloc::sync::Arc<dyn Fn($($A),*) -> R + Send + Sync>
        {
            fn eq(&self, _: &Nil) -> bool { false }
        }
        impl<$($A: 'static,)* R: 'static>
            PartialEq<alloc::sync::Arc<dyn Fn($($A),*) -> R + Send + Sync>> for Nil
        {
            fn eq(&self, _: &alloc::sync::Arc<dyn Fn($($A),*) -> R + Send + Sync>) -> bool { false }
        }
    };
}

impl_arc_fn_nil_eq!();
impl_arc_fn_nil_eq!(A1);
impl_arc_fn_nil_eq!(A1, A2);
impl_arc_fn_nil_eq!(A1, A2, A3);
impl_arc_fn_nil_eq!(A1, A2, A3, A4);
