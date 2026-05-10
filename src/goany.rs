//! `goish::Any` — Go's `interface{}` (a.k.a. `any`).
//!
//! Newtype around `Arc<dyn core::any::Any + Send + Sync>`. The wrap
//! exists for one specific reason: **to give the type a `Default`
//! impl that doesn't violate the orphan rule**. Rust's coherence
//! refuses `impl Default for Arc<dyn Any+Send+Sync>` because both
//! `Arc` and `Any` are foreign — `Any` (this newtype) is local, so
//! we can land Default plus any other crate-defined trait impls
//! (`From<T>`, `MustAs`, …) cleanly.
//!
//! Layout: `#[repr(transparent)]` — `Any` and the inner Arc have
//! identical ABI / size / alignment. We don't currently exploit
//! that with explicit transmutes, but the guarantee keeps the door
//! open for forwarding through-the-wrap with zero runtime cost
//! later.
//!
//! ## Why a newtype, not a type alias
//!
//! A type alias (`pub type Any = Arc<dyn Any+Send+Sync>`) would
//! still hit the orphan rule for Default. The newtype is the
//! cheapest path to a complete trait surface.
//!
//! ## What lives on `Any`
//!
//! - `Default::default()` → `Any` wrapping `__NilMarker` (the
//!   distinguished "this came from `nil`" sentinel; matches the
//!   nil-equality contract in nilval.rs).
//! - `Any::new<T>(v)` → upcast any `T: 'static + Send + Sync` to
//!   `Any`.
//! - `Any::As<T>()` / `Any::MustAs<T>()` → downcast (Option / panic).
//! - `Any::IsNil()` → recognises the `nil`-shape (matches nilval.rs's
//!   `__NilMarker` / `()` predicates).
//! - `From<Nil>` → bare `nil.into()` produces `Any`.
//! - `PartialEq<Nil>` → `if x == nil` works on Any-typed bindings.
//!
//! Format and Reflect impls live in their respective modules
//! (fmt/mod.rs, reflect/mod.rs) and forward through `.0`.
//!
//! ## Migration from `Arc<dyn Any+Send+Sync>`
//!
//! The transpiler's `interface{}` lowering used to spell as
//! `alloc::sync::Arc<dyn core::any::Any + Send + Sync>` directly;
//! it now spells as `goish::Any`. Every existing impl living on the
//! raw Arc form is mirrored here so call-site behaviour stays
//! identical.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::sync::Arc;
use core::any::Any as CoreAny;

use crate::nilval::Nil;

/// `interface{}` / `any`. See module docs.
#[repr(transparent)]
#[derive(Clone)]
pub struct Any(pub(crate) Arc<dyn CoreAny + Send + Sync>);

impl Any {
    /// Wrap an owned value of any `T: 'static + Send + Sync`. This is
    /// the upcast path — Pattern F in the transpiler emits this at
    /// `interface{}` slot positions for owned-T expressions.
    #[inline]
    pub fn new<T: 'static + Send + Sync>(value: T) -> Self {
        Any(Arc::new(value))
    }

    /// `&dyn Any` borrow at the inner Arc. Used by Format / Reflect
    /// forwarders and by the type-assertion lowering.
    #[inline]
    pub fn as_any(&self) -> &(dyn CoreAny + Send + Sync) {
        self.0.as_ref()
    }

    /// Goish equivalent of Go's comma-ok type assertion `v, ok := x.(T)`.
    /// Returns `Some(&T)` when the wrapped value's runtime type is `T`.
    #[inline]
    pub fn As<T: 'static>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }

    /// Same as `As<T>()` — kept under the Rust-conventional name so the
    /// transpiler's type-switch lowering (`switch v := node.(type) {
    /// case T1: …; case T2: … }`) which calls `downcast_ref` on the
    /// scrutinee compiles unchanged. Rust's `Arc<dyn Any>` exposes
    /// `downcast_ref` natively; the newtype mirrors that surface.
    #[inline]
    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }

    /// Goish equivalent of Go's must-form type assertion `x.(T)` —
    /// panics on miss with a Go-shape diagnostic. The `interface
    /// conversion: …` text matches Go's runtime panic so log output
    /// reads naturally for ports.
    #[inline]
    pub fn MustAs<T: 'static>(&self) -> &T {
        self.As::<T>().unwrap_or_else(|| {
            panic!(
                "interface conversion: any is not {}",
                core::any::type_name::<T>()
            )
        })
    }

    /// True iff this `Any` was produced from `nil` (or is the
    /// equivalent zero-value `()`-payload). Mirrors the predicate
    /// used by the `PartialEq<Nil>` impl on the raw Arc form so
    /// `if x == nil { … }` and `x.IsNil()` agree.
    #[inline]
    pub fn IsNil(&self) -> bool {
        let any: &(dyn CoreAny + Send + Sync) = self.0.as_ref();
        any.is::<__NilMarker>() || any.is::<()>()
    }
}

/// Default → wraps `__NilMarker`, the nil-shape sentinel. Matches the
/// existing `From<Nil> for Arc<dyn Any+Send+Sync>` payload exactly
/// so partially-keyed struct literals fill `Any` fields with the
/// same value `nil.into()` would have produced.
impl Default for Any {
    #[inline]
    fn default() -> Self {
        Any(Arc::new(__NilMarker))
    }
}

/// Bare `nil` → `Any` via `nil.into()` at return / let / struct-field
/// positions. Matches nilval.rs's `From<Nil> for Arc<dyn Any+...>`.
impl From<Nil> for Any {
    #[inline]
    fn from(_: Nil) -> Self {
        Any(Arc::new(__NilMarker))
    }
}

impl PartialEq<Nil> for Any {
    #[inline]
    fn eq(&self, _: &Nil) -> bool {
        self.IsNil()
    }
}

impl PartialEq<Any> for Nil {
    #[inline]
    fn eq(&self, other: &Any) -> bool {
        other.IsNil()
    }
}

/// Internal nil-marker for Any. Distinct from nilval.rs's private
/// `__NilMarker` so this module is self-contained; both render to the
/// same nil-shape for IsNil purposes via the `is::<__NilMarker>()`
/// downcast probe.
struct __NilMarker;

/// Reflect for the local marker so `Any::default().Kind()` returns
/// `Invalid` (matching Go's `reflect.ValueOf(nil).Kind()`).
impl crate::reflect::Reflect for __NilMarker {
    fn __reflect_type() -> crate::reflect::Type {
        crate::reflect::Type::__new(crate::reflect::Kind::Invalid, "", &[])
    }
    fn __reflect_value(&self) -> crate::reflect::Value {
        crate::reflect::Value::Invalid
    }
}
