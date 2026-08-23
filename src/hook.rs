// hook — package-level mutable trait pointer (Go's `var X SomeIface;
// func Register(t SomeIface) { X = t }` pattern).
//
// Why this exists: Go encodes hot-swappable behaviour as a package-
// level `var X SomeInterface` that callers replace via a `Register`
// function. Rust statics are immutable; making them mutable requires
// interior mutability + Sync. Plus the value is a `dyn Trait` (un-
// sized), so the cell needs to hold a heap pointer to the trait
// object. `Hook<T>` wraps that combination.
//
// Storage shape — `Arc<T>`, not `Box<T>`. The proc-macro-emitted
// `<T>Ref` newtype that is the canonical user-facing interface-value
// shape ALSO wraps `Arc<dyn T + Send + Sync>`. Aligning the storage
// shapes lets `tracer = t` lower as a single `tracer.set(t.0)` —
// `t.0` is already the right Arc shape, no Box↔Arc conversion noise.
//
// Goishc emits package-level `var X UserInterface` as
// `goish::var! { pub iface X: T; }` (which expands to
// `static X: Hook<dyn T + Send + Sync> = Hook::new();`) and rewrites
// every use site:
//   `X = t`      → `X.set(t.0)` where `t: <T>Ref`
//   `X = nil`    → `X.clear()`
//   `X == nil`   → `!X.is_set()`
//   `X != nil`   → `X.is_set()`
//   `X.M(args)`  → resolves through the `impl T for Hook<dyn T>`
//                   forwarding impl (`#[goish::interface]` emits this)
//
// The forwarding impl gives shared `&T` access to the stored trait
// object — adequate for Go interfaces with `&self` methods. Stateful
// concrete types that need `&mut self` semantics wrap their state
// in `Arc<Mutex<…>>` (the standard interior-mutability pattern) and
// impl the trait on that wrapper.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;

use crate::runtime::spin::SpinLock;

/// Package-level mutable trait pointer.
pub struct Hook<T: ?Sized + Send + Sync + 'static> {
    inner: SpinLock<Option<Arc<T>>>,
}

impl<T: ?Sized + Send + Sync + 'static> Hook<T> {
    /// `const fn new` so the struct can be used in `static` slots.
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(None),
        }
    }

    /// Install or replace the hook value.
    pub fn set(&self, t: Arc<T>) {
        *self.inner.lock() = Some(t);
    }

    /// Uninstall — `is_set()` returns false after this.
    pub fn clear(&self) {
        *self.inner.lock() = None;
    }

    /// Reports whether a hook has been installed.
    pub fn is_set(&self) -> bool {
        self.inner.lock().is_some()
    }

    /// Run `f` with `&T` if a hook is installed, returning the
    /// result wrapped in `Some`. Returns `None` if no hook.
    ///
    /// `&T` (not `&mut T`) — Arc storage gives shared access only.
    /// Stateful interface impls wrap their state in `Arc<Mutex<…>>`.
    pub fn call<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        let g = self.inner.lock();
        g.as_ref().map(|t| f(&**t))
    }

    /// Run `f` with `&T` if a hook is installed; panic with the
    /// supplied message otherwise. Used by `#[goish::interface]`-
    /// generated forwarding impls so user code can call
    /// `tracer.M(args)` directly without a `.call(...).unwrap()`
    /// closure dance. The panic message mirrors Go's nil-method-
    /// dispatch runtime error so debugging signal stays Go-shaped.
    pub fn call_or_panic<R>(&self, nil_msg: &'static str, f: impl FnOnce(&T) -> R) -> R {
        let g = self.inner.lock();
        match g.as_ref() {
            ::core::option::Option::Some(t) => f(&**t),
            ::core::option::Option::None => ::core::panic!("{}", nil_msg),
        }
    }
}

impl<T: ?Sized + Send + Sync + 'static> Default for Hook<T> {
    fn default() -> Self {
        Self::new()
    }
}

// `Hook<T> == nil` / `Hook<T> != nil` — Goish-faithful nil check on
// interface vars. Both `Hook` and `Nil` are local to goish, so the
// orphan rule allows the impls; goishc lowers Go's `tracer == nil`
// directly without a special-case `is_set()` rewrite. Reverse-direction
// impl mirrors `nil == tracer` ergonomics.
impl<T: ?Sized + Send + Sync + 'static> ::core::cmp::PartialEq<crate::Nil> for Hook<T> {
    #[inline]
    fn eq(&self, _: &crate::Nil) -> bool {
        !self.is_set()
    }
}

impl<T: ?Sized + Send + Sync + 'static> ::core::cmp::PartialEq<Hook<T>> for crate::Nil {
    #[inline]
    fn eq(&self, h: &Hook<T>) -> bool {
        !h.is_set()
    }
}

// Per-trait `From<Nil> for Arc<dyn T + Send + Sync>` impls live in
// each trait's module (e.g. `net::http::RoundTripper`). The standard
// Goish pattern: any trait whose value can be `nil`-returned in Go
// gets the triple in priority #5 plus a stub impl that panics if a
// method is invoked through the nil sentinel.
