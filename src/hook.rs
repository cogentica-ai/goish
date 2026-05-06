// hook — package-level mutable trait pointer (Go's `var X SomeIface;
// func Register(t SomeIface) { X = t }` pattern).
//
// Why this exists: Go encodes hot-swappable behaviour as a package-
// level `var X SomeInterface` that callers replace via a `Register`
// function. Rust statics are immutable; making them mutable requires
// interior mutability + Sync. Plus the value is a `dyn Trait` (un-
// sized), so the cell needs to hold `Box<dyn Trait>` rather than the
// trait directly. `Hook<T>` wraps that combination.
//
// Goishc emits package-level `var X UserInterface` as
// `static X: Hook<dyn UserInterface + Send + Sync> = Hook::new();`
// and rewrites every use site:
//   `X = t`      → `X.set(Box::new(t))`
//   `X == nil`   → `!X.is_set()`
//   `X != nil`   → `X.is_set()`
//   `X.M(args)`  → `X.call(|h| h.M(args))`
//
// The `call` form returns `Option<R>` so missing-hook is observable
// without a panic. Free functions that wrap the call with a nil-check
// can `.unwrap()` once they know the hook is set.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::boxed::Box;

use crate::runtime::spin::SpinLock;

/// Package-level mutable trait pointer.
pub struct Hook<T: ?Sized + Send + Sync + 'static> {
    inner: SpinLock<Option<Box<T>>>,
}

impl<T: ?Sized + Send + Sync + 'static> Hook<T> {
    /// `const fn new` so the struct can be used in `static` slots.
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(None),
        }
    }

    /// Install or replace the hook value.
    pub fn set(&self, t: Box<T>) {
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

    /// Run `f` with `&mut T` if a hook is installed, returning the
    /// result wrapped in `Some`. Returns `None` if no hook.
    pub fn call<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut g = self.inner.lock();
        g.as_mut().map(|t| f(&mut **t))
    }
}

impl<T: ?Sized + Send + Sync + 'static> Default for Hook<T> {
    fn default() -> Self {
        Self::new()
    }
}

// Per-trait `From<Nil> for Box<dyn T + Send + Sync>` impls live in each
// trait's module (e.g. `net::http::RoundTripper`). The standard goish
// pattern: any trait whose value can be `nil`-returned in Go gets the
// triple in priority #5 plus a stub impl that panics if a method is
// invoked through the nil sentinel. The boxed shape is the carrier.
