// sync/atomic/value — Go 1.25.5 src/sync/atomic/value.go.
//
// One `.rs` per `.go` (§33).
//
// Go's `atomic.Value` is untyped and PANICS on a type change; goish's
// is generic over T, which makes the inconsistently-typed case
// unrepresentable rather than a runtime panic — the same
// generic-vs-any trade sync::Pool and sync::Map make.

#![allow(non_snake_case)]

// ─── Value<T> ─────────────────────────────────────────────────────
//
// Reference: /share/go/src/sync/atomic/value.go (194 LOC).
//
// Slim deviations from Go (documented):
//
//   * `Value<T>` is generic over the stored type `T` rather than `any`.
//     Goish has static dispatch — same trade-off as `sync::Pool`,
//     `sync::Map`, `sync::singleflight::Group`. The "inconsistent type"
//     panic in Go's Store/Swap/CompareAndSwap is removed: the type is
//     pinned at the type level, not at runtime.
//
//   * `Load` and `Swap` return `(T, bool)` (Goish ok-pattern) instead
//     of returning `nil` for uninitialized state. The bool is `true`
//     iff a Store has occurred. `T: Default` is required so we can
//     return a zero value alongside `false`. Mirrors `gomap.Get` /
//     `chan.Recv`.
//
//   * `Store(nil)` panic is dropped: there is no `nil` for arbitrary
//     `T` in Goish. Callers wanting "store-or-clear" semantics should
//     use `Value<Option<U>>` directly.
//
//   * Backing store is `Mutex<Option<T>>`. Go's lock-free two-pointer
//     dance over `unsafe.Pointer` (efaceWords) can't be replicated
//     across `T` of arbitrary size in Rust without per-T specialization.
//     The Mutex path is correct and matches the public API exactly.

extern crate alloc;
use crate::sync::Mutex;

// Go: value.go:16
//   type Value struct { v any }
/// `atomic.Value` — atomic load/store/swap of a typed value.
///
/// The zero value (constructed via [`Value::new`]) reports `ok=false`
/// from [`Value::Load`] until the first [`Value::Store`].
///
/// Generic over `T`. Mirrors `sync/atomic.Value` (value.go:16).
pub struct Value<T: Clone + Default + Send + 'static> {
    inner: Mutex<Option<T>>,
}

impl<T: Clone + Default + Send + 'static> Value<T> {
    // go: none — goish-only: Go's zero Value IS the empty one, so it
    // declares no constructor. Rust needs one.
    /// Build an empty Value.
    pub const fn new() -> Self {
        return Value {
            inner: Mutex::new(None),
        };
    }

    // go: sdk 1.25.5 sync/atomic/value.go:28-40 Value.Load
    // Go: value.go:28
    //   func (v *Value) Load() (val any) { ... }
    /// Returns the value set by the most recent Store, plus `ok=true`.
    /// If no Store has occurred, returns `(T::default(), false)`.
    pub fn Load(&self) -> (T, bool) {
        return match self.inner.Lock().clone() {
            Some(v) => (v, true),
            None => (T::default(), false),
        };
    }

    // go: sdk 1.25.5 sync/atomic/value.go:47-83 Value.Store
    // Go: value.go:47
    //   func (v *Value) Store(val any) { ... panics on nil / inconsistent type }
    /// Sets the value of the [`Value`] to `val`.
    pub fn Store(&self, val: T) {
        *self.inner.Lock() = Some(val);
    }

    // go: sdk 1.25.5 sync/atomic/value.go:90-128 Value.Swap
    // Go: value.go:90
    //   func (v *Value) Swap(new any) (old any) { ... }
    /// Stores `new` and returns the previous value plus `ok=true`. If
    /// the Value was empty, returns `(T::default(), false)` and stores
    /// `new`.
    pub fn Swap(&self, new: T) -> (T, bool) {
        let mut g = self.inner.Lock();
        return match g.replace(new) {
            Some(old) => (old, true),
            None => (T::default(), false),
        };
    }
}

impl<T: Clone + Default + Send + PartialEq + 'static> Value<T> {
    // go: sdk 1.25.5 sync/atomic/value.go:135-190 Value.CompareAndSwap
    // Go: value.go:135
    //   func (v *Value) CompareAndSwap(old, new any) (swapped bool) { ... }
    /// Atomically sets the stored value to `new` if the current stored
    /// value equals `old`. Returns whether the swap was performed.
    /// If the Value is empty, the swap occurs only if `old` equals
    /// `T::default()`.
    pub fn CompareAndSwap(&self, old: T, new: T) -> bool {
        let mut g = self.inner.Lock();
        let hit = match g.as_ref() {
            Some(v) => *v == old,
            None => old == T::default(),
        };
        if !hit {
            return false;
        }
        *g = Some(new);
        return true;
    }
}

impl<T: Clone + Default + Send + 'static> Default for Value<T> {
    // go: none — goish-only: Rust's `Default`, which Go's zero value
    // gives for free. Go declares no counterpart.
    fn default() -> Self {
        return Self::new();
    }
}
