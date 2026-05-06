// sync/atomic — Go's atomic primitives.
//
// Reference: /share/go/src/sync/atomic/type.go.
//
// Wraps `core::sync::atomic::Atomic*` with Go-shaped methods:
//
//   atomic::Int32     -> Load, Store, Add, Swap, CompareAndSwap, And, Or
//   atomic::Int64     -> Load, Store, Add, Swap, CompareAndSwap, And, Or
//   atomic::Uint32    -> Load, Store, Add, Swap, CompareAndSwap, And, Or
//   atomic::Uint64    -> Load, Store, Add, Swap, CompareAndSwap, And, Or
//   atomic::Uintptr   -> Load, Store, Add, Swap, CompareAndSwap, And, Or
//   atomic::Bool      -> Load, Store, Swap, CompareAndSwap
//
// All methods use `Ordering::SeqCst` to match Go's atomic memory
// model (Go's atomic ops are sequentially consistent across all
// goroutines). The underlying core atomics give us the same
// guarantees.
//
// atomic.Pointer<T> ships as `Pointer<T>` — typed, Arc-backed
// (Go's `*T` ↔ Goish `Option<Arc<T>>`, nil ↔ None). atomic.Value
// is shipped as `Value<T>` — generic rather than untyped (mirror of
// sync::Pool / sync::Map's generic-vs-any trade).
//
// Also omitted: free-function variants (LoadInt32, StoreInt32,
// CompareAndSwapInt32, etc.). Go provides them for legacy reasons;
// the typed-struct API is the post-Go-1.19 idiom.

#![allow(non_snake_case)]

use core::sync::atomic::{
    AtomicBool as CoreBool, AtomicI32 as CoreI32, AtomicI64 as CoreI64,
    AtomicU32 as CoreU32, AtomicU64 as CoreU64, AtomicUsize as CoreUsize,
    Ordering,
};

const ORD: Ordering = Ordering::SeqCst;

// ─── Int32 ────────────────────────────────────────────────────────

/// `atomic.Int32` — atomic 32-bit signed integer. Mirrors
/// `sync/atomic.Int32` (type.go:74).
#[derive(Default)]
pub struct Int32(CoreI32);

impl Int32 {
    pub const fn new(v: i32) -> Self {
        Int32(CoreI32::new(v))
    }
    pub fn Load(&self) -> i32 {
        self.0.load(ORD)
    }
    pub fn Store(&self, v: i32) {
        self.0.store(v, ORD)
    }
    pub fn Add(&self, delta: i32) -> i32 {
        self.0.fetch_add(delta, ORD).wrapping_add(delta)
    }
    pub fn Swap(&self, new: i32) -> i32 {
        self.0.swap(new, ORD)
    }
    pub fn CompareAndSwap(&self, old: i32, new: i32) -> bool {
        self.0.compare_exchange(old, new, ORD, ORD).is_ok()
    }
    pub fn And(&self, mask: i32) -> i32 {
        self.0.fetch_and(mask, ORD)
    }
    pub fn Or(&self, mask: i32) -> i32 {
        self.0.fetch_or(mask, ORD)
    }
}

// ─── Int64 ────────────────────────────────────────────────────────

/// `atomic.Int64`. Mirrors `sync/atomic.Int64` (type.go:107).
#[derive(Default)]
pub struct Int64(CoreI64);

impl Int64 {
    pub const fn new(v: i64) -> Self {
        Int64(CoreI64::new(v))
    }
    pub fn Load(&self) -> i64 {
        self.0.load(ORD)
    }
    pub fn Store(&self, v: i64) {
        self.0.store(v, ORD)
    }
    pub fn Add(&self, delta: i64) -> i64 {
        self.0.fetch_add(delta, ORD).wrapping_add(delta)
    }
    pub fn Swap(&self, new: i64) -> i64 {
        self.0.swap(new, ORD)
    }
    pub fn CompareAndSwap(&self, old: i64, new: i64) -> bool {
        self.0.compare_exchange(old, new, ORD, ORD).is_ok()
    }
    pub fn And(&self, mask: i64) -> i64 {
        self.0.fetch_and(mask, ORD)
    }
    pub fn Or(&self, mask: i64) -> i64 {
        self.0.fetch_or(mask, ORD)
    }
}

// ─── Uint32 ───────────────────────────────────────────────────────

/// `atomic.Uint32`. Mirrors `sync/atomic.Uint32` (type.go:141).
#[derive(Default)]
pub struct Uint32(CoreU32);

impl Uint32 {
    pub const fn new(v: u32) -> Self {
        Uint32(CoreU32::new(v))
    }
    pub fn Load(&self) -> u32 {
        self.0.load(ORD)
    }
    pub fn Store(&self, v: u32) {
        self.0.store(v, ORD)
    }
    pub fn Add(&self, delta: u32) -> u32 {
        self.0.fetch_add(delta, ORD).wrapping_add(delta)
    }
    pub fn Swap(&self, new: u32) -> u32 {
        self.0.swap(new, ORD)
    }
    pub fn CompareAndSwap(&self, old: u32, new: u32) -> bool {
        self.0.compare_exchange(old, new, ORD, ORD).is_ok()
    }
    pub fn And(&self, mask: u32) -> u32 {
        self.0.fetch_and(mask, ORD)
    }
    pub fn Or(&self, mask: u32) -> u32 {
        self.0.fetch_or(mask, ORD)
    }
}

// ─── Uint64 ───────────────────────────────────────────────────────

/// `atomic.Uint64`. Mirrors `sync/atomic.Uint64`.
#[derive(Default)]
pub struct Uint64(CoreU64);

impl Uint64 {
    pub const fn new(v: u64) -> Self {
        Uint64(CoreU64::new(v))
    }
    pub fn Load(&self) -> u64 {
        self.0.load(ORD)
    }
    pub fn Store(&self, v: u64) {
        self.0.store(v, ORD)
    }
    pub fn Add(&self, delta: u64) -> u64 {
        self.0.fetch_add(delta, ORD).wrapping_add(delta)
    }
    pub fn Swap(&self, new: u64) -> u64 {
        self.0.swap(new, ORD)
    }
    pub fn CompareAndSwap(&self, old: u64, new: u64) -> bool {
        self.0.compare_exchange(old, new, ORD, ORD).is_ok()
    }
    pub fn And(&self, mask: u64) -> u64 {
        self.0.fetch_and(mask, ORD)
    }
    pub fn Or(&self, mask: u64) -> u64 {
        self.0.fetch_or(mask, ORD)
    }
}

// ─── Uintptr ──────────────────────────────────────────────────────

// Go: type.go:208
//   type Uintptr struct { _ noCopy; v uintptr }
//
// Goish maps Go's `uintptr` to Rust's `usize` (target-pointer-sized
// unsigned). All semantics mirror Int64/Uint64.
/// `atomic.Uintptr` — atomic pointer-sized unsigned integer.
/// Mirrors `sync/atomic.Uintptr` (type.go:208).
#[derive(Default)]
pub struct Uintptr(CoreUsize);

impl Uintptr {
    pub const fn new(v: usize) -> Self {
        Uintptr(CoreUsize::new(v))
    }
    // Go: type.go:214 — func (x *Uintptr) Load() uintptr
    pub fn Load(&self) -> usize {
        self.0.load(ORD)
    }
    // Go: type.go:217 — func (x *Uintptr) Store(val uintptr)
    pub fn Store(&self, v: usize) {
        self.0.store(v, ORD)
    }
    // Go: type.go:220 — func (x *Uintptr) Swap(new) (old uintptr)
    pub fn Swap(&self, new: usize) -> usize {
        self.0.swap(new, ORD)
    }
    // Go: type.go:223 — func (x *Uintptr) CompareAndSwap(old, new) bool
    pub fn CompareAndSwap(&self, old: usize, new: usize) -> bool {
        self.0.compare_exchange(old, new, ORD, ORD).is_ok()
    }
    // Go: type.go:228 — func (x *Uintptr) Add(delta) (new uintptr)
    //   Returns the NEW value (post-add); use wrapping_add to match
    //   Go's modular semantics on overflow.
    pub fn Add(&self, delta: usize) -> usize {
        self.0.fetch_add(delta, ORD).wrapping_add(delta)
    }
    // Go: type.go:232 — func (x *Uintptr) And(mask) (old uintptr)
    pub fn And(&self, mask: usize) -> usize {
        self.0.fetch_and(mask, ORD)
    }
    // Go: type.go:235 — func (x *Uintptr) Or(mask) (old uintptr)
    pub fn Or(&self, mask: usize) -> usize {
        self.0.fetch_or(mask, ORD)
    }
}

// ─── Bool ─────────────────────────────────────────────────────────

/// `atomic.Bool`. Mirrors `sync/atomic.Bool` (type.go:13).
#[derive(Default)]
pub struct Bool(CoreBool);

impl Bool {
    pub const fn new(v: bool) -> Self {
        Bool(CoreBool::new(v))
    }
    pub fn Load(&self) -> bool {
        self.0.load(ORD)
    }
    pub fn Store(&self, v: bool) {
        self.0.store(v, ORD)
    }
    pub fn Swap(&self, new: bool) -> bool {
        self.0.swap(new, ORD)
    }
    pub fn CompareAndSwap(&self, old: bool, new: bool) -> bool {
        self.0.compare_exchange(old, new, ORD, ORD).is_ok()
    }
}

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
use alloc::sync::Arc;
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
    /// Build an empty Value.
    pub const fn new() -> Self {
        Value { inner: Mutex::new(None) }
    }

    // Go: value.go:28
    //   func (v *Value) Load() (val any) { ... }
    /// Returns the value set by the most recent Store, plus `ok=true`.
    /// If no Store has occurred, returns `(T::default(), false)`.
    pub fn Load(&self) -> (T, bool) {
        match self.inner.Lock().clone() {
            Some(v) => (v, true),
            None => (T::default(), false),
        }
    }

    // Go: value.go:47
    //   func (v *Value) Store(val any) { ... panics on nil / inconsistent type }
    /// Sets the value of the [`Value`] to `val`.
    pub fn Store(&self, val: T) {
        *self.inner.Lock() = Some(val);
    }

    // Go: value.go:90
    //   func (v *Value) Swap(new any) (old any) { ... }
    /// Stores `new` and returns the previous value plus `ok=true`. If
    /// the Value was empty, returns `(T::default(), false)` and stores
    /// `new`.
    pub fn Swap(&self, new: T) -> (T, bool) {
        let mut g = self.inner.Lock();
        match g.replace(new) {
            Some(old) => (old, true),
            None => (T::default(), false),
        }
    }
}

impl<T: Clone + Default + Send + PartialEq + 'static> Value<T> {
    // Go: value.go:135
    //   func (v *Value) CompareAndSwap(old, new any) (swapped bool) { ... }
    /// Atomically sets the stored value to `new` if the current stored
    /// value equals `old`. Returns whether the swap was performed.
    /// If the Value is empty, the swap occurs only if `old` equals
    /// `T::default()`.
    pub fn CompareAndSwap(&self, old: T, new: T) -> bool {
        let mut g = self.inner.Lock();
        match g.as_ref() {
            Some(v) if *v == old => {
                *g = Some(new);
                true
            }
            None if old == T::default() => {
                *g = Some(new);
                true
            }
            _ => false,
        }
    }
}

impl<T: Clone + Default + Send + 'static> Default for Value<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Pointer<T> ───────────────────────────────────────────────────
//
// Line-by-line port of /share/go/src/sync/atomic/type.go:44-69.
//
// Slim deviations from upstream:
//
//   * Go: `*T` (raw pointer, optionally nil).
//     Goish: `Option<Arc<T>>` — `None` ↔ nil, `Some(arc)` ↔ non-nil.
//     Rust has no nullable raw pointer in safe code; `Arc<T>` is the
//     direct analogue of `*T` for shared ownership.
//
//   * Backing store is `Mutex<Option<Arc<T>>>`, not lock-free
//     `unsafe.Pointer`. Same precedent as `Value<T>` above. The public
//     API still presents Go's atomic semantics: any single Load/Store/
//     Swap/CompareAndSwap is a linearization point.
//
//   * CompareAndSwap uses `Arc::ptr_eq` (pointer-identity), which
//     matches Go's `CompareAndSwapPointer` (compares pointer values,
//     not pointee values). Two distinct `Arc::new(7)` calls compare
//     unequal even though the pointees are equal — same as Go.

// Go: type.go:44
//   type Pointer[T any] struct { ... v unsafe.Pointer }
/// `atomic.Pointer<T>` — atomic load/store/swap of a `*T`-like handle.
///
/// The zero value (via [`Pointer::new`]) reports `None` from
/// [`Pointer::Load`] until the first [`Pointer::Store`]. Mirrors
/// `sync/atomic.Pointer[T]` (type.go:47).
pub struct Pointer<T: Send + Sync + 'static> {
    inner: Mutex<Option<Arc<T>>>,
}

impl<T: Send + Sync + 'static> Pointer<T> {
    /// Build an empty Pointer (Go: zero value is nil `*T`).
    pub const fn new() -> Self {
        Pointer { inner: Mutex::new(None) }
    }

    // Go: type.go:58
    //   func (x *Pointer[T]) Load() *T { return (*T)(LoadPointer(&x.v)) }
    /// Atomically load the stored `Arc<T>`. Returns `None` if no Store
    /// has occurred (or last Store was `None`).
    pub fn Load(&self) -> Option<Arc<T>> {
        self.inner.Lock().clone()
    }

    // Go: type.go:61
    //   func (x *Pointer[T]) Store(val *T) { StorePointer(...) }
    /// Atomically store `val`. Pass `None` to clear the pointer (nil).
    pub fn Store(&self, val: Option<Arc<T>>) {
        *self.inner.Lock() = val;
    }

    // Go: type.go:64
    //   func (x *Pointer[T]) Swap(new *T) (old *T) { ... }
    /// Atomically store `new` and return the previous value.
    pub fn Swap(&self, new: Option<Arc<T>>) -> Option<Arc<T>> {
        let mut g = self.inner.Lock();
        core::mem::replace(&mut *g, new)
    }

    // Go: type.go:67
    //   func (x *Pointer[T]) CompareAndSwap(old, new *T) (swapped bool) { ... }
    /// Atomically swap to `new` only if the current value is
    /// pointer-equal to `old` (via `Arc::ptr_eq`, mirroring Go's
    /// `CompareAndSwapPointer` semantics).
    pub fn CompareAndSwap(&self, old: Option<Arc<T>>, new: Option<Arc<T>>) -> bool {
        let mut g = self.inner.Lock();
        let matches = match (g.as_ref(), old.as_ref()) {
            (None, None) => true,
            (Some(cur), Some(want)) => Arc::ptr_eq(cur, want),
            _ => false,
        };
        if matches {
            *g = new;
            true
        } else {
            false
        }
    }
}

impl<T: Send + Sync + 'static> Default for Pointer<T> {
    fn default() -> Self {
        Self::new()
    }
}
