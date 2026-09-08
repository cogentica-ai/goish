// sync/atomic/type — Go 1.25.5 src/sync/atomic/type.go.
//
// One `.rs` per `.go` (§33): the typed wrappers Go added in 1.19 —
// Int32, Int64, Uint32, Uint64, Uintptr, Bool and Pointer. All use
// SeqCst, to match Go's memory model.
//
// atomic.Pointer<T> is typed and Arc-backed: Go's `*T` is goish's
// `Option<Arc<T>>`, and nil is None.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{
    AtomicBool as CoreBool, AtomicI32 as CoreI32, AtomicI64 as CoreI64, AtomicU32 as CoreU32,
    AtomicU64 as CoreU64, AtomicUsize as CoreUsize, Ordering,
};

use crate::sync::Mutex;

// go: none — goish-only: see the note in type.rs's header.
const ORD: Ordering = Ordering::SeqCst;

// ─── Int32 ────────────────────────────────────────────────────────

/// `atomic.Int32` — atomic 32-bit signed integer. Mirrors
/// `sync/atomic.Int32` (type.go:74).
#[derive(Default)]
pub struct Int32(CoreI32);

impl Int32 {
    // go: none — goish-only: Go's zero value IS the empty
    // atomic, so it declares no constructor. Rust needs one.
    pub const fn new(v: i32) -> Self {
        return Int32(CoreI32::new(v));
    }
    // go: sdk 1.25.5 sync/atomic/type.go:80-80 Int32.Load
    pub fn Load(&self) -> i32 {
        return self.0.load(ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:83-83 Int32.Store
    pub fn Store(&self, v: i32) {
        return self.0.store(v, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:94-94 Int32.Add
    pub fn Add(&self, delta: i32) -> i32 {
        return self.0.fetch_add(delta, ORD).wrapping_add(delta);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:86-86 Int32.Swap
    pub fn Swap(&self, new: i32) -> i32 {
        return self.0.swap(new, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:89-91 Int32.CompareAndSwap
    pub fn CompareAndSwap(&self, old: i32, new: i32) -> bool {
        return self.0.compare_exchange(old, new, ORD, ORD).is_ok();
    }
    // go: sdk 1.25.5 sync/atomic/type.go:98-98 Int32.And
    pub fn And(&self, mask: i32) -> i32 {
        return self.0.fetch_and(mask, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:102-102 Int32.Or
    pub fn Or(&self, mask: i32) -> i32 {
        return self.0.fetch_or(mask, ORD);
    }
    // go: none — goish-only: Go has NO atomic Xor. It added And
    // and Or in 1.23 (type.go:96-102) and stopped there.
    //
    // This doc used to say it mirrored `(*Int32).Xor` at a
    // specific type.go line. That line is `And`. The claim was
    // false in both halves — there is no Go declaration to
    // mirror — and it is the kind of citation a reader trusts
    // without checking.
    /// `Xor(mask)` — atomic XOR, a goish extension. Returns the
    /// previous value.
    pub fn Xor(&self, mask: i32) -> i32 {
        return self.0.fetch_xor(mask, ORD);
    }
}

// ─── Int64 ────────────────────────────────────────────────────────

/// `atomic.Int64`. Mirrors `sync/atomic.Int64` (type.go:107).
#[derive(Default)]
pub struct Int64(CoreI64);

impl Int64 {
    // go: none — goish-only: Go's zero value IS the empty
    // atomic, so it declares no constructor. Rust needs one.
    pub const fn new(v: i64) -> Self {
        return Int64(CoreI64::new(v));
    }
    // go: sdk 1.25.5 sync/atomic/type.go:114-114 Int64.Load
    pub fn Load(&self) -> i64 {
        return self.0.load(ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:117-117 Int64.Store
    pub fn Store(&self, v: i64) {
        return self.0.store(v, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:128-128 Int64.Add
    pub fn Add(&self, delta: i64) -> i64 {
        return self.0.fetch_add(delta, ORD).wrapping_add(delta);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:120-120 Int64.Swap
    pub fn Swap(&self, new: i64) -> i64 {
        return self.0.swap(new, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:123-125 Int64.CompareAndSwap
    pub fn CompareAndSwap(&self, old: i64, new: i64) -> bool {
        return self.0.compare_exchange(old, new, ORD, ORD).is_ok();
    }
    // go: sdk 1.25.5 sync/atomic/type.go:132-132 Int64.And
    pub fn And(&self, mask: i64) -> i64 {
        return self.0.fetch_and(mask, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:136-136 Int64.Or
    pub fn Or(&self, mask: i64) -> i64 {
        return self.0.fetch_or(mask, ORD);
    }
    // go: none — goish-only: Go has NO atomic Xor. It added And
    // and Or in 1.23 (type.go:96-102) and stopped there.
    //
    // This doc used to say it mirrored `(*Int64).Xor` at a
    // specific type.go line. That line is `And`. The claim was
    // false in both halves — there is no Go declaration to
    // mirror — and it is the kind of citation a reader trusts
    // without checking.
    /// `Xor(mask)` — atomic XOR, a goish extension. Returns the
    /// previous value.
    pub fn Xor(&self, mask: i64) -> i64 {
        return self.0.fetch_xor(mask, ORD);
    }
}

// ─── Uint32 ───────────────────────────────────────────────────────

/// `atomic.Uint32`. Mirrors `sync/atomic.Uint32` (type.go:141).
#[derive(Default)]
pub struct Uint32(CoreU32);

impl Uint32 {
    // go: none — goish-only: Go's zero value IS the empty
    // atomic, so it declares no constructor. Rust needs one.
    pub const fn new(v: u32) -> Self {
        return Uint32(CoreU32::new(v));
    }
    // go: sdk 1.25.5 sync/atomic/type.go:147-147 Uint32.Load
    pub fn Load(&self) -> u32 {
        return self.0.load(ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:150-150 Uint32.Store
    pub fn Store(&self, v: u32) {
        return self.0.store(v, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:161-161 Uint32.Add
    pub fn Add(&self, delta: u32) -> u32 {
        return self.0.fetch_add(delta, ORD).wrapping_add(delta);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:153-153 Uint32.Swap
    pub fn Swap(&self, new: u32) -> u32 {
        return self.0.swap(new, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:156-158 Uint32.CompareAndSwap
    pub fn CompareAndSwap(&self, old: u32, new: u32) -> bool {
        return self.0.compare_exchange(old, new, ORD, ORD).is_ok();
    }
    // go: sdk 1.25.5 sync/atomic/type.go:165-165 Uint32.And
    pub fn And(&self, mask: u32) -> u32 {
        return self.0.fetch_and(mask, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:169-169 Uint32.Or
    pub fn Or(&self, mask: u32) -> u32 {
        return self.0.fetch_or(mask, ORD);
    }
    // go: none — goish-only: Go has NO atomic Xor. It added And
    // and Or in 1.23 (type.go:96-102) and stopped there.
    //
    // This doc used to say it mirrored `(*Uint32).Xor` at a
    // specific type.go line. That line is `And`. The claim was
    // false in both halves — there is no Go declaration to
    // mirror — and it is the kind of citation a reader trusts
    // without checking.
    /// `Xor(mask)` — atomic XOR, a goish extension. Returns the
    /// previous value.
    pub fn Xor(&self, mask: u32) -> u32 {
        return self.0.fetch_xor(mask, ORD);
    }
}

// ─── Uint64 ───────────────────────────────────────────────────────

/// `atomic.Uint64`. Mirrors `sync/atomic.Uint64`.
#[derive(Default)]
pub struct Uint64(CoreU64);

impl Uint64 {
    // go: none — goish-only: Go's zero value IS the empty
    // atomic, so it declares no constructor. Rust needs one.
    pub const fn new(v: u64) -> Self {
        return Uint64(CoreU64::new(v));
    }
    // go: sdk 1.25.5 sync/atomic/type.go:181-181 Uint64.Load
    pub fn Load(&self) -> u64 {
        return self.0.load(ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:184-184 Uint64.Store
    pub fn Store(&self, v: u64) {
        return self.0.store(v, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:195-195 Uint64.Add
    pub fn Add(&self, delta: u64) -> u64 {
        return self.0.fetch_add(delta, ORD).wrapping_add(delta);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:187-187 Uint64.Swap
    pub fn Swap(&self, new: u64) -> u64 {
        return self.0.swap(new, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:190-192 Uint64.CompareAndSwap
    pub fn CompareAndSwap(&self, old: u64, new: u64) -> bool {
        return self.0.compare_exchange(old, new, ORD, ORD).is_ok();
    }
    // go: sdk 1.25.5 sync/atomic/type.go:199-199 Uint64.And
    pub fn And(&self, mask: u64) -> u64 {
        return self.0.fetch_and(mask, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:203-203 Uint64.Or
    pub fn Or(&self, mask: u64) -> u64 {
        return self.0.fetch_or(mask, ORD);
    }
    // go: none — goish-only: Go has NO atomic Xor. It added And
    // and Or in 1.23 (type.go:96-102) and stopped there.
    //
    // This doc used to say it mirrored `(*Uint64).Xor` at a
    // specific type.go line. That line is `And`. The claim was
    // false in both halves — there is no Go declaration to
    // mirror — and it is the kind of citation a reader trusts
    // without checking.
    /// `Xor(mask)` — atomic XOR, a goish extension. Returns the
    /// previous value.
    pub fn Xor(&self, mask: u64) -> u64 {
        return self.0.fetch_xor(mask, ORD);
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
    // go: none — goish-only: Go's zero value IS the empty
    // atomic, so it declares no constructor. Rust needs one.
    pub const fn new(v: usize) -> Self {
        return Uintptr(CoreUsize::new(v));
    }
    // go: sdk 1.25.5 sync/atomic/type.go:214-214 Uintptr.Load
    // Go: type.go:214 — func (x *Uintptr) Load() uintptr
    pub fn Load(&self) -> usize {
        return self.0.load(ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:217-217 Uintptr.Store
    // Go: type.go:217 — func (x *Uintptr) Store(val uintptr)
    pub fn Store(&self, v: usize) {
        return self.0.store(v, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:220-220 Uintptr.Swap
    // Go: type.go:220 — func (x *Uintptr) Swap(new) (old uintptr)
    pub fn Swap(&self, new: usize) -> usize {
        return self.0.swap(new, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:223-225 Uintptr.CompareAndSwap
    // Go: type.go:223 — func (x *Uintptr) CompareAndSwap(old, new) bool
    pub fn CompareAndSwap(&self, old: usize, new: usize) -> bool {
        return self.0.compare_exchange(old, new, ORD, ORD).is_ok();
    }
    // go: sdk 1.25.5 sync/atomic/type.go:228-228 Uintptr.Add
    // Go: type.go:228 — func (x *Uintptr) Add(delta) (new uintptr)
    //   Returns the NEW value (post-add); use wrapping_add to match
    //   Go's modular semantics on overflow.
    pub fn Add(&self, delta: usize) -> usize {
        return self.0.fetch_add(delta, ORD).wrapping_add(delta);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:232-232 Uintptr.And
    // Go: type.go:232 — func (x *Uintptr) And(mask) (old uintptr)
    pub fn And(&self, mask: usize) -> usize {
        return self.0.fetch_and(mask, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:236-236 Uintptr.Or
    // Go: type.go:235 — func (x *Uintptr) Or(mask) (old uintptr)
    pub fn Or(&self, mask: usize) -> usize {
        return self.0.fetch_or(mask, ORD);
    }
    // go: none — goish-only: Go has NO atomic Xor. It added And
    // and Or in 1.23 and stopped there; this doc used to claim a
    // Go counterpart that does not exist.
    /// `Xor(mask)` — atomic XOR, a goish extension. Returns the
    /// previous value.
    pub fn Xor(&self, mask: usize) -> usize {
        return self.0.fetch_xor(mask, ORD);
    }
}

// ─── Bool ─────────────────────────────────────────────────────────

/// `atomic.Bool`. Mirrors `sync/atomic.Bool` (type.go:13).
#[derive(Default)]
pub struct Bool(CoreBool);

impl Bool {
    // go: none — goish-only: Go's zero value IS the empty
    // atomic, so it declares no constructor. Rust needs one.
    pub const fn new(v: bool) -> Self {
        return Bool(CoreBool::new(v));
    }
    // go: sdk 1.25.5 sync/atomic/type.go:19-19 Bool.Load
    pub fn Load(&self) -> bool {
        return self.0.load(ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:22-22 Bool.Store
    pub fn Store(&self, v: bool) {
        return self.0.store(v, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:25-25 Bool.Swap
    pub fn Swap(&self, new: bool) -> bool {
        return self.0.swap(new, ORD);
    }
    // go: sdk 1.25.5 sync/atomic/type.go:28-30 Bool.CompareAndSwap
    pub fn CompareAndSwap(&self, old: bool, new: bool) -> bool {
        return self.0.compare_exchange(old, new, ORD, ORD).is_ok();
    }
}

// ─── Pointer<T> ───────────────────────────────────────────────────
//
// Line-by-line port of sync/atomic/type.go:44-69.
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
    // go: none — goish-only: Go's zero value IS the empty
    // atomic, so it declares no constructor. Rust needs one.
    /// Build an empty Pointer (Go: zero value is nil `*T`).
    pub const fn new() -> Self {
        return Pointer {
            inner: Mutex::new(None),
        };
    }

    // go: sdk 1.25.5 sync/atomic/type.go:58-58 Pointer.Load
    //   func (x *Pointer[T]) Load() *T { return (*T)(LoadPointer(&x.v)) }
    /// Atomically load the stored `Arc<T>`. Returns `None` if no Store
    /// has occurred (or last Store was `None`).
    pub fn Load(&self) -> Option<Arc<T>> {
        return self.inner.Lock().clone();
    }

    // go: sdk 1.25.5 sync/atomic/type.go:61-61 Pointer.Store
    //   func (x *Pointer[T]) Store(val *T) { StorePointer(...) }
    /// Atomically store `val`. Pass `None` to clear the pointer (nil).
    pub fn Store(&self, val: Option<Arc<T>>) {
        *self.inner.Lock() = val;
    }

    // go: sdk 1.25.5 sync/atomic/type.go:64-64 Pointer.Swap
    //   func (x *Pointer[T]) Swap(new *T) (old *T) { ... }
    /// Atomically store `new` and return the previous value.
    pub fn Swap(&self, new: Option<Arc<T>>) -> Option<Arc<T>> {
        let mut g = self.inner.Lock();
        return core::mem::replace(&mut *g, new);
    }

    // go: sdk 1.25.5 sync/atomic/type.go:67-69 Pointer.CompareAndSwap
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
        if !matches {
            return false;
        }
        *g = new;
        return true;
    }
}

impl<T: Send + Sync + 'static> Default for Pointer<T> {
    // go: none — goish-only: Rust's `Default`, which Go's zero value
    // gives for free. Go declares no counterpart.
    fn default() -> Self {
        return Self::new();
    }
}
