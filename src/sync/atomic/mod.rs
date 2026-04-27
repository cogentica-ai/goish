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
//   atomic::Bool      -> Load, Store, Swap, CompareAndSwap
//
// All methods use `Ordering::SeqCst` to match Go's atomic memory
// model (Go's atomic ops are sequentially consistent across all
// goroutines). The underlying core atomics give us the same
// guarantees.
//
// What v1 omits: atomic.Pointer<T> (lifetime/ownership of T in
// Rust requires more design — `Arc<T>` swap pattern is the
// usual port), atomic.Value (untyped — would need erased storage).
// Both can be added later.
//
// Also omitted: free-function variants (LoadInt32, StoreInt32,
// CompareAndSwapInt32, etc.). Go provides them for legacy reasons;
// the typed-struct API is the post-Go-1.19 idiom.

#![allow(non_snake_case)]

use core::sync::atomic::{
    AtomicBool as CoreBool, AtomicI32 as CoreI32, AtomicI64 as CoreI64,
    AtomicU32 as CoreU32, AtomicU64 as CoreU64, Ordering,
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
