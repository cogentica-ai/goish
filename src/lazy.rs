// lazy — `Lazy<T>` for `static` values whose initialization isn't
// const-evaluable (e.g. `sync::Pool` whose `Pool::new(closure)` calls
// non-const allocator code).
//
// Goish's lowering for Go's `var X = sync.Pool{New: …}` pattern wraps
// the value in a `Lazy<T>` static; first access materialises via the
// supplied init closure. Thread-safe: the inner `SpinLock` serialises
// the one-time init, after which all readers see the same `T`.
//
// Usage shape (emitted by goishc for `var pool = sync.Pool{New: …}`):
//
//   static POOL: goish::lazy::Lazy<sync::Pool<Transport>> =
//       goish::lazy::Lazy::new(|| sync::Pool::new(|| Transport { … }));
//
// Then `pool.Get()` becomes `POOL.deref().Get()` (the Deref impl is
// the user-friendly access).

#![allow(non_snake_case)]

extern crate alloc;

use core::cell::UnsafeCell;
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::runtime::spin::SpinLock;

/// One-time initialisation cell suitable for `static` slots.
pub struct Lazy<T: 'static> {
    /// `None` until first access; `Some(T)` after.
    state: SpinLock<Option<&'static T>>,
    /// Init closure. Stored as a function pointer so the whole struct
    /// is const-evaluable (Box<dyn Fn> would force a runtime alloc).
    init: fn() -> T,
    /// Storage for the initialised value; populated on first access.
    /// Wrapped in UnsafeCell because we mutate it through a shared
    /// reference; access is serialised via `state`'s SpinLock.
    storage: UnsafeCell<Option<T>>,
}

unsafe impl<T: Sync + Send> Sync for Lazy<T> {}

impl<T: 'static> Lazy<T> {
    /// Construct a Lazy with the given initialiser. `init` is a `fn`
    /// pointer (not a closure) so the result is const-evaluable.
    pub const fn new(init: fn() -> T) -> Self {
        Self {
            state: SpinLock::new(None),
            init,
            storage: UnsafeCell::new(None),
        }
    }

    /// Force initialisation (idempotent) and return a borrow of the
    /// inner value. Safe to call concurrently — the SpinLock ensures
    /// only one thread runs `init()`, others wait.
    pub fn get(&'static self) -> &'static T {
        let mut guard = self.state.lock();
        if let Some(r) = *guard {
            return r;
        }
        let v = (self.init)();
        // SAFETY: we hold `state`'s lock, no other thread can touch
        // storage. After write, we publish the &T via `state`.
        unsafe {
            *self.storage.get() = Some(v);
            let r: &'static T = (*self.storage.get()).as_ref().unwrap();
            *guard = Some(r);
            r
        }
    }
}

impl<T: 'static> Deref for Lazy<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: `Self::get` requires `&'static self`; in practice the
        // only callers of `Deref` are static-bound. Forward via the
        // documented `get` path.
        let s: &'static Self = unsafe { core::mem::transmute(self) };
        s.get()
    }
}

// `len(&LAZY)` — Go's `len(magicBody)` lowers to `goish::len(&magicBody)`
// where `magicBody: Lazy<slice<byte>>`. Generic `len` arg-type matching
// can't auto-deref; forward `Len` so call sites stay clean.
impl<T: 'static + crate::builtin::Len> crate::builtin::Len for Lazy<T> {
    fn __len(&self) -> crate::types::int {
        let s: &'static Self = unsafe { core::mem::transmute(self) };
        s.get().__len()
    }
}

impl<T: 'static + crate::builtin::Cap> crate::builtin::Cap for Lazy<T> {
    fn __cap(&self) -> crate::types::int {
        let s: &'static Self = unsafe { core::mem::transmute(self) };
        s.get().__cap()
    }
}

// `LAZY[i]` — for ports that statically declare a `slice<byte>` with
// non-UTF-8 bytes (snappy's `magicBody`) and index it Go-style. The
// indexing operator desugars to `Index::index`; method-call auto-deref
// covers most cases but the explicit forwarder removes ambiguity.
impl<T: 'static + core::ops::Index<I>, I> core::ops::Index<I> for Lazy<T>
where
    T::Output: Sized,
{
    type Output = T::Output;
    fn index(&self, i: I) -> &T::Output {
        let s: &'static Self = unsafe { core::mem::transmute(self) };
        &s.get()[i]
    }
}

// `range!(LAZY)` — package-level `var xs = []byte{…}` lowers to
// `static xs: Lazy<slice<byte>>`. The `range!` macro expands to
// `RangeIter::range(&xs)`, hitting `&Lazy<T>` which lacks an inherent
// `RangeIter` impl. Forward through the once-init Deref so any `&T:
// RangeIter` carries to `&Lazy<T>`. The `'static` constraint matches
// the `Lazy::get` shape exactly.
impl<T: 'static> crate::range::RangeIter for &Lazy<T>
where
    &'static T: crate::range::RangeIter,
{
    type Item = <&'static T as crate::range::RangeIter>::Item;
    type Iter = <&'static T as crate::range::RangeIter>::Iter;
    fn range(self) -> Self::Iter {
        let s: &'static Lazy<T> = unsafe { core::mem::transmute(self) };
        crate::range::RangeIter::range(s.get())
    }
}

// `LAZY == val` and `val == LAZY` — Go's pattern of declaring a
// zero-value sentinel `var nilID ID` and comparing other values to
// it. Without these forwarders the comparison hits `Lazy<T>` and
// fails at the trait layer; ports would have to write `*LAZY == val`
// at every site. Symmetric impls cover both operand orderings.

impl<T: 'static + PartialEq> PartialEq<T> for Lazy<T> {
    fn eq(&self, other: &T) -> bool {
        let s: &'static Self = unsafe { core::mem::transmute(self) };
        s.get() == other
    }
}

impl<T: 'static + PartialEq> PartialEq<&T> for Lazy<T> {
    fn eq(&self, other: &&T) -> bool {
        let s: &'static Self = unsafe { core::mem::transmute(self) };
        s.get() == *other
    }
}

// Symmetric `T == Lazy<T>` and `&T == Lazy<T>` aren't representable
// here — they'd impl `PartialEq` for foreign type `T` / `&T`, which
// the orphan rule rejects. Callers writing `id == NIL_LAZY` must
// flip to `NIL_LAZY == id`; the transpiler does this automatically
// when one side is a registered Lazy static.

// ─── LazyMut<T> — init-phase mutable cell ────────────────────────────
//
// Pairs with `Lazy<LazyMut<T>>` for package-level globals that get
// filled during `init()` and then read post-init: e.g. xid's
// `var dec [256]byte` filled by `for i { dec[i] = 0xFF }` in init().
//
// Today's `Lazy<T>` is read-only post-init. Wrapping `T` in
// `LazyMut<T>` enables `dec.modify(|t| t[i] = 0xFF)` calls during
// init, then bare `dec[i]` reads thereafter.
//
// Contract (panic-checked):
//   * `.modify(...)` is only legal before the first read.
//   * `.get()` / `Deref` freezes the cell; any subsequent `.modify(...)`
//     panics with a clear message.
//
// Sync model:
//   * Hot path (post-freeze read): `Acquire` load on `frozen` flag,
//     bare deref. Lock-free. ~1ns.
//   * Cold path (first read): SpinLock acquire to fence any in-flight
//     writer, set `frozen = true` via `Release`, deref.
//   * Write path (modify): SpinLock acquire, check `frozen` is false,
//     mutate via UnsafeCell. Init-only — performance non-critical.
//
// The Acquire/Release on `frozen` plus the SpinLock pair establish
// happens-before from every `.modify()` to every post-freeze `.get()`,
// matching Go's memory-model guarantee for package init.

/// Init-phase mutable cell that freezes on first read.
///
/// Compose as `Lazy<LazyMut<T>>` for static slots whose value is
/// built up in `init()` and read afterward.
pub struct LazyMut<T: 'static> {
    /// `false` until first `get()`; `true` after — no more writes.
    frozen: AtomicBool,
    /// Serialises writers and the first reader's freeze. Post-freeze
    /// reads bypass this lock entirely.
    write_lock: SpinLock<()>,
    /// Storage cell. Mutated through `&self` during init phase under
    /// the lock; immutably borrowed after freeze.
    storage: UnsafeCell<T>,
}

// SAFETY: LazyMut is Sync when T is. Writes happen only under
// `write_lock` and only before `frozen` is set; reads after freeze
// are immutable. The Release/Acquire on `frozen` orders writes
// before reads.
unsafe impl<T: Send + Sync> Sync for LazyMut<T> {}

impl<T: 'static> LazyMut<T> {
    /// Construct a `LazyMut` with the given initial value. The cell
    /// starts unfrozen; mutate via `.modify(...)` until first read.
    pub const fn new(initial: T) -> Self {
        Self {
            frozen: AtomicBool::new(false),
            write_lock: SpinLock::new(()),
            storage: UnsafeCell::new(initial),
        }
    }

    /// Apply a mutation while still in init phase. Panics if the cell
    /// has already been frozen by a read.
    pub fn modify<F>(&self, f: F)
    where
        F: FnOnce(&mut T),
    {
        let _g = self.write_lock.lock();
        if self.frozen.load(Ordering::Acquire) {
            panic!("LazyMut: write after freeze (a read happened-before this write)");
        }
        // SAFETY: `write_lock` is held; `frozen` is false, so no
        // reader has acquired a `&T` to storage. Mutation is sound.
        unsafe { f(&mut *self.storage.get()) };
    }

    /// Freeze the cell (idempotent) and return a borrow of the inner
    /// value. After the first call, subsequent `.modify(...)` panics.
    pub fn get(&self) -> &T {
        // Hot path: already frozen — bare deref.
        if self.frozen.load(Ordering::Acquire) {
            // SAFETY: `frozen` was set with Release after the last
            // write under `write_lock`; this Acquire load
            // synchronizes-with that Release, so all init writes are
            // visible.
            return unsafe { &*self.storage.get() };
        }
        // Cold path: take the write lock to fence any in-flight
        // writer, mark frozen, then deref. Any concurrent `.modify`
        // running on another thread completes before we publish.
        let _g = self.write_lock.lock();
        self.frozen.store(true, Ordering::Release);
        // SAFETY: lock held, so no writer is mid-mutation. Storage
        // is now treated as immutable for the lifetime of `&self`.
        unsafe { &*self.storage.get() }
    }
}

impl<T: 'static> Deref for LazyMut<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.get()
    }
}

// `dec[i]` — index-forwarder so `Lazy<LazyMut<array<u8, N>>>` lookups
// route through Deref to T's Index impl.
impl<T: 'static + core::ops::Index<I>, I> core::ops::Index<I> for LazyMut<T>
where
    T::Output: Sized,
{
    type Output = T::Output;
    fn index(&self, i: I) -> &T::Output {
        &self.get()[i]
    }
}

// `len(&dec)` — forward `Len` so `goish::len(&LAZY_MUT_T)` works on
// any T with a Len impl.
impl<T: 'static + crate::builtin::Len> crate::builtin::Len for LazyMut<T> {
    fn __len(&self) -> crate::types::int {
        self.get().__len()
    }
}

impl<T: 'static + crate::builtin::Cap> crate::builtin::Cap for LazyMut<T> {
    fn __cap(&self) -> crate::types::int {
        self.get().__cap()
    }
}
