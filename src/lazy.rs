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
