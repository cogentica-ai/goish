// runtime::spin — minimal spinlock for `no_std` use.
//
// Rationale: `dlmalloc::Dlmalloc<A>` is not `Sync`; wrapping it in a
// mutex is the standard pattern. `std::sync::Mutex` is not available
// (and would need libc/futex), so we provide a tiny CAS-based spin
// lock. Single-threaded today means the lock is uncontested and costs
// effectively zero (a single atomic CAS that always wins). When real
// threads / goroutines arrive, this is the right shape to swap for a
// futex-backed mutex.
//
// ─── Raw lock access (M16f-β) ──────────────────────────────────────
//
// `select!`'s multi-M-correct protocol needs to lock several chans at
// once and release them later from a type-erased context (gopark's
// commit fn walks a per-G wait-list of `*const AtomicBool`s — see
// `runtime::sched::G::select_wait`). To support this we expose:
//
//   - `lock_atom()` — pointer to the underlying `AtomicBool`.
//     Stable across the lock's lifetime; same address as `&self`
//     thanks to `#[repr(C)]` with `locked` at offset 0.
//   - `raw_lock` / `raw_unlock` — free functions that lock/unlock by
//     pointer alone (caller's responsibility to keep the underlying
//     SpinLock alive and to call them in matched pairs).
//   - `data_unchecked()` — read/write access to the wrapped `T` while
//     the caller holds the lock via raw operations.
//
// All raw access is `unsafe` and goes around the borrow checker on
// purpose; only `select!`'s expansion uses it, and the macro emits
// the pairing.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

// ─── m.locks discipline (M18b-α phase A) ───────────────────────────
//
// Holding a SpinLock means we are in a non-yielding critical section
// from the scheduler's perspective: the M must not be async-preempted
// while it holds, because the SIGURG trampoline would re-enter Rust
// and could try to take the same lock (deadlock) or, worse, observe
// half-mutated state. Mirrors the role of `lockWithRank`/`unlock` in
// Go's runtime/lock_futex.go, which bump and decrement `m.locks`
// around every internal lock acquisition.
//
// Calls are routed through small helpers so this file stays free of
// `crate::runtime::sched` imports at the static-init level (the
// spin module has callers that exist before the sched module is
// usable). The helpers themselves short-circuit while TLS is not
// ready, so it is safe to take SpinLocks during early `__goish_rt0`
// (`args::__set`, etc.) without touching `fs:0`.

#[inline]
fn bump_m_locks() {
    crate::runtime::sched::acquirem();
}

#[inline]
fn drop_m_locks() {
    crate::runtime::sched::releasem();
}

#[repr(C)]
pub struct SpinLock<T> {
    /// Lock state. Repr(C) puts this at offset 0 so `&SpinLock<T>`
    /// can be cast to `*const AtomicBool` (the `lock_atom` shortcut).
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

pub struct Guard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> Guard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // Bump m.locks AFTER acquiring so the increment happens-after
        // the acquire fence — no reordering can place runtime work
        // outside the locked region.
        bump_m_locks();
        Guard { lock: self }
    }

    /// Pointer to the underlying lock atom. Same address as `&self`
    /// (`#[repr(C)]` with `locked` at offset 0). Stable for the
    /// lifetime of the `SpinLock`. Callers cooperate with `raw_lock`/
    /// `raw_unlock` to lock and unlock by pointer alone, e.g. from
    /// type-erased contexts like `selparkcommit`.
    #[inline]
    pub fn lock_atom(&self) -> *const AtomicBool {
        &self.locked
    }

    /// Read/write access to the wrapped data while the caller holds
    /// the lock via raw operations. **Caller must hold the lock**;
    /// otherwise this is a data race.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn data_unchecked(&self) -> &mut T {
        &mut *self.data.get()
    }
}

/// Acquire a `SpinLock` by raw atom pointer. Pairs with `raw_unlock`.
///
/// **Safety**: `atom` must point to the `locked: AtomicBool` of a
/// live `SpinLock`. Once acquired, the caller must release via
/// `raw_unlock(atom)` exactly once before the SpinLock is dropped.
#[inline]
pub unsafe fn raw_lock(atom: *const AtomicBool) {
    let atom = &*atom;
    while atom
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    bump_m_locks();
}

/// Release a `SpinLock` previously acquired via `raw_lock`.
///
/// **Safety**: `atom` must be the same pointer used in the matching
/// `raw_lock` call.
#[inline]
pub unsafe fn raw_unlock(atom: *const AtomicBool) {
    // Drop m.locks BEFORE releasing the lock so the decrement is
    // observably inside the locked region.
    drop_m_locks();
    (*atom).store(false, Ordering::Release);
}

impl<'a, T> Deref for Guard<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for Guard<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for Guard<'a, T> {
    #[inline]
    fn drop(&mut self) {
        drop_m_locks();
        self.lock.locked.store(false, Ordering::Release);
    }
}
