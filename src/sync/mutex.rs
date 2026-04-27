// sync::Mutex — Go's `sync.Mutex` (Lock / Unlock / TryLock).
//
// Reference: /share/go/src/internal/sync/mutex.go.
//
// Implementation parity with Go (minus the race detector and Go's
// "starvation mode" tail-latency bound):
//
//   - Lock-free fast path. State is a single AtomicU32 bit-packed as
//     `[waiters:31 | locked:1]`. Uncontended Lock/TryLock/Unlock are
//     a single CAS or AtomicAdd; no SpinLock touched.
//
//   - Sema-backed slow path. On contention the parker increments the
//     waiter count atomically, then `sema.acquire()`s. Unlock with
//     waiters does FIFO handoff: decrement waiter count atomically,
//     leave the locked bit set, and `sema.release()` exactly one
//     waiter — that woken G inherits ownership.
//
// Goish v1 omits Go's starvation mode; FIFO handoff already
// guarantees no waiter starves indefinitely.
//
// ─── Generic over T (Go-verbatim ports) ───────────────────────────
//
// Public surface is `Mutex<T = ()>`:
//
//   - `Mutex` (= `Mutex<()>`) is the Go-shape "code-region" mutex.
//     Lock returns a guard whose only role is to release on drop.
//
//   - `Mutex<State>` wraps a State value; Lock returns
//     `MutexGuard<'_, State>` which derefs to `&mut State`. This is
//     how a Go struct of `{ mu sync.Mutex; field T; ... }` is
//     ported to Rust: bundle the protected fields into a `State`
//     struct and let `Mutex<State>` own them.
//
// Examples:
//
//   // Go-shape, just locking a code region:
//   let m = Mutex::new(());
//   { let _g = m.Lock(); /* critical section */ }  // unlocks at }
//
//   // Go-verbatim with protected data (matches `sync.Mutex` field
//   // + struct fields under it):
//   struct State { err: error, count: i64 }
//   let m: Mutex<State> = Mutex::new(State { ... });
//   {
//       let mut g = m.Lock();
//       if !g.err.IsNil() { return; }
//       g.count += 1;
//   }
//
// MutexGuard implements `Deref` and `DerefMut`, so the protected
// fields are accessible directly (`g.field` rather than the more
// verbose `(*g).field`). Drop releases the lock — the same RAII
// pattern as Rust's `std::sync::Mutex<T>`.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

use super::sema::Sema;
use crate::syscall;

const M_LOCKED: u32 = 1;
const M_WAITER_UNIT: u32 = 1 << 1;

/// `sync.Mutex` — mutual-exclusion lock. Generic over the protected
/// data type `T`; `T = ()` (the default) is the Go-shape "no data,
/// just a code region" mutex.
///
/// Mirrors `sync.Mutex` (mutex.go:30) for the API; the `<T>` form
/// mirrors Rust's `std::sync::Mutex<T>` and is what idiomatic
/// Go-to-Rust ports use to bundle the protected fields under the
/// type system.
pub struct Mutex<T = ()> {
    state: AtomicU32,
    sema: Sema,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// Build an unlocked mutex protecting `data`. For the Go-shape
    /// (no protected data), pass `()`:
    ///
    ///     static MU: Mutex = Mutex::new(());
    pub const fn new(data: T) -> Self {
        Mutex {
            state: AtomicU32::new(0),
            sema: Sema::new(),
            data: UnsafeCell::new(data),
        }
    }

    /// Lock acquires the mutex, blocking until available. Returns
    /// a guard whose drop releases the lock. Deref/DerefMut on the
    /// guard exposes the protected data. Mirrors `Mutex.Lock`
    /// (mutex.go:45).
    #[inline]
    pub fn Lock(&self) -> MutexGuard<'_, T> {
        // Fast path: CAS the unlocked state to locked.
        if self
            .state
            .compare_exchange(0, M_LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.lock_slow();
        }
        MutexGuard { mu: self }
    }

    #[cold]
    #[inline(never)]
    fn lock_slow(&self) {
        loop {
            let old = self.state.load(Ordering::Relaxed);
            if old & M_LOCKED == 0 {
                // Lock became available — try to grab without queueing.
                if self
                    .state
                    .compare_exchange(old, old | M_LOCKED, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
                continue;
            }
            // Register as a waiter atomically, then park on the sema.
            // After wake, FIFO handoff means we own the lock — return
            // directly without re-CAS.
            if self
                .state
                .compare_exchange(old, old + M_WAITER_UNIT, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            self.sema.acquire();
            return;
        }
    }

    /// TryLock attempts to acquire the lock without blocking. On
    /// success returns `Some(guard)`; on failure (already held)
    /// returns `None`. Mirrors `Mutex.TryLock` (mutex.go:54).
    #[inline]
    pub fn TryLock(&self) -> Option<MutexGuard<'_, T>> {
        if self
            .state
            .compare_exchange(0, M_LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(MutexGuard { mu: self })
        } else {
            None
        }
    }

    /// Go-shape Lock: acquires the mutex without returning a
    /// guard. Pair with `Unlock`. Useful when lock and unlock must
    /// span different function bodies (e.g., the writer-vs-writer
    /// mutex inside `RWMutex`). For straight-line code prefer the
    /// RAII `Lock` form.
    #[inline]
    pub fn LockManual(&self) {
        if self
            .state
            .compare_exchange(0, M_LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.lock_slow();
        }
    }

    /// Go-shape TryLock returning `bool`. Pair with `Unlock` on
    /// success.
    #[inline]
    pub fn TryLockManual(&self) -> bool {
        self.state
            .compare_exchange(0, M_LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Go-shape explicit Unlock. Pairs with `LockManual` /
    /// `TryLockManual`. Calling this on a Mutex held by a `Lock`
    /// guard is a programming error — the guard's drop will then
    /// double-unlock (and panic) when it falls out of scope.
    #[inline]
    pub fn Unlock(&self) {
        self.unlock();
    }

    /// Internal: drop the locked bit and (if waiters present) hand
    /// off ownership to the head waiter. Used by `MutexGuard::drop`
    /// and by `Unlock`.
    #[inline]
    fn unlock(&self) {
        // Fast path: drop the locked bit when no waiters.
        if self
            .state
            .compare_exchange(M_LOCKED, 0, Ordering::Release, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        self.unlock_slow();
    }

    #[cold]
    #[inline(never)]
    fn unlock_slow(&self) {
        loop {
            let old = self.state.load(Ordering::Relaxed);
            if old & M_LOCKED == 0 {
                fatal(b"goish: sync: unlock of unlocked mutex\n");
            }
            let waiters = old >> 1;
            if waiters == 0 {
                if self
                    .state
                    .compare_exchange(old, 0, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
                continue;
            }
            // Handoff: decrement waiter count, keep locked bit set.
            let new = ((waiters - 1) << 1) | M_LOCKED;
            if self
                .state
                .compare_exchange(old, new, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                self.sema.release();
                return;
            }
        }
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Mutex::new(T::default())
    }
}

/// RAII guard returned by `Mutex<T>::Lock`. Deref/DerefMut expose
/// the protected `T`. Drop releases the lock.
///
/// Mirrors the role of `std::sync::MutexGuard<T>`. For `Mutex<()>`
/// the deref target is `()`, which is uninteresting — the guard
/// just keeps the lock held until it goes out of scope.
pub struct MutexGuard<'a, T> {
    mu: &'a Mutex<T>,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // Safety: we hold the lock until drop.
        unsafe { &*self.mu.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // Safety: we hold the lock until drop.
        unsafe { &mut *self.mu.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.mu.unlock();
    }
}

// MutexGuard is not Send: dropping it from a different thread than
// the one that locked would violate Mutex's caller-thread-agnostic
// nature in goroutine context. (Go's mutex is goroutine-agnostic;
// ours is too — but cross-G transfer requires explicit handoff,
// not implicit Send.)

fn fatal(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(2);
}
