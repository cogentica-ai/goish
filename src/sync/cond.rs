// sync::Cond — Go's `sync.Cond` (slim).
//
// Reference: /share/go/src/sync/cond.go.
//
// Slim deviations:
//
//   * `notifyList` replaced by an `AtomicI64` waiter count + the
//     internal `Sema`. Wait increments the count then sema.acquires;
//     Signal decrements + sema.releases; Broadcast swaps the count
//     to zero and sema.releases that many at once.
//
//   * No `copyChecker` — Rust's borrow rules already prevent the
//     by-value copy that the checker catches in Go. Cond is a
//     `pub struct` whose only field types (`AtomicI64`, `Sema`,
//     `Box<dyn Locker>`) deliberately exclude the manual Clone /
//     Copy that would let the user trip the original error.
//
//   * `L` is `&'static dyn Locker` rather than a Go interface field.
//     This binds the Cond to a specific Mutex / RWMutex chosen at
//     construction time; the goish way to share a Mutex across
//     Conds is to use the same `&MyMutex` for both.

#![allow(non_snake_case)]

extern crate alloc;

use core::sync::atomic::{AtomicI64, Ordering};

use super::sema::Sema;

/// Locker — anything with `Lock` / `Unlock`. Mirrors Go's
/// `sync.Locker` interface. `sync::Mutex` and `sync::RWMutex`
/// implement this; user types can too.
#[goish::interface]
pub trait Locker {
    fn Lock(&self);
    fn Unlock(&self);
}

/// `sync.Cond` — condition variable bound to a `Locker`.
///
/// Construct with [`NewCond`]. Wait/Signal/Broadcast follow Go's
/// semantics:
///   * `Wait()` atomically unlocks `L`, parks, then re-locks `L`.
///   * `Signal()` wakes one parked waiter.
///   * `Broadcast()` wakes all parked waiters.
pub struct Cond<'a, L: Locker + ?Sized> {
    l: &'a L,
    waiters: AtomicI64,
    sema: Sema,
}

/// `sync.NewCond(l)` (cond.go:48) — build a Cond with locker `l`.
pub fn NewCond<L: Locker + ?Sized>(l: &L) -> Cond<'_, L> {
    Cond {
        l,
        waiters: AtomicI64::new(0),
        sema: Sema::new(),
    }
}

impl<'a, L: Locker + ?Sized> Cond<'a, L> {
    /// `(*Cond).Wait()` (cond.go:67) — atomically unlocks `L` and
    /// suspends the calling goroutine. After resuming, re-acquires
    /// `L` before returning.
    pub fn Wait(&self) {
        // Increment waiter count BEFORE Unlock, so a Signal that
        // fires between Unlock and sema.acquire still counts us.
        self.waiters.fetch_add(1, Ordering::AcqRel);
        self.l.Unlock();
        // Park. Sema's credit-store-on-no-waiter behavior closes the
        // lost-wakeup race against a concurrent Signal that arrives
        // before we finish queueing.
        self.sema.acquire();
        self.l.Lock();
    }

    /// `(*Cond).Signal()` (cond.go:82) — wake one waiter, if any.
    pub fn Signal(&self) {
        // Decrement only if there's a waiter to consume; avoid
        // incrementing the sema's credit when there are none.
        loop {
            let w = self.waiters.load(Ordering::Acquire);
            if w <= 0 {
                return;
            }
            if self
                .waiters
                .compare_exchange(w, w - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.sema.release();
                return;
            }
        }
    }

    /// `(*Cond).Broadcast()` (cond.go:91) — wake all waiters.
    pub fn Broadcast(&self) {
        let n = self.waiters.swap(0, Ordering::AcqRel);
        if n > 0 {
            self.sema.release_n(n);
        }
    }
}

// ─── Locker impl for sync::Mutex<T> ─────────────────────────────────

impl<T: Send> Locker for super::Mutex<T> {
    fn Lock(&self) {
        self.LockManual();
    }
    fn Unlock(&self) {
        super::Mutex::<T>::Unlock(self);
    }
}
