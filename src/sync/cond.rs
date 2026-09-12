// go: file sync/cond.go decls: NewCond, Cond.Wait, Cond.Signal, Cond.Broadcast
//
// goishlint:ignore GOISH021 copyChecker, noCopy — the two types behind that same machinery; see the GOISH018 line below.
//
// goishlint:ignore GOISH018 copyChecker.check, noCopy.Lock, noCopy.Unlock — Go's copy-detection machinery. `copyChecker` compares the Cond's own address against a stored one to catch a Cond copied after first use, and `noCopy` is the zero-size marker `go vet` keys on. Rust moves and borrows make both unnecessary: a `Cond` here borrows its Locker for its lifetime, so a copy that would break Go cannot be written.
//
// sync::Cond — Go's `sync.Cond` (slim).
//
// Reference: sync/cond.go.
//
// Slim deviations:
//
//   * `notifyList` IS ported now — see `sync/notifylist.rs`. It used to
//     be "an AtomicI64 waiter count plus the internal Sema", and that
//     deviation was a BUG rather than a simplification: a Broadcast
//     whose count read zero did nothing at all, so a notification
//     arriving while a waiter sat between its count bump and its park
//     left no record. sync_cond_smoke hung about once in fifty runs.
//     Go's ticket-and-watermark scheme has no such window, and the
//     ablation is recorded in ROADMAP §2w: disable the
//     `less(t, notify)` early return and the hang returns at 1 in 25.
//
//   * No `copyChecker` — Rust's borrow rules already prevent the
//     by-value copy that the checker catches in Go. Cond is a
//     `pub struct` whose only field types (`NotifyList`,
//     `Box<dyn Locker>`) deliberately exclude the manual Clone /
//     Copy that would let the user trip the original error.
//
//   * `L` is `&'static dyn Locker` rather than a Go interface field.
//     This binds the Cond to a specific Mutex / RWMutex chosen at
//     construction time; the goish way to share a Mutex across
//     Conds is to use the same `&MyMutex` for both.

#![allow(non_snake_case)]

extern crate alloc;

use core::sync::atomic::Ordering;


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
    /// Go's `notifyList` (cond.go:23). It replaced a waiter COUNT plus
    /// the semaphore's credit, which lost notifications: a `Broadcast`
    /// whose count read zero did nothing at all, so one arriving while a
    /// waiter sat between its bump and its park left no record.
    /// sync_cond_smoke hung about once in fifty runs on that. See
    /// `sync/notifylist.rs` and ROADMAP §2w.
    notify: crate::sync::notifylist::NotifyList,
}

// go: sdk 1.25.5 sync/cond.go:48-50 NewCond
/// `sync.NewCond(l)` (cond.go:48) — build a Cond with locker `l`.
pub fn NewCond<L: Locker + ?Sized>(l: &L) -> Cond<'_, L> {
    Cond {
        l,
        notify: crate::sync::notifylist::NotifyList::new(),
    }
}

impl<'a, L: Locker + ?Sized> Cond<'a, L> {
    // go: sdk 1.25.5 sync/cond.go:67-73 Cond.Wait
    /// `(*Cond).Wait()` (cond.go:67) — atomically unlocks `L` and
    /// suspends the calling goroutine. After resuming, re-acquires
    /// `L` before returning.
    pub fn Wait(&self) {
        // The ticket is taken while the caller's lock is STILL HELD —
        // that ordering is the fix. A notification landing during the
        // Unlock below bumps `notify` past this ticket, and `Wait` sees
        // it instead of parking forever.
        let t = self.notify.Add();
        self.l.Unlock();
        self.notify.Wait(t);
        self.l.Lock();
    }

    // go: none — goish-only: a diagnostic read for the rare hang in
    // ROADMAP §2w. `waiters` is the count Wait bumps before unlocking;
    // the sema pair is its queue and credit. If a hang shows
    // `waiters > 0` with an EMPTY queue and ZERO credit, a wakeup was
    // lost between the two — which is the window Wait's own comment
    // claims is closed.
    /// `(tickets_issued, tickets_notified, queue_len)`, immediately
    /// stale. A hang with `issued > notified` and an EMPTY queue would
    /// mean a waiter holding a ticket never parked and never returned,
    /// which the ticket check is there to make impossible.
    #[doc(hidden)]
    pub fn __debug_state(&self) -> (u32, u32, usize) {
        return self.notify.__debug_state();
    }

    // go: sdk 1.25.5 sync/cond.go:82-85 Cond.Signal
    /// `(*Cond).Signal()` (cond.go:82) — wake one waiter, if any.
    pub fn Signal(&self) {
        self.notify.NotifyOne();
    }

    // go: sdk 1.25.5 sync/cond.go:91-94 Cond.Broadcast
    /// `(*Cond).Broadcast()` (cond.go:91) — wake all waiters.
    pub fn Broadcast(&self) {
        self.notify.NotifyAll();
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
