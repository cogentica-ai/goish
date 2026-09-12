// sync/notifylist — Go's notifyList, the thing `Cond` actually needs.
//
// go: none — goish-only: models Go's `notifyList` (runtime/sema.go
// line 540). Prose rather than an anchor because `sync/sema.rs` — the
// other half of that Go file — does the same, and an anchor would make
// this file owe every declaration in sema.go.
// Go: "a ticket-based notification list used to implement sync.Cond."
//
// WHY THIS EXISTS. goish's Cond counted waiters in an atomic and leaned
// on the semaphore's credit. That loses a notification: `Broadcast` did
// `waiters.swap(0)` and, reading zero, did NOTHING — so a notification
// arriving while a waiter sat between its counter bump and its park left
// no record for the waiter to find. sync_cond_smoke hung about once in
// fifty runs, and a watchdog caught the state:
//
//     STALL phase=2 waiters=2 credit=0 qlen=2
//
// — both goroutines parked at a phase where only one predicate can
// hold. ROADMAP §2w has the full diagnosis.
//
// Go's answer is a TICKET plus a WATERMARK, and the difference is that a
// notification leaves something behind:
//
//   `Add` hands out `t = wait++` BEFORE the caller unlocks.
//   `NotifyAll` stores `notify = wait`.
//   `Wait(t)` returns IMMEDIATELY when `less(t, notify)`.
//
// So a waiter holding a ticket that has not parked yet still sees that
// it was notified. There is no window, rather than a window that the
// credit happens to cover.

#![allow(non_snake_case)]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::runtime::sched::g::G;
use crate::runtime::sched::{chan_park_commit, current_g, goready, gopark};
use crate::runtime::spin::SpinLock;

// go: none — goish-only: Go's `less` (runtime/sema.go line 562).
/// Go: "less checks if a < b, considering a & b running counts that may
/// overflow the 32-bit range, and that their 'unwrapped' difference is
/// always less than 2^31."
///
/// A plain `a < b` would be wrong after `wait` wraps past `u32::MAX` —
/// every outstanding waiter would look already-notified at once.
fn less(a: u32, b: u32) -> bool {
    return crate::convert::int32(a.wrapping_sub(b)) < 0;
}

/// The waiter chain, guarded by the list's SpinLock. Linked through
/// `g.sema_next`, as the semaphore's queue is: a G is parked on at most
/// one thing at a time.
struct ListState {
    head: *mut G,
    tail: *mut G,
}

// SAFETY: the raw `*mut G`s are only ever touched under the SpinLock,
// and G is already Send.
unsafe impl Send for ListState {}

// go: none — goish-only: models Go's `notifyList` (runtime/sema.go
// line 540). Prose rather than an anchor because `sync/sema.rs` — the
// other half of that Go file — does the same, and an anchor would make
// this file owe every declaration in sema.go.
/// Go: "a ticket-based notification list used to implement sync.Cond."
pub struct NotifyList {
    /// Tickets handed out so far. Go keeps this atomic because
    /// `Add` runs under the CALLER's lock, which a `RWMutex` in read
    /// mode makes concurrent.
    wait: AtomicU32,
    /// Tickets up to here have been notified. Read without the lock on
    /// the fast paths, which is why it is atomic rather than plain.
    notify: AtomicU32,
    state: SpinLock<ListState>,
}

impl NotifyList {
    // go: none — goish-only: Go zero-values a notifyList; goish needs a
    // const constructor for a `static`/field initialiser.
    /// An empty list.
    pub const fn new() -> Self {
        return NotifyList {
            wait: AtomicU32::new(0),
            notify: AtomicU32::new(0),
            state: SpinLock::new(ListState {
                head: core::ptr::null_mut(),
                tail: core::ptr::null_mut(),
            }),
        };
    }

    // go: none — goish-only: Go's free function `notifyListAdd`
    // (runtime/sema.go line 571) is a METHOD here, so the name drops the
    // type prefix. Same treatment as `sync/sema.rs`, which models
    // semacquire/semrelease as `Sema::acquire`/`release`.
    /// Go: "adds the caller to a notify list such that it can receive
    /// notifications. The caller must eventually call notifyListWait."
    ///
    /// Must be called while still holding the Cond's locker — that is
    /// the whole point. The ticket is taken before the unlock, so a
    /// notification that lands during the unlock is still addressed to
    /// this waiter.
    pub fn Add(&self) -> u32 {
        return self.wait.fetch_add(1, Ordering::AcqRel);
    }

    // go: none — goish-only: Go's free function `notifyListWait`
    // (runtime/sema.go line 581) is a METHOD here, so the name drops the
    // type prefix. Same treatment as `sync/sema.rs`, which models
    // semacquire/semrelease as `Sema::acquire`/`release`.
    /// Go: "waits for a notification. If one has been sent since
    /// notifyListAdd was called, it returns immediately. Otherwise, it
    /// blocks."
    pub fn Wait(&self, t: u32) {
        let lock_atom = self.state.lock_atom();
        unsafe {
            crate::runtime::spin::raw_lock(lock_atom);
        }
        // Already notified: return without parking. This is the branch
        // the old counter scheme had no equivalent of, and its absence
        // is what lost notifications.
        if less(t, self.notify.load(Ordering::Acquire)) {
            unsafe {
                crate::runtime::spin::raw_unlock(lock_atom);
            }
            return;
        }
        let g = current_g().expect("NotifyList::Wait outside any goroutine");
        let s = unsafe { self.state.data_unchecked() };
        unsafe {
            (*g.as_ptr()).sema_next = core::ptr::null_mut();
            (*g.as_ptr()).notify_ticket = t;
            if s.tail.is_null() {
                s.head = g.as_ptr();
            } else {
                (*s.tail).sema_next = g.as_ptr();
            }
            s.tail = g.as_ptr();
        }
        // The lock is held continuously from the notify check through
        // the enqueue and into the park — `chan_park_commit` releases it
        // on the scheduler stack after the switch. A notifier therefore
        // cannot run between "not yet notified" and "queued".
        gopark(chan_park_commit, lock_atom);
    }

    // go: none — goish-only: Go's free function `notifyListNotifyAll`
    // (runtime/sema.go line 616) is a METHOD here, so the name drops the
    // type prefix. Same treatment as `sync/sema.rs`, which models
    // semacquire/semrelease as `Sema::acquire`/`release`.
    /// Go: "notifies all entries in the list."
    pub fn NotifyAll(&self) {
        // Fast path: no new waiters since the last notification.
        if self.wait.load(Ordering::Acquire) == self.notify.load(Ordering::Acquire) {
            return;
        }
        let lock_atom = self.state.lock_atom();
        let head;
        unsafe {
            crate::runtime::spin::raw_lock(lock_atom);
            let s = self.state.data_unchecked();
            head = s.head;
            s.head = core::ptr::null_mut();
            s.tail = core::ptr::null_mut();
            // Every ticket handed out so far is now notified. A waiter
            // already in the list is woken below; one that has a ticket
            // but has not parked yet will see this in `Wait`.
            self.notify
                .store(self.wait.load(Ordering::Acquire), Ordering::Release);
            crate::runtime::spin::raw_unlock(lock_atom);
        }
        // Ready them OUTSIDE the lock, as Go does: `goready` can enter
        // the scheduler, and holding a SpinLock across that is the
        // `schedule: holding locks` abort.
        let mut g = head;
        while !g.is_null() {
            let next = unsafe { (*g).sema_next };
            unsafe {
                (*g).sema_next = core::ptr::null_mut();
            }
            if let Some(nn) = NonNull::new(g) {
                goready(nn);
            }
            g = next;
        }
    }

    // go: none — goish-only: Go's free function `notifyListNotifyOne`
    // (runtime/sema.go line 653) is a METHOD here, so the name drops the
    // type prefix. Same treatment as `sync/sema.rs`, which models
    // semacquire/semrelease as `Sema::acquire`/`release`.
    /// Go: "notifies one entry in the list."
    ///
    /// Wakes the waiter holding the NEXT ticket specifically, not
    /// whichever is at the head. Go scans for it because a waiter may
    /// still be between `Add` and `Wait` and therefore absent from the
    /// list — in which case bumping `notify` is the whole job and that
    /// waiter will notice in `Wait`.
    pub fn NotifyOne(&self) {
        if self.wait.load(Ordering::Acquire) == self.notify.load(Ordering::Acquire) {
            return;
        }
        let lock_atom = self.state.lock_atom();
        let mut found: *mut G = core::ptr::null_mut();
        unsafe {
            crate::runtime::spin::raw_lock(lock_atom);
            let t = self.notify.load(Ordering::Acquire);
            if t == self.wait.load(Ordering::Acquire) {
                crate::runtime::spin::raw_unlock(lock_atom);
                return;
            }
            self.notify.store(t.wrapping_add(1), Ordering::Release);
            let s = self.state.data_unchecked();
            let mut prev: *mut G = core::ptr::null_mut();
            let mut cur = s.head;
            while !cur.is_null() {
                if (*cur).notify_ticket == t {
                    let next = (*cur).sema_next;
                    if prev.is_null() {
                        s.head = next;
                    } else {
                        (*prev).sema_next = next;
                    }
                    if s.tail == cur {
                        s.tail = prev;
                    }
                    (*cur).sema_next = core::ptr::null_mut();
                    found = cur;
                    break;
                }
                prev = cur;
                cur = (*cur).sema_next;
            }
            crate::runtime::spin::raw_unlock(lock_atom);
        }
        if let Some(nn) = NonNull::new(found) {
            goready(nn);
        }
    }

    // go: none — goish-only: a diagnostic read, for the investigation in
    // ROADMAP §2w and whatever the next one is.
    /// `(wait, notify, queue_len)` — a snapshot, immediately stale.
    #[doc(hidden)]
    pub fn __debug_state(&self) -> (u32, u32, usize) {
        let lock_atom = self.state.lock_atom();
        let mut n = 0usize;
        unsafe {
            crate::runtime::spin::raw_lock(lock_atom);
            let s = self.state.data_unchecked();
            let mut g = s.head;
            while !g.is_null() && n < 1024 {
                n += 1;
                g = (*g).sema_next;
            }
            crate::runtime::spin::raw_unlock(lock_atom);
        }
        return (
            self.wait.load(Ordering::Acquire),
            self.notify.load(Ordering::Acquire),
            n,
        );
    }
}
