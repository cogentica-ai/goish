// sync::sema — internal counting semaphore.
//
// Used as the slow-path primitive for Mutex, WaitGroup, and RWMutex.
// Models Go's runtime address-based semaphore (runtime/sema.go) but
// without the global semroot hash table — each consumer (Mutex,
// RWMutex's reader/writer slots, WaitGroup) owns its own Sema
// instance.
//
// Semantics:
//
//   - `acquire()` blocks until credit is available, then consumes 1.
//   - `release()` either wakes one parked goroutine OR (if no waiter)
//     stores 1 unit of credit for a future acquire().
//   - `release_n(n)` releases n at once; matches Go's
//     `runtime_Semrelease` followed by N-1 more, but as one
//     under-lock operation (used by RWMutex.Unlock waking N readers).
//
// The credit-store-on-no-waiter behavior is what makes this race-
// free against the classic lost-wakeup pattern: a release that
// arrives before the matching acquire has finished queuing itself
// becomes a credit, which the acquire then consumes without parking.
//
// **Allocation-free intrusive queue (task #110).** Earlier versions
// used `VecDeque<NonNull<G>>` for the waiter list, which on first
// push triggered an allocator path 24+ frames deep — overflowing
// the M26 default 2 KiB stack and crashing at the next `RET` when
// RSP crossed below the stackpool span boundary. Diagnosis via
// gdb post-mortem on a captured core (commit f2e334a). The fix
// here threads the waiter chain through `g.sema_next`, mirroring
// Go's `sudog.next` discipline (runtime/runtime2.go:335). Push and
// pop are O(1) and allocation-free, so the slow path no longer
// re-enters the allocator under the Sema lock.

use crate::runtime::sched::{
    chan_park_commit, current_g, gopark, goready, G,
};
use crate::runtime::spin::{raw_lock, raw_unlock, SpinLock};
use core::ptr::NonNull;

pub(crate) struct Sema {
    state: SpinLock<SemaState>,
}

struct SemaState {
    credit: i64,
    /// Head of the FIFO waiter chain (oldest first). Linked via
    /// `g.sema_next`. Null when empty.
    head: *mut G,
    /// Tail of the FIFO waiter chain (newest). Null when empty.
    /// Maintained so `acquire` can append in O(1).
    tail: *mut G,
}

// SemaState contains raw `*mut G`. Access is serialized by the
// outer SpinLock so the standard Send invariants hold.
unsafe impl Send for SemaState {}

impl Sema {
    pub const fn new() -> Self {
        Sema {
            state: SpinLock::new(SemaState {
                credit: 0,
                head: core::ptr::null_mut(),
                tail: core::ptr::null_mut(),
            }),
        }
    }

    /// Block until credit is available, then consume one. Mirrors
    /// `runtime_Semacquire`.
    pub fn acquire(&self) {
        let lock_atom = self.state.lock_atom();
        unsafe { raw_lock(lock_atom); }
        let s = unsafe { self.state.data_unchecked() };
        if s.credit > 0 {
            s.credit -= 1;
            unsafe { raw_unlock(lock_atom); }
            return;
        }
        let g = current_g().expect("Sema::acquire outside any goroutine");
        // Append `g` to the back of the intrusive chain. We hold the
        // Sema's SpinLock, so the only writer of `g.sema_next` is us.
        unsafe {
            (*g.as_ptr()).sema_next = core::ptr::null_mut();
            if s.tail.is_null() {
                s.head = g.as_ptr();
            } else {
                (*s.tail).sema_next = g.as_ptr();
            }
            s.tail = g.as_ptr();
        }
        // chan_park_commit reads M.waitlock and unlocks it on the
        // scheduler stack post-swap (see runtime/sched/scheduler.rs).
        // The lock is held continuously across enqueue → swap, which
        // is what closes the lost-wakeup race.
        gopark(chan_park_commit, lock_atom);
    }

    /// Release one. If a waiter is queued, wake it; else store
    /// credit. Mirrors `runtime_Semrelease`.
    pub fn release(&self) {
        let lock_atom = self.state.lock_atom();
        unsafe { raw_lock(lock_atom); }
        let s = unsafe { self.state.data_unchecked() };
        let g = unsafe { pop_head(s) };
        if let Some(g) = g {
            unsafe { raw_unlock(lock_atom); }
            goready(g);
        } else {
            s.credit += 1;
            unsafe { raw_unlock(lock_atom); }
        }
    }

    /// Release `n` at once. Wakes up to `n` waiters; remainder
    /// becomes credit. Used by RWMutex.Unlock to wake all parked
    /// readers in a single critical section.
    ///
    /// **Allocation-free**: pops one waiter at a time under the
    /// lock, drops the lock, calls `goready`, repeats. No batching
    /// vector. Between iterations a concurrent `release()` may also
    /// pop a waiter or contribute credit, which is fine — both
    /// outcomes preserve the FIFO discipline and credit accounting.
    /// On the iteration that finds the head null, the remaining
    /// `left` count is folded into `credit` as the original
    /// implementation did.
    pub fn release_n(&self, n: i64) {
        if n <= 0 {
            return;
        }
        let lock_atom = self.state.lock_atom();
        let mut left = n;
        loop {
            let next: Option<NonNull<G>> = unsafe {
                raw_lock(lock_atom);
                let s = self.state.data_unchecked();
                match pop_head(s) {
                    Some(g) => {
                        raw_unlock(lock_atom);
                        Some(g)
                    }
                    None => {
                        s.credit += left;
                        raw_unlock(lock_atom);
                        None
                    }
                }
            };
            match next {
                Some(g) => {
                    goready(g);
                    left -= 1;
                    if left == 0 {
                        return;
                    }
                }
                None => return,
            }
        }
    }
}

/// Pop the head of the intrusive waiter chain. Caller must hold the
/// Sema's SpinLock. Returns `None` if the chain is empty.
///
/// Safety: `s.head` and `s.tail` are mutated; both are protected by
/// the Sema lock. The popped G's `sema_next` is left as-is — the G
/// is about to be `goready`'d and the field is overwritten on its
/// next park.
unsafe fn pop_head(s: &mut SemaState) -> Option<NonNull<G>> {
    if s.head.is_null() {
        return None;
    }
    let g = s.head;
    s.head = (*g).sema_next;
    if s.head.is_null() {
        s.tail = core::ptr::null_mut();
    }
    NonNull::new(g)
}
