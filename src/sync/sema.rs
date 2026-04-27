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
// LOC budget: ~60 LOC, used by all four sync primitives.

use alloc::collections::VecDeque;
use core::ptr::NonNull;

use crate::runtime::sched::{
    chan_park_commit, current_g, gopark, goready, G,
};
use crate::runtime::spin::{raw_lock, raw_unlock, SpinLock};

pub(crate) struct Sema {
    state: SpinLock<SemaState>,
}

struct SemaState {
    credit: i64,
    waiters: VecDeque<NonNull<G>>,
}

impl Sema {
    pub const fn new() -> Self {
        Sema {
            state: SpinLock::new(SemaState {
                credit: 0,
                waiters: VecDeque::new(),
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
        s.waiters.push_back(g);
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
        if let Some(g) = s.waiters.pop_front() {
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
    pub fn release_n(&self, n: i64) {
        if n <= 0 {
            return;
        }
        let lock_atom = self.state.lock_atom();
        unsafe { raw_lock(lock_atom); }
        let s = unsafe { self.state.data_unchecked() };
        let mut to_wake = alloc::vec::Vec::with_capacity(n as usize);
        let mut left = n;
        while left > 0 {
            match s.waiters.pop_front() {
                Some(g) => {
                    to_wake.push(g);
                    left -= 1;
                }
                None => break,
            }
        }
        s.credit += left;
        unsafe { raw_unlock(lock_atom); }
        for g in to_wake {
            goready(g);
        }
    }
}
