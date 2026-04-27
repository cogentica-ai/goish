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
//     waiter count atomically, then `sema.acquire()`s, which is
//     internally a SpinLock + waiter VecDeque + gopark. Unlock with
//     waiters does FIFO handoff: decrement waiter count atomically,
//     leave the locked bit set, and `sema.release()` exactly one
//     waiter — that woken G inherits ownership.
//
//   - Lost-wakeup safety. The Sema's credit-store-on-no-waiter path
//     ensures that a release arriving before the matching acquire
//     finished queuing becomes credit consumable by that acquire.
//     The lock-held-across-park primitive (chan_park_commit) makes
//     the queue-vs-park ordering multi-M correct.
//
// Goish v1 omits Go's starvation mode (lockSlow's 1ms threshold and
// `mutexStarving` bit). FIFO handoff already guarantees no waiter
// starves indefinitely; barging by new arrivals is impossible
// because Lock is gated by waiter count, not just the locked bit.
// Throughput in low-contention regimes might be slightly below Go's
// barging-friendly normal mode; we'll revisit when M17c (futex)
// lands the rest of the runtime sema infrastructure.

use core::sync::atomic::{AtomicU32, Ordering};

use super::sema::Sema;
use crate::syscall;

const M_LOCKED: u32 = 1;
const M_WAITER_UNIT: u32 = 1 << 1;

/// `sync.Mutex` — mutual-exclusion lock. Zero value is unlocked.
/// Mirrors `sync.Mutex` (mutex.go:30).
pub struct Mutex {
    state: AtomicU32,
    sema: Sema,
}

unsafe impl Send for Mutex {}
unsafe impl Sync for Mutex {}

impl Mutex {
    pub const fn new() -> Self {
        Mutex {
            state: AtomicU32::new(0),
            sema: Sema::new(),
        }
    }

    /// Lock locks `m`. Mirrors `Mutex.Lock` (mutex.go:45).
    #[inline]
    pub fn Lock(&self) {
        // Fast path: CAS the unlocked state to locked.
        if self
            .state
            .compare_exchange(0, M_LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        self.lock_slow();
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
                    .compare_exchange(
                        old,
                        old | M_LOCKED,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
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
                .compare_exchange(
                    old,
                    old + M_WAITER_UNIT,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                continue;
            }
            self.sema.acquire();
            // Resumed: Unlock has handed us ownership and decremented
            // the waiter count. The locked bit is set; we own it.
            return;
        }
    }

    /// TryLock tries to acquire the lock without blocking. Mirrors
    /// `Mutex.TryLock` (mutex.go:54).
    #[inline]
    pub fn TryLock(&self) -> bool {
        // Single CAS: only succeeds if state is exactly 0 (no
        // waiters, not locked). Matches Go's "no waiters and not
        // locked" guard at internal/sync/mutex.go:77-87 modulo the
        // starvation bit we don't carry.
        self.state
            .compare_exchange(0, M_LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Unlock unlocks `m`. Panics on unlock of unlocked. Mirrors
    /// `Mutex.Unlock` (mutex.go:64).
    #[inline]
    pub fn Unlock(&self) {
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
                // No waiters: drop locked bit.
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
            // The released waiter inherits ownership.
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

impl Default for Mutex {
    fn default() -> Self {
        Mutex::new()
    }
}

fn fatal(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(2);
}
