// runtime::note — one-shot signal modeled after Go's `note` primitive.
//
// Verbatim port of the futex-backed implementation at
// /share/go/src/runtime/lock_futex.go:
//
//   func noteclear(n *note)  { n.key = 0 }
//   func notewakeup(n *note) {
//       old := atomic.Xchg(&n.key, 1)
//       if old != 0 { throw("notewakeup - double wakeup") }
//       futexwakeup(&n.key, 1)
//   }
//   func notesleep(n *note) {
//       for atomic.Load(&n.key) == 0 {
//           futexsleep(&n.key, 0, -1)
//       }
//   }
//
// State semantics (per park-cycle, where a cycle = one
// clear→sleep→wakeup→clear sequence):
//   key == 0: not yet woken; sleeper sleeps in futex_wait(key, 0).
//   key == 1: woken; futex_wake delivered (or about to).
//
// Note is one-shot. The sleeper must `clear()` after `sleep()`
// returns and before the next park cycle. The waker must call
// `wakeup()` exactly once per cycle — `Xchg(0→1)` returning a
// non-zero old value is a fatal "double wakeup" bug.
//
// LOC: ~50, used by the M-idle-parking layer (runtime::sched).

use core::sync::atomic::{AtomicU32, Ordering};

use crate::syscall;

/// One-shot wait/wake signal. The `key` field is the futex word —
/// its address is what the kernel binds wait/wake to.
#[repr(C)]
pub struct Note {
    key: AtomicU32,
}

impl Note {
    /// Build a clear (un-signaled) note.
    pub const fn new() -> Self {
        Note {
            key: AtomicU32::new(0),
        }
    }

    /// Reset to the unsignaled state. Sleeper calls this after
    /// `sleep()` returns, before the next park cycle.
    #[inline]
    pub fn clear(&self) {
        self.key.store(0, Ordering::Release);
    }

    /// Sleep until `wakeup()` has been called. If wake already
    /// happened (key != 0), returns immediately. Spurious futex
    /// wakeups are absorbed by the load-loop.
    pub fn sleep(&self) {
        while self.key.load(Ordering::Acquire) == 0 {
            let addr = &self.key as *const AtomicU32 as *const u32;
            // futex(WAIT_PRIVATE, addr, expected=0, ts=null=forever).
            // Returns 0 on wake, -EAGAIN if *addr != 0 (raced with a
            // wakeup just before this call), -EINTR on spurious. All
            // outcomes loop back through the key load above.
            syscall::Futex(addr, syscall::FUTEX_WAIT_PRIVATE, 0, core::ptr::null());
        }
    }

    /// Signal the note. Exactly one call per park cycle is allowed
    /// — a second wakeup before the sleeper has cleared is a fatal
    /// programming bug, matching Go's `notewakeup` invariant.
    pub fn wakeup(&self) {
        let old = self.key.swap(1, Ordering::AcqRel);
        if old != 0 {
            const MSG: &[u8] = b"goish: note: double wakeup\n";
            syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
            syscall::Exit(2);
        }
        let addr = &self.key as *const AtomicU32 as *const u32;
        syscall::Futex(addr, syscall::FUTEX_WAKE_PRIVATE, 1, core::ptr::null());
    }
}
