// sync::RWMutex — Go's `sync.RWMutex` (RLock / RUnlock / Lock /
// Unlock / TryRLock / TryLock).
//
// Reference: /share/go/src/sync/rwmutex.go.
//
// Direct port of Go's algorithm:
//
//   readerCount: signed int. Positive = active readers. Negative =
//     a writer is pending; subtract MAX to recover the active reader
//     count at the moment Lock flipped the sign.
//   readerWait: number of active readers the pending writer is still
//     waiting on. The last reader to RUnlock under "writer pending"
//     drives this to 0 and signals writerSem.
//   w: Mutex held for writer-vs-writer mutual exclusion.
//   readerSem / writerSem: internal semaphores (our Sema, since we
//     don't have a global runtime sema table yet).
//
// Lock-free fast paths:
//   - RLock: AtomicAdd(readerCount, +1). If result >= 0, return.
//   - RUnlock: AtomicAdd(readerCount, -1). If result >= 0, return.
//   - Lock fast: rw.w.TryLock() + CAS(readerCount, 0, -MAX) — already
//     reflected in TryLock.
//
// All four "if result < 0" branches are the slow paths that touch
// the Sema or readerWait counter. Mirrors Go's rwmutex.go function
// for function (line cites in comments below).

use core::sync::atomic::{AtomicI32, Ordering};

use super::sema::Sema;
use super::Mutex;
use crate::syscall;

const RW_MAX_READERS: i32 = 1 << 30;

/// `sync.RWMutex` — reader/writer mutex. Zero value is unlocked.
/// Many readers OR one writer. New readers wait for a pending
/// writer (no reader-starvation). Mirrors `sync.RWMutex`
/// (rwmutex.go:39).
pub struct RWMutex {
    w: Mutex,           // writer-vs-writer
    writer_sem: Sema,   // writer waits on draining readers
    reader_sem: Sema,   // readers wait on a pending writer
    reader_count: AtomicI32,
    reader_wait: AtomicI32,
}

unsafe impl Send for RWMutex {}
unsafe impl Sync for RWMutex {}

impl RWMutex {
    pub const fn new() -> Self {
        RWMutex {
            w: Mutex::new(()),
            writer_sem: Sema::new(),
            reader_sem: Sema::new(),
            reader_count: AtomicI32::new(0),
            reader_wait: AtomicI32::new(0),
        }
    }

    /// RLock locks `rw` for reading. Mirrors `RWMutex.RLock`
    /// (rwmutex.go:67).
    #[inline]
    pub fn RLock(&self) {
        if self.reader_count.fetch_add(1, Ordering::Acquire) < 0 {
            // A writer is pending — park on reader_sem.
            self.reader_sem.acquire();
        }
    }

    /// TryRLock tries to acquire a read lock without blocking.
    /// Mirrors `RWMutex.TryRLock` (rwmutex.go:87).
    pub fn TryRLock(&self) -> bool {
        loop {
            let c = self.reader_count.load(Ordering::Relaxed);
            if c < 0 {
                return false;
            }
            if self
                .reader_count
                .compare_exchange(c, c + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// RUnlock releases a read lock. Panics if `rw` was not
    /// read-locked. Mirrors `RWMutex.RUnlock` (rwmutex.go:114).
    #[inline]
    pub fn RUnlock(&self) {
        let r = self.reader_count.fetch_sub(1, Ordering::Release) - 1;
        if r < 0 {
            self.r_unlock_slow(r);
        }
    }

    #[cold]
    #[inline(never)]
    fn r_unlock_slow(&self, r: i32) {
        if r + 1 == 0 || r + 1 == -RW_MAX_READERS {
            fatal(b"goish: sync: RUnlock of unlocked RWMutex\n");
        }
        // A writer is pending. If we're the last active reader, signal it.
        if self.reader_wait.fetch_sub(1, Ordering::Release) == 1 {
            self.writer_sem.release();
        }
    }

    /// Lock locks `rw` for writing. If the lock is held by readers
    /// or another writer, blocks. Mirrors `RWMutex.Lock`
    /// (rwmutex.go:144).
    pub fn Lock(&self) {
        // First, resolve writer-vs-writer. Manual lock — the
        // matching Unlock happens in our `Unlock` method.
        self.w.LockManual();
        // Announce a pending writer to readers. fetch_sub returns the
        // OLD readerCount, which equals the number of active readers
        // at the moment of the flip (since prior to the flip the
        // count was non-negative).
        let r_active = self
            .reader_count
            .fetch_sub(RW_MAX_READERS, Ordering::Acquire);
        // Wait for active readers to drain. reader_wait may already
        // be negative from concurrent RUnlock-slow calls; the +r_active
        // brings it back into balance. Park iff the resulting value
        // (old + r_active) is non-zero.
        if r_active != 0 {
            let old_wait = self.reader_wait.fetch_add(r_active, Ordering::Acquire);
            if old_wait + r_active != 0 {
                self.writer_sem.acquire();
            }
        }
    }

    /// TryLock tries to acquire a write lock without blocking.
    /// Mirrors `RWMutex.TryLock` (rwmutex.go:169).
    pub fn TryLock(&self) -> bool {
        if !self.w.TryLockManual() {
            return false;
        }
        if self
            .reader_count
            .compare_exchange(0, -RW_MAX_READERS, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.w.Unlock();
            return false;
        }
        true
    }

    /// Unlock releases a write lock. Panics if `rw` was not
    /// write-locked. Mirrors `RWMutex.Unlock` (rwmutex.go:201).
    pub fn Unlock(&self) {
        // Announce no writer pending — un-flip readerCount.
        let r = self
            .reader_count
            .fetch_add(RW_MAX_READERS, Ordering::Release)
            + RW_MAX_READERS;
        if r >= RW_MAX_READERS {
            fatal(b"goish: sync: Unlock of unlocked RWMutex\n");
        }
        // Wake every reader that parked while the writer held the lock.
        if r > 0 {
            self.reader_sem.release_n(r as i64);
        }
        // Allow other writers to proceed.
        self.w.Unlock();
    }
}

impl Default for RWMutex {
    fn default() -> Self {
        RWMutex::new()
    }
}

fn fatal(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(2);
}
