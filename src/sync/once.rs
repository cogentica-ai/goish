// sync::Once — Go's `sync.Once` (Do).
//
// Verbatim port of /share/go/src/sync/once.go: an AtomicBool fast
// path + a Mutex slow path. Mirrors Go line for line; the slow path
// is the load-bearing piece — without holding the Mutex across `f`,
// a second concurrent caller could see done=false, race ahead, and
// return before f's effects were observable.

use core::sync::atomic::{AtomicBool, Ordering};

use super::Mutex;

/// `sync.Once` — runs `f` exactly once across any number of `Do`
/// calls. Safe to share across goroutines.
///
/// Mirrors `sync.Once` (once.go:20). The zero value is ready to use.
pub struct Once {
    /// Whether the action has been performed. Placed first so the
    /// fast path's `done.load()` is one instruction.
    done: AtomicBool,
    m: Mutex,
}

impl Once {
    /// Build a fresh Once. `const` so `static O: Once = Once::new();`
    /// is allowed.
    pub const fn new() -> Self {
        Once {
            done: AtomicBool::new(false),
            m: Mutex::new(),
        }
    }

    /// `Do` calls `f` if and only if `Do` is being called for the
    /// first time on this `Once`. Concurrent callers all wait for
    /// the first invocation to complete before returning. Mirrors
    /// `sync.Once.Do` (once.go:52).
    ///
    /// If `f` panics, the action is still considered to have
    /// returned (matches Go); future `Do` calls will return without
    /// calling `f`. Goish v1 doesn't unwind on panic (we abort), so
    /// this distinction is moot — a panicking `f` aborts the
    /// process anyway.
    pub fn Do<F: FnOnce()>(&self, f: F) {
        // Fast path: avoid the mutex if done is already true.
        // Acquire ordering: synchronizes with the slow-path
        // `done.store(true, Release)` so callers see all of `f`'s
        // writes when they observe done==true.
        if !self.done.load(Ordering::Acquire) {
            self.do_slow(f);
        }
    }

    #[cold]
    #[inline(never)]
    fn do_slow<F: FnOnce()>(&self, f: F) {
        self.m.Lock();
        // Re-check under the lock — another goroutine may have run
        // f while we were waiting for the mutex.
        if !self.done.load(Ordering::Relaxed) {
            f();
            // Release: pair with the Acquire in Do's fast path.
            self.done.store(true, Ordering::Release);
        }
        self.m.Unlock();
    }
}

impl Default for Once {
    fn default() -> Self {
        Once::new()
    }
}
