// go: file sync/once.go decls: Once.Do
//
// once.go — Go's `sync.Once`.
//
// This file carried NO provenance anchors, like the rest of src/sync/;
// it matched Go by name only. Diffed and anchored now.
//
// goishlint:ignore GOISH018 doSlow — Go splits the mutex-held path into `doSlow` so `Do`'s fast path stays inlinable; goish's `Do` is both, with the same ordering: the store to `done` happens under the mutex, after `f` returns.
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
    // go: none — goish idiom: Go documents that the zero Once is ready
    //     to use; a Rust struct holding an AtomicBool and a Mutex needs
    //     a constructor, and this one is `const` so it can still be a
    //     static.
    /// Build a fresh Once. `const` so `static O: Once = Once::new();`
    /// is allowed.
    pub const fn new() -> Self {
        Once {
            done: AtomicBool::new(false),
            m: Mutex::new(()),
        }
    }

    // go: sdk 1.25.5 sync/once.go:52-71 Once.Do
    /// Go: "Do calls the function f if and only if Do is being called
    /// for the first time for this instance of Once. … Because no call
    /// to Do returns until the one call to f returns, if f causes Do to
    /// be called, it will deadlock."
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
        let _g = self.m.Lock();
        // Re-check under the lock — another goroutine may have run
        // f while we were waiting for the mutex.
        if !self.done.load(Ordering::Relaxed) {
            f();
            // Release: pair with the Acquire in Do's fast path.
            self.done.store(true, Ordering::Release);
        }
        // _g drops -> unlocks
    }
}

impl Default for Once {
    fn default() -> Self {
        Once::new()
    }
}
