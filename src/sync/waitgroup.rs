// sync::WaitGroup — Go's `sync.WaitGroup` (Add / Done / Wait / Go).
//
// Reference: /share/go/src/sync/waitgroup.go.
//
// Implementation parity with Go: bit-packed AtomicU64 state
// `[counter:32 | waiters:32]` for lock-free Add/Done/Wait fast paths;
// the slow path (counter→0 wakes all waiters) uses the internal Sema.
//
//   - `Add(delta)`: AtomicAdd(state, delta << 32). On counter→0 with
//     waiters>0, do a single CAS to zero the state and `release_n`
//     to wake every parked goroutine.
//   - `Wait`: load state; if counter==0 return. Else CAS waiters+=1,
//     then `sema.acquire()`. After wake, return.
//
// Lost-wakeup safety: like Mutex, the queue-vs-state ordering is
// handled by Sema's credit-store-on-no-waiter behavior. Specifically,
// if Add observes waiters>0 just before the matching Wait completes
// its sema.acquire enqueue, Add's release_n stores credit; the Wait
// consumes it without parking.
//
// Goish v1 omits Go's "concurrent Add/Wait misuse" panic check —
// well-formed code is fine.

use core::sync::atomic::{AtomicU64, Ordering};

use super::sema::Sema;
use crate::syscall;

const WG_WAITER_MASK: u64 = (1 << 32) - 1;

/// `sync.WaitGroup` — counting semaphore for "wait for these tasks
/// to finish". Zero value is ready to use. Mirrors
/// `sync.WaitGroup` (waitgroup.go:48).
pub struct WaitGroup {
    state: AtomicU64,
    sema: Sema,
}

unsafe impl Send for WaitGroup {}
unsafe impl Sync for WaitGroup {}

impl WaitGroup {
    pub const fn new() -> Self {
        WaitGroup {
            state: AtomicU64::new(0),
            sema: Sema::new(),
        }
    }

    /// Add adds `delta` to the WaitGroup task counter. Negative
    /// counter panics. Mirrors `WaitGroup.Add` (waitgroup.go:77).
    pub fn Add(&self, delta: i64) {
        // Fold delta into the counter half (high 32 bits).
        let raw_delta = (delta as u64).wrapping_shl(32);
        let state = self.state.fetch_add(raw_delta, Ordering::AcqRel);
        // Compute new counter and current waiters.
        let new_state = state.wrapping_add(raw_delta);
        let counter = (new_state >> 32) as i64; // sign-extended
        let waiters = (new_state & WG_WAITER_MASK) as u32;

        if counter < 0 {
            fatal(b"goish: sync: negative WaitGroup counter\n");
        }
        if counter > 0 || waiters == 0 {
            return;
        }

        // counter == 0 and waiters > 0: zero the state, then wake all.
        // Use CAS to ensure we're the unique waker — concurrent
        // Add(0)s shouldn't double-release.
        if self
            .state
            .compare_exchange(new_state, 0, Ordering::Release, Ordering::Relaxed)
            .is_err()
        {
            // Another Add raced; either it took the wake, or it
            // bumped waiters/counter. We're done — the eventual zero
            // transition will release.
            return;
        }
        self.sema.release_n(waiters as i64);
    }

    /// Done decrements the counter by 1. Mirrors
    /// `WaitGroup.Done` (waitgroup.go:155).
    #[inline]
    pub fn Done(&self) {
        self.Add(-1);
    }

    // go: none — goish-only, for the reason in the doc below.
    /// goish-only: a non-blocking read of "is the counter zero yet?".
    ///
    /// `Wait` parks on the semaphore, which is the right thing when
    /// there is nothing else to do. A caller that must ALSO do
    /// something on a deadline (httptest's Close logs why it is stuck
    /// after five seconds) cannot park, and Go reaches for
    /// `time.AfterFunc` there — which in goish holds a sleeper
    /// goroutine the runtime waits for at exit.
    #[inline]
    pub fn __try_wait(&self) -> bool {
        let state = self.state.load(Ordering::Acquire);
        return crate::int64(state >> 32) == 0;
    }

    /// Wait blocks until the counter reaches zero. Mirrors
    /// `WaitGroup.Wait` (waitgroup.go:160).
    pub fn Wait(&self) {
        loop {
            let state = self.state.load(Ordering::Acquire);
            let counter = (state >> 32) as i64;
            if counter == 0 {
                return;
            }
            // Increment waiter count (low 32 bits) atomically.
            if self
                .state
                .compare_exchange(state, state + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            self.sema.acquire();
            // Resumed: counter reached 0 (we observed before wake).
            return;
        }
    }

    /// Go calls `f` in a new goroutine and adds it to the
    /// WaitGroup. Mirrors `WaitGroup.Go` (waitgroup.go:235), a Go
    /// 1.25 convenience method.
    ///
    /// **Lifetime-bound (Form 3):** `f` is bounded by the borrow
    /// lifetime `'a` of `&self`, not `'static`. This lets `f`
    /// capture references to data that lives at least as long as
    /// `self`. Soundness rests on `WaitGroup`'s `Drop` impl, which
    /// blocks on `Wait()`: when `self` falls out of scope, every
    /// spawned closure has already called `Done()` and finished,
    /// so the captured borrows never outlive their referents.
    ///
    /// Backward-compatible: static WaitGroups (`'a = 'static`)
    /// still work; closures are simply more permissive now.
    pub fn Go<'a, F>(&'a self, f: F)
    where
        F: FnOnce() + Send + 'a,
    {
        self.go_inner(None, f);
    }

    /// Same as `Go`, but spawns the goroutine with an explicit stack
    /// size in bytes (rounded up to the nearest 4 KiB page). Mirrors
    /// the relationship between `runtime::sched::newproc` and
    /// `newproc_with_stack`.
    ///
    /// Use when the default 2 KiB stack is too small — e.g., debug
    /// builds (no inlining inflates frame depth), or workloads that
    /// recurse / hold large stack-allocated buffers.
    pub fn GoStack<'a, F>(&'a self, stack_size: usize, f: F)
    where
        F: FnOnce() + Send + 'a,
    {
        self.go_inner(Some(stack_size), f);
    }

    fn go_inner<'a, F>(&'a self, stack_size: Option<usize>, f: F)
    where
        F: FnOnce() + Send + 'a,
    {
        self.Add(1);
        let body: alloc::boxed::Box<dyn FnOnce() + Send + 'a> = alloc::boxed::Box::new(move || {
            f();
            self.Done();
        });

        // SAFETY: `WaitGroup`'s `Drop` impl calls `Wait()`, which
        // blocks until the counter reaches zero — i.e., until every
        // spawned closure has run `self.Done()` and returned. So
        // although the runtime's `newproc` requires a `'static` Box,
        // every spawned closure with a non-`'static` lifetime `'a`
        // is guaranteed to finish before `'a` ends. Extending the
        // lifetime bound on the Box (without changing the actual
        // captures) is therefore sound.
        //
        // The only escape hatch is `core::mem::forget(wg)`, which
        // bypasses Drop. That is documented as the explicit way to
        // leak goroutines past the WaitGroup's scope.
        let body_static: alloc::boxed::Box<dyn FnOnce() + Send + 'static> =
            unsafe { core::mem::transmute(body) };
        match stack_size {
            Some(sz) => crate::runtime::sched::newproc_with_stack(sz, body_static),
            None => crate::runtime::sched::newproc(body_static),
        }
    }
}

impl Drop for WaitGroup {
    /// Block until the counter reaches zero before releasing the
    /// `WaitGroup` storage. This is the structural-correctness
    /// half of `Go`'s lifetime contract: every closure spawned by
    /// `Go(...)` may borrow data with the same lifetime as the
    /// `WaitGroup`, and Drop here guarantees those closures
    /// complete before that data is freed.
    ///
    /// Fast path: if the counter is already zero (because the user
    /// called `Wait()` explicitly, or no `Go` was ever invoked),
    /// this is a single atomic load and return.
    ///
    /// Slow path: park the calling goroutine in `Wait()` until the
    /// last spawned closure runs `Done()`.
    ///
    /// Note: under `panic = "abort"` (goish's default), this Drop
    /// does not run on panic — the process aborts. In-flight
    /// goroutines are killed mid-execution by the abort.
    fn drop(&mut self) {
        let counter = (self.state.load(Ordering::Acquire) >> 32) as i64;
        if counter == 0 {
            return;
        }
        self.Wait();
    }
}

impl Default for WaitGroup {
    fn default() -> Self {
        WaitGroup::new()
    }
}

fn fatal(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(2);
}
