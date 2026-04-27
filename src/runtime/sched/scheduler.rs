// runtime::sched::scheduler — single-threaded cooperative scheduler.
//
// Layout (M16b):
//
//   - **`Sched`** — holds the run queue, the saved scheduler-thread
//     context (`sched_buf`), and a pointer to the currently-running
//     `G`. One global instance.
//
//   - **`newproc(closure)`** — allocate a `G` with a fresh stack,
//     push it onto the run queue. Mirrors Go's
//     `runtime.newproc(fn)` (proc.go:5158) modulo the GC and
//     multi-P pieces we don't have yet.
//
//   - **`schedule()`** — drain the run queue: pop a G, swap to it,
//     wait until it yields or exits, then loop. Returns when the
//     queue is empty. Called from `__goish_rt0` after the user's
//     `fn main()` returns, so any goroutines spawned by main get
//     a chance to run.
//
//   - **`Gosched()`** — current G voluntarily yields the CPU. Pushes
//     itself back onto the queue and swaps to the scheduler.
//
//   - **`goexit()`** — internal. Called when a G's entry closure
//     returns. Marks the G dead and swaps back to the scheduler,
//     which will free the G's stack on its next dispatch.
//
// Concurrency: a single `SpinLock<Sched>` guards all state. We
// always release the lock before calling `swap_context` so the
// resumed G can re-acquire it (e.g. to call `Gosched`). Single
// thread today, so the lock is uncontended; M17a will move to per-P
// run queues + work stealing where the lock matters.
//
// Rust safety: `G` is heap-allocated via `Box`; the run queue holds
// raw `NonNull<G>` rather than `Box<G>` so we can stash the
// currently-running G's pointer in `current` without invalidating
// the queue's `Box` ownership. When a `G` finishes (status `Dead`),
// the scheduler reconstructs the `Box` via `Box::from_raw` and
// drops it, which runs `Drop` on the Stack (munmap) and the entry
// (already `None` by then).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::ptr::NonNull;

use super::g::{GStatus, G};
use super::gobuf::{make_context, swap_context, Gobuf};
use super::m::current_m;
use crate::runtime::spin::SpinLock;

/// Globally-shared scheduler state. After M17a-β1, this only carries
/// the (still-global) run queue; per-thread state — currently-running
/// G, scheduler-side gobuf — moved to `super::m::M` so it can be
/// per-thread once multi-M lands. M17b will further split the run
/// queue per-P for work stealing.
pub struct Sched {
    /// FIFO of runnable goroutines.
    runq: VecDeque<NonNull<G>>,
}

impl Sched {
    pub const fn new() -> Self {
        Sched {
            runq: VecDeque::new(),
        }
    }
}

unsafe impl Send for Sched {}

static SCHED: SpinLock<Sched> = SpinLock::new(Sched::new());

/// Spawn a new goroutine running `closure`. Returns immediately
/// after enqueueing the G; the closure does not run until the
/// scheduler dispatches.
///
/// Mirrors Go's `runtime.newproc(fn)` from proc.go:5158.
pub fn newproc(closure: Box<dyn FnOnce()>) {
    let g = Box::leak(Box::new(G::new(closure)));
    let g_ptr = NonNull::from(&mut *g);
    SCHED.lock().runq.push_back(g_ptr);
}

/// Voluntarily yield the CPU. Equivalent to Go's `runtime.Gosched()`
/// (proc.go:387). If called from outside any goroutine (i.e. on the
/// scheduler thread itself), this is a no-op.
#[allow(non_snake_case)]
pub fn Gosched() {
    let g_ptr = match current_m().lock().current_g {
        Some(p) => p,
        None => return,
    };
    unsafe {
        (*g_ptr.as_ptr()).status = GStatus::Runnable;
    }
    SCHED.lock().runq.push_back(g_ptr);
    // Capture pointers before releasing locks — both `MAIN_M` (M17a-β1)
    // and `SCHED` are static, so the addresses are stable.
    let buf_from = unsafe { &mut (*g_ptr.as_ptr()).gobuf as *mut Gobuf };
    let buf_to = {
        let m = current_m().lock();
        &m.sched_buf as *const Gobuf
    };
    unsafe {
        swap_context(buf_from, buf_to);
    }
    unsafe {
        (*g_ptr.as_ptr()).status = GStatus::Running;
    }
}

/// Internal: invoked when a G's entry closure returns. Marks the G
/// dead and swaps back to the scheduler. Equivalent to Go's
/// `runtime.goexit1` (proc.go:4431).
fn goexit() -> ! {
    let g_ptr = current_m().lock().current_g.expect("goexit: no current G");
    unsafe {
        (*g_ptr.as_ptr()).status = GStatus::Dead;
    }
    let buf_from = unsafe { &mut (*g_ptr.as_ptr()).gobuf as *mut Gobuf };
    let buf_to = {
        let m = current_m().lock();
        &m.sched_buf as *const Gobuf
    };
    unsafe {
        swap_context(buf_from, buf_to);
    }
    unreachable_dead()
}

#[inline(never)]
#[cold]
fn unreachable_dead() -> ! {
    const MSG: &[u8] = b"goish: sched: scheduler resumed a dead G\n";
    crate::syscall::Write(crate::syscall::STDERR, MSG.as_ptr(), MSG.len());
    crate::syscall::Exit(2);
}

/// Asm-trampoline target every G first jumps to via `make_context`.
/// Picks up the G's entry closure (the M's `current_g` knows which
/// goroutine just resumed) and invokes it. When the closure returns,
/// chain to `goexit`.
extern "C" fn g_entry() -> ! {
    let entry = {
        let g_ptr = current_m()
            .lock()
            .current_g
            .expect("g_entry: no current G");
        unsafe { (*g_ptr.as_ptr()).entry.take().expect("g_entry: empty entry") }
    };
    entry();
    goexit();
}

/// Drain the run queue. For each runnable G, swap into it and wait
/// for it to yield or exit. Returns when the queue is empty.
///
/// Called from `__goish_rt0` after the user's `fn main()` returns
/// so any goroutines spawned with `go!()` get to run. User code
/// can also call this explicitly to interleave goroutine execution
/// with main-thread work.
pub fn schedule() {
    loop {
        let g_opt = SCHED.lock().runq.pop_front();
        let mut g_ptr = match g_opt {
            Some(p) => p,
            None => return,
        };

        let g = unsafe { g_ptr.as_mut() };
        if g.status == GStatus::Idle {
            unsafe {
                make_context(&mut g.gobuf, g.stack.top(), g_entry);
            }
        }
        g.status = GStatus::Running;

        // Mark this M's current G; capture buf_from pointer before
        // dropping the M lock. M's address is stable (static MAIN_M
        // in β1, TLS-resolved in β2) so the `&mut sched_buf` raw
        // pointer survives the lock release.
        let buf_from = {
            let mut m = current_m().lock();
            m.current_g = Some(g_ptr);
            &mut m.sched_buf as *mut Gobuf
        };
        let buf_to = &g.gobuf as *const Gobuf;
        unsafe {
            swap_context(buf_from, buf_to);
        }

        current_m().lock().current_g = None;

        if g.status == GStatus::Dead {
            let _ = unsafe { Box::from_raw(g_ptr.as_ptr()) };
        }
    }
}

/// Number of goroutines currently in the run queue. Useful for
/// tests; not part of Go's public API.
pub fn runq_len() -> usize {
    SCHED.lock().runq.len()
}

/// Pointer to the currently-executing goroutine on the calling M, or
/// `None` if called from outside any goroutine (e.g. on the M's
/// scheduler stack itself). Higher layers (channels, sync) need this
/// to identify which G to park or wake.
pub fn current_g() -> Option<NonNull<G>> {
    current_m().lock().current_g
}

/// Suspend the current goroutine in the `Waiting` state. The G will
/// not be re-scheduled until something calls `goready(g)` on it.
/// Mirrors Go's `runtime.gopark` (proc.go:443) plus the `park_m`
/// continuation (proc.go:4229).
///
/// The `unlockf` callback runs *after* the G has been transitioned
/// to `Waiting`. This is the standard atomic-park pattern: a caller
/// that has just enqueued the G onto a wait list (under some lock)
/// uses `unlockf` to release that lock once the G is safely
/// parked, so a concurrent waker observing the wait list still
/// sees the G in `Waiting` state and the wakeup is not lost.
///
/// If `unlockf` returns `false`, the park is cancelled — the G is
/// transitioned back to `Running` and the call returns immediately.
/// Channels use this to abort a park when a competing receiver/
/// sender materialises before `unlockf` runs.
///
/// In single-threaded goish today the race the pattern guards
/// against can't occur, but the pattern is preserved verbatim
/// because channels (M16d) and sync (M16g) lean on it directly,
/// and the same code will run unchanged once M17a introduces
/// multi-M concurrency.
pub fn gopark<F: FnOnce() -> bool>(unlockf: F) {
    let g_ptr = match current_m().lock().current_g {
        Some(p) => p,
        None => return,
    };

    // Transition to Waiting *before* running unlockf — atomic park
    // pattern (Go runtime/proc.go:443). Any concurrent waker that
    // consults g.status as part of its enqueue logic will see
    // Waiting and correctly enqueue.
    unsafe {
        (*g_ptr.as_ptr()).status = GStatus::Waiting;
    }

    let park = unlockf();
    if !park {
        // unlockf bailed out — abort the park.
        unsafe {
            (*g_ptr.as_ptr()).status = GStatus::Running;
        }
        return;
    }

    let buf_from = unsafe { &mut (*g_ptr.as_ptr()).gobuf as *mut Gobuf };
    let buf_to = {
        let m = current_m().lock();
        &m.sched_buf as *const Gobuf
    };
    unsafe {
        swap_context(buf_from, buf_to);
    }
    unsafe {
        (*g_ptr.as_ptr()).status = GStatus::Running;
    }
}

/// `selparkcommit` — gopark commit fn used by the multi-M-correct
/// `select!` (M16f-β). Releases all chan locks held by the parking
/// goroutine, in the order they appear in `g.select_wait` (which is
/// already lock-order, deduped).
///
/// Mirrors Go's runtime/select.go:63-101 minus the GC-related
/// `activeStackChans` / `parkingOnChan` bookkeeping (goish has no
/// stack-shrinking yet).
///
/// Safety: each entry of `g.select_wait[..g.select_wait_len]` must
/// be a live `*const AtomicBool` of a held SpinLock. The macro emits
/// the matching lock acquisitions before populating this list and
/// calling `gopark(selparkcommit)`.
pub fn selparkcommit() -> bool {
    let g_ptr = match current_m().lock().current_g {
        Some(p) => p,
        None => return true,
    };
    unsafe {
        let g = &mut *g_ptr.as_ptr();
        let n = g.select_wait_len as usize;
        for i in 0..n {
            crate::runtime::spin::raw_unlock(g.select_wait[i]);
        }
        // Clear so a later non-select gopark on this G doesn't try
        // to walk stale pointers. Reset at next select pass-2.
        g.select_wait_len = 0;
    }
    true
}

/// Wake a goroutine previously parked via `gopark`. Mirrors Go's
/// `runtime.goready` (proc.go:479).
///
/// The G is transitioned from `Waiting` to `Runnable` and pushed
/// onto the run queue. The next dispatch will swap into it,
/// resuming it from inside `gopark`.
pub fn goready(g_ptr: NonNull<G>) {
    let mut s = SCHED.lock();
    unsafe {
        debug_assert_eq!(
            (*g_ptr.as_ptr()).status,
            GStatus::Waiting,
            "goready: target G is not parked"
        );
        (*g_ptr.as_ptr()).status = GStatus::Runnable;
    }
    s.runq.push_back(g_ptr);
}
