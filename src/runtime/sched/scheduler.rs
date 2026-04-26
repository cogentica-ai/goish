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
use crate::runtime::spin::SpinLock;

/// Scheduler state.
pub struct Sched {
    /// FIFO of runnable goroutines.
    runq: VecDeque<NonNull<G>>,
    /// Saved register set when the scheduler is suspended (i.e.
    /// when a G is running). `swap_context(&mut sched_buf, &g.gobuf)`
    /// transfers control from the scheduler thread to the G;
    /// `swap_context(&mut g.gobuf, &sched_buf)` transfers it back.
    sched_buf: Gobuf,
    /// Currently-executing G, or `None` when on the scheduler.
    current: Option<NonNull<G>>,
}

impl Sched {
    pub const fn new() -> Self {
        Sched {
            runq: VecDeque::new(),
            sched_buf: Gobuf::new(),
            current: None,
        }
    }
}

// `NonNull<G>` is not `Send` by default. The Sched is accessed via
// SpinLock, which requires its inner type be `Send` for `Sync`-ness.
// In single-threaded use this is moot; we'll revisit when M17a
// introduces real concurrency.
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
    let mut s = SCHED.lock();
    let g_ptr = match s.current {
        Some(p) => p,
        None => return,
    };
    // Push ourselves back onto the queue; status stays `Running`
    // until we resume, but for clarity we mark Runnable here.
    unsafe {
        (*g_ptr.as_ptr()).status = GStatus::Runnable;
    }
    s.runq.push_back(g_ptr);
    // Capture pointers before releasing the lock — Sched is in a
    // static SpinLock, so the addresses are stable.
    let buf_from = unsafe { &mut (*g_ptr.as_ptr()).gobuf as *mut Gobuf };
    let buf_to = &s.sched_buf as *const Gobuf;
    drop(s);
    unsafe {
        swap_context(buf_from, buf_to);
    }
    // When we resume, status is back to Running.
    unsafe {
        (*g_ptr.as_ptr()).status = GStatus::Running;
    }
}

/// Internal: invoked when a G's entry closure returns. Marks the G
/// dead and swaps back to the scheduler. Equivalent to Go's
/// `runtime.goexit1` (proc.go:4431).
fn goexit() -> ! {
    let s = SCHED.lock();
    let g_ptr = s.current.expect("goexit: no current G");
    unsafe {
        (*g_ptr.as_ptr()).status = GStatus::Dead;
    }
    let buf_from = unsafe { &mut (*g_ptr.as_ptr()).gobuf as *mut Gobuf };
    let buf_to = &s.sched_buf as *const Gobuf;
    drop(s);
    unsafe {
        swap_context(buf_from, buf_to);
    }
    // The scheduler should never resume a dead G.
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
/// Picks up the G's entry closure (from a global lookup, since we
/// can't pass it as an argument across `swap_context`'s
/// register-only ABI) and invokes it. When the closure returns,
/// chain to `goexit`.
extern "C" fn g_entry() -> ! {
    // Take the entry closure out of the current G. This drops the
    // `Box` slot to `None` so we don't try to call it twice.
    let entry = {
        let s = SCHED.lock();
        let g_ptr = s.current.expect("g_entry: no current G");
        unsafe { (*g_ptr.as_ptr()).entry.take().expect("g_entry: empty entry") }
    };
    // Run the user's closure — outside the lock so it can spawn
    // more goroutines, yield, etc.
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
        // Pop a G; release lock immediately.
        let g_opt = SCHED.lock().runq.pop_front();
        let mut g_ptr = match g_opt {
            Some(p) => p,
            None => return,
        };

        // First-time entry needs the gobuf set up to start at
        // `g_entry`. Subsequent entries just resume at the saved PC.
        let g = unsafe { g_ptr.as_mut() };
        if g.status == GStatus::Idle {
            unsafe {
                make_context(&mut g.gobuf, g.stack.top(), g_entry);
            }
        }
        g.status = GStatus::Running;

        // Mark current and capture pointers before releasing lock.
        {
            let mut s = SCHED.lock();
            s.current = Some(g_ptr);
        }
        let buf_to = &g.gobuf as *const Gobuf;
        let buf_from = {
            let mut s = SCHED.lock();
            &mut s.sched_buf as *mut Gobuf
        };
        unsafe {
            swap_context(buf_from, buf_to);
        }

        // Resumed: G yielded or exited.
        {
            let mut s = SCHED.lock();
            s.current = None;
        }
        if g.status == GStatus::Dead {
            // Reconstruct the `Box<G>` (we leaked it in `newproc`)
            // and drop it. `Drop` on `Stack` munmaps the stack.
            let _ = unsafe { Box::from_raw(g_ptr.as_ptr()) };
        }
    }
}

/// Number of goroutines currently in the run queue. Useful for
/// tests; not part of Go's public API.
pub fn runq_len() -> usize {
    SCHED.lock().runq.len()
}
