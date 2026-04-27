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
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::g::{GStatus, G};
use super::gobuf::{make_context, swap_context, Gobuf};
use super::m::{current_m, ParkCommit};
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

/// Count of goroutines that exist but haven't yet reached `goexit`.
/// `newproc` increments on `go!()`; `dispatch_one_g` decrements when
/// a G's status is observed `Dead`. Worker Ms (M17a-δ onward) read
/// this to decide whether to ExitThread on an empty runq —
/// `live==0 + runq empty` means everything is genuinely done.
///
/// Atomic (not under SCHED's lock) so workers polling for shutdown
/// don't contend with newproc/dispatch on the runq lock.
static LIVE_G_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Spawn a new goroutine running `closure`. Returns immediately
/// after enqueueing the G; the closure does not run until the
/// scheduler dispatches.
///
/// Mirrors Go's `runtime.newproc(fn)` from proc.go:5158.
pub fn newproc(closure: Box<dyn FnOnce()>) {
    let g = Box::leak(Box::new(G::new(closure)));
    let g_ptr = NonNull::from(&mut *g);
    LIVE_G_COUNT.fetch_add(1, Ordering::AcqRel);
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

/// Dispatch a single goroutine on the calling M, wait for it to
/// yield or exit, then return. Internal helper shared by `schedule`
/// (main M's drain) and `m_schedule_loop` (worker M's loop).
///
/// **Park-commit invariant**. If the G yielded via `gopark`, it left
/// `waitunlockf` populated in this M. After `swap_context` returns —
/// at which point the parker's gobuf is fully written by the asm and
/// the parker is no longer running on this M — we set the G's status
/// to `Waiting`, drop the G from the M, then invoke `waitunlockf`.
/// That callback is what releases the chan/select lock(s) the parker
/// was holding. Mirrors Go's `park_m` (proc.go:4229–4280): casgstatus
/// → dropg → unlockf → schedule. The release order is load-bearing
/// for cross-M correctness — the chan lock must NOT be released until
/// the parker's gobuf is committed and the M no longer claims the G.
/// See chan.go:759-763 in Go 1.25 for the verbatim invariant.
fn dispatch_one_g(mut g_ptr: NonNull<G>) {
    let g = unsafe { g_ptr.as_mut() };
    if g.status == GStatus::Idle {
        unsafe {
            make_context(&mut g.gobuf, g.stack.top(), g_entry);
        }
    }
    g.status = GStatus::Running;

    // Capture buf_from from this M's storage. M's address is stable
    // (static MAIN_M for the main thread, leaked Box for workers),
    // so the &mut sched_buf raw pointer outlives the lock release.
    let buf_from = {
        let mut m = current_m().lock();
        m.current_g = Some(g_ptr);
        &mut m.sched_buf as *mut Gobuf
    };
    let buf_to = &g.gobuf as *const Gobuf;
    unsafe {
        swap_context(buf_from, buf_to);
    }

    // ── post-swap: if G parked, run its commit fn (Go's park_m). ──
    let commit = current_m().lock().waitunlockf.take();
    if let Some(f) = commit {
        // Status flip to Waiting — strictly AFTER gobuf was written
        // by swap_context (above) and BEFORE the commit fn releases
        // the lock that gates remote-M discovery of this G's sudog.
        g.status = GStatus::Waiting;
        // dropg analog: M no longer owns G (proc.go:4256).
        current_m().lock().current_g = None;

        let parked = unsafe { f(g_ptr) };
        if !parked {
            // unlockf returned false — abort the park. Mirror
            // proc.go:4262-4273: status → Runnable, re-enqueue so
            // the next dispatch picks G up again.
            g.status = GStatus::Runnable;
            SCHED.lock().runq.push_back(g_ptr);
            return;
        }
        // Committed park. G stays in Waiting until something calls
        // goready(g) on it. M stays free for the next iteration.
        return;
    }

    current_m().lock().current_g = None;

    if g.status == GStatus::Dead {
        LIVE_G_COUNT.fetch_sub(1, Ordering::AcqRel);
        let _ = unsafe { Box::from_raw(g_ptr.as_ptr()) };
    }
}

/// Drain the run queue. For each runnable G, swap into it and wait
/// for it to yield or exit. Returns when the queue is empty.
///
/// Called from `__goish_rt0` after the user's `fn main()` returns,
/// so any goroutines spawned with `go!()` get to run. User code can
/// also call this explicitly to interleave goroutine execution with
/// main-thread work.
///
/// **Single-M semantic**: returns when the runq is empty even if
/// goroutines are still parked elsewhere. Worker Ms (M17a-δ) use
/// `m_schedule_loop` instead, which loops until *all* goroutines
/// have terminated.
pub fn schedule() {
    loop {
        let g_opt = SCHED.lock().runq.pop_front();
        match g_opt {
            Some(g) => dispatch_one_g(g),
            None => return,
        }
    }
}

/// Bounded spin then `sched_yield(2)`. Used by `m_schedule_loop` on
/// an empty run queue to give other threads CPU. M17c will replace
/// with a futex park/unpark pair.
#[inline(never)]
fn spin_or_yield() {
    const SPIN_LIMIT: u32 = 32;
    let mut spins = 0u32;
    while spins < SPIN_LIMIT {
        core::hint::spin_loop();
        spins += 1;
    }
    let _ = crate::syscall::SchedYield();
}

/// Worker M dispatch loop. Never returns under normal flow — when
/// `LIVE_G_COUNT == 0` and the runq is observed empty, the calling
/// thread terminates via `ExitThread(0)`.
///
/// Spawned worker threads (M17a-δ) call this from their `mstart`.
/// The shutdown predicate (`live == 0 && runq empty`) is intentionally
/// approximate: a tiny race window between observing `live == 0` and
/// re-checking is harmless because `live == 0` already means all
/// goroutines have called `goexit`, so no future `newproc` is in
/// flight from existing Gs. A shutdown caller (`Exit` from main) is
/// the only thing that could still racily push more work, and by
/// then exit_group has already replaced this thread anyway.
pub fn m_schedule_loop() -> ! {
    loop {
        let g_opt = SCHED.lock().runq.pop_front();
        match g_opt {
            Some(g) => dispatch_one_g(g),
            None => {
                if LIVE_G_COUNT.load(Ordering::Acquire) == 0 {
                    crate::syscall::ExitThread(0);
                }
                spin_or_yield();
            }
        }
    }
}

/// Number of live goroutines (created via `newproc`, not yet exited).
/// Useful for diagnostics; not part of Go's public API.
pub fn live_g_count() -> usize {
    LIVE_G_COUNT.load(Ordering::Acquire)
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
/// **Cross-M correctness contract.** The caller is expected to be
/// holding some external lock (the chan lock, or several chan locks
/// for `select!`) that gates remote Ms' ability to discover this G
/// and call `goready` on it. `gopark` records `commit` and
/// `lock_atom` on this M, then calls `swap_context`, which writes
/// the G's gobuf in assembly **before** switching to the scheduler
/// stack. The scheduler (in `dispatch_one_g`) sees `waitunlockf` is
/// populated, transitions the G to `Waiting`, severs ownership from
/// this M, then invokes `commit` — which is what finally releases
/// the lock(s). By the time any waker M can take the chan lock, the
/// parker's gobuf is a valid suspended snapshot.
///
/// Mirror of Go's chanparkcommit pattern (chan.go:748–766; see also
/// the load-bearing comment at chan.go:759–763 spelling out why the
/// lock release must happen after the park transition).
///
/// `commit` returns `true` to commit the park, `false` to abort —
/// the abort path requeues the G as `Runnable` so the next dispatch
/// picks it up. `lock_atom` may be null when the commit fn doesn't
/// need it (e.g. `selparkcommit` walks `g.select_wait` instead).
pub fn gopark(commit: ParkCommit, lock_atom: *const AtomicBool) {
    let g_ptr = match current_m().lock().current_g {
        Some(p) => p,
        None => return,
    };

    // Stash commit + lock pointer on the M. dispatch_one_g picks
    // them up post-swap and runs commit on the scheduler stack.
    {
        let mut m = current_m().lock();
        m.waitunlockf = Some(commit);
        m.waitlock = lock_atom;
    }

    let buf_from = unsafe { &mut (*g_ptr.as_ptr()).gobuf as *mut Gobuf };
    let buf_to = {
        let m = current_m().lock();
        &m.sched_buf as *const Gobuf
    };
    unsafe {
        swap_context(buf_from, buf_to);
    }

    // Resumed (or commit returned false). dispatch_one_g already set
    // status appropriately; the next dispatch into us via
    // dispatch_one_g restored Running before swap_context returned
    // here, so this assignment is defensive but harmless.
    unsafe {
        (*g_ptr.as_ptr()).status = GStatus::Running;
    }
}

/// `chan_park_commit` — gopark commit fn used by `chan::Send`/`Recv`
/// when parking on a single chan. Reads the chan lock atom from
/// `M::waitlock` (where `gopark` stashed it) and releases it.
///
/// Mirrors Go's `chanparkcommit` (chan.go:748). Always returns
/// `true` (channel parks never abort — by the time the parker
/// reaches gopark, the sudog is already enqueued under the chan
/// lock, so any peer that arrives is just the waker).
///
/// Safety: caller (`gopark`) must have stashed a valid chan
/// `lock_atom` in `M::waitlock` and the calling thread must hold
/// that lock at entry.
pub unsafe fn chan_park_commit(_g: NonNull<G>) -> bool {
    let atom = current_m().lock().waitlock;
    debug_assert!(!atom.is_null(), "chan_park_commit: no waitlock");
    crate::runtime::spin::raw_unlock(atom);
    true
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
/// Always returns `true`: select parks never abort once pass-2 has
/// registered all sudogs under held locks.
///
/// Safety: each entry of `g.select_wait[..g.select_wait_len]` must
/// be a live `*const AtomicBool` of a held SpinLock. The macro emits
/// the matching lock acquisitions before populating this list and
/// calling `gopark(selparkcommit, _)`.
pub unsafe fn selparkcommit(g_ptr: NonNull<G>) -> bool {
    let g = &mut *g_ptr.as_ptr();
    let n = g.select_wait_len as usize;
    for i in 0..n {
        crate::runtime::spin::raw_unlock(g.select_wait[i]);
    }
    // Clear so a later non-select gopark on this G doesn't try
    // to walk stale pointers. Reset at next select pass-2.
    g.select_wait_len = 0;
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
