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
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::g::{GStatus, G};
use super::gobuf::{make_context, swap_context, Gobuf};
use super::m::{acquirem, current_m, current_m_storage, releasem, MStorage, ParkCommit};
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
    // M17c: a fresh runnable G — wake one parked M to dispatch.
    wake_idle_m();
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
    // No m.locks bump needed: by this point status = Runnable, so
    // M18b's SIGURG handler filters this G via the
    // `curg.status == Running` predicate (Theorem in design notes:
    // status filter dominates lock-counter for non-Running G).
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
///
/// **m.locks**: not bumped here. Once status is `Dead`, the SIGURG
/// preempt handler filters on `curg.status == Running` and skips
/// injection — the only PC-window where the handler could reach us
/// is the swap_context asm itself, covered by phase-C's PC-range
/// guard. A balanced bump pair is impossible because the swap_context
/// here never returns to this stack.
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
    // M18b-β: stamp the start time so sysmon's force-preempt scan
    // can compute elapsed runtime. Lock-free atomic so sysmon reads
    // without blocking. Must be SET before the swap (sysmon needs
    // a non-zero value the moment the G starts running) and CLEARED
    // after the swap returns (so a parked-G's stale value doesn't
    // make sysmon target this M while it's idle).
    current_m_storage()
        .start_running_ns
        .store(crate::runtime::sysmon::monotonic_ns(), Ordering::Release);
    DISPATCH_STAMP_COUNT.fetch_add(1, Ordering::Relaxed);
    let buf_to = &g.gobuf as *const Gobuf;
    unsafe {
        swap_context(buf_from, buf_to);
    }
    // Clear the start-time stamp now that no G is running.
    current_m_storage()
        .start_running_ns
        .store(0, Ordering::Release);

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
        let prev = LIVE_G_COUNT.fetch_sub(1, Ordering::AcqRel);
        let _ = unsafe { Box::from_raw(g_ptr.as_ptr()) };
        if prev == 1 {
            // Last live goroutine just exited. Any Ms parked on
            // futex_wait need a signal so they observe
            // LIVE_G_COUNT == 0 and exit (workers via ExitThread,
            // main M via schedule() return).
            wake_all_idle_m();
        }
    }
}

/// Drain the run queue. Returns when **all live goroutines** have
/// terminated (`LIVE_G_COUNT == 0`).
///
/// Called from `__goish_rt0` after the user's `fn main()` returns,
/// so any goroutines spawned with `go!()` get to run. User code can
/// also call this explicitly to interleave goroutine execution with
/// main-thread work.
///
/// In multi-M mode (M17a-δ.1+) the main M participates in dispatch
/// alongside worker Ms — same code path. Workers call
/// `m_schedule_loop` instead, which mirrors this loop but exits via
/// `ExitThread(0)` when done.
///
/// **Liveness assumption**: this loop won't return if there are
/// parked goroutines with no waker (a user-program deadlock). Go's
/// runtime detects this via `checkdead` (proc.go:5566); goish v1
/// will hang in that case until M18b lands.
pub fn schedule() {
    loop {
        let g_opt = SCHED.lock().runq.pop_front();
        match g_opt {
            Some(g) => dispatch_one_g(g),
            None => {
                if LIVE_G_COUNT.load(Ordering::Acquire) == 0 {
                    return;
                }
                // Brief spin (~32 PAUSE) to absorb producer
                // latency, then futex-park. Mirrors Go's
                // `runtime.findRunnable` spin-then-stop pattern.
                spin_or_yield();
                if LIVE_G_COUNT.load(Ordering::Acquire) == 0 {
                    return;
                }
                if SCHED.lock().runq.is_empty() {
                    park_m_idle();
                }
            }
        }
    }
}

/// Bounded spin then `sched_yield(2)`. Brief — used as a stepping
/// stone before `park_m_idle` futex-waits. The spin gives a hot
/// producer time to push work and avoid the syscall round-trip.
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

// ─── M17c: idle M parking via futex ────────────────────────────────
//
// Modeled after Go's `stopm`/`startm`/`mPark` (runtime/proc.go) +
// `note`/`futexsleep`/`futexwakeup` (runtime/lock_futex.go).
//
// Two state primitives:
//
//   1. `MIDLE`: the global idle-M list. Each entry is a parked M.
//      mput pushes self before sleeping; mget pops one to wake.
//      Mirrors Go's `sched.midle`.
//
//   2. `MStorage.park`: a one-shot `Note` per M. Cleared before
//      each park-cycle, signaled exactly once by the waker, then
//      cleared again by the sleeper after wake. Mirrors Go's
//      `m.park`.
//
// Park sequence (`park_m_idle`, modeling Go's `stopm`):
//   1. Lock MIDLE.
//   2. Re-check runq + LIVE under MIDLE lock (atomicity with wake).
//   3. If work or shutdown, drop lock and return.
//   4. Else: clear our note, push self onto MIDLE, drop lock.
//   5. note.sleep() — blocks until a waker calls note.wakeup().
//
// Wake sequence (`wake_idle_m`, modeling Go's `startm`-on-wakep):
//   1. Lock MIDLE.
//   2. Pop one MStorage. Drop lock.
//   3. Call note.wakeup() on the popped M.
//
// Race-free invariant:
//   - "M is in MIDLE" ⟺ "M is parked or about to park".
//   - Push/pop on MIDLE are serialized by the SpinLock.
//   - mput happens BEFORE note.sleep, so any waker that pops us
//     and calls note.wakeup before our sleep starts has set
//     note.key = 1 — sleep's load-loop sees it and returns
//     without entering futex_wait.
//   - The runq re-check under MIDLE lock is what closes the race
//     against new work arriving between the previous pop and our
//     park decision.

/// Global idle-M list. Mirrors Go's `sched.midle`. Linked
/// implicitly via Vec ordering (LIFO push/pop, matches Go's stack
/// behavior).
static MIDLE: SpinLock<Vec<&'static MStorage>> = SpinLock::new(Vec::new());

/// Global registry of all M storages, in the order they were
/// registered. Mirrors Go's `sched.allm` (proc.go). Populated by
/// `register_m_storage` from the main thread during bootstrap; not
/// modified after `bootstrap_workers` returns. Workers and sysmon
/// only read it.
///
/// Used by M18b-β's `for_each_m` so sysmon's force-preempt scan
/// can iterate every M's `start_running_ns` and `current_g` without
/// holding any per-M lock.
static ALL_MS: SpinLock<Vec<&'static MStorage>> = SpinLock::new(Vec::new());

/// Register an MStorage globally so M18b-β's sysmon scan can find
/// it. Mirrors Go's `allm` registration. Called from the main
/// thread for `MAIN_M` and for each worker M during
/// `bootstrap_workers`, *and* for sysmon's own M storage from
/// `start_sysmon`. Allocator must be up.
pub fn register_m_storage(storage: &'static MStorage) {
    ALL_MS.lock().push(storage);
}

/// Iterate every registered M storage. Safe to call after
/// `bootstrap_workers` finishes (the registry is read-only from
/// then on; bootstrap and sysmon registration both happen on the
/// main thread before any worker reads it).
pub fn for_each_m<F: FnMut(&'static MStorage)>(mut f: F) {
    let ms = ALL_MS.lock();
    for &m in ms.iter() {
        f(m);
    }
}

/// Number of registered Ms. Diagnostic; tests use it to verify
/// `register_m_storage` was called the expected number of times.
pub fn registered_m_count() -> usize {
    ALL_MS.lock().len()
}

/// Debug counter — bumped every time `dispatch_one_g` stamps a
/// fresh start-running timestamp on its M. Confirms the M18b-β
/// stamp path is exercised.
pub static DISPATCH_STAMP_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Park the calling M until a waker pops it from MIDLE and signals
/// its note. Used by `m_schedule_loop` and `schedule` when the run
/// queue is empty and goroutines are still alive.
///
/// Mirror of Go's `stopm` (proc.go:2997) → `mPark` (proc.go:1972).
fn park_m_idle() {
    let storage = current_m_storage();

    // mput + park-decision under MIDLE lock — atomicity ensures
    // wakers either see us in MIDLE (and pop us) or push runq
    // before we re-check. Go does this under `sched.lock`.
    {
        let mut midle = MIDLE.lock();
        // Re-check conditions under the lock.
        if !SCHED.lock().runq.is_empty() {
            return;
        }
        if LIVE_G_COUNT.load(Ordering::Acquire) == 0 {
            return;
        }
        // Clear note BEFORE mput so a waker that pops us
        // immediately sees a fresh note. Order matters: clear
        // happens-before any wakeup that targets this cycle.
        storage.park.clear();
        midle.push(storage);
    }

    // notesleep — blocks in futex_wait(key, 0) until note.wakeup()
    // sets key = 1. If the wakeup raced ahead of the sleep entry,
    // sleep's load-loop sees key != 0 and returns without syscall.
    storage.park.sleep();

    // Note: clear() will run at the start of the *next* park-cycle
    // (above). Leaving key = 1 between cycles is fine — the next
    // clear() resets it before the next mput.
}

/// Wake one idle M, if any. Called by code that pushes new work
/// to the run queue (`newproc`, `goready`).
///
/// Mirror of Go's `wakep` (proc.go:3217) + `startm`-on-wakep
/// (proc.go:3040).
pub fn wake_idle_m() {
    let storage = match MIDLE.lock().pop() {
        Some(s) => s,
        None => return,
    };
    storage.park.wakeup();
}

/// Wake every idle M. Used at shutdown when the last live
/// goroutine exits — parked Ms need a signal to observe
/// `LIVE_G_COUNT == 0` and exit.
fn wake_all_idle_m() {
    loop {
        let storage = match MIDLE.lock().pop() {
            Some(s) => s,
            None => break,
        };
        storage.park.wakeup();
    }
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
                // Brief spin then futex-park (M17c). spin_or_yield
                // first so a producer pushing inflight work right
                // now can avoid the syscall round-trip.
                spin_or_yield();
                if LIVE_G_COUNT.load(Ordering::Acquire) == 0 {
                    crate::syscall::ExitThread(0);
                }
                if SCHED.lock().runq.is_empty() {
                    park_m_idle();
                }
            }
        }
    }
}

/// Number of live goroutines (created via `newproc`, not yet exited).
/// Useful for diagnostics; not part of Go's public API.
pub fn live_g_count() -> usize {
    LIVE_G_COUNT.load(Ordering::Acquire)
}

/// Number of CPUs available to this process via the calling thread's
/// affinity mask. Returns 1 on syscall failure or zero-CPU mask.
///
/// Mirrors Go's `runtime.getCPUCount` (os_linux.go:104). 8 KiB
/// affinity buffer is generous enough for any plausible host
/// (65 536 CPUs); a popcount over the returned bytes gives the
/// effective parallelism.
pub fn num_cpus() -> usize {
    const MAX_CPUS: usize = 64 * 1024;
    let mut buf = [0u8; MAX_CPUS / 8];
    let r = crate::syscall::SchedGetaffinity(0, buf.len(), buf.as_mut_ptr());
    if r <= 0 {
        return 1;
    }
    let n = (r as usize).min(buf.len());
    let mut count: usize = 0;
    for &v in &buf[..n] {
        count += v.count_ones() as usize;
    }
    if count == 0 {
        1
    } else {
        count
    }
}

/// Worker M entry point. Spawned by `spawn_worker_m` via `clone(2)`
/// with `CLONE_SETTLS` already pointing at the worker's `MStorage`.
/// Records the kernel tid in `M::procid`, then enters
/// `m_schedule_loop`. Never returns — terminates via `ExitThread(0)`
/// from inside the loop when `LIVE_G_COUNT == 0`.
///
/// Mirrors Go's `runtime.mstart1` (proc.go:1689) minus the GC and
/// signal-handling pieces we don't carry yet.
extern "C" fn mstart() -> ! {
    let tid = crate::syscall::Gettid();
    let id = {
        let m = super::m::current_m().lock();
        m.procid.store(tid, Ordering::Release);
        m.id as usize
    };
    // M17b-α: each worker M acquires its corresponding P. Worker id
    // matches P id by construction (`bootstrap_workers` spawns id=1..N
    // and `bootstrap_ps(N)` populates P slots 0..N).
    if let Some(p) = super::p::p_at(id) {
        super::p::acquirep(p);
    }
    m_schedule_loop()
}

/// Per-worker stack size — 64 KiB. Larger than goroutine stacks
/// (which goroutines own) because the M's scheduler stack handles
/// interrupts, panic paths, and dispatch overhead. Matches the
/// minimum Go uses for `g0` stack on Linux (proc.go: stackGuard
/// constants).
const WORKER_M_STACK: usize = 64 * 1024;

/// Allocate one new worker M with the given id, mmap its scheduler
/// stack, then `clone(2)` a fresh thread to run `mstart()` on it
/// with `CLONE_SETTLS` pointing at the new M's TLS slot.
///
/// The MStorage is `Box::leak`'d so its address is stable for the
/// thread's lifetime (TLS reads return `&storage.m`). The stack is
/// also leaked — process exit (`exit_group`) reclaims everything.
///
/// Returns the kernel tid the kernel assigned to the new thread.
fn spawn_worker_m(id: u32) -> i64 {
    use crate::syscall;

    let storage: &'static super::m::MStorage =
        Box::leak(Box::new(super::m::MStorage::new(id)));
    storage.init_tls_self();
    // M17c: register so wake_idle_m can scan for parked workers.
    register_m_storage(storage);

    let stack_base = syscall::Mmap(
        core::ptr::null_mut(),
        WORKER_M_STACK,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
        -1,
        0,
    );
    if stack_base == syscall::MAP_FAILED {
        const MSG: &[u8] = b"goish: spawn_worker_m: mmap failed\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    let stack_top = unsafe { stack_base.add(WORKER_M_STACK) };

    unsafe {
        syscall::Clone(
            syscall::CLONE_THREAD_FLAGS,
            stack_top,
            mstart,
            storage.fs_base() as u64,
        )
    }
}

/// Bootstrap N-1 worker Ms (one per CPU beyond the main M). Called
/// from `__goish_rt0` after `setup_main_tls()` and before user code
/// runs, so by the time `__goish_main()` is entered the worker pool
/// is already dispatching.
///
/// Mirrors Go's `runtime.schedinit` + `runtime.startTheWorld` for
/// the GOMAXPROCS-sized M creation, minus the per-P machinery (M17b
/// adds Ps; for now everything shares one global runq).
pub fn bootstrap_workers() {
    let n = num_cpus();
    // Spawn one worker per CPU beyond the main M (id=0).
    for i in 1..n {
        let _ = spawn_worker_m(i as u32);
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

    // Hold m.locks > 0 across the setup → swap window. Unlike
    // Gosched/goexit, gopark's G has status == Running until
    // dispatch_one_g flips it to Waiting *post*-swap (the commit-fn
    // pattern), so the SIGURG handler's status filter does NOT cover
    // this body. Only the lock counter does.
    //
    // Discipline mirrors Go's gopark (proc.go:419):
    //   acquirem → setup → releasem → mcall(park_m)
    // i.e. the matching releasem runs *before* the context switch so
    // the +1 / -1 are accounted on the same M (the parker's M may
    // differ from the resuming M after multi-M migration). The
    // residual window between releasem and swap_context entry is
    // covered by phase-C's PC-range guard (`is_in_runtime_text`).
    acquirem();

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
    releasem();
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

/// `block_forever_commit` — gopark commit fn for nil-chan send/recv.
/// Returns `true` (commit the park) but releases nothing; the G is
/// never goready'd by anyone, so this is a permanent park.
///
/// Mirrors Go's `gopark(nil, nil, waitReasonChanSendNilChan,
/// traceBlockForever, 2)` (chan.go:181, 536). Used only by `Send`/
/// `Recv` on a nil chan; in `select!` nil cases are filtered before
/// the lock-order pass and never reach gopark.
pub unsafe fn block_forever_commit(_g: NonNull<G>) -> bool {
    true
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
        let atom = g.select_wait[i];
        // Skip nulls: nil chans contribute null atoms to the
        // dedup'd select_wait list. Null entries get sorted to the
        // front by the macro's address-sort and survive dedup as a
        // single null head; we ignore them here (no lock to release).
        if !atom.is_null() {
            crate::runtime::spin::raw_unlock(atom);
        }
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
    {
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
    // M17c: a runnable G is now in the queue — wake an idle M.
    wake_idle_m();
}
