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
use super::gobuf::{gogo, make_context_gogo, mcall_asm, Gobuf};
use super::m::{acquirem, current_m, current_m_storage, releasem, MStorage, ParkCommit};
use super::p::current_p;
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

/// Push a batch of goroutines onto the global runq. Called by
/// `P::runqputslow` (M17b-β) when a P's local runq is full and half
/// of it spills to global. Pointers are passed as `*mut G`; null
/// entries are skipped (defensive — `runqputslow` does not produce
/// nulls in practice).
///
/// Mirrors a slim subset of Go's `globrunqputbatch` (proc.go).
pub(crate) fn globrunqput_batch(batch: &[*mut G]) {
    let mut s = SCHED.lock();
    for &g in batch {
        if let Some(g_ptr) = NonNull::new(g) {
            s.runq.push_back(g_ptr);
        }
    }
}

/// Pop one G off the global runq, returning `None` if empty.
/// Used by `findrunnable_local_then_global` as the second-tier
/// fallback when the M's local P runq is empty.
fn globrunqget_one() -> Option<NonNull<G>> {
    SCHED.lock().runq.pop_front()
}

/// Find the next runnable G for the calling M. Drain order
/// (M17b-γ + M27e): local P runq → global runq → steal from another P
/// → drain netpoll(0). Returns `None` if all four tiers come up empty.
///
/// Mirrors a slim subset of Go's `findRunnable` (proc.go:3377).
/// Goish does not carry the spinning-M / nmspinning state machine,
/// the idlepMask, the trace/GC/finalizer hooks, or netpoll's blocking
/// drain (Go's `netpoll(blocking)` when all Ps idle); step (3) is
/// unconditional rather than gated on `mp.spinning`, and the netpoll
/// step (4) is always non-blocking — sysmon's tick is the fallback
/// for the "all Ps idle" case in v1.
#[inline(never)]
#[link_section = "goish_rt_text"]
fn find_runnable() -> Option<NonNull<G>> {
    if let Some(p) = current_p() {
        if let Some(g) = unsafe { p.runqget() } {
            return Some(g);
        }
    }
    if let Some(g) = globrunqget_one() {
        return Some(g);
    }
    if let Some(g) = steal_work() {
        return Some(g);
    }
    poll_netpoll_take_one()
}

/// Non-blocking netpoll drain. Returns the head G (transitioned
/// Waiting → Runnable; execute() will move it to Running). The tail,
/// if any, is goready'd so other Ms can pick the rest up via
/// `wake_idle_m`. Mirrors Go's findRunnable netpoll branch
/// (proc.go:3553) which calls `netpoll(0)` and `injectglist(&list)`.
#[inline(never)]
#[link_section = "goish_rt_text"]
fn poll_netpoll_take_one() -> Option<NonNull<G>> {
    let ready = crate::runtime::netpoll::poll(0);
    if ready.is_empty() {
        return None;
    }
    let mut iter = ready.into_iter();
    let head = iter.next()?;
    unsafe {
        debug_assert_eq!((*head.as_ptr()).status, GStatus::Waiting);
        (*head.as_ptr()).status = GStatus::Runnable;
    }
    for g in iter {
        goready(g);
    }
    Some(head)
}

/// Attempt to steal a runnable G from another P. Mirrors a slim
/// subset of Go's `stealWork` (proc.go:3816): four tries × random
/// permutation of all Ps via `stealOrder.start(cheaprand())`; the
/// last try also permits stealing from each target's `runnext`
/// slot (with the `usleep(3)`/SchedYield anti-thrash backoff
/// applied inside `runqgrab`).
///
/// On success returns the "head" G of the stolen batch — the rest
/// (if any) was published into the calling M's local runq by
/// `runqsteal`. Returns `None` if four full passes turn up empty.
#[inline(never)]
#[link_section = "goish_rt_text"]
fn steal_work() -> Option<NonNull<G>> {
    if !crate::runtime::flags::WORK_STEALING.load(Ordering::Relaxed) {
        return None;
    }
    let pp = current_p()?;
    super::p::STEAL_PASSES.fetch_add(1, Ordering::Relaxed);

    const STEAL_TRIES: u32 = 4;
    let allow_runnext_steal =
        crate::runtime::flags::STEAL_RUNNEXT.load(Ordering::Relaxed);
    for i in 0..STEAL_TRIES {
        let steal_runnext_g = allow_runnext_steal && (i == STEAL_TRIES - 1);
        let mut e = super::p::STEAL_ORDER.start(crate::runtime::rand::cheaprand());
        while !e.done() {
            let pos = e.position() as usize;
            if let Some(p2) = super::p::p_at(pos) {
                // Skip self.
                if !core::ptr::eq(p2 as *const _, pp as *const _) {
                    // Cheap pre-check: skip empty targets unless
                    // we're also authorized to steal runnext.
                    // Mirrors Go's `idlepMask.read(...)` early exit
                    // (proc.go:3879). Goish does not carry an
                    // idlepMask; `runqempty` is the right check at
                    // this layer.
                    let has_work = !p2.runqempty()
                        || (steal_runnext_g
                            && !p2.runnext.load(Ordering::Acquire).is_null());
                    if has_work {
                        if let Some(g) =
                            unsafe { pp.runqsteal(p2, steal_runnext_g) }
                        {
                            super::p::STEAL_HITS.fetch_add(1, Ordering::Relaxed);
                            return Some(g);
                        }
                    }
                }
            }
            e.next();
        }
    }
    None
}

/// True when this M has any work it can dispatch — on its bound P's
/// local runq, on the global runq, or stealable from another P
/// (M17b-γ). Used by the idle-park re-check under MIDLE lock so we
/// don't sleep through a producer.
///
/// **The all-Ps scan is critical for γ.** Without it, a producer
/// that pushed work to its own P calls `wake_idle_m` before the
/// to-be-parked worker reaches MIDLE.push, so the wake hits an
/// empty MIDLE and is lost. The worker then parks on a runq that
/// *appears* empty (self.P empty, global empty) but actually has
/// stealable work elsewhere — and never wakes again until the
/// next unrelated `wake_idle_m`. Mirrors a slim subset of Go's
/// "delicate dance" in `findRunnable` (proc.go:3635-3713) where
/// the spinning M re-checks all P runqs after dropping
/// `nmspinning` and before truly parking.
///
/// Held under MIDLE lock from `park_m_idle`, so concurrent
/// producers' `wake_idle_m` will block until our scan completes —
/// either we find work and don't park, or we push to MIDLE and the
/// producer's subsequent `wake_idle_m` pops us.
#[inline(never)]
#[link_section = "goish_rt_text"]
fn has_local_or_global_work() -> bool {
    if let Some(p) = current_p() {
        if p.runq_has_work() {
            return true;
        }
    }
    if !SCHED.lock().runq.is_empty() {
        return true;
    }
    let me = current_p();
    let mut found = false;
    super::p::for_each_p(|p2| {
        if found {
            return;
        }
        if let Some(s) = me {
            if core::ptr::eq(p2 as *const _, s as *const _) {
                return;
            }
        }
        if !p2.runqempty() {
            found = true;
        }
    });
    found
}

/// Count of goroutines that exist but haven't yet reached `goexit`.
/// `newproc` increments on `go!()`; `dispatch_one_g` decrements when
/// a G's status is observed `Dead`. Worker Ms (M17a-δ onward) read
/// this to decide whether to ExitThread on an empty runq —
/// `live==0 + runq empty` means everything is genuinely done.
///
/// Atomic (not under SCHED's lock) so workers polling for shutdown
/// don't contend with newproc/dispatch on the runq lock.
static LIVE_G_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Push a goroutine onto the runnable set, routing through the bound
/// P's runq (M17b-β) when available, otherwise to the global runq.
///
/// `next=true` puts the G into P's `runnext` slot — the LIFO-prefer
/// fastpath used by `goready` (chan-waker, mutex-waker) so the
/// freshly-resumed G keeps any cache locality it had with the waker.
///
/// `next=false` appends to the runq tail — the FIFO path used by
/// `newproc` (fresh spawn) and `Gosched` (voluntary yield). Without
/// work-stealing (γ), `next=true` for newproc would let the most
/// recent spawn dominate `runnext` and starve earlier ones; `next=false`
/// keeps spawn order deterministic. We can revisit once γ ships.
///
/// **acquirem/releasem bracketing** (Go parity): mirrors Go's `ready()`
/// discipline at proc.go:1121–1136. Comment there is explicit — *"disable
/// preemption because it can be holding p in a local var"*. Without the
/// bump, an async-preempt or coop-preempt can fire between `current_p()`
/// and `p.runqput()`, migrate the M to a different P, and the subsequent
/// `runqput` then writes to a P this M no longer owns — violating the
/// SPMC ring's single-writer invariant (`runqtail` and `runq[]` slots).
#[inline(never)]
#[link_section = "goish_rt_text"]
fn enqueue_runnable(g_ptr: NonNull<G>, next: bool) {
    super::m::acquirem();
    if let Some(p) = current_p() {
        unsafe { p.runqput(g_ptr, next) };
    } else {
        SCHED.lock().runq.push_back(g_ptr);
    }
    wake_idle_m();
    super::m::releasem();
}

/// Spawn a new goroutine running `closure`. Returns immediately
/// after enqueueing the G; the closure does not run until the
/// scheduler dispatches.
///
/// Mirrors Go's `runtime.newproc(fn)` from proc.go:5158. The G is
/// allocated with the default 2 KiB stack (page-rounded to 4 KiB).
pub fn newproc(closure: Box<dyn FnOnce()>) {
    let g = Box::leak(Box::new(G::new(closure)));
    let g_ptr = NonNull::from(&mut *g);
    LIVE_G_COUNT.fetch_add(1, Ordering::AcqRel);
    enqueue_runnable(g_ptr, false);
}

/// **`newproc_with_stack(size, closure)`** — spawn a goroutine with
/// an explicit stack size (M26). Used by `go!(stack(N), closure)` when
/// the caller knows the default 2 KiB stack is too small (deep
/// recursion, large stack-allocated buffers) or wants to shrink for
/// massive goroutine counts.
///
/// `size` is rounded up to the nearest 4 KiB page; the minimum
/// allocation is one page regardless of the request. Goish has no
/// `morestack`, so the stack you request is the stack you get —
/// overflow silently corrupts adjacent memory unless a guard page
/// has been installed (Phase γ work).
pub fn newproc_with_stack(size: usize, closure: Box<dyn FnOnce()>) {
    let g = Box::leak(Box::new(G::new_with_stack(size, closure)));
    let g_ptr = NonNull::from(&mut *g);
    LIVE_G_COUNT.fetch_add(1, Ordering::AcqRel);
    enqueue_runnable(g_ptr, false);
}

/// Voluntarily yield the CPU. Equivalent to Go's `runtime.Gosched()`
/// (proc.go:387). If called from outside any goroutine (i.e. on the
/// scheduler thread itself), this is a no-op.
///
/// **M17b-ε.γ.1**: implemented as `mcall(gosched_m)`, mirroring Go's
/// `runtime.Gosched` → `mcall(gosched_m)` → `goschedImpl(_, false)`
/// (proc.go:387, 4283, 4319).
///
/// On the user G's stack we only check that we're inside a goroutine
/// (curg is set). The actual yield mechanism — saving the G's PC/SP
/// into curg.gobuf, switching to g0's stack, re-enqueuing the G,
/// picking the next G — runs entirely inside `gosched_m` on g0.
///
/// Resume: when `execute(g)` later does `gogo(&g.gobuf)`, control
/// returns to the instruction after `mcall(gosched_m)`'s asm call,
/// inside this function's frame; we then return normally to the
/// user-visible call site.
#[allow(non_snake_case)]
#[inline(never)]
#[link_section = "goish_rt_text"]
pub fn Gosched() {
    // Lock-free curg read (per-M, single-thread mutator). Taking
    // M's SpinLock here would risk a coop_preempt_check-driven
    // Gosched detour mid-check, migrating us to another M before
    // the actual mcall call (see `mcall` body for full rationale).
    if unsafe { current_m().data_unchecked().curg }.is_none() {
        return;
    }
    unsafe {
        mcall(gosched_m);
    }
}

/// Internal: invoked when a G's entry closure returns. Marks the G
/// dead, switches to g0, and runs `goexit0` on g0's stack — which
/// frees the G and calls `schedule()`. Equivalent to Go's
/// `runtime.goexit1` → `mcall(goexit0)` (proc.go:4431, 4459).
///
/// **m.locks**: not bumped here. `goexit0` runs on g0 and never
/// returns to this stack; the trampoline `unreachable_dead` is
/// retained as a defensive marker.
#[inline(never)]
#[link_section = "goish_rt_text"]
fn goexit() -> ! {
    unsafe {
        mcall(goexit0);
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
///
/// Before invoking the closure, installs a panic-recovery `Gobuf`
/// pointing at `on_g_panic_aborted`. The `#[panic_handler]` reads
/// this and `gogo`s here on user-code panic, abandoning the panicked
/// frames but keeping the rest of the runtime alive (per-goroutine
/// panic isolation). After the closure returns normally, the
/// recovery point is invalidated (rsp=0) so a later runtime-internal
/// panic on this M's g0 still aborts the process.
extern "C" fn g_entry() -> ! {
    // Install panic recovery + take entry in a sub-frame that's freed
    // before `entry()` runs — keeps g_entry's own frame minimal so
    // small (2 KiB default) goroutine stacks don't bust the budget
    // during the prologue.
    let entry = unsafe { g_entry_setup() };
    entry();
    unsafe { g_entry_clear_recovery() };
    goexit();
}

/// Variant of `g_entry` for goroutines spawned with auto-grow
/// (bare `go!()` form, `g.growable == true`). Wraps `entry()` in
/// `runtime::sched::maybe_grow_step`, so the user closure runs
/// inside the tier-aware grow scope: home (2 KiB) → tier-2 (64 KiB)
/// → tier-3 (1 MiB), pivoting lazily as SP descends into each tier's
/// red zone.
///
/// Goroutines spawned via `go!(stack(N), …)` / `go!(N, …)` skip this
/// wrap (`g.growable == false`) and run on a strictly-N-byte stack.
extern "C" fn g_entry_growable() -> ! {
    let entry = unsafe { g_entry_setup() };
    crate::runtime::sched::maybe_grow_step(entry);
    unsafe { g_entry_clear_recovery() };
    goexit();
}

#[inline(never)]
unsafe fn g_entry_setup() -> alloc::boxed::Box<dyn FnOnce()> {
    let g_ptr = current_m()
        .lock()
        .curg
        .expect("g_entry: no current G");
    let g = unsafe { &mut *g_ptr.as_ptr() };
    crate::runtime::sched::make_context_gogo(
        &mut g.panic_recover,
        g.stack.top(),
        on_g_panic_aborted,
    );
    g.entry.take().expect("g_entry: empty entry")
}

#[inline(never)]
unsafe fn g_entry_clear_recovery() {
    if let Some(g_ptr) = current_m().lock().curg {
        unsafe { (*g_ptr.as_ptr()).panic_recover.rsp = 0 };
    }
}

/// Recovery entry called via `gogo(g.panic_recover)` from the panic
/// handler when user code panics. Runs on the G's own stack (rsp=top)
/// so the abandoned mid-panic frames are below us and will be
/// overwritten by future activity on this G's stack — which is fine,
/// the G is about to die.
///
/// Walks `g.cleanups` to release fds/locks/etc. that were registered
/// by the abandoned frames, then chains to `goexit` so the scheduler
/// reclaims this G normally.
extern "C" fn on_g_panic_aborted() -> ! {
    // Cleanups already ran in the `#[panic_handler]` (where the
    // panicked stack frames were still valid). Here we're on a fresh
    // top-of-stack frame; just print, clear panicking flag, and exit.
    const MSG: &[u8] = b"goish: goroutine recovered from panic, scheduler continuing\n";
    crate::syscall::Write(crate::syscall::STDERR, MSG.as_ptr(), MSG.len());

    // Increment the per-process panicked-G counter for diagnostics.
    G_PANIC_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    // Clear the panicking flag so any final code on this G observes
    // the normal-execution state. The G is about to die anyway, but
    // this also defends against false positives if the flag were ever
    // observed post-recovery (e.g., a future feature that reuses Gs).
    if let Some(g_ptr) = current_m().lock().curg {
        unsafe { (*g_ptr.as_ptr()).panicking.store(false, core::sync::atomic::Ordering::Release) };
    }

    goexit();
}

/// True while the current goroutine is inside the panic handler's
/// cleanup walk — i.e., a `defer!{}` body is being run because the
/// scope is unwinding due to panic, not because it exited normally.
///
/// Mirrors Go's `recover()` for the *observation* part — the
/// `recover!()` macro reads this. Unlike Go, our flag does NOT stop
/// panic propagation: the goroutine still terminates after defers
/// run. (Stopping propagation would require frame-level unwind tables,
/// gated behind nightly + -Zbuild-std on no_std crates.)
///
/// Returns `false` outside any goroutine (g0 / sysmon).
#[inline]
pub fn panicking() -> bool {
    if let Some(g_ptr) = current_g() {
        unsafe { (*g_ptr.as_ptr()).panicking.load(core::sync::atomic::Ordering::Acquire) }
    } else {
        false
    }
}

/// Total number of goroutines that have died by panic (vs normal
/// return) since process start. Read by tests + diagnostic dumps.
pub static G_PANIC_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

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
// ─── M18b-δ.4 — G use-after-free / double-dispatch trap ─────────────
//
// Catches the case where `dispatch_one_g` is handed a G pointer whose
// memory has been freed and (typically) zeroed by the allocator. The
// existing chan_micro_send_only_segvinfo dumps show this in
// "Pattern C": SEGV at 0x20c8bc inside `make_context(&g.gobuf,
// g.stack.top(), …)` with `si_addr = -8`, meaning `g.stack.base + g.stack.size = 0`.
//
// Validates the G's stack invariants (each goroutine stack is a
// dedicated 64 KiB mmap, see runtime::sched::stack). If the
// invariants are violated, dump the G's memory + nearby diagnostic
// state and exit cleanly so we can root-cause from the dump rather
// than chasing a generic SEGV inside make_context.
//
// Tagged `goish_rt_text` so the SIGURG handler refuses to inject
// here (PC-range filter).

#[inline(never)]
#[link_section = "goish_rt_text"]
fn dispatch_g_trap_dump(label: &[u8], g_ptr: NonNull<G>) -> ! {
    use crate::syscall;
    let stderr = syscall::STDERR;

    let dump_str = |s: &[u8]| {
        syscall::Write(stderr, s.as_ptr(), s.len());
    };
    let dump_hex = |label: &[u8], v: u64| {
        syscall::Write(stderr, label.as_ptr(), label.len());
        let mut buf = [0u8; 18];
        buf[0] = b'0';
        buf[1] = b'x';
        for i in 0..16 {
            let nib = ((v >> ((15 - i) * 4)) & 0xf) as u8;
            buf[2 + i] = if nib < 10 {
                b'0' + nib
            } else {
                b'a' + (nib - 10)
            };
        }
        syscall::Write(stderr, buf.as_ptr(), buf.len());
        syscall::Write(stderr, b"\n".as_ptr(), 1);
    };

    dump_str(b"\n=== goish: dispatch_one_g received bad G ===\n");
    dump_str(label);
    dump_str(b"\n");
    dump_hex(b"  g_ptr        = ", g_ptr.as_ptr() as u64);

    // G fields. Read the stack base/top via volatile to avoid the
    // compiler folding a stale snapshot.
    let g_ref = unsafe { g_ptr.as_ref() };
    let stack_base = g_ref.stack.base() as u64;
    let stack_top = g_ref.stack.top() as u64;
    dump_hex(b"  stack.base   = ", stack_base);
    dump_hex(b"  stack.top    = ", stack_top);
    dump_hex(b"  stack.size   = ", stack_top.wrapping_sub(stack_base));

    // Status byte read raw to avoid GStatus enum UB on bad values.
    let status_raw = unsafe {
        let p = (g_ptr.as_ptr() as *const u8)
            .add(core::mem::offset_of!(G, status));
        p.read_volatile()
    };
    dump_hex(b"  status_raw   = ", status_raw as u64);

    dump_hex(b"  LIVE_G_COUNT = ", LIVE_G_COUNT.load(Ordering::Relaxed) as u64);
    dump_hex(
        b"  DISPATCH_CT  = ",
        DISPATCH_STAMP_COUNT.load(Ordering::Relaxed) as u64,
    );
    let (locks, tramp, parking, no_curg, not_running, sp_range) =
        crate::runtime::preempt::skip_breakdown();
    dump_hex(b"  preempt_inv  = ", crate::runtime::preempt::invocations());
    dump_hex(b"  preempt_inj  = ", crate::runtime::preempt::injections());
    dump_hex(b"  skip_locks   = ", locks);
    dump_hex(b"  skip_tramp   = ", tramp);
    dump_hex(b"  skip_parking = ", parking);
    dump_hex(b"  skip_nocurg  = ", no_curg);
    dump_hex(b"  skip_notrun  = ", not_running);
    dump_hex(b"  skip_sprange = ", sp_range);

    // Hex-dump first 384 bytes of G memory — covers select_wait
    // (0x000..0x100), stack (0x100..0x110), entry (0x110..0x120),
    // gobuf (0x120..0x158), status+padding+select_wait_len+preempt
    // (0x158..0x180). If the allocator zeroed the page, this should
    // be all zeros.
    dump_str(b"  G memory:\n");
    for off in (0usize..384).step_by(16) {
        let p = unsafe { (g_ptr.as_ptr() as *const u8).add(off) };
        let lo = unsafe { (p as *const u64).read_volatile() };
        let hi = unsafe { (p.add(8) as *const u64).read_volatile() };
        // "  +0xNNN = "
        let mut prefix = [0u8; 12];
        prefix[0] = b' ';
        prefix[1] = b' ';
        prefix[2] = b'+';
        prefix[3] = b'0';
        prefix[4] = b'x';
        let nib2 = ((off >> 8) & 0xf) as u8;
        let nib1 = ((off >> 4) & 0xf) as u8;
        let nib0 = (off & 0xf) as u8;
        prefix[5] = if nib2 < 10 { b'0' + nib2 } else { b'a' + (nib2 - 10) };
        prefix[6] = if nib1 < 10 { b'0' + nib1 } else { b'a' + (nib1 - 10) };
        prefix[7] = if nib0 < 10 { b'0' + nib0 } else { b'a' + (nib0 - 10) };
        prefix[8] = b' ';
        prefix[9] = b'=';
        prefix[10] = b' ';
        syscall::Write(stderr, prefix.as_ptr(), 11);
        // dump lo and hi as two qwords.
        let mut buf = [0u8; 36];
        buf[0] = b'0'; buf[1] = b'x';
        for i in 0..16 {
            let nib = ((lo >> ((15 - i) * 4)) & 0xf) as u8;
            buf[2 + i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        }
        buf[18] = b' ';
        buf[19] = b'0'; buf[20] = b'x';
        for i in 0..16 {
            let nib = ((hi >> ((15 - i) * 4)) & 0xf) as u8;
            buf[21 + i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        }
        syscall::Write(stderr, buf.as_ptr(), 37);
        syscall::Write(stderr, b"\n".as_ptr(), 1);
    }

    syscall::Exit(139);
}

#[inline(never)]
#[link_section = "goish_rt_text"]
fn dispatch_validate_g(g_ptr: NonNull<G>) {
    // Per-G stacks are now variable-sized (M26): every G stores its
    // own allocation size on `stack`. Validate that the stored bounds
    // are internally consistent and the size is a power of two ≥
    // FIXED_STACK (2 KiB) — covers both pool-managed slots
    // (2K/4K/8K/16K/32K) and direct-mmap'd large stacks (always
    // page-rounded → multiple of 4096, which is also a power of two
    // multiple). Anything else indicates the G was freed (and likely
    // zeroed) before we got here.
    const FIXED_STACK: usize = 2 * 1024;
    let g_ref = unsafe { g_ptr.as_ref() };
    let base = g_ref.stack.base();
    let top = g_ref.stack.top();
    let recorded = g_ref.stack.size();
    if top > base
        && base != 0
        && top - base == recorded
        && recorded >= FIXED_STACK
        && recorded.is_power_of_two()
    {
        return;
    }
    dispatch_g_trap_dump(b"  reason       : stack invariants violated", g_ptr)
}

/// **`mcall(fn)`** — switch to g0's stack and call `fn(curg)`.
///
/// User-G-side half of Go's `runtime·mcall` (asm_amd64.s:427). Saves
/// the caller's PC/SP/BP/callee-saved into `curg.gobuf`, then the
/// asm switches to `m.g0.gobuf.sp` and calls `fn(curg)`. `fn` must
/// be `-> !` and end with `schedule()` (or `execute(g)`), which uses
/// `gogo` to leave g0 — never returning to mcall_asm directly.
///
/// **Why a Rust wrapper rather than pure asm.** Go encodes `curg`
/// in R14 and `m.g0` at a fixed offset of `g.m`, so its mcall is
/// pure asm. Rust's calling convention has no dedicated `g`
/// register, so we resolve `curg` and `g0` in Rust here and hand the
/// gobuf pointers + fn + arg to a 4-arg asm helper.
///
/// **Save discipline.** `mcall_asm` saves the *return address from
/// this Rust frame's call* as `curg.gobuf.pc`. So when something
/// later calls `gogo(&curg.gobuf)`, control resumes at the
/// instruction after `call mcall_asm` inside this wrapper, which
/// then returns normally to the caller (Gosched/gopark/goexit). The
/// user-visible flow is: caller calls Gosched → mcall(gosched_m)
/// runs gosched_m on g0 → schedule loops, eventually execute(curg)
/// gogos back into curg's saved frame → mcall returns → Gosched
/// returns → user code resumes.
///
/// **Safety.** Caller must already be running as a goroutine (i.e.
/// `m.curg` is `Some`). The Rust wrapper does no allocation and no
/// SpinLock-Guard-spanning work between curg lookup and the asm call.
#[inline(never)]
#[link_section = "goish_rt_text"]
unsafe fn mcall(fn_to_call: extern "C" fn(*mut G) -> !) {
    // **Bump m.locks across the wrapper.** Even with lock-free reads
    // below, SIGURG can land on user G's stack between the reads and
    // the asm call; the trampoline's `Gosched` would save G's gobuf
    // mid-wrapper, re-enqueue, and any M might dispatch it — control
    // would resume inside *this* mcall frame on a possibly-different
    // M while our captured `g0_ptr` is for the *original* M's g0.
    // mcall_asm would then switch RSP to the wrong M's g0 stack and
    // corrupt scheduler state on both Ms.
    //
    // `acquirem` makes m.locks > 0 throughout the wrapper; SIGURG is
    // skipped on the m.locks check. The matching `releasem` runs
    // **inside the fn body** on g0 (gosched_m / park_m / goexit0
    // call `releasem` before `schedule()`), since by then we're past
    // the mcall_asm switch and the wrapper's local state is no longer
    // load-bearing.
    acquirem();

    // **Why lock-free reads of g0/curg** (not `current_m().lock()`):
    //
    // Both fields are per-M and only mutated by the M's own thread,
    // so a same-thread read is data-race-free without the SpinLock.
    //
    // Taking the SpinLock here would compound the migration risk: the
    // Guard<M> drop runs `cooperative_preempt_check`, which can
    // trigger another Gosched detour. acquirem above already prevents
    // SIGURG-induced migration; lock-free reads close the
    // coop_preempt_check vector too.
    let storage = current_m_storage();
    let g0_ptr = storage.g0.load(Ordering::Acquire);
    debug_assert!(!g0_ptr.is_null(), "mcall: g0 not initialized");

    let curg = unsafe { current_m().data_unchecked().curg }
        .expect("mcall: no current G");

    let from_buf = unsafe { &mut (*curg.as_ptr()).gobuf as *mut Gobuf };
    let to_buf = unsafe { &(*g0_ptr).gobuf as *const Gobuf };

    unsafe {
        mcall_asm(from_buf, to_buf, fn_to_call, curg.as_ptr());
    }
}

/// **`execute(gp)`** — run `gp` on the current M. Mirrors Go's
/// `execute` (proc.go:3336). Never returns: ends in `gogo(&gp.gobuf)`,
/// which JMPs into the goroutine's saved context.
///
/// Must be called on g0's stack (i.e., from inside `schedule()`,
/// `gosched_m`, `park_m`, or `goexit0`). The first call after a
/// goroutine is allocated lazily lays out the `Idle → Running` first
/// frame via `make_context_gogo`.
#[inline(never)]
#[link_section = "goish_rt_text"]
fn execute(mut g_ptr: NonNull<G>) -> ! {
    dispatch_validate_g(g_ptr);
    let g = unsafe { g_ptr.as_mut() };
    if g.status == GStatus::Idle {
        // First-time dispatch: lay out gobuf for gogo. PC is either
        // `g_entry` (fixed-stack goroutines: `go!(stack(N), …)` and
        // `go!(N, …)`) or `g_entry_growable` (bare `go!()` — wraps
        // user `entry()` in `maybe_grow_step` for tier-aware lazy
        // growth). Sp = stack_top-8, with goexit_trampoline parked
        // at [sp].
        let entry_fn: extern "C" fn() -> ! =
            if g.growable { g_entry_growable } else { g_entry };
        unsafe {
            make_context_gogo(&mut g.gobuf, g.stack.top(), entry_fn);
        }
    }
    g.status = GStatus::Running;

    // Clear stale preempt-request flag; sysmon will set it again if
    // this G runs too long.
    g.preempt.store(false, Ordering::Relaxed);

    {
        let mut m = current_m().lock();
        m.curg = Some(g_ptr);
    }
    // M18b-β: stamp the start time so sysmon's force-preempt scan can
    // compute elapsed runtime. Lock-free; cleared in the yield-fn
    // bodies (gosched_m / park_m / goexit0) after dropg.
    current_m_storage()
        .start_running_ns
        .store(crate::runtime::sysmon::monotonic_ns(), Ordering::Release);
    DISPATCH_STAMP_COUNT.fetch_add(1, Ordering::Relaxed);

    let buf = &g.gobuf as *const Gobuf;
    unsafe { gogo(buf) }
}

/// `dropg` — sever the M↔G ownership and clear the run-time stamp.
/// Mirrors Go's `dropg()` (proc.go:3322): zeros `m.curg` and `gp.m`.
/// Goish carries no `gp.m` field yet; only the M side is cleared.
#[inline(always)]
fn dropg() {
    current_m().lock().curg = None;
    current_m_storage()
        .start_running_ns
        .store(0, Ordering::Release);
}

/// `gosched_m(gp)` — Gosched continuation on g0. Mirrors Go's
/// `gosched_m` → `goschedImpl(gp, false)` (proc.go:4283, 4318).
///
/// Runs after `mcall(gosched_m)` switched to g0. Sets gp Runnable,
/// drops M's claim, re-enqueues, then `schedule()` picks the next G.
extern "C" fn gosched_m(g_ptr: *mut G) -> ! {
    // Release the mcall-wrapper's m.locks bump (we're now on g0; no
    // user-G context to preempt back into).
    releasem();
    let g = NonNull::new(g_ptr).expect("gosched_m: null gp");
    unsafe {
        (*g_ptr).status = GStatus::Runnable;
    }
    dropg();
    // `next=false` matches Go's `goschedImpl(_, false)` — Gosched
    // yields to the back of the queue (proc.go:4307 globrunqput).
    enqueue_runnable(g, false);
    schedule()
}

/// `park_m(gp)` — gopark continuation on g0. Mirrors Go's `park_m`
/// (proc.go:4229). Sets gp Waiting, drops M's claim, runs the
/// commit fn (the unlockf that releases chan/select locks); on
/// `false` the park is aborted and gp is `execute()`d immediately,
/// otherwise schedule() picks something else.
extern "C" fn park_m(g_ptr: *mut G) -> ! {
    // Release the mcall-wrapper's m.locks bump.
    releasem();
    let g = NonNull::new(g_ptr).expect("park_m: null gp");

    // Take waitunlockf but DO NOT clear waitlock yet — goish's
    // commit fns (e.g. `chan_park_commit`) read `m.waitlock` from M
    // rather than receive it as an arg, so the slot must remain
    // populated across the unlockf call. Mirrors Go's proc.go:4258
    // which passes mp.waitlock to fn(gp, mp.waitlock) and then nil's
    // both fields *after* the call returns.
    let unlockf = current_m().lock().waitunlockf.take();

    unsafe {
        (*g_ptr).status = GStatus::Waiting;
    }
    dropg();

    if let Some(f) = unlockf {
        let parked = unsafe { f(g) };
        // Clear waitlock now that unlockf has consumed it (matches
        // Go's `mp.waitlock = nil` at proc.go:4261).
        current_m().lock().waitlock = core::ptr::null();
        if !parked {
            // Abort park (proc.go:4262-4273): status → Runnable;
            // execute(gp, true) — re-dispatch this same G immediately.
            unsafe {
                (*g_ptr).status = GStatus::Runnable;
            }
            execute(g);
        }
    } else {
        current_m().lock().waitlock = core::ptr::null();
    }
    schedule()
}

/// `goexit0(gp)` — goexit continuation on g0. Mirrors Go's
/// `goexit0` (proc.go:4447) plus `gdestroy` (proc.go:4452): casgstatus
/// to Dead, dropg, decrement live-count, free the G via
/// `Box::from_raw`, then `schedule()`.
extern "C" fn goexit0(g_ptr: *mut G) -> ! {
    // Release the mcall-wrapper's m.locks bump.
    releasem();
    unsafe {
        (*g_ptr).status = GStatus::Dead;
    }
    dropg();

    let prev = LIVE_G_COUNT.fetch_sub(1, Ordering::AcqRel);

    // Poison gobuf before the box drops the rest of the G — KASAN-
    // style beacon for any post-free dispatch via stale pointer.
    unsafe {
        const POISON: u64 = 0xDEADBEEF_DEADBEEF;
        let gbuf_off = core::mem::offset_of!(G, gobuf);
        let g_bytes = g_ptr as *mut u8;
        let gobuf_size = core::mem::size_of::<Gobuf>();
        let mut off = 0usize;
        while off < gobuf_size {
            (g_bytes.add(gbuf_off + off) as *mut u64).write_volatile(POISON);
            off += 8;
        }
    }
    let _ = unsafe { Box::from_raw(g_ptr) };

    if prev == 1 {
        // Last live goroutine just exited. Wake every parked M so
        // they observe LIVE_G_COUNT == 0 and either exit (main M)
        // or stay parked (workers, reaped by exit_group).
        wake_all_idle_m();
    }
    schedule()
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
///
/// **M17b-ε**: under the mcall-pattern, `schedule()` runs on g0's
/// stack and never returns. Picks a runnable G via `find_runnable`
/// and hands off to `execute(g)` (which uses `gogo` to JMP into the
/// G — also no return). When no work is left and `LIVE_G_COUNT == 0`
/// the main M exits the process (`Exit(0)`); workers stay parked
/// forever (process exit will reap them).
#[inline(never)]
#[link_section = "goish_rt_text"]
pub fn schedule() -> ! {
    loop {
        match find_runnable() {
            Some(g) => execute(g), // never returns
            None => {
                if LIVE_G_COUNT.load(Ordering::Acquire) == 0 {
                    maybe_exit_main_m();
                }
                // Brief spin (~32 PAUSE) to absorb producer
                // latency, then futex-park. Mirrors Go's
                // `runtime.findRunnable` spin-then-stop pattern.
                spin_or_yield();
                if LIVE_G_COUNT.load(Ordering::Acquire) == 0 {
                    maybe_exit_main_m();
                }
                if !has_local_or_global_work() {
                    park_m_idle();
                }
            }
        }
    }
}

/// Exit the process if the calling thread is the main M (id == 0).
/// On worker Ms this is a no-op — workers remain parked forever and
/// are reaped by `exit_group(2)` from the main M's `Exit`.
#[inline(never)]
#[link_section = "goish_rt_text"]
fn maybe_exit_main_m() {
    let id = current_m().lock().id;
    if id == 0 {
        crate::syscall::Exit(0);
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
#[inline(never)]
#[link_section = "goish_rt_text"]
fn park_m_idle() {
    let storage = current_m_storage();

    // mput + park-decision under MIDLE lock — atomicity ensures
    // wakers either see us in MIDLE (and pop us) or push runq
    // before we re-check. Go does this under `sched.lock`.
    {
        let mut midle = MIDLE.lock();
        // Re-check conditions under the lock. M17b-β: cover both
        // local P runq and global runq; either has work blocks
        // the park.
        if has_local_or_global_work() {
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
#[inline(never)]
#[link_section = "goish_rt_text"]
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
#[inline(never)]
#[link_section = "goish_rt_text"]
pub fn m_schedule_loop() -> ! {
    // M17b-ε: schedule() is the unified entry point under the mcall
    // pattern; it never returns. The main-vs-worker shutdown branch
    // lives inside `maybe_exit_main_m()` (workers stay parked).
    schedule()
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

/// Number of worker Ms that have completed `acquirep` and entered
/// `m_schedule_loop`. `bootstrap_workers` waits on this so that, by
/// the time the runtime hands control to user `main()`, every P has
/// its M bound. `clone(2)` returns asynchronously (the new thread
/// is *runnable* but may not have *run* yet), so without this
/// barrier `for_each_p` from the main M can briefly observe a P
/// with `bound_m() == None` — observable in `sched_p_alpha`'s
/// "every P bound" assertion under stress.
///
/// Mirrors the post-condition of Go's `procresize` (proc.go:5904):
/// after that returns, every P has been assigned to an M (or to the
/// idle list, which goish doesn't carry yet — workers acquirep
/// directly at startup).
static WORKERS_PRIMED: AtomicUsize = AtomicUsize::new(0);

/// Worker M entry point. Spawned by `spawn_worker_m` via `clone(2)`
/// with `CLONE_SETTLS` already pointing at the worker's `MStorage`.
/// Records the kernel tid in `M::procid`, acquires its P, signals
/// `bootstrap_workers`, then enters `m_schedule_loop`.
///
/// Never returns: the M parks (futex-waits) when no work is found,
/// and `exit_group(2)` from main M's `runtime.exit` reaps every
/// parked worker at process termination.
///
/// Mirrors Go's `runtime.mstart1` (proc.go:1689) minus the GC and
/// signal-handling pieces we don't carry yet.
extern "C" fn mstart() -> ! {
    // M18b-δ.3: register this worker's per-thread alt signal stack
    // first, before any other work. Sysmon may be live by the time
    // we reach `WORKERS_PRIMED.fetch_add`, and the SIGURG handler is
    // installed with `SA_ONSTACK` — so the alt stack must already be
    // in place before any SIGURG can land on this thread.
    super::m::install_signal_stack();

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
    // Signal `bootstrap_workers` that this worker has finished
    // wiring itself up. Done after `acquirep` (and after
    // `install_signal_stack`) so the bootstrap-side wait observes a
    // fully-bound P AND a thread that's ready to receive signals on
    // its alt stack.
    WORKERS_PRIMED.fetch_add(1, Ordering::Release);
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

    // M17b-ε.α: allocate this worker's `g0` BEFORE clone(2). The
    // mmap'd 64 KiB region we just got is the OS thread stack — i.e.,
    // exactly what `g0.stack` adopts. Storing the pointer in
    // `m.g0` before clone means the worker's `mstart` sees a fully-
    // wired g0 from its first instruction, so any future `getg()`
    // there returns g0 (not None / not stale).
    //
    // Box::leak: g0 lives for the M's lifetime; process exit reclaims
    // the heap and the stack mmap together via exit_group(2).
    let g0_box = alloc::boxed::Box::new(super::g::G::new_g0(stack_base, WORKER_M_STACK));
    let g0_ptr: *mut super::g::G = alloc::boxed::Box::leak(g0_box) as *mut _;
    storage.g0.store(g0_ptr, Ordering::Release);

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
    // Pre-grow MIDLE / ALL_MS to capacity so subsequent push()es
    // never reallocate. MIDLE is hit on every M park; without this
    // the first park-cycle pushes trigger amortized Vec growth (an
    // allocator round-trip under MIDLE's SpinLock — exactly the
    // class of slow path the M26-phase + intrusive-Sema work
    // chased out of the runtime). Sized to `n` (will never grow
    // past the M count) but capped at MAX_PS for safety.
    {
        let cap = n.min(crate::runtime::sched::MAX_PS);
        MIDLE.lock().reserve_exact(cap.saturating_sub(1));
        ALL_MS.lock().reserve_exact(cap);
    }
    // Spawn one worker per CPU beyond the main M (id=0).
    for i in 1..n {
        let _ = spawn_worker_m(i as u32);
    }
    // Wait until every spawned worker has completed `acquirep`.
    // Each worker increments `WORKERS_PRIMED` after binding its P,
    // so this load reaching `n - 1` means every P[1..n] has its
    // bound M. Bounded wait: each worker only executes a handful
    // of instructions between `clone(2)` returning and `acquirep`,
    // typically resolving in microseconds.
    let want = n.saturating_sub(1);
    while WORKERS_PRIMED.load(Ordering::Acquire) < want {
        let _ = crate::syscall::SchedYield();
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
    current_m().lock().curg
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
#[inline(never)]
#[link_section = "goish_rt_text"]
pub fn gopark(commit: ParkCommit, lock_atom: *const AtomicBool) {
    // Lock-free curg read — see `mcall` for why taking the SpinLock
    // here is unsafe (coop_preempt_check can migrate us mid-call).
    if unsafe { current_m().data_unchecked().curg }.is_none() {
        return;
    }

    // Hold m.locks > 0 across the setup → mcall window. Mirrors Go's
    // gopark (proc.go:419):
    //   acquirem → setup → releasem → mcall(park_m)
    // The matching releasem runs *before* the context switch so the
    // +1 / -1 are accounted on the same M (the parker's M may differ
    // from the resuming M after multi-M migration).
    acquirem();

    // Stash commit + lock pointer on the M. park_m picks them up on
    // g0 post-mcall and invokes commit there (after dropg).
    //
    // We hold `m.locks > 0` across this whole block (acquirem above),
    // so the SpinLock-Guard's coop_preempt_check skips on m.locks > 0
    // and cannot migrate us before mcall.
    {
        let mut m = current_m().lock();
        m.waitunlockf = Some(commit);
        m.waitlock = lock_atom;
    }

    releasem();
    unsafe {
        mcall(park_m);
    }
    // Resumed via gogo from execute() — control re-enters the user
    // G's frame at the instruction after `mcall(park_m)`'s asm call.
    // status was restored to Running by execute().
}

/// `block_forever_commit` — gopark commit fn for nil-chan send/recv.
/// Returns `true` (commit the park) but releases nothing; the G is
/// never goready'd by anyone, so this is a permanent park.
///
/// Mirrors Go's `gopark(nil, nil, waitReasonChanSendNilChan,
/// traceBlockForever, 2)` (chan.go:181, 536). Used only by `Send`/
/// `Recv` on a nil chan; in `select!` nil cases are filtered before
/// the lock-order pass and never reach gopark.
#[inline(never)]
#[link_section = "goish_rt_text"]
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
#[inline(never)]
#[link_section = "goish_rt_text"]
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
#[inline(never)]
#[link_section = "goish_rt_text"]
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
    // Do NOT clear g.select_wait_len here. Once raw_unlock above
    // releases each chan atom, a waker on another M can claim our
    // sudog and goready us *before* we return. If that waker's pass-1
    // re-dispatches this G on a different M and that G runs the next
    // select! iteration's pass-2 (which writes select_wait_len again),
    // the clear here would race and overwrite the new value with 0.
    // The next selparkcommit invocation would then read 0, walk no
    // atoms, and the new pass-2's chan locks would be leaked. Verified
    // via rr replay: the fix removes the only writer that races with
    // pass-2's `__g.select_wait_len = __take_n` (select_macro.rs:626).
    // Pass-2 always sets the value freshly before each gopark; no
    // other commit fn reads it; leaving stale len behind is harmless.
    true
}

/// Wake a goroutine previously parked via `gopark`. Mirrors Go's
/// `runtime.goready` (proc.go:479).
///
/// The G is transitioned from `Waiting` to `Runnable` and pushed
/// onto the local P's runq (M17b-β) — falling back to the global
/// runq when the caller holds no P (e.g. sysmon-driven wakers or
/// pre-bootstrap callers). `wake_idle_m` ensures a parked M picks
/// up the work whether it's local or global.
#[inline(never)]
#[link_section = "goish_rt_text"]
pub fn goready(g_ptr: NonNull<G>) {
    unsafe {
        debug_assert_eq!(
            (*g_ptr.as_ptr()).status,
            GStatus::Waiting,
            "goready: target G is not parked"
        );
        (*g_ptr.as_ptr()).status = GStatus::Runnable;
    }
    // next=true: chan-waker / sync-waker fastpath — the just-readied G
    // gets `runnext` priority on the local P. Toggled by GOISH_RUNNEXT
    // (debug feature flag).
    let next = crate::runtime::flags::RUNNEXT_FASTPATH.load(Ordering::Relaxed);
    enqueue_runnable(g_ptr, next);
}
