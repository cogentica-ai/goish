// runtime::sysmon — system-monitor thread + timer heap (M18a).
//
// Mirrors Go's `runtime.sysmon` (proc.go:6228) and the timer heap
// from `runtime/time.go`. Goish v1 simplifications:
//
//   - One global timer heap (Go has per-P heaps for locality).
//     SpinLock-protected min-heap keyed by deadline_ns.
//
//   - One dedicated sysmon thread spawned at runtime startup. It
//     is its own OS thread (`clone(2)`), with its own MStorage so
//     `current_m()` reads work; but it is NOT a goroutine
//     dispatcher — its only job is to wake timer-parked Gs.
//
//   - Wake-up signaling uses the seqcount-style futex idiom: a
//     monotonically-increasing `SYSMON_PARK` AtomicU32. Sysmon
//     samples it, processes timers, then `futex_wait`s on it
//     against the sample. Any time.Sleep that pushes a deadline
//     earlier than the current top-of-heap does `fetch_add(1)`
//     and `futex_wake(1)` — sysmon's wait sees the value mismatch
//     and returns -EAGAIN immediately, recomputing its nap.
//
//   - time.Sleep parks via the standard `gopark(chan_park_commit,
//     lock_atom)` protocol with the timer-heap lock held across
//     swap_context — same multi-M-correct pattern channels use.
//     The lock is released by chan_park_commit on the scheduler
//     stack post-swap.
//
// What v1 does NOT include:
//   - Per-P timer heaps (Go's `pp.timers`).
//   - Timer modify/stop (no Timer/Ticker objects yet — only Sleep).
//   - sysmon's other duties: GC trigger, network poller, scavenger,
//     forced preemption (M18b will own preemption).

use alloc::boxed::Box;
use alloc::collections::BinaryHeap;
use core::cmp::{Ordering as CmpOrdering, Reverse};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::runtime::sched::{
    chan_park_commit, current_g, for_each_m, gopark, goready, register_m_storage, G,
};
use crate::runtime::spin::{raw_lock, SpinLock};
use crate::syscall::{
    self, Clone, ClockGettime, Futex, Timespec, CLOCK_MONOTONIC, CLONE_THREAD_FLAGS,
    FUTEX_WAIT_PRIVATE, FUTEX_WAKE_PRIVATE, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE,
    PROT_READ, PROT_WRITE,
};

// ─── Monotonic clock helper ───────────────────────────────────────

/// Read CLOCK_MONOTONIC and return ns since an arbitrary fixed
/// epoch. Used as the timer-heap deadline reference.
#[inline]
pub fn monotonic_ns() -> i64 {
    let mut ts = Timespec::default();
    let _ = ClockGettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec)
}

// ─── Timer heap ───────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct TimerEntry {
    deadline_ns: i64,
    g: NonNull<G>,
}

unsafe impl Send for TimerEntry {}

impl PartialEq for TimerEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline_ns == other.deadline_ns
    }
}
impl Eq for TimerEntry {}
impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.deadline_ns.cmp(&other.deadline_ns)
    }
}
impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

// `Reverse` makes BinaryHeap behave as a min-heap (earliest
// deadline first).
static TIMER_HEAP: SpinLock<BinaryHeap<Reverse<TimerEntry>>> =
    SpinLock::new(BinaryHeap::new());

// Seqcount-style wake-counter for sysmon. fetch_add invalidates
// any in-flight futex_wait sample.
static SYSMON_PARK: AtomicU32 = AtomicU32::new(0);

/// Wake sysmon if it's currently napping. Bumps the seqcount
/// (so any in-flight futex_wait against the previous value
/// returns -EAGAIN immediately) and delivers a futex_wake in
/// case sysmon is mid-wait. Async-signal-safe: only an atomic
/// fetch_add and a raw futex syscall — callable from signal
/// handler context. Used by `runtime::signal::goish_sigtramp`
/// to ensure pending signals dispatch promptly even when
/// sysmon's nap timeout is far in the future.
pub fn wake() {
    SYSMON_PARK.fetch_add(1, Ordering::Release);
    let addr = &SYSMON_PARK as *const AtomicU32 as *const u32;
    Futex(addr, FUTEX_WAKE_PRIVATE, 1, core::ptr::null());
}

/// Push the calling G onto the timer heap with deadline
/// `now + ns`, then `gopark` until sysmon wakes it. Heap lock is
/// held continuously across enqueue → swap so sysmon cannot
/// observe and `goready` the G until its gobuf is fully committed
/// — same primitive chan/select use.
pub fn timer_park(ns: i64) {
    if ns <= 0 {
        return;
    }
    let deadline = monotonic_ns().wrapping_add(ns);
    let g = match current_g() {
        Some(g) => g,
        None => return, // outside any goroutine — nothing to park
    };

    let lock_atom = TIMER_HEAP.lock_atom();
    unsafe {
        raw_lock(lock_atom);
    }
    let heap = unsafe { TIMER_HEAP.data_unchecked() };
    let need_wake = match heap.peek() {
        Some(Reverse(top)) => deadline < top.deadline_ns,
        None => true,
    };
    heap.push(Reverse(TimerEntry {
        deadline_ns: deadline,
        g,
    }));

    if need_wake {
        // Bump the seqcount so any sysmon futex_wait against the
        // previous value returns immediately, then deliver the
        // syscall wake in case sysmon is mid-wait.
        SYSMON_PARK.fetch_add(1, Ordering::Release);
        let addr = &SYSMON_PARK as *const AtomicU32 as *const u32;
        Futex(addr, FUTEX_WAKE_PRIVATE, 1, core::ptr::null());
    }

    // gopark releases lock_atom on the scheduler stack post-swap.
    gopark(chan_park_commit, lock_atom);
}

// ─── sysmon loop ──────────────────────────────────────────────────

/// Default poll period when the heap is empty. Long enough that
/// idle sysmon doesn't burn CPU; short enough that timers added
/// without need_wake-signaling (impossible in current design, but
/// belt-and-suspenders) still get serviced.
const SYSMON_IDLE_NS: i64 = 60 * 1_000_000_000; // 60 s

/// Max nap between force-preempt scans (M18b-β). Caps the sysmon
/// nap so a goroutine that has been running for more than
/// FORCE_PREEMPT_NS gets a SIGURG within roughly this period.
/// Mirrors Go's sysmon `forcePreemptNS = 10 * 1e6` quantum
/// (proc.go:6280) — we use the same 10 ms cadence.
const FORCE_PREEMPT_NS: i64 = 10 * 1_000_000; // 10 ms

// ─── M18b-β: force-preempt scan ──────────────────────────────────
//
// Once every sysmon tick, walk every registered M. For each one
// whose `current_g` has been Running for longer than
// `FORCE_PREEMPT_NS`, set `g.preempt = true` and `tgkill(SIGURG)`
// the M's Linux thread. The SIGURG handler in `runtime::preempt`
// then injects via the asyncPreempt trampoline. If the M was in a
// runtime critical section (`m.locks > 0`) the handler skips, but
// `g.preempt` stays set — the cooperative path (M18b-γ) catches
// the G when it next releases its last lock. Sysmon retries on
// every subsequent tick until either the G yields or the M shows a
// fresh `start_running_ns` (because the previous G already yielded
// and a different one is now running).
//
// Mirrors the role of Go's `retake` (proc.go:6275) +
// `preemptone` (proc.go:6398) without the per-P bookkeeping that
// goish v1 doesn't carry.

// Diagnostic counters (read by tests).
static SYSMON_SCAN_TICKS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
static SYSMON_FORCE_PREEMPTS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Number of times sysmon ran its force-preempt scan loop.
pub fn force_preempt_scan_ticks() -> u64 {
    SYSMON_SCAN_TICKS.load(Ordering::Relaxed)
}

/// Number of times sysmon issued a tgkill SIGURG to force-preempt
/// a long-running G.
pub fn force_preempt_signals_sent() -> u64 {
    SYSMON_FORCE_PREEMPTS.load(Ordering::Relaxed)
}

fn check_force_preempt(now: i64) {
    if !crate::runtime::flags::ASYNC_PREEMPT.load(Ordering::Relaxed) {
        return;
    }
    SYSMON_SCAN_TICKS.fetch_add(1, Ordering::Relaxed);
    let pid = syscall::Getpid();
    for_each_m(|storage| {
        let start = storage.start_running_ns.load(Ordering::Acquire);
        if start == 0 {
            return; // M is idle / between dispatches
        }
        if now.wrapping_sub(start) < FORCE_PREEMPT_NS {
            return; // hasn't been running long enough
        }
        // Read curg lock-free under the same Theorem 1 invariant
        // the SIGURG handler relies on. We're on a *different*
        // thread here (sysmon), so this is a cross-thread read —
        // but `current_g` is only written under `m.locks > 0` and
        // x86-64 makes a naturally aligned 8-byte load atomic, so
        // the value we observe is either the previous committed
        // pointer or the freshly committed one. Either is safe to
        // act on (we just ask the handler to consider it).
        let m = unsafe { storage.m.data_unchecked() };
        let g_ptr = match m.curg {
            Some(p) => p,
            None => return,
        };
        let g_ref = unsafe { g_ptr.as_ref() };
        // Set preempt flag for cooperative-side rescue (M18b-γ).
        g_ref.preempt.store(true, Ordering::Release);
        // Send SIGURG to the M's thread.
        let tid = m.procid.load(Ordering::Acquire);
        if tid > 0 {
            SYSMON_FORCE_PREEMPTS.fetch_add(1, Ordering::Relaxed);
            syscall::Tgkill(pid, tid, syscall::SIGURG);
        }
    });
}

/// Process all expired timers, then sleep until the next deadline
/// or until signaled. Never returns. Spawned on its own OS thread.
extern "C" fn sysmon_main() -> ! {
    // Set tid in our M.
    let tid = syscall::Gettid();
    {
        let m = crate::runtime::sched::current_m().lock();
        m.procid.store(tid, Ordering::Release);
    }

    loop {
        // Sample seqcount BEFORE inspecting the heap. Any
        // time.Sleep that bumps the seqcount after this point
        // invalidates our upcoming futex_wait against the sample.
        let sample = SYSMON_PARK.load(Ordering::Acquire);

        // M23: drain any signals delivered since the last poll
        // and forward them to registered channels. Non-blocking;
        // signal handler did the work of bumping the per-sig
        // counter from async context.
        crate::runtime::signal::dispatch_pending();

        let now = monotonic_ns();

        // M18b-β: scan Ms for goroutines that have been running
        // too long and force-preempt them via SIGURG.
        check_force_preempt(now);

        // Fire all expired timers. Pop one at a time, drop the heap
        // lock, goready, repeat. Avoids batching into a Vec (which
        // would allocate once per sysmon tick that has any expirations).
        let next_deadline: Option<i64> = loop {
            let popped: Option<NonNull<G>> = {
                let mut heap = TIMER_HEAP.lock();
                match heap.peek().copied() {
                    Some(Reverse(entry)) if entry.deadline_ns <= now => {
                        heap.pop();
                        Some(entry.g)
                    }
                    _ => break heap.peek().map(|Reverse(e)| e.deadline_ns),
                }
            };
            if let Some(g) = popped {
                goready(g);
            }
        };

        // Sleep until next deadline (or default poll). Capped at
        // FORCE_PREEMPT_NS so the next force-preempt scan fires
        // within ~10 ms regardless of timer activity.
        let nap_ns = match next_deadline {
            Some(d) => (d - now).max(1_000),
            None => SYSMON_IDLE_NS,
        }
        .min(FORCE_PREEMPT_NS);
        let ts = Timespec {
            tv_sec: nap_ns / 1_000_000_000,
            tv_nsec: nap_ns % 1_000_000_000,
        };
        let addr = &SYSMON_PARK as *const AtomicU32 as *const u32;
        // futex_wait(SYSMON_PARK, sample, ts):
        //   - if SYSMON_PARK != sample (a signal happened): -EAGAIN, return now
        //   - else sleep up to ts; on signal -> return; on timeout -> return
        Futex(addr, FUTEX_WAIT_PRIVATE, sample, &ts);
    }
}

const SYSMON_STACK: usize = 64 * 1024;

/// Spawn the sysmon thread. Must be called once after worker
/// bootstrap so register_m_storage's allocator is up.
pub fn start_sysmon() {
    let storage: &'static crate::runtime::sched::MStorage = Box::leak(Box::new(
        crate::runtime::sched::MStorage::new(u32::MAX), // sentinel id for sysmon
    ));
    storage.init_tls_self();
    register_m_storage(storage);

    let stack_base = syscall::Mmap(
        core::ptr::null_mut(),
        SYSMON_STACK,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if stack_base == MAP_FAILED {
        const MSG: &[u8] = b"goish: sysmon: mmap failed\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    let stack_top = unsafe { stack_base.add(SYSMON_STACK) };

    unsafe {
        Clone(
            CLONE_THREAD_FLAGS,
            stack_top,
            sysmon_main,
            storage.fs_base() as u64,
        );
    }
}
