// runtime/pprof/sample — SIGPROF-driven CPU sampling.
//
// go: none — goish-only: Go's sampler lives in `runtime/cpuprof.go` and
// `runtime/signal_unix.go`, entangled with the M/P machinery and a
// lock-free ring goish has no equivalent of. This is the same idea
// built from the pieces goish has.
//
// `setitimer(ITIMER_PROF)` delivers SIGPROF every `period` of CPU time
// — user AND system, which is why it is ITIMER_PROF and not
// ITIMER_VIRTUAL: a profile that ignored kernel time would attribute
// nothing to a syscall-heavy function.
//
// The handler walks the INTERRUPTED stack, not its own. Its RBP is the
// handler frame; the profiled frame is in the ucontext the kernel
// pushed, which `segv.rs` already reads the same way for its
// backtraces. `segv::walk_frames` takes an explicit RBP precisely so it
// can be pointed at either.
//
// ─── what runs in the handler ────────────────────────────────────────
//
// Nothing that allocates, locks or parks. A SIGPROF can land anywhere,
// including inside the allocator with its own lock held, so the handler
// writes into a preallocated fixed ring with an atomic index and does
// nothing else. Symbolisation, string interning and protobuf encoding
// all happen later, on an ordinary goroutine, from the recorded PCs.

#![allow(non_snake_case)]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::runtime::preempt::{UcontextT, REG_RBP, REG_RIP};
use crate::runtime::segv::MAX_FRAMES;

/// How many samples the ring holds before it starts dropping. At the
/// default 100 Hz this is ~80 seconds of profile; a longer run loses
/// the OLDEST samples, which is the wrong end but is what a fixed
/// buffer can do without allocating in a signal handler.
const RING: usize = 8192;

/// One captured stack. `depth` is how many of `pcs` are valid.
#[derive(Clone, Copy)]
struct Sample {
    pcs: [u64; MAX_FRAMES],
    depth: usize,
}

impl Sample {
    // go: none — goish-only: a zero sample for the ring's const init.
    const fn empty() -> Self {
        return Sample {
            pcs: [0u64; MAX_FRAMES],
            depth: 0,
        };
    }
}

/// The ring. A plain static rather than anything guarded: only the
/// signal handler writes it, and only while `ACTIVE`, and the reader
/// runs after `stop()` has disarmed the timer and cleared `ACTIVE`.
static mut RING_BUF: [Sample; RING] = [Sample::empty(); RING];

/// Total samples taken, including any that wrapped. The write index is
/// `WRITTEN % RING`, so a reader can tell whether it lost any.
static WRITTEN: AtomicUsize = AtomicUsize::new(0);

/// Whether the handler should record. Cleared BEFORE the timer is
/// disarmed so an in-flight signal cannot write after the reader
/// starts.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// The sampling period actually programmed, in nanoseconds, for the
/// profile's `period` field.
static PERIOD_NS: AtomicU64 = AtomicU64::new(0);

// go: none — goish-only: see the module header.
/// The SIGPROF handler. Async-signal-safe by construction: it reads two
/// registers out of the ucontext, walks a bounded frame chain, and
/// writes into preallocated storage.
extern "C" fn goish_prof_sigtramp(_sig: i32, _info: *const u8, ctx: *mut UcontextT) {
    if !ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    if ctx.is_null() {
        return;
    }
    // The INTERRUPTED frame, not the handler's own.
    let rip = crate::convert::uint64(unsafe { (*ctx).uc_mcontext.gregs[REG_RIP] });
    let rbp = crate::convert::uint64(unsafe { (*ctx).uc_mcontext.gregs[REG_RBP] });

    let (lo, hi) = match stack_bounds() {
        Some(b) => b,
        // No current G — the sample landed on g0 or the bootstrap
        // thread. Go attributes those to the runtime; goish drops them
        // rather than walking a stack it cannot bound.
        None => return,
    };

    let mut frames = [0u64; MAX_FRAMES];
    // The interrupted PC is the leaf and is NOT in the frame chain:
    // walk_frames returns RETURN addresses, so without this the
    // innermost function is missing from every sample and its time is
    // attributed to its caller.
    frames[0] = rip;
    // Walk into a second buffer, then splice after the leaf.
    let mut rest = [0u64; MAX_FRAMES];
    let n = crate::runtime::segv::walk_frames(rbp, lo, hi, &mut rest);
    let mut depth = 1usize;
    let mut i = 0usize;
    while i < n && depth < MAX_FRAMES {
        frames[depth] = rest[i];
        depth += 1;
        i += 1;
    }

    let slot = WRITTEN.fetch_add(1, Ordering::Relaxed) % RING;
    unsafe {
        let r = &raw mut RING_BUF[slot];
        (*r).pcs = frames;
        (*r).depth = depth;
    }
}

// go: none — goish-only: see the module header.
/// The current G's stack region, or None when there is no G to bound
/// the walk with.
fn stack_bounds() -> Option<(usize, usize)> {
    if !crate::runtime::sched::is_tls_ready() {
        return None;
    }
    let g_ptr = unsafe { crate::runtime::sched::current_m().data_unchecked().curg }?;
    let g = unsafe { &*g_ptr.as_ptr() };
    let lo = g.active_stack_lo.load(Ordering::Relaxed);
    let hi = g.active_stack_hi.load(Ordering::Relaxed);
    if lo == 0 || hi <= lo {
        return None;
    }
    return Some((lo, hi));
}

// go: none — goish-only: see the module header.
/// Install the handler and arm the timer at `hz` samples per second of
/// CPU time. Returns false if the kernel refused either.
pub(crate) fn start(hz: i64) -> bool {
    if hz <= 0 {
        return false;
    }
    let period_ns = 1_000_000_000i64 / hz;
    PERIOD_NS.store(crate::convert::uint64(period_ns), Ordering::Relaxed);
    WRITTEN.store(0, Ordering::Relaxed);

    let sa = crate::syscall::Sigaction {
        sa_handler: goish_prof_sigtramp as *const () as usize,
        sa_flags: crate::syscall::SA_SIGINFO
            | crate::syscall::SA_RESTORER
            | crate::syscall::SA_ONSTACK,
        sa_restorer: crate::syscall::SigreturnTrampoline as *const () as usize,
        sa_mask: 0,
    };
    let r = unsafe {
        crate::syscall::RtSigaction(
            crate::syscall::SIGPROF,
            &sa as *const _,
            core::ptr::null_mut(),
        )
    };
    if r != 0 {
        return false;
    }

    // ACTIVE before the timer: a signal that arrives the instant the
    // timer is armed must find the handler willing to record.
    ACTIVE.store(true, Ordering::SeqCst);
    let usec = period_ns / 1_000;
    let tv = crate::os::exec_posix::Timeval {
        Sec: 0,
        Usec: usec,
    };
    let it = crate::syscall::Itimerval {
        it_interval: tv,
        it_value: tv,
    };
    let r = crate::syscall::Setitimer(
        crate::syscall::ITIMER_PROF,
        &it as *const _,
        core::ptr::null_mut(),
    );
    if r != 0 {
        ACTIVE.store(false, Ordering::SeqCst);
        return false;
    }
    return true;
}

// go: none — goish-only: see the module header.
/// Disarm the timer and stop recording. Ordering matters: `ACTIVE` is
/// cleared FIRST so a signal already in flight sees it and returns
/// without touching the ring the caller is about to read.
pub(crate) fn stop() {
    ACTIVE.store(false, Ordering::SeqCst);
    let zero = crate::os::exec_posix::Timeval {
        Sec: 0,
        Usec: 0,
    };
    let it = crate::syscall::Itimerval {
        it_interval: zero,
        it_value: zero,
    };
    let _ = crate::syscall::Setitimer(
        crate::syscall::ITIMER_PROF,
        &it as *const _,
        core::ptr::null_mut(),
    );
}

// go: none — goish-only: see the module header.
/// How many samples were taken, including any the ring dropped.
pub(crate) fn taken() -> usize {
    return WRITTEN.load(Ordering::Relaxed);
}

// go: none — goish-only: see the module header.
/// The programmed period in nanoseconds, for the profile's `period`.
pub(crate) fn period_ns() -> u64 {
    return PERIOD_NS.load(Ordering::Relaxed);
}

// go: none — goish-only: see the module header.
/// Visit each recorded stack. Only valid after [`stop`].
pub(crate) fn for_each<F: FnMut(&[u64])>(mut f: F) {
    let total = WRITTEN.load(Ordering::Relaxed);
    let n = if total < RING { total } else { RING };
    for i in 0..n {
        let s = unsafe { &*(&raw const RING_BUF[i]) };
        if s.depth > 0 {
            f(&s.pcs[..s.depth]);
        }
    }
}
