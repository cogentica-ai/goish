// runtime::preempt — asynchronous preemption via SIGURG (M18b).
//
// This is the `phase B` cut: the SIGURG handler is installed and
// makes a full safety decision, but DOES NOT modify the user's
// `ucontext` and DOES NOT inject any code. It only bumps diagnostic
// counters where it would have injected.
//
// ─── Pipeline (target shape, from Go runtime/preempt.go +
//     signal_unix.go + signal_amd64.go) ───────────────────────────
//
//   1. Sysmon (or, in tests, a goroutine) sends SIGURG to a target
//      thread via `tgkill(2)` or process-wide via `kill(2)`.
//   2. Kernel saves the full register set into `ucontext_t` and
//      enters `goish_preempt_sigtramp` with `SA_SIGINFO` calling
//      convention: `(int sig, siginfo_t *info, void *ctx)`.
//   3. Handler reads `current_m_locks()` lock-free, peeks at
//      `current_m().data_unchecked()` (safe at L=0 by Theorem 1
//      from the design notes), checks `curg.status == Running`,
//      checks `SP ∈ G.stack` with margin.
//   4. If all checks pass: phase B counts `PREEMPT_DECISIONS`;
//      phase C will modify `ucontext.RIP` and `RSP` so that when
//      the kernel sigreturns, the user G enters the trampoline.
//
// ─── Why a separate handler from os::signal's `goish_sigtramp`? ─
//
// `os::signal::Notify` uses a single-arg handler that bumps a
// counter and pokes sysmon. It is intentionally minimal — async-
// signal-safe with no lock-free reads of M state. The preempt path
// needs three-arg `SA_SIGINFO` so it can inspect (and eventually
// modify) the saved register set in `ucontext`. Keeping the two
// paths separate avoids overloading the established os::signal
// handler shape.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::runtime::sched::{
    current_m, current_m_locks, current_m_storage, GStatus,
};
use crate::syscall;

// ─── ucontext_t layout (Linux x86_64) ──────────────────────────────
//
// Mirrors `/usr/include/x86_64-linux-gnu/sys/ucontext.h` and the
// kernel's `arch/x86/include/uapi/asm/sigcontext.h`. We define only
// the prefix we read; the trailing sigset/fpregs storage is
// represented as opaque padding.
//
// Cross-checked against Go's `runtime/defs_linux_amd64.go`:
//   - `type stackt`  ↔ `StackT` here
//   - `type sigcontext` (inline `gregs[23]` etc.) ↔ `McontextT`
//   - `type ucontext` ↔ `UcontextT`
//
// Field order is load-bearing — the kernel writes specific offsets.

#[repr(C)]
pub struct StackT {
    pub ss_sp: *mut u8,
    pub ss_flags: i32,
    _pad0: i32,
    pub ss_size: usize,
}

/// `mcontext_t` — saved register state pushed by the kernel on
/// signal entry. `gregs` is a 23-element array of `u64`; indices are
/// the `REG_*` constants below.
#[repr(C)]
pub struct McontextT {
    pub gregs: [u64; 23],
    pub fpregs: usize,
    pub _reserved: [u64; 8],
}

/// `ucontext_t` — the second argument to a SA_SIGINFO handler's
/// third parameter (after sig, info). The kernel hands us a pointer
/// to one of these, allocated on the signal stack.
#[repr(C)]
pub struct UcontextT {
    pub uc_flags: u64,
    pub uc_link: *mut UcontextT,
    pub uc_stack: StackT,
    pub uc_mcontext: McontextT,
    // uc_sigmask + fpregs storage follow; we don't read or write
    // either, so they are intentionally absent here. The kernel
    // doesn't care that our struct is shorter — it allocated the
    // full thing and only the offsets we touch matter.
}

// Linux x86_64 register indices in `gregs[]`. Matches
// arch/x86/include/uapi/asm/sigcontext.h enums.
pub const REG_R8: usize = 0;
pub const REG_R9: usize = 1;
pub const REG_R10: usize = 2;
pub const REG_R11: usize = 3;
pub const REG_R12: usize = 4;
pub const REG_R13: usize = 5;
pub const REG_R14: usize = 6;
pub const REG_R15: usize = 7;
pub const REG_RDI: usize = 8;
pub const REG_RSI: usize = 9;
pub const REG_RBP: usize = 10;
pub const REG_RBX: usize = 11;
pub const REG_RDX: usize = 12;
pub const REG_RAX: usize = 13;
pub const REG_RCX: usize = 14;
pub const REG_RSP: usize = 15;
pub const REG_RIP: usize = 16;
pub const REG_EFL: usize = 17;

/// Stack budget below the kernel-saved RSP that the (future) async-
/// preempt trampoline needs: a red-zone-skip subq, a frame for
/// asyncPreempt's prologue (BP + flags + 384-byte save area + 16-byte
/// alignment slack + a 256-byte safety margin) plus the inner
/// `goish_async_preempt2` Rust frame. Cap at 1 KiB to leave plenty of
/// margin on a 64 KiB G stack.
pub const ASYNC_PREEMPT_STACK: usize = 1024;

// ─── Diagnostic counters (read by tests in phase B) ────────────────
//
// All `Relaxed` — the test only needs an eventual snapshot, and the
// signal handler runs on the same thread that produced the writes,
// so happens-before is implicit on x86 anyway. `wake_*` are split
// out so a regression in any predicate is observable independently.

static PREEMPT_INVOCATIONS: AtomicU64 = AtomicU64::new(0);
static PREEMPT_DECISIONS: AtomicU64 = AtomicU64::new(0);
static SKIP_LOCKS: AtomicU64 = AtomicU64::new(0);
static SKIP_NO_CURG: AtomicU64 = AtomicU64::new(0);
static SKIP_NOT_RUNNING: AtomicU64 = AtomicU64::new(0);
static SKIP_SP_RANGE: AtomicU64 = AtomicU64::new(0);

/// Total handler invocations since process start.
pub fn invocations() -> u64 {
    PREEMPT_INVOCATIONS.load(Ordering::Relaxed)
}

/// Times the handler decided injection would be safe (phase B
/// counts; phase C will actually inject).
pub fn decisions() -> u64 {
    PREEMPT_DECISIONS.load(Ordering::Relaxed)
}

/// Per-skip-reason counts. Order: locks, no_curg, not_running,
/// sp_range. Useful for diagnosing flaky tests.
pub fn skip_breakdown() -> (u64, u64, u64, u64) {
    (
        SKIP_LOCKS.load(Ordering::Relaxed),
        SKIP_NO_CURG.load(Ordering::Relaxed),
        SKIP_NOT_RUNNING.load(Ordering::Relaxed),
        SKIP_SP_RANGE.load(Ordering::Relaxed),
    )
}

// ─── Handler ───────────────────────────────────────────────────────
//
// SA_SIGINFO calling convention: the kernel passes
//   (int sig, siginfo_t *info, void *ctx)
// where `ctx` is `ucontext_t *`. The handler runs on whatever stack
// the kernel chose (default: user's current SP minus 128-byte red
// zone minus signal frame); for goroutines on 64 KiB stacks this is
// fine.
//
// **Allowed operations** (all async-signal-safe):
//   - lock-free atomic loads/stores (counters, m.locks)
//   - reading the M's struct via `data_unchecked()` (Theorem 1
//     applies: at L=0 no concurrent write is in flight)
//   - reading G.status, G.stack metadata
//   - kernel syscalls (none yet — phase C may add `tgkill`)
//
// **Forbidden** (would deadlock or violate AS-safety):
//   - SpinLock acquisition (`current_m().lock()`, etc.)
//   - heap allocation
//   - any `gopark` / `swap_context` (we are *not* the trampoline yet)

extern "C" fn goish_preempt_sigtramp(
    _sig: i32,
    _info: *const u8,        // siginfo_t* — opaque, unused in phase B
    ctx: *mut UcontextT,
) {
    PREEMPT_INVOCATIONS.fetch_add(1, Ordering::Relaxed);

    // Predicate 1: m.locks == 0. While > 0, the M is in a non-
    // yielding critical section; injecting would re-enter Rust into
    // a runtime function that may try to take the same lock.
    if current_m_locks() != 0 {
        SKIP_LOCKS.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Predicate 2: M has a current G. If None, we're on g0 doing
    // scheduler work — preemption doesn't apply.
    //
    // Lock-free read: by Theorem 1 (design notes), `m.current_g`'s
    // 8-byte aligned slot is stable while m.locks == 0 because all
    // writers run inside `LockedM`-guarded regions which bump
    // m.locks first.
    let m = unsafe { current_m().data_unchecked() };
    let curg_opt = m.current_g;
    let g_ptr = match curg_opt {
        Some(p) => p,
        None => {
            SKIP_NO_CURG.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Predicate 3: G.status == Running. Filters Gs that have already
    // flipped status in preparation for yielding (Gosched/goexit set
    // Runnable/Dead before swap_context).
    let g_ref = unsafe { g_ptr.as_ref() };
    if g_ref.status != GStatus::Running {
        SKIP_NOT_RUNNING.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Predicate 4: SP is inside G.stack with enough margin for the
    // future trampoline frame. Filters cases where the kernel
    // delivered SIGURG while the M was on its g0/scheduler stack
    // (dispatch_one_g pre-swap window) — there `m.curg` is set but
    // the caller's stack is the worker's mmap'd 64 KiB scheduler
    // stack, not the G's stack.
    let sp = unsafe { (*ctx).uc_mcontext.gregs[REG_RSP] } as usize;
    let stack_lo = g_ref.stack.base();
    let stack_hi = g_ref.stack.top();
    if sp < stack_lo + ASYNC_PREEMPT_STACK || sp >= stack_hi {
        SKIP_SP_RANGE.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // All predicates satisfied. Phase C will inject; phase B just
    // counts.
    PREEMPT_DECISIONS.fetch_add(1, Ordering::Relaxed);

    // `ctx` write deliberately omitted in phase B. Suppress unused-
    // var warning by referencing it.
    let _: &mut UcontextT = unsafe { &mut *ctx };
}

// Silence unused-field warnings without exposing them.
const _: () = {
    let _ = core::mem::size_of::<StackT>();
    let _ = core::mem::size_of::<UcontextT>();
};
const _: UnsafeCell<()> = UnsafeCell::new(());

// ─── Install ───────────────────────────────────────────────────────

/// Install the SIGURG preempt handler. Idempotent. Called from
/// `__goish_rt0` after sysmon has started.
///
/// Uses SA_SIGINFO so the kernel passes `(sig, info, ctx)` and we
/// can reach `ucontext`. SA_RESTORER + the existing
/// `SigreturnTrampoline` complete the kernel's mandated sigreturn
/// path.
pub fn install() {
    let sa = syscall::Sigaction {
        sa_handler: goish_preempt_sigtramp as usize,
        sa_flags: syscall::SA_SIGINFO | syscall::SA_RESTORER | syscall::SA_RESTART,
        sa_restorer: syscall::SigreturnTrampoline as usize,
        sa_mask: 0,
    };
    unsafe {
        let r = syscall::RtSigaction(syscall::SIGURG, &sa as *const _, core::ptr::null_mut());
        if r != 0 {
            const MSG: &[u8] = b"goish: preempt: rt_sigaction(SIGURG) failed\n";
            syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
            syscall::Exit(2);
        }
    }
}
