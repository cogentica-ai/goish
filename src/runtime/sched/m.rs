// runtime::sched::m — per-M (OS thread) state.
//
// Mirrors Go's `runtime.m` (runtime/runtime2.go:514+) minus the
// pieces we don't carry yet. Each OS thread owns one `M`; the
// scheduler routes per-thread state — currently-running `G`,
// scheduler-side gobuf for context switches, M id and Linux tid —
// through it.
//
// ─── β1 (this file) ──────────────────────────────────────────────
//
// Only the main thread exists today. `MAIN_M` holds the single M,
// wrapped in a `SpinLock` for the same reason `SCHED` is locked:
// keeps the borrow checker honest at no extra cost in single-M
// (one uncontended CAS per access). `current_m()` returns the static
// `&MAIN_M` unconditionally.
//
// ─── β2 (next task #69) ──────────────────────────────────────────
//
// `arch_prctl(ARCH_SET_FS, &m.tls_self_ptr)` makes `fs:[0]` read
// back `&m`, so `current_m()` becomes a one-instruction
// `mov %fs:0, _`. Worker Ms (M17a-δ) clone with `CLONE_SETTLS` and
// land on their own M. The `tls_self_ptr` field below is reserved
// for that wiring; β1 leaves it null.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicI32};

use super::g::G;
use super::gobuf::Gobuf;
use crate::runtime::spin::SpinLock;

/// One OS thread's scheduler-visible state.
pub struct M {
    /// Logical M id assigned by the scheduler. Main M is 0; workers
    /// get monotonically-increasing ids when M17a-δ spawns them.
    pub id: u32,
    /// Linux kernel tid (from `gettid(2)`). Set by `mstart` for
    /// workers, by `__goish_rt0` for the main M.
    pub procid: AtomicI32,
    /// Currently-running goroutine on this M, or `None` while the
    /// M is on its scheduler stack between dispatches.
    pub current_g: Option<NonNull<G>>,
    /// Saved register set when this M is suspended (i.e. while a
    /// goroutine is executing on it). `swap_context(&mut sched_buf,
    /// &g.gobuf)` transfers control from the M's scheduler context
    /// into the goroutine; `swap_context(&mut g.gobuf, &sched_buf)`
    /// transfers it back.
    pub sched_buf: Gobuf,
    /// M17c will use this for futex-based idle parking. Currently
    /// unused (β1 doesn't park Ms — schedule() returns when runq
    /// drains).
    pub parked: AtomicBool,
    /// Self-pointer used by β2's TLS wiring: `arch_prctl` will set
    /// `fs` to point at this field, so `mov %fs:0, _` reads back the
    /// M's address. Null in β1 (no TLS yet).
    pub tls_self_ptr: *const M,
}

// Same justification as `Sched`: `M` holds raw pointers (`NonNull<G>`,
// `*const M`) and atomics that aren't auto-`Send`. Single-M today;
// multi-M (M17a-δ) only ever accesses an M from its own thread, so
// no cross-thread borrowing of `&M` happens in practice.
unsafe impl Send for M {}

impl M {
    /// Build an empty M. `id` should be unique across all Ms in the
    /// process; β1 only allocates `MAIN_M` with id=0.
    pub const fn new(id: u32) -> Self {
        M {
            id,
            procid: AtomicI32::new(0),
            current_g: None,
            sched_buf: Gobuf::new(),
            parked: AtomicBool::new(false),
            tls_self_ptr: core::ptr::null(),
        }
    }
}

/// The main thread's M. Always present. β2 will additionally wire up
/// `fs:[0]` to point at this static so `current_m()` can switch from
/// "always &MAIN_M" to a TLS-backed read.
pub static MAIN_M: SpinLock<M> = SpinLock::new(M::new(0));

/// Pointer to the currently-running M.
///
/// β1: returns `&MAIN_M` unconditionally. Single-M only.
/// β2: rewrites to read `fs:[0]` via inline asm — multi-M-correct.
#[inline]
pub fn current_m() -> &'static SpinLock<M> {
    &MAIN_M
}
