// runtime::sched::g — the goroutine struct.
//
// Slim port of Go's `runtime.g` (runtime/runtime2.go:394). We carry
// only what's load-bearing for M16b's cooperative scheduler:
//
//   - **`gobuf`**: saved register set; the asm context switch reads
//     and writes through this.
//   - **`stack`**: per-goroutine mmap'd stack region.
//   - **`status`**: which scheduler state the G is in. The full Go
//     state machine has 9 states (Gidle, Grunnable, Grunning,
//     Gsyscall, Gwaiting, Gmoribund_unused, Gdead, Genqueue_unused,
//     Gcopystack); single-threaded cooperative goish needs only
//     four.
//   - **`entry`**: the closure that runs when the G first executes.
//     Stored as `Box<dyn FnOnce()>` so we can call it exactly once
//     and drop the storage afterwards.

use alloc::boxed::Box;
use core::sync::atomic::AtomicBool;

use super::gobuf::Gobuf;
use super::stack::Stack;

/// Maximum number of distinct chans a single `select!` can hold locks
/// on. Mirrors the cap on case count from `select_macro.rs` (32).
/// Locked-chan list is deduped at register time so it can be shorter
/// than the case count when several cases share a chan.
pub const SELECT_WAIT_MAX: usize = 32;

/// Lifecycle states a `G` can be in.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GStatus {
    /// Just allocated; entry closure not yet called. Becomes
    /// `Running` on first `swap_context` into the G.
    Idle,
    /// On the run queue, waiting for the scheduler to pick it.
    Runnable,
    /// Currently executing on an M.
    Running,
    /// Suspended via `gopark`. Will return to `Runnable` only when
    /// something calls `goready` on this G.
    Waiting,
    /// Finished — the entry closure returned. Scheduler will drop
    /// the G and free its stack on next dispatch.
    Dead,
}

/// `G` — one goroutine.
pub struct G {
    pub gobuf: Gobuf,
    pub stack: Stack,
    pub status: GStatus,
    /// Entry closure. `Some(box)` until the G first runs, then
    /// `None`. Allows us to drop the closure storage as soon as
    /// it begins executing rather than holding it for the G's
    /// lifetime.
    pub entry: Option<Box<dyn FnOnce()>>,
    /// `select!` (M16f-β) per-G wait-list of distinct chan-lock
    /// `AtomicBool` pointers, in lock-acquire order, populated when
    /// the goroutine parks on a select with no default. The select-
    /// macro fills these in pass-2 right before `gopark`; the
    /// commit fn (`runtime::sched::selparkcommit`) walks this slice
    /// and releases each lock under the park transition. Mirrors
    /// Go's `gp.waiting` (runtime/select.go:84) but stored as a
    /// flat slice of lock atoms instead of an intrusive sudog
    /// linked list (sudogs in goish are typed per case and can't
    /// share a heterogeneous link list cleanly).
    pub select_wait: [*const AtomicBool; SELECT_WAIT_MAX],
    pub select_wait_len: u8,
    /// Asynchronous-preempt request flag. Sysmon's
    /// `check_force_preempt` (M18b-β) sets this on Gs that have
    /// been running for too long; the SIGURG handler clears it on
    /// successful injection, and `raw_unlock`'s cooperative path
    /// (M18b-γ) clears it when calling `Gosched` post-unlock.
    /// Mirrors Go's `g.preempt` (runtime/runtime2.go).
    pub preempt: AtomicBool,
}

impl G {
    /// Allocate a `G` with a fresh stack and the given entry closure.
    /// Status starts as `Idle`; the scheduler will transition to
    /// `Running` on first dispatch.
    pub fn new(entry: Box<dyn FnOnce()>) -> Self {
        G {
            gobuf: Gobuf::new(),
            stack: Stack::new(),
            status: GStatus::Idle,
            entry: Some(entry),
            select_wait: [core::ptr::null(); SELECT_WAIT_MAX],
            select_wait_len: 0,
            preempt: AtomicBool::new(false),
        }
    }

    /// M17b-ε.α: construct an M's `g0` — the goroutine whose stack is
    /// the M's OS thread stack. `g0` is permanent: it never parks,
    /// never exits, never holds a user closure. Its sole purpose is
    /// to give the scheduler a stack-distinct G so `getg()` can
    /// distinguish "running user code" (`m.curg`) from "running
    /// scheduler code" (`m.g0`).
    ///
    /// The caller passes the OS-thread-stack bounds directly:
    ///   - Worker M: bounds of the `Mmap(_, WORKER_M_STACK)` region
    ///     allocated in `spawn_worker_m` (the same region passed as
    ///     `child_stack` to `clone(2)`).
    ///   - Main M: bounds parsed from `/proc/self/maps`'s `[stack]`
    ///     entry containing the current rsp.
    ///
    /// `Stack::adopted` is non-owning — `g0`'s Drop will not munmap
    /// the OS thread stack (the kernel reclaims it at thread exit).
    ///
    /// Mirrors Go's `mp.g0 = malg(16384 * sys.StackGuardMultiplier);
    /// mp.g0.stack.{lo, hi} = …` pattern from `proc.go:2346` /
    /// `os_linux.go:newosproc`.
    pub fn new_g0(stack_base: *mut u8, stack_size: usize) -> Self {
        // M17b-ε.β: stamp g0.gobuf.sp = top-of-stack so the first
        // `mcall(_)` on this M has a valid g0 stack pointer to switch
        // to. Mirrors Go's `mstart1` (proc.go:1911):
        //   gp.sched.sp = getcallersp()
        // We use the stack top (highest address) rather than capturing
        // the current rsp because:
        //   1. We may not yet be running on this stack (worker M's g0
        //      is allocated by the parent thread before clone(2)).
        //   2. Every mcall switches rsp to this exact value, so the
        //      yield fn body always starts at a fresh frame at the
        //      top — bounded stack use, no growth across mcalls.
        //
        // The 16-byte alignment is enforced because SysV expects
        // `rsp % 16 == 0` immediately before a CALL. After the asm
        // `mov rsp, [rsi+0x00]` and the subsequent `call rdx` in
        // mcall_asm, the resulting `rsp % 16 == 8` matches the SysV
        // convention at fn entry.
        let top = ((stack_base as usize) + stack_size) & !0xf;
        let mut gobuf = Gobuf::new();
        gobuf.rsp = top as u64;
        G {
            gobuf,
            stack: Stack::adopted(stack_base, stack_size),
            // g0 is always Running: it represents the M's scheduler
            // context. Status changes never apply to g0; only `curg`
            // moves through Idle/Runnable/Running/Waiting/Dead.
            status: GStatus::Running,
            entry: None,
            select_wait: [core::ptr::null(); SELECT_WAIT_MAX],
            select_wait_len: 0,
            preempt: AtomicBool::new(false),
        }
    }
}


// `Box<dyn FnOnce()>` is `Send` only when the closure is `Send`. For
// M16b we don't move Gs across threads, so the marker isn't needed
// yet; M17a will require `+ Send` on user closures.
unsafe impl Send for G {}
