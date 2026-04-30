// runtime::sched — goroutine scheduler primitives.
//
// Phase M16a establishes the lowest-level building block: a stackful
// coroutine context-switch primitive. Higher layers (M16b's run
// queue, M16c's gopark/goready, M16d-f's channels, M16g's sync) all
// sit on this.
//
// The shape of the primitive is borrowed directly from Go's
// `runtime/asm_amd64.s` `gogo` / `mcall` family, but simplified
// because we don't carry the full G/M/P metadata yet:
//
//   - **`Gobuf`** — a saved register set: rsp, rbp, and the SysV
//     callee-saved registers (rbx, r12, r13, r14, r15). The PC is
//     stored implicitly at `[rsp]` (the return address pushed by the
//     caller's CALL instruction or set up by `make_context`).
//
//   - **`swap_context(from, to)`** — saves the current callee-saved
//     register set into `*from` and loads `*to` into the registers,
//     then `RET`s. Because PC lives at `[rsp]`, the RET pops the
//     saved PC from `*to`'s stack and jumps there. This implements a
//     symmetric two-context exchange in 14 mov instructions.
//
//   - **`make_context(stack_top, entry)`** — sets up a fresh stack
//     so that the first `swap_context` *to* this gobuf transfers
//     control to `entry`. Lays the entry pointer at the top of the
//     new stack so the implicit RET picks it up.
//
//   - **`Stack`** — a mmap-backed page-aligned region used as a
//     coroutine's stack. Allocated independently from the main
//     mheap so coroutine creation never contends with user
//     allocations.
//
// What's *not* here: the G struct, run queue, scheduler loop, or any
// concept of "current goroutine". M16b adds those. This module is
// internal — `pub` only so the smoke example can exercise it
// directly. Once the public scheduler API lands in M16b, the
// internals here become `pub(crate)`.
//
// Rust safety scope: every public function in this module is
// `unsafe`. Context-switching fundamentally violates Rust's stack
// invariants — the function returns to a different stack than it
// was called on. The unsafety is contained to this module; M16b's
// public API will wrap it behind `go!()` and a scheduler that
// preserves Rust invariants from the outside.

#![allow(dead_code)]

mod g;
mod gobuf;
pub mod grow;
mod m;
mod p;
mod scheduler;
mod stack;
pub mod stackpool;

pub use g::{GStatus, SELECT_WAIT_MAX, G};
pub use gobuf::{gogo, make_context, make_context_gogo, swap_context, Gobuf};
// `mcall_asm` is `pub(crate)`; expose it through the parent for the
// SIGURG handler's PC-range filter (`is_in_mcall_asm`).
pub(crate) use gobuf::mcall_asm;
pub use m::{
    acquirem, current_g0_gobuf, current_m, current_m_locks, current_m_storage, is_tls_ready,
    releasem, setup_main_g0, setup_main_tls, MStorage, ParkCommit, M, MAIN_M,
};
pub use p::{
    acquirep, bootstrap_ps, current_p, for_each_p, num_ps, p_at, releasep, LOCAL_RUNQ_SIZE,
    MAX_PS, P, P_DEAD, P_IDLE, P_RUNNING, P_SYSCALL, STEAL_HITS, STEAL_PASSES,
};
pub use scheduler::{
    block_forever_commit, bootstrap_workers, chan_park_commit, current_g, for_each_m, gopark,
    goready, live_g_count, m_schedule_loop, newproc, newproc_with_stack, num_cpus,
    register_m_storage, registered_m_count, runq_len, schedule, selparkcommit, Gosched,
    DISPATCH_STAMP_COUNT,
};
pub use grow::{
    grow_bytes_live, grow_calls, grow_hits, grow_live, grow_peak_live, maybe_grow,
    DEFAULT_GROW_BARE_CAP, DEFAULT_GROW_RED_ZONE,
};
pub use stack::Stack;
