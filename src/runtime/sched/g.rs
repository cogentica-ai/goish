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

use super::gobuf::Gobuf;
use super::stack::Stack;

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
        }
    }
}

// `Box<dyn FnOnce()>` is `Send` only when the closure is `Send`. For
// M16b we don't move Gs across threads, so the marker isn't needed
// yet; M17a will require `+ Send` on user closures.
unsafe impl Send for G {}
