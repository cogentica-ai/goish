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
use core::sync::atomic::{AtomicBool, AtomicUsize};

use super::gobuf::Gobuf;
use super::stack::Stack;
use crate::runtime::spin::SpinLock;
use crate::syscall;

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
    /// `AtomicBool` pointers. **Pointer to a stack-resident array
    /// owned by the parking goroutine's `select!` invocation**, in
    /// lock-acquire order, populated when the goroutine parks on a
    /// select with no default. The select macro stashes the
    /// `&__sel_atoms[0]` of its local array in pass-2 right before
    /// `gopark`; the commit fn (`runtime::sched::selparkcommit`)
    /// walks `[select_wait..select_wait+select_wait_len]` and
    /// releases each lock under the park transition. Safe because
    /// the parker's stack frame stays live throughout the park.
    ///
    /// **Memory note**: storing a pointer (8 B) instead of an inline
    /// `[*const AtomicBool; 32]` (256 B) saves 248 B per G — half
    /// the struct. Most goroutines never `select!` and never
    /// populate this; the savings let mcentral fit ~50% more Gs.
    /// Mirrors Go's `gp.waiting` (runtime/select.go:84) but stored
    /// as a flat-slice pointer rather than an intrusive sudog
    /// linked list (sudogs in goish are typed per case).
    pub select_wait: *const *const AtomicBool,
    pub select_wait_len: u8,
    /// Asynchronous-preempt request flag. Sysmon's
    /// `check_force_preempt` (M18b-β) sets this on Gs that have
    /// been running for too long; the SIGURG handler clears it on
    /// successful injection, and `raw_unlock`'s cooperative path
    /// (M18b-γ) clears it when calling `Gosched` post-unlock.
    /// Mirrors Go's `g.preempt` (runtime/runtime2.go).
    pub preempt: AtomicBool,
    /// **Sema waiter intrusive link** (task #110). When this G is
    /// parked in `Sema::acquire`, this points at the next G in the
    /// FIFO waiter chain (or null if tail). Lets `Sema` keep its
    /// queue without a heap-allocated `VecDeque`, fixing a
    /// 24-frame-deep alloc-path stack overflow on 2 KiB stacks
    /// (commit f2e334a's followup).
    ///
    /// **Concurrency**: only mutated under the owning Sema's
    /// `SpinLock`. A G is in at most one Sema queue at any time
    /// (a parked G can only be parked on one thing), so a single
    /// link suffices. Plain `*mut G` — G already
    /// `unsafe impl Send`s, and access is serialized by the Sema
    /// lock.
    pub sema_next: *mut G,
    /// M28-α: bottom of the goroutine's currently-active stack region.
    /// Equals `stack.lo()` until `runtime::sched::maybe_grow` pivots
    /// onto a fresh region; reset on grow exit. Used by `maybe_grow`
    /// to compute remaining stack against the right bounds.
    pub active_stack_lo: AtomicUsize,
    /// Top (highest address) of the active stack region. Mirrors
    /// `active_stack_lo`. Currently informational; reserved for
    /// debugger inspection and future bounds checks.
    pub active_stack_hi: AtomicUsize,
    /// M28-β: growth-region chain. Each `maybe_grow` pivot would push
    /// `(base, size)` here so the region outlives the closure that
    /// allocated it (currently unused — M28-β is reverted; see the
    /// comment in `runtime::sched::grow.rs::grow_and_call`). Stored
    /// as a `*mut GrowChain` instead of inline `SpinLock<Vec<…>>` to
    /// keep `sizeof(G)` small for 1M-goroutine workloads — when
    /// M28-β re-enables, the first push allocates the chain.
    /// `null` means "no chain yet"; `Drop for G` frees the chain
    /// data and Munmap's each entry.
    pub growth_chain: core::sync::atomic::AtomicPtr<super::grow::GrowChain>,
    /// Panic recovery point. Initialized by `g_entry` before invoking
    /// the user closure: pc=`on_g_panic_aborted`, sp=top-of-stack.
    /// Cleared (sp=0) when the user closure returns normally.
    ///
    /// On panic, the `#[panic_handler]` checks `panic_recover.rsp != 0`
    /// and `gogo`s here to abandon the panicked frames and re-enter the
    /// G at a clean stack via `on_g_panic_aborted`, which runs cleanups
    /// and chains to `goexit`. Without this, a panic would `Exit(2)`
    /// and kill the whole process.
    ///
    /// Per-goroutine isolation only — Drops in the panicked frames are
    /// SKIPPED (we're in panic=abort mode; a real unwind requires
    /// nightly + -Zbuild-std). Resource cleanups must register with
    /// `cleanups` to release on panic.
    pub panic_recover: super::gobuf::Gobuf,
    /// Head of the per-G cleanup list. Resources registered here have
    /// their callbacks run by `on_g_panic_aborted` (or by the
    /// `#[panic_handler]` immediately before `gogo`) so they're
    /// released even though Drops are skipped on panic-abort.
    /// Each `Cleanup` is a stack-allocated node in the resource owner's
    /// frame; on normal Drop the owner unlinks itself.
    pub cleanups: core::sync::atomic::AtomicPtr<super::cleanup::Cleanup>,
    /// True while this G is inside the panic handler's cleanup walk.
    /// Set by `#[panic_handler]` before invoking `cleanup::run_all`,
    /// cleared by `on_g_panic_aborted` before `goexit`. Read by the
    /// `recover!()` macro so a `defer!{}` body can distinguish "scope
    /// exited normally" from "scope unwound via panic".
    pub panicking: AtomicBool,
    /// The panic value, captured by `#[panic_handler]` from
    /// `PanicInfo::message()`. Read & cleared by `recover!()` (Go's
    /// recover semantics — once retrieved, subsequent recover()s
    /// in the same panic chain see nil).
    ///
    /// Stored as `error` rather than the original payload type
    /// because Rust's `panic!()` macro doesn't expose typed payloads
    /// in no_std (we only get a renderable `&Arguments`). Ports that
    /// want typed-panic recovery should still use `errors::As` after
    /// recover; the underlying payload is the rendered message.
    pub panic_value: SpinLock<Option<crate::error>>,
}

impl G {
    /// Allocate a `G` for the bare `go!()` form: a
    /// `BARE_STACK_RESERVE` (1 MiB) lazily-committed virtual
    /// reservation with a bottom guard page (M29). The kernel commits
    /// physical pages as the goroutine actually touches them, so
    /// call depth needs no up-front sizing and a shallow goroutine
    /// costs ~one page of physical memory. Status starts as `Idle`;
    /// the scheduler transitions to `Running` on first dispatch.
    pub fn new(entry: Box<dyn FnOnce()>) -> Self {
        Self::with_stack(Stack::new_reserved(), entry)
    }

    /// Allocate a `G` with a stack of the requested size (M26).
    /// `stack_size` is rounded up to the nearest page by `Stack::new_sized`.
    /// Used by `go!(stack(N), closure)` when the caller wants an
    /// exact size: sub-page pool carve for ≤ 32 KiB (1M-goroutine
    /// density), direct guarded mmap above that.
    pub fn new_with_stack(stack_size: usize, entry: Box<dyn FnOnce()>) -> Self {
        Self::with_stack(Stack::new_sized(stack_size), entry)
    }

    fn with_stack(stack: Stack, entry: Box<dyn FnOnce()>) -> Self {
        let lo = stack.base();
        let hi = stack.top();
        G {
            gobuf: Gobuf::new(),
            stack,
            status: GStatus::Idle,
            entry: Some(entry),
            select_wait: core::ptr::null(),
            select_wait_len: 0,
            preempt: AtomicBool::new(false),
            sema_next: core::ptr::null_mut(),
            active_stack_lo: AtomicUsize::new(lo),
            active_stack_hi: AtomicUsize::new(hi),
            growth_chain: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            panic_recover: super::gobuf::Gobuf::new(),
            cleanups: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            panicking: AtomicBool::new(false),
            panic_value: SpinLock::new(None),
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
            select_wait: core::ptr::null(),
            select_wait_len: 0,
            preempt: AtomicBool::new(false),
            sema_next: core::ptr::null_mut(),
            active_stack_lo: AtomicUsize::new(stack_base as usize),
            active_stack_hi: AtomicUsize::new(stack_base as usize + stack_size),
            growth_chain: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            panic_recover: super::gobuf::Gobuf::new(),
            cleanups: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            panicking: AtomicBool::new(false),
            panic_value: SpinLock::new(None),
        }
    }
}

impl Drop for G {
    /// Free any M28-β growth regions still attached to this G.
    /// Runs when the G is dropped after `goexit` (scheduler frees
    /// dead Gs). The growth regions outlived the closures that
    /// allocated them — that's the whole point of pinning to the G.
    ///
    /// Lazy-alloc shape: `growth_chain` is `null` for goroutines
    /// that never grew (M28-β-style pinning re-enable will allocate
    /// on first push). Drop is a no-op in the null case — saves
    /// the 32 B inline `SpinLock<Vec>` per non-grown G.
    fn drop(&mut self) {
        let chain_ptr = self.growth_chain.swap(
            core::ptr::null_mut(),
            core::sync::atomic::Ordering::AcqRel,
        );
        if !chain_ptr.is_null() {
            unsafe {
                let chain = alloc::boxed::Box::from_raw(chain_ptr);
                for (base, size) in chain.regions.iter() {
                    let _ = syscall::Munmap(*base, *size);
                }
                drop(chain);
            }
        }
    }
}


// `Box<dyn FnOnce()>` is `Send` only when the closure is `Send`. For
// M16b we don't move Gs across threads, so the marker isn't needed
// yet; M17a will require `+ Send` on user closures.
unsafe impl Send for G {}
