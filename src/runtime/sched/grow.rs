// runtime::sched::grow — on-demand stack growth via stack pivoting.
//
// Goish goroutines run on a 2 KiB sub-page carve from `stackpool`,
// which is fine for shallow code but will overflow for deep recursion
// or large local buffers. This module ports the technique from the
// Rust ecosystem's `psm`/`stacker` crates: when about to recurse,
// `maybe_grow(red_zone, size, f)` checks remaining stack and, if low,
// allocates a fresh region and PIVOTs RSP onto it for the duration of
// `f`. When `f` returns, RSP pivots back. The original G stack is
// untouched.
//
// Crucially this is NOT Go's `morestack` — no frames are copied, no
// stack is "grown" in place. It's "borrow elbow room and put it back".
//
// References:
// - psm/src/arch/x86_64.s:68-85 (rust_psm_on_stack)
// - psm/src/lib.rs:181-207 (on_stack closure marshalling)
// - stacker/src/lib.rs:148-168 (_grow)

use core::arch::naked_asm;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::syscall;

// ─── monitoring counters ─────────────────────────────────────────────
//
// Observability for "when did a stack grow, when did it return". All
// counters use Relaxed ordering: they are not used for any safety
// invariant, only for telemetry / smoke-test assertions.

/// Total `maybe_grow` calls (cheap fast-path AND grew). Monotonic.
static GROW_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Calls that actually triggered a grow (took the slow path with a
/// fresh mmap'd region). Monotonic.
static GROW_HITS: AtomicUsize = AtomicUsize::new(0);

/// Number of goroutines currently executing inside a grown region.
/// Increments on grow entry, decrements on grow return.
static GROW_LIVE: AtomicUsize = AtomicUsize::new(0);

/// High-water mark of `GROW_LIVE`.
static GROW_PEAK_LIVE: AtomicUsize = AtomicUsize::new(0);

/// Bytes currently pinned across all live grown regions.
static GROW_BYTES_LIVE: AtomicUsize = AtomicUsize::new(0);

/// Total `maybe_grow` calls (any path). Useful for hit-rate calc.
pub fn grow_calls() -> usize {
    GROW_CALLS.load(Ordering::Relaxed)
}

/// Calls that actually allocated and pivoted (slow path).
pub fn grow_hits() -> usize {
    GROW_HITS.load(Ordering::Relaxed)
}

/// Goroutines currently executing inside a grown region.
pub fn grow_live() -> usize {
    GROW_LIVE.load(Ordering::Relaxed)
}

/// High-water mark of `grow_live()`.
pub fn grow_peak_live() -> usize {
    GROW_PEAK_LIVE.load(Ordering::Relaxed)
}

/// Bytes currently pinned across all live grown regions.
pub fn grow_bytes_live() -> usize {
    GROW_BYTES_LIVE.load(Ordering::Relaxed)
}

// ─── go!() macro defaults (M28-γ) ────────────────────────────────────

/// Headroom triggering a grow: when current SP is within
/// DEFAULT_GROW_RED_ZONE bytes of the stack base, `maybe_grow` pivots.
/// 1 KiB is enough for several SysV frames of normal Rust code plus
/// a panic format buffer.
pub const DEFAULT_GROW_RED_ZONE: usize = 1024;

/// Cap used by bare `go!(|| body)`. The implicit form starts on a
/// 2 KiB carve; if it ever grows, it pivots onto this much.
/// Tuned to fit comfortably for handlers, parsers, codegen passes.
pub const DEFAULT_GROW_BARE_CAP: usize = 64 * 1024;

// ─── leaf asm: read RSP ──────────────────────────────────────────────

/// Returns the current value of RSP at the call site, accounting for
/// the 8 bytes the CALL instruction pushed. Mirrors `psm::stack_pointer`.
#[unsafe(naked)]
extern "C" fn current_sp() -> usize {
    naked_asm!(
        "lea rax, [rsp + 8]", // skip our own return address
        "ret",
    )
}

// ─── pivot trampoline (psm/x86_64.s:68-85) ───────────────────────────

/// Pivot RSP onto `new_sp`, call `callback(data, ret_ptr)`, pivot back.
///
/// SysV ABI inputs:
///   rdi = data        — pointer to closure storage
///   rsi = ret_ptr     — pointer to MaybeUninit<R> for the return value
///   rdx = callback    — extern "sysv64" fn(*mut u8, *mut u8)
///   rcx = new_sp      — top of the new stack region (must be 16-aligned)
///
/// Saves old RBP/RSP via the standard prologue, pivots RSP to `rcx`,
/// runs `callback` (which reads the closure from `data` and writes the
/// result through `ret_ptr`), then restores via RBP. A normal `ret`
/// returns control on the original stack.
#[unsafe(naked)]
unsafe extern "C" fn goish_on_stack(
    _data: *mut u8,
    _ret_ptr: *mut u8,
    _callback: extern "C" fn(*mut u8, *mut u8),
    _new_sp: *mut u8,
) {
    naked_asm!(
        "push rbp",
        "mov  rbp, rsp",
        "mov  rsp, rcx", // PIVOT to new stack
        "call rdx",      // rdi/rsi already correct
        "mov  rsp, rbp", // PIVOT back
        "pop  rbp",
        "ret",
    )
}

// ─── closure marshalling ─────────────────────────────────────────────

/// Trampoline that runs on the new stack. Reads the user's closure
/// out of `data`, executes it, writes the result through `ret_ptr`.
extern "C" fn run_closure<F, R>(data: *mut u8, ret_ptr: *mut u8)
where
    F: FnOnce() -> R,
{
    let closure_slot = data as *mut MaybeUninit<F>;
    let return_slot = ret_ptr as *mut MaybeUninit<R>;
    // SAFETY: caller (maybe_grow) wrote a valid F into closure_slot
    // before calling goish_on_stack, and provided a fresh
    // MaybeUninit<R> for the result.
    unsafe {
        let f: F = (*closure_slot).as_mut_ptr().read();
        let r: R = f();
        (*return_slot).write(r);
    }
}

// ─── public API ──────────────────────────────────────────────────────

/// Run `f` either in place (if at least `red_zone` bytes are still
/// available on the current stack) or on a freshly-allocated region
/// of `stack_size` bytes.
///
/// `red_zone` is the minimum free space required to skip growth. A
/// generous default is 8–16 KiB — enough headroom for several frames
/// of normal Rust code plus any `format!` / panic machinery.
///
/// `stack_size` is the size of the growth region when growth happens.
/// Rounded up to a multiple of the page size (4096). Suggest 32–64 KiB
/// for parser-style recursion.
///
/// Returns whatever `f` returns.
///
/// **Recommended use** (M28-α/γ shipping shape): pure-CPU work
/// inside `f`. Recursive parsers, AST visitors, codegen passes,
/// number crunching with deep recursion — all fine. The growth
/// region is freed when `f` returns.
///
/// **Limitation**: do not call `Gosched` / channel send/recv /
/// `gopark` inside `f` from a goroutine that may be migrated to a
/// different M before the closure returns. The growth region is
/// freed at this scope's end, so a future resume on a stale gobuf
/// SP would land in unmapped memory. There's a known scheduler
/// residual interaction (see
/// `project_residual_4pct_root_cause_found.md`) that makes this
/// path racey at present; the fix is deferred. If you need to park
/// from inside deep recursion, prefer
/// `go!(stack(N), ||)` with N large enough to avoid `maybe_grow`.
pub fn maybe_grow<F, R>(red_zone: usize, stack_size: usize, f: F) -> R
where
    F: FnOnce() -> R,
{
    GROW_CALLS.fetch_add(1, Ordering::Relaxed);

    // Fast path: do we have enough remaining stack?
    let sp = current_sp();
    let lo = current_active_stack_lo();
    if lo == 0 || sp.saturating_sub(lo) >= red_zone {
        // Either we don't know our bounds (lo==0, e.g., main thread
        // before scheduler init) or we have headroom. Run in place.
        return f();
    }

    grow_and_call(stack_size, f)
}

/// Slow path: allocate a fresh stack region and pivot onto it.
fn grow_and_call<F, R>(stack_size: usize, f: F) -> R
where
    F: FnOnce() -> R,
{
    const PAGE: usize = 4096;
    let size = (stack_size + PAGE - 1) & !(PAGE - 1);
    let size = size.max(2 * PAGE);

    // Allocate a fresh region. Direct mmap for M28-α; the stackpool
    // will grow a "growth tier" in M28-β.
    let base = syscall::Mmap(
        core::ptr::null_mut(),
        size,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
        -1,
        0,
    );
    if (base as isize) < 0 {
        panic!("maybe_grow: mmap failed");
    }
    // RSP descends, so the entry SP is at the top of the region. The
    // SysV ABI requires RSP to be 16-byte aligned at the CALL site —
    // page-aligned ⇒ 16-aligned ⇒ subtract 8 to mirror what a CALL
    // would have pushed (`goish_on_stack`'s `push rbp` then re-aligns
    // to 16 before the inner `call rdx`).
    let new_sp = (base as usize + size) as *mut u8;

    // Update bookkeeping: counters + active-stack-bounds for any
    // nested `maybe_grow` calls inside `f`.
    GROW_HITS.fetch_add(1, Ordering::Relaxed);
    let live = GROW_LIVE.fetch_add(1, Ordering::Relaxed) + 1;
    let mut peak = GROW_PEAK_LIVE.load(Ordering::Relaxed);
    while live > peak {
        match GROW_PEAK_LIVE.compare_exchange_weak(
            peak,
            live,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(p) => peak = p,
        }
    }
    GROW_BYTES_LIVE.fetch_add(size, Ordering::Relaxed);
    let saved_lo = swap_active_stack_lo(base as usize);
    let saved_hi = swap_active_stack_hi(base as usize + size);

    // Stack-resident closure slot — gives us a stable pointer to pass
    // through the asm pivot without paying the Box::new allocator path
    // on the home stack. The home-stack frame for `grow_and_call`
    // remains live through the entire pivot/execution/pivot-back
    // cycle, so `&mut closure_slot` stays valid for the asm-side
    // `run_closure` to read F out of. After F is consumed, the
    // MaybeUninit is logically empty; its scope-end is a no-op drop.
    //
    // Why this matters: in debug builds the Box::new path adds ~3 fn
    // frames (Box::new → alloc::alloc::alloc → goish heap allocator),
    // each ~100 B, which pushed the 2 KiB home stack into overflow
    // when a goroutine entered maybe_grow at entry — see
    // `examples/grow_park_smoke.rs` for the regression evidence.
    let mut closure_slot: MaybeUninit<F> = MaybeUninit::new(f);
    let mut return_slot: MaybeUninit<R> = MaybeUninit::uninit();

    unsafe {
        goish_on_stack(
            &mut closure_slot as *mut _ as *mut u8,
            &mut return_slot as *mut _ as *mut u8,
            run_closure::<F, R>,
            new_sp,
        );
    }

    // Restore bookkeeping and free the growth region. M28-α: the
    // mapping is tied to this scope. Safe for closures that finish
    // synchronously (deep CPU recursion, parsers, codegen). NOT
    // safe if the closure parks via Gosched / channel ops on a
    // path where another M might wake it before we return — that
    // is documented in `maybe_grow`'s public doc.
    //
    // **Re-enablement of M28-β is now in scope** (the cooperative-
    // preempt residual that previously blocked it has been resolved
    // by the deferred-runqput fix in 956153a, the selparkcommit
    // clear removal in 84edfb5, and the async-preempt EFLAGS
    // preservation in 9028a07). To make grown regions outlive their
    // closures, push `(base, size)` onto `G.growth_chain` here and
    // skip the `Munmap` below — the `Drop for G` impl in `g.rs:254`
    // already drains the chain at goexit. Validation gate before
    // flipping: `make e2e LOOPS=100 FILTER='^chan_'` clean plus
    // a heavy-recursion-with-park smoke. See the 3-tier design
    // memory for context.
    swap_active_stack_lo(saved_lo);
    swap_active_stack_hi(saved_hi);
    GROW_LIVE.fetch_sub(1, Ordering::Relaxed);
    GROW_BYTES_LIVE.fetch_sub(size, Ordering::Relaxed);
    let _ = syscall::Munmap(base, size);

    // SAFETY: run_closure wrote the result through `ret_ptr` before
    // returning normally. (Panic propagation is a separate concern —
    // we abort on panic in this build, so unwinding can't unwind
    // through the asm.)
    unsafe { return_slot.assume_init() }
}

// ─── active-stack tracking (M28-α minimal) ───────────────────────────
//
// In M28-α we track the "active stack region" via a per-G atomic pair.
// Default is the G's home stack (set when the G is constructed).
// `maybe_grow` pushes/pops via these swap fns. M28-β replaces this
// scalar with a chain so multiple nested grows work cleanly.
//
// For now we read/write fields on the current G if one is bound, or
// fall through to "unknown" (lo == 0 → fast path always taken). The
// main thread before scheduler init has no G — that's fine, deep
// recursion in main is the user's problem.

fn current_active_stack_lo() -> usize {
    match crate::runtime::sched::scheduler::current_g() {
        Some(g) => unsafe {
            (*g.as_ptr()).active_stack_lo.load(Ordering::Acquire)
        },
        None => 0,
    }
}

fn swap_active_stack_lo(new: usize) -> usize {
    match crate::runtime::sched::scheduler::current_g() {
        Some(g) => unsafe {
            (*g.as_ptr())
                .active_stack_lo
                .swap(new, Ordering::AcqRel)
        },
        None => 0,
    }
}

fn swap_active_stack_hi(new: usize) -> usize {
    match crate::runtime::sched::scheduler::current_g() {
        Some(g) => unsafe {
            (*g.as_ptr())
                .active_stack_hi
                .swap(new, Ordering::AcqRel)
        },
        None => 0,
    }
}

// Silence unused-import lint when this module's helpers compose with
// each other but the `NonNull` import isn't otherwise needed.
const _: Option<NonNull<()>> = None;
