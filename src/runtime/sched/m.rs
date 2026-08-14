// runtime::sched::m — per-M (OS thread) state.
//
// Mirrors Go's `runtime.m` (runtime/runtime2.go:514+) minus the
// pieces we don't carry yet. Each OS thread owns one `M`; the
// scheduler routes per-thread state — currently-running `G`,
// scheduler-side gobuf for context switches, M id and Linux tid —
// through it.
//
// ─── TLS layout (M17a-β2) ────────────────────────────────────────
//
// Each M is wrapped in an `MStorage`:
//
//     #[repr(C)]
//     struct MStorage {
//         tls_self: UnsafeCell<*const SpinLock<M>>,  // offset 0
//         m: SpinLock<M>,                            // offset 8
//     }
//
// At init, we plant `&storage.m` into `storage.tls_self`. Then
// `arch_prctl(ARCH_SET_FS, &storage.tls_self)` makes the calling
// thread's `fs` segment base equal `&storage.tls_self`, so a
// `mov %fs:0, _` reads back `&storage.m` — the SpinLock guarding
// this thread's M. `current_m()` does exactly that.
//
// For workers, `clone(2)` with `CLONE_SETTLS` and `tls = &storage
// .tls_self` sets the child's fs base atomically with thread
// creation; the child's first `current_m()` already returns its
// own M.
//
// The `#[repr(C)]` attribute on `MStorage` and the tls_self field
// at offset 0 are load-bearing — `mov %fs:0` reads from offset 0.

use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use super::g::G;
use super::p::P;
use crate::runtime::note::Note;
use crate::runtime::spin::SpinLock;
use crate::syscall;

/// Park-commit function pointer. Invoked by the scheduler **after**
/// `swap_context` has saved the parking G's gobuf and the M has
/// dropped the G (Go's `park_m` step at proc.go:4259). Returns
/// `true` to commit the park (G stays in `Waiting` until something
/// calls `goready`); `false` to abort (G is requeued as `Runnable`
/// for the next dispatch on this M).
///
/// Mirrors Go's `func(*g, unsafe.Pointer) bool` in
/// `runtime.gopark`'s second arg (proc.go:420). Goish stashes the
/// `unsafe.Pointer` analog in `M::waitlock` rather than passing it
/// at the call site, so the pointer-typed signature here is just
/// `unsafe fn(NonNull<G>) -> bool`.
pub type ParkCommit = unsafe fn(NonNull<G>) -> bool;

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
    /// Currently-running user goroutine on this M, or `None` while
    /// the M is on its `g0` scheduler stack between dispatches.
    /// Mirrors Go's `m.curg` (runtime/runtime2.go:544).
    pub curg: Option<NonNull<G>>,
    /// Park-commit fn populated by `gopark` and consumed by
    /// `dispatch_one_g` post-swap (see `scheduler::dispatch_one_g`).
    /// `Some(_)` between the gopark call site and the commit
    /// invocation; `None` otherwise. Mirrors Go's `m.waitunlockf`
    /// (runtime/runtime2.go:566).
    pub waitunlockf: Option<ParkCommit>,
    /// Opaque lock pointer published by the parking G for its commit
    /// fn to release. For chan parks: the chan's `lock_atom`. For
    /// select parks: null (selparkcommit walks `g.select_wait`).
    /// Mirrors Go's `m.waitlock` (runtime/runtime2.go:567).
    pub waitlock: *const AtomicBool,
}

unsafe impl Send for M {}

impl M {
    /// Build an empty M. `id` should be unique across all Ms in the
    /// process; the main M uses id=0; M17a-δ assigns 1..N to workers.
    pub const fn new(id: u32) -> Self {
        M {
            id,
            procid: AtomicI32::new(0),
            curg: None,
            waitunlockf: None,
            waitlock: core::ptr::null(),
        }
    }
}

/// Per-thread storage that holds the M, the TLS self-pointer, and
/// the M's park note. `#[repr(C)]` pins `tls_self` to offset 0 so
/// `mov %fs:0, _` reads it back as a `*const SpinLock<M>`.
///
/// `park` is a `Note` — Go's one-shot wait/wake primitive
/// (lock_futex.go). Mirrors `m.park` (runtime2.go). Its address is
/// the futex word the kernel binds wait/wake to.
#[repr(C)]
pub struct MStorage {
    /// Self-pointer to `m`. Read by `current_m()` via `mov %fs:0`.
    /// Written exactly once at init, then immutable for the
    /// lifetime of the storage.
    pub tls_self: UnsafeCell<*const SpinLock<M>>,
    /// The actual M. Locking serializes the (uncontended in
    /// practice — only this M's own thread accesses it) field
    /// reads/writes the borrow checker would otherwise reject.
    pub m: SpinLock<M>,
    /// One-shot park signal. M17c idle-parking flow:
    ///   1. M pushes itself onto the global midle list.
    ///   2. M calls `park.sleep()` — blocks in futex_wait until
    ///      a waker calls `park.wakeup()`.
    ///   3. M calls `park.clear()` to reset for the next cycle.
    pub park: Note,
    /// Non-yielding-section depth counter. Incremented by
    /// `acquirem()` (and auto-bumped by SpinLock acquisition);
    /// decremented by `releasem()`. M18b's SIGURG preempt handler
    /// reads this lock-free and skips injection while > 0. Mirrors
    /// Go's `m.locks` (runtime2.go:546). Per-M and only mutated by
    /// the M's own thread, so accesses are race-free at the hardware
    /// level on x86-64; AtomicU32 is for lint compliance.
    pub locks: AtomicU32,
    /// CLOCK_MONOTONIC nanosecond timestamp when the M last
    /// transitioned `current_g` from None to Some(g). 0 means "no G
    /// is currently running on this M" (between dispatches, or when
    /// parked idle). M18b-β's sysmon scan reads this lock-free to
    /// detect goroutines that have been running too long without
    /// yielding.
    pub start_running_ns: AtomicI64,
    /// Bound P, or null when this M holds no P. Mirrors Go's `m.p`
    /// (runtime/runtime2.go:561). Atomic so other threads (steal
    /// scans, sysmon) can read it lock-free; written exclusively by
    /// the owning M's thread via `acquirep` / `releasep`.
    pub current_p: AtomicPtr<P>,
    /// M17b-ε.α: pointer to this M's `g0` — the goroutine whose stack
    /// is the M's OS thread stack. Scheduler / yield-fn bodies run on
    /// `g0`'s stack rather than the user G's stack. Mirrors Go's
    /// `m.g0` (runtime/runtime2.go:533).
    ///
    /// Null until `setup_main_tls` (main M) or the worker's `mstart`
    /// (worker M) has parsed the OS thread stack bounds and allocated
    /// the `G` object via `Box::leak`. After that, the pointer is
    /// stable for the M's lifetime.
    ///
    /// Read by `getg()` to determine whether the calling code is on
    /// `g0`'s stack (returns `g0`) or on the user G's stack (returns
    /// `m.curg`). Read by `mcall` asm to find the stack to switch to.
    pub g0: AtomicPtr<crate::runtime::sched::g::G>,
}

// MStorage holds a raw pointer in UnsafeCell. We assert thread-
// locality of access (each thread only ever touches its own MStorage
// through TLS) so the inner field doesn't actually need
// synchronization beyond the SpinLock on `m`.
unsafe impl Sync for MStorage {}

impl MStorage {
    /// Const-initialize an MStorage with a null tls_self. Caller
    /// must call `init_tls_self` exactly once before any
    /// `current_m()` read on the corresponding thread.
    pub const fn new(id: u32) -> Self {
        MStorage {
            tls_self: UnsafeCell::new(core::ptr::null()),
            m: SpinLock::new(M::new(id)),
            park: Note::new(),
            locks: AtomicU32::new(0),
            start_running_ns: AtomicI64::new(0),
            current_p: AtomicPtr::new(core::ptr::null_mut()),
            g0: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Plant the self-pointer. Idempotent: writes the address of
    /// `self.m` into `self.tls_self`.
    pub fn init_tls_self(&'static self) {
        unsafe { *self.tls_self.get() = &self.m; }
    }

    /// Address that `arch_prctl(ARCH_SET_FS, _)` should be called
    /// with, or that `clone(2)` should pass as `tls`. This is the
    /// address of the `tls_self` field — `fs:[0]` will read its
    /// stored pointer (= `&self.m`).
    pub fn fs_base(&self) -> usize {
        self.tls_self.get() as usize
    }
}

/// The main thread's M storage. Initialized in `__goish_rt0` via
/// `setup_main_tls()`; subsequent `current_m()` reads are TLS-backed.
pub static MAIN_M: MStorage = MStorage::new(0);

/// Process-wide flag: `true` once the main thread has planted its
/// `fs` base via `setup_main_tls`. Before this point, `current_m()`
/// reads from `fs:0` would dereference an unset segment register;
/// `acquirem`/`releasem` consult this flag and become no-ops while
/// it is `false` so SpinLocks taken during pre-TLS init (e.g.
/// `args::__set`) don't crash.
///
/// Workers see `true` from their first instruction because their
/// `fs` base is planted by `clone(2)` with `CLONE_SETTLS` atomically
/// with thread creation, before any user code on the worker runs.
static TLS_READY: AtomicBool = AtomicBool::new(false);

/// Pre-goish fs base (the glibc TCB planted by ld.so), saved by
/// `setup_main_tls` before fs is hijacked for the M slot. Zero in
/// static builds and before `setup_main_tls` runs. FFI workers that
/// must call glibc-using foreign code (CUDA etc.) spawn via
/// `clone(2)` with `CLONE_SETTLS` set to this value.
static PRE_GOISH_FS_BASE: AtomicUsize = AtomicUsize::new(0);

/// The fs base this process had before goish planted its M slot
/// (0 = none/static build/not yet saved).
#[inline]
pub fn pre_goish_fs_base() -> usize {
    PRE_GOISH_FS_BASE.load(Ordering::Acquire)
}

/// M17b-ε.α.5: pointer to the current M's `g0.gobuf` — the
/// scheduler-context save slot. Used as the `swap_context` "from"
/// slot when entering a user G (saves M's pre-dispatch state) and
/// as the "to" slot when a user G yields (resumes M's scheduler
/// loop).
///
/// Mirrors Go's `m.g0.sched` (used as `gp.sched` of the g0 G in
/// asm `gogo`/`mcall` save/restore). Replaces the legacy
/// `m.sched_buf` slot.
///
/// Precondition: `g0` has been allocated for the calling M (i.e.
/// `setup_main_g0` for main M, `spawn_worker_m` for workers). After
/// bootstrap, every M that runs scheduler code has its g0 wired.
#[inline]
pub fn current_g0_gobuf() -> *mut crate::runtime::sched::gobuf::Gobuf {
    let g0_ptr = current_m_storage().g0.load(Ordering::Acquire);
    debug_assert!(!g0_ptr.is_null(), "current_g0_gobuf: g0 not yet initialized");
    unsafe { &mut (*g0_ptr).gobuf as *mut crate::runtime::sched::gobuf::Gobuf }
}

/// Mark TLS as ready. Called once from `setup_main_tls` after
/// `arch_prctl(ARCH_SET_FS, …)` succeeds. Idempotent.
#[inline]
pub fn mark_tls_ready() {
    TLS_READY.store(true, Ordering::Release);
}

/// True iff this thread can safely call `current_m()` /
/// `current_m_storage()`. The main thread answers `true` after
/// `setup_main_tls`; workers answer `true` from their entry point.
#[inline]
pub fn is_tls_ready() -> bool {
    TLS_READY.load(Ordering::Acquire)
}

/// Increment the calling M's non-yielding-section depth counter.
/// Pairs with `releasem` (LIFO). No-op while TLS is not yet ready
/// (early init on the main thread). Mirrors Go's `acquirem`
/// (runtime/runtime1.go:631).
///
/// **Why not RAII**: gopark's protocol requires `releasem` *before*
/// the swap_context that yields the goroutine — see Go's
/// proc.go:419. An RAII guard whose Drop runs after the function
/// returns would post-date the yield. Free functions match the
/// surgical placement Go uses.
///
/// **Why a single fs-relative asm RMW, not `AtomicU32::fetch_add`**
/// (2026-07 lost-wakeup fix): debug builds do not inline
/// `core::sync::atomic` — the fetch would be a *call* into regular
/// `.text`, where the SIGURG handler's `goish_rt_text` PC filter
/// can't see us. An injection between "materialize this M's `locks`
/// address" and "apply the RMW" migrates the G to another M, and
/// the RMW then lands on the *old* M's counter: the old M is stuck
/// > 0 forever (never preemptible again) and the new M's matching
/// `releasem` underflows to `u32::MAX`, after which the preempt
/// checks misread "one lock held" as "none held" and preempt inside
/// critical sections. With fs-relative addressing the per-M address
/// is never held in a register across a preemptible instruction —
/// the RMW always hits the M we are executing on *at that instant*.
#[inline(never)]
#[link_section = "goish_rt_text"]
pub fn acquirem() {
    if !is_tls_ready() {
        return;
    }
    unsafe {
        core::arch::asm!(
            "lock add dword ptr fs:[{off}], 1",
            off = const core::mem::offset_of!(MStorage, locks),
            options(nostack),
        );
    }
}

/// Decrement the calling M's non-yielding-section depth counter.
/// Pairs with `acquirem`. Mirrors Go's `releasem`
/// (runtime/runtime1.go:638).
///
/// Single fs-relative `xadd` for the same migration-atomicity
/// reason as `acquirem` (see there); `xadd` rather than `sub` so
/// the previous value feeds the underflow tripwire.
#[inline(never)]
#[link_section = "goish_rt_text"]
pub fn releasem() {
    if !is_tls_ready() {
        return;
    }
    let prev: u32;
    unsafe {
        core::arch::asm!(
            "mov {p:e}, -1",
            "lock xadd dword ptr fs:[{off}], {p:e}",
            p = out(reg) prev,
            off = const core::mem::offset_of!(MStorage, locks),
            options(nostack),
        );
    }
    // Underflow tripwire. `locks` is per-M state: a bump/drop pair
    // that straddles a park (gopark can resume on a different M)
    // leaves the parking M at +1 forever and wraps the resuming M's
    // count to u32::MAX — after which the SIGURG handler and the
    // coop-preempt check misread "one lock held" as "none held" and
    // preempt inside critical sections (the select! straddle behind
    // the 2026-07 lost-wakeup hang). Any pair spanning a park must
    // split into two same-M epochs around it.
    if prev == 0 {
        // Underflow: dump the caller chain of the FIRST bad releasem,
        // then exit hard. A debug_assert here is worse than useless —
        // the panic path itself takes locks and re-enters releasem, so
        // one underflow cascades into an unbounded panic storm ending
        // in a stack overflow (observed 2026-08-14). Self-contained
        // rbp walk with loose sanity checks — releasem may run on g0,
        // where the G-bounded walker refuses to work. The primary
        // guard against ever reaching this is scheduler.rs's
        // check_no_locks_at_schedule ("schedule: holding locks").
        unsafe {
            let msg = b"releasem UNDERFLOW, caller PCs:\n";
            crate::syscall::Write(crate::syscall::STDERR, msg.as_ptr(), msg.len());
            let mut rbp: u64;
            core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack));
            let mut hops = 0;
            while hops < 10 && rbp != 0 && rbp & 7 == 0 {
                let next = *(rbp as *const u64);
                let pc = *((rbp + 8) as *const u64);
                if pc == 0 { break; }
                let mut buf = [b'0'; 19];
                buf[0] = b' '; buf[1] = b'0'; buf[2] = b'x';
                let mut v = pc;
                let mut i = 18;
                while i >= 3 { let nib = (v & 0xf) as u8;
                    buf[i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
                    v >>= 4; i -= 1; }
                crate::syscall::Write(crate::syscall::STDERR, buf.as_ptr(), buf.len());
                crate::syscall::Write(crate::syscall::STDERR, b"\n".as_ptr(), 1);
                if next <= rbp || next - rbp > 1 << 20 { break; }
                rbp = next;
                hops += 1;
            }
        }
        crate::syscall::Exit(87);
    }
    let _ = prev;
}

/// Read the calling M's `locks` count without touching it. Used by
/// the SIGURG handler (M18b phase B+) for the `canPreemptM`
/// predicate. Returns 0 while TLS is not yet ready.
#[inline]
pub fn current_m_locks() -> u32 {
    if !is_tls_ready() {
        return 0;
    }
    current_m_storage().locks.load(Ordering::Relaxed)
}

/// Per-M signal stack size (M18b-δ.3 — SA_ONSTACK). 32 KiB is well
/// above MINSIGSTKSZ on every Linux x86-64 host, including AVX-512
/// where the kernel's xstate area can approach 4 KiB. Mirrors Go's
/// `gsignal.stack` allocation in `runtime/proc.go:mpreinit`.
const SIGNAL_STACK_SIZE: usize = 32 * 1024;

/// Allocate and register a per-thread alt signal stack.
///
/// **Why**: without `SA_ONSTACK` + a registered alt stack, the kernel
/// allocates the rt_sigframe immediately below the user G's red zone
/// on the user G's own stack. Whether this collides with a slot we
/// might want to write from the handler (e.g. `[ucontext.RSP - 144]`
/// for the resume-PC) depends on FPU xstate size (host-CPU dependent).
/// To eliminate the dependence entirely, every M registers a
/// dedicated alt stack at startup; from then on SIGURG is always
/// delivered there.
///
/// **When**: must be called on the same thread that will later
/// receive signals — sigaltstack is a per-thread setting. Main M
/// calls this from `setup_main_tls`; workers call it at the very top
/// of `mstart`, before signaling readiness via `WORKERS_PRIMED`.
///
/// **Mmap is leaked**: each thread keeps its alt stack for its
/// lifetime; process exit reclaims everything.
pub fn install_signal_stack() {
    let p = syscall::Mmap(
        core::ptr::null_mut(),
        SIGNAL_STACK_SIZE,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == syscall::MAP_FAILED {
        const MSG: &[u8] = b"goish: install_signal_stack: mmap failed\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    let st = syscall::SigaltstackT {
        ss_sp: p as usize,
        ss_flags: 0,
        _pad0: 0,
        ss_size: SIGNAL_STACK_SIZE,
    };
    let r = unsafe {
        syscall::Sigaltstack(&st as *const _, core::ptr::null_mut())
    };
    if r != 0 {
        const MSG: &[u8] = b"goish: install_signal_stack: sigaltstack failed\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
}

/// Initialize the main thread's TLS slot and plant `fs`.
///
/// **Must be called exactly once, very early in `__goish_rt0`** —
/// before any code that reads `current_m()` (chans, scheduler, etc.).
/// After this call, every subsequent `current_m()` on the main
/// thread reads `&MAIN_M.m` via `mov %fs:0`.
pub fn setup_main_tls() {
    // Preserve the pre-goish fs base before hijacking fs for the M
    // slot. In dynamically-linked processes ld.so has already planted
    // the glibc TCB here; glibc-using foreign code (CUDA, libstdc++)
    // can only run on a thread whose fs points at that TCB — e.g. an
    // FFI worker spawned with CLONE_SETTLS = pre_goish_fs_base().
    // Zero in static builds (no ld.so, nothing to preserve).
    // NB: ARCH_GET_FS *writes* the base to the given address.
    let mut saved_base: usize = 0;
    let r = syscall::ArchPrctl(
        syscall::ARCH_GET_FS,
        &mut saved_base as *mut usize as usize,
    );
    if r == 0 && saved_base != 0 {
        PRE_GOISH_FS_BASE.store(saved_base, Ordering::Release);
    }
    MAIN_M.init_tls_self();
    let fs_base = MAIN_M.fs_base();
    let r = syscall::ArchPrctl(syscall::ARCH_SET_FS, fs_base);
    if r != 0 {
        const MSG: &[u8] = b"goish: arch_prctl(ARCH_SET_FS) failed\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    // Activate `acquirem` / `releasem` after fs is planted; before
    // this they short-circuit to keep pre-TLS SpinLock callers
    // (e.g. `args::__set`) from dereferencing an uninitialized
    // segment.
    mark_tls_ready();
    // Stamp the main thread's tid into MAIN_M's `procid` so M18b-β
    // sysmon's `tgkill(tid, SIGURG)` can target it. Workers do this
    // in their own `mstart` after `clone(2)`; the main thread has
    // no equivalent entry, so we do it here.
    let tid = syscall::Gettid();
    MAIN_M.m.lock().procid.store(tid, Ordering::Release);
    // M18b-δ.3: register the main thread's per-thread alt signal
    // stack BEFORE `preempt::install` arms the SIGURG handler with
    // `SA_ONSTACK`. Without this, the very first SIGURG delivered to
    // the main M would land on the user G's stack (kernel falls
    // back when SA_ONSTACK is set but no alt stack is registered).
    install_signal_stack();
    // Note: main M is NOT registered with the M_LIST. Registration
    // would push to a Vec, which calls into the allocator — and
    // setup_main_tls runs before `mheap_init()` in `__goish_rt0`
    // (chan/scheduler ops need current_m() before mheap is up).
    // Main M never parks idle (it's the supervisor — terminates
    // via Exit when LIVE_G_COUNT==0), so wakers don't need to find
    // it. Worker Ms are registered in `spawn_worker_m`.
}

/// M17b-ε.α: allocate main M's `g0` after the allocator is online.
///
/// Must run AFTER `mheap_init()` (we Box::leak the G), and BEFORE
/// `bootstrap_workers` so all Ms in the pool have their g0 wired by
/// the time goroutines start running.
///
/// Parses `/proc/self/maps` to find the `[stack]` mapping containing
/// the current rsp. That mapping is the main thread's OS stack —
/// what `g0.stack` should adopt (non-owning).
///
/// Falls back to a heuristic 8 MiB region anchored at current rsp if
/// the parse fails (e.g. `/proc` not mounted in some sandbox). The
/// fallback is sized for default Linux `RLIMIT_STACK = 8 MiB`.
pub fn setup_main_g0() {
    use crate::runtime::sched::g::G;
    use crate::runtime::sched::stack::parse_main_stack_bounds;

    let mut buf = [0u8; 16 * 1024];
    let (base, mut size) = match parse_main_stack_bounds(&mut buf) {
        Some(pair) => pair,
        None => {
            // Heuristic fallback: 8 MiB stack with current rsp inside.
            let rsp: usize;
            unsafe {
                core::arch::asm!(
                    "mov {}, rsp",
                    out(reg) rsp,
                    options(nomem, nostack, preserves_flags),
                );
            }
            const FALLBACK_STACK: usize = 8 * 1024 * 1024;
            // Round rsp up to nearest FALLBACK_STACK boundary as approximate top.
            let top = (rsp + FALLBACK_STACK - 1) & !(FALLBACK_STACK - 1);
            let base = top - FALLBACK_STACK;
            (base as *mut u8, FALLBACK_STACK)
        }
    };

    // The kernel writes argv/envp/auxv — pointer arrays AND their
    // strings — into the TOP of the main thread's [stack] mapping; the
    // process entry rsp sits just below them (argc at [rsp], argv at
    // rsp+8, per the ELF stack layout). `new_g0` stamps gobuf.rsp =
    // base+size, so adopting the full mapping would point every mcall
    // at the environment block and scheduler frames would shred it
    // downward. That was the exec::LookPath bug: after the main M's
    // first deep scheduler excursion, a run-dependent tail of the env
    // strings (PATH included) was destroyed for the rest of the
    // process. Cap the adopted region at entry rsp (= argv - 8).
    if let Some(raw) = crate::runtime::args::get() {
        if !raw.argv.is_null() {
            let entry_rsp = ((raw.argv as usize).saturating_sub(8)) & !0xf;
            let b = base as usize;
            if entry_rsp > b && entry_rsp < b + size {
                size = entry_rsp - b;
            }
        }
    }

    let g0_box = alloc::boxed::Box::new(G::new_g0(base, size));
    let g0_ptr: *mut G = alloc::boxed::Box::leak(g0_box) as *mut _;
    MAIN_M.g0.store(g0_ptr, Ordering::Release);
}

/// Pointer to the currently-running M's `SpinLock<M>`, read from the
/// thread's `fs` register. Each thread's fs base was planted at init
/// (main: `setup_main_tls`; workers: `CLONE_SETTLS` + per-thread
/// `MStorage`), so this is a single instruction on the hot path.
///
/// **Must not be called before `setup_main_tls()`** — fs is
/// uninitialized at process entry; reading it would yield garbage.
#[inline]
pub fn current_m() -> &'static SpinLock<M> {
    let ptr: *const SpinLock<M>;
    unsafe {
        core::arch::asm!(
            "mov %fs:0, {0}",
            out(reg) ptr,
            options(nostack, preserves_flags, att_syntax),
        );
        &*ptr
    }
}

/// Pointer to the calling thread's `MStorage`. Recovers the storage
/// address from the inner `&SpinLock<M>` via `container_of`-style
/// offset arithmetic, which is well-defined because `MStorage` is
/// `#[repr(C)]` and `m` is at the offset returned by
/// `core::mem::offset_of!`.
///
/// Used by M17c's idle-park path to access `parked` (the futex word
/// outside the SpinLock).
#[inline]
pub fn current_m_storage() -> &'static MStorage {
    let m_lock = current_m() as *const SpinLock<M>;
    let m_offset = core::mem::offset_of!(MStorage, m);
    let storage_ptr = (m_lock as usize - m_offset) as *const MStorage;
    unsafe { &*storage_ptr }
}
