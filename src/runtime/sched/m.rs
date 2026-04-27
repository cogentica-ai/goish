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
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

use super::g::G;
use super::gobuf::Gobuf;
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
    pub current_g: Option<NonNull<G>>,
    /// Saved register set when this M is suspended (i.e. while a
    /// goroutine is executing on it). `swap_context(&mut sched_buf,
    /// &g.gobuf)` transfers control from the M's scheduler context
    /// into the goroutine; `swap_context(&mut g.gobuf, &sched_buf)`
    /// transfers it back.
    pub sched_buf: Gobuf,
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
            current_g: None,
            sched_buf: Gobuf::new(),
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
    /// Preempt scratch slot — user PC the trampoline must jump back
    /// to when the preempted G is resumed. Written by
    /// `goish_preempt_sigtramp` before each injection. The
    /// trampoline reads this **once at entry** and snapshots the
    /// value onto the G's stack; the per-M slot is then free to be
    /// overwritten by subsequent preempts on this M without
    /// affecting the in-flight trampoline. The handler's write and
    /// the trampoline's first read happen on the same thread with
    /// SIGURG masked between them (kernel default mask), so the
    /// snapshot sees a stable value.
    pub preempt_resume_pc: UnsafeCell<u64>,
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
            preempt_resume_pc: UnsafeCell::new(0),
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
#[inline]
pub fn acquirem() {
    if !is_tls_ready() {
        return;
    }
    current_m_storage()
        .locks
        .fetch_add(1, Ordering::Relaxed);
}

/// Decrement the calling M's non-yielding-section depth counter.
/// Pairs with `acquirem`. Mirrors Go's `releasem`
/// (runtime/runtime1.go:638).
#[inline]
pub fn releasem() {
    if !is_tls_ready() {
        return;
    }
    current_m_storage()
        .locks
        .fetch_sub(1, Ordering::Relaxed);
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

/// Initialize the main thread's TLS slot and plant `fs`.
///
/// **Must be called exactly once, very early in `__goish_rt0`** —
/// before any code that reads `current_m()` (chans, scheduler, etc.).
/// After this call, every subsequent `current_m()` on the main
/// thread reads `&MAIN_M.m` via `mov %fs:0`.
pub fn setup_main_tls() {
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
    // Note: main M is NOT registered with the M_LIST. Registration
    // would push to a Vec, which calls into the allocator — and
    // setup_main_tls runs before `mheap_init()` in `__goish_rt0`
    // (chan/scheduler ops need current_m() before mheap is up).
    // Main M never parks idle (it's the supervisor — terminates
    // via Exit when LIVE_G_COUNT==0), so wakers don't need to find
    // it. Worker Ms are registered in `spawn_worker_m`.
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
