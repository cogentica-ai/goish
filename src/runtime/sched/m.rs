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
use core::sync::atomic::{AtomicBool, AtomicI32};

use super::g::G;
use super::gobuf::Gobuf;
use crate::runtime::spin::SpinLock;
use crate::syscall;

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
    /// unused (β2 doesn't park Ms — schedule() returns when runq
    /// drains).
    pub parked: AtomicBool,
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
            parked: AtomicBool::new(false),
        }
    }
}

/// Per-thread storage that holds both the M and the TLS self-pointer
/// at offset 0. `#[repr(C)]` pins `tls_self` to offset 0 so
/// `mov %fs:0, _` reads it back as a `*const SpinLock<M>`.
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
