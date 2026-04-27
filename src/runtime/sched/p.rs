// runtime::sched::p — the processor (P).
//
// Slim port of Go's `runtime.p` (runtime/runtime2.go:642). A P is a
// "permission slip" to run goroutines — the central per-CPU resource
// in Go's M:N scheduler. Each running M holds a P; Ms without a P sit
// idle. The P owns:
//
//   - a bounded local run queue (β) — lock-free SPMC ring of 256 Gs,
//   - a `runnext` slot for the most-recently-readied G (β),
//   - an mcache (ε) — per-size-class span freelists.
//
// Phase α (this file): the bare struct + bootstrap + M↔P binding.
// β fills in `runqput`/`runqget`/`runqsteal`. γ wires `findRunnable`.
// ε attaches the mcache. Each phase commits independently.
//
// Why static-array storage. Ps are a fixed-size pool (one per CPU).
// `bootstrap_ps(n)` runs once at startup, leaks `n` boxed Ps, and
// stashes the pointers in `ALL_PS`. After bootstrap the array is
// read-only — workers, sysmon, and steal scans iterate it without
// any lock. Sized at 256 entries (fits any plausible CPU count).
//
// Lifecycle:
//
//   Pdead    — slot uninitialized. Initial state of every entry
//              before bootstrap_ps runs; Ps never re-enter this
//              state in v1 (no GOMAXPROCS rescaling).
//   Pidle    — initialized, no M bound. New Ps after bootstrap_ps
//              start here. An M acquires by transitioning to
//              Prunning (acquirep).
//   Prunning — bound to an M via acquirep. The M is the unique
//              writer to this P's runq.
//   Psyscall — reserved for future syscall-handoff (phase B+).
//              Currently unused.

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use super::g::G;
use super::m::{current_m_storage, is_tls_ready, MStorage};

// ─── status constants (Go's _Pidle / _Prunning / _Psyscall / _Pdead) ─

/// Initialized P with no bound M, eligible for `acquirep`.
pub const P_IDLE: u32 = 0;
/// Bound to an M and dispatching goroutines.
pub const P_RUNNING: u32 = 1;
/// Bound M is in a syscall; reserved for future handoffp.
pub const P_SYSCALL: u32 = 2;
/// Slot uninitialized. Never re-entered after init.
pub const P_DEAD: u32 = 3;

/// Local run queue capacity per P. Matches Go's 256
/// (runtime/runtime2.go:664).
pub const LOCAL_RUNQ_SIZE: usize = 256;

/// Maximum number of Ps the runtime can bootstrap. Picked to cover
/// any plausible host (≤256 CPUs); higher caps are easy to bump.
pub const MAX_PS: usize = 256;

// ─── P struct ────────────────────────────────────────────────────────

/// One processor. Mirrors Go's `type p struct` (runtime2.go:642).
///
/// **Thread safety**. The runq fields (`runqhead` / `runqtail` / `runq`
/// / `runnext`) follow Go's lock-free SPMC discipline: only the bound
/// M (the "owner P") writes `runqtail` and ring slots; other Ms may
/// read `runqhead`/`runqtail` and CAS the head forward to steal. β
/// fills in the operations; α ships the struct skeleton with
/// zero-initialized fields so β is purely additive.
pub struct P {
    /// Logical P id, equal to its index in `ALL_PS`. Stable for the
    /// lifetime of the process.
    pub id: u32,
    /// One of `P_IDLE` / `P_RUNNING` / `P_SYSCALL` / `P_DEAD`.
    /// Mutated by `acquirep` / `releasep` and (later) by syscall
    /// handoff. Atomic so steal scans can read it without locks.
    pub status: AtomicU32,

    /// Back-pointer to the bound M. Null when `status == P_IDLE`.
    /// Atomic so `for_each_m` / steal scans can read other Ps' Ms
    /// without locking. Written exclusively by `acquirep` / `releasep`
    /// from the M acquiring/releasing this P.
    pub m: AtomicPtr<MStorage>,

    /// Lock-free SPMC ring head — index of the next G to be consumed.
    /// Other Ms CAS this forward when stealing. β populates.
    pub runqhead: AtomicU32,
    /// Lock-free SPMC ring tail — index of the next free slot.
    /// Only the owner M writes it. β populates.
    pub runqtail: AtomicU32,
    /// Bounded ring buffer of runnable Gs. β fills in.
    pub runq: UnsafeCell<[*mut G; LOCAL_RUNQ_SIZE]>,
    /// Most-recently-readied G to dispatch ahead of the ring. Other Ms
    /// can CAS this to null to steal it. Mirrors Go's `runnext`
    /// (runtime2.go:677). β populates.
    pub runnext: AtomicPtr<G>,

    /// Phase ε will attach an mcache here (per-size-class span cache).
    /// Currently a placeholder so the struct layout is final from α.
    pub mcache_placeholder: UnsafeCell<usize>,
}

unsafe impl Send for P {}
unsafe impl Sync for P {}

impl P {
    /// Const-construct an idle P with id=0 and zeroed runq. Callers
    /// (only `bootstrap_ps`) override `id` before publishing.
    pub const fn new(id: u32) -> Self {
        P {
            id,
            status: AtomicU32::new(P_IDLE),
            m: AtomicPtr::new(core::ptr::null_mut()),
            runqhead: AtomicU32::new(0),
            runqtail: AtomicU32::new(0),
            runq: UnsafeCell::new([core::ptr::null_mut(); LOCAL_RUNQ_SIZE]),
            runnext: AtomicPtr::new(core::ptr::null_mut()),
            mcache_placeholder: UnsafeCell::new(0),
        }
    }

    /// Read the bound M storage, if any. Returns `None` when the P is
    /// idle. Safe to call from any thread (atomic load).
    #[inline]
    pub fn bound_m(&self) -> Option<&'static MStorage> {
        let p = self.m.load(Ordering::Acquire);
        if p.is_null() {
            None
        } else {
            // Safety: every MStorage stored here was leaked into 'static
            // by `bootstrap_workers` / `setup_main_tls` and never freed.
            unsafe { Some(&*p) }
        }
    }
}

// ─── ALL_PS — global P registry ──────────────────────────────────────

/// Number of bootstrapped Ps. Set once by `bootstrap_ps`.
static NUM_PS: AtomicU32 = AtomicU32::new(0);

/// Global P registry. Slot `i` holds `&'static P` with `id == i` after
/// bootstrap, or null otherwise. Size-bounded so we don't need a Vec
/// (which would require allocator + lock and complicate startup
/// ordering relative to mheap_init).
///
/// Mirrors Go's `allp` (proc.go).
static ALL_PS: [AtomicPtr<P>; MAX_PS] = {
    const NULL: AtomicPtr<P> = AtomicPtr::new(core::ptr::null_mut());
    [NULL; MAX_PS]
};

/// Allocate `n` Ps and register them in `ALL_PS`. Must be called
/// exactly once at startup, after the allocator is online and before
/// any worker M attempts `acquirep`.
///
/// Mirrors a slim subset of Go's `procresize` (proc.go:5904):
/// no rescaling, no GC handoff, no migration of in-flight Gs.
///
/// Each P is `Box::leak`'d so its address is `'static`. The initial
/// status is `P_IDLE` — ready to be acquired.
pub fn bootstrap_ps(n: usize) {
    let n = n.min(MAX_PS);
    if NUM_PS.load(Ordering::Acquire) != 0 {
        // Re-entry guard: bootstrap_ps must be a one-shot.
        return;
    }
    for i in 0..n {
        let p: &'static P = alloc::boxed::Box::leak(alloc::boxed::Box::new(P::new(i as u32)));
        ALL_PS[i].store(p as *const P as *mut P, Ordering::Release);
    }
    NUM_PS.store(n as u32, Ordering::Release);
}

/// Number of bootstrapped Ps. 0 before `bootstrap_ps`.
#[inline]
pub fn num_ps() -> usize {
    NUM_PS.load(Ordering::Acquire) as usize
}

/// Read P at index `i`, or `None` if unbootstrapped.
#[inline]
pub fn p_at(i: usize) -> Option<&'static P> {
    if i >= num_ps() {
        return None;
    }
    let p = ALL_PS[i].load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // Safety: every P stored here was leaked into 'static by
        // bootstrap_ps and never freed.
        Some(unsafe { &*p })
    }
}

/// Iterate every bootstrapped P. Read-only — safe from any thread
/// after `bootstrap_ps` returns.
pub fn for_each_p<F: FnMut(&'static P)>(mut f: F) {
    let n = num_ps();
    for i in 0..n {
        if let Some(p) = p_at(i) {
            f(p);
        }
    }
}

// ─── M↔P binding (acquirep / releasep / current_p) ──────────────────

/// Bind P `p` to the calling M. Transitions `p.status` from `P_IDLE`
/// to `P_RUNNING` and records the M↔P backlinks. Panics if `p` is
/// already running on another M (would indicate a bootstrap race).
///
/// Mirrors Go's `acquirep` (proc.go:5790). Like Go, the binding is
/// strictly LIFO with `releasep` — every acquire pairs with a release.
pub fn acquirep(p: &'static P) {
    if !is_tls_ready() {
        return;
    }
    let storage = current_m_storage();
    // 1) Mark P running.
    let prev = p.status.swap(P_RUNNING, Ordering::AcqRel);
    debug_assert!(
        prev == P_IDLE,
        "acquirep: target P was not idle (status={})",
        prev
    );
    // 2) Backlink P → M.
    p.m.store(storage as *const MStorage as *mut MStorage, Ordering::Release);
    // 3) Forward link M → P.
    storage
        .current_p
        .store(p as *const P as *mut P, Ordering::Release);
}

/// Unbind the calling M from its current P. Returns the released P,
/// or `None` if no P was bound. Mirrors Go's `releasep`
/// (proc.go:5814).
///
/// The M may then call `park_m_idle` (idle-park) or another
/// `acquirep` (handoff). Until then it has no permission to dispatch
/// goroutines.
pub fn releasep() -> Option<&'static P> {
    if !is_tls_ready() {
        return None;
    }
    let storage = current_m_storage();
    let p_ptr = storage.current_p.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if p_ptr.is_null() {
        return None;
    }
    let p = unsafe { &*p_ptr };
    // Sever P → M backlink before flipping status, so a steal scan
    // that finds status==P_IDLE never sees a stale m pointer.
    p.m.store(core::ptr::null_mut(), Ordering::Release);
    p.status.store(P_IDLE, Ordering::Release);
    Some(p)
}

/// Read the calling M's bound P, or `None` if unbound. Hot-path
/// accessor for `runqput` / `runqget` (β) and the small-alloc path
/// (ε), so it avoids any locks.
#[inline]
pub fn current_p() -> Option<&'static P> {
    if !is_tls_ready() {
        return None;
    }
    let p_ptr = current_m_storage()
        .current_p
        .load(Ordering::Acquire);
    if p_ptr.is_null() {
        None
    } else {
        Some(unsafe { &*p_ptr })
    }
}

// Suppress unused warning; phase β will reference G.
const _: fn() = || {
    let _: *mut G = core::ptr::null_mut();
    let _: Option<NonNull<G>> = None;
};
