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
    // M17b-γ: prime the coprime table for randomized steal scans.
    // Mirrors `procresize`'s `stealOrder.reset(uint32(nprocs))`
    // (proc.go:5999).
    STEAL_ORDER.reset(n as u32);
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

// ─── runq operations (M17b-β) ────────────────────────────────────────
//
// Lock-free SPMC ring discipline ported verbatim from Go's runtime
// (proc.go:7058,7178,7104). The owner P (the bound M's thread) is the
// sole writer of `runqtail` and the ring slots; other Ms (steal scans
// in γ) only CAS `runqhead` forward and read slots after acquire-load
// of the matching tail.
//
// Memory ordering:
//   - `runqhead`: load-acquire by readers (owner pop, stealers),
//                 CAS-release for advancement.
//   - `runqtail`: store-release by owner after writing the slot,
//                 load-acquire by stealers before reading slots.
//   - `runnext` : compare-exchange (AcqRel) — both owner and stealers
//                 race for it.
//
// Slot mutation goes through the UnsafeCell. Synchronization is
// provided exclusively by the head/tail atomics; the slot itself is
// a plain `*mut G` write whose visibility piggybacks on the
// store-release of `runqtail` (write before release-store ⇒ visible
// to any thread that acquires-load the same atomic). This mirrors
// Go's `pp.runq[t%N].set(gp)` followed by `atomic.StoreRel(&pp.runqtail, t+1)`.

impl P {
    /// Try to put `gp` on the local runnable queue. If the queue is
    /// full, kicks half of it (plus `gp`) onto the global queue via
    /// `runqputslow`. `next=true` puts `gp` into the `runnext` slot,
    /// kicking any prior runnext to the ring tail.
    ///
    /// Mirrors `runqput` (proc.go:7058). Executed only by the owner P.
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub unsafe fn runqput(&self, gp: NonNull<G>, next: bool) {
        let mut gp_ptr = gp.as_ptr();

        if next {
            // Set runnext, kicking the prior one to the ring.
            loop {
                let oldnext = self.runnext.load(Ordering::Relaxed);
                if self
                    .runnext
                    .compare_exchange_weak(
                        oldnext,
                        gp_ptr,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    if oldnext.is_null() {
                        return;
                    }
                    // Prior runnext gets pushed to the ring instead.
                    gp_ptr = oldnext;
                    break;
                }
            }
        }

        loop {
            let h = self.runqhead.load(Ordering::Acquire);
            let t = self.runqtail.load(Ordering::Relaxed);
            if t.wrapping_sub(h) < LOCAL_RUNQ_SIZE as u32 {
                // Room in the ring.
                let slot = (t as usize) % LOCAL_RUNQ_SIZE;
                (*self.runq.get())[slot] = gp_ptr;
                self.runqtail
                    .store(t.wrapping_add(1), Ordering::Release);
                return;
            }
            // Full — try to overflow half + this G to global.
            let g_to_push = NonNull::new_unchecked(gp_ptr);
            if self.runqputslow(g_to_push, h, t) {
                return;
            }
            // CAS lost — queue may have drained; retry the put.
        }
    }

    /// Spill half the local runq plus `gp` to the global runq.
    /// Returns true on success, false if the head CAS lost a race
    /// (owner P should retry the put).
    ///
    /// Mirrors `runqputslow` (proc.go:7104).
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    fn runqputslow(&self, gp: NonNull<G>, h: u32, t: u32) -> bool {
        const HALF: usize = LOCAL_RUNQ_SIZE / 2;
        let mut batch: [*mut G; HALF + 1] = [core::ptr::null_mut(); HALF + 1];
        let n = t.wrapping_sub(h) / 2;
        // Sanity: this path is only entered with t-h == LOCAL_RUNQ_SIZE.
        // n must be HALF.
        debug_assert_eq!(n as usize, HALF, "runqputslow: queue not full");
        for i in 0..n {
            let slot = (h.wrapping_add(i) as usize) % LOCAL_RUNQ_SIZE;
            batch[i as usize] = unsafe { (*self.runq.get())[slot] };
        }
        if self
            .runqhead
            .compare_exchange(
                h,
                h.wrapping_add(n),
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return false;
        }
        batch[n as usize] = gp.as_ptr();
        super::scheduler::globrunqput_batch(&batch[..(n as usize) + 1]);
        true
    }

    /// Pop the next G from the local runnable queue, examining
    /// `runnext` first then the ring. Returns `None` if both are empty.
    ///
    /// Mirrors `runqget` (proc.go:7178). Executed only by the owner P.
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub unsafe fn runqget(&self) -> Option<NonNull<G>> {
        let next = self.runnext.load(Ordering::Acquire);
        if !next.is_null() {
            // Only the owner P can publish a new runnext; only
            // stealers (γ) can race to clear it. So a single CAS
            // attempt is sufficient.
            if self
                .runnext
                .compare_exchange(next, core::ptr::null_mut(), Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(NonNull::new_unchecked(next));
            }
        }
        loop {
            let h = self.runqhead.load(Ordering::Acquire);
            let t = self.runqtail.load(Ordering::Acquire);
            if t == h {
                return None;
            }
            let slot = (h as usize) % LOCAL_RUNQ_SIZE;
            let gp = (*self.runq.get())[slot];
            if self
                .runqhead
                .compare_exchange_weak(
                    h,
                    h.wrapping_add(1),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                if gp.is_null() {
                    // Stale slot from a previous wrap — skip and retry.
                    continue;
                }
                return Some(NonNull::new_unchecked(gp));
            }
        }
    }

    /// Cheap, racy "is there work for me here?" check used by the
    /// schedule loops post-park to decide whether to dispatch or
    /// re-park. False negatives are harmless: a `wake_idle_m` from
    /// the producer will catch us. False positives just turn into a
    /// `runqget == None` on the next iteration.
    pub fn runq_has_work(&self) -> bool {
        if !self.runnext.load(Ordering::Acquire).is_null() {
            return true;
        }
        let h = self.runqhead.load(Ordering::Acquire);
        let t = self.runqtail.load(Ordering::Acquire);
        h != t
    }

    /// Approximate count of Gs in the local runq + runnext. Diagnostic
    /// only — racy across multiple Ms.
    pub fn runq_len(&self) -> usize {
        let mut n = 0usize;
        if !self.runnext.load(Ordering::Relaxed).is_null() {
            n += 1;
        }
        let h = self.runqhead.load(Ordering::Relaxed);
        let t = self.runqtail.load(Ordering::Relaxed);
        n + t.wrapping_sub(h) as usize
    }

    // ─── M17b-γ: work-stealing primitives (verbatim port) ──────────
    //
    // Each function below mirrors its Go counterpart with proof of
    // line-for-line equivalence in `doc/M17b-gamma-proof.md`. The
    // memory-ordering refinement is: every Go `atomic.LoadAcq` /
    // `atomic.StoreRel` / `atomic.CasRel` ↔ Rust `Acquire` /
    // `Release` / `Release`-on-success-CAS, and every plain Go field
    // read on a single-writer field is `Relaxed` in Goish (still
    // safe because the same single-writer invariant holds).

    /// Race-free emptiness check usable from any P. Verbatim port of
    /// `runqempty` (proc.go:7027). Defends against the runnext-window
    /// race (Go's comment, lines 7028-7031): if `head == tail` is
    /// observed but `runnext` was non-nil and got kicked into the
    /// ring between the head and runnext loads, a naive read returns
    /// false. The double-tail-load loop forces a re-snapshot until
    /// `tail` is stable across the runnext read.
    pub fn runqempty(&self) -> bool {
        loop {
            let head = self.runqhead.load(Ordering::Acquire);
            let tail = self.runqtail.load(Ordering::Acquire);
            let runnext = self.runnext.load(Ordering::Acquire);
            if tail == self.runqtail.load(Ordering::Acquire) {
                return head == tail && runnext.is_null();
            }
        }
    }

    /// Grab a half-batch of Gs from `self`'s runq into the caller's
    /// runq slot array, returning the count grabbed. Verbatim port of
    /// `runqgrab` (proc.go:7242).
    ///
    /// Argument mapping:
    ///   - `self`         ⟷ Go `pp *p`        (target P being raided)
    ///   - `dst`          ⟷ Go `batch *[256]guintptr` (caller's runq)
    ///   - `batch_head`   ⟷ Go `batchHead uint32`     (caller's tail)
    ///   - `steal_runnext_g` ⟷ Go `stealRunNextG bool`
    ///
    /// Memory-ordering equivalence (proof §5):
    ///   - LoadAcq on `runqhead`, `runqtail` (G1)
    ///   - LoadAcq on `runnext` for the n=0 fallback (G3a)
    ///   - CAS-Release on `runqhead` to commit consume (G5)
    ///   - CAS-AcqRel on `runnext` for the runnext steal (G3c)
    ///
    /// `usleep(3)` (Go) substitutes as `SchedYield()` here — it is a
    /// liveness optimization (anti-thrash), not a safety property
    /// (G3b).
    ///
    /// Safety: `dst` must be a valid `[*mut G; LOCAL_RUNQ_SIZE]`
    /// owned by the caller's P, and the caller must hold the
    /// single-writer invariant on those slots (i.e. caller is the M
    /// bound to the destination P).
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub unsafe fn runqgrab(
        &self,
        dst: *mut [*mut G; LOCAL_RUNQ_SIZE],
        batch_head: u32,
        steal_runnext_g: bool,
    ) -> u32 {
        loop {
            let h = self.runqhead.load(Ordering::Acquire);
            let t = self.runqtail.load(Ordering::Acquire);
            let mut n = t.wrapping_sub(h);
            n = n - n / 2;
            if n == 0 {
                if !steal_runnext_g {
                    return 0;
                }
                let next = self.runnext.load(Ordering::Acquire);
                if next.is_null() {
                    return 0;
                }
                if self.status.load(Ordering::Acquire) == P_RUNNING {
                    // Anti-thrash backoff: give the target a chance
                    // to schedule its own runnext before we snipe it.
                    // Go uses usleep(3) at proc.go:7263; without a
                    // low-resolution-timer integration in goish, a
                    // single SchedYield is the closest analog and
                    // preserves the "yield once" liveness intent.
                    let _ = crate::syscall::SchedYield();
                }
                if self
                    .runnext
                    .compare_exchange(
                        next,
                        core::ptr::null_mut(),
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_err()
                {
                    continue;
                }
                let slot = (batch_head as usize) % LOCAL_RUNQ_SIZE;
                (*dst)[slot] = next;
                return 1;
            }
            // Defensive: torn (h, t) read can yield n > cap/2.
            // Mirrors Go's "read inconsistent h and t" guard
            // (proc.go:7281).
            if n > (LOCAL_RUNQ_SIZE / 2) as u32 {
                continue;
            }
            for i in 0..n {
                let src_slot = (h.wrapping_add(i) as usize) % LOCAL_RUNQ_SIZE;
                let g = (*self.runq.get())[src_slot];
                let dst_slot = (batch_head.wrapping_add(i) as usize) % LOCAL_RUNQ_SIZE;
                (*dst)[dst_slot] = g;
            }
            if self
                .runqhead
                .compare_exchange(
                    h,
                    h.wrapping_add(n),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return n;
            }
            // CAS lost — slot copies into `dst` are dead writes
            // (caller has not yet StoreRel'd its tail), so loop and
            // retry.
        }
    }

    /// Steal half of `target`'s runnable Gs into `self`'s runq,
    /// returning one stolen G for immediate dispatch. Remaining
    /// stolen Gs (if any) are published to `self`'s runq via
    /// `StoreRel(runqtail)`. Verbatim port of `runqsteal`
    /// (proc.go:7297).
    ///
    /// Returns `None` if `runqgrab` came back with 0.
    ///
    /// Safety: caller must be the M bound to `self`. The
    /// single-writer invariant on `self.runq[]` slots and
    /// `self.runqtail` is what makes the SPMC ring lock-free.
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub unsafe fn runqsteal(
        &self,
        target: &P,
        steal_runnext_g: bool,
    ) -> Option<NonNull<G>> {
        // Single-writer read: only `self`'s owner M writes
        // `self.runqtail`, and that owner is the caller.
        let t = self.runqtail.load(Ordering::Relaxed);
        let n = target.runqgrab(self.runq.get(), t, steal_runnext_g);
        if n == 0 {
            return None;
        }
        let n = n - 1;
        // Caller takes the *last-grabbed* G at index t+n
        // (proc.go:7304).
        let last_slot = (t.wrapping_add(n) as usize) % LOCAL_RUNQ_SIZE;
        let gp = (*self.runq.get())[last_slot];
        if n == 0 {
            // Exactly one stolen — caller takes it, runqtail
            // unchanged.
            return NonNull::new(gp);
        }
        let h = self.runqhead.load(Ordering::Acquire);
        debug_assert!(
            t.wrapping_sub(h).wrapping_add(n) < LOCAL_RUNQ_SIZE as u32,
            "runqsteal: runq overflow"
        );
        // Publish the n remaining stolen Gs at indices [t, t+n).
        self.runqtail
            .store(t.wrapping_add(n), Ordering::Release);
        NonNull::new(gp)
    }
}

// ─── stealOrder — coprime-based pseudo-random P enumeration ─────────
//
// Verbatim port of Go's `randomOrder` / `randomEnum` (proc.go:7560+).
// The enumeration uses the fact that for X coprime to N, the sequence
// (i + X) mod N visits every value in [0, N) exactly once. Different
// seeds (cheaprand) pick different X, giving each steal pass a fresh
// permutation without explicit shuffling.
//
// Goish stores the coprimes in a fixed-size array (no Vec at static
// init) — capacity bound is `MAX_PS` since coprimes-of-N is always
// < N ≤ MAX_PS.

/// Steal-scan order. `reset(n)` is called from `bootstrap_ps` after
/// the P count is known, mirroring Go's `procresize`'s
/// `stealOrder.reset(uint32(nprocs))` (proc.go:5999). Read from any
/// M via `start(seed)`.
pub static STEAL_ORDER: RandomOrder = RandomOrder::new();

pub struct RandomOrder {
    /// Number of Ps. 0 before `reset`.
    count: AtomicU32,
    /// Number of valid entries in `coprimes`.
    coprime_count: AtomicU32,
    /// Coprimes of `count` in ascending order. Capacity `MAX_PS`,
    /// in-use range `[0, coprime_count)`.
    coprimes: UnsafeCell<[u32; MAX_PS]>,
}

unsafe impl Sync for RandomOrder {}

impl RandomOrder {
    pub const fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
            coprime_count: AtomicU32::new(0),
            coprimes: UnsafeCell::new([0; MAX_PS]),
        }
    }

    /// Reconfigure for `count` Ps. Mirrors `randomOrder.reset`
    /// (proc.go:7578). Called once from `bootstrap_ps` on the main
    /// thread, before any worker M exists — so no concurrent reader
    /// can observe partial state. The Release-stores on
    /// `coprime_count` then `count` publish the array writes in
    /// dependency order: any later `Acquire`-load of `count` that
    /// sees a non-zero value transitively sees a consistent
    /// `coprimes[0..coprime_count]`.
    pub fn reset(&self, count: u32) {
        let count = count.min(MAX_PS as u32);
        let mut k = 0u32;
        let buf = unsafe { &mut *self.coprimes.get() };
        let mut i = 1u32;
        while i <= count && (k as usize) < MAX_PS {
            if gcd(i, count) == 1 {
                buf[k as usize] = i;
                k += 1;
            }
            i += 1;
        }
        self.coprime_count.store(k, Ordering::Release);
        self.count.store(count, Ordering::Release);
    }

    /// Begin a fresh enumeration. Mirrors `randomOrder.start`
    /// (proc.go:7588). Returns an empty enumeration if `reset`
    /// hasn't run yet.
    pub fn start(&self, seed: u32) -> RandomEnum {
        let count = self.count.load(Ordering::Acquire);
        let coprime_count = self.coprime_count.load(Ordering::Acquire);
        if count == 0 || coprime_count == 0 {
            return RandomEnum {
                i: 0,
                count: 0,
                pos: 0,
                inc: 1,
            };
        }
        let pos = seed % count;
        let coprime_idx = (seed / count) % coprime_count;
        let inc = unsafe { (*self.coprimes.get())[coprime_idx as usize] };
        RandomEnum {
            i: 0,
            count,
            pos,
            inc,
        }
    }
}

pub struct RandomEnum {
    i: u32,
    count: u32,
    pos: u32,
    inc: u32,
}

impl RandomEnum {
    /// Mirrors `randomEnum.done` (proc.go:7596).
    #[inline]
    pub fn done(&self) -> bool {
        self.i == self.count
    }
    /// Mirrors `randomEnum.next` (proc.go:7600).
    #[inline]
    pub fn next(&mut self) {
        self.i += 1;
        self.pos = (self.pos + self.inc) % self.count;
    }
    /// Mirrors `randomEnum.position` (proc.go:7605).
    #[inline]
    pub fn position(&self) -> u32 {
        self.pos
    }
}

/// Euclidean GCD. Mirrors Go's `gcd` (proc.go:7609).
fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

// ─── γ diagnostic counters ───────────────────────────────────────────

/// Total successful steals across all Ms.
pub static STEAL_HITS: AtomicU32 = AtomicU32::new(0);
/// Number of times an M entered the steal pass (regardless of
/// whether it succeeded).
pub static STEAL_PASSES: AtomicU32 = AtomicU32::new(0);
