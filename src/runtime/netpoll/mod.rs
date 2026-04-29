// runtime/netpoll — slim port of Go's runtime/netpoll.go +
// runtime/netpoll_epoll.go (Go 1.25). Lifts the NumCPU-concurrency
// cap on net::Listener::Accept / net::Conn::Read / net::Conn::Write
// by parking goroutines that hit EAGAIN onto an edge-triggered epoll
// fd; the I/O completion wakes them via an unblock-CAS that races
// against the parker's pdWait→Wait transition.
//
// What's ported (per doc/M27e-netpoller-design.md):
//   PollDesc { fd, rg, wg, rd, wd, rseq, wseq }
//                                — netpoll.go:75 (M27e-α + M27f-α deadlines)
//   init()                       — netpoll_epoll.go:21 (epollcreate1 + eventfd2)
//   open(fd) -> *const PollDesc  — netpoll_epoll.go:49 (EPOLL_CTL_ADD, EPOLLIN|OUT|RDHUP|ET)
//   close(pd)                    — netpoll_epoll.go:57
//   block(pd, mode) -> BlockResult — netpoll.go:548 (Ready / Timedout / Aborted)
//   unblock(pd, mode, ioready)   — netpoll.go:591
//   poll(delay_ms) -> gList      — netpoll_epoll.go:99
//   netpoll_break()              — netpoll_epoll.go:67
//   set_deadline(pd, ns, mode)   — netpoll.go:371 poll_runtime_pollSetDeadline
//   fire_expired_deadlines(now)  — netpoll.go:622 netpolldeadlineimpl
//                                  (sysmon-driven; no per-pd timer object)
//
// Deferred:
//   - Tagged-pointer fdseq (stale-event protection across fd reuse).
//   - pollCache slab — v1 leaks one Box<PollDesc> per open fd.
//   - closing/eventErr atomic info bits — v1 conflates "closing"
//     with "fd closed; next syscall returns EBADF".

#![allow(non_snake_case)]

extern crate alloc;

use alloc::collections::BinaryHeap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::cmp::{Ordering as CmpOrdering, Reverse};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicUsize, Ordering};

use crate::runtime::sched::{current_m, goready, gopark, G};
use crate::runtime::spin::SpinLock;
use crate::syscall;

// ─── pollDesc state machine constants (netpoll.go:64) ────────────────
//
// rg / wg each hold one of:
//   PD_NIL    (0): no waiter, no pending notification
//   PD_READY  (1): fd is ready; next block returns immediately
//   PD_WAIT   (2): goroutine is preparing to park on this slot
//   *G       (>2): goroutine parked on this slot
//
// 1 and 2 are below the lowest possible valid pointer (G is heap-
// allocated, well above the first 4 KiB), so the discriminator is
// just `value <= 2` vs `value > 2`.

const PD_NIL: usize = 0;
const PD_READY: usize = 1;
const PD_WAIT: usize = 2;

// ─── PollDesc ────────────────────────────────────────────────────────

/// Per-fd parker state. Stored stably (Box::leak) for the lifetime of
/// the registration — epoll holds a `*const PollDesc` in `ev.data` and
/// expects it to remain valid until EPOLL_CTL_DEL.
///
/// **Concurrency**: `rg` and `wg` are independent atomic state machines
/// (one for read-mode parkers, one for write-mode). Concurrent block
/// in the same mode is forbidden — Go panics "double wait"; we panic
/// the same. For Conn this is naturally enforced (one reader, one
/// writer per Conn).
pub struct PollDesc {
    /// Kernel fd. Constant for the lifetime of this Arc<PollDesc>;
    /// only read by `close()` to issue EPOLL_CTL_DEL on the right fd.
    /// Stored Atomic to keep the struct interior-mutable (alternatives
    /// would require a &mut self constructor, which conflicts with
    /// Arc::new's by-value initialization).
    pub fd: AtomicI32,
    /// Index into `REGISTRY.slots` for this PollDesc. `event.data`
    /// (low 32 bits) carries this index; `poll()` looks up the Arc
    /// in the slab to safely deref.
    pub slot: AtomicU32,
    /// Read-side parker state. See PD_* constants above.
    pub rg: AtomicUsize,
    /// Write-side parker state.
    pub wg: AtomicUsize,

    /// Read deadline (CLOCK_MONOTONIC nanoseconds, sysmon-comparable).
    /// `0` = no deadline. `-1` = expired (block returns timeout
    /// immediately). Mirrors Go's `pd.rd` (netpoll.go:110).
    pub rd: AtomicI64,
    /// Write deadline. `0` = none, `-1` = expired.
    pub wd: AtomicI64,
    /// Read-deadline generation counter. Bumped by `set_deadline`
    /// before pushing onto `DEADLINE_HEAP`; sysmon discards heap
    /// entries whose seq doesn't match. Mirrors Go's `pd.rseq`.
    pub rseq: AtomicU32,
    /// Write-deadline generation counter.
    pub wseq: AtomicU32,
    /// Slot-recycle generation counter. Bumped by `close()` before
    /// the slot returns to the freelist. Bottom 16 bits are packed
    /// into bits [32..48] of `EpollEvent.data` at `EPOLL_CTL_ADD`
    /// time; `poll()` filters stale events whose embedded tag no
    /// longer matches `pd.fdseq.load()`. Mirrors Go's `pd.fdseq`
    /// (netpoll.go:79) — Go uses 24 bits, we use 16.
    pub fdseq: AtomicU32,
}

impl PollDesc {
    fn new(fd: i32) -> Self {
        PollDesc {
            fd: AtomicI32::new(fd),
            slot: AtomicU32::new(u32::MAX),
            rg: AtomicUsize::new(PD_NIL),
            wg: AtomicUsize::new(PD_NIL),
            rd: AtomicI64::new(0),
            wd: AtomicI64::new(0),
            rseq: AtomicU32::new(0),
            wseq: AtomicU32::new(0),
            // Start at 1 — Go reserves 0 (netpoll.go:256-258
            // "value 0 is special in setEventErr").
            fdseq: AtomicU32::new(1),
        }
    }
}

impl Drop for PollDesc {
    fn drop(&mut self) {
        // Fires when the last Arc<PollDesc> clone drops. The Drop
        // ordering is what makes `live_count()` accurately reflect
        // currently-allocated PollDescs even if a `poll()` iteration
        // holds an in-flight clone past `netpoll::close()`.
        PD_LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Outcome of a `block(pd, mode)` call. Mirrors the (bool, errcode)
/// pair Go's `runtime_pollWait` returns to the user — but folded into
/// a tri-state because v1 only distinguishes ready/timeout/aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockResult {
    /// Slot was PD_READY when consumed (or epoll fired during park).
    /// Caller proceeds with the I/O syscall.
    Ready,
    /// Deadline expired while parked (or before park was attempted).
    /// Caller returns a timeout error.
    Timedout,
    /// Slot returned PD_NIL through some non-deadline path (e.g.
    /// netpoll_break drove an unblock with ioready=false). Caller
    /// retries; we don't generate this case in v1 but keep the
    /// variant so future closing/cancel logic has a slot.
    Aborted,
}

// ─── Module-global state ─────────────────────────────────────────────

/// epoll fd. `-1` until init() runs; thereafter constant for the
/// process lifetime.
static EPFD: AtomicI32 = AtomicI32::new(-1);

/// eventfd backing netpoll_break. Address of this static is used as
/// the magic `ev.data` value distinguishing the eventfd from
/// PollDesc pointers (cf. netpoll_epoll.go:36 `&netpollEventFd`).
static EVENTFD_FD: AtomicI32 = AtomicI32::new(-1);

/// Coalesces concurrent netpoll_break() calls. Set to 1 when a wakeup
/// is in flight; cleared after netpoll consumes the eventfd value.
static WAKE_SIG: AtomicI32 = AtomicI32::new(0);

/// Init guard — set once by `init()`, idempotent.
static INIT: SpinLock<bool> = SpinLock::new(false);

// ─── lifecycle counters ──────────────────────────────────────────────
//
// Post-M27k there is no leak — PollDescs are owned by `Arc<PollDesc>`
// and freed when the last Arc clone drops. These counters expose the
// flow:
//
//   PD_LIVE      — currently allocated (non-dropped). Equivalent to
//   the registry's slab-occupancy count plus any in-flight clones the
//   poll loop is holding. Drops to zero when all conns close.
//
//   PD_TOTAL_OPENS — monotonic count of every `open()` call that
//   succeeded with EPOLL_CTL_ADD. Telemetry only.
//
//   PD_RECYCLED  — count of opens that reused a freed slot index
//   (slab grew once, then indices recycle). Indicates `Vec` capacity
//   reuse, not memory reuse — every open allocates a fresh
//   `Arc<PollDesc>`.
//
// All Relaxed: observability only, not used for safety invariants.
static PD_LIVE: AtomicUsize = AtomicUsize::new(0);
static PD_TOTAL_OPENS: AtomicUsize = AtomicUsize::new(0);
static PD_RECYCLED: AtomicUsize = AtomicUsize::new(0);

/// Currently allocated PollDescs (Arc<PollDesc> instances). Drops to
/// zero after all conns close — no leak.
pub fn live_count() -> usize {
    PD_LIVE.load(Ordering::Relaxed)
}

/// Monotonic total of all successful `open()` calls. Useful for
/// telemetry (load over time) and for the recycle hit ratio.
pub fn total_opens_count() -> usize {
    PD_TOTAL_OPENS.load(Ordering::Relaxed)
}

/// Count of opens that reused a freed slot index (slab capacity
/// reuse). `recycled_count() / total_opens_count()` is the cache hit
/// ratio for the slab's `Vec<u32>` free index list.
pub fn recycled_count() -> usize {
    PD_RECYCLED.load(Ordering::Relaxed)
}

/// Estimated bytes currently held by live PollDescs. Bounded by
/// peak concurrency, drops to zero when all conns close.
pub fn live_bytes() -> usize {
    live_count() * core::mem::size_of::<PollDesc>()
}

// ─── PollDesc registry (M27k slab) ───────────────────────────────────
//
// Idiomatic Rust replacement for Go's never-free pollCache. Mirrors
// async-io's Reactor.sources slab (smol-rs/async-io reactor.rs). Each
// PollDesc lives in an `Arc<PollDesc>`; the slab owns one strong
// reference per registered fd. `event.data` carries the slab INDEX
// (not a raw pointer), so concurrent `close()` is safe: it removes
// the slab's Arc, dropping the count by one. If `poll()` already
// cloned the Arc for an in-flight event, that clone keeps the
// PollDesc alive until it's processed; once all clones drop the
// PollDesc is freed.
//
// Why this beats Go's design: Go uses `persistentalloc` for pollDescs
// (never returned to the OS) plus tagged-pointer fdseq for stale-event
// filtering. We get both safety AND clean reclamation by separating
// the *index* (stable, fits in a u32) from the *pointer* (Rust-managed
// via Arc). The fdseq tag is still useful — protects against the
// short window between EPOLL_CTL_DEL and the slab.remove() during
// which a recycled-index event could otherwise alias.
struct RegistryInner {
    slots: Vec<Option<Arc<PollDesc>>>,
    /// Free slot indices, popped on insert.
    free: Vec<u32>,
}

static REGISTRY: SpinLock<RegistryInner> = SpinLock::new(RegistryInner {
    slots: Vec::new(),
    free: Vec::new(),
});

/// Insert `arc` into the slab; return the assigned slot index. The
/// slab takes one strong reference (clone); caller's `arc` is
/// untouched.
fn registry_insert(arc: &Arc<PollDesc>) -> u32 {
    let mut g = REGISTRY.lock();
    if let Some(idx) = g.free.pop() {
        g.slots[idx as usize] = Some(arc.clone());
        PD_RECYCLED.fetch_add(1, Ordering::Relaxed);
        idx
    } else {
        let idx = g.slots.len() as u32;
        g.slots.push(Some(arc.clone()));
        idx
    }
}

/// Remove the slab's Arc clone for `idx`. Returns the removed Arc
/// (caller may drop it immediately, or hold to extend the lifetime).
fn registry_remove(idx: u32) -> Option<Arc<PollDesc>> {
    let mut g = REGISTRY.lock();
    let i = idx as usize;
    if i >= g.slots.len() {
        return None;
    }
    let removed = g.slots[i].take();
    if removed.is_some() {
        g.free.push(idx);
    }
    removed
}

/// Look up the Arc for `idx` and clone it. Returns None if the slot
/// has been closed (slab took() the entry).
fn registry_get(idx: u32) -> Option<Arc<PollDesc>> {
    let g = REGISTRY.lock();
    let i = idx as usize;
    if i >= g.slots.len() {
        return None;
    }
    g.slots[i].clone()
}

/// Look up a `Weak<PollDesc>` for `idx`. Used by the deadline heap so
/// pending entries don't keep the PollDesc alive past close.
fn registry_get_weak(idx: u32) -> Option<Weak<PollDesc>> {
    let g = REGISTRY.lock();
    let i = idx as usize;
    if i >= g.slots.len() {
        return None;
    }
    g.slots[i].as_ref().map(Arc::downgrade)
}

// ─── event.data layout ───────────────────────────────────────────────
//
// `event.data` is a 64-bit cookie the kernel echoes back from
// EPOLL_CTL_ADD on every event. We split it so a single equality
// check against `eventfd_tag()` works AND we never alias with a
// userspace-pointer-shaped value (the eventfd discriminator is
// `&EVENTFD_FD as u64`, which has bits [48..] all zero on Linux):
//
//   bit  [48]     — `1` for slab events, `0` for the eventfd. This
//                   is the cheap discriminator: any `data` with bit
//                   48 set is a slab event, period.
//   bits [32..48] — fdseq tag (low 16 bits of pd.fdseq) for stale-
//                   event filtering across the EPOLL_CTL_DEL ↔
//                   slab.take() window.
//   bits [0..32]  — slot index (u32 from REGISTRY).
//   bits [49..64] — reserved (zero).
//
// The fdseq tag is no longer strictly required for safety (the slab
// take() makes the slot lookup return None, so the deref simply never
// happens), but it's a cheap fast-path filter for the brief window
// where EPOLL_CTL_DEL has fired but slab.take() hasn't — and it costs
// only 16 bits.
const SLOT_MASK: u64 = 0xFFFF_FFFF;
const FDSEQ_MASK: u64 = 0xFFFF;
const FDSEQ_SHIFT: u32 = 32;
const SLAB_DISCRIMINATOR: u64 = 1u64 << 48;

#[inline]
fn pack_event_data(slot: u32, fdseq: u32) -> u64 {
    SLAB_DISCRIMINATOR | (slot as u64) | (((fdseq as u64) & FDSEQ_MASK) << FDSEQ_SHIFT)
}

#[inline]
fn unpack_slot(data: u64) -> u32 {
    (data & SLOT_MASK) as u32
}

#[inline]
fn unpack_tag(data: u64) -> u32 {
    ((data >> FDSEQ_SHIFT) & FDSEQ_MASK) as u32
}

// ─── init / open / close ─────────────────────────────────────────────

/// One-time poller init. Creates the epoll fd and the eventfd, and
/// registers the eventfd for EPOLLIN. Called lazily on first
/// `open(fd)`. Idempotent — safe to call from multiple Ms.
pub fn init() {
    let mut g = INIT.lock();
    if *g {
        return;
    }

    let epfd = syscall::EpollCreate1(syscall::O_CLOEXEC);
    if epfd < 0 {
        panic!("netpoll: epoll_create1 failed");
    }
    let efd = syscall::Eventfd(0, syscall::EFD_CLOEXEC | syscall::EFD_NONBLOCK);
    if efd < 0 {
        let _ = syscall::Close(epfd);
        panic!("netpoll: eventfd2 failed");
    }

    // Register the eventfd with EPOLLIN (level-triggered is fine —
    // we drain to zero each time, matching Go).
    let mut ev = syscall::EpollEvent {
        events: syscall::EPOLLIN,
        data: eventfd_tag(),
    };
    let r = syscall::EpollCtl(epfd, syscall::EPOLL_CTL_ADD, efd, &mut ev);
    if r < 0 {
        let _ = syscall::Close(efd);
        let _ = syscall::Close(epfd);
        panic!("netpoll: epoll_ctl(eventfd) failed");
    }

    EVENTFD_FD.store(efd, Ordering::Release);
    EPFD.store(epfd, Ordering::Release);
    *g = true;
}

/// Tag value stored in `EpollEvent.data` for the netpollBreak eventfd.
/// Mirrors Go's `*(**uintptr)(...) = &netpollEventFd` — the address of
/// a unique static is used as the discriminator (cf. netpoll_epoll.go:36).
#[inline]
fn eventfd_tag() -> u64 {
    &EVENTFD_FD as *const AtomicI32 as u64
}

/// Register `fd` with the poller and return an owning `Arc<PollDesc>`
/// the caller (net::Listener / net::Conn) holds for the lifetime of
/// the registration. On failure, returns `None`.
///
/// **Memory lifetime — Rust-managed.** `PollDesc` is owned by
/// `Arc<PollDesc>`. The slab (`REGISTRY`) holds one strong reference
/// per registered fd; the caller's returned Arc is the second. When
/// `close()` is called, the slab releases its clone; once the caller
/// drops their Arc and any in-flight `poll()` clone drops too, the
/// PollDesc is freed. No leak. (Compare async-io's `Reactor.sources:
/// Mutex<Slab<Arc<Source>>>` — same pattern.)
///
/// Stale-event filtering uses `pd.fdseq` (low 16 bits embedded in
/// `event.data`); see the layout doc above.
///
/// `fd` should already be `O_NONBLOCK` — the caller arranges that via
/// SOCK_NONBLOCK in socket()/accept4() or fcntl(F_SETFL).
pub fn open(fd: i32) -> Option<Arc<PollDesc>> {
    if EPFD.load(Ordering::Acquire) < 0 {
        init();
    }

    // Allocate a fresh PollDesc, register it in the slab. `Arc::new`
    // gives strong=1; `registry_insert` clones to strong=2 (caller +
    // slab).
    let arc = Arc::new(PollDesc::new(fd));
    let slot = registry_insert(&arc);
    arc.slot.store(slot, Ordering::Release);

    let fdseq = arc.fdseq.load(Ordering::Relaxed);
    let mut ev = syscall::EpollEvent {
        events: syscall::EPOLLIN
            | syscall::EPOLLOUT
            | syscall::EPOLLRDHUP
            | syscall::EPOLLET,
        data: pack_event_data(slot, fdseq),
    };
    let r = syscall::EpollCtl(
        EPFD.load(Ordering::Acquire),
        syscall::EPOLL_CTL_ADD,
        fd,
        &mut ev,
    );
    if r < 0 {
        // Registration failed — undo the slab insert. The two Arc
        // references (caller's + slab's) both drop; PollDesc freed.
        let _ = registry_remove(slot);
        return None;
    }
    PD_LIVE.fetch_add(1, Ordering::Relaxed);
    PD_TOTAL_OPENS.fetch_add(1, Ordering::Relaxed);
    Some(arc)
}

/// Unregister `pd` from the poller and release the slab's strong
/// reference. The caller's Arc is consumed; if no `poll()` iteration
/// is currently holding a clone, the PollDesc is freed at the end of
/// this call. Otherwise it's freed when the last in-flight clone
/// drops. Caller still owns the fd — `close(2)` on the fd is the
/// caller's responsibility.
pub fn close(pd: Arc<PollDesc>) {
    let slot = pd.slot.load(Ordering::Acquire);
    // Best-effort EPOLL_CTL_DEL — the kernel may have already removed
    // the registration if the fd was closed.
    let fd = pd.fd.load(Ordering::Relaxed);
    let mut ev = syscall::EpollEvent { events: 0, data: 0 };
    let _ = syscall::EpollCtl(
        EPFD.load(Ordering::Acquire),
        syscall::EPOLL_CTL_DEL,
        fd,
        &mut ev,
    );
    // Bump fdseq BEFORE removing from the slab. Any in-flight epoll
    // event still referring to this slot via the old fdseq tag will
    // fail the tag check in poll() and self-discard.
    pd.fdseq.fetch_add(1, Ordering::AcqRel);
    // Bump rseq + wseq so any pending deadline-heap entries for this
    // pd no longer match — sysmon will pop and discard them.
    pd.rseq.fetch_add(1, Ordering::AcqRel);
    pd.wseq.fetch_add(1, Ordering::AcqRel);
    // PD_LIVE is decremented in `Drop for PollDesc`, not here — that
    // way an in-flight poll() clone keeps the count accurate.
    // Drop the slab's clone. Future `registry_get(slot)` returns None;
    // the slot index is freed for reuse by a later `open()`.
    let _slab_arc = registry_remove(slot);
    drop(_slab_arc);
    // Caller's Arc drops at end of fn — together with the slab drop
    // above, that brings the strong count down by 2. If `poll()` is
    // not currently iterating an event for this slot, count = 0 and
    // the PollDesc is freed here. Otherwise it's freed when poll's
    // clone drops at the end of its event-processing loop.
    drop(pd);
}

// ─── block / unblock ─────────────────────────────────────────────────

/// Pick the right slot for `mode`. `b'r'` → rg, anything else → wg.
#[inline]
fn slot(pd: &PollDesc, mode: u8) -> &AtomicUsize {
    if mode == b'r' { &pd.rg } else { &pd.wg }
}

/// Park the current goroutine on `pd.{rg,wg}` for I/O readiness.
/// Mirrors Go's `netpollblock` (netpoll.go:548).
///
/// Concurrent `block` in the same mode is undefined behavior (Go
/// panics "double wait"). For Conn this is naturally enforced.
pub fn block(pd: &PollDesc, mode: u8) -> BlockResult {
    // Pre-park deadline check. If the deadline already expired, skip
    // park and return Timedout — saves a context switch and matches
    // Go's `netpollcheckerr` running before `gopark` (netpoll.go:574).
    let dl = if mode == b'r' { &pd.rd } else { &pd.wd };
    if dl.load(Ordering::Acquire) < 0 {
        return BlockResult::Timedout;
    }

    let gpp = slot(pd, mode);

    // Set gpp from PD_NIL to PD_WAIT, consuming any pdReady fast-path.
    loop {
        if gpp
            .compare_exchange(PD_READY, PD_NIL, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return BlockResult::Ready;
        }
        if gpp
            .compare_exchange(PD_NIL, PD_WAIT, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
        let v = gpp.load(Ordering::Acquire);
        if v != PD_READY && v != PD_NIL {
            // Either PD_WAIT (concurrent block — caller misuse) or a
            // stale G pointer (impossible — we never park without
            // first transitioning Wait→Nil on resume).
            panic!("netpoll: double wait");
        }
    }

    // Park: park-commit fn CASes PD_WAIT → G ptr. If a concurrent
    // unblock raced us to PD_READY, the CAS in the commit fails and
    // gopark aborts; we proceed to the swap-cleanup below either way.
    gopark(
        netpoll_block_commit,
        gpp as *const AtomicUsize as *const AtomicBool,
    );

    // Resumed. Race-cleanup: if we slept (G ptr stored) the unblock
    // path overwrote it with PD_READY (ioready) or PD_NIL (deadline).
    // If commit aborted, slot still has PD_WAIT. Drain to PD_NIL.
    let old = gpp.swap(PD_NIL, Ordering::AcqRel);
    if old > PD_WAIT {
        panic!("netpoll: corrupted polldesc");
    }
    if old == PD_READY {
        return BlockResult::Ready;
    }
    // Slot resolved to PD_NIL: either a deadline-fire unblock or a
    // future cancel path. Distinguish by inspecting the deadline.
    if dl.load(Ordering::Acquire) < 0 {
        BlockResult::Timedout
    } else {
        BlockResult::Aborted
    }
}

/// gopark commit fn for `block`. The waiting slot's address was
/// stashed in `M::waitlock` (cast through `*const AtomicBool`).
/// CAS PD_WAIT → G ptr; success means the park is committed and we
/// keep waiting. Failure means a concurrent unblock raced us to
/// PD_READY — abort, the G is requeued runnable.
unsafe fn netpoll_block_commit(g: NonNull<G>) -> bool {
    // Read from the M without taking its SpinLock — we're between
    // gopark's `releasem()` and `mcall`, so we still own this M.
    let m = current_m();
    let gpp_ptr = unsafe { m.data_unchecked() }.waitlock as *const AtomicUsize;
    if gpp_ptr.is_null() {
        return false;
    }
    let gpp = unsafe { &*gpp_ptr };
    gpp.compare_exchange(
        PD_WAIT,
        g.as_ptr() as usize,
        Ordering::AcqRel,
        Ordering::Acquire,
    )
    .is_ok()
}

/// Move `pd.{rg,wg}` to PD_READY (or PD_NIL on close). Returns the
/// G that was parked, if any, so the caller can push it onto a
/// runnable list. Mirrors Go's `netpollunblock` (netpoll.go:591).
fn unblock(pd: &PollDesc, mode: u8, ioready: bool) -> Option<NonNull<G>> {
    let gpp = slot(pd, mode);
    loop {
        let old = gpp.load(Ordering::Acquire);
        if old == PD_READY {
            return None;
        }
        if old == PD_NIL && !ioready {
            // Only set pdReady on a real I/O event; "close" with no
            // parker is a no-op (poll_runtime_pollWait checks errors
            // before parking again).
            return None;
        }
        let new = if ioready { PD_READY } else { PD_NIL };
        if gpp
            .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            if old == PD_NIL || old == PD_WAIT {
                return None;
            }
            // old > PD_WAIT — it's a parked G pointer.
            return NonNull::new(old as *mut G);
        }
    }
}

// ─── poll / netpoll_break ────────────────────────────────────────────

/// Poll the epoll fd for ready descriptors. Returns the list of
/// goroutines that became runnable. `delay_ms`:
///   `< 0` — block indefinitely (sysmon never uses this in v1).
///   `== 0` — non-blocking sweep (the hot find_runnable path).
///   `> 0` — block up to `delay_ms` milliseconds.
///
/// Mirrors Go's `netpoll(delay int64) (gList, int32)`
/// (netpoll_epoll.go:99). Returned Vec is heap-alloc only when the
/// poll produces results — the empty case allocates zero.
#[allow(non_upper_case_globals)]
pub fn poll(delay_ms: i32) -> Vec<NonNull<G>> {
    let epfd = EPFD.load(Ordering::Acquire);
    if epfd < 0 {
        return Vec::new();
    }
    const MAX_EVENTS: usize = 128;
    let mut events: [syscall::EpollEvent; MAX_EVENTS] =
        [syscall::EpollEvent { events: 0, data: 0 }; MAX_EVENTS];
    let n = syscall::EpollPwait(
        epfd,
        events.as_mut_ptr(),
        MAX_EVENTS as i32,
        delay_ms,
        ptr::null(),
        0,
    );
    if n <= 0 {
        // 0 = timeout, <0 = -errno (EINTR usually). Either way return
        // empty; callers treat as "nothing to do this round".
        return Vec::new();
    }
    let mut to_run: Vec<NonNull<G>> = Vec::new();
    let evtag = eventfd_tag();
    for i in 0..n as usize {
        let ev = events[i];
        let data = ev.data;
        let evbits = ev.events;
        if evbits == 0 {
            continue;
        }
        // The eventfd is registered with `data = &EVENTFD_FD as u64`
        // (no fdseq tag, top bits zero), so the equality check works
        // identically with or without tagging.
        if data == evtag {
            // Drain the eventfd counter (8-byte read).
            if delay_ms != 0 {
                let mut one: u64 = 0;
                let _ = syscall::Read(
                    EVENTFD_FD.load(Ordering::Acquire),
                    &mut one as *mut u64 as *mut u8,
                    8,
                );
                WAKE_SIG.store(0, Ordering::Release);
            }
            continue;
        }
        // M27k: look up the Arc<PollDesc> by slot index. If the slot
        // is None, the registration was closed since this event was
        // queued — drop the event. The Arc clone we get back keeps
        // the PollDesc alive for the duration of this iteration even
        // if a concurrent close() removes the slab entry.
        let slot = unpack_slot(data);
        let event_tag = unpack_tag(data);
        let arc = match registry_get(slot) {
            Some(a) => a,
            None => continue,
        };
        // Fast-path stale-event filter for the EPOLL_CTL_DEL ↔
        // slab.take() window: if fdseq was bumped since this event
        // was registered, the underlying fd has been closed (and
        // possibly the slot reused). Drop the event.
        let live_tag = arc.fdseq.load(Ordering::Acquire) & (FDSEQ_MASK as u32);
        if event_tag != live_tag {
            continue;
        }
        let pd: &PollDesc = &arc;
        if evbits
            & (syscall::EPOLLIN
                | syscall::EPOLLRDHUP
                | syscall::EPOLLHUP
                | syscall::EPOLLERR)
            != 0
        {
            if let Some(g) = unblock(pd, b'r', true) {
                to_run.push(g);
            }
        }
        if evbits & (syscall::EPOLLOUT | syscall::EPOLLHUP | syscall::EPOLLERR) != 0 {
            if let Some(g) = unblock(pd, b'w', true) {
                to_run.push(g);
            }
        }
        // `arc` drops here — strong count goes back to its
        // pre-event-iteration value.
    }
    to_run
}

/// Wake a blocked `poll(>0 or <0)` call. Coalesces — concurrent
/// breaks past the first are no-ops until netpoll drains the eventfd.
/// Mirrors `netpollBreak` (netpoll_epoll.go:67).
pub fn netpoll_break() {
    if WAKE_SIG
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return; // wakeup already in flight
    }
    let efd = EVENTFD_FD.load(Ordering::Acquire);
    if efd < 0 {
        return;
    }
    let one: u64 = 1;
    let n = syscall::Write(efd, &one as *const u64 as *const u8, 8);
    if n != 8 {
        // EAGAIN (11) on a full counter is fine — something else
        // already wrote to it and netpoll will pick it up. EINTR (4)
        // is also benign. Anything else is unrecoverable.
        const EINTR: isize = 4;
        const EAGAIN: isize = 11;
        if n != -EAGAIN && n != -EINTR {
            panic!("netpoll: eventfd write failed");
        }
    }
}

// ─── Deadlines ────────────────────────────────────────────────────────
//
// V1 deadline strategy: a single global min-heap of `(deadline_ns,
// pd, mode, seq)` entries, scanned by sysmon's tick. Each entry's
// `seq` is matched against `pd.{rseq,wseq}` at fire time — stale
// entries (deadline reset, deadline cleared, fd closed before fire)
// are silently dropped.
//
// Trade vs. Go's per-pd `pd.rt`/`pd.wt` timer objects: simpler (no
// per-pd timer init/stop), uses sysmon's existing tick instead of a
// dedicated timer-fire path. Cost: heap entries accumulate at one
// per `set_deadline` call until they fire — for HTTP keep-alive (one
// SetReadDeadline per request), this is bounded by request rate
// times max keep-alive timeout.

/// One pending deadline.
///
/// **Lifetime safety**: `pd` is a `Weak<PollDesc>`. If the underlying
/// PollDesc has been freed (last Arc clone dropped after close), the
/// `weak.upgrade()` in `fire_expired_deadlines` returns `None` and the
/// entry self-discards. Otherwise we get a fresh `Arc<PollDesc>`
/// holding the PollDesc alive for the duration of the wake. Stale
/// entries (deadline reset/cleared since push) are filtered by `seq`
/// mismatch as before — `netpoll::close` bumps both `rseq` and `wseq`
/// on the way out, so any pending entries for a closed fd whose
/// PollDesc happens to still be alive (because someone holds the Arc)
/// also self-discard via the seq mismatch.
struct DeadlineEntry {
    deadline_ns: i64,
    pd: Weak<PollDesc>,
    mode: u8, // b'r' or b'w'
    seq: u32,
}

impl PartialEq for DeadlineEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline_ns == other.deadline_ns
    }
}
impl Eq for DeadlineEntry {}
impl Ord for DeadlineEntry {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.deadline_ns.cmp(&other.deadline_ns)
    }
}
impl PartialOrd for DeadlineEntry {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

static DEADLINE_HEAP: SpinLock<BinaryHeap<Reverse<DeadlineEntry>>> =
    SpinLock::new(BinaryHeap::new());

/// Set or clear a read/write deadline on `pd`.
///
/// `deadline_ns == 0` clears the deadline (no expiration).
/// `deadline_ns > 0` is a CLOCK_MONOTONIC nanosecond timestamp at
/// which the corresponding parker wakes with `BlockResult::Timedout`.
/// `deadline_ns < 0` immediately expires (block returns Timedout
/// without parking).
///
/// Mirrors Go's `poll_runtime_pollSetDeadline` (netpoll.go:371) — but
/// without timer modify/stop (we push a new heap entry each call and
/// rely on `seq` to invalidate stale entries).
pub fn set_deadline(pd: &PollDesc, deadline_ns: i64, mode: u8) {
    let (dl, seq) = if mode == b'r' {
        (&pd.rd, &pd.rseq)
    } else {
        (&pd.wd, &pd.wseq)
    };

    // Bump seq so any in-flight stale heap entry stops matching.
    seq.fetch_add(1, Ordering::AcqRel);

    if deadline_ns == 0 {
        dl.store(0, Ordering::Release);
        return;
    }
    if deadline_ns < 0 {
        // Past deadline → mark expired and unblock any current parker
        // immediately so it returns Timedout on resume.
        dl.store(-1, Ordering::Release);
        if let Some(g) = unblock(pd, mode, false) {
            goready(g);
        }
        return;
    }

    dl.store(deadline_ns, Ordering::Release);
    // Resolve a Weak<PollDesc> via the slab. This avoids burdening
    // callers with passing the Arc through, and the Weak naturally
    // self-invalidates if the PollDesc is freed before the deadline
    // fires.
    let slot = pd.slot.load(Ordering::Acquire);
    let weak = match registry_get_weak(slot) {
        Some(w) => w,
        // Slot was already removed (close raced this set_deadline) —
        // nothing to do; any parker on this pd will see the dl<0
        // store and timeout on its own.
        None => return,
    };
    let entry = DeadlineEntry {
        deadline_ns,
        pd: weak,
        mode,
        seq: seq.load(Ordering::Acquire),
    };
    DEADLINE_HEAP.lock().push(Reverse(entry));
}

/// Fire all deadlines that expired at or before `now`. Called from
/// sysmon's main tick (alongside the timer-heap scan). Stale entries
/// (whose pd.{rseq,wseq} no longer matches the entry's seq, or whose
/// pd.rd/wd was reset to a future value) are popped and discarded.
///
/// Mirrors Go's `netpolldeadlineimpl` (netpoll.go:622) per-fire body
/// driven by a heap pop loop instead of per-pd timers.
pub fn fire_expired_deadlines(now: i64) {
    loop {
        let popped: Option<DeadlineEntry> = {
            let mut heap = DEADLINE_HEAP.lock();
            match heap.peek() {
                Some(Reverse(entry)) if entry.deadline_ns <= now => {
                    heap.pop().map(|r| r.0)
                }
                _ => return,
            }
        };
        let entry = match popped {
            Some(e) => e,
            None => return,
        };
        // M27k: Weak::upgrade returns None if the PollDesc was freed
        // since the entry was pushed (caller closed the conn / dropped
        // their Arc). In that case the deadline is moot — drop it.
        let arc = match entry.pd.upgrade() {
            Some(a) => a,
            None => continue,
        };
        let pd: &PollDesc = &arc;
        let (dl, seq) = if entry.mode == b'r' {
            (&pd.rd, &pd.rseq)
        } else {
            (&pd.wd, &pd.wseq)
        };
        // The seq counter discriminates: bumped by `set_deadline`
        // (deadline replaced/cleared) and by `close` (fd closed → all
        // pending deadlines for this pd self-discard).
        if seq.load(Ordering::Acquire) != entry.seq {
            continue;
        }
        // Mark expired and wake the parked G (if any).
        dl.store(-1, Ordering::Release);
        if let Some(g) = unblock(pd, entry.mode, false) {
            goready(g);
        }
    }
}
