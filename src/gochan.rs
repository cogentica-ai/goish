// gochan — Go's `chan` type and operations.
//
// User-facing API (made via `make!(chan T)` or `make!(chan T, cap)`):
//
//     ch.Send(v)                 // c <- v
//     let (v, ok) = ch.Recv();   // v, ok := <-c
//     ch.Close();                // close(c)
//     ch.Len()                   // len(c)
//     ch.Cap()                   // cap(c)
//
// Both unbuffered (cap=0) and buffered (cap>0) channels share one
// implementation: the same `Hchan<T>` carries a `cap: usize` and a
// `VecDeque<T>` ring buffer (empty when cap=0). Slow paths around
// `gopark`/`goready` are identical to the unbuffered case from
// M16d; the new fast paths added here for cap>0 are:
//
//   - **send into a non-full buffer**: push to tail, no park, no
//     wakeup. Returns immediately.
//   - **recv from a non-empty buffer**: pop from head. Returns
//     immediately.
//   - **recv with full buffer + parked sender**: pop head for the
//     receiver, push sender's value to tail (filling the slot the
//     receiver just freed), and `goready` the sender. This
//     preserves Go's FIFO semantics across the wraparound.
//
// Send/Recv ordering preferences (mirror runtime/chan.go):
//
//   - **Send**: parked receiver > buffer space > park
//   - **Recv**: closed-and-empty > parked sender > non-empty buf > park
//
// The "parked receiver beats buffer space" preference matters for
// strict FIFO ordering on heavily-contended channels. The "parked
// sender beats non-empty buffer" preference is what makes buffered
// channels with full buffers act like unbuffered ones from the
// receiver's perspective.
//
// ─── Internal layout for select! ──────────────────────────────────
//
// `Send`/`Recv` are thin wrappers over five lower-level helpers that
// the upcoming `select!` macro composes:
//
//   __try_send(v)        try-without-park; Ok | Err(v) | panic
//   __try_recv()         try-without-park; Some((v,ok)) | None
//   __register_send(sg)  enqueue parked sender; false on closed
//   __register_recv(sg)  enqueue parked receiver; Err on closed-empty
//   __cancel_send(sg)    drop a no-longer-needed sudog from sendq
//   __cancel_recv(sg)    drop a no-longer-needed sudog from recvq
//
// Helpers acquire the chan's lock for the duration of one operation
// only. In cooperative single-M scheduling, no other goroutine runs
// between successive helper calls on the same channel, so a
// select-pass-1 loop calling __try_* across N chans is race-free
// without holding all locks simultaneously. (Multi-M support — M17a —
// will need a global lock-order sort, see M16f-β.)

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate alloc;

use crate::runtime::lockfree_ring::LockFreeRing;
use alloc::sync::Arc;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::runtime::sched::{
    block_forever_commit, chan_park_commit, current_g, gopark, goready, G,
};
use crate::runtime::spin::{raw_lock, raw_unlock, SpinLock};
use crate::syscall;

/// Per-`select!` shared coordination state. Lives on the parking
/// goroutine's stack frame for the lifetime of one select. Every
/// sudog registered by that select carries a `NonNull<SelectCoord>`
/// pointing here; plain `Send`/`Recv` sudogs use `coord = None`.
///
/// The `done` flag is the winner-take-all latch: the first waker
/// that pops a select sudog and CAS-flips `done` from `false` to
/// `true` is the unique case that fires. Subsequent wakers that pop
/// stale select sudogs from other channels see `done == true`,
/// discard the sudog, and continue scanning their queue (or fall
/// through to buffer/closed paths).
///
/// Mirrors the role of `gp.selectDone` in Go's runtime/select.go,
/// just relocated from the G to the per-select struct because goish
/// doesn't carry a free wakeup slot on G (sudogs are stack-owned by
/// the parking G, so the wakee identifies the winner by scanning
/// its own sudogs' `success` bits — no `gp.param` needed).
#[doc(hidden)]
pub struct SelectCoord {
    #[doc(hidden)]
    pub done: AtomicBool,
}

impl SelectCoord {
    #[allow(dead_code)] // wired up in M16f-α step 4 (select! macro)
    #[doc(hidden)]
    pub fn new() -> Self {
        SelectCoord {
            done: AtomicBool::new(false),
        }
    }
}

/// Wait-list entry for a parked goroutine. Lives on the stack of
/// the goroutine that's parking.
///
/// **Intrusive queue links** (zero-alloc port — task #110 followup):
/// `next` / `prev` thread the sudog into the chan's `sendq` /
/// `recvq` doubly-linked lists, replacing the heap-allocated
/// `VecDeque<NonNull<Sudog<T>>>`. Push, pop, and mid-list cancel
/// (select pass-3) all run in O(1) under the chan lock with zero
/// allocator round-trips. Mirrors Go's `sudog.next` / `prev`
/// (runtime/runtime2.go:335).
#[doc(hidden)]
pub struct Sudog<T> {
    #[doc(hidden)]
    pub g: NonNull<G>,
    /// Send sudog: starts `Some(value)`, taken by a matching
    /// receiver. Recv sudog: starts `None`, filled by a matching
    /// sender.
    #[doc(hidden)]
    pub value: Option<T>,
    /// True on a successful handoff; false on a close-induced
    /// wakeup.
    #[doc(hidden)]
    pub success: bool,
    /// `Some(coord)` if this sudog belongs to a `select!`; `None`
    /// for plain `Send`/`Recv`. Wakers consult `coord.done` via CAS
    /// before firing; on a stale sudog the CAS fails and the waker
    /// must skip this entry and try the next.
    #[doc(hidden)]
    pub coord: Option<NonNull<SelectCoord>>,
    /// Intrusive queue link (sendq / recvq successor). Null when
    /// the sudog is at the tail or unqueued. Only mutated under the
    /// owning chan's `state` SpinLock.
    #[doc(hidden)]
    pub next: *mut Sudog<T>,
    /// Intrusive queue link (sendq / recvq predecessor). Null when
    /// at the head or unqueued. Same lock discipline as `next`.
    #[doc(hidden)]
    pub prev: *mut Sudog<T>,
}

impl<T> Sudog<T> {
    /// Build a non-select send sudog carrying `v`.
    #[doc(hidden)]
    pub fn new_send(g: NonNull<G>, v: T) -> Self {
        Sudog {
            g,
            value: Some(v),
            success: false,
            coord: None,
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
        }
    }

    /// Build a non-select recv sudog (empty value slot).
    #[doc(hidden)]
    pub fn new_recv(g: NonNull<G>) -> Self {
        Sudog {
            g,
            value: None,
            success: false,
            coord: None,
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
        }
    }

    /// Build a select-bound send sudog carrying `v`. The waker that
    /// pops this sudog must succeed at `coord.done` CAS to fire it.
    #[allow(dead_code)] // wired up in M16f-α step 4 (select! macro)
    #[doc(hidden)]
    pub fn new_send_select(g: NonNull<G>, v: T, coord: NonNull<SelectCoord>) -> Self {
        Sudog {
            g,
            value: Some(v),
            success: false,
            coord: Some(coord),
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
        }
    }

    /// Build a select-bound recv sudog. CAS-gated like its send peer.
    #[allow(dead_code)] // wired up in M16f-α step 4 (select! macro)
    #[doc(hidden)]
    pub fn new_recv_select(g: NonNull<G>, coord: NonNull<SelectCoord>) -> Self {
        Sudog {
            g,
            value: None,
            success: false,
            coord: Some(coord),
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
        }
    }
}

/// Intrusive doubly-linked queue of `Sudog<T>` pointers. All sudogs
/// live on parking goroutines' stacks; this queue just threads them
/// via `next`/`prev`. Zero-alloc replacement for the prior
/// `VecDeque<NonNull<Sudog<T>>>`.
///
/// **Concurrency**: only mutated under the owning chan's
/// `state` SpinLock — same discipline as the prior VecDeque.
#[doc(hidden)]
pub struct SudogQueue<T> {
    head: *mut Sudog<T>,
    tail: *mut Sudog<T>,
}

unsafe impl<T> Send for SudogQueue<T> {}

impl<T> SudogQueue<T> {
    pub const fn new() -> Self {
        SudogQueue {
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.is_null()
    }

    /// Append `sg` to the tail. Caller must hold the chan lock and
    /// guarantee `sg` is not already in any queue.
    pub fn push_back(&mut self, sg: *mut Sudog<T>) {
        unsafe {
            (*sg).next = core::ptr::null_mut();
            (*sg).prev = self.tail;
            if self.tail.is_null() {
                self.head = sg;
            } else {
                (*self.tail).next = sg;
            }
            self.tail = sg;
        }
    }

    /// Pop the head, or return null if empty.
    pub fn pop_front(&mut self) -> *mut Sudog<T> {
        if self.head.is_null() {
            return core::ptr::null_mut();
        }
        let h = self.head;
        unsafe {
            self.head = (*h).next;
            if self.head.is_null() {
                self.tail = core::ptr::null_mut();
            } else {
                (*self.head).prev = core::ptr::null_mut();
            }
            (*h).next = core::ptr::null_mut();
            (*h).prev = core::ptr::null_mut();
        }
        h
    }

    /// Unlink `sg` from this queue using its own `prev` / `next`
    /// fields. Caller must guarantee `sg` is in this queue (not
    /// already popped). O(1).
    pub fn unlink(&mut self, sg: *mut Sudog<T>) {
        unsafe {
            let prev = (*sg).prev;
            let next = (*sg).next;
            if prev.is_null() {
                self.head = next;
            } else {
                (*prev).next = next;
            }
            if next.is_null() {
                self.tail = prev;
            } else {
                (*next).prev = prev;
            }
            (*sg).next = core::ptr::null_mut();
            (*sg).prev = core::ptr::null_mut();
        }
    }

    /// Walk the queue looking for `sg`; if found, unlink and return
    /// true. Used by `__cancel_*` to distinguish select winner from
    /// loser. O(N) in the queue length.
    pub fn cancel(&mut self, sg: *mut Sudog<T>) -> bool {
        unsafe {
            let mut cur = self.head;
            while !cur.is_null() {
                if cur == sg {
                    self.unlink(cur);
                    return true;
                }
                cur = (*cur).next;
            }
        }
        false
    }
}

unsafe impl<T> Send for Sudog<T> {}
unsafe impl<T> Sync for Sudog<T> {}

/// Outcome of `__register_send_locked` / `__register_recv_locked`.
/// `select!` pass-2 dispatches on this to decide whether to plant a
/// sudog, treat the case as permanently dormant (nil chan), or
/// signal a closed-chan race.
#[doc(hidden)]
pub enum RegisterStatus {
    /// Sudog enqueued on the chan's wait queue. Pass-3 must cancel
    /// it after wake.
    Registered,
    /// Chan is nil — case is permanently not-ready; no sudog
    /// enqueued, no cancel needed in pass-3.
    Skip,
    /// Chan is closed. For send: panic-worthy. For recv: should
    /// have been caught in pass-1 try_recv (closed-and-empty);
    /// reaching here in pass-2 indicates a multi-M race where the
    /// chan was closed under the held lock — unreachable in
    /// practice since the lock is held continuously.
    Closed,
}

/// Lock-protected channel state.
#[doc(hidden)]
pub struct HchanState<T> {
    closed: bool,
    /// Buffer capacity. 0 = unbuffered.
    cap: usize,
    /// Ring buffer of in-flight values. For cap=0 (unbuffered) the
    /// ring exists with capacity 1 but is never used (buf hand-off
    /// goes directly via sudog). For cap>0, length is in `[0, cap]`.
    /// Storage migrated from `VecDeque<T>` to the lock-free MPMC
    /// ring as Stage 1 of the chan lock-free hot-path refactor.
    /// Stage 1 still holds the SpinLock across all ring ops; Stage 2
    /// will move the ring outside the lock to capture the speedup.
    buf: LockFreeRing<T>,
    /// Goroutines waiting to send.
    sendq: SudogQueue<T>,
    /// Goroutines waiting to receive.
    recvq: SudogQueue<T>,
}

/// Public channel descriptor.
///
/// `nil` is set at construction and never mutates. It corresponds to
/// Go's `var c chan T` zero-value: send/recv block forever; in
/// `select!` the case is filtered out (skipped from lock order, poll
/// order, and pass-2 register). Mirrors runtime/chan.go:177-183 and
/// runtime/select.go:173-177.
pub struct Hchan<T> {
    nil: bool,
    state: SpinLock<HchanState<T>>,
}

unsafe impl<T: Send> Send for Hchan<T> {}
unsafe impl<T: Send> Sync for Hchan<T> {}

/// Go-shaped `chan<T>`. Cloning is cheap (Arc bump). Cloned handles
/// reference the same channel.
pub struct chan<T> {
    inner: Arc<Hchan<T>>,
}

impl<T> Clone for chan<T> {
    fn clone(&self) -> Self {
        chan {
            inner: self.inner.clone(),
        }
    }
}

/// `Default` returns Go's `var c chan T` zero value — a nil chan whose
/// sends/recvs block forever. Required for struct literals that use
/// `..Default::default()` (the common k8s/json idiom in transpiled
/// ports). Mirrors `chan::nil()`.
impl<T> Default for chan<T> {
    fn default() -> Self {
        Self::nil()
    }
}

impl<T> chan<T> {
    /// `make!(chan T)` — unbuffered channel (cap=0).
    pub fn new_unbuffered() -> Self {
        Self::new_buffered(0)
    }

    /// `make!(chan T, cap)` — buffered channel.
    pub fn new_buffered(cap: usize) -> Self {
        chan {
            inner: Arc::new(Hchan {
                nil: false,
                state: SpinLock::new(HchanState {
                    closed: false,
                    cap,
                    // For cap=0, allocate a 1-slot dummy ring (never
                    // touched — buf hand-off bypasses the buffer for
                    // unbuffered chans). The 64 B overhead per
                    // unbuffered chan is negligible.
                    buf: LockFreeRing::new(cap.max(1)),
                    sendq: SudogQueue::new(),
                    recvq: SudogQueue::new(),
                }),
            }),
        }
    }

    /// `var c chan T` — Go's nil chan zero value. Send/Recv block
    /// forever; in `select!` cases referencing a nil chan are
    /// silently skipped (filtered out of the lock order and poll
    /// order). Mirrors runtime/chan.go:177-183.
    pub fn nil() -> Self {
        chan {
            inner: Arc::new(Hchan {
                nil: true,
                state: SpinLock::new(HchanState {
                    closed: false,
                    cap: 0,
                    buf: LockFreeRing::new(1),
                    sendq: SudogQueue::new(),
                    recvq: SudogQueue::new(),
                }),
            }),
        }
    }

    /// `c == nil` predicate. Lock-free; the `nil` flag is set at
    /// construction and never mutates.
    #[doc(hidden)]
    #[inline]
    pub fn is_nil(&self) -> bool {
        self.inner.nil
    }

    /// `len(ch)` — number of values currently in the buffer. Always
    /// 0 for unbuffered channels and nil chans.
    pub fn Len(&self) -> usize {
        if self.inner.nil {
            return 0;
        }
        self.inner.state.lock().buf.len()
    }

    /// `cap(ch)` — buffer capacity (0 for unbuffered and nil).
    pub fn Cap(&self) -> usize {
        if self.inner.nil {
            return 0;
        }
        self.inner.state.lock().cap
    }

    // ─── Raw lock access (M16f-β) ─────────────────────────────────
    //
    // Multi-M-correct `select!` (M16f-β) needs to lock several chans
    // at once via the pre-sorted lock-order, then access each chan's
    // state without holding a typed `Guard<HchanState<T>>` (because
    // multiple chans of different `T` can't coexist in a typed list).
    // These accessors expose the raw atom + an unchecked deref to
    // bridge the gap. All `unsafe`; only `select!`'s expansion uses
    // them, and the macro emits the lock/unlock pairing.

    /// Pointer to the chan's underlying `AtomicBool` lock. Used as
    /// the lock-order sort key (Arc-stable across the chan's
    /// lifetime) and as the operand to `runtime::spin::raw_lock` /
    /// `raw_unlock` in the select macro.
    #[doc(hidden)]
    #[inline]
    pub fn __lock_atom(&self) -> *const core::sync::atomic::AtomicBool {
        self.inner.state.lock_atom()
    }

    /// Access the locked state. **Caller must hold the lock** via
    /// `runtime::spin::raw_lock(self.__lock_atom())`.
    #[doc(hidden)]
    #[inline]
    pub unsafe fn __state_unchecked(&self) -> &mut HchanState<T> {
        self.inner.state.data_unchecked()
    }
}

// ─── Locked-state helpers — same logic as __try_*/__register_*/
//     __cancel_*, but operating on an already-held HchanState.
//     The caller (the select macro) holds all relevant chan locks
//     across pass-1 + pass-2 register, so these helpers must not
//     re-lock.

impl<T> chan<T> {
    /// Locked-state recv. Same semantics as `__try_recv` minus the
    /// chan-lock acquisition. Caller holds `s`'s lock.
    ///
    /// **Note**: only invoked for non-nil chans by `select!` (the
    /// macro filters nil cases at the dispatch site, so nothing
    /// here special-cases nil). Plain `Recv` never reaches the
    /// locked path on nil chans either (the `nil` early-return
    /// happens before lock acquisition).
    #[doc(hidden)]
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub fn __try_recv_locked(s: &mut HchanState<T>) -> Option<(T, bool)>
    where
        T: Default,
    {
        if s.closed && s.buf.len() == 0 {
            return Some((T::default(), false));
        }
        unsafe {
            let mut cur = s.sendq.head;
            while !cur.is_null() {
                let next = (*cur).next;
                let send_ptr = NonNull::new_unchecked(cur);
                if !try_claim_sudog(send_ptr) {
                    cur = next;
                    continue;
                }
                s.sendq.unlink(cur);
                let sender_v = (*cur)
                    .value
                    .take()
                    .expect("recv-locked: sender sudog empty");
                let v = if s.cap == 0 {
                    sender_v
                } else {
                    let head = s
                        .buf
                        .try_recv()
                        .expect("recv-locked: buf empty with parked sender");
                    s.buf
                        .try_send(sender_v)
                        .ok()
                        .expect("buf rotate: ring full though slot just freed");
                    head
                };
                (*cur).success = true;
                let send_g = (*cur).g;
                goready(send_g);
                return Some((v, true));
            }
        }
        if let Some(v) = s.buf.try_recv() {
            return Some((v, true));
        }
        None
    }

    /// Locked-state send. Same semantics as `__try_send` minus the
    /// chan-lock acquisition.
    #[doc(hidden)]
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub fn __try_send_locked(s: &mut HchanState<T>, v: T) -> Result<(), T> {
        if s.closed {
            fatal(b"goish: chan: send on closed channel\n");
        }
        unsafe {
            let mut cur = s.recvq.head;
            while !cur.is_null() {
                let next = (*cur).next;
                let recv_ptr = NonNull::new_unchecked(cur);
                if !try_claim_sudog(recv_ptr) {
                    cur = next;
                    continue;
                }
                s.recvq.unlink(cur);
                (*cur).value = Some(v);
                (*cur).success = true;
                let recv_g = (*cur).g;
                goready(recv_g);
                return Ok(());
            }
        }
        if s.buf.len() < s.cap {
            s.buf
                .try_send(v)
                .ok()
                .expect("buf send: ring full though len < cap");
            return Ok(());
        }
        Err(v)
    }

    /// Locked-state register a recv sudog. Caller holds the chan
    /// lock. Returns `RegisterStatus::Closed` on closed-and-empty,
    /// `Registered` otherwise. `Skip` is unreachable here (nil
    /// chans don't reach the locked path).
    #[doc(hidden)]
    pub fn __register_recv_locked(s: &mut HchanState<T>, sg: &mut Sudog<T>) -> RegisterStatus {
        if s.closed && s.buf.len() == 0 {
            return RegisterStatus::Closed;
        }
        s.recvq.push_back(sg as *mut Sudog<T>);
        RegisterStatus::Registered
    }

    /// Locked-state register a send sudog. Returns
    /// `RegisterStatus::Closed` on closed chan, `Registered`
    /// otherwise.
    #[doc(hidden)]
    pub fn __register_send_locked(s: &mut HchanState<T>, sg: &mut Sudog<T>) -> RegisterStatus {
        if s.closed {
            return RegisterStatus::Closed;
        }
        s.sendq.push_back(sg as *mut Sudog<T>);
        RegisterStatus::Registered
    }
}

fn fatal(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(2);
}

/// CAS-claim a sudog before firing it. Returns `true` if this waker
/// is allowed to proceed with the handoff, `false` if the sudog is a
/// stale `select!` entry (another case in the same select already
/// won) and the waker must discard it.
///
/// AcqRel on success ensures any subsequent writes to the sudog
/// (`value`, `success`) and the subsequent `goready` happen-after the
/// claim is observed under M17a multi-M; on the failure path we use
/// Acquire so we observe the winning waker's state if we want to
/// inspect the sudog (we don't, but it's the conservative choice).
///
/// For non-select sudogs (`coord == None`) the CAS is skipped and
/// the waker always succeeds.
#[inline(never)]
#[link_section = "goish_rt_text"]
fn try_claim_sudog<T>(sg: NonNull<Sudog<T>>) -> bool {
    let coord_opt = unsafe { (*sg.as_ptr()).coord };
    let coord = match coord_opt {
        None => return true, // plain Send/Recv — always claim
        Some(c) => c,
    };
    let done_ref = unsafe { &(*coord.as_ptr()).done };
    done_ref
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

// ─── Internal helpers (composed by Send/Recv and by select!) ───────

impl<T> chan<T> {
    /// Try to send `v` without parking. Returns `Ok(())` on success
    /// (handed off to a parked receiver, or pushed into the buffer).
    /// Returns `Err(v)` if the operation would block (no parked
    /// receiver, buffer full, chan unbuffered with no waiter).
    /// Panics on closed chan — Go semantics for `c <- v`.
    #[doc(hidden)]
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub fn __try_send(&self, v: T) -> Result<(), T> {
        let mut s = self.inner.state.lock();
        if s.closed {
            drop(s);
            fatal(b"goish: chan: send on closed channel\n");
        }

        // Scan recvq in FIFO order. CAS-claim each candidate; on a
        // stale select sudog (claim fails), leave it in place — the
        // parking G's pass-3 will cancel it. Removing it here would
        // hide the loser from `__cancel_recv`'s "is it still in the
        // queue?" check that distinguishes winner from loser.
        unsafe {
            let mut cur = s.recvq.head;
            while !cur.is_null() {
                let next = (*cur).next;
                let recv_ptr = NonNull::new_unchecked(cur);
                if !try_claim_sudog(recv_ptr) {
                    cur = next;
                    continue;
                }
                // Claim succeeded — remove from queue and hand off.
                s.recvq.unlink(cur);
                (*cur).value = Some(v);
                (*cur).success = true;
                let recv_g = (*cur).g;
                drop(s);
                goready(recv_g);
                return Ok(());
            }
        }

        // Buffer has room — push and return.
        if s.buf.len() < s.cap {
            s.buf
                .try_send(v)
                .ok()
                .expect("buf send: ring full though len < cap");
            return Ok(());
        }

        // Would block.
        Err(v)
    }

    /// Try to recv without parking. Returns `Some((v, ok))` if a
    /// value (or close-and-empty terminator) is immediately
    /// available. Returns `None` if the operation would block.
    #[doc(hidden)]
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub fn __try_recv(&self) -> Option<(T, bool)>
    where
        T: Default,
    {
        let mut s = self.inner.state.lock();

        // closed-and-empty → (zero, false)
        if s.closed && s.buf.len() == 0 {
            drop(s);
            return Some((T::default(), false));
        }

        // Parked sender beats non-empty buffer (rotates buf if cap>0).
        // Peek + CAS-claim; only remove a sudog from sendq once we
        // successfully claim it. Stale select sudogs stay in place
        // for pass-3 cleanup by the parking G.
        unsafe {
            let mut cur = s.sendq.head;
            while !cur.is_null() {
                let next = (*cur).next;
                let send_ptr = NonNull::new_unchecked(cur);
                if !try_claim_sudog(send_ptr) {
                    cur = next;
                    continue;
                }
                s.sendq.unlink(cur);
                let sender_v = (*cur).value.take().expect("recv: sender sudog empty");
                let v = if s.cap == 0 {
                    sender_v
                } else {
                    let head = s
                        .buf
                        .try_recv()
                        .expect("recv: buf empty with parked sender");
                    s.buf
                        .try_send(sender_v)
                        .ok()
                        .expect("buf rotate: ring full though slot just freed");
                    head
                };
                (*cur).success = true;
                let send_g = (*cur).g;
                drop(s);
                goready(send_g);
                return Some((v, true));
            }
        }

        // Non-empty buffer.
        if let Some(v) = s.buf.try_recv() {
            return Some((v, true));
        }

        None
    }

    /// Enqueue a send-direction sudog on `sendq`. Caller is
    /// responsible for `gopark`-ing afterwards and inspecting
    /// `sg.success` on wake. Returns `false` if the chan is closed
    /// (caller should panic before parking).
    #[doc(hidden)]
    pub fn __register_send(&self, sg: &mut Sudog<T>) -> bool {
        let mut s = self.inner.state.lock();
        if s.closed {
            return false;
        }
        s.sendq.push_back(sg as *mut Sudog<T>);
        true
    }

    /// Enqueue a recv-direction sudog on `recvq`. Returns `Err(())`
    /// if the chan is already closed-and-empty (caller should
    /// return `(zero, false)` and not park).
    #[doc(hidden)]
    pub fn __register_recv(&self, sg: &mut Sudog<T>) -> Result<(), ()> {
        let mut s = self.inner.state.lock();
        if s.closed && s.buf.len() == 0 {
            return Err(());
        }
        s.recvq.push_back(sg as *mut Sudog<T>);
        Ok(())
    }

    /// Drop a previously-registered send sudog from `sendq`. Returns
    /// `true` if the sudog was found and removed (this case lost the
    /// select), `false` if it was already gone (this case won — the
    /// firing waker had popped it out of the queue).
    ///
    /// Used by `select!` pass-3 to (a) clean up losing cases and
    /// (b) identify the winning case in one pass.
    #[doc(hidden)]
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub fn __cancel_send(&self, sg: NonNull<Sudog<T>>) -> bool {
        let mut s = self.inner.state.lock();
        s.sendq.cancel(sg.as_ptr())
    }

    /// Drop a previously-registered recv sudog from `recvq`. Same
    /// winner/loser convention as `__cancel_send`.
    #[doc(hidden)]
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub fn __cancel_recv(&self, sg: NonNull<Sudog<T>>) -> bool {
        let mut s = self.inner.state.lock();
        s.recvq.cancel(sg.as_ptr())
    }
}

// ─── Public Send / Recv / Close — thin wrappers over helpers ───────

impl<T> chan<T> {
    /// `c <- v` — send `v` on the channel. Blocks if no receiver
    /// is ready and the buffer is full (or the channel is
    /// unbuffered with no parked receiver). Panics on closed
    /// channels.
    ///
    /// **Multi-M correctness**. The chan lock is held continuously
    /// across pass-1 (try fast paths) and the sudog enqueue, and is
    /// released only inside `chan_park_commit` — which `gopark`
    /// schedules to run on the scheduler's stack *after*
    /// `swap_context` has committed the parker's gobuf. This mirrors
    /// Go's chanparkcommit pattern (chan.go:748-766; see invariant
    /// comment at chan.go:759-763). A waker on a different M cannot
    /// observe our sudog without holding the chan lock, so by the
    /// time it can `goready` us our gobuf is already a valid
    /// suspended snapshot.
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub fn Send(&self, v: T) {
        // nil chan — block forever (Go runtime/chan.go:177-183).
        // No lock to acquire, no commit fn touches state.
        if self.inner.nil {
            let _ = v;
            gopark(block_forever_commit, core::ptr::null());
            // gopark on a nil chan never goready's — unreachable.
            unsafe { core::hint::unreachable_unchecked() }
        }

        let lock_atom = self.inner.state.lock_atom();
        unsafe {
            raw_lock(lock_atom);
        }
        let s = unsafe { self.inner.state.data_unchecked() };

        // Phase 1: try the non-blocking fast paths under held lock.
        let v = match Self::__try_send_locked(s, v) {
            Ok(()) => {
                unsafe {
                    raw_unlock(lock_atom);
                }
                return;
            }
            Err(v) => v,
        };

        // Phase 2: register-and-park, lock still held.
        let g = current_g().unwrap_or_else(|| {
            unsafe {
                raw_unlock(lock_atom);
            }
            fatal(b"goish: chan: Send outside of any goroutine\n")
        });
        let mut my_sudog = Sudog::new_send(g, v);
        match Self::__register_send_locked(s, &mut my_sudog) {
            RegisterStatus::Registered => {}
            RegisterStatus::Closed => {
                unsafe {
                    raw_unlock(lock_atom);
                }
                fatal(b"goish: chan: send on closed channel\n");
            }
            RegisterStatus::Skip => unsafe { core::hint::unreachable_unchecked() },
        }

        // gopark stashes (chan_park_commit, lock_atom) on the M and
        // calls swap_context. dispatch_one_g runs the commit
        // post-swap, which is what unlocks the chan. From here we
        // resume only after some peer has matched our sudog and
        // called goready on our G.
        gopark(chan_park_commit, lock_atom);

        if !my_sudog.success {
            fatal(b"goish: chan: send on closed channel (woken with !success)\n");
        }
        debug_assert!(my_sudog.value.is_none());
    }

    /// `v, ok := <-c` — receive a value. Order of preference per
    /// runtime/chan.go:524-630:
    ///   1. closed-and-empty → return (zero, false)
    ///   2. parked sender → take value (rotating buffer if cap>0)
    ///   3. non-empty buffer → pop from head
    ///   4. otherwise park
    ///
    /// Same multi-M lock discipline as `Send` — see the comment
    /// there.
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub fn Recv(&self) -> (T, bool)
    where
        T: Default,
    {
        // nil chan — block forever (Go runtime/chan.go:532-538).
        if self.inner.nil {
            gopark(block_forever_commit, core::ptr::null());
            unsafe { core::hint::unreachable_unchecked() }
        }

        let lock_atom = self.inner.state.lock_atom();
        unsafe {
            raw_lock(lock_atom);
        }
        let s = unsafe { self.inner.state.data_unchecked() };

        // Phase 1: try the non-blocking fast paths under held lock.
        if let Some(result) = Self::__try_recv_locked(s) {
            unsafe {
                raw_unlock(lock_atom);
            }
            return result;
        }

        // Phase 2: register-and-park.
        let g = current_g().unwrap_or_else(|| {
            unsafe {
                raw_unlock(lock_atom);
            }
            fatal(b"goish: chan: Recv outside of any goroutine\n")
        });
        let mut my_sudog = Sudog::new_recv(g);
        match Self::__register_recv_locked(s, &mut my_sudog) {
            RegisterStatus::Registered => {}
            RegisterStatus::Closed => {
                unsafe {
                    raw_unlock(lock_atom);
                }
                return (T::default(), false);
            }
            RegisterStatus::Skip => unsafe { core::hint::unreachable_unchecked() },
        }

        gopark(chan_park_commit, lock_atom);

        if !my_sudog.success {
            return (T::default(), false);
        }
        let v = my_sudog.value.take().expect("recv: sudog empty after wake");
        (v, true)
    }

    /// `close(c)` — close the channel. Wakes all parked receivers
    /// with `(zero, false)` and all parked senders with
    /// success=false (causing them to panic on resume). Panics if
    /// the channel is already closed. Buffered values remain in
    /// the buffer and are drained by future `Recv` calls before
    /// they start returning `(zero, false)`.
    ///
    /// Stale `select!` sudogs (whose select already won via another
    /// case) fail the CAS-claim and are left in the queue; the
    /// owning goroutine's pass-3 will cancel them when it resumes.
    /// This keeps "close on multiple chans of one select" from
    /// firing more than one case of that select.
    #[inline(never)]
    #[link_section = "goish_rt_text"]
    pub fn Close(&self) {
        // close(nil chan) panics per Go (runtime/chan.go closechan).
        if self.inner.nil {
            fatal(b"goish: chan: close of nil channel\n");
        }
        let mut s = self.inner.state.lock();
        if s.closed {
            drop(s);
            fatal(b"goish: chan: close of closed channel\n");
        }
        s.closed = true;

        unsafe {
            let mut cur = s.recvq.head;
            while !cur.is_null() {
                let next = (*cur).next;
                let recv_ptr = NonNull::new_unchecked(cur);
                if !try_claim_sudog(recv_ptr) {
                    cur = next;
                    continue;
                }
                s.recvq.unlink(cur);
                (*cur).success = false;
                (*cur).value = None;
                let recv_g = (*cur).g;
                goready(recv_g);
                cur = next;
            }
            let mut cur = s.sendq.head;
            while !cur.is_null() {
                let next = (*cur).next;
                let send_ptr = NonNull::new_unchecked(cur);
                if !try_claim_sudog(send_ptr) {
                    cur = next;
                    continue;
                }
                s.sendq.unlink(cur);
                (*cur).success = false;
                let send_g = (*cur).g;
                goready(send_g);
                cur = next;
            }
        }
    }
}
