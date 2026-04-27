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

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::runtime::sched::{current_g, gopark, goready, G};
use crate::runtime::spin::SpinLock;
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
#[doc(hidden)] pub struct SelectCoord {
    #[doc(hidden)] pub done: AtomicBool,
}

impl SelectCoord {
    #[allow(dead_code)] // wired up in M16f-α step 4 (select! macro)
    #[doc(hidden)] pub fn new() -> Self {
        SelectCoord {
            done: AtomicBool::new(false),
        }
    }
}

/// Wait-list entry for a parked goroutine. Lives on the stack of
/// the goroutine that's parking.
#[doc(hidden)] pub struct Sudog<T> {
    #[doc(hidden)] pub g: NonNull<G>,
    /// Send sudog: starts `Some(value)`, taken by a matching
    /// receiver. Recv sudog: starts `None`, filled by a matching
    /// sender.
    #[doc(hidden)] pub value: Option<T>,
    /// True on a successful handoff; false on a close-induced
    /// wakeup.
    #[doc(hidden)] pub success: bool,
    /// `Some(coord)` if this sudog belongs to a `select!`; `None`
    /// for plain `Send`/`Recv`. Wakers consult `coord.done` via CAS
    /// before firing; on a stale sudog the CAS fails and the waker
    /// must skip this entry and try the next.
    #[doc(hidden)] pub coord: Option<NonNull<SelectCoord>>,
}

impl<T> Sudog<T> {
    /// Build a non-select send sudog carrying `v`.
    #[doc(hidden)] pub fn new_send(g: NonNull<G>, v: T) -> Self {
        Sudog {
            g,
            value: Some(v),
            success: false,
            coord: None,
        }
    }

    /// Build a non-select recv sudog (empty value slot).
    #[doc(hidden)] pub fn new_recv(g: NonNull<G>) -> Self {
        Sudog {
            g,
            value: None,
            success: false,
            coord: None,
        }
    }

    /// Build a select-bound send sudog carrying `v`. The waker that
    /// pops this sudog must succeed at `coord.done` CAS to fire it.
    #[allow(dead_code)] // wired up in M16f-α step 4 (select! macro)
    #[doc(hidden)] pub fn new_send_select(
        g: NonNull<G>,
        v: T,
        coord: NonNull<SelectCoord>,
    ) -> Self {
        Sudog {
            g,
            value: Some(v),
            success: false,
            coord: Some(coord),
        }
    }

    /// Build a select-bound recv sudog. CAS-gated like its send peer.
    #[allow(dead_code)] // wired up in M16f-α step 4 (select! macro)
    #[doc(hidden)] pub fn new_recv_select(g: NonNull<G>, coord: NonNull<SelectCoord>) -> Self {
        Sudog {
            g,
            value: None,
            success: false,
            coord: Some(coord),
        }
    }
}

unsafe impl<T> Send for Sudog<T> {}
unsafe impl<T> Sync for Sudog<T> {}

/// Lock-protected channel state.
#[doc(hidden)]
pub struct HchanState<T> {
    closed: bool,
    /// Buffer capacity. 0 = unbuffered.
    cap: usize,
    /// Ring buffer of in-flight values. Length is in `[0, cap]`.
    buf: VecDeque<T>,
    /// Goroutines waiting to send.
    sendq: VecDeque<NonNull<Sudog<T>>>,
    /// Goroutines waiting to receive.
    recvq: VecDeque<NonNull<Sudog<T>>>,
}

/// Public channel descriptor.
pub struct Hchan<T> {
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

impl<T> chan<T> {
    /// `make!(chan T)` — unbuffered channel (cap=0).
    pub fn new_unbuffered() -> Self {
        Self::new_buffered(0)
    }

    /// `make!(chan T, cap)` — buffered channel.
    pub fn new_buffered(cap: usize) -> Self {
        chan {
            inner: Arc::new(Hchan {
                state: SpinLock::new(HchanState {
                    closed: false,
                    cap,
                    buf: VecDeque::with_capacity(cap),
                    sendq: VecDeque::new(),
                    recvq: VecDeque::new(),
                }),
            }),
        }
    }

    /// `len(ch)` — number of values currently in the buffer. Always
    /// 0 for unbuffered channels.
    pub fn Len(&self) -> usize {
        self.inner.state.lock().buf.len()
    }

    /// `cap(ch)` — buffer capacity (0 for unbuffered).
    pub fn Cap(&self) -> usize {
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
    #[doc(hidden)]
    pub fn __try_recv_locked(s: &mut HchanState<T>) -> Option<(T, bool)>
    where
        T: Default,
    {
        if s.closed && s.buf.is_empty() {
            return Some((T::default(), false));
        }
        let mut i = 0;
        while i < s.sendq.len() {
            let send_ptr = s.sendq[i];
            if !try_claim_sudog(send_ptr) {
                i += 1;
                continue;
            }
            s.sendq.remove(i);
            let sender_v = unsafe {
                (*send_ptr.as_ptr())
                    .value
                    .take()
                    .expect("recv-locked: sender sudog empty")
            };
            let v = if s.cap == 0 {
                sender_v
            } else {
                let head = s
                    .buf
                    .pop_front()
                    .expect("recv-locked: buf empty with parked sender");
                s.buf.push_back(sender_v);
                head
            };
            unsafe {
                (*send_ptr.as_ptr()).success = true;
            }
            let send_g = unsafe { (*send_ptr.as_ptr()).g };
            goready(send_g);
            return Some((v, true));
        }
        if let Some(v) = s.buf.pop_front() {
            return Some((v, true));
        }
        None
    }

    /// Locked-state send. Same semantics as `__try_send` minus the
    /// chan-lock acquisition.
    #[doc(hidden)]
    pub fn __try_send_locked(s: &mut HchanState<T>, v: T) -> Result<(), T> {
        if s.closed {
            fatal(b"goish: chan: send on closed channel\n");
        }
        let mut i = 0;
        while i < s.recvq.len() {
            let recv_ptr = s.recvq[i];
            if !try_claim_sudog(recv_ptr) {
                i += 1;
                continue;
            }
            s.recvq.remove(i);
            unsafe {
                (*recv_ptr.as_ptr()).value = Some(v);
                (*recv_ptr.as_ptr()).success = true;
            }
            let recv_g = unsafe { (*recv_ptr.as_ptr()).g };
            goready(recv_g);
            return Ok(());
        }
        if s.buf.len() < s.cap {
            s.buf.push_back(v);
            return Ok(());
        }
        Err(v)
    }

    /// Locked-state register a recv sudog. Caller holds the chan
    /// lock. Returns `Err(())` if the chan is closed-and-empty.
    #[doc(hidden)]
    pub fn __register_recv_locked(s: &mut HchanState<T>, sg: &mut Sudog<T>) -> Result<(), ()> {
        if s.closed && s.buf.is_empty() {
            return Err(());
        }
        s.recvq.push_back(NonNull::from(sg));
        Ok(())
    }

    /// Locked-state register a send sudog. Returns `false` on closed.
    #[doc(hidden)]
    pub fn __register_send_locked(s: &mut HchanState<T>, sg: &mut Sudog<T>) -> bool {
        if s.closed {
            return false;
        }
        s.sendq.push_back(NonNull::from(sg));
        true
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
#[inline]
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
    #[doc(hidden)] pub fn __try_send(&self, v: T) -> Result<(), T> {
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
        let mut i = 0;
        while i < s.recvq.len() {
            let recv_ptr = s.recvq[i];
            if !try_claim_sudog(recv_ptr) {
                i += 1;
                continue;
            }
            // Claim succeeded — remove from queue and hand off.
            s.recvq.remove(i);
            unsafe {
                (*recv_ptr.as_ptr()).value = Some(v);
                (*recv_ptr.as_ptr()).success = true;
            }
            let recv_g = unsafe { (*recv_ptr.as_ptr()).g };
            drop(s);
            goready(recv_g);
            return Ok(());
        }

        // Buffer has room — push and return.
        if s.buf.len() < s.cap {
            s.buf.push_back(v);
            return Ok(());
        }

        // Would block.
        Err(v)
    }

    /// Try to recv without parking. Returns `Some((v, ok))` if a
    /// value (or close-and-empty terminator) is immediately
    /// available. Returns `None` if the operation would block.
    #[doc(hidden)] pub fn __try_recv(&self) -> Option<(T, bool)>
    where
        T: Default,
    {
        let mut s = self.inner.state.lock();

        // closed-and-empty → (zero, false)
        if s.closed && s.buf.is_empty() {
            drop(s);
            return Some((T::default(), false));
        }

        // Parked sender beats non-empty buffer (rotates buf if cap>0).
        // Peek + CAS-claim; only remove a sudog from sendq once we
        // successfully claim it. Stale select sudogs stay in place
        // for pass-3 cleanup by the parking G.
        let mut i = 0;
        while i < s.sendq.len() {
            let send_ptr = s.sendq[i];
            if !try_claim_sudog(send_ptr) {
                i += 1;
                continue;
            }
            s.sendq.remove(i);
            let sender_v = unsafe {
                (*send_ptr.as_ptr())
                    .value
                    .take()
                    .expect("recv: sender sudog empty")
            };
            let v = if s.cap == 0 {
                sender_v
            } else {
                let head = s
                    .buf
                    .pop_front()
                    .expect("recv: buf empty with parked sender");
                s.buf.push_back(sender_v);
                head
            };
            unsafe {
                (*send_ptr.as_ptr()).success = true;
            }
            let send_g = unsafe { (*send_ptr.as_ptr()).g };
            drop(s);
            goready(send_g);
            return Some((v, true));
        }

        // Non-empty buffer.
        if let Some(v) = s.buf.pop_front() {
            return Some((v, true));
        }

        None
    }

    /// Enqueue a send-direction sudog on `sendq`. Caller is
    /// responsible for `gopark`-ing afterwards and inspecting
    /// `sg.success` on wake. Returns `false` if the chan is closed
    /// (caller should panic before parking).
    #[doc(hidden)] pub fn __register_send(&self, sg: &mut Sudog<T>) -> bool {
        let mut s = self.inner.state.lock();
        if s.closed {
            return false;
        }
        s.sendq.push_back(NonNull::from(sg));
        true
    }

    /// Enqueue a recv-direction sudog on `recvq`. Returns `Err(())`
    /// if the chan is already closed-and-empty (caller should
    /// return `(zero, false)` and not park).
    #[doc(hidden)] pub fn __register_recv(&self, sg: &mut Sudog<T>) -> Result<(), ()> {
        let mut s = self.inner.state.lock();
        if s.closed && s.buf.is_empty() {
            return Err(());
        }
        s.recvq.push_back(NonNull::from(sg));
        Ok(())
    }

    /// Drop a previously-registered send sudog from `sendq`. Returns
    /// `true` if the sudog was found and removed (this case lost the
    /// select), `false` if it was already gone (this case won — the
    /// firing waker had popped it out of the queue).
    ///
    /// Used by `select!` pass-3 to (a) clean up losing cases and
    /// (b) identify the winning case in one pass.
    #[doc(hidden)] pub fn __cancel_send(&self, sg: NonNull<Sudog<T>>) -> bool {
        let mut s = self.inner.state.lock();
        let before = s.sendq.len();
        s.sendq.retain(|p| *p != sg);
        s.sendq.len() != before
    }

    /// Drop a previously-registered recv sudog from `recvq`. Same
    /// winner/loser convention as `__cancel_send`.
    #[doc(hidden)] pub fn __cancel_recv(&self, sg: NonNull<Sudog<T>>) -> bool {
        let mut s = self.inner.state.lock();
        let before = s.recvq.len();
        s.recvq.retain(|p| *p != sg);
        s.recvq.len() != before
    }
}

// ─── Public Send / Recv / Close — thin wrappers over helpers ───────

impl<T> chan<T> {
    /// `c <- v` — send `v` on the channel. Blocks if no receiver
    /// is ready and the buffer is full (or the channel is
    /// unbuffered with no parked receiver). Panics on closed
    /// channels.
    pub fn Send(&self, v: T) {
        // Phase 1: try the non-blocking fast paths.
        let v = match self.__try_send(v) {
            Ok(()) => return,
            Err(v) => v,
        };

        // Phase 2: park on sendq with our value.
        let g = current_g().unwrap_or_else(|| {
            fatal(b"goish: chan: Send outside of any goroutine\n")
        });
        let mut my_sudog = Sudog::new_send(g, v);
        if !self.__register_send(&mut my_sudog) {
            fatal(b"goish: chan: send on closed channel\n");
        }
        gopark(|| true);

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
    pub fn Recv(&self) -> (T, bool)
    where
        T: Default,
    {
        // Phase 1: try the non-blocking fast paths.
        if let Some(result) = self.__try_recv() {
            return result;
        }

        // Phase 2: park on recvq.
        let g = current_g().unwrap_or_else(|| {
            fatal(b"goish: chan: Recv outside of any goroutine\n")
        });
        let mut my_sudog = Sudog::new_recv(g);
        if self.__register_recv(&mut my_sudog).is_err() {
            return (T::default(), false);
        }
        gopark(|| true);

        if !my_sudog.success {
            return (T::default(), false);
        }
        let v = my_sudog
            .value
            .take()
            .expect("recv: sudog empty after wake");
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
    pub fn Close(&self) {
        let mut s = self.inner.state.lock();
        if s.closed {
            drop(s);
            fatal(b"goish: chan: close of closed channel\n");
        }
        s.closed = true;

        let mut i = 0;
        while i < s.recvq.len() {
            let recv_ptr = s.recvq[i];
            if !try_claim_sudog(recv_ptr) {
                i += 1;
                continue;
            }
            s.recvq.remove(i);
            unsafe {
                (*recv_ptr.as_ptr()).success = false;
                (*recv_ptr.as_ptr()).value = None;
            }
            let recv_g = unsafe { (*recv_ptr.as_ptr()).g };
            goready(recv_g);
        }
        let mut i = 0;
        while i < s.sendq.len() {
            let send_ptr = s.sendq[i];
            if !try_claim_sudog(send_ptr) {
                i += 1;
                continue;
            }
            s.sendq.remove(i);
            unsafe {
                (*send_ptr.as_ptr()).success = false;
            }
            let send_g = unsafe { (*send_ptr.as_ptr()).g };
            goready(send_g);
        }
    }
}
