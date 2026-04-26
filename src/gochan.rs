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

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::ptr::NonNull;

use crate::runtime::sched::{current_g, gopark, goready, G};
use crate::runtime::spin::SpinLock;
use crate::syscall;

/// Wait-list entry for a parked goroutine. Lives on the stack of
/// the goroutine that's parking.
struct Sudog<T> {
    g: NonNull<G>,
    /// Send sudog: starts `Some(value)`, taken by a matching
    /// receiver. Recv sudog: starts `None`, filled by a matching
    /// sender.
    value: Option<T>,
    /// True on a successful handoff; false on a close-induced
    /// wakeup.
    success: bool,
}

unsafe impl<T> Send for Sudog<T> {}
unsafe impl<T> Sync for Sudog<T> {}

/// Lock-protected channel state.
struct HchanState<T> {
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
}

fn fatal(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(2);
}

impl<T> chan<T> {
    /// `c <- v` — send `v` on the channel. Blocks if no receiver
    /// is ready and the buffer is full (or the channel is
    /// unbuffered with no parked receiver). Panics on closed
    /// channels.
    pub fn Send(&self, v: T) {
        // Phase 1: try the fast paths under the lock.
        let v_to_park = {
            let mut s = self.inner.state.lock();
            if s.closed {
                drop(s);
                fatal(b"goish: chan: send on closed channel\n");
            }

            // Parked receiver beats buffer space — direct handoff.
            if let Some(recv_ptr) = s.recvq.pop_front() {
                unsafe {
                    (*recv_ptr.as_ptr()).value = Some(v);
                    (*recv_ptr.as_ptr()).success = true;
                }
                let recv_g = unsafe { (*recv_ptr.as_ptr()).g };
                drop(s);
                goready(recv_g);
                return;
            }

            // Buffer has room — push and return.
            if s.buf.len() < s.cap {
                s.buf.push_back(v);
                return;
            }

            // Buffer full (or cap=0). Carry `v` into the park phase.
            v
        };

        // Phase 2: park on sendq with our value.
        let g = current_g().unwrap_or_else(|| {
            fatal(b"goish: chan: Send outside of any goroutine\n")
        });
        let mut my_sudog = Sudog::<T> {
            g,
            value: Some(v_to_park),
            success: false,
        };
        let sudog_ptr = NonNull::from(&mut my_sudog);
        {
            let mut s = self.inner.state.lock();
            // Re-check closed since we briefly dropped the lock.
            if s.closed {
                drop(s);
                fatal(b"goish: chan: send on closed channel\n");
            }
            s.sendq.push_back(sudog_ptr);
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
        // Phase 1: try the fast paths under the lock.
        {
            let mut s = self.inner.state.lock();

            if s.closed && s.buf.is_empty() {
                drop(s);
                return (T::default(), false);
            }

            if let Some(send_ptr) = s.sendq.pop_front() {
                let sender_v = unsafe {
                    (*send_ptr.as_ptr())
                        .value
                        .take()
                        .expect("recv: sender sudog empty")
                };
                let v = if s.cap == 0 {
                    sender_v
                } else {
                    // Buffered with parked sender ⇒ buffer was full.
                    // Pop the head for the receiver, push sender's
                    // value to the tail to fill the freed slot.
                    let head = s.buf.pop_front().expect("recv: buf empty with parked sender");
                    s.buf.push_back(sender_v);
                    head
                };
                unsafe {
                    (*send_ptr.as_ptr()).success = true;
                }
                let send_g = unsafe { (*send_ptr.as_ptr()).g };
                drop(s);
                goready(send_g);
                return (v, true);
            }

            if let Some(v) = s.buf.pop_front() {
                return (v, true);
            }
        }

        // Phase 2: park on recvq.
        let g = current_g().unwrap_or_else(|| {
            fatal(b"goish: chan: Recv outside of any goroutine\n")
        });
        let mut my_sudog = Sudog::<T> {
            g,
            value: None,
            success: false,
        };
        let sudog_ptr = NonNull::from(&mut my_sudog);
        {
            let mut s = self.inner.state.lock();
            // Re-check closed-and-empty since we briefly dropped the lock.
            if s.closed && s.buf.is_empty() {
                drop(s);
                return (T::default(), false);
            }
            s.recvq.push_back(sudog_ptr);
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
    pub fn Close(&self) {
        let mut s = self.inner.state.lock();
        if s.closed {
            drop(s);
            fatal(b"goish: chan: close of closed channel\n");
        }
        s.closed = true;

        while let Some(recv_ptr) = s.recvq.pop_front() {
            unsafe {
                (*recv_ptr.as_ptr()).success = false;
                (*recv_ptr.as_ptr()).value = None;
            }
            let recv_g = unsafe { (*recv_ptr.as_ptr()).g };
            goready(recv_g);
        }
        while let Some(send_ptr) = s.sendq.pop_front() {
            unsafe {
                (*send_ptr.as_ptr()).success = false;
            }
            let send_g = unsafe { (*send_ptr.as_ptr()).g };
            goready(send_g);
        }
    }
}
