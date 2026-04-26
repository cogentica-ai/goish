// gochan — Go's `chan` type and operations.
//
// User-facing API (made via `make!(chan T)`):
//
//     ch.Send(v)       // c <- v
//     let (v, ok) = ch.Recv();  // v, ok := <-c
//     ch.Close();
//
// M16d only ships unbuffered channels (the simpler case: no
// internal buffer; sender and receiver always meet directly).
// M16e extends this with `make!(chan T, n)` ring-buffer semantics.
//
// Internal layout mirrors Go's `runtime.hchan` (runtime/chan.go:34)
// with M16d-relevant fields only:
//
//   - `closed`        — set by `Close`; subsequent sends panic,
//                       receives return zero+false
//   - `sendq`/`recvq` — FIFOs of `Sudog<T>`s for goroutines parked
//                       on send/recv
//   - lock            — single SpinLock around the state
//
// Direct-handoff semantics on unbuffered channels:
//
//   - **send with parked receiver**: pop receiver's sudog, deposit
//     value into `recvq.value`, mark `success=true`, `goready` the
//     receiver. Sender returns immediately.
//   - **send with no receiver**: build sender sudog with the value,
//     enqueue, `gopark`. On wake: `success=true` means receiver
//     took our value; `success=false` means channel closed during
//     park (panic on send).
//   - **recv with parked sender**: pop sender's sudog, take its
//     value, mark `success=true`, `goready` the sender. Receiver
//     returns the value.
//   - **recv with no sender**: build receiver sudog, enqueue,
//     `gopark`. On wake: `success=true` means sender filled our
//     slot; `success=false` means channel closed (return
//     zero+false).
//
// Sudog allocation: per-call, on the parking goroutine's *own*
// stack. Keeping it on-stack avoids any per-channel-op heap
// traffic; the wait-list holds a `NonNull<Sudog<T>>` which is
// valid as long as the parking G is alive (and a parked G's stack
// is preserved by definition).
//
// Rust safety: the channel state lives in a `SpinLock`. The
// `unsafe` is confined to (1) dereferencing the per-G `Sudog`
// pointer to do the value handoff and (2) the `Send`/`Sync`
// impls on `Hchan<T>` and `chan<T>`. The chained `Arc<Hchan<T>>`
// shape is exactly Rust's standard cross-thread sharing pattern.

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
/// the goroutine that's parking; the wait queue holds a pointer.
struct Sudog<T> {
    g: NonNull<G>,
    /// Send sudog: starts `Some(value)`, taken by a matching
    /// receiver. Recv sudog: starts `None`, filled by a matching
    /// sender. After wake, the parking goroutine consults this to
    /// retrieve / verify the result.
    value: Option<T>,
    /// Set true on a successful handoff; false if the goroutine
    /// was woken because the channel closed.
    success: bool,
}

unsafe impl<T> Send for Sudog<T> {}
unsafe impl<T> Sync for Sudog<T> {}

/// Lock-protected channel state. Lives inside `Hchan<T>`.
struct HchanState<T> {
    closed: bool,
    /// Goroutines waiting to send on this channel.
    sendq: VecDeque<NonNull<Sudog<T>>>,
    /// Goroutines waiting to receive from this channel.
    recvq: VecDeque<NonNull<Sudog<T>>>,
}

/// Public channel descriptor — every `chan<T>` handle holds an
/// `Arc<Hchan<T>>` to share the state across goroutines.
pub struct Hchan<T> {
    state: SpinLock<HchanState<T>>,
}

unsafe impl<T: Send> Send for Hchan<T> {}
unsafe impl<T: Send> Sync for Hchan<T> {}

/// Go-shaped `chan<T>`. Cloning is cheap (Arc bump). Cloned handles
/// reference the same underlying channel.
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
    /// `make!(chan T)` — unbuffered channel.
    pub fn new_unbuffered() -> Self {
        chan {
            inner: Arc::new(Hchan {
                state: SpinLock::new(HchanState {
                    closed: false,
                    sendq: VecDeque::new(),
                    recvq: VecDeque::new(),
                }),
            }),
        }
    }
}

/// Internal: print a fatal panic-style message and exit. We don't
/// have unwinding, so unrecoverable channel misuse aborts.
fn fatal(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(2);
}

impl<T> chan<T> {
    /// `c <- v` — send `v` on the channel. Blocks until a receiver
    /// takes the value (unbuffered semantics). Panics if the
    /// channel is closed.
    pub fn Send(&self, v: T) {
        let g = current_g().unwrap_or_else(|| {
            fatal(b"goish: chan: Send outside of any goroutine\n")
        });
        let mut my_sudog = Sudog::<T> {
            g,
            value: Some(v),
            success: false,
        };
        let sudog_ptr = NonNull::from(&mut my_sudog);

        // Phase 1: under the channel lock, either hand off directly
        // or enqueue our sudog and prepare to park.
        {
            let mut s = self.inner.state.lock();
            if s.closed {
                drop(s);
                fatal(b"goish: chan: send on closed channel\n");
            }
            if let Some(recv_ptr) = s.recvq.pop_front() {
                // Direct handoff: deposit value into receiver's
                // sudog and wake them.
                let v = my_sudog.value.take().expect("send sudog empty");
                unsafe {
                    (*recv_ptr.as_ptr()).value = Some(v);
                    (*recv_ptr.as_ptr()).success = true;
                }
                let recv_g = unsafe { (*recv_ptr.as_ptr()).g };
                drop(s);
                goready(recv_g);
                return;
            }
            // No receiver — park.
            s.sendq.push_back(sudog_ptr);
        } // lock released

        // Phase 2: park. unlockf = always-park; the channel lock
        // is already released so we have nothing to drop here.
        gopark(|| true);

        // Phase 3: woken. Either a receiver took our value
        // (success=true, value=None) or the channel closed
        // (success=false; we panic).
        if !my_sudog.success {
            fatal(b"goish: chan: send on closed channel (woken with !success)\n");
        }
        debug_assert!(my_sudog.value.is_none());
    }

    /// `v, ok := <-c` — receive a value. Blocks until a sender
    /// arrives (unbuffered) or the channel is closed. Returns
    /// `(zero, false)` if the channel is closed and no value is
    /// available.
    pub fn Recv(&self) -> (T, bool)
    where
        T: Default,
    {
        let g = current_g().unwrap_or_else(|| {
            fatal(b"goish: chan: Recv outside of any goroutine\n")
        });
        let mut my_sudog = Sudog::<T> {
            g,
            value: None,
            success: false,
        };
        let sudog_ptr = NonNull::from(&mut my_sudog);

        // Phase 1: under the lock, take a sender's value, return
        // zero+false if closed-and-empty, or enqueue + park.
        {
            let mut s = self.inner.state.lock();
            if let Some(send_ptr) = s.sendq.pop_front() {
                let v = unsafe { (*send_ptr.as_ptr()).value.take().expect("send sudog empty") };
                unsafe {
                    (*send_ptr.as_ptr()).success = true;
                }
                let send_g = unsafe { (*send_ptr.as_ptr()).g };
                drop(s);
                goready(send_g);
                return (v, true);
            }
            if s.closed {
                drop(s);
                return (T::default(), false);
            }
            s.recvq.push_back(sudog_ptr);
        }

        gopark(|| true);

        if !my_sudog.success {
            // Channel closed during park.
            return (T::default(), false);
        }
        let v = my_sudog.value.take().expect("recv sudog empty after wake");
        (v, true)
    }

    /// `close(c)` — close the channel. Wakes all parked receivers
    /// with `(zero, false)` and all parked senders with a
    /// success=false signal (which causes them to panic on resume,
    /// matching Go's "send on closed channel"). Panics if already
    /// closed.
    pub fn Close(&self) {
        let mut s = self.inner.state.lock();
        if s.closed {
            drop(s);
            fatal(b"goish: chan: close of closed channel\n");
        }
        s.closed = true;

        // Wake all parked receivers — they get success=false.
        while let Some(recv_ptr) = s.recvq.pop_front() {
            unsafe {
                (*recv_ptr.as_ptr()).success = false;
                (*recv_ptr.as_ptr()).value = None;
            }
            let recv_g = unsafe { (*recv_ptr.as_ptr()).g };
            goready(recv_g);
        }
        // Wake all parked senders — they will panic on resume.
        while let Some(send_ptr) = s.sendq.pop_front() {
            unsafe {
                (*send_ptr.as_ptr()).success = false;
            }
            let send_g = unsafe { (*send_ptr.as_ptr()).g };
            goready(send_g);
        }
    }
}
