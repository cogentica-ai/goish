// runtime::lockfree_ring — bounded MPMC lock-free ring buffer
// (Vyukov bounded MPMC queue, with sequence numbers per slot).
//
// Reference: Dmitry Vyukov, "Bounded MPMC queue"
//   http://www.1024cores.net/home/lock-free-algorithms/queues/bounded-mpmc-queue
//
// Used as the buffered hot path inside `chan<T>` (Phase 2). This
// module is the lock-free primitive only — no parking, no waker
// integration, no select! coordination. Those layers belong to the
// owning chan.
//
// Capacity is rounded up to the next power of two so the slot index
// is `idx & cap_mask` instead of `idx % cap`. Minimum capacity is 1.
//
// Memory ordering recap:
//   - Slot publication: producer writes value, then `seq.store(tail+1, Release)`.
//     Consumer's `seq.load(Acquire)` synchronises-with that release;
//     after the load returns `head+1`, the value-read is well-defined.
//   - Slot recycling: consumer reads value, then
//     `seq.store(head + cap, Release)`. Producer's `seq.load(Acquire)`
//     synchronises-with that, so when producer sees `seq == tail`,
//     no consumer is still touching the slot's value.
//   - `head`/`tail` use Relaxed loads + CAS-claim (Relaxed/Relaxed) —
//     the Acquire/Release synchronisation happens on `slot.seq`, not
//     on the indices. This is the Vyukov insight that makes the
//     queue cheaper than naïve seqlock-style designs.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 64-byte-aligned wrapper to keep cross-side atomics on disjoint
/// cache lines. x86_64 lines are 64 B; ARM64 is 64 or 128 depending
/// on the micro-arch (we use 64 — the common case).
#[repr(align(64))]
struct CachePadded<T>(T);

impl<T> core::ops::Deref for CachePadded<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

/// A single slot. `seq` encodes the slot's lifecycle:
///   `seq == tail`           ⇒ empty, ready for producer at index `tail`
///   `seq == head + 1`       ⇒ full,  ready for consumer at index `head`
///   anything else           ⇒ mid-flight, contended; producer or
///                              consumer must retry
///
/// Aligned to 64 B so adjacent slots don't false-share. For T larger
/// than ~56 bytes the padding is wasted, but that's acceptable —
/// most chan element types are pointer-or-int sized.
#[repr(align(64))]
struct Slot<T> {
    seq: AtomicUsize,
    val: UnsafeCell<MaybeUninit<T>>,
}

/// Bounded MPMC lock-free ring. Capacity is fixed at construction
/// (rounded up to a power of two). Send and recv are wait-free under
/// no contention and lock-free under contention (a stuck thread
/// can't block progress; CAS retries finite-bounded by other threads'
/// successes).
pub struct LockFreeRing<T> {
    /// Owned by drainers. Each successful `try_recv` advances head.
    head: CachePadded<AtomicUsize>,
    /// Owned by fillers. Each successful `try_send` advances tail.
    tail: CachePadded<AtomicUsize>,
    /// Storage. Length is power of two; `cap_mask = len - 1`.
    slots: Box<[Slot<T>]>,
    cap_mask: usize,
}

// SAFETY: `Slot<T>` shares state across threads via atomics +
// per-slot publication ordering. T must be `Send` for the ring to be
// safely sharable; no `T: Sync` bound because each slot is only
// accessed by exactly one thread between claim and publish.
unsafe impl<T: Send> Send for LockFreeRing<T> {}
unsafe impl<T: Send> Sync for LockFreeRing<T> {}

impl<T> LockFreeRing<T> {
    /// Create a ring with capacity rounded up to the next power of
    /// two (minimum 1). For `cap == 0`, capacity becomes 1; the
    /// chan layer treats unbuffered channels separately and should
    /// not instantiate this type at all.
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1).next_power_of_two();
        let mut slots: Vec<Slot<T>> = Vec::with_capacity(cap);
        for i in 0..cap {
            slots.push(Slot {
                seq: AtomicUsize::new(i),
                val: UnsafeCell::new(MaybeUninit::uninit()),
            });
        }
        Self {
            head: CachePadded(AtomicUsize::new(0)),
            tail: CachePadded(AtomicUsize::new(0)),
            slots: slots.into_boxed_slice(),
            cap_mask: cap - 1,
        }
    }

    /// Total slot count (capacity).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap_mask + 1
    }

    /// Current occupancy. Snapshot only — racy under concurrent
    /// producers/consumers, mirrors Go's `len(chan)` semantics
    /// (also snapshot-and-racy).
    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }

    /// Try to enqueue `v`. Returns `Err(v)` if full.
    ///
    /// Wait-free under no contention. Under contention this loops
    /// (CAS on `tail`) but makes progress whenever any other
    /// producer succeeds — never blocks on a stalled thread.
    pub fn try_send(&self, v: T) -> Result<(), T> {
        let mut tail = self.tail.load(Ordering::Relaxed);
        loop {
            // Safety: `tail & cap_mask` is in [0, cap), and `slots`
            // has length `cap`.
            let slot = unsafe { self.slots.get_unchecked(tail & self.cap_mask) };
            let seq = slot.seq.load(Ordering::Acquire);
            let diff = seq.wrapping_sub(tail) as isize;
            if diff == 0 {
                // Slot is ready for us at this `tail`. Claim it.
                match self.tail.compare_exchange_weak(
                    tail,
                    tail.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Write the value, then publish via seq.
                        unsafe {
                            (*slot.val.get()).write(v);
                        }
                        slot.seq.store(tail.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    Err(observed) => {
                        // Another producer beat us; resume from the
                        // observed `tail`.
                        tail = observed;
                    }
                }
            } else if diff < 0 {
                // seq < tail ⇒ slot still owned by an older
                // generation's consumer (i.e., consumer hasn't
                // published `seq = tail` yet). Means the ring is
                // full from this producer's perspective.
                return Err(v);
            } else {
                // seq > tail ⇒ another producer already claimed
                // and published this slot; reload tail and retry.
                tail = self.tail.load(Ordering::Relaxed);
            }
        }
    }

    /// Try to dequeue. Returns `None` if empty.
    pub fn try_recv(&self) -> Option<T> {
        let mut head = self.head.load(Ordering::Relaxed);
        loop {
            let slot = unsafe { self.slots.get_unchecked(head & self.cap_mask) };
            let seq = slot.seq.load(Ordering::Acquire);
            let diff = seq.wrapping_sub(head.wrapping_add(1)) as isize;
            if diff == 0 {
                // Slot is full at this `head`. Claim it.
                match self.head.compare_exchange_weak(
                    head,
                    head.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        let v = unsafe { (*slot.val.get()).assume_init_read() };
                        // Publish the slot as recyclable for the
                        // producer at index `head + cap` (next lap).
                        slot.seq
                            .store(head.wrapping_add(self.capacity()), Ordering::Release);
                        return Some(v);
                    }
                    Err(observed) => {
                        head = observed;
                    }
                }
            } else if diff < 0 {
                // seq < head + 1 ⇒ slot still owned by producer
                // (i.e., not yet published). Empty from this
                // consumer's perspective.
                return None;
            } else {
                // Another consumer already claimed; reload.
                head = self.head.load(Ordering::Relaxed);
            }
        }
    }
}

impl<T> Drop for LockFreeRing<T> {
    fn drop(&mut self) {
        // Drop any values still in the ring. We have unique access
        // (`&mut self`), so no atomic ordering subtleties.
        while self.try_recv().is_some() {}
    }
}
