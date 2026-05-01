// Smoke test: runtime::lockfree_ring — Vyukov MPMC correctness.
//
// Validates the lock-free ring as a standalone primitive (Phase 1 of
// chan<T>'s lock-free hot path):
//
//   1. Single-thread round-trip: Send N values, Recv all N, in FIFO
//      order, exact count.
//   2. SPSC stress: 1 producer, 1 consumer, N values, FIFO ordering
//      preserved.
//   3. MPMC stress: 4 producers × 4 consumers, total = N, no
//      duplicates (per-value bitset), no losses (final count == N).
//   4. Capacity rounding + wraparound: small ring, many values,
//      values still delivered exactly once.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::runtime::lockfree_ring::LockFreeRing;
use goish::runtime::sched::schedule;
use goish::sync::WaitGroup;
use goish::{go, syscall, KB};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    // Scheduler-driven body so Wait() / WG-Drop can park properly.
    go!(stack(64 * KB), || {
        test_single_thread_round_trip();
        test_spsc_fifo();
        test_mpmc_no_loss_no_dup();
        test_wraparound();
    });
    schedule();

    const OK: &[u8] = b"lockfree_ring_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ── Test 1: single-thread Send N → Recv N, FIFO ─────────────────────

fn test_single_thread_round_trip() {
    let r: LockFreeRing<i32> = LockFreeRing::new(64);
    check(r.capacity() == 64, b"st: capacity != 64\n");
    check(r.len() == 0, b"st: initial len != 0\n");

    for i in 0..50 {
        check(r.try_send(i).is_ok(), b"st: try_send unexpectedly full\n");
    }
    check(r.len() == 50, b"st: post-send len != 50\n");

    for i in 0..50 {
        match r.try_recv() {
            Some(v) => check(v == i, b"st: FIFO order broken\n"),
            None => die(b"st: try_recv unexpectedly empty\n"),
        }
    }
    check(r.len() == 0, b"st: post-recv len != 0\n");
    check(r.try_recv().is_none(), b"st: trailing recv not None\n");
}

// ── Test 2: 1 producer, 1 consumer, FIFO check ──────────────────────

fn test_spsc_fifo() {
    const N: i32 = 10_000;
    // Box::leak so the closures can capture by &'static reference
    // without entangling lifetimes. (Form 3 WG could also handle
    // this via &-borrow + auto-Wait-on-drop, but for a stress test
    // a static-lifetime ring keeps the example focused on the
    // ring's correctness.)
    let r: &'static LockFreeRing<i32> =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(LockFreeRing::new(256)));

    static SAW_OUT_OF_ORDER: AtomicUsize = AtomicUsize::new(0);
    static RECEIVED: AtomicUsize = AtomicUsize::new(0);

    let wg = WaitGroup::new();

    wg.Go(|| {
        // Producer: push 0..N, retrying on full.
        for i in 0..N {
            while r.try_send(i).is_err() {
                goish::runtime::sched::Gosched();
            }
        }
    });

    wg.Go(|| {
        // Consumer: pop N values, verify they arrive in order.
        let mut expected: i32 = 0;
        let mut got: i32 = 0;
        while got < N {
            match r.try_recv() {
                Some(v) => {
                    if v != expected {
                        SAW_OUT_OF_ORDER.fetch_add(1, Ordering::Relaxed);
                    }
                    expected += 1;
                    got += 1;
                }
                None => goish::runtime::sched::Gosched(),
            }
        }
        RECEIVED.store(got as usize, Ordering::Release);
    });

    wg.Wait();

    check(
        SAW_OUT_OF_ORDER.load(Ordering::Acquire) == 0,
        b"spsc: FIFO violation\n",
    );
    check(
        RECEIVED.load(Ordering::Acquire) == N as usize,
        b"spsc: missed values\n",
    );
}

// ── Test 3: 4P × 4C MPMC, no duplicates, no losses ──────────────────

fn test_mpmc_no_loss_no_dup() {
    const N_PRODUCERS: usize = 4;
    const N_CONSUMERS: usize = 4;
    const PER_PRODUCER: usize = 1_000;
    const TOTAL: usize = N_PRODUCERS * PER_PRODUCER;

    let r: &'static LockFreeRing<usize> =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(LockFreeRing::new(64)));

    // Bitset for "I saw this value." Box::leak so consumers can
    // share a 'static reference. AtomicU64 array indexed by bit.
    use core::sync::atomic::AtomicU64;
    let bitmap_words: usize = (TOTAL + 63) / 64;
    let mut bitmap_vec: Vec<AtomicU64> = Vec::with_capacity(bitmap_words);
    for _ in 0..bitmap_words {
        bitmap_vec.push(AtomicU64::new(0));
    }
    let bitmap: &'static [AtomicU64] = alloc::boxed::Box::leak(bitmap_vec.into_boxed_slice());

    static DUPLICATES: AtomicUsize = AtomicUsize::new(0);
    static RECEIVED: AtomicUsize = AtomicUsize::new(0);

    let wg = WaitGroup::new();

    // Producers: each emits values [pid*PER_PRODUCER .. (pid+1)*PER_PRODUCER).
    for pid in 0..N_PRODUCERS {
        wg.Go(move || {
            let lo = pid * PER_PRODUCER;
            let hi = lo + PER_PRODUCER;
            for v in lo..hi {
                while r.try_send(v).is_err() {
                    goish::runtime::sched::Gosched();
                }
            }
        });
    }

    // Consumers: pop until total reaches N, marking the bitmap.
    for _ in 0..N_CONSUMERS {
        wg.Go(|| loop {
            if RECEIVED.load(Ordering::Acquire) >= TOTAL {
                return;
            }
            match r.try_recv() {
                Some(v) => {
                    let word_idx = v / 64;
                    let bit = 1u64 << (v % 64);
                    let prev = bitmap[word_idx].fetch_or(bit, Ordering::AcqRel);
                    if prev & bit != 0 {
                        DUPLICATES.fetch_add(1, Ordering::Relaxed);
                    }
                    RECEIVED.fetch_add(1, Ordering::AcqRel);
                }
                None => {
                    if RECEIVED.load(Ordering::Acquire) >= TOTAL {
                        return;
                    }
                    goish::runtime::sched::Gosched();
                }
            }
        });
    }

    wg.Wait();

    check(
        DUPLICATES.load(Ordering::Acquire) == 0,
        b"mpmc: duplicate value delivered\n",
    );
    check(
        RECEIVED.load(Ordering::Acquire) == TOTAL,
        b"mpmc: total received != expected\n",
    );

    // Every bit should be set.
    for (i, w) in bitmap.iter().enumerate() {
        let v = w.load(Ordering::Acquire);
        let expected = if i == bitmap_words - 1 && TOTAL % 64 != 0 {
            (1u64 << (TOTAL % 64)) - 1
        } else {
            !0u64
        };
        check(v == expected, b"mpmc: missing values in bitmap\n");
    }
}

// ── Test 4: capacity = 4, push 200 values, all delivered exactly once

fn test_wraparound() {
    let r: LockFreeRing<u32> = LockFreeRing::new(4);
    check(r.capacity() == 4, b"wrap: capacity != 4\n");

    let mut sent: Vec<u32> = Vec::with_capacity(200);
    let mut got: Vec<u32> = Vec::with_capacity(200);

    // Interleaved send/recv to force the ring to wrap many times.
    for i in 0..200u32 {
        // Always recv if there's room.
        while r.try_send(i).is_err() {
            if let Some(v) = r.try_recv() {
                got.push(v);
            }
        }
        sent.push(i);

        // Drain occasionally so we wrap, not just fill.
        if i % 7 == 0 {
            if let Some(v) = r.try_recv() {
                got.push(v);
            }
        }
    }
    while let Some(v) = r.try_recv() {
        got.push(v);
    }

    check(sent.len() == 200, b"wrap: sent count\n");
    check(got.len() == 200, b"wrap: recv count\n");
    for i in 0..200 {
        check(sent[i] == got[i], b"wrap: order broken across wraps\n");
    }
}
