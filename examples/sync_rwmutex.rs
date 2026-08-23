// Smoke test: M16g-δ — sync.RWMutex.
//
// Tests:
//   1. Many concurrent readers don't block each other (RLock fast path).
//   2. Writer blocks new readers until done (no reader-starvation
//      under writer pressure).
//   3. Reader-writer-reader sequence under contention preserves
//      mutual exclusion: when the writer holds the lock, no readers
//      observe a half-updated value.
//   4. TryLock / TryRLock fast paths.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::runtime::sched::schedule;
use goish::sync::RWMutex;
use goish::{go, syscall};

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
    test_many_readers();
    test_writer_blocks_readers();
    test_writer_atomic_update();
    test_trylock_paths();

    const OK: &[u8] = b"sync_rwmutex: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ── Test 1: many readers run in parallel without blocking each other.

fn test_many_readers() {
    static RW: RWMutex = RWMutex::new();
    static READERS_DONE: AtomicUsize = AtomicUsize::new(0);

    READERS_DONE.store(0, Ordering::Relaxed);

    const N: usize = 32;
    for _ in 0..N {
        go!(|| {
            RW.RLock();
            // Pretend to read for a moment.
            for _ in 0..100 {
                core::hint::spin_loop();
            }
            RW.RUnlock();
            READERS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    schedule();

    check(
        READERS_DONE.load(Ordering::Relaxed) == N,
        b"many-readers: not all done\n",
    );
}

// ── Test 2: a pending writer blocks new readers from acquiring;
// existing readers continue, then writer runs, then the (new) readers
// run. Verified via in-section counts.

fn test_writer_blocks_readers() {
    static RW: RWMutex = RWMutex::new();
    // Counters for observed states.
    static R_BEFORE: AtomicUsize = AtomicUsize::new(0);
    static W_RAN: AtomicUsize = AtomicUsize::new(0);
    static R_AFTER: AtomicUsize = AtomicUsize::new(0);

    R_BEFORE.store(0, Ordering::Relaxed);
    W_RAN.store(0, Ordering::Relaxed);
    R_AFTER.store(0, Ordering::Relaxed);

    // Pre-readers: take RLock and hold briefly.
    const N_PRE: usize = 4;
    for _ in 0..N_PRE {
        go!(|| {
            RW.RLock();
            R_BEFORE.fetch_add(1, Ordering::Relaxed);
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
            RW.RUnlock();
        });
    }

    // Writer arrives: must wait for pre-readers to drain.
    go!(|| {
        RW.Lock();
        W_RAN.fetch_add(1, Ordering::Relaxed);
        RW.Unlock();
    });

    // Post-readers: arrive after the writer; should block until writer done.
    const N_POST: usize = 4;
    for _ in 0..N_POST {
        go!(|| {
            RW.RLock();
            R_AFTER.fetch_add(1, Ordering::Relaxed);
            RW.RUnlock();
        });
    }
    schedule();

    check(
        R_BEFORE.load(Ordering::Relaxed) == N_PRE,
        b"writer-blocks: pre-readers count wrong\n",
    );
    check(
        W_RAN.load(Ordering::Relaxed) == 1,
        b"writer-blocks: writer didn't run\n",
    );
    check(
        R_AFTER.load(Ordering::Relaxed) == N_POST,
        b"writer-blocks: post-readers count wrong\n",
    );
}

// ── Test 3: under heavy contention, writers' updates are atomic
// (readers never see a torn value).
//
// Shared "value" is two i64s that should always sum to a constant.
// Writer increments one, decrements the other under the write lock.
// Readers check the invariant under the read lock.

fn test_writer_atomic_update() {
    static RW: RWMutex = RWMutex::new();
    static A: AtomicI64 = AtomicI64::new(0);
    static B: AtomicI64 = AtomicI64::new(100);
    static MISMATCHES: AtomicUsize = AtomicUsize::new(0);

    A.store(0, Ordering::Relaxed);
    B.store(100, Ordering::Relaxed);
    MISMATCHES.store(0, Ordering::Relaxed);

    const N_WRITERS: usize = 4;
    const N_READERS: usize = 16;
    const ITERS: usize = 500;

    static GS_DONE: AtomicUsize = AtomicUsize::new(0);
    GS_DONE.store(0, Ordering::Relaxed);

    for _ in 0..N_WRITERS {
        go!(|| {
            for _ in 0..ITERS {
                RW.Lock();
                let a = A.load(Ordering::Relaxed);
                let b = B.load(Ordering::Relaxed);
                A.store(a + 1, Ordering::Relaxed);
                B.store(b - 1, Ordering::Relaxed);
                RW.Unlock();
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    for _ in 0..N_READERS {
        go!(|| {
            for _ in 0..ITERS {
                RW.RLock();
                let a = A.load(Ordering::Relaxed);
                let b = B.load(Ordering::Relaxed);
                if a + b != 100 {
                    MISMATCHES.fetch_add(1, Ordering::Relaxed);
                }
                RW.RUnlock();
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    check(
        GS_DONE.load(Ordering::Relaxed) == N_WRITERS + N_READERS,
        b"atomic-update: not all Gs done\n",
    );
    check(
        MISMATCHES.load(Ordering::Relaxed) == 0,
        b"atomic-update: torn read observed\n",
    );
    check(
        A.load(Ordering::Relaxed) == (N_WRITERS * ITERS) as i64,
        b"atomic-update: A wrong final\n",
    );
    check(
        B.load(Ordering::Relaxed) == 100 - (N_WRITERS * ITERS) as i64,
        b"atomic-update: B wrong final\n",
    );
}

// ── Test 4: TryLock / TryRLock single-threaded fast paths.

fn test_trylock_paths() {
    static RW: RWMutex = RWMutex::new();

    check(RW.TryLock(), b"trylock: fresh, TryLock failed\n");
    check(!RW.TryLock(), b"trylock: locked, TryLock succeeded\n");
    check(
        !RW.TryRLock(),
        b"trylock: write-locked, TryRLock succeeded\n",
    );
    RW.Unlock();

    check(RW.TryRLock(), b"trylock: TryRLock failed after Unlock\n");
    check(
        RW.TryRLock(),
        b"trylock: 2nd TryRLock failed (readers should compose)\n",
    );
    // Writer can't acquire while readers hold.
    check(
        !RW.TryLock(),
        b"trylock: TryLock succeeded with active readers\n",
    );
    RW.RUnlock();
    RW.RUnlock();

    // Now writer can take it.
    check(RW.TryLock(), b"trylock: TryLock failed after RUnlocks\n");
    RW.Unlock();
}
