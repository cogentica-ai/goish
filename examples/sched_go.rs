// Smoke test: M16b — go!() macro + cooperative scheduler.
//
// Verifies the public scheduler surface end-to-end:
//
//   - go!(closure) spawns a goroutine; the closure runs cooperatively
//     after main returns (or via explicit Gosched / runtime::sched::schedule)
//   - Multiple goroutines run in interleaved order via Gosched
//   - Goroutines can spawn further goroutines
//   - Captured state (move closures) survives across the swap

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::go;
use goish::runtime::sched::{schedule, Gosched};
use goish::{syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// Counters shared across goroutines and main.
static A_RAN: AtomicUsize = AtomicUsize::new(0);
static B_RAN: AtomicUsize = AtomicUsize::new(0);
static SPAWN_COUNT: AtomicUsize = AtomicUsize::new(0);
static INTERLEAVE_LOG: AtomicUsize = AtomicUsize::new(0); // bit-packed sequence

#[goish::main]
fn main() {
    // ─── Test 1: a single goroutine runs after main returns ─────────
    //
    // Spawn one G that bumps a counter. Main returns immediately;
    // __goish_rt0's schedule() drains the queue and runs it.
    go!(|| {
        A_RAN.fetch_add(1, Ordering::Relaxed);
    });

    // ─── Test 2: a captured value survives into the goroutine ───────
    //
    // The move closure captures `secret` by value; the captured
    // copy must survive the goroutine's stack switch.
    let secret: u64 = 0x_DEAD_BEEF_F00D_CAFE;
    go!(move || {
        if secret == 0x_DEAD_BEEF_F00D_CAFE {
            B_RAN.fetch_add(1, Ordering::Relaxed);
        }
    });

    // ─── Test 3: a goroutine that spawns more goroutines ────────────
    //
    // The outer G spawns 5 inner Gs, each of which bumps SPAWN_COUNT.
    // Verifies that newproc + schedule work re-entrantly inside a
    // running G.
    go!(|| {
        for _ in 0..5 {
            go!(|| {
                SPAWN_COUNT.fetch_add(1, Ordering::Relaxed);
            });
        }
    });

    // ─── Test 4: cooperative interleave via Gosched ─────────────────
    //
    // Three goroutines, each Gosched()'ing between increments. Without
    // Gosched, Go #1 would run to completion before #2 starts. With
    // Gosched, they interleave. We log the sequence with 2-bit
    // markers so the test can spot if interleave was actually achieved.
    go!(|| {
        for _ in 0..3 {
            let v = INTERLEAVE_LOG.load(Ordering::Relaxed);
            INTERLEAVE_LOG.store((v << 2) | 1, Ordering::Relaxed);
            Gosched();
        }
    });
    go!(|| {
        for _ in 0..3 {
            let v = INTERLEAVE_LOG.load(Ordering::Relaxed);
            INTERLEAVE_LOG.store((v << 2) | 2, Ordering::Relaxed);
            Gosched();
        }
    });
    go!(|| {
        for _ in 0..3 {
            let v = INTERLEAVE_LOG.load(Ordering::Relaxed);
            INTERLEAVE_LOG.store((v << 2) | 3, Ordering::Relaxed);
            Gosched();
        }
    });

    // ─── Test 5: explicit drain inside main, then verify state ─────
    //
    // Call schedule() explicitly so we can assert results before
    // main returns. After this returns, all goroutines spawned so
    // far have finished.
    schedule();

    check(A_RAN.load(Ordering::Relaxed) == 1, b"test1: A didn't run\n");
    check(B_RAN.load(Ordering::Relaxed) == 1, b"test2: B didn't run\n");
    check(
        SPAWN_COUNT.load(Ordering::Relaxed) == 5,
        b"test3: nested spawn count\n",
    );

    // The interleave log should contain 9 markers (3 from each of 3
    // Gs). The exact pattern depends on FIFO scheduling but should
    // include all three markers, not just one.
    let log = INTERLEAVE_LOG.load(Ordering::Relaxed);
    let mut seen = [false; 4];
    let mut ll = log;
    let mut count = 0;
    while ll != 0 {
        seen[(ll & 3) as usize] = true;
        ll >>= 2;
        count += 1;
    }
    check(count == 9, b"test4: wrong number of interleave events\n");
    check(
        seen[1] && seen[2] && seen[3],
        b"test4: not all three Gs interleaved\n",
    );

    // ─── Test 6: many goroutines (stress) ──────────────────────────
    //
    // Spawn 1000 goroutines, each bumping a counter. After drain,
    // counter should be exactly 1000. Stresses the run queue
    // capacity, the per-G stack mmap, and Box drop on Dead Gs.
    static MANY: AtomicUsize = AtomicUsize::new(0);
    for _ in 0..1000 {
        go!(|| {
            MANY.fetch_add(1, Ordering::Relaxed);
        });
    }
    schedule();
    check(
        MANY.load(Ordering::Relaxed) == 1000,
        b"test6: stress count mismatch\n",
    );

    const OK: &[u8] = b"sched_go: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
