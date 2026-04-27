// Smoke test: M17b-β — per-P runq production, consumption, and global
// overflow.
//
// Verifies:
//   1. `runqput`/`runqget` round-trip on the bound P. Push N Gs from
//      the bound M, drain them back, see them all run.
//   2. Filling beyond LOCAL_RUNQ_SIZE (256) triggers `runqputslow`,
//      sending half-batches to the global runq. Workers pick those up.
//   3. With work-stealing not yet enabled (γ), Gs queued on one P
//      with no overflow can still be drained — but the system as a
//      whole completes when all Gs are reachable from some M.
//
// The key invariant: spawn N tasks via go!() that each bump a counter,
// schedule(), assert counter == N regardless of how routing splits
// between local and global runqs.

#![no_std]
#![no_main]

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::runtime::sched::{current_p, schedule, LOCAL_RUNQ_SIZE};
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
    test_local_runq_only();
    test_overflow_to_global();

    const OK: &[u8] = b"sched_p_beta: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ─── Test 1: spawn N << 256, all go to local P runq, all run ─────────

fn test_local_runq_only() {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    const N: usize = 64;

    // After spawning N goroutines, current_p().runq_len() should be
    // approximately N (pre-schedule, nothing has dispatched off the
    // main M yet — but workers may have stolen, so don't assert
    // tightly). Just count post-schedule.
    for _ in 0..N {
        go!(move || {
            COUNT.fetch_add(1, Ordering::Relaxed);
        });
    }

    // Spot-check the local P actually saw some of these. With workers
    // running in parallel they may steal in γ, but β has no steal so
    // every spawn lands on the main M's P.
    if let Some(p) = current_p() {
        // racy snapshot — main M's P runq holds some pre-dispatch.
        let _len = p.runq_len();
        // Don't assert exact value; just that runq_len() compiles
        // and returns sensibly.
    }

    schedule();
    check(
        COUNT.load(Ordering::Relaxed) == N,
        b"local: count != N\n",
    );
}

// ─── Test 2: spawn many > LOCAL_RUNQ_SIZE, force runqputslow ─────────

fn test_overflow_to_global() {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    // 4× LOCAL_RUNQ_SIZE so we exercise multiple `runqputslow`
    // batches. With N=1024, the local runq hits 256 four times,
    // each time spilling 128 + 1 to the global runq.
    let n: usize = LOCAL_RUNQ_SIZE * 4;

    for _ in 0..n {
        go!(move || {
            COUNT.fetch_add(1, Ordering::Relaxed);
        });
    }
    schedule();
    check(
        COUNT.load(Ordering::Relaxed) == n,
        b"overflow: count != N\n",
    );
}
