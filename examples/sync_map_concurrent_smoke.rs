// sync_map_concurrent_smoke — the shape issue #20 was reported from.
//
// A downstream `SyncMap` protected a `gomap` with
// `runtime::spin::SpinLock` and called `LoadOrStore` from repeated
// `WaitGroup.Go` rounds. `Set` on a missing key ALLOCATES, and a spin
// guard is an `m.locks` region, so the first allocation that had to
// park killed the process:
//
//     goish: fatal: schedule: holding locks (in park_m)
//
// The scheduler was right and the lock was wrong. A spin guard is a
// non-preemptible critical section for the runtime's own use, not a
// no_std stand-in for a mutex; `runtime::spin` is crate-private now so
// the mistake is not reachable from outside. `sync::Map` is the
// primitive for this, and it is built on `sync::Mutex`, whose slow
// path parks like Go's.
//
// WHAT THIS DOES AND DOES NOT PROVE. The compile-time half of the fix
// is enforced by the compiler, not by this file: `runtime::spin` being
// crate-private is what stops a downstream crate reaching the wrong
// primitive, and `cargo check --examples` is the test for it.
//
// This example is the behavioural half — `sync::Map` under real
// contention gives Go's answers: exactly one storer per key (so the
// `loaded` flags sum to WORKERS-1 per key) and every caller seeing the
// winner's value.
//
// It does NOT reproduce the abort. Swapping `sync::Map` back onto a
// SpinLock and rerunning this passes, because allocating under the
// guard only dies if the allocation actually parks, which it does not
// at this size. Adding one `Gosched()` inside the guarded region does
// trip it, exactly as it should:
//
//     goish: fatal: schedule: holding locks (in gosched_m) - a
//     SpinLock guard is held across a park/yield
//
// So the tripwire is verified alive by perturbation, not by this
// example passing. Saying otherwise would make a green run here look
// like evidence it is not.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::sync::{Map, WaitGroup};
use goish::types::int;

static FAILED: AtomicUsize = AtomicUsize::new(0);

const ROUNDS: usize = 8;
const WORKERS: usize = 8;
const KEYS: usize = 16;

fn check(cond: bool, msg: &str) {
    if cond {
        fmt::Printf!("[ok] %s\n", string::from_bytes(msg.as_bytes()));
    } else {
        fmt::Printf!("[!!] %s\n", string::from_bytes(msg.as_bytes()));
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
}

#[goish::main]
fn main() {
    // One storer per key across all workers: LoadOrStore returns
    // loaded=false exactly once for each key it creates.
    static STORED: AtomicUsize = AtomicUsize::new(0);
    static LOADED: AtomicUsize = AtomicUsize::new(0);
    static WRONG_VALUE: AtomicUsize = AtomicUsize::new(0);

    for round in 0..ROUNDS {
        // A fresh Map per round, so every round races the same missing
        // keys from scratch — that is what makes Set allocate under
        // the lock rather than hitting an already-populated entry.
        let m: Arc<Map<int, string>> = Arc::new(Map::new());
        let wg = Arc::new(WaitGroup::default());
        for _w in 0..WORKERS {
            let m = m.clone();
            let wg2 = wg.clone();
            wg.Add(1);
            go_worker(m, round, wg2, &STORED, &LOADED, &WRONG_VALUE);
        }
        wg.Wait();
    }

    let total = ROUNDS * WORKERS * KEYS;
    check(
        STORED.load(Ordering::Relaxed) == ROUNDS * KEYS,
        "exactly one store per key",
    );
    check(
        LOADED.load(Ordering::Relaxed) == total - ROUNDS * KEYS,
        "every other caller loaded",
    );
    check(
        WRONG_VALUE.load(Ordering::Relaxed) == 0,
        "every caller saw the stored value",
    );

    let f = FAILED.load(Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d rounds x %d workers x %d keys\n",
        ROUNDS as i64, WORKERS as i64, KEYS as i64);
}

/// Spawned separately so the closure's captures are plain moves —
/// `go!` needs a 'static body and the statics are borrowed by
/// reference at the call site.
fn go_worker(
    m: Arc<Map<int, string>>,
    round: usize,
    wg: Arc<WaitGroup>,
    stored: &'static AtomicUsize,
    loaded: &'static AtomicUsize,
    wrong: &'static AtomicUsize,
) {
    goish::go!(move || {
        for k in 0..KEYS {
            // The value is derived from the key, so every worker that
            // races to store the same key stores the SAME string —
            // which is what lets a reader check it got the winner's.
            let want = fmt::Sprintf!("r%d-k%d", round as int, k as int);
            let (got, was_loaded) = m.LoadOrStore(int::from(k as i64), want.clone());
            if was_loaded {
                loaded.fetch_add(1, Ordering::Relaxed);
            } else {
                stored.fetch_add(1, Ordering::Relaxed);
            }
            if got != want {
                wrong.fetch_add(1, Ordering::Relaxed);
            }
        }
        wg.Done();
    });
}
