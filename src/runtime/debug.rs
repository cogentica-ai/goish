// runtime::debug — Go's runtime introspection (NumCPU, NumGoroutine,
// GOMAXPROCS).
//
// Reference: /share/go/src/runtime/debug.go.
//
// Goish v1 simplifications:
//   - GOMAXPROCS just reports the worker-pool size set at startup
//     by `bootstrap_workers()` (which used `sched_getaffinity`).
//     Goish does not yet support dynamic GOMAXPROCS adjustment;
//     calls with `n > 0` accept and return the new value but do
//     not currently spawn or stop worker Ms.
//
//   - NumGoroutine counts live goroutines (created via newproc, not
//     yet exited) — same definition as Go's `gcount()`.

#![allow(non_snake_case)]

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::types::int;

/// Cached at startup so subsequent calls are a single atomic load.
/// Set by the first NumCPU call.
static NUM_CPU_CACHE: AtomicUsize = AtomicUsize::new(0);

/// Currently-active GOMAXPROCS value. Initialized lazily from
/// `sched::num_cpus()` on the first read; subsequent calls update
/// the cached value (without actually changing the worker pool —
/// see module-level note).
static GOMAXPROCS_CACHE: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn cpu_count() -> usize {
    let cached = NUM_CPU_CACHE.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }
    let n = super::sched::num_cpus();
    // Race is benign — multiple threads racing to populate the cache
    // all write the same value.
    NUM_CPU_CACHE.store(n, Ordering::Release);
    n
}

/// `runtime.NumCPU()` — number of logical CPUs available to this
/// process (the affinity mask popcount). Mirrors `NumCPU`
/// (debug.go:154). Goish queries `sched_getaffinity` once at first
/// call and caches.
pub fn NumCPU() -> int {
    cpu_count() as int
}

/// `runtime.NumGoroutine()` — count of goroutines created via
/// `go!()` and not yet exited (live G count). Mirrors
/// `NumGoroutine` (debug.go:179) which calls `gcount()` over the
/// global counters. Goish has a single global LIVE_G_COUNT, so
/// this is a single atomic load.
pub fn NumGoroutine() -> int {
    super::sched::live_g_count() as int
}

/// `runtime.GOMAXPROCS(n)` — get/set the maximum number of CPUs
/// that can execute goroutines simultaneously, returning the
/// **previous** setting. `n <= 0` means "report only, don't set".
/// Mirrors `GOMAXPROCS` (debug.go:70).
///
/// **Goish v1 caveat**: setting only updates the reported value;
/// it does not actually grow or shrink the worker M pool. The
/// pool is sized once at startup by `bootstrap_workers()`.
pub fn GOMAXPROCS(n: int) -> int {
    let prev = {
        let cached = GOMAXPROCS_CACHE.load(Ordering::Acquire);
        if cached != 0 {
            cached
        } else {
            let init = cpu_count();
            // Same benign-race tolerance as cpu_count().
            GOMAXPROCS_CACHE.store(init, Ordering::Release);
            init
        }
    };
    if n > 0 {
        GOMAXPROCS_CACHE.store(n as usize, Ordering::Release);
    }
    prev as int
}
