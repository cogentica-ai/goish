// runtime::debug — Go's runtime introspection AND the user-facing
// `runtime/debug` package surface.
//
// This module hosts two logically-distinct groups of API:
//
//   1. Functions mirroring Go's `runtime` package (NumCPU,
//      NumGoroutine, GOMAXPROCS) — re-exported up to `runtime::`
//      so `goish::runtime::NumCPU()` Just Works. Reference:
//      /share/go/src/runtime/debug.go.
//
//   2. Functions mirroring Go's `runtime/debug` package
//      (Stack, PrintStack, SetGCPercent, FreeOSMemory,
//      SetMemoryLimit, GCStats / ReadGCStats, …). Users access
//      them as `goish::runtime::debug::SetGCPercent(...)`.
//      Reference: /share/go/src/runtime/debug/{stack.go,
//      garbage.go}.
//
// Goish v1 simplifications:
//
//   - GOMAXPROCS just reports the worker-pool size set at startup
//     by `bootstrap_workers()` (which used `sched_getaffinity`).
//     Goish does not yet support dynamic GOMAXPROCS adjustment;
//     calls with `n > 0` accept and return the new value but do
//     not currently spawn or stop worker Ms.
//
//   - NumGoroutine counts live goroutines (created via newproc, not
//     yet exited) — same definition as Go's `gcount()`.
//
//   - The `runtime/debug` package functions are slim: goish has
//     no garbage collector, no stack-walker, and no build-info
//     manifest. SetGCPercent/SetMemoryLimit/SetMaxStack/etc. accept
//     and remember a value (returning the previous setting) but
//     have no runtime effect. ReadGCStats fills the struct with
//     zero values and a single PauseQuantile entry. Stack returns
//     a fixed placeholder string. These stubs let user code
//     compile and behave sensibly without crashing.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int};

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

// ─── Go `runtime/debug` package surface ──────────────────────────────
//
// Below this line: ports of /share/go/src/runtime/debug/*.go. Users
// reach these through `goish::runtime::debug::<Name>(...)`, matching
// Go's import path `import "runtime/debug"`.

// ─── stack.go ────────────────────────────────────────────────────────

/// `runtime/debug.Stack()` (stack.go:23) — returns a formatted
/// stack trace for the calling goroutine.
///
/// **Slim deviation**: goish v1 has no stack-walker (the runtime
/// switches stacks via `swap_context` and does not maintain a
/// frame-pointer chain compatible with libunwind). This stub
/// returns a fixed placeholder so user code that logs stack traces
/// during a panic still produces output rather than crashing.
pub fn Stack() -> slice<byte> {
    let placeholder: &'static [u8] =
        b"goroutine 1 [running]:\n\tgoish runtime/debug.Stack: stack trace unavailable in slim port\n";
    let mut v: Vec<byte> = Vec::with_capacity(placeholder.len());
    v.extend_from_slice(placeholder);
    slice::__from_vec(v)
}

/// `runtime/debug.PrintStack()` (stack.go:17) — write the formatted
/// stack trace from `Stack()` to standard error.
pub fn PrintStack() {
    let s = Stack();
    let e = crate::os::Stderr();
    // Best-effort write; ignore errors as Go does.
    let _ = e.Write(s);
}

// ─── garbage.go: GCStats + ReadGCStats ───────────────────────────────

/// `runtime/debug.GCStats` (garbage.go:14) — collected garbage-
/// collection statistics. Goish has no GC, so all numeric fields
/// are zero and the slice fields are empty.
pub struct GCStats {
    /// Time of last collection. (Go: `time.Time`.) Goish reports
    /// the zero Time.
    pub LastGC: crate::time::Time,
    /// Total number of collections.
    pub NumGC: i64,
    /// Sum of all GC pause durations.
    pub PauseTotal: crate::time::Duration,
    /// Pause history, most recent first.
    pub Pause: slice<crate::time::Duration>,
    /// Pause-end times history, most recent first.
    pub PauseEnd: slice<crate::time::Time>,
    /// Optional output buffer for percentile summaries. If non-empty,
    /// `ReadGCStats` would fill it with min/quartile/max pause values.
    pub PauseQuantiles: slice<crate::time::Duration>,
}

impl GCStats {
    /// Zero-value constructor. Equivalent to Go's `var s debug.GCStats`.
    pub fn new() -> Self {
        GCStats {
            LastGC: crate::time::Time::default(),
            NumGC: 0,
            PauseTotal: crate::time::Duration(0),
            Pause: slice::__from_vec(Vec::new()),
            PauseEnd: slice::__from_vec(Vec::new()),
            PauseQuantiles: slice::__from_vec(Vec::new()),
        }
    }
}

/// `runtime/debug.ReadGCStats(stats)` (garbage.go:31) — fill `stats`
/// with current GC statistics.
///
/// **Slim deviation**: goish has no GC. This zeroes the numeric
/// fields, clears the history slices, and (if non-empty)
/// fills `PauseQuantiles` with zeros — matching what a long-lived
/// process with zero collections would report.
pub fn ReadGCStats(stats: &mut GCStats) {
    stats.LastGC = crate::time::Time::default();
    stats.NumGC = 0;
    stats.PauseTotal = crate::time::Duration(0);
    stats.Pause = slice::__from_vec(Vec::new());
    stats.PauseEnd = slice::__from_vec(Vec::new());
    // PauseQuantiles is caller-provided buffer; if non-empty, zero each entry.
    let n = stats.PauseQuantiles.len() as int;
    if n > 0 {
        let mut v: Vec<crate::time::Duration> = Vec::with_capacity(n as usize);
        for _ in 0..n {
            v.push(crate::time::Duration(0));
        }
        stats.PauseQuantiles = slice::__from_vec(v);
    }
}

// ─── garbage.go: knob setters (slim stubs that remember the value) ──

/// Initial GC percent — Go's default is 100 ("trigger collection
/// when heap doubles").
const DEFAULT_GC_PERCENT: i64 = 100;
static GC_PERCENT_CACHE: AtomicI64 = AtomicI64::new(DEFAULT_GC_PERCENT);

/// `runtime/debug.SetGCPercent(percent) -> previous` (garbage.go:93).
/// Slim: remembers the value and returns the previous setting; goish
/// has no GC so the knob is purely advisory.
pub fn SetGCPercent(percent: int) -> int {
    let prev = GC_PERCENT_CACHE.swap(percent as i64, Ordering::AcqRel);
    prev as int
}

/// `runtime/debug.FreeOSMemory()` (garbage.go:101) — force a GC
/// followed by attempting to release memory to the OS.
///
/// Slim: no-op. Goish allocates from the host libc-style heap and
/// has no separate "Go heap" to flush.
pub fn FreeOSMemory() {
    // intentionally empty
}

/// `runtime/debug.SetMaxStack(bytes) -> previous` (garbage.go:117).
///
/// Go semantics: the limit a goroutine stack may *grow* to before
/// the program crashes (64-bit default 1 GiB). Goish stacks don't
/// grow — a bare `go!()` goroutine gets a fixed-size `MAP_NORESERVE`
/// virtual reservation, lazily committed a page at a time, with a
/// guard page below it. The reservation *is* the crash limit: run
/// past it and the guard page faults with a spawn-site diagnostic —
/// the same observable behavior as Go's limit, at the same cost
/// (virtual space only, until touched).
///
/// So in goish this knob sets the reservation size used for bare
/// `go!()` goroutines spawned **after** the call (including
/// `WaitGroup.Go` / anything built on bare spawns). Deep-recursion
/// workloads — compilers, tree walkers — call it once at startup:
///
/// ```ignore
/// debug::SetMaxStack(512 * 1024 * 1024); // 512 MiB reservations
/// ```
///
/// Documented deviations from Go: the initial value is 1 MiB (Go:
/// 1 GiB — goish keeps bare goroutines VMA-cheap by default), and
/// already-running goroutines keep the reservation they were born
/// with. One-off sizes are better served by `go!(stack(N), …)`.
pub fn SetMaxStack(bytes: int) -> int {
    let prev = crate::runtime::sched::set_bare_reserve(bytes as usize);
    prev as int
}

/// Initial max-threads — Go's default is 10000.
const DEFAULT_MAX_THREADS: i64 = 10_000;
static MAX_THREADS_CACHE: AtomicI64 = AtomicI64::new(DEFAULT_MAX_THREADS);

/// `runtime/debug.SetMaxThreads(threads) -> previous` (garbage.go:135).
/// Slim: remembers the value. Goish v1 sizes its M pool once at
/// startup; this does not influence M creation.
pub fn SetMaxThreads(threads: int) -> int {
    let prev = MAX_THREADS_CACHE.swap(threads as i64, Ordering::AcqRel);
    prev as int
}

static PANIC_ON_FAULT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// `runtime/debug.SetPanicOnFault(enabled) -> previous`
/// (garbage.go:155). Slim: remembers the value. Goish does not
/// translate signal-induced faults into panics — bad memory access
/// still aborts the process.
pub fn SetPanicOnFault(enabled: bool) -> bool {
    PANIC_ON_FAULT.swap(enabled, Ordering::AcqRel)
}

/// Initial soft memory limit — Go's default is `math.MaxInt64`.
const DEFAULT_MEMORY_LIMIT: i64 = i64::MAX;
static MEMORY_LIMIT_CACHE: AtomicI64 = AtomicI64::new(DEFAULT_MEMORY_LIMIT);

/// `runtime/debug.SetMemoryLimit(limit) -> previous`
/// (garbage.go:234). A negative input does NOT adjust the limit
/// and instead returns the current value (matches Go's contract).
/// Slim: remembers the value but does not throttle allocations.
pub fn SetMemoryLimit(limit: i64) -> i64 {
    if limit < 0 {
        return MEMORY_LIMIT_CACHE.load(Ordering::Acquire);
    }
    MEMORY_LIMIT_CACHE.swap(limit, Ordering::AcqRel)
}

/// `runtime/debug.SetTraceback(level)` (garbage.go:179).
/// Slim: no-op. Goish does not print configurable tracebacks on
/// panic.
pub fn SetTraceback<S: Into<string>>(_level: S) {
    // intentionally empty
}

// ─── BuildInfo (mod.go) ──────────────────────────────────────────────

/// `runtime/debug.BuildInfo` (mod.go:24) — module/build information.
///
/// **Slim deviation**: goish v1 does not embed a Go-style module
/// manifest. `ReadBuildInfo` returns `(BuildInfo::default(), false)`
/// to mirror Go's "no build info available" return path.
#[derive(Default, Clone)]
pub struct BuildInfo {
    pub GoVersion: string,
    pub Path: string,
    pub Main: Module,
    pub Deps: slice<Module>,
    pub Settings: slice<BuildSetting>,
}

#[derive(Default, Clone)]
pub struct Module {
    pub Path: string,
    pub Version: string,
    pub Sum: string,
    // Go has Replace *Module here; skipped in slim port (no mod graph).
}

#[derive(Default, Clone)]
pub struct BuildSetting {
    pub Key: string,
    pub Value: string,
}

/// `runtime/debug.ReadBuildInfo()` (mod.go:46) — return the build
/// information embedded in the running binary, or `(zero, false)`.
///
/// Slim: always returns `(BuildInfo::default(), false)`.
pub fn ReadBuildInfo() -> (BuildInfo, bool) {
    (BuildInfo::default(), false)
}

// ─── SetCrashOutput (stack.go:49) ────────────────────────────────────

/// `runtime/debug.CrashOptions` (stack.go:36) — placeholder type for
/// future expansion. Currently has no fields.
#[derive(Default, Clone)]
pub struct CrashOptions {
    // for future expansion
    _private: (),
}

/// `runtime/debug.SetCrashOutput(f, opts) -> error` (stack.go:49) —
/// configure an additional file to receive crash output.
///
/// Slim: no-op returning nil. Goish does not produce duplicated
/// crash reports.
pub fn SetCrashOutput<F>(_f: F, _opts: CrashOptions) -> error {
    nil
}
