// go: file testing/allocs.go decls: AllocsPerRun
//
// testing/allocs.go — measuring allocations around a function call.
//
// Portable only since runtime::ReadMemStats landed: this is the whole
// of the file, and its body is two MemStats samples with the calls in
// between.

#![allow(non_snake_case)]

use crate::types::int;

// go: sdk 1.25.5 testing/allocs.go:20-48 AllocsPerRun
/// Go: "AllocsPerRun returns the average number of allocations during
/// calls to f. Although the return value has type float64, it will
/// always be an integral value.
///
/// To compute the number of allocations, the function will first be run
/// once as a warm-up. The average number of allocations over the
/// specified number of runs will then be measured and returned."
///
/// The warm-up run matters: it is not counted, and without it the first
/// call's lazy initialisation — a sync.Once, a map's first bucket — is
/// charged to the average and the answer is wrong by a constant.
///
/// Go's comment on the integer division is worth keeping: "We are
/// forced to return a float64 because the API is silly, but do the
/// division as integers so we can ask if AllocsPerRun()==1 instead of
/// AllocsPerRun()<2."
///
/// Deviations. Go pins GOMAXPROCS to 1 for the measurement and restores
/// it on the way out, so a concurrent allocation on another P cannot
/// land in the window; goish's `runtime::GOMAXPROCS` is a no-op that
/// reports the CPU count, so that guard is unavailable and a
/// measurement taken while other goroutines allocate will read high.
/// Go also panics if called during a parallel test — goish has no
/// `t.Parallel`, so there is no such state to check.
pub fn AllocsPerRun(runs: int, f: impl Fn()) -> crate::types::float64 {
    // Go: warm up the function.
    f();

    // Go: measure the starting statistics.
    let mut memstats = crate::runtime::MemStats::default();
    crate::runtime::ReadMemStats(&mut memstats);
    let start = memstats.Mallocs;

    // Go: run the function the specified number of times.
    let mut i: int = 0;
    while i < runs {
        f();
        i += 1;
    }

    // Go: read the final statistics.
    crate::runtime::ReadMemStats(&mut memstats);
    let mallocs = memstats.Mallocs - start;

    // Go: return float64(mallocs / uint64(runs))
    if runs <= 0 {
        return 0.0;
    }
    return crate::float64(mallocs / crate::uint64(runs));
}
