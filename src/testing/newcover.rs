// go: file testing/newcover.go decls: Coverage
//
// testing/newcover.go — the coverage-reporting surface.
//
// **Partial port, and permanently so.** Coverage counters are emitted
// by cmd/compile under `-cover`; a library cannot arrange that. Only
// `Coverage` is ported, taking Go's own "coverage not enabled" branch.
//
// goishlint:ignore GOISH018 coverReport, registerCover, RegisterCover, InitRuntimeCoverage, ResetCoverage, SnapshotCoverage, mustBeNil — all drive counters the compiler does not emit here.
// goishlint:ignore GOISH021 cover, goCoverTearDown, coverReport2 — same.

#![allow(non_snake_case)]

extern crate alloc;

// go: sdk 1.25.5 testing/newcover.go:54-59 Coverage
/// Go: "Coverage reports the current code coverage as a fraction in the
/// range [0, 1]. If coverage is not enabled, Coverage returns 0."
///
/// Coverage is never enabled here — see `CoverMode` — so this takes
/// Go's own `cover.mode == ""` branch and returns 0.
pub fn Coverage() -> crate::types::float64 {
    // Go: if cover.mode == "" { return 0.0 }
    return 0.0;
}
