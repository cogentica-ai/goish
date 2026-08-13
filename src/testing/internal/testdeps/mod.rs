// go: package testing/internal/testdeps
//
// testing/internal/testdeps — the canonical `testDeps` implementation,
// which `go test`'s generated main package hands to `testing.MainStart`.
//
// **Partial port.** The fuzzing members need `internal/fuzz`, the
// profiling members need `runtime/pprof` and `runtime/trace`, and the
// coverage members need compiler instrumentation — none of which goish
// has. What is here is the rest: regexp name matching, the import path,
// and the testlog writer that records file operations for cmd/go's
// caching.

mod deps;

pub use deps::{testLog, TestDeps};
