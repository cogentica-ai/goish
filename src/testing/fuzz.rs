// go: package testing
//
// Only `corpusEntry` is ported here. The rest of fuzz.go is the fuzzing
// engine, which drives internal/fuzz — a package goish does not have
// (it needs a coordinator process, a worker protocol, and compiler
// coverage instrumentation). corpusEntry is carried across on its own
// because testDeps names it in four method signatures, so the driver
// cannot be ported without it.
//
// go: file testing/fuzz.go decls:
// goishlint:ignore GOISH021 F, InternalFuzzTarget, fuzzResult, fuzzCrashError, fuzzContext, fuzzState, fuzzMode, fuzzCoordinator, fuzzWorker, seedCorpusOnly, fuzzWorkerExitCode, supportedTypes — the fuzzing engine needs internal/fuzz, which goish does not have; only corpusEntry is carried across, for testDeps' signatures.
// goishlint:ignore GOISH018 Add, Fail, Fuzz, Helper, Skipped, Skip, Skipf, SkipNow, Error, Errorf, Fatal, Fatalf, Log, Logf, Setenv, TempDir, Name, Cleanup, report, fRunner, runFuzzTests, runFuzzing, initFuzzFlags, String — same: F and the fuzzing engine are not ported.

use crate::gostring::string;

// go: sdk 1.25.5 testing/fuzz.go:88-97 corpusEntry
/// Go: "corpusEntry is an alias to the same type as
/// internal/fuzz.CorpusEntry. We use a type alias because we don't want
/// to export this type, and we can't import internal/fuzz from
/// testing."
///
/// goish spells it as a named struct rather than an alias to an
/// anonymous one: Rust has no anonymous struct types, and nothing here
/// depends on the two spellings being identical, only on the field set.
#[derive(Clone, Default, PartialEq)]
#[allow(non_snake_case)]
pub(crate) struct corpusEntry {
    pub Parent: string,
    pub Path: string,
    pub Data: crate::goslice::slice<crate::types::byte>,
    pub Values: crate::goslice::slice<crate::goany::Any>,
    pub Generation: crate::types::int,
    pub IsSeed: bool,
}
