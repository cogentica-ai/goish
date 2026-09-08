// go: package testing
//
// Only `corpusEntry` is ported here. The rest of fuzz.go is the fuzzing
// engine, which drives internal/fuzz — a package goish does not have
// (it needs a coordinator process, a worker protocol, and compiler
// coverage instrumentation). corpusEntry is carried across on its own
// because testDeps names it in four method signatures, so the driver
// cannot be ported without it.
//
// go: file testing/fuzz.go decls: fuzzResult.String
// goishlint:ignore GOISH021 F, fuzzCrashError, fuzzContext, fuzzState, fuzzMode, fuzzCoordinator, fuzzWorker, seedCorpusOnly, fuzzWorkerExitCode, supportedTypes — the fuzzing engine needs internal/fuzz, which goish does not have; only corpusEntry is carried across, for testDeps' signatures.
// goishlint:ignore GOISH018 Add, Fail, Fuzz, Helper, Skipped, Skip, Skipf, SkipNow, Error, Errorf, Fatal, Fatalf, Log, Logf, Setenv, TempDir, Name, Cleanup, report, fRunner, runFuzzTests, runFuzzing, initFuzzFlags — same: F and the fuzzing engine are not ported.

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

// goishlint:ignore GOISH019 InternalFuzzTarget — Go's `Fn` is
// `func(f *F)`; goish has no `F`, so the field is a bare `fn()`
// placeholder. Nothing calls it: `listTests`, the only consumer that
// can exist without the fuzzing engine, reads `Name` and never `Fn`.
// go: sdk 1.25.5 testing/fuzz.go:49-52 InternalFuzzTarget
/// Go: "An internal type but exported because it is cross-package; part
/// of the implementation of the 'go test' command."
#[allow(non_snake_case)]
pub struct InternalFuzzTarget {
    pub Name: string,
    pub Fn: fn(),
}

// go: sdk 1.25.5 testing/fuzz.go:432-436 fuzzResult
/// Go: the outcome of a fuzzing run. Carried across for its String
/// method, which the driver prints; the engine that would produce one
/// is not ported.
#[allow(non_snake_case)]
#[derive(Default)]
pub struct fuzzResult {
    /// Go: "The number of iterations."
    pub N: crate::types::int,
    /// Go: "The total time taken."
    pub T: crate::time::Duration,
    /// Go: "Error is the error from the failing input".
    pub Error: crate::errors::error,
}

#[allow(non_snake_case)]
impl fuzzResult {
    // go: sdk 1.25.5 testing/fuzz.go:438-443 fuzzResult.String
    /// Go: the empty string on success — NOT "ok" or a summary. The
    /// driver prints this unconditionally, so a successful fuzz run
    /// must contribute nothing to the output.
    pub fn String(&self) -> string {
        if self.Error == crate::errors::nil {
            return string::from_static("");
        }
        return self.Error.Error();
    }
}
