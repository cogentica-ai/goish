// go: package testing/internal/testdeps
//
// go: file testing/internal/testdeps/deps.go decls: TestDeps.InitRuntimeCoverage, TestDeps.MatchString, TestDeps.ImportPath, testLog.Getenv, testLog.Open, testLog.Stat, testLog.Chdir, testLog.add, TestDeps.StartTestLog, TestDeps.StopTestLog
// goishlint:ignore GOISH018 StartCPUProfile, StopCPUProfile, WriteProfileTo, SetPanicOnExit0, CoordinateFuzzing, RunFuzzWorker, ReadCorpus, CheckCorpus, ResetCoverage, SnapshotCoverage, coverTearDown — profiling needs runtime/pprof and runtime/trace, fuzzing needs internal/fuzz, coverage needs compiler instrumentation, and SetPanicOnExit0 needs internal/testlog, none of which goish has.
// goishlint:ignore GOISH021 Cover, CoverMode, Covered, CoverSelectedPackages, CoverSnapshotFunc, CoverProcessTestDirFunc, CoverMarkProfileEmittedFunc, matchPat, matchRe — package state for the same three subsystems.

#![allow(non_snake_case)]

extern crate alloc;


use crate::gostring::string;

// go: sdk 1.25.5 testing/internal/testdeps/deps.go:34 TestDeps
/// Go: "TestDeps is an implementation of the testing.testDeps
/// interface, suitable for passing to testing.MainStart."
pub struct TestDeps;

/// Go's `matchPat`/`matchRe` — the last pattern compiled, cached so a
/// -run applied to a thousand test names compiles once.
static MATCH_CACHE: crate::sync::Mutex<Option<(string, crate::regexp::Regexp)>> =
    crate::sync::Mutex::new(None);

impl TestDeps {
    // go: sdk 1.25.5 testing/internal/testdeps/deps.go:39-48 TestDeps.MatchString
    /// Go: compile the pattern, caching it against the last one used.
    ///
    /// The cache is keyed on the PATTERN, not merely non-nil, so a
    /// second distinct -run in the same process recompiles rather than
    /// silently matching against the first.
    pub fn MatchString(&self, pat: string, str_: string) -> (bool, crate::errors::error) {
        let mut g = MATCH_CACHE.Lock();
        let stale = match g.as_ref() {
            None => true,
            Some((p, _)) => *p != pat,
        };
        if stale {
            let (re, err) = crate::regexp::Compile(pat.clone());
            if err != crate::errors::nil {
                return (false, err);
            }
            *g = Some((pat, re));
        }
        let re = &g.as_ref().unwrap().1;
        return (re.MatchString(str_), crate::errors::nil);
    }

    // go: sdk 1.25.5 testing/internal/testdeps/deps.go:65-67 TestDeps.ImportPath
    /// Go returns the package var `ImportPath`, which the generated
    /// main package sets. goish has no code generator, so it is empty —
    /// the same value Go reports for a binary built without one.
    pub fn ImportPath(&self) -> string {
        return string::from_static("");
    }

    // go: sdk 1.25.5 testing/internal/testdeps/deps.go:111-125 TestDeps.StartTestLog
    // goishlint:ignore GOISH018 StartTestLog — Go also calls
    // `testlog.SetLogger(&log)` so the os package reports its file
    // operations here. goish has no internal/testlog, so nothing feeds
    // the log; the writer and its header are ported, the hook is not.
    pub fn StartTestLog(&self, w: alloc::boxed::Box<dyn crate::io::Writer + Send + Sync>) {
        let mut l = LOG.Lock();
        l.w = Some(crate::bufio::NewWriter(w));
        if !l.set {
            // Go: "Tests that define TestMain and then run m.Run
            // multiple times will call StartTestLog/StopTestLog
            // multiple times."
            l.set = true;
            // Go: "known to cmd/go/internal/test/test.go" — the header
            // is what makes the file recognisable as a test log.
            if let Some(bw) = l.w.as_mut() {
                let _ = bw.WriteString(string::from_static("# test log\n"));
            }
        }
    }

    // go: sdk 1.25.5 testing/internal/testdeps/deps.go:218-223 TestDeps.InitRuntimeCoverage
    /// Go: hand `testing` the coverage mode and its teardown, or three zero
    /// values when the binary was not built with coverage.
    ///
    /// goish takes the second branch permanently: `CoverMode` is set by
    /// the compiler's generated main, which does not exist here. That
    /// is the same answer Go gives for `go test` without `-cover`, and
    /// it is what makes `registerCover` record nothing.
    pub fn InitRuntimeCoverage(
        &self,
    ) -> (
        string,
        Option<crate::testing::testing::TearDownFunc>,
        Option<crate::testing::testing::SnapCovFunc>,
    ) {
        // Go: `if CoverMode == "" { return }`.
        return (string::from_static(""), None, None);
    }

    // go: sdk 1.25.5 testing/internal/testdeps/deps.go:126-133 TestDeps.StopTestLog
    /// The Flush is the point: the log is buffered, so without it a
    /// short test's entries never reach the file.
    pub fn StopTestLog(&self) -> crate::errors::error {
        let mut l = LOG.Lock();
        let err = match l.w.as_mut() {
            Some(bw) => bw.Flush(),
            None => crate::errors::nil,
        };
        l.w = None;
        return err;
    }
}

// goishlint:ignore GOISH019 testLog — Go's `mu sync.Mutex` guards the
// other two fields; goish wraps the whole struct in one Mutex instead,
// so the guard is not a field. Same two pieces of state.
// go: sdk 1.25.5 testing/internal/testdeps/deps.go:70-74 testLog
/// Go: the writer behind `internal/testlog` — it records each file
/// operation a test performs so cmd/go can decide whether a cached
/// result is still valid.
#[allow(non_camel_case_types)]
pub struct testLog {
    pub(crate) w: Option<
        crate::bufio::Writer<alloc::boxed::Box<dyn crate::io::Writer + Send + Sync>>,
    >,
    pub(crate) set: bool,
}

// go: sdk 1.25.5 testing/internal/testdeps/deps.go:109 log
static LOG: crate::sync::Mutex<testLog> = crate::sync::Mutex::new(testLog {
    w: None,
    set: false,
});

impl testLog {
    // go: sdk 1.25.5 testing/internal/testdeps/deps.go:76-78 testLog.Getenv
    // goishlint:ignore GOISH020 Getenv — Go's receiver is `l *testLog`,
    // the package-level `log` var. goish's `log` is a static behind a
    // Mutex, which a `&self` method cannot reach without handing out a
    // borrow of it, so these are associated functions over that static.
    pub fn Getenv(key: string) {
        testLog::add(string::from_static("getenv"), key);
    }

    // go: sdk 1.25.5 testing/internal/testdeps/deps.go:80-82 testLog.Open
    // goishlint:ignore GOISH020 Open — Go's receiver is `l *testLog`,
    // the package-level `log` var. goish's `log` is a static behind a
    // Mutex, which a `&self` method cannot reach without handing out a
    // borrow of it, so these are associated functions over that static.
    pub fn Open(name: string) {
        testLog::add(string::from_static("open"), name);
    }

    // go: sdk 1.25.5 testing/internal/testdeps/deps.go:84-86 testLog.Stat
    // goishlint:ignore GOISH020 Stat — Go's receiver is `l *testLog`,
    // the package-level `log` var. goish's `log` is a static behind a
    // Mutex, which a `&self` method cannot reach without handing out a
    // borrow of it, so these are associated functions over that static.
    pub fn Stat(name: string) {
        testLog::add(string::from_static("stat"), name);
    }

    // go: sdk 1.25.5 testing/internal/testdeps/deps.go:88-90 testLog.Chdir
    // goishlint:ignore GOISH020 Chdir — Go's receiver is `l *testLog`,
    // the package-level `log` var. goish's `log` is a static behind a
    // Mutex, which a `&self` method cannot reach without handing out a
    // borrow of it, so these are associated functions over that static.
    pub fn Chdir(name: string) {
        testLog::add(string::from_static("chdir"), name);
    }

    // go: sdk 1.25.5 testing/internal/testdeps/deps.go:93-107 testLog.add
    // goishlint:ignore GOISH020 add — Go's receiver is `l *testLog`,
    // the package-level `log` var. goish's `log` is a static behind a
    // Mutex, which a `&self` method cannot reach without handing out a
    // borrow of it, so these are associated functions over that static.
    /// Go: append one `op name` line.
    ///
    /// A name containing a newline is DROPPED rather than escaped: the
    /// log is line-oriented and cmd/go parses it that way, so one
    /// embedded newline would desynchronise every entry after it. An
    /// empty name is dropped for the same reason.
    pub fn add(op: string, name: string) {
        if crate::strings::Contains(name.clone(), "\n") || name.Len() == 0 {
            return;
        }
        let mut l = LOG.Lock();
        let bw = match l.w.as_mut() {
            Some(bw) => bw,
            None => return,
        };
        let _ = bw.WriteString(op);
        let _ = bw.WriteByte(b' ');
        let _ = bw.WriteString(name);
        let _ = bw.WriteByte(b'\n');
    }
}
