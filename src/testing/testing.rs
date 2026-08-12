// go: file testing/testing.go decls: common.FailNow, common.Skip, common.SkipNow, T.Run, tRunner
//
// testing/testing.go — the parts of Go's test driver that are ported.
//
// **Partial port.** `common`, `M`, `Init`, the flag set, the chatty
// printer, Parallel, Context/Deadline, Setenv/Chdir and the output
// buffering are not here yet; `T` and the runner live in mod[rs] and
// are hand-written around what is ported. This file exists so the
// anchored declarations are not in the module root, which GOISH015
// forbids.
//
// goishlint:ignore GOISH018 after, Attr, before, callerName, callSite, Chdir, CheckCorpus, checkFuzzFn, checkParallel, checkRaces, Cleanup, Context, CoordinateFuzzing, CoverMode, Deadline, destination, Error, Errorf, Fail, Failed, Fatal, Fatalf, flushPartial, flushToParent, fmtDuration, frameSkip, Get, Helper, ImportPath, Init, InitRuntimeCoverage, IsBoolFlag, listTests, log, Log, Logf, Main, MainStart, MatchString, Name, newChattyPrinter, newTestState, Output, Parallel, parseCpuList, pcToName, prefix, Printf, private, ReadCorpus, release, removeAll, report, ResetCoverage, resetRaces, runCleanup, RunFuzzWorker, runningList, runTests, RunTests, Set, Setenv, setOutputWriter, SetPanicOnExit0, setRan, Short, shouldFailFast, Skipf, Skipped, SnapshotCoverage, startAlarm, StartCPUProfile, StartTestLog, stopAlarm, StopCPUProfile, StopTestLog, String, TempDir, Testing, testingSynctestTest, toOutputDir, Updatef, Verbose, waitParallel, Write, writeLine, writeProfiles, WriteProfileTo — the driver is only partly ported; see the note above.
// goishlint:ignore GOISH021 _, blockProfile, blockProfileRate, chatty, chattyFlag, chattyPrinter, common, count, coverProfile, cpuList, cpuListStr, cpuProfile, errMain, errNilPanicOrGoexit, failFast, fullPath, gocoverdir, haveExamples, indent, indenter, initRan, InternalTest, M, marker, match, matchList, matchStringOnly, maxStackLen, memProfile, memProfileRate, mutexProfile, mutexProfileFraction, normalPanic, numFailed, outputDir, outputWriter, panicHandling, panicOnExit0, parallel, parallelConflict, parallelStart, parallelStop, realStderr, recoverAndReturnPanic, running, short, shuffle, skip, T, TB, testBinary, testDeps, testingTesting, testlog, testlogFile, testState, timeout, traceFile — same: the driver's types and package state come with the driver.
// goishlint:ignore GOISH017 common.FailNow, common.Skip, common.SkipNow — declared on Go's `common`, ported as methods on goish's `T`, which is the only type that embeds it here.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{indent_for, write_status, StringBytesAccess, TState, T, TEST_STACK};
use crate::gostring::string;

impl T {
    // go: sdk 1.25.5 testing/testing.go:987-1014 common.FailNow
    /// Go: "FailNow marks the function as having failed and stops its
    /// execution by calling runtime.Goexit (which then runs all
    /// deferred calls in the current goroutine). Execution will
    /// continue at the next test or benchmark."
    ///
    /// Each test body runs on its own goroutine (see `tRunner`), so the
    /// Goexit ends this test and leaves the rest of the suite running.
    ///
    /// **Deviation — when cleanups run.** Go relies on Goexit unwinding
    /// through `tRunner`'s deferred call to run the cleanup stack and
    /// signal the parent. goish is `panic = "abort"` and
    /// `runtime::Goexit` does not run Drop-based deferred work (see its
    /// definition), so this runs the cleanup stack and signals the
    /// parent *before* the Goexit, on a live stack. The observable
    /// ordering is the same — cleanups run, the parent is released,
    /// the goroutine dies — but it happens on the way in rather than on
    /// the way out.
    pub fn FailNow(&self) -> ! {
        self.state.failed.store(true, Ordering::Release);
        // Go: c.mu.Lock(); c.finished = true; c.mu.Unlock()
        self.state.finished.store(true, Ordering::Release);
        self.finish_before_goexit();
        crate::runtime::Goexit();
    }

    // go: none — goish-only: the cleanup-and-signal step Go performs in
    // `tRunner`'s deferred call during the Goexit unwind. goish has no
    // unwind, so both the normal return path and the Goexit path call
    // this explicitly. Idempotent: the `reported` flag makes a second
    // call a no-op, so a `Cleanup` callback that itself calls `FailNow`
    // cannot re-enter it.
    fn finish_before_goexit(&self) {
        if self
            .state
            .reported
            .swap(true, Ordering::AcqRel)
        {
            return;
        }
        self.drain_cleanups();
        // Wake whoever is waiting on this test. Buffered with capacity
        // 1 and sent exactly once, so this never blocks — which matters,
        // because parking here would strand a test that is on its way
        // out.
        self.state.signal.Send(true);
    }

    // go: sdk 1.25.5 testing/testing.go:1223-1227 common.Skip
    /// Go: "Skip is equivalent to Log followed by SkipNow."
    ///
    /// Before `runtime::Goexit` existed this called `syscall::Exit(0)`
    /// and took the whole suite down with it, which made Skip unusable
    /// anywhere but the last test. It now ends only this test's
    /// goroutine.
    pub fn Skip<M: Into<string>>(&self, msg: M) -> ! {
        let msg: string = msg.into();
        self.write_line(b"skp", &msg);
        self.SkipNow();
    }

    // go: sdk 1.25.5 testing/testing.go:1244-1251 common.SkipNow
    /// Go: "SkipNow marks the test as having been skipped and stops its
    /// execution by calling runtime.Goexit. If a test fails (see Error,
    /// Errorf, Fail) and is then skipped, it is still considered to
    /// have failed. Execution will continue at the next test or
    /// benchmark."
    ///
    /// Same cleanup-ordering deviation as `FailNow`.
    pub fn SkipNow(&self) -> ! {
        // Go: c.mu.Lock(); c.skipped = true; c.finished = true;
        //     c.mu.Unlock(); runtime.Goexit()
        self.state.skipped.store(true, Ordering::Release);
        self.state.finished.store(true, Ordering::Release);
        self.finish_before_goexit();
        crate::runtime::Goexit();
    }

    // go: sdk 1.25.5 testing/testing.go:1948-2015 T.Run
    /// Go: "Run runs f as a subtest of t called name. It runs f in a
    /// separate goroutine and blocks until f returns or calls
    /// t.Parallel to become a parallel test. Run may be called
    /// simultaneously from multiple goroutines, but all such calls must
    /// return before the outer test function for t returns."
    ///
    /// Running `f` on its own goroutine is what makes `t.Fatal` inside
    /// a subtest end that subtest rather than everything above it.
    ///
    /// **Deviation — the `Send + 'static` bound.** Go's closure can
    /// capture freely because its escape analysis and GC keep the
    /// captures alive across the goroutine boundary. goish spawns
    /// through `go!()`, which requires an owned `'static` body, so a
    /// subtest closure must own what it uses. Non-capturing closures
    /// and `move` closures over owned data are unaffected.
    pub fn Run<F: FnOnce(&mut T) + Send + 'static>(&mut self, name: string, f: F) -> bool {
        // Compose the qualified name "Parent/Child" for logging.
        let mut qualified_bytes: Vec<u8> = Vec::new();
        qualified_bytes.extend_from_slice(self.name.clone().__as_bytes_internal());
        qualified_bytes.push(b'/');
        qualified_bytes.extend_from_slice(name.__as_bytes_internal());
        let qualified = string::from_bytes(&qualified_bytes);

        let sub = T {
            name: qualified.clone(),
            state: Arc::new(TState::new()),
            depth: self.depth + 1,
        };

        let header_indent = indent_for(sub.depth);
        write_status(b"=== RUN  ", header_indent.as_bytes(), &qualified);

        let state = sub.state.clone();
        tRunner(sub, f);

        let passed = !state.failed.load(Ordering::Acquire);
        if state.skipped.load(Ordering::Acquire) {
            write_status(b"--- SKIP: ", header_indent.as_bytes(), &qualified);
        } else if passed {
            write_status(b"--- PASS: ", header_indent.as_bytes(), &qualified);
        } else {
            write_status(b"--- FAIL: ", header_indent.as_bytes(), &qualified);
            // Go: a failing subtest fails its parent.
            self.state.failed.store(true, Ordering::Release);
        }
        return passed;
    }
}

// go: sdk 1.25.5 testing/testing.go:1774-1940 tRunner
/// Go: run `fn(t)` on its own goroutine and block until it finishes,
/// whether it returned normally or ended through `runtime.Goexit`.
///
/// The goroutine is the whole point. `t.Fatal` and `t.Skip` terminate
/// the calling goroutine, so a test that fails hard must not be sharing
/// one with the runner or with its siblings — otherwise a single
/// `Fatal` takes down everything after it. That was goish's behaviour
/// until `runtime::Goexit` landed: `Skip` called `syscall::Exit(0)`.
///
/// **Deviations.** Go's `tRunner` carries the parallel-subtest barrier,
/// race-error accounting, and a deferred recover that re-panics after
/// flushing output to the root. None of those exist here yet:
/// `t.Parallel` is not ported, goish has no race detector, and a panic
/// in a test is already isolated per-goroutine by the runtime's own
/// recovery path. What remains is the part that matters for
/// correctness — spawn, wait for exactly one signal, and let the caller
/// read the outcome out of the shared state.
pub(crate) fn tRunner<F: FnOnce(&mut T) + Send + 'static>(t: T, fn_: F) {
    let state = t.state.clone();

    // Go: `go tRunner(t, fn)`. The explicit stack is goish's: a test
    // body is arbitrary user code and the 2 KiB default is nowhere near
    // enough. Reserved, not committed.
    crate::go!(stack(TEST_STACK), move || {
        let mut t = t;
        fn_(&mut t);
        // Reached only when the test returned normally — a FailNow or
        // SkipNow has already run this and Goexited.
        t.finish_before_goexit();
    });

    // Go: `<-t.signal`. Exactly one send happens per test, from
    // whichever path finished it.
    let _ = state.signal.Recv();
}
