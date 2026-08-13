// go: file testing/testing.go decls: common.resetRaces, common.checkRaces, MainStart, M.startAlarm, M.stopAlarm, listTests, toOutputDir, runTests, RunTests, runningList, T.report, shouldFailFast, common.TempDir, removeAll, common.frameSkip, common.callSite, common.runCleanup, T.Parallel, T.Deadline, newTestState, testState.waitParallel, testState.release, T.checkParallel, common.setRan, common.destination, common.flushToParent, indenter.Write, common.setOutputWriter, common.flushPartial, common.Output, outputWriter.Write, outputWriter.writeLine, chattyFlag.Get, chattyFlag.prefix, common.private, common.Attr, common.checkFuzzFn, matchStringOnly.MatchString, matchStringOnly.StartCPUProfile, matchStringOnly.StopCPUProfile, matchStringOnly.WriteProfileTo, matchStringOnly.ImportPath, matchStringOnly.StartTestLog, matchStringOnly.StopTestLog, matchStringOnly.SetPanicOnExit0, matchStringOnly.CoordinateFuzzing, matchStringOnly.RunFuzzWorker, matchStringOnly.ReadCorpus, matchStringOnly.CheckCorpus, matchStringOnly.ResetCoverage, matchStringOnly.SnapshotCoverage, matchStringOnly.InitRuntimeCoverage, callerName, pcToName, newChattyPrinter, chattyPrinter.Updatef, chattyPrinter.Printf, common.Setenv, common.Chdir, common.Context, parseCpuList, CoverMode, Init, Short, Verbose, Testing, chattyFlag.IsBoolFlag, chattyFlag.Set, chattyFlag.String, fmtDuration, common.Name, common.Log, common.Logf, common.Error, common.Errorf, common.Fail, common.FailNow, common.Failed, common.Fatal, common.Fatalf, common.Skip, common.Skipf, common.SkipNow, common.Skipped, common.Helper, common.Cleanup, T.Run, tRunner
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
// goishlint:ignore GOISH020 newChattyPrinter, Updatef, Printf — Go reads
// the package-level `chatty.json` in the constructor and is variadic
// over `...any` in both printers. goish passes `json` explicitly (which
// is what Go's own comment on `prefix` says it wanted: "allows tests to
// check the json behavior without modifying the global variable") and
// takes the already-formatted string, as elsewhere in this port.
// goishlint:ignore GOISH020 parseCpuList — Go reads the package-level
// `*cpuListStr` and writes the package-level `cpuList`; goish takes the
// string and returns the list, so the helper does not depend on flag
// registration having happened and can be tested on its own.
// goishlint:ignore GOISH020 Logf, Skipf — Go's signature is `(format string, args ...any)`; goish takes the already-formatted string, since `Sprintf!` formats at the call site. `Errorf`/`Fatalf` keep the runtime-variadic slice for ports that spread one, so both shapes exist in the package.
// goishlint:ignore GOISH018 after, Attr, before, callSite, CheckCorpus, checkFuzzFn, checkParallel, checkRaces, CoordinateFuzzing, Deadline, destination, flushPartial, flushToParent, frameSkip, Get, ImportPath, InitRuntimeCoverage, listTests, log, Main, MainStart, MatchString, newTestState, Output, Parallel, private, ReadCorpus, release, removeAll, report, ResetCoverage, resetRaces, runCleanup, RunFuzzWorker, runningList, runTests, RunTests, setOutputWriter, SetPanicOnExit0, setRan, shouldFailFast, SnapshotCoverage, startAlarm, StartCPUProfile, StartTestLog, stopAlarm, StopCPUProfile, StopTestLog, TempDir, testingSynctestTest, toOutputDir, waitParallel, Write, writeLine, writeProfiles, WriteProfileTo — the driver is only partly ported; see the note above.
// goishlint:ignore GOISH021 _, blockProfile, blockProfileRate, chatty, common, count, coverProfile, cpuList, cpuListStr, cpuProfile, errNilPanicOrGoexit, failFast, fullPath, gocoverdir, haveExamples, indent, indenter, initRan, match, memProfile, memProfileRate, mutexProfile, mutexProfileFraction, normalPanic, outputDir, outputWriter, panicHandling, panicOnExit0, parallel, parallelStart, parallelStop, realStderr, recoverAndReturnPanic, short, shuffle, skip, T, TB, testingTesting, testlog, testlogFile, timeout, traceFile — same: the driver's types and package state come with the driver.
// goishlint:ignore GOISH017 common.FailNow, common.Skip, common.SkipNow — declared on Go's `common`, ported as methods on goish's `T`, which is the only type that embeds it here.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{StringBytesAccess, TState, T, TEST_STACK};
use crate::gostring::string;
use crate::types::int;
use crate::types::uintptr;

impl T {
    // go: sdk 1.25.5 testing/testing.go:938-940 common.Name
    /// Go: "Name returns the name of the running (sub-) test or
    /// benchmark. The name will include the name of the test along with
    /// the names of any nested sub-tests."
    pub fn Name(&self) -> string {
        return self.name.clone();
    }

    // go: sdk 1.25.5 testing/testing.go:1189-1192 common.Logf
    /// Go: "Logf formats its arguments according to the format,
    /// analogous to Printf, and records the text in the error log. A
    /// final newline is added if not provided."
    ///
    /// Deviation: Go is variadic over `...any`. goish takes the already
    /// formatted string, which is what `Sprintf!` produces at the call
    /// site; `Errorf` below keeps the runtime-variadic shape for ports
    /// that spread a slice.
    pub fn Logf<M: Into<string>>(&self, msg: M) {
        self.checkFuzzFn(string::from_static("Logf"));
        let msg: string = msg.into();
        self.write_line(b"   ", &msg);
    }

    // go: sdk 1.25.5 testing/testing.go:1178-1181 common.Log
    /// Go: "Log formats its arguments using default formatting,
    /// analogous to Println, and records the text in the error log."
    pub fn Log<M: Into<string>>(&self, msg: M) {
        self.checkFuzzFn(string::from_static("Log"));
        let msg: string = msg.into();
        self.Logf(msg);
    }

    // go: sdk 1.25.5 testing/testing.go:1202-1206 common.Errorf
    /// Go: "Errorf is equivalent to Logf followed by Fail."
    ///
    /// `args` is the runtime variadic slice `fmt.Sprintf` would spread.
    /// Two call shapes work without ceremony:
    ///   - `t.Errorf("simple msg")` — empty args slice via `Default`
    ///   - `t.Errorf("got %v want %v", goish::slice!([]Any{a, b}))`
    pub fn Errorf<M: Into<string>>(
        &self,
        format: M,
        args: crate::goslice::slice<crate::goany::Any>,
    ) {
        self.checkFuzzFn(string::from_static("Errorf"));
        let format: string = format.into();
        let msg: string = if args.Len() == 0 {
            format
        } else {
            crate::fmt::Sprintv(format, args)
        };
        // Go: c.log(...); c.Fail()
        self.write_line(b"err", &msg);
        self.Fail();
    }

    // go: sdk 1.25.5 testing/testing.go:1195-1199 common.Error
    /// Go: "Error is equivalent to Log followed by Fail."
    pub fn Error<M: Into<string>>(&self, msg: M) {
        self.checkFuzzFn(string::from_static("Error"));
        let msg: string = msg.into();
        self.Errorf(msg, crate::goslice::slice::new());
    }

    // go: sdk 1.25.5 testing/testing.go:952-963 common.Fail
    /// Go: "Fail marks the function as having failed but continues
    /// execution."
    ///
    /// Go's first act is `if c.parent != nil { c.parent.Fail() }`, so a
    /// failure is visible on every ancestor the moment it happens
    /// rather than when the subtest returns. goish walks the same chain
    /// through the parent link on `TState`.
    ///
    /// Go also panics on "Fail in goroutine after <name> has
    /// completed", guarding against a stray goroutine writing to a
    /// finished test. goish records `done` but does not panic on it:
    /// the panic would land on whatever goroutine happened to be
    /// and goish's per-G isolation would turn a diagnostic
    /// into a killed goroutine somewhere unrelated.
    pub fn Fail(&self) {
        // Go: if c.parent != nil { c.parent.Fail() }
        let mut p = self.state.parent.clone();
        while let Some(state) = p {
            state.failed.store(true, Ordering::Release);
            p = state.parent.clone();
        }
        self.state.failed.store(true, Ordering::Release);
    }

    // go: sdk 1.25.5 testing/testing.go:1216-1220 common.Fatalf
    /// Go: "Fatalf is equivalent to Logf followed by FailNow."
    pub fn Fatalf<M: Into<string>>(
        &self,
        format: M,
        args: crate::goslice::slice<crate::goany::Any>,
    ) -> ! {
        self.checkFuzzFn(string::from_static("Fatalf"));
        let format: string = format.into();
        self.Errorf(format, args);
        self.FailNow();
    }

    // go: sdk 1.25.5 testing/testing.go:1209-1213 common.Fatal
    /// Go: "Fatal is equivalent to Log followed by FailNow."
    pub fn Fatal<M: Into<string>>(&self, msg: M) -> ! {
        self.checkFuzzFn(string::from_static("Fatal"));
        let msg: string = msg.into();
        self.Fatalf(msg, crate::goslice::slice::new());
    }

    // go: sdk 1.25.5 testing/testing.go:1230-1234 common.Skipf
    /// Go: "Skipf is equivalent to Logf followed by SkipNow."
    pub fn Skipf<M: Into<string>>(&self, msg: M) -> ! {
        self.checkFuzzFn(string::from_static("Skipf"));
        let msg: string = msg.into();
        self.Skip(msg);
    }

    // go: sdk 1.25.5 testing/testing.go:966-977 common.Failed
    /// Go: "Failed reports whether the function has failed."
    ///
    /// Go re-checks the race detector's error count here before
    /// answering; goish has no race detector, so the read is just the
    /// flag.
    pub fn Failed(&self) -> bool {
        return self.state.failed.load(Ordering::Acquire);
    }

    // go: sdk 1.25.5 testing/testing.go:1254-1258 common.Skipped
    /// Go: "Skipped reports whether the test was skipped."
    pub fn Skipped(&self) -> bool {
        return self.state.skipped.load(Ordering::Acquire);
    }

    // go: sdk 1.25.5 testing/testing.go:1263-1282 common.Helper
    /// Go: "Helper marks the calling function as a test helper
    /// function. When printing file and line information, that function
    /// will be skipped."
    ///
    /// Records the caller's PC, as Go does. Go's comment on the
    /// hand-inlined Callers call is worth keeping — "repeating code
    /// from callerName here to save walking a stack frame" — because it
    /// explains why this does not simply call `callerName`: an extra
    /// frame would shift the skip count.
    ///
    /// Deviation: the set is recorded but not yet *consumed*. Go reads
    /// it from `callSite`, which needs `frameSkip`, which walks the
    /// parent chain using `common`'s `runner`, `creator`, `level`,
    /// `cleanupName` and `cleanupPc` — fields goish's `T` does not
    /// carry yet. So marking a helper is faithful and currently has no
    /// observable effect; it stops being a no-op when callSite lands.
    pub fn Helper(&self) {
        // Go: repeating code from callerName here to save walking a
        // stack frame.
        let mut pc: crate::goslice::slice<uintptr> = crate::make!([]uintptr, 1);
        // Go: skip runtime.Callers + Helper
        let n = crate::runtime::Callers(2, &mut pc);
        if n == 0 {
            panic!("testing: zero callers found");
        }
        let mut set = self.state.helperPCs.Lock();
        if !set.Has(pc[0]) {
            set.Set(pc[0], true);
        }
    }

    // go: none — goish-only: read back what `Helper` recorded. Go's
    // `callSite`/`frameSkip` reach `c.helperPCs` directly because they
    // are in-package; the field stays private here, and this is how a
    // future callSite — and the smoke test — observe it.
    #[doc(hidden)]
    pub fn __helper_pcs(&self) -> crate::goslice::slice<uintptr> {
        return self.state.helperPCs.Lock().Keys();
    }

    // go: sdk 1.25.5 testing/testing.go:1287-1314 common.Cleanup
    /// Go: "Cleanup registers a function to be called when the test (or
    /// subtest) and all its subtests complete. Cleanup functions will
    /// be called in last added, first called order."
    ///
    /// Deviation: Go wraps the callback to record the cleanup's name and
    /// stack for the "cleanup panicked" diagnostic. goish stores the
    /// callback directly — the diagnostic needs `runtime.Callers`
    /// frame resolution, which is not ported.
    pub fn Cleanup<F: FnOnce() + Send + 'static>(&self, f: F) {
        self.checkFuzzFn(string::from_static("Cleanup"));
        let mut pc: crate::goslice::slice<crate::types::uintptr> =
            crate::goslice::slice::__from_vec(alloc::vec![0; maxStackLen]);
        // Go: "Skip two extra frames to account for this function and
        // runtime.Callers itself."
        let n = crate::runtime::Callers(2, &mut pc);
        let cleanupPc = pc.slice(0, n);

        // Go wraps the callback so that WHILE it runs, the test's
        // cleanupName/cleanupPc point at this registration site — which
        // is how a failure during teardown is blamed on the line that
        // registered the cleanup rather than on the teardown loop. The
        // pair is cleared again on the way out.
        let st = self.state.clone();
        let fnw = move || {
            let name = callerName(0);
            {
                *st.cleanupName.Lock() = name;
                *st.cleanupPc.Lock() = cleanupPc;
            }
            f();
            *st.cleanupName.Lock() = string::from_static("");
            *st.cleanupPc.Lock() = crate::goslice::slice::new();
        };
        self.state.cleanups.Lock().push(alloc::boxed::Box::new(fnw));
    }

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
        self.checkFuzzFn(string::from_static("FailNow"));
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
        self.checkFuzzFn(string::from_static("Skip"));
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
        self.checkFuzzFn(string::from_static("SkipNow"));
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
        // Go: `testName, ok, _ := t.tstate.match.fullName(&t.common, name)`
        // — the matcher both FILTERS on -run/-skip and deduplicates
        // sibling names, so it has to be consulted before anything else
        // and its answer used as the test's name. Two subtests called
        // "x" become "x" and "x#01" here, not at print time.
        let ts = self.state.tstate.Lock().clone();
        let qualified = match ts.as_ref() {
            Some(ts) => {
                let mut g = ts.matcher.Lock();
                match g.as_mut() {
                    Some(m) => {
                        let (full, ok, _partial) = m.fullName(
                            crate::int32(crate::int64(*self.state.level.Lock())),
                            &self.name,
                            &name,
                        );
                        if !ok {
                            // Filtered out by -run or -skip. Go returns
                            // true: the SUBTEST did not fail, it simply
                            // never ran.
                            return true;
                        }
                        full
                    }
                    None => __join_name(&self.name, &name),
                }
            }
            None => __join_name(&self.name, &name),
        };

        let mut sub_state = TState::new();
        // Go: `t.common.parent = &t.common` on the subtest, which is
        // what makes a failing subtest fail its ancestors immediately.
        sub_state.parent = Some(self.state.clone());
        let sub = T {
            name: qualified.clone(),
            state: Arc::new(sub_state),
            depth: self.depth + 1,
        };

        // Go: `t.setOutputWriter()` in T.Run, right after the subtest's
        // common is built. It must happen after the Arc exists, because
        // the writer holds a Weak back to it.
        sub.state.setOutputWriter();
        *sub.state.level.Lock() = sub.depth;
        // Go: `creator: pc[:n]` — "the stack trace at the point where
        // the parent called t.Run", so frameSkip can resume the search
        // in the parent from this call site.
        {
            let mut pc: crate::goslice::slice<crate::types::uintptr> =
                crate::goslice::slice::__from_vec(alloc::vec![0; maxStackLen]);
            let n = crate::runtime::Callers(2, &mut pc);
            *sub.state.creator.Lock() = pc.slice(0, n);
        }
        // Go: every test in one run shares the run-wide state.
        *sub.state.tstate.Lock() = self.state.tstate.Lock().clone();

        // Go: the run's chattyPrinter is copied onto every test.
        attach_chatty(&sub.state);
        *sub.state.start.Lock() = crate::time::Now();
        running_store(qualified.clone(), crate::time::Now());

        // Go: `t.chatty.Updatef(t.name, "=== RUN   %s\n", t.name)`.
        if let Some(c) = sub.state.chatty.Lock().as_ref() {
            c.Updatef(
                qualified.clone(),
                crate::fmt::Sprintf!("=== RUN   %s\n", qualified.clone()),
            );
        }
        drain_chatty();

        let state = sub.state.clone();
        tRunner(sub, f);

        // A subtest that called Parallel has NOT finished — tRunner
        // returned because Parallel signalled, not because the body
        // did. Its status line is printed by this test's own tRunner,
        // once the barrier has released it and it has really finished.
        // Printing here would report PASS for a test that fails later.
        if state.isParallel.load(Ordering::Acquire) {
            return true;
        }

        let passed = !state.failed.load(Ordering::Acquire);
        if !passed && !state.skipped.load(Ordering::Acquire) {
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
    // Go: tRunner records the name on the common and marks the test —
    // and every ancestor — as having run, so a parent whose body only
    // calls t.Run still reports ran.
    *state.name.Lock() = t.name.clone();
    state.setRan();
    // Go: `t.w = indenter{&t.common}` for every test EXCEPT the hidden
    // root, whose w is os.Stdout. That difference is load-bearing:
    // flushToParent compares the parent's writer against the chatty
    // printer's to decide "write straight out" versus "buffer into my
    // parent", so a top-level test prints immediately while a subtest
    // is buffered under it. goish spells "w is the real output" as
    // None, and the root is exactly the test with no parent.
    if state.parent.is_some() {
        *state.w.Lock() = Some(indenter {
            c: Arc::downgrade(&state),
        });
    }
    // Go: `t.runner = callerName(0)` — frameSkip stops when the walk
    // reaches this frame, i.e. the runner calling the test function.
    *state.runner.Lock() = callerName(0);

    // Go: `go tRunner(t, fn)`. The explicit stack is goish's: a test
    // body is arbitrary user code and the 2 KiB default is nowhere near
    // enough. Reserved, not committed.
    crate::go!(stack(TEST_STACK), move || {
        let mut t = t;
        // Go: `t.start = …; t.resetRaces()` immediately before fn(t),
        // so races from before this test began are not charged to it.
        *t.state.start.Lock() = crate::time::Now();
        t.state.resetRaces();
        fn_(&mut t);
        // Reached only when the test returned normally — a FailNow or
        // SkipNow has already run this and Goexited.
        t.finish_before_goexit();
    });

    // Go: `<-t.signal`. Exactly one send happens per test, from
    // whichever path finished it — a normal finish, or T.Parallel
    // handing control back before it parks.
    let _ = state.signal.Recv();

    // Go: tRunner's deferred func, `if len(t.sub) > 0`. Any subtest
    // that called Parallel is now parked on this test's barrier.
    let subs: Vec<Arc<TState>> = state.sub.Lock().clone();
    if !subs.is_empty() {
        // Go: "Decrease the running count for this test and mark it as
        // no longer running" — the parent gives up its slot so a
        // parallel child can take it.
        let ts = state.tstate.Lock().clone();
        if let Some(ts) = ts.as_ref() {
            ts.release();
        }

        // Go: `close(t.barrier)` — "Release the parallel subtests."
        // Closing rather than sending is what releases ALL of them;
        // a send would wake exactly one and hang the rest.
        state.barrier.Close();

        // Go: "Wait for subtests to complete." Each one's status line
        // is written here, now that its final pass/fail state is known.
        for sub in subs.iter() {
            let _ = sub.signal.Recv();
            report_parallel_sub(&state, sub);
        }

        // Go: "Reacquire the count for sequential tests."
        if !state.isParallel.load(Ordering::Acquire) {
            if let Some(ts) = ts.as_ref() {
                ts.waitParallel();
            }
        }
    } else if state.isParallel.load(Ordering::Acquire) {
        // Go: "Only release the count for this test if it was run as a
        // parallel test."
        let ts = state.tstate.Lock().clone();
        if let Some(ts) = ts {
            ts.release();
        }
    }

    // Go: `t.checkRaces()` first in tRunner's deferred func — any race
    // this test caused is attributed to it before it is reported.
    state.checkRaces();

    // Go: `t.duration += highPrecisionTimeSince(t.start)` in tRunner's
    // deferred func, before the report — so the reported time is the
    // test's own, not including any wait for serial tests.
    {
        let start = *state.start.Lock();
        let mut d = state.duration.Lock();
        *d = crate::time::Duration(d.0 + crate::time::Since(start).0);
    }

    // Go: `t.report()` — "Report after all subtests have finished."
    // A parallel subtest is reported by its parent instead, once the
    // barrier has released it, so it is skipped here.
    if !state.isParallel.load(Ordering::Acquire) {
        state.report();
        drain_chatty();
    }

    // Go: tRunner's deferred func, `if t.Failed() { numFailed.Add(1) }`.
    if state.failed.load(Ordering::Acquire) {
        numFailed.fetch_add(1, Ordering::AcqRel);
    }

    // Go: `running.Delete(t.name)` once the test is finished.
    running_delete(state.name.Lock().clone());

    // Go: `t.done = true` in tRunner's deferred func, once the test and
    // all its subtests have completed. `destination` reads this to
    // re-home late output onto the nearest still-running ancestor.
    state.done.store(true, Ordering::Release);
}

// ─── chatty flag / printer ───────────────────────────────────────────
//
// The `-test.v` flag's value type and the framing marker the chatty
// printer emits. Ported ahead of the flag plumbing itself: these are
// pure value logic, and the flag registration they hang off needs
// `flag` globals (`flag.Var`, `flag.Parsed`) that goish does not have.

// go: sdk 1.25.5 testing/testing.go:524-527 chattyFlag
/// Go: the value behind `-test.v`. It is tri-state, not a bool:
/// unset, `-v` (`on`), and `-v=test2json` (`on` and `json`).
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct chattyFlag {
    /// Go: "-v is set in some form"
    pub on: bool,
    /// Go: "-v=test2json is set, to make output better for test2json"
    pub json: bool,
}

impl chattyFlag {
    // go: sdk 1.25.5 testing/testing.go:530-530 chattyFlag.IsBoolFlag
    /// Go: `func (*chattyFlag) IsBoolFlag() bool { return true }` —
    /// tells `flag` that a bare `-test.v` is legal, with no `=value`.
    pub fn IsBoolFlag(&self) -> bool {
        return true;
    }

    // go: sdk 1.25.5 testing/testing.go:532-544 chattyFlag.Set
    /// Go: parse the flag's argument. Anything other than the three
    /// recognised spellings is an error, so `-test.v=yes` is rejected
    /// rather than quietly treated as true.
    pub fn Set(&mut self, arg: string) -> crate::error {
        let a: &str = arg.as_ref();
        match a {
            // Go: case "true", "test2json":
            //         f.on = true; f.json = arg == "test2json"
            "true" | "test2json" => {
                self.on = true;
                self.json = a == "test2json";
            }
            // Go: case "false": f.on = false; f.json = false
            "false" => {
                self.on = false;
                self.json = false;
            }
            // Go: default: return fmt.Errorf("invalid flag -test.v=%s", arg)
            _ => {
                return crate::errors::New(crate::fmt::Sprintf!(
                    "invalid flag -test.v=%s",
                    arg.clone()
                ));
            }
        }
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 testing/testing.go:546-554 chattyFlag.String
    /// Go: render the flag back to its spelling, so `flag`'s usage
    /// output shows what is set.
    pub fn String(&self) -> string {
        if self.json {
            return string::from_static("test2json");
        }
        if self.on {
            return string::from_static("true");
        }
        return string::from_static("false");
    }
}

// go: sdk 1.25.5 testing/testing.go:563-563 marker
/// Go: `const marker = byte(0x16) // ^V for framing`
pub const marker: crate::types::byte = 0x16;

// go: sdk 1.25.5 testing/testing.go:587-592 chattyPrinter.prefix
/// Go: the framing prefix a chatty line carries in test2json mode, and
/// the empty string otherwise.
///
/// Deviation: Go's receiver is `*chattyPrinter` and it tests
/// `p != nil`, because the field is nil whenever `-v` is unset. A nil
/// receiver is not expressible in Rust, so this is a free function over
/// the one field the method reads — both of Go's false cases (nil
/// receiver, json off) collapse into `json == false`.
pub fn prefix(json: bool) -> string {
    // Go: if p != nil && p.json { return string(marker) }
    //     return ""
    if json {
        return string::from_bytes(&[marker]);
    }
    return string::from_static("");
}

// go: sdk 1.25.5 testing/testing.go:876-878 fmtDuration
/// Go: `fmt.Sprintf("%.2fs", d.Seconds())` — the elapsed time on a
/// `--- PASS:` line.
///
/// This could not be ported until fmt learned precision: on the old
/// verb scanner `%.2f` rendered as the default float followed by a
/// stray `f`.
pub fn fmtDuration(d: crate::time::Duration) -> string {
    return crate::fmt::Sprintf!("%.2fs", d.Seconds());
}

// ─── package state and Init ──────────────────────────────────────────

// go: sdk 1.25.5 testing/testing.go:698-698 testBinary
/// Go: `var testBinary = "0"` — "testBinary is set by cmd/go to "1" if
/// this is a test binary."
///
/// Deviation: Go's is a `var` that the linker overwrites at build time
/// (`-X testing.testBinary=1`). goish has no cmd/go and no linker
/// rewrite, so nothing can ever set it; a `const` says that plainly
/// rather than implying a mutability that does not exist.
pub const testBinary: &str = "0";

/// Go's package-level flag values, as `flag.Flag` handles.
///
/// Go stores these in package vars typed `*bool` / `*string`; goish's
/// flag hands back a `Flag<T>` whose `Get()` reads the parsed value, so
/// the shape is the same indirection with a different spelling.
/// Registered but not yet consumed by the runner: `Main` does not act
/// on count/timeout/parallel/failfast/shuffle/list yet. They are
/// registered anyway so a command line written for `go test` parses
/// rather than erroring out on an unknown flag — the values are simply
/// read by nothing so far. Consuming them is runner work, not flag
/// work.
#[allow(dead_code)]
struct testFlags {
    short: crate::flag::Flag<bool>,
    chatty: crate::flag::Flag<bool>,
    run: crate::flag::Flag<string>,
    skip: crate::flag::Flag<string>,
    count: crate::flag::Flag<crate::types::uint>,
    timeout: crate::flag::Flag<crate::time::Duration>,
    parallel: crate::flag::Flag<int>,
    fullPath: crate::flag::Flag<bool>,
    failFast: crate::flag::Flag<bool>,
    shuffle: crate::flag::Flag<string>,
    outputDir: crate::flag::Flag<string>,
    list: crate::flag::Flag<string>,
}

static INIT_RAN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static FLAGS: crate::sync::Mutex<Option<testFlags>> = crate::sync::Mutex::new(None);

// go: sdk 1.25.5 testing/testing.go:439-485 Init
/// Go: "Init registers testing flags. These flags are automatically
/// registered by the "go test" command before running test functions,
/// so Init is only needed when calling functions such as Benchmark
/// without using "go test". Init is not safe to call concurrently. It
/// has no effect if it was called before."
///
/// **Deviation — which flags.** Go registers 25. goish registers the 12
/// whose behaviour it can honour, and leaves out the ones that would be
/// accepted and then silently ignored: the profiling flags
/// (`-test.cpuprofile`, `-test.memprofile`, `-test.blockprofile`,
/// `-test.mutexprofile`, `-test.trace`) need `runtime/pprof`, and
/// `-test.gocoverdir`/`-test.coverprofile` need coverage
/// instrumentation from the compiler. Accepting a flag and doing
/// nothing is worse than rejecting it, because a CI script would look
/// like it was collecting profiles.
///
/// `-test.v` is registered as a plain bool rather than through
/// `flag.Var(&chatty)`: goish's flag has no `Value` interface yet, so
/// the `test2json` spelling is not reachable from the command line even
/// though `chattyFlag` itself parses it (see its port above).
pub fn Init() {
    // Go: if initRan { return }; initRan = true
    if INIT_RAN.swap(true, Ordering::AcqRel) {
        return;
    }
    let f = testFlags {
        // Go: "The short flag requests that tests run more quickly, but
        // its functionality is provided by test writers themselves."
        short: crate::flag::Bool("test.short", false, "run smaller test suite to save time"),
        chatty: crate::flag::Bool("test.v", false, "verbose: print additional output"),
        run: crate::flag::String("test.run", "", "run only tests and examples matching `regexp`"),
        skip: crate::flag::String("test.skip", "", "do not list or run tests matching `regexp`"),
        count: crate::flag::Uint("test.count", 1, "run tests and benchmarks `n` times"),
        timeout: crate::flag::Duration(
            "test.timeout",
            crate::time::Duration(0),
            "panic test binary after duration `d` (default 0, timeout disabled)",
        ),
        parallel: crate::flag::Int(
            "test.parallel",
            crate::runtime::NumCPU(),
            "run at most `n` tests in parallel",
        ),
        fullPath: crate::flag::Bool("test.fullpath", false, "show full file names in error messages"),
        failFast: crate::flag::Bool(
            "test.failfast",
            false,
            "do not start new tests after the first test failure",
        ),
        shuffle: crate::flag::String(
            "test.shuffle",
            "off",
            "randomize the execution order of tests and benchmarks",
        ),
        outputDir: crate::flag::String("test.outputdir", "", "write profiles to `dir`"),
        list: crate::flag::String(
            "test.list",
            "",
            "list tests, examples, and benchmarks matching `regexp` then exit",
        ),
    };
    *FLAGS.Lock() = Some(f);
}

// go: sdk 1.25.5 testing/testing.go:679-689 Short
/// Go: "Short reports whether the -test.short flag is set."
///
/// Go panics both when Init has not run and when flag.Parse has not
/// been called, because a `Short()` that silently answers false would
/// make a `-short` CI run quietly do the long thing. goish keeps both
/// panics.
pub fn Short() -> bool {
    let g = FLAGS.Lock();
    let f = match g.as_ref() {
        // Go: if short == nil { panic("testing: Short called before Init") }
        None => panic!("testing: Short called before Init"),
        Some(f) => f,
    };
    // Go: "Catch code that calls this from TestMain without first
    //      calling flag.Parse."
    if !crate::flag::Parsed() {
        panic!("testing: Short called before Parse");
    }
    return f.short.Get();
}

// go: sdk 1.25.5 testing/testing.go:715-721 Verbose
/// Go: "Verbose reports whether the -test.v flag is set."
pub fn Verbose() -> bool {
    let g = FLAGS.Lock();
    // Go: same Parse check as Short.
    if !crate::flag::Parsed() {
        panic!("testing: Verbose called before Parse");
    }
    return match g.as_ref() {
        None => false,
        Some(f) => f.chatty.Get(),
    };
}

// go: sdk 1.25.5 testing/testing.go:703-705 Testing
/// Go: "Testing reports whether the current code is being run as part
/// of a test. This will report true in programs created by "go test",
/// false in programs created by "go build"."
///
/// Always false here: nothing sets `testBinary`, because goish has no
/// cmd/go to set it. See the var above.
pub fn Testing() -> bool {
    // Go: return testBinary == "1"
    return testBinary == "1";
}

// go: none — goish-only: read the parsed `-test.run` / `-test.skip`
// patterns so a runner can build the matcher that match.rs provides.
// Go reaches its package vars directly; goish's live behind the Mutex.
#[doc(hidden)]
pub fn __run_skip_patterns() -> (string, string) {
    let g = FLAGS.Lock();
    return match g.as_ref() {
        None => (string::from_static(""), string::from_static("")),
        Some(f) => (f.run.Get(), f.skip.Get()),
    };
}

// go: none — goish-only: reads the -v flag without Verbose's
// flag.Parsed() check, so example output can consult it before Init.
pub(crate) fn __chatty_on() -> bool {
    let g = FLAGS.Lock();
    return match g.as_ref() {
        None => false,
        Some(f) => f.chatty.Get(),
    };
}

// go: none — goish idiom: Go reads `*count`, `*parallel`, `*timeout`
// and `cpuList` as package-level pointers; goish keeps them behind
// FLAGS, so each gets a reader. Defaults match Go's when Init has not
// run: one iteration, GOMAXPROCS-many parallel slots, no timeout.
pub(crate) fn countFlag() -> crate::types::uint {
    let g = FLAGS.Lock();
    return match g.as_ref() {
        None => 1,
        Some(f) => f.count.Get(),
    };
}

// go: none — goish idiom: see countFlag.
pub(crate) fn parallelFlag() -> int {
    let g = FLAGS.Lock();
    return match g.as_ref() {
        None => crate::runtime::GOMAXPROCS(0),
        Some(f) => f.parallel.Get(),
    };
}

// go: none — goish idiom: see countFlag.
pub(crate) fn timeoutFlag() -> crate::time::Duration {
    let g = FLAGS.Lock();
    return match g.as_ref() {
        None => crate::time::Duration(0),
        Some(f) => f.timeout.Get(),
    };
}

// go: none — goish idiom: Go's `cpuList` is a package var filled by
// parseCpuList; goish keeps the parsed list here. Empty means "just
// the current GOMAXPROCS", which is what Go's default -cpu produces.
pub(crate) fn cpuList() -> alloc::vec::Vec<int> {
    return alloc::vec![crate::runtime::GOMAXPROCS(0)];
}

// go: sdk 1.25.5 testing/testing.go:710-712 CoverMode
/// Go: "CoverMode reports what the test coverage mode is set to. The
/// values are "set", "count", or "atomic". The return value will be
/// empty if test coverage is not enabled."
///
/// Always empty here, and permanently so: coverage counters are emitted
/// by cmd/compile under `-cover`, which a library cannot arrange. The
/// empty string is the honest answer Go itself gives for an
/// uninstrumented binary, so callers branching on it take the correct
/// path rather than a special-cased one.
pub fn CoverMode() -> string {
    return string::from_static("");
}

impl T {
    // go: sdk 1.25.5 testing/testing.go:1428-1445 common.Setenv
    /// Go: "Setenv calls os.Setenv(key, value) and uses Cleanup to
    /// restore the environment variable to its original value after the
    /// test."
    ///
    /// The restore is asymmetric and that asymmetry is the whole point:
    /// if the variable existed it is put back to its previous value; if
    /// it did not, it is *unset* rather than left as an empty string. A
    /// test that set `HOME=""` and a test that unset `HOME` are
    /// different states, and `LookupEnv` can tell them apart.
    ///
    /// Deviation: Go also refuses to run in a parallel test ("cannot
    /// use Setenv in parallel tests"), since the environment is process
    /// global. goish has no `t.Parallel`, so there is no such state to
    /// check — when Parallel lands, that guard has to land with it.
    pub fn Setenv(&self, key: string, value: string) {
        self.checkFuzzFn(string::from_static("Setenv"));
        // Go: T.Setenv calls checkParallel before delegating to
        // common.Setenv — the whole process shares one environment and
        // one working directory, so neither is safe under Parallel.
        self.checkParallel();
        // Go: prevValue, ok := os.LookupEnv(key)
        let (prevValue, ok) = crate::os::LookupEnv(key.clone());

        let err = crate::os::Setenv(key.clone(), value);
        if err != crate::errors::nil {
            self.Fatalf(
                crate::fmt::Sprintf!("cannot set environment variable: %v", err.Error()),
                crate::goslice::slice::new(),
            );
        }

        if ok {
            let k = key.clone();
            let v = prevValue;
            self.Cleanup(move || {
                let _ = crate::os::Setenv(k.clone(), v.clone());
            });
        } else {
            let k = key;
            self.Cleanup(move || {
                let _ = crate::os::Unsetenv(k.clone());
            });
        }
    }

    // go: sdk 1.25.5 testing/testing.go:1453-1487 common.Chdir
    /// Go: "Chdir calls os.Chdir(dir) and uses Cleanup to restore the
    /// current working directory to its original value after the test."
    ///
    /// Go: "On POSIX platforms, PWD represents 'an absolute pathname of
    /// the current working directory.' Since we are changing the
    /// working directory, we should also set or update PWD to reflect
    /// that." — so a relative `dir` is resolved through `os.Getwd`
    /// first, because PWD must be absolute.
    ///
    /// Deviations: Go holds the old directory open as a *file
    /// descriptor* and restores with `oldwd.Chdir()`, which survives
    /// the directory being renamed underneath it. goish records the
    /// path from `os.Getwd` instead, so a rename during the test defeats
    /// the restore. Go's switch on `runtime.GOOS` collapses: goish is
    /// linux-only, so only the POSIX arm exists.
    pub fn Chdir(&self, dir: string) {
        self.checkFuzzFn(string::from_static("Chdir"));
        // Go: T.Chdir calls checkParallel before delegating to
        // common.Chdir — the whole process shares one environment and
        // one working directory, so neither is safe under Parallel.
        self.checkParallel();
        let (oldwd, werr) = crate::os::Getwd();
        if werr != crate::errors::nil {
            self.Fatal(werr.Error());
        }
        let err = crate::os::Chdir(dir.clone());
        if err != crate::errors::nil {
            self.Fatal(err.Error());
        }

        // Go: if !filepath.IsAbs(dir) { dir, err = os.Getwd() }
        let ds: &str = dir.as_ref();
        let abs = if ds.starts_with('/') {
            dir
        } else {
            let (cwd, cerr) = crate::os::Getwd();
            if cerr != crate::errors::nil {
                self.Fatal(cerr.Error());
            }
            cwd
        };
        self.Setenv(string::from_static("PWD"), abs);

        self.Cleanup(move || {
            // Go panics if the restore fails: "It's not safe to
            // continue with tests if we can't get back to the original
            // working directory."
            let e = crate::os::Chdir(oldwd.clone());
            if e != crate::errors::nil {
                panic!("testing.Chdir: cannot restore working directory");
            }
        });
    }

    // go: sdk 1.25.5 testing/testing.go:1494-1497 common.Context
    /// Go: "Context returns a context that is canceled just before
    /// Cleanup-registered functions are called.
    ///
    /// Cleanup functions can wait for any resources that shut down on
    /// Context.Done before the test or benchmark completes."
    ///
    /// Deviation: Go's context is created per test in `tRunner` and
    /// cancelled just before the cleanup stack runs. goish's `T` does
    /// not own one yet, so this returns `context.Background()` — never
    /// cancelled. Anything waiting on `Done()` therefore waits forever
    /// rather than being released at cleanup time, which is why this is
    /// called out rather than left to be discovered.
    pub fn Context(&self) -> alloc::sync::Arc<dyn crate::context::Context> {
        return crate::context::Background();
    }
}

// go: sdk 1.25.5 testing/testing.go:2705-2721 parseCpuList
/// Go: parse the `-test.cpu` list into the GOMAXPROCS values each test
/// is run at, defaulting to the current GOMAXPROCS when empty.
///
/// Deviation: Go writes the package-level `cpuList` and calls
/// `os.Exit(1)` on a malformed entry. goish returns the list and lets
/// the caller decide — exiting the process from a parsing helper is the
/// kind of thing that makes a library untestable, and `Main` is the
/// right place for that decision.
pub fn parseCpuList(cpuListStr: string) -> (crate::goslice::slice<int>, crate::error) {
    let mut cpuList: alloc::vec::Vec<int> = alloc::vec::Vec::new();
    let parts = crate::strings::Split(cpuListStr, string::from_static(","));
    for i in 0..parts.Len() {
        let val = crate::strings::TrimSpace(parts[i].clone());
        if val.Len() == 0 {
            continue;
        }
        let (cpu, err) = crate::strconv::Atoi(val.clone());
        if err != crate::errors::nil || cpu <= 0 {
            // Go: fmt.Fprintf(os.Stderr, "testing: invalid value %q for
            //         -test.cpu\n", val); os.Exit(1)
            return (
                crate::goslice::slice::new(),
                crate::errors::New(crate::fmt::Sprintf!(
                    "testing: invalid value %q for -test.cpu",
                    val
                )),
            );
        }
        cpuList.push(cpu);
    }
    // Go: if cpuList == nil { cpuList = append(cpuList, runtime.GOMAXPROCS(-1)) }
    if cpuList.len() == 0 {
        cpuList.push(crate::runtime::GOMAXPROCS(-1));
    }
    return (crate::goslice::slice::__from_vec(cpuList), crate::errors::nil);
}

// ─── chattyPrinter ───────────────────────────────────────────────────

// goishlint:ignore GOISH019 chattyPrinter — Go carries `lastNameMu
// sync.Mutex` beside the `lastName` string it guards; goish folds them
// into `Mutex<string>`, since that field is the only thing the mutex
// protects. Same protection, one field fewer.
// go: sdk 1.25.5 testing/testing.go:572-577 chattyPrinter
/// Go: the `-v` output writer. It tracks the last test name it printed
/// for, so that interleaved output from different tests stays
/// attributable.
pub struct chattyPrinter {
    w: alloc::sync::Arc<crate::sync::Mutex<alloc::vec::Vec<crate::types::byte>>>,
    /// Go: `lastNameMu sync.Mutex // guards lastName` and
    /// `lastName string // last printed test name in chatty mode`.
    /// Folded into one Mutex, since the mutex guards only that field.
    lastName: crate::sync::Mutex<string>,
    /// Go: "-v=json output mode"
    json: bool,
}

// go: sdk 1.25.5 testing/testing.go:579-581 newChattyPrinter
/// Go: `return &chattyPrinter{w: w, json: chatty.json}`.
///
/// Deviation: Go writes to an `io.Writer`; goish accumulates into a
/// shared buffer the caller owns, because `T`'s output path is
/// `write_line` to stdout rather than a writer chain. The buffer keeps
/// the printer testable, which is what Go's comment on `prefix` says
/// it wanted from `p.json` too.
pub fn newChattyPrinter(
    w: alloc::sync::Arc<crate::sync::Mutex<alloc::vec::Vec<crate::types::byte>>>,
    json: bool,
) -> chattyPrinter {
    return chattyPrinter {
        w: w,
        lastName: crate::sync::Mutex::new(string::from_static("")),
        json: json,
    };
}

impl chattyPrinter {
    // go: sdk 1.25.5 testing/testing.go:597-607 chattyPrinter.Updatef
    /// Go: "Updatef prints a message about the status of the named test
    /// to w. The formatted message must include the test name itself."
    ///
    /// Because the message already names the test, no `=== NAME` line is
    /// emitted — Go's comment: "Since the message already implies an
    /// association with a specific new test, we don't need to check what
    /// the old test name was or log an extra NAME line for it."
    pub fn Updatef(&self, testName: string, msg: string) {
        let mut last = self.lastName.Lock();
        *last = testName;
        let line = crate::fmt::Sprintf!("%s%s", self.prefix(), msg);
        self.w.Lock().extend_from_slice(line.as_bytes());
    }

    // go: sdk 1.25.5 testing/testing.go:611-623 chattyPrinter.Printf
    /// Go: "Printf prints a message, generated by the named test, that
    /// does not necessarily mention that tests's name itself."
    ///
    /// Since the message does *not* name the test, the printer emits a
    /// `=== NAME` line whenever the test changed since the last write.
    /// That is what keeps interleaved `-v` output attributable: without
    /// it, a log line from a second test would appear under the first
    /// test's heading.
    pub fn Printf(&self, testName: string, msg: string) {
        let mut last = self.lastName.Lock();
        if last.Len() == 0 {
            *last = testName;
        } else if *last != testName {
            let hdr = crate::fmt::Sprintf!(
                "%s=== NAME  %s\n",
                self.prefix(),
                testName.clone()
            );
            self.w.Lock().extend_from_slice(hdr.as_bytes());
            *last = testName;
        }
        self.w.Lock().extend_from_slice(msg.as_bytes());
    }

    // go: none — goish idiom: Go's `chattyPrinter.prefix` is a method
    // that tolerates a nil receiver. The free `prefix(json)` above is
    // the ported logic; this forwards so the call sites read like Go's.
    fn prefix(&self) -> string {
        return prefix(self.json);
    }
}

// ─── caller attribution ──────────────────────────────────────────────

// go: sdk 1.25.5 testing/testing.go:1641-1648 callerName
/// Go: "callerName gives the function name (qualified with a package
/// path) for the caller after skip frames (where 0 means the current
/// function)."
///
/// Portable only since runtime::CallersFrames landed — before that
/// `pcToName` could only ever have returned "", which would have made
/// every `Helper`/`Cleanup` attribution silently blank.
pub fn callerName(skip: int) -> string {
    let mut pc: crate::goslice::slice<crate::types::uintptr> =
        crate::make!([]uintptr, 1);
    // Go: skip + runtime.Callers + callerName
    let n = crate::runtime::Callers(skip + 2, &mut pc);
    if n == 0 {
        panic!("testing: zero callers found");
    }
    return pcToName(pc[0]);
}

// go: sdk 1.25.5 testing/testing.go:1650-1655 pcToName
/// Go: resolve one PC to its qualified function name.
pub fn pcToName(pc: crate::types::uintptr) -> string {
    let pcs: crate::goslice::slice<crate::types::uintptr> =
        crate::goslice::slice::__from_vec(alloc::vec![pc]);
    let mut frames = crate::runtime::CallersFrames(pcs);
    let (frame, _) = frames.Next();
    return frame.Function;
}

// ─── testDeps: the seam to the generated test main ──────────────────

crate::var! {
    // go: sdk 1.25.5 testing/testing.go:2133 errMain
    /// Go: `var errMain = errors.New("testing: unexpected use of func
    /// Main")`. A package-level var, so every stub returns the SAME
    /// error value and a caller's `err == errMain` holds. Built through
    /// `var!` rather than a plain fn, which would mint a fresh
    /// (pointer-unequal) error per call and silently break that.
    pub(crate) errMain: error = "testing: unexpected use of func Main";
}

// go: sdk 1.25.5 testing/testing.go:2192-2209 testDeps
/// Go: "testDeps is an internal interface of functionality that is
/// passed into this package by a test's generated main package. The
/// canonical implementation of this interface is
/// testing/internal/testdeps's TestDeps."
///
/// goish has no `go test` code generator, so the only implementation in
/// the tree is [`matchStringOnly`] — which is exactly the fallback Go
/// itself uses from the deprecated `testing.Main`. The
/// fuzzing/profiling members are kept in the trait rather than dropped,
/// because `M.Run` calls them and a shortened interface would change
/// how the driver reads against Go.
#[allow(non_snake_case, dead_code)]
pub(crate) trait testDeps {
    fn ImportPath(&self) -> string;
    fn MatchString(&self, pat: string, str_: string) -> (bool, crate::errors::error);
    fn SetPanicOnExit0(&self, v: bool);
    fn StartCPUProfile(&self, w: &mut dyn crate::io::Writer) -> crate::errors::error;
    fn StopCPUProfile(&self);
    fn StartTestLog(&self, w: &mut dyn crate::io::Writer);
    fn StopTestLog(&self) -> crate::errors::error;
    fn WriteProfileTo(
        &self,
        name: string,
        w: &mut dyn crate::io::Writer,
        debug: crate::types::int,
    ) -> crate::errors::error;
    #[allow(clippy::too_many_arguments)]
    fn CoordinateFuzzing(
        &self,
        timeout: crate::time::Duration,
        limit: crate::types::int64,
        minimizeTimeout: crate::time::Duration,
        minimizeLimit: crate::types::int64,
        parallel: crate::types::int,
        seed: crate::goslice::slice<crate::testing::fuzz::corpusEntry>,
        types: crate::goslice::slice<crate::reflect::Type>,
        corpusDir: string,
        cacheDir: string,
    ) -> crate::errors::error;
    fn RunFuzzWorker(
        &self,
        f: &mut dyn FnMut(crate::testing::fuzz::corpusEntry) -> crate::errors::error,
    ) -> crate::errors::error;
    fn ReadCorpus(
        &self,
        dir: string,
        types: crate::goslice::slice<crate::reflect::Type>,
    ) -> (crate::goslice::slice<crate::testing::fuzz::corpusEntry>, crate::errors::error);
    fn CheckCorpus(
        &self,
        vals: crate::goslice::slice<crate::goany::Any>,
        types: crate::goslice::slice<crate::reflect::Type>,
    ) -> crate::errors::error;
    fn ResetCoverage(&self);
    fn SnapshotCoverage(&self);
    fn InitRuntimeCoverage(&self) -> (string, Option<TearDownFunc>, Option<SnapCovFunc>);
}

// go: none — goish idiom: names for the two funcs Go returns inline
// from InitRuntimeCoverage, which Rust cannot spell anonymously.
pub(crate) type TearDownFunc =
    alloc::boxed::Box<dyn Fn(string, string) -> (string, crate::errors::error) + Send + Sync>;
// go: none — goish idiom: see TearDownFunc.
pub(crate) type SnapCovFunc = alloc::boxed::Box<dyn Fn() -> crate::types::float64 + Send + Sync>;

// go: sdk 1.25.5 testing/testing.go:2135 matchStringOnly
/// Go: `type matchStringOnly func(pat, str string) (bool, error)` — a
/// func type carrying the whole testDeps interface, where every member
/// except MatchString is a stub. It is what `testing.Main` passes when
/// no generated main package supplied real deps.
///
/// goish wraps the func in a struct because Rust cannot hang an impl
/// block off a bare function type.
#[allow(non_camel_case_types)]
pub(crate) struct matchStringOnly {
    f: alloc::boxed::Box<
        dyn Fn(string, string) -> (bool, crate::errors::error) + Send + Sync,
    >,
}

#[allow(dead_code)]
impl matchStringOnly {
    // go: none — goish idiom: Go converts with `matchStringOnly(fn)`;
    // Rust needs a named constructor for the wrapper struct.
    pub(crate) fn new<F>(f: F) -> Self
    where
        F: Fn(string, string) -> (bool, crate::errors::error) + Send + Sync + 'static,
    {
        return matchStringOnly {
            f: alloc::boxed::Box::new(f),
        };
    }
}

#[allow(non_snake_case, unused_variables)]
impl testDeps for matchStringOnly {
    // go: sdk 1.25.5 testing/testing.go:2137 matchStringOnly.MatchString
    fn MatchString(&self, pat: string, str_: string) -> (bool, crate::errors::error) {
        return (self.f)(pat, str_);
    }

    // go: sdk 1.25.5 testing/testing.go:2138 matchStringOnly.StartCPUProfile
    fn StartCPUProfile(&self, w: &mut dyn crate::io::Writer) -> crate::errors::error {
        return errMain.into();
    }

    // go: sdk 1.25.5 testing/testing.go:2139 matchStringOnly.StopCPUProfile
    fn StopCPUProfile(&self) {}

    // go: sdk 1.25.5 testing/testing.go:2140 matchStringOnly.WriteProfileTo
    fn WriteProfileTo(
        &self,
        name: string,
        w: &mut dyn crate::io::Writer,
        debug: crate::types::int,
    ) -> crate::errors::error {
        return errMain.into();
    }

    // go: sdk 1.25.5 testing/testing.go:2141 matchStringOnly.ImportPath
    fn ImportPath(&self) -> string {
        return string::from_static("");
    }

    // go: sdk 1.25.5 testing/testing.go:2142 matchStringOnly.StartTestLog
    fn StartTestLog(&self, w: &mut dyn crate::io::Writer) {}

    // go: sdk 1.25.5 testing/testing.go:2143 matchStringOnly.StopTestLog
    fn StopTestLog(&self) -> crate::errors::error {
        return errMain.into();
    }

    // go: sdk 1.25.5 testing/testing.go:2144 matchStringOnly.SetPanicOnExit0
    fn SetPanicOnExit0(&self, v: bool) {}

    // go: sdk 1.25.5 testing/testing.go:2145-2147 matchStringOnly.CoordinateFuzzing
    fn CoordinateFuzzing(
        &self,
        timeout: crate::time::Duration,
        limit: crate::types::int64,
        minimizeTimeout: crate::time::Duration,
        minimizeLimit: crate::types::int64,
        parallel: crate::types::int,
        seed: crate::goslice::slice<crate::testing::fuzz::corpusEntry>,
        types: crate::goslice::slice<crate::reflect::Type>,
        corpusDir: string,
        cacheDir: string,
    ) -> crate::errors::error {
        return errMain.into();
    }

    // go: sdk 1.25.5 testing/testing.go:2148 matchStringOnly.RunFuzzWorker
    fn RunFuzzWorker(
        &self,
        f: &mut dyn FnMut(crate::testing::fuzz::corpusEntry) -> crate::errors::error,
    ) -> crate::errors::error {
        return errMain.into();
    }

    // go: sdk 1.25.5 testing/testing.go:2149-2151 matchStringOnly.ReadCorpus
    fn ReadCorpus(
        &self,
        dir: string,
        types: crate::goslice::slice<crate::reflect::Type>,
    ) -> (crate::goslice::slice<crate::testing::fuzz::corpusEntry>, crate::errors::error) {
        return (crate::goslice::slice::new(), errMain.into());
    }

    // go: sdk 1.25.5 testing/testing.go:2152 matchStringOnly.CheckCorpus
    fn CheckCorpus(
        &self,
        vals: crate::goslice::slice<crate::goany::Any>,
        types: crate::goslice::slice<crate::reflect::Type>,
    ) -> crate::errors::error {
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 testing/testing.go:2153 matchStringOnly.ResetCoverage
    fn ResetCoverage(&self) {}

    // go: sdk 1.25.5 testing/testing.go:2154 matchStringOnly.SnapshotCoverage
    fn SnapshotCoverage(&self) {}

    // go: sdk 1.25.5 testing/testing.go:2156-2158 matchStringOnly.InitRuntimeCoverage
    /// Go's body is a naked `return`, i.e. all three zero values: no
    /// coverage mode, and no teardown or snapshot func.
    fn InitRuntimeCoverage(&self) -> (string, Option<TearDownFunc>, Option<SnapCovFunc>) {
        return (string::from_static(""), None, None);
    }
}

// ─── test shims ──────────────────────────────────────────────────────
//
// `matchStringOnly` and `testDeps` are unexported, exactly as in Go, so
// an example cannot name them. These shims give the smoke test a way in
// without widening the real API — the same pattern fstest.rs uses.

/// What driving every `testDeps` member on a `matchStringOnly` yields.
#[doc(hidden)]
#[allow(non_snake_case)]
pub struct __DepsProbe {
    pub matched: bool,
    pub matchErr: crate::errors::error,
    pub importPath: string,
    pub startCPUProfile: crate::errors::error,
    pub stopTestLog: crate::errors::error,
    pub writeProfileTo: crate::errors::error,
    pub coordinateFuzzing: crate::errors::error,
    pub runFuzzWorker: crate::errors::error,
    /// Go returns nil here, NOT errMain — the one stub that succeeds.
    pub checkCorpus: crate::errors::error,
    pub readCorpusLen: crate::types::int,
    pub readCorpusErr: crate::errors::error,
    pub coverMode: string,
    pub hasTearDown: bool,
    pub hasSnapcov: bool,
}

// go: none — goish-only: test shim for the unexported matchStringOnly.
#[doc(hidden)]
pub fn __shim_match_string_only<F>(f: F, pat: string, str_: string) -> __DepsProbe
where
    F: Fn(string, string) -> (bool, crate::errors::error) + Send + Sync + 'static,
{
    let d = matchStringOnly::new(f);
    let mut w = crate::io::DiscardWriter();
    let (matched, matchErr) = d.MatchString(pat, str_);
    let (corpus, readCorpusErr) =
        d.ReadCorpus(string::from_static("dir"), crate::goslice::slice::new());
    let (coverMode, tearDown, snapcov) = d.InitRuntimeCoverage();
    // The four no-op members are called for their absence of effect;
    // a panic or a hang here is the failure they can produce.
    d.StopCPUProfile();
    d.StartTestLog(&mut w);
    d.SetPanicOnExit0(true);
    d.ResetCoverage();
    d.SnapshotCoverage();
    return __DepsProbe {
        matched,
        matchErr,
        importPath: d.ImportPath(),
        startCPUProfile: d.StartCPUProfile(&mut w),
        stopTestLog: d.StopTestLog(),
        writeProfileTo: d.WriteProfileTo(string::from_static("p"), &mut w, 0),
        coordinateFuzzing: d.CoordinateFuzzing(
            crate::time::Duration(0),
            0,
            crate::time::Duration(0),
            0,
            0,
            crate::goslice::slice::new(),
            crate::goslice::slice::new(),
            string::from_static(""),
            string::from_static(""),
        ),
        runFuzzWorker: d.RunFuzzWorker(&mut |_e| crate::errors::nil),
        checkCorpus: d.CheckCorpus(
            crate::goslice::slice::new(),
            crate::goslice::slice::new(),
        ),
        readCorpusLen: corpus.Len(),
        readCorpusErr,
        coverMode,
        hasTearDown: tearDown.is_some(),
        hasSnapcov: snapcov.is_some(),
    };
}

// go: none — goish-only: exposes the unexported errMain so a test can
// assert the stubs return that exact error rather than merely non-nil.
#[doc(hidden)]
pub fn __shim_err_main() -> crate::errors::error {
    return errMain.into();
}

// ─── flag and common odds and ends ───────────────────────────────────

#[allow(non_snake_case)]
impl chattyFlag {
    // go: sdk 1.25.5 testing/testing.go:556-561 chattyFlag.Get
    /// Go returns `any`: the string "test2json" under -v=test2json, and
    /// the bool `on` otherwise. flag.Getter callers type-switch on it,
    /// so the two shapes must stay distinguishable.
    pub fn Get(&self) -> crate::goany::Any {
        if self.json {
            return crate::goany::Any::new(string::from_static("test2json"));
        }
        return crate::goany::Any::new(self.on);
    }

    // go: sdk 1.25.5 testing/testing.go:565-570 chattyFlag.prefix
    /// Go: the framing marker under -v=test2json, otherwise "".
    pub fn prefix(&self) -> string {
        if self.json {
            return string::from_bytes(&[marker]);
        }
        return string::from_static("");
    }
}

#[allow(non_snake_case)]
impl T {
    // go: sdk 1.25.5 testing/testing.go:723-727 common.checkFuzzFn
    /// Go: "panics if the method is called from inside a fuzz target."
    /// goish never sets `inFuzzFn` — F is not ported — so this never
    /// fires today. It is carried across because Output, TempDir,
    /// Setenv and Chdir all begin with a call to it, and porting those
    /// verbatim means the call has to resolve.
    pub(crate) fn checkFuzzFn(&self, name: string) {
        if self.state.inFuzzFn.load(Ordering::Acquire) {
            panic!("testing: f.{} was called inside the fuzz target, use t.{} instead",
                   name.as_ref() as &str, name.as_ref() as &str);
        }
    }

    // go: sdk 1.25.5 testing/testing.go:931-931 common.private
    /// Go: an empty method whose only job is to make TB unimplementable
    /// outside the testing package.
    #[allow(dead_code)]
    pub(crate) fn private(&self) {}

    // go: sdk 1.25.5 testing/testing.go:1509-1522 common.Attr
    /// Go: "Attr emits a test attribute associated with this test."
    ///
    /// Both rejections report through Errorf and RETURN rather than
    /// panicking, so a malformed attribute fails its own test instead
    /// of taking down the run.
    pub fn Attr(&self, key: string, value: string) {
        if crate::strings::ContainsFunc(key.clone(), crate::unicode::IsSpace) {
            self.Errorf(
                "disallowed whitespace in attribute key %q",
                crate::goslice::slice::__from_vec(alloc::vec![crate::goany::Any::new(key)]),
            );
            return;
        }
        if crate::strings::ContainsAny(value.clone(), "\r\n") {
            self.Errorf(
                "disallowed newline in attribute value %q",
                crate::goslice::slice::__from_vec(alloc::vec![crate::goany::Any::new(value)]),
            );
            return;
        }
        // Go: `if c.chatty == nil { return }` — no chatty printer, no
        // attribute stream to emit onto.
        let guard = self.state.chatty.Lock();
        let chatty = match guard.as_ref() {
            Some(c) => c,
            None => return,
        };
        // goish's Updatef takes the message pre-formatted; Go's is
        // variadic. Same text either way.
        chatty.Updatef(
            self.name.clone(),
            crate::fmt::Sprintf!(
                "=== ATTR  %s %v %v\n",
                self.name.clone(),
                key,
                value
            ),
        );
    }
}

#[allow(non_snake_case)]
impl TState {
    // go: sdk 1.25.5 testing/testing.go:942-948 common.setRan
    /// Go: marks this test and EVERY ancestor as having run. The
    /// recursion is what lets a parent whose body only calls t.Run
    /// still report as ran.
    pub(crate) fn setRan(&self) {
        if let Some(p) = self.parent.as_ref() {
            p.setRan();
        }
        self.ran.store(true, Ordering::Release);
    }

    // go: sdk 1.25.5 testing/testing.go:1045-1061 common.destination
    /// Go: "destination selects the test to which output should be
    /// appended. It returns the test if it is incomplete. Otherwise, it
    /// finds its closest incomplete parent."
    ///
    /// Returning None is meaningful, not an error path: it says every
    /// test up the chain has completed, and the callers turn that into
    /// a panic naming the test that was written to too late.
    pub(crate) fn destination(self: &Arc<Self>) -> Option<Arc<TState>> {
        if !self.done.load(Ordering::Acquire) && !self.isSynctest.load(Ordering::Acquire) {
            return Some(self.clone());
        }
        let mut cur = self.parent.clone();
        while let Some(p) = cur {
            if !p.done.load(Ordering::Acquire) {
                return Some(p);
            }
            cur = p.parent.clone();
        }
        return None;
    }
}

// go: none — goish-only: `destination` is unexported, as in Go. This
// exposes the parent-walk it performs so a test can drive it.
#[doc(hidden)]
pub fn __shim_destination(t: &T) -> Option<string> {
    return t
        .state
        .destination()
        .map(|d| return d.name.Lock().clone());
}

// go: none — goish-only: lets a test observe `ran` and `done`, which
// tRunner maintains and which nothing else can read from outside.
#[doc(hidden)]
pub fn __shim_ran_done(t: &T) -> (bool, bool) {
    return (
        t.state.ran.load(Ordering::Acquire),
        t.state.done.load(Ordering::Acquire),
    );
}

// go: none — goish-only: registers a cleanup on the test that is
// currently tearing down. Go's cleanup closures capture `t` and call
// `t.Cleanup` directly; goish's `T` is not `Send + 'static`, so a test
// needs a handle it can move into the closure. Returns that handle.
#[doc(hidden)]
pub fn __shim_cleanup_handle(t: &T) -> CleanupHandle {
    return CleanupHandle {
        state: t.state.clone(),
    };
}

/// A `Send + 'static` handle for registering cleanups from inside a
/// cleanup.
#[doc(hidden)]
pub struct CleanupHandle {
    state: Arc<TState>,
}

#[allow(non_snake_case)]
impl CleanupHandle {
    // go: none — goish-only: same push common.Cleanup performs, from a
    // handle that can be moved into a cleanup closure.
    #[doc(hidden)]
    pub fn Cleanup<F: FnOnce() + Send + 'static>(&self, f: F) {
        self.state.cleanups.Lock().push(alloc::boxed::Box::new(f));
    }
}

// go: none — goish-only: reads the `output` buffer outputWriter appends
// to. Nothing flushes it to stdout yet — that is flushToParent, which is
// not ported — so this is the only way to see what was written.
#[doc(hidden)]
pub fn __shim_output_buf(t: &T) -> string {
    return string::from_bytes(&t.state.output.Lock());
}

// go: none — goish-only: marks a test done so a test can drive
// destination's re-homing branch without racing a real runner.
#[doc(hidden)]
pub fn __shim_mark_done(t: &T) {
    t.state.done.store(true, Ordering::Release);
}

// ─── outputWriter ────────────────────────────────────────────────────

// go: sdk 1.25.5 testing/testing.go:850 indent
/// Go: `const indent = "    "` — "An indent of 4 spaces will neatly
/// align the dashes with the status indicator of the parent."
pub(crate) const indent: &[crate::types::byte] = b"    ";

// go: sdk 1.25.5 testing/testing.go:1120-1123 outputWriter
/// Go: "outputWriter buffers, formats and writes log messages."
///
/// Go's field is `c *common`, a cycle the GC does not mind. goish holds
/// a Weak, so `common` and its writer do not keep each other alive.
/// A dead Weak stands in for Go's nil `c`, which Write already handles.
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct outputWriter {
    pub(crate) c: alloc::sync::Weak<TState>,
    /// Go: "incomplete ('\n'-free) suffix of last Write".
    pub(crate) partial: Arc<crate::sync::Mutex<Vec<crate::types::byte>>>,
}

#[allow(non_snake_case)]
impl TState {
    // go: sdk 1.25.5 testing/testing.go:1115-1117 common.setOutputWriter
    /// Go: `c.o = &outputWriter{c: c}`. goish takes the Arc explicitly
    /// because the writer holds a Weak back to it, and `self` alone
    /// cannot produce one.
    pub(crate) fn setOutputWriter(self: &Arc<Self>) {
        *self.o.Lock() = Some(outputWriter {
            c: Arc::downgrade(self),
            partial: Arc::new(crate::sync::Mutex::new(Vec::new())),
        });
    }

    // go: sdk 1.25.5 testing/testing.go:1087-1097 common.flushPartial
    /// Go: "flushPartial checks the buffer for partial logs and outputs
    /// them." The newline is written through Write, not appended to the
    /// buffer, so it goes through the same indent and chatty routing as
    /// any other line.
    pub(crate) fn flushPartial(self: &Arc<Self>) {
        let partial = {
            let g = self.o.Lock();
            match g.as_ref() {
                Some(o) => o.partial.Lock().len() > 0,
                None => false,
            }
        };
        if partial {
            let w = self.o.Lock().clone();
            if let Some(mut o) = w {
                use crate::io::Writer;
                let _ = o.Write(crate::goslice::slice::__from_vec(alloc::vec![b'\n']));
            }
        }
    }

    // go: sdk 1.25.5 testing/testing.go:1105-1111 common.Output
    /// Go: "Output returns a Writer that writes to the same test output
    /// stream as TB.Log. […] After a test function and all its parents
    /// return, neither Output nor the Write method may be called."
    ///
    /// The panic is the documented behaviour, not a goish shortcut: a
    /// nil destination means every test up the chain has finished, so
    /// there is nowhere for the bytes to go.
    pub(crate) fn Output(self: &Arc<Self>) -> outputWriter {
        let n = match self.destination() {
            Some(n) => n,
            None => panic!(
                "Output called after {} has completed",
                self.name.Lock().as_ref() as &str
            ),
        };
        // Go returns n.o directly; a test that never had one set gets
        // Go's nil *outputWriter, whose Write is a documented no-op.
        let g = n.o.Lock();
        return match g.as_ref() {
            Some(o) => o.clone(),
            None => outputWriter {
                c: alloc::sync::Weak::new(),
                partial: Arc::new(crate::sync::Mutex::new(Vec::new())),
            },
        };
    }
}

#[allow(non_snake_case)]
impl outputWriter {
    // go: sdk 1.25.5 testing/testing.go:1158-1171 outputWriter.writeLine
    fn writeLine(&self, b: &[crate::types::byte]) {
        let c = match self.c.upgrade() {
            Some(c) => c,
            None => return,
        };
        if !c.done.load(Ordering::Acquire) && c.chatty.Lock().is_some() {
            let line = crate::fmt::Sprintf!(
                "%s%s",
                string::from_bytes(indent),
                string::from_bytes(b)
            );
            if c.bench.load(Ordering::Acquire) {
                // Go: "Benchmarks don't print === CONT, so we should
                // skip the test printer and just print straight to
                // stdout."
                crate::fmt::Print!(line);
            } else {
                let g = c.chatty.Lock();
                if let Some(p) = g.as_ref() {
                    p.Printf(c.name.Lock().clone(), line);
                }
            }
            return;
        }
        let mut out = c.output.Lock();
        out.extend_from_slice(indent);
        out.extend_from_slice(b);
    }
}

#[allow(non_snake_case)]
impl crate::io::Writer for outputWriter {
    // go: sdk 1.25.5 testing/testing.go:1127-1155 outputWriter.Write
    /// Go: "It may not be called after a test function and all its
    /// parents return."
    ///
    /// The nil-receiver branch is load-bearing: Go's comment says "o can
    /// be nil if this is called from a top-level *TB that is no longer
    /// active. Just ignore the message in that case." goish spells that
    /// as a dead Weak.
    fn Write(
        &mut self,
        p: crate::goslice::slice<crate::types::byte>,
    ) -> (crate::types::int, crate::errors::error) {
        let c = match self.c.upgrade() {
            Some(c) => c,
            None => return (0, crate::errors::nil),
        };
        if c.destination().is_none() {
            panic!(
                "Write called after {} has completed",
                c.name.Lock().as_ref() as &str
            );
        }

        let bytes = p.clone().__into_vec();
        // Go: `bytes.SplitAfter(p, []byte("\n"))` — the last element is
        // always the partial (newline-free) tail, possibly empty.
        let mut lines: Vec<Vec<crate::types::byte>> = Vec::new();
        let mut cur: Vec<crate::types::byte> = Vec::new();
        for b in bytes.iter() {
            cur.push(*b);
            if *b == b'\n' {
                lines.push(core::mem::take(&mut cur));
            }
        }
        lines.push(cur);

        let last = lines.len() - 1;
        for (i, line) in lines[..last].iter().enumerate() {
            // Go: emit the partial line held over from the last Write.
            if i == 0 && self.partial.Lock().len() > 0 {
                let mut joined = core::mem::take(&mut *self.partial.Lock());
                joined.extend_from_slice(line);
                self.writeLine(&joined);
            } else {
                self.writeLine(line);
            }
        }
        // Go: save the partial line for the next call.
        self.partial.Lock().extend_from_slice(&lines[last]);

        return (p.Len(), crate::errors::nil);
    }
}

#[allow(non_snake_case)]
impl T {
    // go: none — goish idiom: Go's Output is a method on the embedded
    // `common`, so `t.Output()` resolves through embedding. goish's T
    // holds the state in a field, so the forward is written out.
    /// Go: "Output returns a Writer that writes to the same test output
    /// stream as TB.Log. The output is indented like TB.Log lines, but
    /// Output does not add source locations or newlines."
    pub fn Output(&self) -> outputWriter {
        self.checkFuzzFn(string::from_static("Output"));
        return self.state.Output();
    }
}

// ─── indenter and flushToParent ──────────────────────────────────────

// go: sdk 1.25.5 testing/testing.go:846-848 indenter
/// Go: `type indenter struct { c *common }` — the io.Writer a subtest
/// flushes through, so its output lands indented inside its parent's
/// buffer. Weak for the same reason outputWriter is.
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct indenter {
    pub(crate) c: alloc::sync::Weak<TState>,
}

#[allow(non_snake_case)]
impl crate::io::Writer for indenter {
    // go: sdk 1.25.5 testing/testing.go:852-873 indenter.Write
    /// Indents each line by four spaces. The marker byte, if a line
    /// starts with one, is copied out FIRST and the indent goes after
    /// it — test2json frames on that byte, so indenting ahead of it
    /// would put whitespace where the framing has to be.
    fn Write(
        &mut self,
        b: crate::goslice::slice<crate::types::byte>,
    ) -> (crate::types::int, crate::errors::error) {
        let n = b.Len();
        let c = match self.c.upgrade() {
            Some(c) => c,
            None => return (n, crate::errors::nil),
        };
        let buf = b.__into_vec();
        let mut out = c.output.Lock();
        let mut rest: &[crate::types::byte] = &buf;
        while !rest.is_empty() {
            // Go: `end := bytes.IndexByte(b, '\n')`; a line with no
            // newline runs to the end of the input.
            let end = match rest.iter().position(|x| return *x == b'\n') {
                Some(i) => i + 1,
                None => rest.len(),
            };
            let mut line = &rest[..end];
            if line[0] == marker {
                out.push(marker);
                line = &line[1..];
            }
            out.extend_from_slice(indent);
            out.extend_from_slice(line);
            rest = &rest[end..];
        }
        return (n, crate::errors::nil);
    }
}

#[allow(non_snake_case)]
impl TState {
    // go: sdk 1.25.5 testing/testing.go:807-844 common.flushToParent
    /// Go: moves this test's buffered output up to its parent, behind
    /// the status line the caller passes as `format`.
    ///
    /// The output is appended to the FORMAT, not printed before it, so
    /// the logged lines appear after the `--- FAIL` line rather than
    /// above it. Getting that backwards reads fine until a test fails.
    pub(crate) fn flushToParent(
        &self,
        testName: string,
        format: string,
        args: crate::goslice::slice<crate::goany::Any>,
    ) {
        let p = match self.parent.as_ref() {
            Some(p) => p.clone(),
            // Go dereferences c.parent unconditionally; a top-level
            // test never reaches here because nothing flushes the root
            // to a parent it does not have.
            None => return,
        };

        let mut format = format;
        let mut args = args.clone().__into_vec();
        {
            let mut out = self.output.Lock();
            if out.len() > 0 {
                // Go: `format += "%s"` and the buffer becomes the last
                // argument, then the buffer is cleared.
                format = crate::fmt::Sprintf!("%s%s", format, string::from_static("%s"));
                args.push(crate::goany::Any::new(string::from_bytes(&out)));
                out.clear();
            }
        }

        let args = crate::goslice::slice::__from_vec(args);
        let chatty = self.chatty.Lock().clone();

        // Go: `if c.chatty != nil && (p.w == c.chatty.w || c.chatty.json)`
        // — i.e. the parent's writer IS the real output stream, so this
        // write goes straight out rather than into a buffer. goish
        // spells "the parent writes to the real output" as "the parent
        // has no indenter", which is true exactly for the root.
        //
        // Go's comment explains why it matters: the write must be
        // atomic with respect to other tests, "so that we don't end up
        // with confusing '=== NAME' lines in the middle of our
        // '--- PASS' block."
        let parent_is_root = p.w.Lock().is_none();
        if let Some(c) = chatty {
            if parent_is_root {
                c.Updatef(testName, crate::fmt::Sprintv(format, args));
                return;
            }
        }

        // Otherwise: "We're flushing to the output buffer of the parent
        // test, which will itself follow a test-name header when it is
        // finally flushed to stdout."
        let prefix = match self.chatty.Lock().as_ref() {
            Some(c) => c.prefix(),
            None => string::from_static(""),
        };
        let msg = crate::fmt::Sprintv(
            crate::fmt::Sprintf!("%s%s", prefix, format),
            args,
        );

        let w = p.w.Lock().clone();
        match w {
            Some(mut ind) => {
                use crate::io::Writer;
                let _ = ind.Write(crate::goslice::slice::__from_vec(
                    msg.clone().__as_bytes_internal().to_vec(),
                ));
            }
            None => {
                // The root: Go's driver holds an os.Stdout here.
                let bytes = msg.clone().__as_bytes_internal().to_vec();
                crate::syscall::Write(
                    crate::syscall::STDOUT,
                    bytes.as_ptr(),
                    bytes.len(),
                );
            }
        }
    }
}

// ─── parallel gating ─────────────────────────────────────────────────

// go: sdk 1.25.5 testing/testing.go:1657 parallelConflict
/// Go: the panic message when a test that called Setenv or Chdir also
/// calls Parallel. Both change process-wide state, so they cannot be
/// safe while siblings run concurrently.
pub(crate) const parallelConflict: &str =
    "testing: test using t.Setenv or t.Chdir can not use t.Parallel";

// goishlint:ignore GOISH019 testState — `mu`, `running` and
// `numWaiting` become one Mutex<testStateCounts>: Rust wants the
// guarded group named, and the two counters are only ever read and
// written as a pair. `match *matcher` is absent because the matcher is
// threaded through runTests, which is not ported yet.
// go: sdk 1.25.5 testing/testing.go:2072-2096 testState
/// Go: the state shared by every test in one run — the name matcher,
/// the deadline, and the counters that gate how many tests run in
/// parallel at once.
#[allow(non_camel_case_types)]
pub struct testState {
    pub(crate) deadline: crate::sync::Mutex<crate::time::Time>,
    /// Go: "isFuzzing is true in the state used when generating random
    /// inputs for fuzz targets. isFuzzing is false when running normal
    /// tests and when running fuzz tests as unit tests."
    ///
    /// Always false in goish — F is not ported — but runFuzzTests and
    /// tRunner both branch on it, so the field is carried across rather
    /// than dropped and re-added later.
    #[allow(dead_code)]
    pub(crate) isFuzzing: core::sync::atomic::AtomicBool,
    /// Go: "Channel used to signal tests that are ready to be run in
    /// parallel." Unbuffered, so `release` hands off to exactly one
    /// waiter and blocks until that waiter takes it.
    pub(crate) startParallel: crate::gochan::chan<bool>,
    /// Guards `running` and `numWaiting` together — they are read and
    /// written as a pair, so separate atomics would not be enough.
    pub(crate) counts: crate::sync::Mutex<testStateCounts>,
    /// Go: `testState.match *matcher` — the -run/-skip filter, shared by
    /// every test in the run so subtest name deduplication is global.
    pub(crate) matcher: crate::sync::Mutex<Option<crate::testing::r#match::matcher>>,
}

// go: none — goish idiom: Go guards `running` and `numWaiting` with the
// struct's own `mu`. Rust wants the guarded group named, so the pair
// lives in one Mutex rather than two.
#[allow(non_camel_case_types)]
#[derive(Default)]
pub struct testStateCounts {
    /// Go: "the number of tests currently running in parallel. This
    /// does not include tests that are waiting for subtests."
    pub running: crate::types::int,
    /// Go: "the number tests waiting to be run in parallel."
    pub numWaiting: crate::types::int,
    /// Go: "a copy of the parallel flag."
    pub maxParallel: crate::types::int,
}

// go: sdk 1.25.5 testing/testing.go:2098-2105 newTestState
// goishlint:ignore GOISH020 newTestState — Go's second parameter is
// the *matcher, which runTests supplies; goish has no runTests yet, so
// there is nothing to pass and no field to store it in. Restore the
// parameter when runTests lands.
#[allow(non_snake_case)]
pub fn newTestState(maxParallel: crate::types::int) -> Arc<testState> {
    return Arc::new(testState {
        deadline: crate::sync::Mutex::new(crate::time::Time::default()),
        isFuzzing: core::sync::atomic::AtomicBool::new(false),
        startParallel: crate::gochan::chan::new_unbuffered(),
        matcher: crate::sync::Mutex::new(None),
        counts: crate::sync::Mutex::new(testStateCounts {
            // Go: "Set the count to 1 for the main (sequential) test."
            running: 1,
            numWaiting: 0,
            maxParallel,
        }),
    });
}

#[allow(non_snake_case)]
impl testState {
    // go: sdk 1.25.5 testing/testing.go:2107-2117 testState.waitParallel
    /// Go: admit this test to the parallel pool, or park until a slot
    /// frees. The unlock BEFORE the receive is the whole point — holding
    /// the lock across the park would deadlock every releaser.
    pub fn waitParallel(&self) {
        {
            let mut c = self.counts.Lock();
            if c.running < c.maxParallel {
                c.running += 1;
                return;
            }
            c.numWaiting += 1;
        }
        let _ = self.startParallel.Recv();
    }

    // go: sdk 1.25.5 testing/testing.go:2119-2129 testState.release
    /// Go: give up a parallel slot. If someone is waiting, hand the slot
    /// straight to them rather than decrementing — so `running` stays
    /// accurate and no slot is ever lost between the two.
    pub fn release(&self) {
        {
            let mut c = self.counts.Lock();
            if c.numWaiting == 0 {
                c.running -= 1;
                return;
            }
            c.numWaiting -= 1;
        }
        // Go: `s.startParallel <- true` — "Pick a waiting test to be
        // run." Sent with the lock released, as above.
        self.startParallel.Send(true);
    }
}

#[allow(non_snake_case)]
impl T {
    // go: sdk 1.25.5 testing/testing.go:1728-1741 T.checkParallel
    /// Go: "Non-parallel subtests that have parallel ancestors may still
    /// run in parallel with other tests: they are only non-parallel with
    /// respect to the other subtests of the same parent. Since calls
    /// like SetEnv or Chdir affects the whole process, we need to deny
    /// those if the current test or any parent is parallel."
    pub(crate) fn checkParallel(&self) {
        let mut cur = Some(self.state.clone());
        while let Some(c) = cur {
            if c.isParallel.load(Ordering::Acquire) {
                panic!("{}", parallelConflict);
            }
            cur = c.parent.clone();
        }
        self.state.denyParallel.store(true, Ordering::Release);
    }
}

#[allow(non_snake_case)]
impl T {
    // go: sdk 1.25.5 testing/testing.go:2053-2068 T.Deadline
    /// Go: "Deadline reports the time at which the test binary will have
    /// exceeded the timeout specified by the -timeout flag. The ok
    /// result is false if the -timeout flag indicates no timeout (0)."
    ///
    /// The zero Time doubles as "no deadline", which is why ok is
    /// derived from IsZero rather than tracked separately.
    pub fn Deadline(&self) -> (crate::time::Time, bool) {
        if self.state.isSynctest.load(Ordering::Acquire) {
            // Go: "There's no point in returning a real-clock deadline
            // to a test using a fake clock."
            panic!("testing: t.Deadline called inside synctest bubble");
        }
        let deadline = match self.state.tstate.Lock().as_ref() {
            Some(ts) => ts.deadline.Lock().clone(),
            // Go dereferences t.tstate unconditionally; a test built
            // outside a run has no run-wide state, which reads as no
            // deadline.
            None => crate::time::Time::default(),
        };
        let ok = !deadline.IsZero();
        return (deadline, ok);
    }
}

#[allow(non_snake_case)]
impl T {
    // go: sdk 1.25.5 testing/testing.go:1663-1726 T.Parallel
    /// Go: "Parallel signals that this test is to be run in parallel
    /// with (and only with) other parallel tests."
    ///
    /// The sequence is the load-bearing part. The test signals its
    /// PARENT that it is done for now, parks on the parent's barrier
    /// until the parent's own body returns, and only then asks the
    /// run-wide state for a parallel slot. Reordering any of the three
    /// either deadlocks the parent or lets more tests run at once than
    /// -parallel allows.
    pub fn Parallel(&mut self) {
        if self.state.isParallel.load(Ordering::Acquire) {
            panic!("testing: t.Parallel called multiple times");
        }
        if self.state.isSynctest.load(Ordering::Acquire) {
            panic!("testing: t.Parallel called inside synctest bubble");
        }
        if self.state.denyParallel.load(Ordering::Acquire) {
            panic!("{}", parallelConflict);
        }
        let parent = match self.state.parent.as_ref() {
            Some(p) => p.clone(),
            // Go: `if t.parent.barrier == nil { return }` — "T.Parallel
            // has no effect when fuzzing." A top-level test has no
            // parent to be released by, so the same early return
            // applies.
            None => return,
        };

        self.state.isParallel.store(true, Ordering::Release);

        // Go: "We don't want to include the time we spend waiting for
        // serial tests in the test duration. Record the elapsed time
        // thus far and reset the timer afterwards."
        {
            let start = *self.state.start.Lock();
            let mut d = self.state.duration.Lock();
            *d = crate::time::Duration(d.0 + crate::time::Since(start).0);
        }

        // Go: "Add to the list of tests to be released by the parent."
        parent.sub.Lock().push(self.state.clone());

        // Go: "Report any races during execution of this test up to
        // this point" — anything after the park belongs to whoever
        // else is running, not to this test.
        self.state.checkRaces();

        // Go: `t.chatty.Updatef(t.name, "=== PAUSE %s\n", t.name)`.
        if let Some(c) = self.state.chatty.Lock().as_ref() {
            c.Updatef(
                self.name.clone(),
                crate::fmt::Sprintf!("=== PAUSE %s\n", self.name.clone()),
            );
        }
        drain_chatty();
        // Go: `running.Delete(t.name)` — a test parked on the barrier
        // is not running, and must not show up in a timeout report.
        running_delete(self.name.clone());

        // Go: `t.signal <- true` — "Release calling test." The parent
        // is blocked in tRunner waiting on exactly this.
        self.state.signal.Send(true);

        // Go: `<-t.parent.barrier` — "Wait for the parent test to
        // complete." The parent closes the barrier, which wakes every
        // parked subtest at once.
        let _ = parent.barrier.Recv();

        // Go: `t.tstate.waitParallel()` — only NOW compete for one of
        // the -parallel slots. Asking before the barrier would let a
        // subtest hold a slot while it was still blocked.
        let ts = self.state.tstate.Lock().clone();
        if let Some(ts) = ts {
            ts.waitParallel();
        }

        // Go: `t.chatty.Updatef(t.name, "=== CONT  %s\n", t.name)`, then
        // `t.start = highPrecisionTimeNow()` — the clock restarts so the
        // wait for serial tests is not counted as this test's duration.
        if let Some(c) = self.state.chatty.Lock().as_ref() {
            c.Updatef(
                self.name.clone(),
                crate::fmt::Sprintf!("=== CONT  %s\n", self.name.clone()),
            );
        }
        drain_chatty();
        // Go: `running.Store(t.name, highPrecisionTimeNow())` — back on
        // the list, and the clock restarts.
        running_store(self.name.clone(), crate::time::Now());
        *self.state.start.Lock() = crate::time::Now();
        // Go: "Reset the local race counter to ignore any races that
        // happened while this goroutine was blocked". Note it does NOT
        // call parent.checkRaces here — a race introduced by another
        // parallel subtest should be reported by that subtest.
        self.state
            .lastRaceErrors
            .store(crate::int64(race_Errors()), Ordering::Release);
    }
}

// go: none — goish idiom: Go emits a subtest's status through
// `t.report()` -> `flushToParent`, driven by the subtest's OWN tRunner.
// goish's T.Run writes status directly, so a parallel subtest — which
// returns from tRunner early, at the Parallel call — needs its parent
// to write the line once the barrier has released it and it has really
// finished. Same text, same place in the output; different caller.
fn report_parallel_sub(parent: &Arc<TState>, sub: &Arc<TState>) {
    if sub.failed.load(Ordering::Acquire) && !sub.skipped.load(Ordering::Acquire) {
        parent.failed.store(true, Ordering::Release);
    }
    sub.report();
    drain_chatty();
}

#[allow(non_snake_case)]
impl TState {
    // go: sdk 1.25.5 testing/testing.go:1535-1574 common.runCleanup
    // goishlint:ignore GOISH020 runCleanup — Go's `ph panicHandling`
    // parameter selects whether to recover a panicking cleanup and
    // return its value. goish runs under panic=abort with per-G
    // recovery, so there is no panic value to hand back and no second
    // behaviour to select between; the parameter would have exactly one
    // legal argument. Restore it if unwinding ever lands.
    /// Go: "runCleanup is called at the end of the test."
    ///
    /// The loop re-takes the lock on every iteration rather than
    /// draining the slice once, which is what lets a cleanup register
    /// ANOTHER cleanup and still have it run. Taking the whole list up
    /// front — the obvious Rust rewrite — pushes the new callback onto
    /// a slice nobody reads again, and it is silently never called.
    pub(crate) fn runCleanup(&self) {
        self.cleanupStarted.store(true, Ordering::Release);

        loop {
            let cleanup = {
                let mut g = self.cleanups.Lock();
                // Go: LIFO — the last registered cleanup runs first.
                g.pop()
            };
            match cleanup {
                Some(f) => f(),
                None => break,
            }
        }

        self.cleanupStarted.store(false, Ordering::Release);
    }
}

// ─── source attribution ──────────────────────────────────────────────

// go: sdk 1.25.5 testing/testing.go:627 maxStackLen
pub(crate) const maxStackLen: usize = 50;

#[allow(non_snake_case)]
impl TState {
    // go: sdk 1.25.5 testing/testing.go:734-802 common.frameSkip
    /// Go: "frameSkip searches, starting after skip frames, for the
    /// first caller in a function not marked as a helper and returns
    /// that frame."
    ///
    /// Three redirections make this more than a stack walk, and each
    /// one changes which line a failure is blamed on:
    ///   * `runtime.gopanic` frames are skipped outright.
    ///   * On reaching the cleanup function, the walk RESTARTS from the
    ///     stack captured when Cleanup was registered — so a failure in
    ///     teardown points at the registration site.
    ///   * On reaching tRunner in a subtest, it restarts from the
    ///     parent's t.Run call site and keeps searching up.
    pub(crate) fn frameSkip(self: &Arc<Self>, skip: crate::types::int) -> crate::runtime::Frame {
        let mut pcs: crate::goslice::slice<crate::types::uintptr> =
            crate::goslice::slice::__from_vec(alloc::vec![0; maxStackLen]);
        // Go: "Skip two extra frames to account for this function and
        // runtime.Callers itself."
        let n = crate::runtime::Callers(skip + 2, &mut pcs);
        if n == 0 {
            panic!("testing: zero callers found");
        }
        let mut frames = crate::runtime::CallersFrames(pcs.slice(0, n));

        let mut c = self.clone();
        let mut firstFrame = crate::runtime::Frame::default();
        let mut prevFrame = crate::runtime::Frame::default();
        loop {
            let (frame, more) = frames.Next();

            if frame.Function == string::from_static("runtime.gopanic") {
                if !more {
                    break;
                }
                continue;
            }
            if frame.Function == *c.cleanupName.Lock() {
                // Restart from where Cleanup was called.
                frames = crate::runtime::CallersFrames(c.cleanupPc.Lock().clone());
                continue;
            }
            if firstFrame.PC == 0 {
                firstFrame = frame.clone();
            }
            if frame.Function == *c.runner.Lock() {
                // Go: "We've gone up all the way to the tRunner calling
                // the test function."
                if *c.level.Lock() > 1 {
                    // A subtest: continue in the parent, from the point
                    // of the t.Run call that created this subtest.
                    frames = crate::runtime::CallersFrames(c.creator.Lock().clone());
                    let parent = match c.parent.as_ref() {
                        Some(p) => p.clone(),
                        None => return prevFrame,
                    };
                    c = parent;
                    continue;
                }
                return prevFrame;
            }
            // Go: convert any newly-added helper PCs to names, lazily.
            {
                let mut names = c.helperNames.Lock();
                if names.is_none() {
                    let mut m: crate::map<string, bool> = crate::map::new();
                    for pc in c.helperPCs.Lock().Keys().iter() {
                        m.Set(pcToName(*pc), true);
                    }
                    *names = Some(m);
                }
                let (_, ok) = names.as_ref().unwrap().Get(frame.Function.clone());
                if !ok {
                    // "Found a frame that wasn't inside a helper."
                    return frame;
                }
            }

            prevFrame = frame;
            if !more {
                break;
            }
        }
        return firstFrame;
    }

    // go: sdk 1.25.5 testing/testing.go:1063-1085 common.callSite
    /// Go: "callSite retrieves and formats the file and line of the
    /// call site."
    ///
    /// The two fallbacks are Go's, not defensive padding: an
    /// unsymbolisable frame prints "???" rather than an empty name, and
    /// line 0 becomes 1 so the result is always a location an editor
    /// can open.
    pub(crate) fn callSite(self: &Arc<Self>, skip: crate::types::int) -> string {
        let frame = self.frameSkip(skip);
        let mut file = frame.File.clone();
        let mut line = frame.Line;
        if file.Len() != 0 {
            // Go consults the -fullpath flag here; goish has no flag
            // parsing in this path yet, so it takes the default: base
            // name only.
            file = crate::path::Base(file);
        } else {
            file = string::from_static("???");
        }
        if line == 0 {
            line = 1;
        }
        return crate::fmt::Sprintf!("%s:%d: ", file, line);
    }
}

// go: none — goish-only: `callSite` is unexported, as in Go. This gives
// a test a way to see what it attributes a failure to.
#[doc(hidden)]
pub fn __shim_call_site(t: &T, skip: crate::types::int) -> string {
    return t.state.callSite(skip);
}

// ─── TempDir ─────────────────────────────────────────────────────────

// go: sdk 1.25.5 testing/testing.go:1400-1421 removeAll
/// Go: "removeAll is like os.RemoveAll, but retries Windows 'Access is
/// denied' errors up to an arbitrary timeout."
///
/// Go's body is a retry loop around os.RemoveAll, gated on
/// `isWindowsRetryable(err)`. goish targets Linux only, where that
/// predicate is false for every error, so the loop provably runs once
/// and the timeout and backoff are dead code. Written as the single
/// call it reduces to rather than as a loop that always returns on its
/// first iteration.
#[allow(non_snake_case)]
pub(crate) fn removeAll(path: string) -> crate::errors::error {
    return crate::os::RemoveAll(path);
}

#[allow(non_snake_case)]
impl T {
    // go: sdk 1.25.5 testing/testing.go:1321-1390 common.TempDir
    /// Go: "TempDir returns a temporary directory for the test to use.
    /// The directory is automatically removed when the test and all its
    /// subtests complete."
    ///
    /// The automatic removal is the part goish's previous hand-rolled
    /// version lacked entirely — it created directories under /tmp and
    /// never deleted them. It also numbered them from ONE process-wide
    /// counter, so two tests could not tell their directories apart;
    /// Go gives each test its own parent and numbers within it.
    pub fn TempDir(&self) -> string {
        self.checkFuzzFn(string::from_static("TempDir"));

        let seq;
        {
            let mut st = self.state.tempDirState.Lock();

            // Go: "Usually the case with js/wasm" — an empty dir means
            // none has been made yet.
            let nonExistent;
            if st.dir.Len() == 0 {
                nonExistent = true;
            } else {
                let (_, err) = crate::os::Stat(st.dir.clone());
                nonExistent = crate::os::IsNotExist(err.clone());
                if err != crate::errors::nil && !nonExistent {
                    drop(st);
                    self.Fatalf(
                        "TempDir: %v",
                        crate::goslice::slice::__from_vec(alloc::vec![
                            crate::goany::Any::new(err.Error())
                        ]),
                    );
                }
            }

            if nonExistent {
                let mut pattern = self.Name();
                // Go: "Limit length of file names on disk."
                if pattern.Len() > 64 {
                    pattern = pattern.slice(0, 64);
                }
                // Go: "Drop unusual characters (such as path separators
                // or characters interacting with globs) from the
                // directory name to avoid surprising os.MkdirTemp
                // behavior."
                pattern = crate::strings::Map(
                    |r: crate::types::rune| -> crate::types::rune {
                        if r < 0x80 {
                            const allowed: &str = "!#$%&()+,-.=@^_{}~ ";
                            if (0x30..=0x39).contains(&r)
                                || (0x61..=0x7a).contains(&r)
                                || (0x41..=0x5a).contains(&r)
                            {
                                return r;
                            }
                            if allowed.chars().any(|c| return c as crate::types::rune == r) {
                                return r;
                            }
                        } else if crate::unicode::IsLetter(r) || crate::unicode::IsDigit(r) {
                            // Go tests unicode.IsNumber, which covers
                            // category N (Nd, Nl, No); goish has only
                            // IsDigit, i.e. Nd. So a non-ASCII numeral
                            // like a Roman numeral is dropped from the
                            // directory name where Go would keep it.
                            // Harmless here — MkdirTemp appends a random
                            // suffix, so two names that sanitise alike
                            // still get distinct directories.
                            return r;
                        }
                        return -1;
                    },
                    pattern,
                );

                let (dir, err) = crate::os::MkdirTemp("", pattern);
                st.dir = dir.clone();
                st.err = err.clone();
                if err == crate::errors::nil {
                    // Go registers the removal as a Cleanup, which is
                    // what ties the directory's lifetime to the test's.
                    let toRemove = dir;
                    self.Cleanup(move || {
                        let e = removeAll(toRemove);
                        if e != crate::errors::nil {
                            // Go: c.Errorf("TempDir RemoveAll cleanup: %v", err)
                            let msg = crate::fmt::Sprintf!(
                                "TempDir RemoveAll cleanup: %v",
                                e.Error()
                            );
                            let bytes = msg.clone().__as_bytes_internal().to_vec();
                            crate::syscall::Write(
                                crate::syscall::STDOUT,
                                bytes.as_ptr(),
                                bytes.len(),
                            );
                        }
                    });
                }
            }

            if st.err == crate::errors::nil {
                st.seq += 1;
            }
            seq = st.seq;
            if st.err != crate::errors::nil {
                let e = st.err.clone();
                drop(st);
                self.Fatalf(
                    "TempDir: %v",
                    crate::goslice::slice::__from_vec(alloc::vec![
                        crate::goany::Any::new(e.Error())
                    ]),
                );
            }
        }

        let parent = self.state.tempDirState.Lock().dir.clone();
        let dir = crate::fmt::Sprintf!("%s%c%03d", parent, '/' as crate::types::rune, seq);
        let err = crate::os::Mkdir(dir.clone(), 0o777);
        if err != crate::errors::nil {
            self.Fatalf(
                "TempDir: %v",
                crate::goslice::slice::__from_vec(alloc::vec![
                    crate::goany::Any::new(err.Error())
                ]),
            );
        }
        return dir;
    }
}

// ─── fail-fast ───────────────────────────────────────────────────────

// go: sdk 1.25.5 testing/testing.go:520 numFailed
/// Go: "number of test failures". Incremented by tRunner for every
/// top-level test that fails, and read only by shouldFailFast.
pub(crate) static numFailed: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

// go: sdk 1.25.5 testing/testing.go:2723-2725 shouldFailFast
/// Go: "shouldFailFast reports whether the test binary should stop
/// running new tests."
///
/// Both halves are needed: -failfast on its own does nothing until
/// something has actually failed, and a failure on its own does not
/// stop the run unless -failfast was asked for.
#[allow(non_snake_case)]
pub fn shouldFailFast() -> bool {
    let g = FLAGS.Lock();
    let f = match g.as_ref() {
        // Go dereferences *failFast, which is nil before Init; goish
        // reads "no flags registered" as "not set".
        None => return false,
        Some(f) => f,
    };
    return f.failFast.Get() && numFailed.load(Ordering::Acquire) > 0;
}

// ─── report ──────────────────────────────────────────────────────────

/// The buffer the run's chattyPrinter writes into.
///
/// Go's chattyPrinter holds an `io.Writer` and writes straight to
/// stdout; goish's `newChattyPrinter` takes a shared byte buffer
/// instead (a deviation that predates this work). `drain_chatty` empties
/// it to stdout, and tRunner calls that immediately after every report,
/// so the ordering a reader sees is the same as Go's.
static CHATTY_BUF: crate::sync::Mutex<Option<Arc<crate::sync::Mutex<Vec<crate::types::byte>>>>> =
    crate::sync::Mutex::new(None);

// go: none — goish-only: empties the chattyPrinter's buffer to stdout.
pub(crate) fn drain_chatty() {
    let buf = match CHATTY_BUF.Lock().as_ref() {
        Some(b) => b.clone(),
        None => return,
    };
    let bytes = core::mem::take(&mut *buf.Lock());
    if !bytes.is_empty() {
        crate::syscall::Write(crate::syscall::STDOUT, bytes.as_ptr(), bytes.len());
    }
}

// go: none — goish-only: installs the run's chattyPrinter on a test.
// Go's driver does this in runTests when -v is set; goish's runner is
// always chatty, which is what makes it behave like `go test -v`.
pub(crate) fn attach_chatty(state: &Arc<TState>) {
    let buf = {
        let mut g = CHATTY_BUF.Lock();
        if g.is_none() {
            *g = Some(Arc::new(crate::sync::Mutex::new(Vec::new())));
        }
        g.as_ref().unwrap().clone()
    };
    *state.chatty.Lock() = Some(Arc::new(newChattyPrinter(buf, false)));
}

#[allow(non_snake_case)]
impl TState {
    // go: sdk 1.25.5 testing/testing.go:2383-2401 T.report
    /// Go: emit this test's status line, and with it whatever the test
    /// buffered, up to the parent.
    ///
    /// Two things are easy to miss. A top-level test reports NOTHING
    /// here — it has no parent to flush to, and its line is the
    /// driver's job. And without a chatty printer only FAILURES are
    /// reported: a passing subtest is silent unless -v, which is why
    /// goish's runner attaches a printer to every test.
    pub(crate) fn report(&self) {
        if self.parent.is_none() {
            return;
        }
        if self.isSynctest.load(Ordering::Acquire) {
            // Go: "t.parent will handle reporting".
            return;
        }
        let dstr = fmtDuration(*self.duration.Lock());
        let name = self.name.Lock().clone();
        let format = string::from_static("--- %s: %s (%s)\n");
        let failed = self.failed.load(Ordering::Acquire);
        let chatty = self.chatty.Lock().is_some();

        let verb = if failed {
            string::from_static("FAIL")
        } else if !chatty {
            return;
        } else if self.skipped.load(Ordering::Acquire) {
            string::from_static("SKIP")
        } else {
            string::from_static("PASS")
        };

        self.flushToParent(
            name.clone(),
            format,
            crate::goslice::slice::__from_vec(alloc::vec![
                crate::goany::Any::new(verb),
                crate::goany::Any::new(name),
                crate::goany::Any::new(dstr),
            ]),
        );
    }
}

// ─── the running-test registry ───────────────────────────────────────

// go: sdk 1.25.5 testing/testing.go:522 running
/// Go: `var running sync.Map // map[string]time.Time of running,
/// unpaused tests`.
///
/// "unpaused" is the load-bearing word: T.Parallel DELETES its entry
/// before parking and re-adds it on resume, so a test blocked on the
/// barrier is not reported as running. Without that, a timeout panic
/// would name every parallel test in the tree rather than the ones
/// actually stuck.
pub(crate) static running: crate::sync::Mutex<
    Option<crate::map<string, crate::time::Time>>,
> = crate::sync::Mutex::new(None);

// go: none — goish idiom: Go's `running` is a sync.Map, usable
// zero-valued. goish's map needs constructing, so the two accessors
// initialise on first use.
pub(crate) fn running_store(name: string, at: crate::time::Time) {
    let mut g = running.Lock();
    if g.is_none() {
        *g = Some(crate::map::new());
    }
    g.as_mut().unwrap().Set(name, at);
}

// go: none — goish idiom: see running_store.
pub(crate) fn running_delete(name: string) {
    let mut g = running.Lock();
    if let Some(m) = g.as_mut() {
        m.Delete(name);
    }
}

// go: sdk 1.25.5 testing/testing.go:2688-2696 runningList
/// Go: "runningList returns the list of running tests." Sorted, so a
/// timeout panic reads the same way twice — map iteration order is
/// random in Go and unspecified here, and an unsorted list would make
/// two timeouts of the same hang look like different bugs.
#[allow(non_snake_case)]
pub fn runningList() -> crate::goslice::slice<string> {
    let mut list: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    {
        let g = running.Lock();
        if let Some(m) = g.as_ref() {
            for k in m.Keys().iter() {
                let (v, _) = m.Get(k.clone());
                list.push(crate::fmt::Sprintf!(
                    "%s (%v)",
                    k.clone(),
                    crate::time::Since(v).Round(crate::time::Second)
                ));
            }
        }
    }
    list.sort();
    return crate::goslice::slice::__from_vec(list);
}

// ─── the test runner ─────────────────────────────────────────────────

// go: sdk 1.25.5 testing/testing.go:1765-1770 InternalTest
/// Go: "InternalTest is an internal type but exported because it is
/// cross-package; it is part of the implementation of the 'go test'
/// command."
#[allow(non_snake_case)]
pub struct InternalTest {
    pub Name: string,
    pub F: crate::testing::TestFn,
}

// go: sdk 1.25.5 testing/testing.go:2445-2490 runTests
// goishlint:ignore GOISH020 runTests — Go's first parameter is the
// matchString func, which it forwards into newMatcher; goish's caller
// (Main) has no generated main package to get one from and passes None,
// so the parameter would have exactly one legal argument. The deadline
// parameter is kept.
/// Go: run every test, once per -count, once per -cpu entry.
///
/// The structure that matters is the hidden ROOT test: Go wraps the
/// whole run in a `T` whose writer is stdout and whose body is a loop
/// of `t.Run(test.Name, test.F)`. Every "top-level" test is really a
/// subtest of it. That is what gives -run filtering, name
/// deduplication and parallel gating to top-level tests for free,
/// rather than needing a second implementation beside T.Run.
#[allow(non_snake_case)]
pub fn runTests(
    tests: &[InternalTest],
    deadline: crate::time::Time,
) -> (bool, bool) {
    let mut ran = false;
    let mut ok = true;

    let (patterns, skips) = __run_skip_patterns();
    let cpus = cpuList();
    let count = countFlag();

    for procs in cpus.iter() {
        crate::runtime::GOMAXPROCS(*procs);
        for i in 0..count {
            if shouldFailFast() {
                break;
            }
            if i > 0 && !ran {
                // Go: "There were no tests to run on the first
                // iteration. This won't change, so no reason to keep
                // trying."
                break;
            }
            let tstate = newTestState(parallelFlag());
            *tstate.deadline.Lock() = deadline;
            *tstate.matcher.Lock() = Some(crate::testing::r#match::newMatcher(
                None,
                &patterns,
                &string::from_static("-test.run"),
                &skips,
            ));

            // The hidden root. Its `w` stays None — that is what tells
            // flushToParent "my parent writes to the real output".
            let root = T::__new_root(string::from_static(""));
            *root.state.tstate.Lock() = Some(tstate);
            attach_chatty(&root.state);

            let items: alloc::vec::Vec<(string, crate::testing::TestFn)> =
                tests.iter().map(|t| return (t.Name.clone(), t.F)).collect();
            let rstate = root.state.clone();
            tRunner(root, move |t| {
                for (name, f) in items.into_iter() {
                    t.Run(name, f);
                }
            });

            ok = ok && !rstate.failed.load(Ordering::Acquire);
            ran = ran || rstate.ran.load(Ordering::Acquire);
        }
    }
    return (ran, ok);
}

// go: sdk 1.25.5 testing/testing.go:2433-2443 RunTests
// goishlint:ignore GOISH020 RunTests — same dropped matchString
// parameter as runTests; see the note there.
/// Go: "An internal function but exported because it is cross-package;
/// part of the implementation of the 'go test' command."
#[allow(non_snake_case)]
pub fn RunTests(tests: &[InternalTest]) -> bool {
    let mut deadline = crate::time::Time::default();
    let t = timeoutFlag();
    if t > crate::time::Duration(0) {
        deadline = crate::time::Now().Add(t);
    }
    let (ran, ok) = runTests(tests, deadline);
    if !ran {
        // Go also checks `!haveExamples`; goish has no examples runner,
        // so the warning fires whenever nothing matched.
        let msg = b"testing: warning: no tests to run\n";
        crate::syscall::Write(crate::syscall::STDERR, msg.as_ptr(), msg.len());
    }
    return ok;
}

// go: none — goish idiom: Go composes a subtest's name inside
// matcher.fullName. This is the fallback for a T with no run-wide
// state — a bare T built outside runTests — which has no matcher to
// ask. The root's empty name yields "Child", not "/Child".
fn __join_name(parent: &string, sub: &string) -> string {
    if parent.Len() == 0 {
        return sub.clone();
    }
    return crate::fmt::Sprintf!("%s/%s", parent.clone(), sub.clone());
}

// go: sdk 1.25.5 testing/testing.go:2637-2659 toOutputDir
/// Go: "toOutputDir returns the file name relocated, if required, to
/// outputDir."
///
/// An ABSOLUTE path is returned unchanged — -outputdir relocates
/// relative profile names, it does not re-root paths the user spelled
/// out in full. Go's Windows drive-letter branch is dropped: goish
/// targets Linux, where a leading separator is the whole test.
#[allow(non_snake_case)]
pub fn toOutputDir(path: string) -> string {
    let dir = {
        let g = FLAGS.Lock();
        match g.as_ref() {
            None => string::from_static(""),
            Some(f) => f.outputDir.Get(),
        }
    };
    if dir.Len() == 0 || path.Len() == 0 {
        return path;
    }
    if crate::os::IsPathSeparator(path.as_bytes()[0]) {
        return path;
    }
    return crate::fmt::Sprintf!(
        "%s%c%s",
        dir,
        '/' as crate::types::rune,
        path
    );
}

// go: sdk 1.25.5 testing/testing.go:2403-2429 listTests
// goishlint:ignore GOISH020 listTests — Go's first parameter is the
// matchString func, supplied by the generated main package; goish has
// none and uses regexp::MatchString directly, the same function Go's
// generated main passes.
/// Go: print the names matching -test.list and run nothing.
///
/// It lists all four kinds — tests, benchmarks, fuzz targets and
/// examples — from one pattern, which is why it needs the four
/// Internal* types even though goish can only RUN the first.
#[allow(non_snake_case)]
pub fn listTests(
    tests: &[InternalTest],
    benchmarks: &[crate::testing::benchmark::InternalBenchmark],
    fuzzTargets: &[crate::testing::fuzz::InternalFuzzTarget],
    examples: &[crate::testing::example::InternalExample],
) {
    let pattern = {
        let g = FLAGS.Lock();
        match g.as_ref() {
            None => string::from_static(""),
            Some(f) => f.list.Get(),
        }
    };

    // Go: a bad -test.list regexp is fatal, and it is diagnosed BEFORE
    // any name is printed — otherwise a partial listing would look
    // like a complete one.
    let (_, err) = crate::regexp::MatchString(pattern.clone(), "non-empty");
    if err != crate::errors::nil {
        let msg = crate::fmt::Sprintf!(
            "testing: invalid regexp in -test.list (%q): %s\n",
            pattern.clone(),
            err.Error()
        );
        let b = msg.clone().__as_bytes_internal().to_vec();
        crate::syscall::Write(crate::syscall::STDERR, b.as_ptr(), b.len());
        crate::syscall::Exit(1);
    }

    for t in tests.iter() {
        let (ok, _) = crate::regexp::MatchString(pattern.clone(), t.Name.clone());
        if ok {
            crate::fmt::Println!(t.Name.clone());
        }
    }
    for b in benchmarks.iter() {
        let (ok, _) = crate::regexp::MatchString(pattern.clone(), b.Name.clone());
        if ok {
            crate::fmt::Println!(b.Name.clone());
        }
    }
    for ft in fuzzTargets.iter() {
        let (ok, _) = crate::regexp::MatchString(pattern.clone(), ft.Name.clone());
        if ok {
            crate::fmt::Println!(ft.Name.clone());
        }
    }
    for e in examples.iter() {
        let (ok, _) = crate::regexp::MatchString(pattern.clone(), e.Name.clone());
        if ok {
            crate::fmt::Println!(e.Name.clone());
        }
    }
}

// ─── M ───────────────────────────────────────────────────────────────

// goishlint:ignore GOISH019 M — Go's M holds `benchmarks`,
// `fuzzTargets`, `afterOnce` and `exitCode` for machinery goish does
// not have (the benchmark and fuzz runners, and an M.Run that would set
// an exit code). The four fields present are the ones MainStart fills
// and startAlarm/stopAlarm read.
// go: sdk 1.25.5 testing/testing.go:2171-2186 M
/// Go: "M is a type passed to a TestMain function to run the actual
/// tests."
/// `deps` and `examples` are filled by MainStart and read by `M.Run`,
/// which is not ported — its body is M.before/M.after. They are held
/// rather than dropped so the struct still says what an M is.
#[allow(non_snake_case, dead_code)]
pub struct M {
    pub(crate) deps: alloc::boxed::Box<dyn testDeps + Send + Sync>,
    pub(crate) tests: alloc::vec::Vec<InternalTest>,
    pub(crate) examples: alloc::vec::Vec<crate::testing::example::InternalExample>,
    pub(crate) timer: crate::sync::Mutex<Option<crate::time::Timer>>,
}

// go: sdk 1.25.5 testing/testing.go:2213-2223 MainStart
// goishlint:ignore GOISH020 MainStart — Go takes `benchmarks` and
// `fuzzTargets` slices too; neither runner is ported, so there is
// nothing that could consume them and no field to hold them.
/// Go: "MainStart is meant for use by tests generated by 'go test'. It
/// is not meant to be called directly."
///
/// The registerCover call is not ceremony: it is where a coverage-built
/// binary hands testing its mode and teardown. goish's deps return the
/// empty mode, so registerCover records nothing — but the seam is real
/// and calling it keeps that visible.
#[allow(non_snake_case)]
pub fn MainStart(
    deps: alloc::boxed::Box<dyn testDeps + Send + Sync>,
    tests: alloc::vec::Vec<InternalTest>,
    examples: alloc::vec::Vec<crate::testing::example::InternalExample>,
) -> M {
    let (mode, tearDown, snapcov) = deps.InitRuntimeCoverage();
    crate::testing::newcover::registerCover(mode, tearDown, snapcov);
    Init();
    return M {
        deps,
        tests,
        examples,
        timer: crate::sync::Mutex::new(None),
    };
}

#[allow(non_snake_case)]
impl M {
    // go: sdk 1.25.5 testing/testing.go:2662-2685 M.startAlarm
    /// Go: arm the -timeout watchdog and return the deadline it
    /// implies. A zero or negative timeout means no watchdog, and the
    /// zero Time it returns is what T.Deadline reports as "no
    /// deadline".
    ///
    /// goish's -timeout defaults to 0, so the timer is normally never
    /// created. That matters beyond efficiency: goish waits for every
    /// goroutine at exit and Timer::Stop does not cancel the sleeper,
    /// so an armed watchdog would pin process exit for its full
    /// duration even after stopAlarm.
    pub fn startAlarm(&self) -> crate::time::Time {
        let timeout = timeoutFlag();
        if timeout <= crate::time::Duration(0) {
            return crate::time::Time::default();
        }
        let deadline = crate::time::Now().Add(timeout);
        *self.timer.Lock() = Some(crate::time::AfterFunc(timeout, move || {
            // Go also calls m.after() and sets a full traceback first;
            // both are profiling teardown goish has no backing for.
            let list = runningList();
            let mut extra = string::from_static("");
            if list.Len() > 0 {
                let mut b: alloc::vec::Vec<crate::types::byte> = alloc::vec::Vec::new();
                b.extend_from_slice(b"\nrunning tests:");
                for i in 0..list.Len() {
                    b.extend_from_slice(b"\n\t");
                    b.extend_from_slice(list[i].clone().__as_bytes_internal());
                }
                extra = string::from_bytes(&b);
            }
            panic!(
                "test timed out after {}{}",
                timeout.String().as_ref() as &str,
                extra.as_ref() as &str
            );
        }));
        return deadline;
    }

    // go: sdk 1.25.5 testing/testing.go:2699-2703 M.stopAlarm
    pub fn stopAlarm(&self) {
        if timeoutFlag() > crate::time::Duration(0) {
            if let Some(t) = self.timer.Lock().as_ref() {
                t.Stop();
            }
        }
    }
}

// ─── race reporting ──────────────────────────────────────────────────

// go: none — goish idiom: Go calls `race.Errors()` from internal/race.
// goish has no race detector, which is the same situation as any Go
// build without `-race`: internal/race/norace.go is literally
// `func Errors() int { return 0 }`. Spelled out here rather than
// inlined as a constant so the two call sites read like Go's.
fn race_Errors() -> crate::types::int {
    return 0;
}

#[allow(non_snake_case)]
impl TState {
    // go: sdk 1.25.5 testing/testing.go:1581-1587 common.resetRaces
    /// Go: rebase this test's race counter, so races that happened
    /// before it started are not attributed to it. A subtest rebases
    /// through its PARENT's checkRaces, which is what makes the parent
    /// report a pre-existing race first.
    pub(crate) fn resetRaces(&self) {
        if self.parent.is_none() {
            self.lastRaceErrors
                .store(crate::int64(race_Errors()), Ordering::Release);
        } else {
            let n = self.parent.as_ref().unwrap().checkRaces();
            self.lastRaceErrors.store(n, Ordering::Release);
        }
    }

    // go: sdk 1.25.5 testing/testing.go:1599-1637 common.checkRaces
    /// Go: report any race seen since this test's last check, exactly
    /// once, and tell every ancestor about it so they do not report it
    /// again.
    ///
    /// Both loops are compare-and-swap rather than plain stores because
    /// parallel subtests call this concurrently: two of them seeing the
    /// same race must not both report it. The claim is the CAS on
    /// `raceErrorLogged`, not the counter.
    pub(crate) fn checkRaces(&self) -> crate::types::int64 {
        let raceErrors = crate::int64(race_Errors());
        loop {
            let last = self.lastRaceErrors.load(Ordering::Acquire);
            if raceErrors <= last {
                // Go: "All races have already been reported."
                return raceErrors;
            }
            if self
                .lastRaceErrors
                .compare_exchange(last, raceErrors, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        if self
            .raceErrorLogged
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Go: "This is the first race we've encountered for this
            // test. Mark the test as failed, and log the reason why
            // only once."
            self.__errorf_race();
        }

        // Go: "Update the parent(s) of this test so that they don't
        // re-report the race."
        let mut parent = self.parent.clone();
        while let Some(p) = parent {
            loop {
                let last = p.lastRaceErrors.load(Ordering::Acquire);
                if raceErrors <= last {
                    // Go: "This race was already reported by another
                    // (likely parallel) subtest."
                    return raceErrors;
                }
                if p.lastRaceErrors
                    .compare_exchange(last, raceErrors, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    break;
                }
            }
            parent = p.parent.clone();
        }

        return raceErrors;
    }

    // go: none — goish idiom: Go's checkRaces calls c.Errorf, a method
    // on the embedded common. goish's Errorf lives on T, which this
    // state cannot reach, so the failure is recorded directly.
    fn __errorf_race(&self) {
        self.failed.store(true, Ordering::Release);
        let mut p = self.parent.clone();
        while let Some(x) = p {
            x.failed.store(true, Ordering::Release);
            p = x.parent.clone();
        }
    }
}
