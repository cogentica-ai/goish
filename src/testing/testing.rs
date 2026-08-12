// go: file testing/testing.go decls: chattyFlag.IsBoolFlag, chattyFlag.Set, chattyFlag.String, chattyPrinter.prefix, fmtDuration, common.Name, common.Log, common.Logf, common.Error, common.Errorf, common.Fail, common.FailNow, common.Failed, common.Fatal, common.Fatalf, common.Skip, common.Skipf, common.SkipNow, common.Skipped, common.Helper, common.Cleanup, T.Run, tRunner
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
// goishlint:ignore GOISH020 Logf, Skipf — Go's signature is `(format string, args ...any)`; goish takes the already-formatted string, since `Sprintf!` formats at the call site. `Errorf`/`Fatalf` keep the runtime-variadic slice for ports that spread one, so both shapes exist in the package.
// goishlint:ignore GOISH018 after, Attr, before, callerName, callSite, Chdir, CheckCorpus, checkFuzzFn, checkParallel, checkRaces, Context, CoordinateFuzzing, CoverMode, Deadline, destination, flushPartial, flushToParent, frameSkip, Get, ImportPath, Init, InitRuntimeCoverage, listTests, log, Main, MainStart, MatchString, newChattyPrinter, newTestState, Output, Parallel, parseCpuList, pcToName, Printf, private, ReadCorpus, release, removeAll, report, ResetCoverage, resetRaces, runCleanup, RunFuzzWorker, runningList, runTests, RunTests, Setenv, setOutputWriter, SetPanicOnExit0, setRan, Short, shouldFailFast, SnapshotCoverage, startAlarm, StartCPUProfile, StartTestLog, stopAlarm, StopCPUProfile, StopTestLog, TempDir, Testing, testingSynctestTest, toOutputDir, Updatef, Verbose, waitParallel, Write, writeLine, writeProfiles, WriteProfileTo — the driver is only partly ported; see the note above.
// goishlint:ignore GOISH021 _, blockProfile, blockProfileRate, chatty, chattyPrinter, common, count, coverProfile, cpuList, cpuListStr, cpuProfile, errMain, errNilPanicOrGoexit, failFast, fullPath, gocoverdir, haveExamples, indent, indenter, initRan, InternalTest, M, match, matchList, matchStringOnly, maxStackLen, memProfile, memProfileRate, mutexProfile, mutexProfileFraction, normalPanic, numFailed, outputDir, outputWriter, panicHandling, panicOnExit0, parallel, parallelConflict, parallelStart, parallelStop, realStderr, recoverAndReturnPanic, running, short, shuffle, skip, T, TB, testBinary, testDeps, testingTesting, testlog, testlogFile, testState, timeout, traceFile — same: the driver's types and package state come with the driver.
// goishlint:ignore GOISH017 common.FailNow, common.Skip, common.SkipNow — declared on Go's `common`, ported as methods on goish's `T`, which is the only type that embeds it here.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{indent_for, write_status, StringBytesAccess, TState, T, TEST_STACK};
use crate::gostring::string;

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
        let msg: string = msg.into();
        self.write_line(b"   ", &msg);
    }

    // go: sdk 1.25.5 testing/testing.go:1178-1181 common.Log
    /// Go: "Log formats its arguments using default formatting,
    /// analogous to Println, and records the text in the error log."
    pub fn Log<M: Into<string>>(&self, msg: M) {
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
    /// running, and goish's per-G isolation would turn a diagnostic
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
        let format: string = format.into();
        self.Errorf(format, args);
        self.FailNow();
    }

    // go: sdk 1.25.5 testing/testing.go:1209-1213 common.Fatal
    /// Go: "Fatal is equivalent to Log followed by FailNow."
    pub fn Fatal<M: Into<string>>(&self, msg: M) -> ! {
        let msg: string = msg.into();
        self.Fatalf(msg, crate::goslice::slice::new());
    }

    // go: sdk 1.25.5 testing/testing.go:1230-1234 common.Skipf
    /// Go: "Skipf is equivalent to Logf followed by SkipNow."
    pub fn Skipf<M: Into<string>>(&self, msg: M) -> ! {
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
    /// No-op here. Go records the caller's PC in `helperPCs` and
    /// consults it from `callSite` when attributing a failure to a
    /// file:line. goish does not print file:line on failures at all
    /// (that needs `runtime.CallersFrames`, which is not ported), so
    /// there is nothing yet for the marker to suppress.
    pub fn Helper(&self) {}

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
        self.state.cleanups.Lock().push(alloc::boxed::Box::new(f));
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

        let mut sub_state = TState::new();
        // Go: `t.common.parent = &t.common` on the subtest, which is
        // what makes a failing subtest fail its ancestors immediately.
        sub_state.parent = Some(self.state.clone());
        let sub = T {
            name: qualified.clone(),
            state: Arc::new(sub_state),
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
