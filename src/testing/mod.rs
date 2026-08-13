// testing — Go's `testing` package.
//
// Reference: /share/go/src/testing/testing.go.
//
// User-facing API:
//
//   fn TestFoo(t: &mut testing::T) {
//       if 1 + 1 != 2 {
//           t.Errorf(Sprintf!("got %d, want 2", 1 + 1));
//       }
//       t.Run(string::from_static("subtest"), |t| {
//           t.Logf(string::from_static("running subtest"));
//       });
//   }
//
//   #[goish::main]
//   fn main() {
//       let tests: &[(&str, fn(&mut testing::T))] = &[
//           ("TestFoo", TestFoo),
//       ];
//       syscall::Exit(testing::Main(tests));
//   }
//
// Implemented:
//
//   - T::Name, T::Errorf, T::Logf, T::Fatalf
//   - T::Error, T::Log, T::Fatal (variadic; goish takes one string)
//   - T::Fail, T::FailNow, T::Failed
//   - T::Skip, T::Skipf, T::SkipNow, T::Skipped
//   - T::Run(name, fn) for subtests
//   - T::Cleanup(fn) for deferred cleanup
//   - T::TempDir for per-test scratch directories (auto-removed)
//   - T::Helper (no-op; Go uses it to attribute file:line in failure
//     messages, which goish does not track yet)
//   - testing::Main(tests) — runner returning an exit code
//   - match.rs: the full -run/-skip filter and subtest name uniquer
//
// Each test body runs on its own goroutine (`tRunner`), which is what
// makes FailNow/Fatal/Skip end one test rather than the process. They
// are `runtime::Goexit` underneath, exactly as in Go.
//
// Not ported yet: Parallel, Context, Deadline, Output, Attr, Setenv,
// Chdir, B (benchmarks), F (fuzzing), M/TestMain, and flag parsing —
// so `-run`/`-v` are not wired to the matcher that match.rs provides.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod benchmark;
pub mod fstest;
pub mod example;
pub mod run_example;
pub mod fuzz;
pub mod slogtest;
pub mod iotest;
pub mod r#match;
mod allocs;
mod newcover;
mod testing;
pub use allocs::AllocsPerRun;
pub use newcover::Coverage;
pub use testing::{
    callerName, chattyFlag, chattyPrinter, fmtDuration, marker, newChattyPrinter, parseCpuList,
    pcToName, prefix, testBinary, CoverMode, Init, Short, Testing, Verbose,
    indenter, newTestState, outputWriter, runningList, listTests, shouldFailFast, toOutputDir, testState, testStateCounts, __run_skip_patterns, __shim_destination, __shim_err_main, __shim_call_site, __shim_cleanup_handle, __shim_mark_done, __shim_output_buf, CleanupHandle, __shim_ran_done, __shim_match_string_only, __DepsProbe,
};

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;

use crate::gostring::string;
use crate::sync::Mutex;
use crate::syscall;
use crate::types::int;

// ─── T ────────────────────────────────────────────────────────────

pub(crate) struct TState {
    pub(crate) failed: AtomicBool,
    pub(crate) skipped: AtomicBool,
    /// Go: `common.finished` — "Test function has completed." Set by
    /// FailNow/SkipNow before the Goexit so the runner can tell a
    /// deliberate exit from a goroutine that died some other way.
    pub(crate) finished: AtomicBool,
    /// goish-only: guards `finish_before_goexit` against running twice
    /// (normal return after an explicit FailNow, or a Cleanup callback
    /// that itself calls FailNow).
    pub(crate) reported: AtomicBool,
    /// Go: `common.signal chan bool` — "To signal a test is done."
    /// Buffered with capacity 1 and sent exactly once, so the sender
    /// never parks; a test on its way out through Goexit must not be
    /// able to block here.
    pub(crate) signal: crate::gochan::chan<bool>,
    /// Cleanup callbacks, run in LIFO order on test return.
    /// Boxed because the closure types differ across calls.
    pub(crate) cleanups: Mutex<Vec<Box<dyn FnOnce() + Send + 'static>>>,
    /// Go: `common.parent *common`. Go's `Fail` walks up this chain so
    /// a failure is visible on every ancestor immediately, not only
    /// once the subtest returns.
    pub(crate) parent: Option<Arc<TState>>,
    /// Go: `common.helperPCs map[uintptr]struct{}` — "functions to be
    /// skipped when writing file/line info". Populated by `Helper`.
    pub(crate) helperPCs: Mutex<crate::map<crate::types::uintptr, bool>>,
    /// Go: `common.inFuzzFn bool` — "Whether the fuzz target, if this
    /// is one, is running." Never set in goish (F is not ported), but
    /// `checkFuzzFn` guards Output/TempDir/Setenv/Chdir on it, so the
    /// field has to exist for those to port verbatim.
    pub(crate) inFuzzFn: AtomicBool,
    /// Go: `common.chatty *chattyPrinter` — "A copy of chattyPrinter,
    /// if the chatty flag is set." goish's runner writes through
    /// `write_status` rather than a printer, so this stays None until
    /// the M.Run driver lands; `Attr` reads it exactly as Go does.
    pub(crate) chatty: Mutex<Option<Arc<testing::chattyPrinter>>>,
    /// Go: `common.ran bool` — "Test or benchmark (or one of its
    /// subtests) was executed."
    pub(crate) ran: AtomicBool,
    /// Go: `common.done bool` — "Test is finished and all subtests have
    /// completed." `destination` reads it to decide whether late output
    /// belongs to this test or has to be re-homed on an ancestor.
    pub(crate) done: AtomicBool,
    /// Go: `common.isSynctest bool`. goish has no synctest bubbles, so
    /// this is always false — but `destination` branches on it, and a
    /// port that dropped the term would silently change which test
    /// late output lands on.
    pub(crate) isSynctest: AtomicBool,
    /// Go: `common.name string`. goish also keeps the name on `T` for
    /// the existing logging path; `destination`'s callers need it on
    /// the shared state, since they walk the parent chain.
    pub(crate) name: Mutex<string>,
    /// Go: `common.output []byte` — "Output generated by test or
    /// benchmark." The buffer `outputWriter` appends indented lines to,
    /// flushed to the parent when the test finishes.
    pub(crate) output: Mutex<Vec<crate::types::byte>>,
    /// Go: `common.bench bool` — "Whether the current test is a
    /// benchmark." `writeLine` branches on it: benchmarks print
    /// straight to stdout because they never emit `=== CONT`.
    pub(crate) bench: AtomicBool,
    /// Go: `common.o *outputWriter` — "Writes output."
    ///
    /// Go's outputWriter holds `c *common`, a cycle Go's GC does not
    /// mind. goish holds a Weak instead, so the pair does not leak; the
    /// field is set after the Arc exists, which is why it is an Option.
    pub(crate) o: Mutex<Option<testing::outputWriter>>,
    /// Go: `common.w io.Writer` — "For flushToParent."
    ///
    /// Go sets it to `indenter{&t.common}` for every test, so a
    /// subtest's flush lands indented in its parent's buffer. A
    /// top-level test's parent is nil and it never flushes, so None
    /// here means "the root output stream" — goish writes that
    /// straight to stdout, where Go's driver holds an os.Stdout.
    pub(crate) w: Mutex<Option<testing::indenter>>,
    /// Go: `common.isParallel bool` — "Whether the test is parallel."
    pub(crate) isParallel: AtomicBool,
    /// Go: `T.denyParallel bool` — set by Setenv/Chdir, which change
    /// process-wide state and so cannot coexist with Parallel.
    pub(crate) denyParallel: AtomicBool,
    /// Go: `T.tstate *testState` — the run-wide state (matcher,
    /// deadline, parallel counters) every test in one run shares.
    pub(crate) tstate: Mutex<Option<Arc<testing::testState>>>,
    /// Go: `common.barrier chan bool` — "To signal parallel subtests
    /// they may start." A parent closes it once its own body returns,
    /// which releases every parallel subtest at once.
    pub(crate) barrier: crate::gochan::chan<bool>,
    /// Go: `common.sub []*T` — "Queue of subtests to be run in
    /// parallel." goish keeps the shared state rather than the T, since
    /// waiting on a subtest only needs its signal channel.
    pub(crate) sub: Mutex<Vec<Arc<TState>>>,
    /// Go: `common.level int` — "Nesting depth of test or benchmark."
    /// The parent needs it to indent a parallel subtest's status line,
    /// which it prints only after the barrier releases.
    pub(crate) level: Mutex<usize>,
    /// Go: `common.cleanupStarted atomic.Bool` — "Registered cleanup
    /// callbacks have started to execute." Cleanup itself reads it, so
    /// a cleanup registering another cleanup is handled rather than
    /// silently dropped.
    pub(crate) cleanupStarted: AtomicBool,
    /// Go: `common.helperNames map[string]struct{}` — "helperPCs
    /// converted to function names". Built lazily by frameSkip, since
    /// symbolising every helper PC up front costs more than most tests
    /// ever need.
    pub(crate) helperNames: Mutex<Option<crate::map<string, bool>>>,
    /// Go: `common.cleanupName string` — "Name of the cleanup
    /// function."
    pub(crate) cleanupName: Mutex<string>,
    /// Go: `common.cleanupPc []uintptr` — "The stack trace at the point
    /// where Cleanup was called." frameSkip switches to it so a failure
    /// inside a cleanup is attributed to where the cleanup was
    /// REGISTERED, not to the teardown loop.
    pub(crate) cleanupPc: Mutex<crate::goslice::slice<crate::types::uintptr>>,
    /// Go: `common.creator []uintptr` — "If level > 0, the stack trace
    /// at the point where the parent called t.Run."
    pub(crate) creator: Mutex<crate::goslice::slice<crate::types::uintptr>>,
    /// Go: `common.runner string` — "Function name of tRunner running
    /// the test." frameSkip stops when it reaches this frame.
    pub(crate) runner: Mutex<string>,
    /// Go: `common.tempDirMu sync.Mutex` guarding the three fields
    /// below. They are read and written together, so they share one.
    pub(crate) tempDirState: Mutex<TempDirState>,
    /// Go: `common.start highPrecisionTime` — "Time test or benchmark
    /// started."
    pub(crate) start: Mutex<crate::time::Time>,
    /// Go: `common.duration time.Duration`. Accumulated rather than
    /// computed at the end, because T.Parallel banks the elapsed time
    /// so far and restarts the clock — the wait for serial tests is not
    /// this test's duration.
    pub(crate) duration: Mutex<crate::time::Duration>,
    /// Go: `common.lastRaceErrors atomic.Int64` — "Max value of
    /// race.Errors seen during the test or its subtests."
    pub(crate) lastRaceErrors: core::sync::atomic::AtomicI64,
    /// Go: `common.raceErrorLogged atomic.Bool` — so the "race
    /// detected" message is logged once per test, not once per race.
    pub(crate) raceErrorLogged: AtomicBool,
}

/// Go: `common.tempDir`, `tempDirErr` and `tempDirSeq`.
#[derive(Default)]
pub(crate) struct TempDirState {
    /// The per-test parent directory, created once.
    pub dir: string,
    /// The error from creating it, remembered so every later TempDir
    /// call fails the same way instead of retrying.
    pub err: crate::errors::error,
    /// Sequence number for the numbered subdirectory.
    pub seq: crate::types::int32,
}

impl TState {
    pub(crate) fn new() -> Self {
        return TState {
            failed: AtomicBool::new(false),
            skipped: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            reported: AtomicBool::new(false),
            signal: crate::gochan::chan::new_buffered(1),
            cleanups: Mutex::new(Vec::new()),
            parent: None,
            helperPCs: Mutex::new(crate::map::new()),
            inFuzzFn: AtomicBool::new(false),
            chatty: Mutex::new(None),
            ran: AtomicBool::new(false),
            done: AtomicBool::new(false),
            isSynctest: AtomicBool::new(false),
            name: Mutex::new(string::from_static("")),
            output: Mutex::new(Vec::new()),
            bench: AtomicBool::new(false),
            o: Mutex::new(None),
            w: Mutex::new(None),
            isParallel: AtomicBool::new(false),
            denyParallel: AtomicBool::new(false),
            tstate: Mutex::new(None),
            barrier: crate::gochan::chan::new_unbuffered(),
            sub: Mutex::new(Vec::new()),
            level: Mutex::new(0),
            cleanupStarted: AtomicBool::new(false),
            helperNames: Mutex::new(None),
            cleanupName: Mutex::new(string::from_static("")),
            cleanupPc: Mutex::new(crate::goslice::slice::new()),
            creator: Mutex::new(crate::goslice::slice::new()),
            runner: Mutex::new(string::from_static("")),
            tempDirState: Mutex::new(TempDirState::default()),
            start: Mutex::new(crate::time::Now()),
            duration: Mutex::new(crate::time::Duration(0)),
            lastRaceErrors: core::sync::atomic::AtomicI64::new(0),
            raceErrorLogged: AtomicBool::new(false),
        };
    }
}

/// Stack for a test goroutine.
///
/// goish's default 2 KiB is far too small for a test body: debug builds
/// do not inline, and a test that reaches into `crypto` or `encoding`
/// can nest deeply. 1 MiB of *reserved* address space costs nothing
/// until touched — the kernel commits on demand — so this buys depth
/// without RSS.
const TEST_STACK: usize = 1024 * 1024;

/// `testing.T` — the test handle. Shared across goroutines via
/// `Arc<TState>`; the public `T` is a value type that holds the
/// Arc, mirroring Go's `*testing.T` reference semantics.
pub struct T {
    pub(crate) name: string,
    pub(crate) state: Arc<TState>,
    /// Indent depth for sub-test logging output. Top-level = 0,
    /// each `Run` increments by 1.
    pub(crate) depth: usize,
}

impl T {
    // go: none — goish-only: the hidden root T that runTests wraps a
    // run in. Go builds it as a struct literal; goish needs a
    // constructor because the state lives behind an Arc. Depth 0 and
    // an empty name mean its subtests are the top-level tests.
    #[doc(hidden)]
    pub fn __new_root(name: string) -> Self {
        return T::new(name);
    }

    fn new(name: string) -> Self {
        T {
            name,
            state: Arc::new(TState::new()),
            depth: 0,
        }
    }

    pub(crate) fn drain_cleanups(&self) {
        self.state.runCleanup();
    }

    pub(crate) fn write_line(&self, tag: &[u8], msg: &string) {
        // Go: `n.flushPartial()` in common.log, before the line is
        // written. An Output() write with no trailing newline is held
        // back as a partial; a Log arriving next must not be spliced
        // onto the end of it.
        self.state.flushPartial();
        // …and push it out before this line. flushPartial writes through
        // the chattyPrinter, which buffers; this line goes straight to
        // stdout. Without the drain the two arrive in the wrong order —
        // Go prints the pending partial first, then the log.
        testing::drain_chatty();

        let indent = indent_for(self.depth + 1);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(indent.as_bytes());
        buf.extend_from_slice(tag);
        buf.push(b' ');
        buf.extend_from_slice(self.name.clone().__as_bytes_internal());
        buf.push(b':');
        buf.push(b' ');
        buf.extend_from_slice(msg.clone().__as_bytes_internal());
        buf.push(b'\n');
        syscall::Write(syscall::STDOUT, buf.as_ptr(), buf.len());
    }
}

// go: none — goish-only: the output indent for a subtest at `depth`.
// Go indents through its `indenter` io.Writer wrapper, which goish does
// not have; this returns the prefix as a `string` so nothing in the
// signature is a Rust container.
pub(crate) fn indent_for(depth: usize) -> string {
    let mut v = Vec::with_capacity(depth * 4);
    for _ in 0..depth {
        v.extend_from_slice(b"    ");
    }
    return string::from_bytes(&v);
}

// ─── Runner ──────────────────────────────────────────────────────

/// Test entry. Each test function takes a `&mut T` and may call
/// any of the assertion / logging methods.
pub type TestFn = fn(&mut T);


/// `testing.Main(tests)` — run the given list of (name, fn) pairs
/// in registration order, print PASS/FAIL/SKIP per test, and
/// return an exit code (0 if all passed, 1 if any failed).
///
/// Mirrors the role of Go's `go test` driver. Goish doesn't
/// auto-discover `Test*` functions (no compile-time reflection of
/// modules); the user is expected to assemble the slice in the
/// `#[goish::main]` body.
pub fn Main(tests: &[(&'static str, TestFn)]) -> int {
    // Go's testing.Main is
    //     os.Exit(MainStart(matchStringOnly(matchString), tests,
    //                       benchmarks, nil, examples).Run())
    // goish follows the same path as far as it goes: MainStart wires
    // the deps and coverage seam, the alarm brackets the run, and
    // RunTests does the work. M.Run itself is not ported — its body is
    // M.before/M.after, which are entirely profiling, tracing and
    // coverage setup goish has no backing for.
    let internal: Vec<testing::InternalTest> = tests
        .iter()
        .map(|(name, f)| {
            return testing::InternalTest {
                Name: string::from_static(name),
                F: *f,
            };
        })
        .collect();

    // Go passes matchStringOnly(matchString) — the same regexp match
    // its generated main package supplies.
    let deps = alloc::boxed::Box::new(testing::matchStringOnly::new(
        |pat: string, str_: string| {
            return crate::regexp::MatchString(pat, str_);
        },
    ));
    let m = testing::MainStart(deps, internal, Vec::new());

    let _deadline = m.startAlarm();
    let ok = testing::RunTests(&m.tests);
    m.stopAlarm();

    let summary: &[u8] = if ok { b"\nPASS\n" } else { b"\nFAIL\n" };
    syscall::Write(syscall::STDOUT, summary.as_ptr(), summary.len());

    if ok {
        return 0;
    }
    return 1;
}



// `string::as_bytes()` is `pub(crate)` and the `testing` module is
// inside the goish crate, so we can call it directly without an
// extra extension trait. The `__as_bytes_internal` calls above
// resolve to crate-internal byte access.

pub(crate) trait StringBytesAccess {
    fn __as_bytes_internal(&self) -> &[u8];
}

impl StringBytesAccess for string {
    #[inline]
    fn __as_bytes_internal(&self) -> &[u8] {
        // Crate-internal access: as_bytes is pub(crate), reachable
        // from any module inside goish.
        crate::gostring::__crate_as_bytes(self)
    }
}
