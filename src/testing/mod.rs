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

pub mod fstest;
pub mod iotest;
pub mod r#match;

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::gostring::string;
use crate::sync::Mutex;
use crate::syscall;
use crate::types::int;

// ─── T ────────────────────────────────────────────────────────────

struct TState {
    failed: AtomicBool,
    skipped: AtomicBool,
    /// Go: `common.finished` — "Test function has completed." Set by
    /// FailNow/SkipNow before the Goexit so the runner can tell a
    /// deliberate exit from a goroutine that died some other way.
    finished: AtomicBool,
    /// goish-only: guards `finish_before_goexit` against running twice
    /// (normal return after an explicit FailNow, or a Cleanup callback
    /// that itself calls FailNow).
    reported: AtomicBool,
    /// Go: `common.signal chan bool` — "To signal a test is done."
    /// Buffered with capacity 1 and sent exactly once, so the sender
    /// never parks; a test on its way out through Goexit must not be
    /// able to block here.
    signal: crate::gochan::chan<bool>,
    /// Cleanup callbacks, run in LIFO order on test return.
    /// Boxed because the closure types differ across calls.
    cleanups: Mutex<Vec<Box<dyn FnOnce() + Send + 'static>>>,
}

impl TState {
    fn new() -> Self {
        return TState {
            failed: AtomicBool::new(false),
            skipped: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            reported: AtomicBool::new(false),
            signal: crate::gochan::chan::new_buffered(1),
            cleanups: Mutex::new(Vec::new()),
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
    name: string,
    state: Arc<TState>,
    /// Indent depth for sub-test logging output. Top-level = 0,
    /// each `Run` increments by 1.
    depth: usize,
}

impl T {
    fn new(name: string) -> Self {
        T {
            name,
            state: Arc::new(TState::new()),
            depth: 0,
        }
    }

    /// Test name. Mirrors `t.Name()`.
    pub fn Name(&self) -> string {
        self.name.clone()
    }

    /// `t.Logf(msg)` — print a log message tagged with the test
    /// name. Mirrors `t.Log` / `t.Logf`. (Goish takes a pre-formatted
    /// string; users build it via `Sprintf!`.)
    pub fn Logf<M: Into<string>>(&self, msg: M){
        let msg: string = msg.into();
        self.write_line(b"   ", &msg);
    }

    /// `t.Log(msg)` — alias for Logf since goish doesn't carry the
    /// printf-vs-print distinction in the API.
    pub fn Log<M: Into<string>>(&self, msg: M){
        let msg: string = msg.into();
        self.Logf(msg);
    }

    /// `t.Errorf(format, args)` — log + mark test as failed. Test
    /// continues. Mirrors Go: `func (c *common) Errorf(format string,
    /// args ...any)` (testing.go) — `args` is the runtime variadic
    /// slice that `fmt.Sprintf` would normally spread. We accept it
    /// directly and route through `fmt::Sprintv` (the runtime spread
    /// helper) for formatting.
    ///
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
        self.state.failed.store(true, Ordering::Release);
        self.write_line(b"err", &msg);
    }

    /// `t.Error(msg)` — alias for Errorf with no format args.
    pub fn Error<M: Into<string>>(&self, msg: M){
        let msg: string = msg.into();
        self.Errorf(msg, crate::goslice::slice::new());
    }

    /// `t.Fail()` — mark failed without logging.
    pub fn Fail(&self) {
        self.state.failed.store(true, Ordering::Release);
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

    /// `t.Fatalf(format, args)` — log + mark test as failed, then
    /// abort the current test. Mirrors Go: `func (c *common) Fatalf(
    /// format string, args ...any)` (testing.go) — `args` is the
    /// runtime variadic slice that `fmt.Sprintf` would normally
    /// spread. Same call-shape contract as `Errorf`:
    ///   - `t.Fatalf("simple msg", goish::slice::new())` — no args
    ///   - `t.Fatalf("got %v want %v", goish::slice!([]Any{a, b}))`
    pub fn Fatalf<M: Into<string>>(
        &self,
        format: M,
        args: crate::goslice::slice<crate::goany::Any>,
    ) -> ! {
        let format: string = format.into();
        self.Errorf(format, args);
        self.FailNow();
    }

    /// `t.Fatal(msg)` — alias for Fatalf with no format args.
    pub fn Fatal<M: Into<string>>(&self, msg: M) -> ! {
        let msg: string = msg.into();
        self.Fatalf(msg, crate::goslice::slice::new());
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

    /// `t.Skipf(msg)` — alias for Skip.
    pub fn Skipf<M: Into<string>>(&self, msg: M) -> ! {
        let msg: string = msg.into();
        self.Skip(msg);
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

    /// `t.Failed()` — has Errorf/Fatalf/Fail been called?
    pub fn Failed(&self) -> bool {
        self.state.failed.load(Ordering::Acquire)
    }

    /// `t.Skipped()` — has Skip*/SkipNow been called?
    pub fn Skipped(&self) -> bool {
        self.state.skipped.load(Ordering::Acquire)
    }

    /// `t.Helper()` — no-op in v1. Go uses this to skip helper
    /// functions in failure stack traces; goish doesn't track
    /// file:line in messages yet.
    pub fn Helper(&self) {}

    /// `t.Cleanup(f)` — register a function to run when the test
    /// completes. Called in LIFO order. Mirrors `t.Cleanup`.
    pub fn Cleanup<F: FnOnce() + Send + 'static>(&self, f: F) {
        self.state.cleanups.Lock().push(Box::new(f));
    }

    /// `t.TempDir()` (testing/testing.go:1241) — return a unique
    /// directory for use during this test, automatically removed
    /// when the test (or its subtest) finishes. On failure to create
    /// the directory, calls Fatalf.
    ///
    /// The directory name is `<os.TempDir()>/<sanitised name><N>`
    /// where N is a process-local sequence number and path
    /// separators in the test name are replaced with '_'.
    pub fn TempDir(&mut self) -> string {
        static SEQ: core::sync::atomic::AtomicU64 =
            core::sync::atomic::AtomicU64::new(0);

        let base = crate::os::TempDir();

        let name_bytes_owned = self.name.clone();
        let nb = name_bytes_owned.__as_bytes_internal();
        let mut path: Vec<u8> = Vec::new();
        let base_bytes = base.__as_bytes_internal();
        path.extend_from_slice(base_bytes);
        if !path.ends_with(b"/") {
            path.push(b'/');
        }
        for &c in nb {
            if c == b'/' || c == 0 {
                path.push(b'_');
            } else {
                path.push(c);
            }
        }

        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut tmp = [0u8; 20];
        let mut idx = tmp.len();
        let mut m = n;
        if m == 0 {
            idx -= 1;
            tmp[idx] = b'0';
        } else {
            while m > 0 {
                idx -= 1;
                tmp[idx] = b'0' + (m % 10) as u8;
                m /= 10;
            }
        }
        path.extend_from_slice(&tmp[idx..]);

        let dir = string::from_bytes(&path);
        let err = crate::os::Mkdir(dir.clone(), 0o700);
        if !err.IsNil() {
            self.Fatalf(
                string::from_static(
                    "testing.T.TempDir: failed to create temp directory",
                ),
                crate::goslice::slice::new(),
            );
        }

        let cleanup_path = dir.clone();
        self.Cleanup(move || {
            let _ = crate::os::RemoveAll(cleanup_path);
        });

        dir
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
        write_status(b"=== RUN  ", &header_indent, &qualified);

        let state = sub.state.clone();
        tRunner(sub, f);

        let passed = !state.failed.load(Ordering::Acquire);
        if state.skipped.load(Ordering::Acquire) {
            write_status(b"--- SKIP: ", &header_indent, &qualified);
        } else if passed {
            write_status(b"--- PASS: ", &header_indent, &qualified);
        } else {
            write_status(b"--- FAIL: ", &header_indent, &qualified);
            // Go: a failing subtest fails its parent.
            self.state.failed.store(true, Ordering::Release);
        }
        return passed;
    }

    fn drain_cleanups(&self) {
        // Drain in LIFO order (Go semantics).
        let mut funcs: Vec<Box<dyn FnOnce() + Send + 'static>> = {
            let mut g = self.state.cleanups.Lock();
            core::mem::take(&mut *g)
        };
        while let Some(f) = funcs.pop() {
            f();
        }
    }

    fn write_line(&self, tag: &[u8], msg: &string) {
        let indent = indent_for(self.depth + 1);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&indent);
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

fn indent_for(depth: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(depth * 4);
    for _ in 0..depth {
        v.extend_from_slice(b"    ");
    }
    v
}

fn write_status(tag: &[u8], indent: &[u8], name: &string) {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(indent);
    buf.extend_from_slice(tag);
    buf.extend_from_slice(name.clone().__as_bytes_internal());
    buf.push(b'\n');
    syscall::Write(syscall::STDOUT, buf.as_ptr(), buf.len());
}

// ─── Runner ──────────────────────────────────────────────────────

/// Test entry. Each test function takes a `&mut T` and may call
/// any of the assertion / logging methods.
pub type TestFn = fn(&mut T);

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
fn tRunner<F: FnOnce(&mut T) + Send + 'static>(t: T, fn_: F) {
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

/// `testing.Main(tests)` — run the given list of (name, fn) pairs
/// in registration order, print PASS/FAIL/SKIP per test, and
/// return an exit code (0 if all passed, 1 if any failed).
///
/// Mirrors the role of Go's `go test` driver. Goish doesn't
/// auto-discover `Test*` functions (no compile-time reflection of
/// modules); the user is expected to assemble the slice in the
/// `#[goish::main]` body.
pub fn Main(tests: &[(&'static str, TestFn)]) -> int {
    let mut total = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for (name, f) in tests {
        let t = T::new(string::from_static(name));
        let name_s = t.name.clone();
        write_status(b"=== RUN  ", b"", &name_s);
        let state = t.state.clone();
        tRunner(t, *f);
        if state.skipped.load(Ordering::Acquire) {
            write_status(b"--- SKIP: ", b"", &name_s);
            skipped += 1;
        } else if state.failed.load(Ordering::Acquire) {
            write_status(b"--- FAIL: ", b"", &name_s);
            failed += 1;
        } else {
            write_status(b"--- PASS: ", b"", &name_s);
        }
        total += 1;
    }

    let passed = total - failed - skipped;
    let summary_bytes: Vec<u8> = build_summary(total, passed, failed, skipped);
    syscall::Write(
        syscall::STDOUT,
        summary_bytes.as_ptr(),
        summary_bytes.len(),
    );

    if failed > 0 {
        1
    } else {
        0
    }
}

fn build_summary(total: int, passed: int, failed: int, skipped: int) -> Vec<u8> {
    let mut s: Vec<u8> = Vec::new();
    s.extend_from_slice(b"\n");
    if failed > 0 {
        s.extend_from_slice(b"FAIL\t");
    } else {
        s.extend_from_slice(b"ok\t");
    }
    write_int(&mut s, total);
    s.extend_from_slice(b" tests, ");
    write_int(&mut s, passed);
    s.extend_from_slice(b" passed, ");
    write_int(&mut s, failed);
    s.extend_from_slice(b" failed, ");
    write_int(&mut s, skipped);
    s.extend_from_slice(b" skipped\n");
    s
}

fn write_int(buf: &mut Vec<u8>, mut n: int) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let neg = n < 0;
    if neg {
        n = -n;
    }
    let mut tmp = [0u8; 20];
    let mut idx = tmp.len();
    while n > 0 {
        idx -= 1;
        tmp[idx] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    if neg {
        idx -= 1;
        tmp[idx] = b'-';
    }
    buf.extend_from_slice(&tmp[idx..]);
}

// `string::as_bytes()` is `pub(crate)` and the `testing` module is
// inside the goish crate, so we can call it directly without an
// extra extension trait. The `__as_bytes_internal` calls above
// resolve to crate-internal byte access.

trait StringBytesAccess {
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
