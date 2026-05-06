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
// Subset implemented in v1 (sufficient for porting most tests):
//
//   - T::Name, T::Errorf, T::Logf, T::Fatalf
//   - T::Error, T::Log, T::Fatal (variadic; goish takes one string)
//   - T::Fail, T::FailNow, T::Failed
//   - T::Skip, T::Skipf, T::SkipNow, T::Skipped
//   - T::Run(name, fn) for subtests
//   - T::Cleanup(fn) for deferred cleanup
//   - T::Helper (no-op in v1; affects file:line in failure messages
//     in Go, which we don't track)
//   - testing::Main(tests) — runner returning an exit code
//
// Not in v1: Parallel, TempDir, Context, Output, Attr, Setenv,
// Chdir, B (benchmarks), TestMain integration with -run/-v flags.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod iotest;

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
    /// Cleanup callbacks, run in LIFO order on test return.
    /// Boxed because the closure types differ across calls.
    cleanups: Mutex<Vec<Box<dyn FnOnce() + Send + 'static>>>,
}

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
            state: Arc::new(TState {
                failed: AtomicBool::new(false),
                skipped: AtomicBool::new(false),
                cleanups: Mutex::new(Vec::new()),
            }),
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
        args: crate::goslice::slice<alloc::sync::Arc<dyn core::any::Any + Send + Sync>>,
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

    /// `t.FailNow()` — mark failed and abort the current test.
    /// In Go this is implemented via runtime.Goexit on the test
    /// goroutine; goish v1 aborts the process. Tests that need to
    /// recover should use Skip / Errorf instead.
    pub fn FailNow(&self) -> ! {
        self.state.failed.store(true, Ordering::Release);
        const MSG: &[u8] = b"--- FAIL: testing.T.FailNow\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(1);
    }

    /// `t.Fatalf(msg)` — log error then FailNow.
    pub fn Fatalf<M: Into<string>>(&self, msg: M) -> ! {
        let msg: string = msg.into();
        self.Errorf(msg, crate::goslice::slice::new());
        self.FailNow();
    }

    /// `t.Fatal(msg)` — alias for Fatalf.
    pub fn Fatal<M: Into<string>>(&self, msg: M) -> ! {
        let msg: string = msg.into();
        self.Fatalf(msg);
    }

    /// `t.Skip(msg)` — mark skipped + log + abort current test.
    pub fn Skip<M: Into<string>>(&self, msg: M) -> ! {
        let msg: string = msg.into();
        self.state.skipped.store(true, Ordering::Release);
        self.write_line(b"skp", &msg);
        // Like FailNow, we exit the process for v1 simplicity. A
        // future iteration can use a setjmp-style escape to skip
        // just the current test function.
        syscall::Exit(0);
    }

    /// `t.Skipf(msg)` — alias for Skip.
    pub fn Skipf<M: Into<string>>(&self, msg: M) -> ! {
        let msg: string = msg.into();
        self.Skip(msg);
    }

    /// `t.SkipNow()` — Skip without a message.
    pub fn SkipNow(&self) -> ! {
        self.Skip(string::from_static(""));
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

    /// `t.Run(name, f)` — run f as a sub-test under this test.
    /// Reports its own PASS/FAIL line. Returns true if the sub-
    /// test passed. The parent test does not fail automatically
    /// when a sub-test fails — the caller may want to inspect the
    /// return value.
    pub fn Run<F: FnOnce(&mut T)>(&mut self, name: string, f: F) -> bool {
        // Compose the qualified name "Parent/Child" for logging.
        let mut qualified_bytes: Vec<u8> = Vec::new();
        qualified_bytes.extend_from_slice(self.name.clone().__as_bytes_internal());
        qualified_bytes.push(b'/');
        qualified_bytes.extend_from_slice(name.__as_bytes_internal());
        let qualified = string::from_bytes(&qualified_bytes);

        let mut sub = T {
            name: qualified.clone(),
            state: Arc::new(TState {
                failed: AtomicBool::new(false),
                skipped: AtomicBool::new(false),
                cleanups: Mutex::new(Vec::new()),
            }),
            depth: self.depth + 1,
        };

        let header_indent = indent_for(sub.depth);
        write_status(b"=== RUN  ", &header_indent, &qualified);

        f(&mut sub);
        sub.run_cleanups();

        let passed = !sub.Failed();
        if sub.Skipped() {
            write_status(b"--- SKIP: ", &header_indent, &qualified);
        } else if passed {
            write_status(b"--- PASS: ", &header_indent, &qualified);
        } else {
            write_status(b"--- FAIL: ", &header_indent, &qualified);
            // Propagate failure to parent.
            self.state.failed.store(true, Ordering::Release);
        }
        passed
    }

    fn run_cleanups(&mut self) {
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
        let mut t = T::new(string::from_static(name));
        write_status(b"=== RUN  ", b"", &t.name);
        f(&mut t);
        t.run_cleanups();
        if t.Skipped() {
            write_status(b"--- SKIP: ", b"", &t.name);
            skipped += 1;
        } else if t.Failed() {
            write_status(b"--- FAIL: ", b"", &t.name);
            failed += 1;
        } else {
            write_status(b"--- PASS: ", b"", &t.name);
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
