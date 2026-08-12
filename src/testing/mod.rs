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
pub mod iotest;
pub mod r#match;
mod allocs;
mod newcover;
mod testing;
use testing::tRunner;
pub use allocs::AllocsPerRun;
pub use newcover::Coverage;
pub use testing::{
    chattyFlag, fmtDuration, marker, parseCpuList, prefix, testBinary, CoverMode, Init, Short,
    Testing, Verbose, __run_skip_patterns,
};

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
    fn new(name: string) -> Self {
        T {
            name,
            state: Arc::new(TState::new()),
            depth: 0,
        }
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


    pub(crate) fn drain_cleanups(&self) {
        // Drain in LIFO order (Go semantics).
        let mut funcs: Vec<Box<dyn FnOnce() + Send + 'static>> = {
            let mut g = self.state.cleanups.Lock();
            core::mem::take(&mut *g)
        };
        while let Some(f) = funcs.pop() {
            f();
        }
    }

    pub(crate) fn write_line(&self, tag: &[u8], msg: &string) {
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

pub(crate) fn write_status(tag: &[u8], indent: &[u8], name: &string) {
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
