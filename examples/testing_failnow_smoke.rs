// testing_failnow_smoke — the behaviour goish's testing package did
// not have until runtime::Goexit landed.
//
// Before: t.Skip() called syscall::Exit(0) and t.FailNow() called
// syscall::Exit(1), so either one ended the whole process. A skipped
// test silently cancelled every test after it, and the run still
// reported success. That made Skip unusable anywhere except the last
// test in the slice.
//
// After: each test body runs on its own goroutine (tRunner), so
// FailNow/Skip end exactly one test. This example asserts that the
// tests *after* a skipping test and a failing test still run, that
// their outcomes are recorded correctly, and that cleanups registered
// before the exit still fire.
//
// The whole file is one assertion: if the hard-exit behaviour ever
// comes back, the counters below never reach their expected values and
// the summary line never prints.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::gostring::string;
use goish::testing;
use goish::{fmt, syscall};

static RAN: AtomicUsize = AtomicUsize::new(0);
static AFTER_SKIP: AtomicUsize = AtomicUsize::new(0);
static PAST_SKIP: AtomicUsize = AtomicUsize::new(0);
static PAST_FATAL: AtomicUsize = AtomicUsize::new(0);
static CLEANUP_RAN: AtomicUsize = AtomicUsize::new(0);

/// Skips partway through. Nothing after the Skip may run.
fn TestSkipsMidway(t: &mut testing::T) {
    RAN.fetch_add(1, Ordering::SeqCst);
    t.Cleanup(|| {
        CLEANUP_RAN.fetch_add(1, Ordering::SeqCst);
    });
    t.Skip(string::from_static("skipping on purpose"));
    #[allow(unreachable_code)]
    {
        PAST_SKIP.fetch_add(1, Ordering::SeqCst);
    }
}

/// Runs after the skip. Reaching this at all is the point.
fn TestRunsAfterSkip(t: &mut testing::T) {
    RAN.fetch_add(1, Ordering::SeqCst);
    AFTER_SKIP.fetch_add(1, Ordering::SeqCst);
    let _ = t.Name();
}

/// Fails hard. Nothing after the Fatal may run, and the failure must
/// be recorded rather than swallowed.
fn TestFatalMidway(t: &mut testing::T) {
    RAN.fetch_add(1, Ordering::SeqCst);
    t.Cleanup(|| {
        CLEANUP_RAN.fetch_add(1, Ordering::SeqCst);
    });
    t.Fatal(string::from_static("failing on purpose"));
    #[allow(unreachable_code)]
    {
        PAST_FATAL.fetch_add(1, Ordering::SeqCst);
    }
}

/// Runs after the hard failure.
fn TestRunsAfterFatal(t: &mut testing::T) {
    RAN.fetch_add(1, Ordering::SeqCst);
    let _ = t.Name();
}

/// A subtest that Fatals must end the subtest, not the parent: the
/// parent has to get far enough to run its second subtest.
fn TestFatalInSubtestSpares(t: &mut testing::T) {
    RAN.fetch_add(1, Ordering::SeqCst);
    t.Run(string::from_static("fatal"), |t| {
        t.Fatal(string::from_static("subtest fails hard"));
    });
    t.Run(string::from_static("still-runs"), |t| {
        SUBTEST_AFTER.fetch_add(1, Ordering::SeqCst);
        let _ = t.Name();
    });
}

static SUBTEST_AFTER: AtomicUsize = AtomicUsize::new(0);

#[goish::main]
fn main() {
    // These deliberately fail and skip, so the exit code from Main is
    // 1 by design. This example asserts on the counters instead.
    let tests: &[(&str, testing::TestFn)] = &[
        ("TestSkipsMidway", TestSkipsMidway),
        ("TestRunsAfterSkip", TestRunsAfterSkip),
        ("TestFatalMidway", TestFatalMidway),
        ("TestRunsAfterFatal", TestRunsAfterFatal),
        ("TestFatalInSubtestSpares", TestFatalInSubtestSpares),
    ];
    let code = testing::Main(tests);

    fmt::Println!("");
    let mut failed = 0;

    // 1. Every one of the five tests started. Under the old behaviour
    //    the process died inside the first one.
    if RAN.load(Ordering::SeqCst) == 5 {
        fmt::Println!("[ 1] all 5 tests ran            PASS");
    } else {
        fmt::Println!("[ 1] all 5 tests ran            FAIL");
        failed += 1;
    }

    // 2. Neither Skip nor Fatal returned to its caller.
    if PAST_SKIP.load(Ordering::SeqCst) == 0 && PAST_FATAL.load(Ordering::SeqCst) == 0 {
        fmt::Println!("[ 2] Skip/Fatal did not return  PASS");
    } else {
        fmt::Println!("[ 2] Skip/Fatal did not return  FAIL");
        failed += 1;
    }

    // 3. The test registered after the skipping one ran.
    if AFTER_SKIP.load(Ordering::SeqCst) == 1 {
        fmt::Println!("[ 3] test after Skip ran        PASS");
    } else {
        fmt::Println!("[ 3] test after Skip ran        FAIL");
        failed += 1;
    }

    // 4. Cleanups registered before the exit still ran — once for the
    //    skipping test, once for the fataling one.
    if CLEANUP_RAN.load(Ordering::SeqCst) == 2 {
        fmt::Println!("[ 4] cleanups ran on both exits PASS");
    } else {
        fmt::Println!("[ 4] cleanups ran on both exits FAIL");
        failed += 1;
    }

    // 5. A Fatal in a subtest spares its parent's later subtests.
    if SUBTEST_AFTER.load(Ordering::SeqCst) == 1 {
        fmt::Println!("[ 5] subtest Fatal spares peer  PASS");
    } else {
        fmt::Println!("[ 5] subtest Fatal spares peer  FAIL");
        failed += 1;
    }

    // 6. The run is still reported as failed — isolating a failure must
    //    not hide it.
    if code == 1 {
        fmt::Println!("[ 6] failures still reported    PASS");
    } else {
        fmt::Println!("[ 6] failures still reported    FAIL");
        failed += 1;
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
