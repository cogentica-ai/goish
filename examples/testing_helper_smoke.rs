// testing_helper_smoke — t.Helper's PC bookkeeping.
//
// Helper was a no-op until runtime.CallersFrames landed. It now records
// the calling function's PC, exactly as Go does, so that a future
// callSite can skip helper frames when attributing a failure to a
// file:line.
//
// The bookkeeping is worth pinning now rather than when callSite
// arrives, because the subtle part is the *identity* of what gets
// recorded: one entry per calling function, not per call. A Helper that
// recorded a fresh PC each time would grow without bound and skip
// nothing useful.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::gostring::string;
use goish::testing;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

#[inline(never)]
fn helper_a(t: &testing::T) {
    t.Helper();
}

#[inline(never)]
fn helper_b(t: &testing::T) {
    t.Helper();
}

static RESULT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn TestHelperRecords(t: &mut testing::T) {
    // No helpers marked yet.
    if t.__helper_pcs().Len() != 0 {
        t.Error(s("expected no helper PCs initially"));
        return;
    }

    // One helper, called three times, must record ONE entry: the PC is
    // the call site inside helper_a, which is the same every time.
    helper_a(t);
    helper_a(t);
    helper_a(t);
    let after_one = t.__helper_pcs().Len();

    // A second, distinct helper adds exactly one more.
    helper_b(t);
    let after_two = t.__helper_pcs().Len();

    // Pack both results for main to check.
    RESULT.store(
        ((after_one as usize) << 8) | (after_two as usize),
        core::sync::atomic::Ordering::SeqCst,
    );
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let tests: &[(&str, testing::TestFn)] = &[("TestHelperRecords", TestHelperRecords)];
    let code = testing::Main(tests);
    fmt::Println!("");

    let packed = RESULT.load(core::sync::atomic::Ordering::SeqCst);
    let after_one = (packed >> 8) & 0xff;
    let after_two = packed & 0xff;

    // 1. The test itself passed (no Error calls).
    if code == 0 {
        fmt::Println!("[ 1] test passed               PASS");
    } else {
        fmt::Println!("[ 1] test passed               FAIL");
        failed += 1;
    }

    // 2. Three calls from ONE helper record one entry, not three.
    if after_one == 1 {
        fmt::Println!("[ 2] one entry per function    PASS");
    } else {
        fmt::Println!("[ 2] one entry per function    FAIL got ", after_one as i64);
        failed += 1;
    }

    // 3. A second distinct helper adds exactly one.
    if after_two == 2 {
        fmt::Println!("[ 3] distinct helpers distinct PASS");
    } else {
        fmt::Println!("[ 3] distinct helpers distinct FAIL got ", after_two as i64);
        failed += 1;
    }

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 3");
        syscall::Exit(1);
    }
}
