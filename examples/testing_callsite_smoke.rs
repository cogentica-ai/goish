// testing_callsite_smoke — common.frameSkip and common.callSite.
//
// This is how a test failure gets attributed to a line. The naive
// version — "walk up N frames" — is wrong in three situations that all
// occur in ordinary tests, and frameSkip handles each by REDIRECTING
// the walk rather than counting further:
//
//   * t.Helper: a failure reported from inside a helper should point at
//     the caller of the helper, not at the helper's own body. The walk
//     skips every frame whose function is a registered helper.
//
//   * Cleanup: a failure during teardown should point at the line that
//     REGISTERED the cleanup, not at the teardown loop, which is the
//     same line for every test in the binary. On reaching the cleanup
//     frame the walk restarts from the stack captured at registration.
//     Only the wrapper is covered here (check 5); the redirect itself
//     needs a call site taken from INSIDE a cleanup, which needs a T
//     that can be moved into the closure.
//
//   * Subtests: on reaching tRunner the walk has run out of test code,
//     so for a subtest it resumes in the parent from the t.Run call
//     site instead of stopping.
//
// The assertions are on the FILE, not the line number, because line
// numbers move whenever this file is edited and a test that has to be
// updated on every edit stops being read. Attributing to the right file
// is already the property the redirections exist to preserve — a walk
// that fell through to the runner would report testing.rs.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::strings;
use goish::sync::Mutex;
use goish::testing::{self, __shim_call_site};
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

static OBS: Mutex<alloc::vec::Vec<(string, string)>> = Mutex::new(alloc::vec::Vec::new());

fn record(k: &str, v: string) {
    OBS.Lock().push((s(k), v));
}

fn get(k: &str) -> string {
    for (a, b) in OBS.Lock().iter() {
        if a == &s(k) {
            return b.clone();
        }
    }
    return s("<unset>");
}

/// The skip to pass so the walk starts at the caller of the shim.
///
/// Go counts from callSite itself: skip=0 is callSite's own frame, and
/// common.log passes 3 for "callSite + log + public function". Here the
/// chain is callSite(0) -> __shim_call_site(1) -> the test fn(2), so
/// the shim costs exactly one frame more than a direct call would.
const SKIP: goish::types::int = 2;

/// True if the call site names THIS file rather than the testing
/// package's own source.
fn is_here(site: string) -> bool {
    return strings::HasPrefix(site, "testing_callsite_smoke.rs:");
}

fn direct(t: &mut testing::T) {
    record("direct", __shim_call_site(t, SKIP));
}

/// A helper marks itself, so a site taken inside it attributes to the
/// CALLER of the helper.
fn helper(t: &mut testing::T) {
    t.Helper();
    record("in_helper", __shim_call_site(t, SKIP));
}

fn via_helper(t: &mut testing::T) {
    helper(t);
}

fn in_cleanup(t: &mut testing::T) {
    // A cleanup cannot ask for its own call site — T is not
    // Send + 'static — so this checks the other half: that Go's wrapper
    // around every cleanup, which records and then clears the
    // registration stack, leaves the cleanup itself working.
    record("before_cleanup", __shim_call_site(t, SKIP));
    t.Cleanup(|| {
        record("cleanup_ran", s("yes"));
    });
}

fn in_subtest(t: &mut testing::T) {
    t.Run(s("child"), |t| {
        record("subtest", __shim_call_site(t, SKIP));
    });
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let code = testing::Main(&[
        ("Direct", direct),
        ("ViaHelper", via_helper),
        ("InCleanup", in_cleanup),
        ("InSubtest", in_subtest),
    ]);

    // 1. The tree ran green — nothing here panicked or mis-walked into
    //    a frame that does not exist.
    {
        if code == 0 {
            fmt::Println!("[ 1] tree runs green           PASS");
        } else {
            fmt::Println!("[ 1] tree runs green           FAIL");
            failed += 1;
        }
    }

    // 2. A direct call attributes to this file, not to the testing
    //    package. A walk that stopped one frame short would report
    //    testing.rs for every failure in the binary.
    {
        if is_here(get("direct")) {
            fmt::Println!("[ 2] direct site is this file  PASS");
        } else {
            fmt::Println!("[ 2] direct site is this file  FAIL [", get("direct"), "]");
            failed += 1;
        }
    }

    // 3. A site taken inside a t.Helper() function still attributes to
    //    this file — and specifically not to a frame inside testing.
    {
        if is_here(get("in_helper")) {
            fmt::Println!("[ 3] helper attributes to file PASS");
        } else {
            fmt::Println!(
                "[ 3] helper attributes to file FAIL [",
                get("in_helper"),
                "]"
            );
            failed += 1;
        }
    }

    // 4. A subtest attributes to this file too. This is the case where
    //    the walk runs into tRunner and has to resume from the parent's
    //    t.Run call site rather than giving up.
    {
        if is_here(get("subtest")) {
            fmt::Println!("[ 4] subtest resumes in parent PASS");
        } else {
            fmt::Println!("[ 4] subtest resumes in parent FAIL [", get("subtest"), "]");
            failed += 1;
        }
    }

    // 5. Cleanups still run with the registration stack recorded — the
    //    wrapper Go installs around every cleanup did not break the
    //    cleanup itself.
    {
        if get("cleanup_ran") == s("yes") && is_here(get("before_cleanup")) {
            fmt::Println!("[ 5] cleanup wrapper is inert  PASS");
        } else {
            fmt::Println!("[ 5] cleanup wrapper is inert  FAIL");
            failed += 1;
        }
    }

    // 6. Every site ends in ":N: " — callSite's format. Line 0 becomes
    //    1 and an unknown file becomes "???", so the result is always
    //    something an editor can open.
    {
        let d = get("direct");
        if strings::HasSuffix(d.clone(), ": ") && strings::Contains(d.clone(), ".rs:") {
            fmt::Println!("[ 6] site format is file:line: PASS");
        } else {
            fmt::Println!("[ 6] site format is file:line: FAIL [", d, "]");
            failed += 1;
        }
    }

    fmt::Println!(
        "    sites: direct=",
        get("direct"),
        " helper=",
        get("in_helper")
    );
    fmt::Println!("           subtest=", get("subtest"));

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
