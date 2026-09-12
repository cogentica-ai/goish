// testing_probe_testmain — a TEST binary must report
// `testing::Testing() == true`, including during package init (#24).
//
// `#[goish::test_main]` is goish's stand-in for what cmd/go does at link
// time with `-X testing.testBinary=1`.
//
// The package-init row is the one that matters and the reason this is a
// macro rather than a setter. Measured against Go: in a `go test` binary
// `testing.Testing()` is true at package-VARIABLE init time, before any
// test runs. `#[goish::main]` calls `::goish::init()` and
// `::goish::__run_pkg_inits()` before the user's body, so a setter
// called at the top of that body would already be too late — every
// `#[goish::init]` would have run and seen false.
//
// The downstream case is typescript-go's `bundled.TestingLibPath`, which
// must reject production calls and return the source `libs` directory in
// tests. Without this the port had to either weaken the production guard
// or invent a package-local test-mode shim.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::Ordering;
use goish::{fmt, testing};

/// A package with an `init`, registered through `goish::import!` below —
/// which is how a port's init actually reaches `.init_array` and gets
/// run by `__run_pkg_inits()`.
///
/// A bare `#[goish::init]` in an example is NEVER CALLED: the attribute
/// only wraps the body in `PkgInit::run_once`, and something has to
/// invoke it. The first version of this probe had one at file scope, and
/// the package-init row failed — correctly, because AT_INIT keeps the
/// WRONG answer as its default precisely so "the init never ran" cannot
/// read as a pass.
mod probe_pkg {
    use core::sync::atomic::{AtomicBool, Ordering};

    /// Seeded with the answer the row does NOT want, so a silent
    /// no-run fails.
    pub static AT_INIT: AtomicBool = AtomicBool::new(false);

    #[goish::init]
    pub fn init() {
        AT_INIT.store(goish::testing::Testing(), Ordering::Relaxed);
    }
}

goish::import! {
    probe_pkg as _probe_pkg,
}

#[goish::test_main]
fn main() {
    let mut bad = 0;

    if !testing::Testing() {
        fmt::Println!("[!!] Testing() is false in a #[goish::test_main] binary");
        bad += 1;
    } else {
        fmt::Println!("[ok] Testing() is true in a #[goish::test_main] binary");
    }

    if !probe_pkg::AT_INIT.load(Ordering::Relaxed) {
        fmt::Println!("[!!] Testing() was false during package init — the mark is set too late");
        bad += 1;
    } else {
        fmt::Println!("[ok] Testing() was already true during package init");
    }

    if (testing::testBinary().as_ref() as &str) != "1" {
        fmt::Println!("[!!] testBinary() is not \"1\"");
        bad += 1;
    } else {
        fmt::Println!("[ok] testBinary() is \"1\", as cmd/go's -X sets it");
    }

    // The downstream shape: a guard that must reject in production and
    // allow in a test.
    let allowed = testing::Testing();
    if !allowed {
        fmt::Println!("[!!] a TestingLibPath-shaped guard would reject in a test binary");
        bad += 1;
    } else {
        fmt::Println!("[ok] a TestingLibPath-shaped guard admits a test binary");
    }

    if bad != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", bad as i64);
        goish::os::Exit(1);
    }
    fmt::Println!("\nok 4/4");
}
