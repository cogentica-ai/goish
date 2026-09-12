// testing_probe_main — an ORDINARY binary must report
// `testing::Testing() == false` (#24).
//
// The negative half of the pair. `testing_probe_testmain` is the
// positive half, and both are separate PROCESSES on purpose: test
// identity is a property of the binary, so a single process cannot
// establish both answers.
//
// Measured against Go: a `go build` binary reports false both in `main`
// and at package-variable init time.

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
    pub static AT_INIT: AtomicBool = AtomicBool::new(true);

    #[goish::init]
    pub fn init() {
        AT_INIT.store(goish::testing::Testing(), Ordering::Relaxed);
    }
}

goish::import! {
    probe_pkg as _probe_pkg,
}

#[goish::main]
fn main() {
    let mut bad = 0;

    if testing::Testing() {
        fmt::Println!("[!!] Testing() is true in a #[goish::main] binary");
        bad += 1;
    } else {
        fmt::Println!("[ok] Testing() is false in a #[goish::main] binary");
    }

    if probe_pkg::AT_INIT.load(Ordering::Relaxed) {
        fmt::Println!("[!!] Testing() was true during package init");
        bad += 1;
    } else {
        fmt::Println!("[ok] Testing() was false during package init");
    }

    if (testing::testBinary().as_ref() as &str) != "0" {
        fmt::Println!("[!!] testBinary() is not \"0\"");
        bad += 1;
    } else {
        fmt::Println!("[ok] testBinary() is \"0\", as Go's var starts");
    }

    if bad != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", bad as i64);
        goish::os::Exit(1);
    }
    fmt::Println!("\nok 3/3");
}
