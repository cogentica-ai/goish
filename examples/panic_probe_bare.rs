// panic_probe_bare — a probe for issue #6, not a test.
//
// The simplest shape: an unhandled panic in a plain spawned goroutine,
// with no WaitGroup involved. Go ends the program with a nonzero
// status; goish used to print "recovered ... scheduler continuing" and
// run on, so a program could sail past a panic it never handled and
// exit 0 with partial results.
//
// Expected: exit 2, and "probe: still alive" must NOT appear.
//
// Excluded from e2e; driven by panic_fatal_ref_smoke.

#![no_std]
#![no_main]

extern crate goish;

use goish::runtime::sched;
use goish::{go, syscall, KB};

#[goish::main]
fn main() {
    go!(stack(32 * KB), || {
        panic!("unhandled panic in a bare goroutine");
    });
    // Give the panicking G time to run and take the process down.
    for _ in 0..2_000_000 {
        sched::Gosched();
    }
    let m = b"probe: still alive (BUG: should not reach here)\n";
    syscall::Write(syscall::STDOUT, m.as_ptr(), m.len());
    syscall::Exit(0);
}
