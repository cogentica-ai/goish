// panic_probe_waitgroup — a probe for issue #6, not a test.
//
// `wg.Go` increments the counter, runs the body, and calls `Done()`
// only after the body RETURNS. An unhandled panic abandons that frame,
// so `Done()` never runs and `Wait()` blocks forever.
//
// Expected AFTER the fix: the process dies with status 2 and a fatal
// diagnostic, exactly as an unrecovered panic ends a Go program.
// Before it: the two "recovered" lines and a permanent hang.
//
// Excluded from e2e; driven by panic_fatal_ref_smoke, which asserts
// this probe's exit status.

#![no_std]
#![no_main]

extern crate goish;

use goish::sync::WaitGroup;
use goish::{syscall, KB};

#[goish::main]
fn main() {
    let msg = b"probe: before Wait\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    {
        let wg = WaitGroup::new();
        wg.GoStack(32 * KB, || {
            panic!("unhandled panic in WaitGroup.Go");
        });
        wg.Wait();
    }
    let done = b"probe: Wait returned (BUG: should not reach here)\n";
    syscall::Write(syscall::STDOUT, done.as_ptr(), done.len());
    syscall::Exit(0);
}
