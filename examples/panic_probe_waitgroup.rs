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
// WHY THE SLEEP. `Done()` is deferred, so it runs while the panic is
// still unwinding — BEFORE the runtime decides the panic is fatal.
// `Wait()` can therefore return and main can race the dying goroutine
// to the exit. That race is Go's too, not goish's: the equivalent Go
// program (sync.WaitGroup.Go + panic + os.Exit(0) straight after Wait)
// exits 0 in 29 runs out of 200 on this machine. So "Wait returned"
// is a coin flip in Go as well — 53 of 100 — and asserting either way
// pins a scheduling accident. The sleep gives the fatal exit its
// moment: with it, Go is 100/100 status 2 and never prints the line
// below. That is the contract worth pinning, and it still says
// everything issue #6 asks — Wait did not hang, and the unrecovered
// panic killed the process anyway.
//
// Excluded from e2e; driven by panic_fatal_ref_smoke, which asserts
// this probe's exit status.

#![no_std]
#![no_main]

extern crate goish;

use goish::sync::WaitGroup;
use goish::time;
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
    let done = b"probe: Wait returned\n";
    syscall::Write(syscall::STDOUT, done.as_ptr(), done.len());
    time::Sleep(500 * time::Millisecond);
    let alive = b"probe: still alive (BUG: panic was not fatal)\n";
    syscall::Write(syscall::STDOUT, alive.as_ptr(), alive.len());
    syscall::Exit(0);
}
