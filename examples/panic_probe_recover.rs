// panic_probe_recover — a probe for issue #6, not a test.
//
// A deferred `recover!()` CONSUMES the panic value, so the scheduler
// is entitled to continue: this is the one case where "goroutine
// recovered from panic, scheduler continuing" is a true statement.
//
// It also covers the half the fatal-exit change does not reach. The
// recovered goroutine still cannot resume its abandoned Rust stack
// (goish's documented limitation), so `WaitGroup.Go`'s Done() would
// still be owed by a frame that will never run again — which is why
// Go writes it as `defer wg.Done()` and goish now does too. If that
// regressed, `Wait()` below would block and this probe would hang
// rather than fail.
//
// Expected: exit 0, having printed the recovery line and reached the
// end of Wait().
//
// Excluded from e2e; driven by panic_fatal_ref_smoke.

#![no_std]
#![no_main]

extern crate goish;

use goish::sync::WaitGroup;
use goish::{defer, recover, syscall, KB};

#[goish::main]
fn main() {
    {
        let wg = WaitGroup::new();
        wg.GoStack(32 * KB, || {
            defer! {
                let e = recover!();
                if e != goish::errors::nil {
                    let m = b"probe: recovered\n";
                    syscall::Write(syscall::STDOUT, m.as_ptr(), m.len());
                }
            }
            panic!("recovered panic");
        });
        wg.Wait();
    }
    let m = b"probe: Wait returned\n";
    syscall::Write(syscall::STDOUT, m.as_ptr(), m.len());
    syscall::Exit(0);
}
