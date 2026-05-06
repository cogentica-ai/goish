// segv_diagnostic_smoke — overflow a goroutine's stack on purpose
// and confirm the SIGSEGV handler prints an actionable diagnostic
// before the process exits with code 2.
//
// The handler should identify:
//   - the spawn site of the goroutine that overflowed (file:line of
//     the `go!()` invocation below)
//   - the home-stack bounds and fault address
//   - a hint pointing at `stack(N)` / `maybe_grow_step`
//
// Without the handler, this program would die with a silent
// "Segmentation fault" — no information about which goroutine, no
// spawn site, no actionable suggestion.
//
// Manual run only — this example is excluded from the e2e suite (it
// crashes by design). Run with:
//
//     cargo run --example segv_diagnostic_smoke
//
// Expected exit code: 2. Expected stderr: "goish: stack overflow"
// followed by spawn-site, region, and suggestion lines.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::runtime::sched;
use goish::{go, syscall, KB};

#[inline(never)]
fn overflow(n: i64) -> i64 {
    // Big stack frame so we exhaust the 2 KiB home stack quickly
    // without auto-grow (`stack(2 * KB)` opts out of grow).
    let scratch: [u8; 1024] = [0; 1024];
    // Read after recursion to keep the array live.
    overflow(n + 1).wrapping_add(scratch[(n as usize) & 1023] as i64)
}

#[goish::main]
fn main() {
    syscall::Write(
        syscall::STDOUT,
        b"segv_diagnostic_smoke: about to overflow on purpose\n".as_ptr(),
        52,
    );

    // Bounded 2 KiB stack, no auto-grow — `overflow` will exhaust
    // it within a handful of recursive calls. The SIGSEGV handler
    // should fire and exit(2) before the process aborts silently.
    go!(stack(2 * KB), || {
        let _ = overflow(0);
    });

    sched::schedule();
}
