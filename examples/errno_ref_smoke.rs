// errno_ref_smoke — what a raw errno says about itself.
//
// Reference: Go 1.25.5 syscall, measured by tools/gen_errno_ref.go.
// Every GO[] line is Go's verbatim output.
//
// Nine of these twenty-five rendered as the bare word "errno" before
// this smoke existed, and they are the nine that matter most: a
// refused connection, a reset peer, a broken pipe, an address already
// in use, an aborted connection, no buffer space, out of memory, a bad
// descriptor. `net` hands those back more often than all the rest
// combined, and every one of them produced the same four characters.
//
// The unknown-errno fallback carries the NUMBER, as Go's does — Go
// renders errno 0 as "errno 0". goish dropped it, so two different
// unrecognised failures were indistinguishable in a log, which is
// exactly when the number is the only thing left to go on.
//
// Timeout() and Temporary() are pinned alongside the text because they
// are what a caller BRANCHES on, and the classification is not
// guessable from the name: EINTR is temporary but not a timeout,
// ETIMEDOUT is both, ECONNREFUSED is neither. EAGAIN answering
// timeout=true is the one that makes a deadline-fired read read as a
// timeout to every caller that asks the net.Error question.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::syscall;

// Go's verbatim output.
const GO: [&str; 25] = [
    "errno 0    \"errno 0\"                          timeout=false temporary=false",
    "errno 1    \"operation not permitted\"          timeout=false temporary=false",
    "errno 2    \"no such file or directory\"        timeout=false temporary=false",
    "errno 4    \"interrupted system call\"          timeout=false temporary=true",
    "errno 9    \"bad file descriptor\"              timeout=false temporary=false",
    "errno 11   \"resource temporarily unavailable\" timeout=true  temporary=true",
    "errno 12   \"cannot allocate memory\"           timeout=false temporary=false",
    "errno 13   \"permission denied\"                timeout=false temporary=false",
    "errno 17   \"file exists\"                      timeout=false temporary=false",
    "errno 20   \"not a directory\"                  timeout=false temporary=false",
    "errno 21   \"is a directory\"                   timeout=false temporary=false",
    "errno 22   \"invalid argument\"                 timeout=false temporary=false",
    "errno 23   \"too many open files in system\"    timeout=false temporary=true",
    "errno 24   \"too many open files\"              timeout=false temporary=true",
    "errno 32   \"broken pipe\"                      timeout=false temporary=false",
    "errno 38   \"function not implemented\"         timeout=false temporary=false",
    "errno 39   \"directory not empty\"              timeout=false temporary=false",
    "errno 95   \"operation not supported\"          timeout=false temporary=false",
    "errno 98   \"address already in use\"           timeout=false temporary=false",
    "errno 99   \"cannot assign requested address\"  timeout=false temporary=false",
    "errno 103  \"software caused connection abort\" timeout=false temporary=false",
    "errno 104  \"connection reset by peer\"         timeout=false temporary=false",
    "errno 105  \"no buffer space available\"        timeout=false temporary=false",
    "errno 110  \"connection timed out\"             timeout=true  temporary=true",
    "errno 111  \"connection refused\"               timeout=false temporary=false",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            goish::string(GO[i])
        );
    }
}

#[goish::main]
fn main() {
    let ns: [i32; 25] = [
        0, 1, 2, 4, 9, 11, 12, 13, 17, 20, 21, 22, 23, 24, 32, 38, 39, 95, 98, 99, 103, 104, 105,
        110, 111,
    ];
    for n in ns.iter() {
        let e = syscall::Errno(*n as _);
        chk(fmt::Sprintf!(
            "errno %-4d %-34q timeout=%-5v temporary=%v",
            *n as i64,
            e.Error(),
            e.Timeout(),
            e.Temporary()
        ));
    }

    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
