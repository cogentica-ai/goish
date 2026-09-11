// panic_fatal_ref_smoke — an unrecovered goroutine panic is FATAL.
//
// Issue #6: goish converted an unhandled panic in a user goroutine
// into ordinary goroutine termination and kept the scheduler running.
// Two things were wrong with that. It reported a panic as "recovered"
// when nothing had recovered it, and it continued with the panicked
// frame abandoned mid-flight — every epilogue that frame still owed
// was simply skipped. `sync::WaitGroup::Go` is where that surfaced:
// its `Done()` never ran, `Wait()` blocked forever, and the process
// hung with all scheduler threads parked in futex_wait_queue. A useful
// panic became a deadlock, and SIGTERM would not clear it.
//
// This drives four probe binaries as SUBPROCESSES, because what is
// being asserted is the exit status of a process — something no
// in-process check can see. Each probe is excluded from the e2e set
// (two of them exit non-zero by design) and exists only to be run
// from here.
//
// The four cases are the ones the issue asks for:
//
//   bare       an unhandled panic in a plain goroutine exits 2
//   waitgroup  an unhandled panic inside WaitGroup.Go exits 2 PROMPTLY
//              rather than hanging — the reported failure. This one
//              asserted more than Go guarantees at first and flaked in
//              CI for it: `Done()` is DEFERRED, so it runs while the
//              panic is still unwinding, and `Wait()` can return
//              before the dying goroutine reaches the exit. Measured
//              on real Go: exit 0 in 29 of 200 runs when main exits
//              immediately after Wait, and "Wait returned" printed in
//              53 of 100 when it does not. The probe now sleeps after
//              Wait, which makes Go 100/100 status 2, and the
//              assertion is that the process did not survive — not
//              which of the two goroutines got there first.
//   recover    a deferred `recover!()` consumes the panic, and the
//              scheduler continues, which is the one case where
//              "recovered ... continuing" is a true statement
//   goexit     runtime::Goexit stays non-fatal and is not counted as a
//              panic. It lands on the SAME recovery gobuf as the panic
//              handler and is told apart only by the `goexiting` flag,
//              so making panics fatal could easily have taken Goexit
//              with it.
//
// The `recover` case also covers the half the fatal-exit change does
// not reach. A recovered goroutine still cannot resume its abandoned
// Rust stack, so `WaitGroup.Go`'s Done() is owed by a frame that will
// never run again. Go writes that as `defer wg.Done()`
// (sync/waitgroup.go:238) and goish called it after `f()` — a plain
// call. It is a `defer!` now, so the counter is settled on both paths.
// Reverted, this probe hangs instead of failing.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::os;
use goish::os::exec;
use goish::types::int;
use goish::{fmt, strings};

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

const GO: [&str; 8] = [
    "bare:rc          2",
    "bare:continued   false",
    "waitgroup:rc     2",
    "waitgroup:still_alive false",
    "recover:rc       0",
    "recover:wait_returned true",
    "goexit:rc        0",
    "goexit:panics    0",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    *ln += 1;
}

/// The probes sit beside this binary, whatever the profile or target
/// directory, so derive their paths from argv[0] rather than guessing.
fn probe_path(name: &str) -> string {
    let args = os::Args();
    let me = args[0].clone();
    let s: &str = me.as_ref();
    let cut = match s.rfind('/') {
        Some(i) => i + 1,
        None => 0,
    };
    return string::from(&s[..cut]) + string::from(name);
}

/// Run a probe and return (exit code, combined output).
///
/// A missing probe binary must not read as a wrong exit status. With
/// no ProcessState the run never happened at all — the binary is not
/// beside this one — and that is a broken test rather than a failed
/// assertion, so say which. It costs nothing and it is exactly the
/// confusion that cost time here: a partial `cargo build` left the
/// probes unbuilt and the driver reported `goexit:rc -1`, which reads
/// like Goexit going wrong.
fn run_probe(name: &str) -> (int, string) {
    let path = probe_path(name);
    let mut cmd = exec::Command(path.clone(), goish::make!([]string, 0));
    let (out, err) = cmd.CombinedOutput();
    let code = match &cmd.ProcessState {
        Some(st) => st.ExitCode(),
        None => {
            fmt::Printf!(
                "[!!] probe did not run: %s (%v)\n     build it with: cargo build --example %s\n",
                path,
                err,
                string::from(name)
            );
            FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            int::from(-1)
        }
    };
    return (code, string::from_bytes(out.as_ref()));
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let (rc, out) = run_probe("panic_probe_bare");
    chk(&mut ln, &fmt::Sprintf!("%-16s %d", string::from_static("bare:rc"), rc));
    chk(&mut ln, &fmt::Sprintf!("%-16s %v", string::from_static("bare:continued"),
        strings::Contains(&out, "still alive")));

    let (rc, out) = run_probe("panic_probe_waitgroup");
    chk(&mut ln, &fmt::Sprintf!("%-16s %d", string::from_static("waitgroup:rc"), rc));
    // NOT "Wait returned": `Done()` is deferred, so it runs while the
    // panic is still unwinding and Wait can legitimately return before
    // the process dies. Go behaves the same way — 53 of 100 runs print
    // it — so the assertion is that the panic won the race to the exit
    // status, not that Wait lost it.
    chk(&mut ln, &fmt::Sprintf!("%s %v", string::from_static("waitgroup:still_alive"),
        strings::Contains(&out, "still alive")));

    let (rc, out) = run_probe("panic_probe_recover");
    chk(&mut ln, &fmt::Sprintf!("%-16s %d", string::from_static("recover:rc"), rc));
    chk(&mut ln, &fmt::Sprintf!("%s %v", string::from_static("recover:wait_returned"),
        strings::Contains(&out, "Wait returned")));

    let (rc, out) = run_probe("panic_probe_goexit");
    chk(&mut ln, &fmt::Sprintf!("%-16s %d", string::from_static("goexit:rc"), rc));
    chk(&mut ln, &fmt::Sprintf!("%-16s %v", string::from_static("goexit:panics"),
        if strings::Contains(&out, "panics=0") { 0 } else { 1 }));

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    let f = FAILED.load(core::sync::atomic::Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ln as i64, GO.len() as i64);
}
