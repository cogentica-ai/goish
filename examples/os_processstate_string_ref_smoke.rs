// os_processstate_string_ref_smoke — a ptrace stop names its event.
//
// Go's ProcessState.String (os/exec_posix.go:108-136) appends
// " (trap N)" when a stopped child's signal is SIGTRAP and the byte
// above it is non-zero — the ptrace event that stopped it. goish had
// no such branch, so a fork stop and an exec stop both rendered as a
// bare "stop signal: trace/breakpoint trap" and the event was lost.
//
// The rows cannot come from a real child: a status like 0x01057f is
// only produced under ptrace, and Go's own ProcessState has unexported
// fields and no constructor. tools/gen_processstate_string_export.go
// is the export_test.go shim that hands one back, which is also why
// scripts/goref.sh grew its extra-file argument — an internal test of
// `os` cannot import `testing`, since `testing` imports `os`.
//
// GO[] is the verbatim output of tools/gen_processstate_string_ref.go
// under scripts/goref.sh, transcribed programmatically.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::os::ProcessState;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 10] = [
    "name=exit0 str=\"exit status 0\"",
    "name=exit3 str=\"exit status 3\"",
    "name=exit255 str=\"exit status 255\"",
    "name=sigkill str=\"signal: killed\"",
    "name=sigsegv_core str=\"signal: segmentation fault (core dumped)\"",
    "name=stop_sigstop str=\"stop signal: stopped (signal)\"",
    "name=stop_sigtrap_nocause str=\"stop signal: trace/breakpoint trap\"",
    "name=stop_sigtrap_fork str=\"stop signal: trace/breakpoint trap (trap 1)\"",
    "name=stop_sigtrap_exec str=\"stop signal: trace/breakpoint trap (trap 4)\"",
    "name=continued str=\"continued\"",
];

fn chk(got: goish::string) {
    let i = SEEN.fetch_add(1, Ordering::Relaxed);
    if i < GO.len() && got == string(GO[i]) {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            string(if i < GO.len() { GO[i] } else { "" })
        );
    }
}

fn chk_one(name: goish::string, status: i32) {
    let ps = ProcessState::__new(4242 as goish::int, status);
    chk(fmt::Sprintf!("name=%s str=%q", name, ps.String()));
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    chk_one(string::from_static("exit0"), 0x000000);
    chk_one(string::from_static("exit3"), 0x000300);
    chk_one(string::from_static("exit255"), 0x00ff00);
    chk_one(string::from_static("sigkill"), 0x000009);
    chk_one(string::from_static("sigsegv_core"), 0x00008b);
    chk_one(string::from_static("stop_sigstop"), 0x00137f);
    chk_one(string::from_static("stop_sigtrap_nocause"), 0x00057f);
    chk_one(string::from_static("stop_sigtrap_fork"), 0x01057f);
    chk_one(string::from_static("stop_sigtrap_exec"), 0x04057f);
    chk_one(string::from_static("continued"), 0x00ffff);

    let f = FAILED.load(Ordering::Relaxed);
    let seen = SEEN.load(Ordering::Relaxed);
    if f == 0 && seen == GO.len() {
        fmt::Printf!("\nok %d/%d\n", seen as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of %d (ran %d)\n", f as i64, GO.len() as i64, seen as i64);
    goish::os::Exit(1);
}
