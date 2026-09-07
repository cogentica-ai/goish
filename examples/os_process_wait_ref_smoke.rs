// os_process_wait_ref_smoke — os.Process.Wait.
//
// Go's Cmd.Wait reaps through `c.Process.Wait()`; goish's called
// syscall::Wait4 itself and there was no Process.Wait at all, so the
// rusage the kernel writes was thrown away with it — which is why
// ProcessState.UserTime and SystemTime could not be ported either.
//
// CPU times cannot be pinned to a value; they are whatever the machine
// spent. What is pinned is the shape Go guarantees around them — which
// state a Wait returns for an exit and for a signal death, and what
// the SECOND Wait on a reaped pid says — plus the times as ORDERING
// facts: a child that burns CPU reports more user time than one that
// sleeps, and a sleeper's user time is far under its wall clock. A
// rusage that was never filled in fails all three at once.
//
// GO[] is the verbatim output of tools/gen_process_wait_ref.go under
// scripts/goref.sh.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

/// Every mismatch below lands here; the process exits non-zero if it is
/// not zero (ROADMAP §2b-vii).
static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

use goish::gostring::string;
use goish::os::exec;
use goish::types::int;
use goish::{fmt, time};

const GO: [&str; 9] = [
    "exit0        err=<nil> exited=true code=0 success=true str=\"exit status 0\"",
    "exit0-again  err=wait: no child processes",
    "exit3        err=<nil> exited=true code=3 success=false str=\"exit status 3\"",
    "exit3-again  err=wait: no child processes",
    "sigkill      err=<nil> exited=false code=-1 success=false str=\"signal: killed\"",
    "sigkill-again err=wait: no child processes",
    "sigterm      err=<nil> exited=false code=-1 success=false str=\"signal: terminated\"",
    "sigterm-again err=wait: no child processes",
    "cpu          busy>idle=true idle_user<wall=true idle_user_lt_100ms=true",
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

fn sh(script: &str) -> exec::Cmd {
    let mut args = goish::make!([]string, 0);
    args = goish::append!(args, string::from_static("-c"));
    args = goish::append!(args, string::from(script));
    return exec::Command(string::from_static("/bin/sh"), args);
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
    let mut ln: usize = 0;
    let cases: [(&str, &str); 4] = [
        ("exit0", "exit 0"),
        ("exit3", "exit 3"),
        ("sigkill", "kill -9 $$"),
        ("sigterm", "kill -15 $$"),
    ];
    for (name, script) in cases.iter() {
        let mut cmd = sh(script);
        let e = cmd.Start();
        if !e.IsNil() {
            fmt::Printf!("[!!] start %s: %v\n", string::from(*name), e);
            goish::os::Exit(1);
        }
        let p = match cmd.Process.clone() {
            Some(p) => p,
            None => {
                fmt::Printf!("[!!] no Process after Start for %s\n", string::from(*name));
                goish::os::Exit(1);
                return;
            }
        };
        let (st, werr) = p.Wait();
        chk(
            &mut ln,
            &fmt::Sprintf!(
                "%-12s err=%v exited=%v code=%d success=%v str=%q",
                string::from(*name),
                werr,
                st.Exited(),
                st.ExitCode(),
                st.Success(),
                st.String()
            ),
        );
        // A reaped pid has no child left to wait for: ECHILD, wrapped
        // by NewSyscallError exactly as Go wraps it.
        let (_, werr2) = p.Wait();
        chk(
            &mut ln,
            &fmt::Sprintf!("%-12s err=%v", string::from(*name) + string::from_static("-again"), werr2),
        );
    }

    // CPU time. The busy child must out-burn the sleeper, and the
    // sleeper's user time must be far below its wall clock — the three
    // facts a zero rusage cannot satisfy.
    let mut busy = sh("i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done");
    let _ = busy.Start();
    let bp = busy.Process.clone().unwrap();
    let (bst, _) = bp.Wait();

    let mut idle = sh("sleep 0.3");
    let start = time::Now();
    let _ = idle.Start();
    let ip = idle.Process.clone().unwrap();
    let (ist, _) = ip.Wait();
    let wall = time::Since(start);

    chk(
        &mut ln,
        &fmt::Sprintf!(
            "%-12s busy>idle=%v idle_user<wall=%v idle_user_lt_100ms=%v",
            string::from_static("cpu"),
            bst.UserTime() > ist.UserTime(),
            ist.UserTime() < wall,
            ist.UserTime() < time::Millisecond * 100
        ),
    );

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
    goish::os::Exit(0);
}
