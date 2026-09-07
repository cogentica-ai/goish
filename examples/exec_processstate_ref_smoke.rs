// exec_processstate_ref_smoke — Cmd.ProcessState.
//
// Go documents the field as "Wait or Run will populate its
// ProcessState when the command completes" (os/exec/exec.go line 243).
// goish's Cmd had no such field: after a Run there was nowhere to read
// the exit code, the signal or the CPU time from, only the error.
//
// The field could not have been filled before os.Process.Wait was
// ported, which is the point of the last row. Go reaps through
// `c.Process.Wait()` (exec.go:922) and goish called syscall::Wait4
// here with a NULL rusage — so UserTime would have been zero however
// the field was wired. Delegating to Process.Wait supplies the state
// AND the rusage, and deletes the duplicate wait path.
//
// GO[] is the verbatim output of tools/gen_cmd_processstate_ref.go
// under scripts/goref.sh.

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

const GO: [&str; 8] = [
    "before-start  state=<nil>",
    "exit0         err=<nil> state=code=0 exited=true success=true str=\"exit status 0\"",
    "exit0-again   err=exec: Wait was already called state=code=0 exited=true success=true str=\"exit status 0\"",
    "exit7         err=exit status 7 state=code=7 exited=true success=false str=\"exit status 7\"",
    "exit7-again   err=exec: Wait was already called state=code=7 exited=true success=false str=\"exit status 7\"",
    "sigkill       err=signal: killed state=code=-1 exited=false success=false str=\"signal: killed\"",
    "sigkill-again err=exec: Wait was already called state=code=-1 exited=false success=false str=\"signal: killed\"",
    "rusage        busy>idle=true idle_lt_100ms=true",
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

/// Go's `has` helper: the state, or `<nil>` when the field is unset.
fn has(c: &exec::Cmd) -> string {
    return match &c.ProcessState {
        None => string::from_static("<nil>"),
        Some(st) => fmt::Sprintf!(
            "code=%d exited=%v success=%v str=%q",
            st.ExitCode(),
            st.Exited(),
            st.Success(),
            st.String()
        ),
    };
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

    let fresh = sh("exit 0");
    chk(
        &mut ln,
        &fmt::Sprintf!("%-13s state=%s", string::from_static("before-start"), has(&fresh)),
    );

    let cases: [(&str, &str); 3] = [("exit0", "exit 0"), ("exit7", "exit 7"), ("sigkill", "kill -9 $$")];
    for (name, script) in cases.iter() {
        let mut cmd = sh(script);
        let err = cmd.Run();
        chk(
            &mut ln,
            &fmt::Sprintf!("%-13s err=%v state=%s", string::from(*name), err, has(&cmd)),
        );
        // A second Wait is refused, and the state must survive it.
        let err2 = cmd.Wait();
        chk(
            &mut ln,
            &fmt::Sprintf!(
                "%-13s err=%v state=%s",
                string::from(*name) + string::from_static("-again"),
                err2,
                has(&cmd)
            ),
        );
    }

    // The rusage reached Cmd, not just Process.
    let mut busy = sh("i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done");
    let _ = busy.Run();
    let mut idle = sh("sleep 0.3");
    let _ = idle.Run();
    let bu = busy.ProcessState.as_ref().map(|s| s.UserTime()).unwrap_or(time::Duration(0));
    let iu = idle.ProcessState.as_ref().map(|s| s.UserTime()).unwrap_or(time::Duration(0));
    chk(
        &mut ln,
        &fmt::Sprintf!(
            "%-13s busy>idle=%v idle_lt_100ms=%v",
            string::from_static("rusage"),
            bu > iu,
            iu < time::Millisecond * 100
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
