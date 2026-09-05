//! Pinned against Go 1.25.5: `os.Process` — Kill, Signal and
//! FindProcess.
//!
//! goish had none of it. `Cmd.Start()` gave you a running child and no
//! way to stop it: no Process field, no Kill, no Signal. A server that
//! shells out and needs a timeout had nothing to call.
//!
//! Four behaviours the reference settles:
//!
//!   * Signalling a process that has already been REAPED is
//!     `os: process already finished` (ErrProcessDone), not a raw
//!     errno. Go translates ESRCH through `convertESRCH` for exactly
//!     this: a caller racing Wait would otherwise see "no such
//!     process", an error about the implementation rather than about
//!     the process.
//!   * `Signal(0)` is the liveness probe — nil while alive,
//!     ErrProcessDone once reaped — which is what Go's own doc for
//!     FindProcess tells you to use.
//!   * FindProcess always succeeds on unix, whether or not the pid
//!     exists.
//!   * A second `Wait` is `exec: Wait was already called`. goish said
//!     "os/exec: Wait called before Start" for both cases, which is
//!     wrong for the far more common one.
//!
//! Kill and Wait are exercised from separate handles on purpose: the
//! Process is cloneable and every clone shares the done flag, which is
//! what lets one goroutine kill a child while another sits in Wait.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh os <process_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::os::exec;
use goish::os::exec_posix;
use goish::{fmt, slice, string, time};

/// Go's output, verbatim.
const GO: [&str; 9] = [
    "kill                 err=\"<nil>\"                                        pid>0=true",
    "wait-after-kill      err=\"signal: killed\"                               code=-1",
    "signal-term          err=\"<nil>\"                                        ",
    "wait-after-term      err=\"signal: terminated\"                           ",
    "kill-after-wait      err=\"os: process already finished\"                 ",
    "signal-0-alive       err=\"<nil>\"                                        ",
    "signal-0-dead        err=\"os: process already finished\"                 ",
    "findprocess-self     err=\"<nil>\"                                        same-pid=true",
    "wait-twice           err=\"exec: Wait was already called\"                ",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;
fn sleeper() -> exec::Cmd {
    let mut args = slice::<string>::new();
    args = goish::append!(args, string("-c"));
    args = goish::append!(args, string("sleep 30"));
    exec::Command(string("/bin/sh"), args)
}
fn show(tag: &'static str, err: goish::error, extra: string) {
    chk(fmt::Sprintf!(
        "%-20s err=%-46q %s",
        string::from_static(tag),
        if err.IsNil() {
            string("<nil>")
        } else {
            err.Error()
        },
        extra
    ));
}

/// Compare one rendered line against the Go reference, in order.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    let want = string::from_static(GO[i]);
    if got == want {
        return;
    }
    fmt::Printf!("DIFF go   : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    unsafe { FAILED += 1 };
}
#[goish::main]
fn main() {
    let mut c = sleeper();
    let _ = c.Start();
    let p = c.Process.clone().unwrap();
    show("kill", p.Kill(), fmt::Sprintf!("pid>0=%v", p.Pid > 0));
    let werr = c.Wait();
    let ee = goish::errors::AsConcrete::<exec::ExitError>(&werr);
    let code = match &ee {
        Some(e) => e.ExitCode() as i64,
        None => -2,
    };
    show("wait-after-kill", werr, fmt::Sprintf!("code=%d", code));

    let mut c2 = sleeper();
    let _ = c2.Start();
    show(
        "signal-term",
        c2.Process.clone().unwrap().Signal(goish::int::from(15)),
        string(""),
    );
    show("wait-after-term", c2.Wait(), string(""));

    let mut c3 = sleeper();
    let _ = c3.Start();
    let _ = c3.Process.clone().unwrap().Kill();
    let _ = c3.Wait();
    show(
        "kill-after-wait",
        c3.Process.clone().unwrap().Kill(),
        string(""),
    );

    let mut c4 = sleeper();
    let _ = c4.Start();
    show(
        "signal-0-alive",
        c4.Process.clone().unwrap().Signal(goish::int::from(0)),
        string(""),
    );
    let _ = c4.Process.clone().unwrap().Kill();
    let _ = c4.Wait();
    time::Sleep(time::Duration(50_000_000));
    show(
        "signal-0-dead",
        c4.Process.clone().unwrap().Signal(goish::int::from(0)),
        string(""),
    );

    let (fp, ferr) = exec_posix::FindProcess(goish::os::Getpid());
    show(
        "findprocess-self",
        ferr,
        fmt::Sprintf!("same-pid=%v", fp.Pid == goish::os::Getpid()),
    );

    let mut args5 = slice::<string>::new();
    args5 = goish::append!(args5, string("-c"));
    args5 = goish::append!(args5, string("exit 3"));
    let mut c5 = exec::Command(string("/bin/sh"), args5);
    let _ = c5.Start();
    let _ = c5.Wait();
    show("wait-twice", c5.Wait(), string(""));

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("os.Process: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}
