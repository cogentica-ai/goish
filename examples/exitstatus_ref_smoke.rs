//! Pinned against Go 1.25.5: what a failed command reports.
//!
//! Four divergences, all fixed here, all measured:
//!
//!   1. There was no `exec.ExitError` and no `os.ProcessState`, so a
//!      caller could not read an exit code at all — the only way to
//!      get the number back was to parse "exit status 1".
//!   2. A signalled process printed "signal: 9". Go prints
//!      "signal: killed": it renders the NAME, which is the
//!      difference between an error a person can read and one they
//!      have to look up.
//!   3. A core dump appends " (core dumped)", which goish never said.
//!   4. A binary that does not exist reported "exit status 127".
//!      That is what `sh -c 'exit 127'` reports too, so the caller
//!      could not tell a missing program from one that chose that
//!      code. Go reports
//!      "fork/exec /nonexistent/binary: no such file or directory",
//!      and it is NOT an ExitError — the process never started.
//!
//! (4) is why exit codes are checked alongside the message: a smoke
//! that only compared error text would have passed (3) and (4) as
//! "some error happened".
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh os/exec <exitstatus_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::os::exec;
use goish::{fmt, slice, string};

/// Go's output, verbatim.
const GO: [&str; 8] = [
    "true           exitErr=false code=-2   exited=false success=false signaled=false err=\"<nil>\"",
    "exit-1         exitErr=true  code=1    exited=true  success=false signaled=false err=\"exit status 1\"",
    "exit-42        exitErr=true  code=42   exited=true  success=false signaled=false err=\"exit status 42\"",
    "exit-255       exitErr=true  code=255  exited=true  success=false signaled=false err=\"exit status 255\"",
    "sigkill        exitErr=true  code=-1   exited=false success=false signaled=true  err=\"signal: killed\"",
    "sigterm        exitErr=true  code=-1   exited=false success=false signaled=true  err=\"signal: terminated\"",
    "sigsegv        exitErr=true  code=-1   exited=false success=false signaled=true  err=\"signal: segmentation fault (core dumped)\"",
    "notfound       exitErr=false code=-2   exited=false success=false signaled=false err=\"fork/exec /nonexistent/binary: no such file or directory\"",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;
#[goish::main]
fn main() {
    let cases: [(&str, &str); 8] = [
        ("true", "exit 0"),
        ("exit-1", "exit 1"),
        ("exit-42", "exit 42"),
        ("exit-255", "exit 255"),
        ("sigkill", "kill -9 $$"),
        ("sigterm", "kill -15 $$"),
        ("sigsegv", "kill -11 $$"),
        ("notfound", ""),
    ];
    for (tag, script) in cases.iter() {
        let err = if *tag == "notfound" {
            let mut c = exec::Command(string("/nonexistent/binary"), slice::<string>::new());
            c.Run()
        } else {
            let mut args = slice::<string>::new();
            args = goish::append!(args, string("-c"));
            args = goish::append!(args, string::from_static(script));
            let mut c = exec::Command(string("/bin/sh"), args);
            c.Run()
        };
        let ee = goish::errors::AsConcrete::<exec::ExitError>(&err);
        let is_exit = ee.is_some();
        let (code, exited, success, signaled) = match &ee {
            Some(e) => (e.ExitCode() as i64, e.Exited(), e.Success(), !e.Exited()),
            None => (-2i64, false, false, false),
        };
        chk(fmt::Sprintf!(
            "%-14s exitErr=%-5v code=%-4d exited=%-5v success=%-5v signaled=%-5v err=%q",
            string::from_static(tag),
            is_exit,
            code,
            exited,
            success,
            signaled,
            if err.IsNil() {
                string("<nil>")
            } else {
                err.Error()
            }
        ));
    }
    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("exit status: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
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
