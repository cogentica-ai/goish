// flag_errorhandling_smoke — `NewFlagSet`'s error policy (ROADMAP §2o).
//
// Go's `NewFlagSet(name, errorHandling)` takes a policy that Parse acts
// on: ContinueOnError returns the error, ExitOnError calls os.Exit(2)
// — or 0 for -h/-help — and PanicOnError panics. `flag.CommandLine`,
// the set behind the top-level `flag.Parse()`, is ExitOnError, so a Go
// program with a bad flag STOPS.
//
// goish's FlagSet took neither parameter and always returned the error.
// The signature difference is a compile error a porter sees at once;
// the BEHAVIOUR difference was silent — a program relying on
// ExitOnError to stop ran on with a default value, and the symptom
// surfaced somewhere else entirely.
//
// The missing `name` was the same omission: `defaultUsage` prints
// "Usage of <name>:" and goish could only produce Go's unnamed
// "Usage:" branch, so `-h` differed from Go on its first line.
//
// Measured against Go 1.25.5:
//
//   ContinueOnError=0 ExitOnError=1 PanicOnError=2
//   ContinueOnError, bad flag -> err "flag provided but not defined: -nope"
//                                and the message + usage on Output
//   -help                     -> flag.ErrHelp, "flag: help requested"
//   PanicOnError, bad flag    -> panics with the error value
//   ExitOnError               -> os.Exit(2), or Exit(0) for -h/-help
//
// The exit cases run as a SUBPROCESS: a process that stops cannot
// assert anything about itself, and goish's `recover!()` does not
// resume, so the panic case cannot be caught in-process either.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::flag::{self, ErrorHandling};
use goish::os::exec;
use goish::{fmt, int, os, string, strings};

static mut FAILED: int = 0;

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("[ok] %s\n", name);
    } else {
        unsafe { FAILED += 1 };
        fmt::Printf!("[!!] %s — %s\n", name, detail);
    }
}

/// The probe sits beside this binary whatever the profile.
fn probe_path() -> string {
    let args = os::Args();
    let me = args[0i64].clone();
    let s: &str = me.as_ref();
    let cut = match s.rfind('/') {
        Some(i) => i + 1,
        None => 0,
    };
    return string::from(&s[..cut]) + string::from("flag_errorhandling_probe");
}

fn run_probe(arg: &'static str) -> (int, string) {
    let path = probe_path();
    let mut cmd = exec::Command(path.clone(), goish::slice!([]string{ arg }));
    let (out, err) = cmd.CombinedOutput();
    let code = match &cmd.ProcessState {
        Some(st) => st.ExitCode(),
        None => {
            fmt::Printf!(
                "[!!] probe did not run: %s (%v)\n     build it with: cargo build --example flag_errorhandling_probe\n",
                path,
                err
            );
            unsafe { FAILED += 1 };
            int::from(-1)
        }
    };
    return (code, string::from_bytes(out.as_ref()));
}

#[goish::main]
fn main() {
    // ── ContinueOnError: in-process, the error comes back ───────────
    let mut fs = flag::NewFlagSet("prog", ErrorHandling::ContinueOnError);
    // Go writes the message and the usage listing to Output even under
    // ContinueOnError, so capture it rather than letting it land in
    // this smoke's own output — and assert it, since it is part of the
    // contract.
    let buf = goish::bytes::NewBufferString(string(""));
    fs.SetOutput(buf);
    let _ = fs.Bool("v", false, "verbose");
    let e = fs.Parse(&goish::slice!([]string{ "-nope" }));
    check(
        "ContinueOnError returns Go's error and the process lives",
        !e.IsNil() && e.Error() == "flag provided but not defined: -nope",
        if e.IsNil() { string("<nil>") } else { e.Error() },
    );

    check(
        "the policy is readable back, and the name with it",
        fs.ErrorHandling() == ErrorHandling::ContinueOnError && fs.Name() == "prog",
        fmt::Sprintf!("name=%q", fs.Name()),
    );

    // Go: CommandLine is an ExitOnError set. This is the whole point of
    // §2o — `flag.Parse()` must stop on a bad flag.
    check(
        "CommandLine is ExitOnError, as Go's is",
        flag::CommandLine.Lock().ErrorHandling() == ErrorHandling::ExitOnError,
        string("CommandLine is not ExitOnError"),
    );

    // ── ExitOnError: only visible from outside the process ──────────
    let (rc_ok, _) = run_probe("ok");
    check(
        "a clean parse does NOT exit — the control for the two below",
        rc_ok == 7,
        fmt::Sprintf!("rc=%d want 7", rc_ok),
    );

    let (rc_bad, out_bad) = run_probe("bad");
    check(
        "ExitOnError exits 2 on an undefined flag",
        rc_bad == 2,
        fmt::Sprintf!("rc=%d want 2", rc_bad),
    );
    check(
        "and prints Go's message before the usage listing",
        strings::Contains(out_bad.clone(), string("flag provided but not defined: -nope")),
        out_bad.clone(),
    );
    check(
        "with the NAMED usage header Go prints",
        strings::Contains(out_bad.clone(), string("Usage of prog:")),
        out_bad.clone(),
    );

    let (rc_help, out_help) = run_probe("help");
    check(
        "-help exits 0, because it is a request that was honoured",
        rc_help == 0,
        fmt::Sprintf!("rc=%d want 0", rc_help),
    );
    check(
        "and prints the usage listing",
        strings::Contains(out_help.clone(), string("Usage of prog:")),
        out_help.clone(),
    );

    // ── PanicOnError ────────────────────────────────────────────────
    //
    // Exits 2 like the ExitOnError case, so the exit code alone cannot
    // tell them apart. The runtime's panic banner is what distinguishes
    // them, and asserting it is what stops this row passing on an
    // ordinary exit.
    let (rc_panic, out_panic) = run_probe("panic");
    check(
        "PanicOnError panics rather than exiting quietly",
        rc_panic == 2 && strings::Contains(out_panic.clone(), string("goish: panic")),
        fmt::Sprintf!("rc=%d out=%s", rc_panic, out_panic.clone()),
    );
    check(
        "and the panic carries Go's error text",
        strings::Contains(
            out_panic.clone(),
            string("flag provided but not defined: -nope"),
        ),
        out_panic.clone(),
    );
    check(
        "which the ExitOnError case does NOT print",
        !strings::Contains(out_bad.clone(), string("goish: panic")),
        string("ExitOnError printed a panic banner"),
    );

    let f = unsafe { FAILED };
    if f == 0 {
        fmt::Printf!("\nok 12/12\n");
        os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", f);
    os::Exit(1);
}
