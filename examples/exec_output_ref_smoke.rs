// exec_output_ref_smoke — Output, CombinedOutput and String vs Go.
//
// Output captures stdout and, when Stderr was not otherwise being
// collected, attaches a BOUNDED prefix of stderr to the ExitError —
// that is what ExitError.Stderr is for, and why Go bounds it with
// prefixSuffixSaver (32 KiB of head and tail, with the middle replaced
// by "... omitting N bytes ..."). A failing command that writes
// megabytes to stderr must not hold megabytes in an error.
//
// CombinedOutput points BOTH streams at one buffer, which is what
// interleaves them; goish shares one Arc where Go assigns the same
// pointer twice.
//
// The last row is the guard: Output refuses when Stdout is already
// set, rather than silently discarding what the caller asked for.
//
// GO[] is the verbatim output of tools/gen_exec_output_ref.go under
// scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::os::exec;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 5] = [
    "echo out=\"hello world\\n\" err=<nil>",
    "fail out=\"out\\n\" code=3 stderr=\"err\\n\"",
    "combined out=\"one\\ntwo\\n\" err=<nil>",
    "string=\"/bin/echo a b\"",
    "stdout-already-set err=exec: Stdout already set",
];

fn chk(got: goish::string) {
    let i = SEEN.fetch_add(1, Ordering::Relaxed);
    if i < GO.len() && got == string(GO[i]) {
        fmt::Printf!("ok   %s
", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d
  got:  %s
  want: %s
",
            i as i64,
            got,
            string(if i < GO.len() { GO[i] } else { "" })
        );
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn args(v: &[&'static str]) -> goish::goslice::slice<string> {
    let mut s = goish::make!([]string, 0);
    for a in v { s = goish::append!(s, string::from_static(a)); }
    s
}

fn run() {
    let mut c1 = exec::Command("/bin/echo", args(&["hello", "world"]));
    let (out, err) = c1.Output();
    chk(fmt::Sprintf!("echo out=%q err=%v", goish::string::from_bytes(&out), err));

    let mut c2 = exec::Command("/bin/sh", args(&["-c", "echo out; echo err 1>&2; exit 3"]));
    let (out2, err2) = c2.Output();
    let mut code: goish::types::int = 0;
    let mut stderr = string::new();
    if let Some(ee) = goish::errors::As::<exec::ExitError>(err2.clone()) {
        code = ee.ExitCode();
        stderr = goish::string::from_bytes(&ee.Stderr);
    }
    chk(fmt::Sprintf!("fail out=%q code=%d stderr=%q", goish::string::from_bytes(&out2), code as i64, stderr));

    let mut c3 = exec::Command("/bin/sh", args(&["-c", "echo one; echo two 1>&2"]));
    let (comb, err3) = c3.CombinedOutput();
    chk(fmt::Sprintf!("combined out=%q err=%v", goish::string::from_bytes(&comb), err3));

    let c4 = exec::Command("/bin/echo", args(&["a", "b"]));
    chk(fmt::Sprintf!("string=%q", c4.String()));

    let mut c5 = exec::Command("/bin/echo", args(&["x"]));
    c5.SetStdout(goish::bytes::Buffer::new());
    let (_, e5) = c5.Output();
    chk(fmt::Sprintf!("stdout-already-set err=%v", e5));

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("\nok 5/5\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of 5\n", f as i64);
    goish::os::Exit(1);
}
