// exec_environ_ref_smoke — the child's environment, against Go.
//
// Cmd.Environ reports what the child would get. The rules are all in
// dedupEnvCase, and each row here is one of them:
//
//   * duplicates resolve LAST-WINS, which Go gets by building the
//     output backwards and reversing it. Forwards would keep the
//     first.
//   * an entry with no "=" is preserved as-is ("novalue"); an empty
//     entry is dropped.
//   * an entry containing NUL is DROPPED and reported as an error —
//     "to prevent security issues" (go.dev/issue/56284).
//   * a key with a leading "=" is a real thing on Windows, so the
//     separator search restarts after it.
//   * on linux keys are case-SENSITIVE, so "a" and "A" both survive.
//
// GO[] is the verbatim output of tools/gen_exec_environ_ref.go under
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

static GO: [&str; 4] = [
    "dedup=[\"B=2\" \"A=3\" \"novalue\" \"C=4\"]",
    "nul=[\"A=2\"]",
    "leading-eq=[\"K=1\" \"=weird=w\"]",
    "case=[\"a=1\" \"A=2\"]",
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
fn main() { goish::go!(stack(1024*1024), move || { run(); }); loop { goish::runtime::sched::Gosched(); } }

fn env(v: &[&'static str]) -> goish::goslice::slice<string> {
    let mut s = goish::make!([]string, 0);
    for a in v { s = goish::append!(s, string::from_static(a)); }
    s
}

fn run() {
    let mut c = exec::Command("/bin/echo", goish::make!([]string, 0));
    c.Env = env(&["A=1", "B=2", "A=3", "novalue", "", "C=4"]);
    chk(fmt::Sprintf!("dedup=%q", c.Environ()));

    let mut c2 = exec::Command("/bin/echo", goish::make!([]string, 0));
    c2.Env = env(&["A=1", "BAD=x\0y", "A=2"]);
    chk(fmt::Sprintf!("nul=%q", c2.Environ()));

    let mut c3 = exec::Command("/bin/echo", goish::make!([]string, 0));
    c3.Env = env(&["=weird=v", "K=1", "=weird=w"]);
    chk(fmt::Sprintf!("leading-eq=%q", c3.Environ()));

    let mut c4 = exec::Command("/bin/echo", goish::make!([]string, 0));
    c4.Env = env(&["a=1", "A=2"]);
    chk(fmt::Sprintf!("case=%q", c4.Environ()));
    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("
ok 4/4
");
        goish::os::Exit(0);
    }
    fmt::Printf!("
FAILED %d of 4
", f as i64);
    goish::os::Exit(1);
}
