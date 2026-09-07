// flag_uint64_ref_smoke — Uint64 and Arg, against Go 1.25.5.
//
// Uint64 was the one integer width goish's flag set could not express:
// a Go program calling flag.Uint64 had nothing to call. The first row
// uses 18446744073709551615 on purpose — the value that does not fit
// an int64, so a set that quietly routed uint64 through the int path
// would fail here and only here.
//
// Arg(i) is how positional arguments are read after parsing, and its
// contract is the out-of-range case: Go returns "" rather than
// panicking, which is what lets flag.Arg(0) be read unguarded. The row
// checks index 2 (past the end) and -1 (negative) for that reason.
//
// GO[] is the verbatim output of tools/gen_flag_uint64_ref.go under
// scripts/goref.sh.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::flag;
use goish::fmt;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 4] = [
    "parse err=<nil> n=18446744073709551615 s=\"x\"",
    "args nargs=2 a0=\"one\" a1=\"two\" a2=\"\" a-1=\"\"",
    "default n=42",
    "negative err=true",
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

fn argv(v: &[&'static str]) -> goish::goslice::slice<string> {
    let mut s = goish::make!([]string, 0);
    for a in v { s = goish::append!(s, string::from_static(a)); }
    s
}

fn run() {
    let mut fs = flag::NewFlagSet();
    let n = fs.Uint64("n", 7, "a uint64");
    let s = fs.String("s", "d", "a string");
    let err = fs.Parse(&argv(&["-n", "18446744073709551615", "-s", "x", "one", "two"]));
    chk(fmt::Sprintf!("parse err=%v n=%d s=%q", err, n.Get(), s.Get()));
    chk(fmt::Sprintf!("args nargs=%d a0=%q a1=%q a2=%q a-1=%q",
        fs.NArg() as i64, fs.Arg(0), fs.Arg(1), fs.Arg(2), fs.Arg(-1)));

    let mut fs2 = flag::NewFlagSet();
    let d = fs2.Uint64("d", 42, "a uint64");
    let _ = fs2.Parse(&goish::make!([]string, 0));
    chk(fmt::Sprintf!("default n=%d", d.Get()));

    let mut fs3 = flag::NewFlagSet();
    let _ = fs3.Uint64("n", 1, "a uint64");
    let e3 = fs3.Parse(&argv(&["-n", "-5"]));
    chk(fmt::Sprintf!("negative err=%v", !e3.IsNil()));
    let f = FAILED.load(Ordering::Relaxed);
    let seen = SEEN.load(Ordering::Relaxed);
    // Nothing failed AND every row ran.
    if f == 0 && seen == GO.len() {
        fmt::Printf!("
ok %d/%d
", seen as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!("
FAILED %d of %d (ran %d)
", f as i64, GO.len() as i64, seen as i64);
    goish::os::Exit(1);
}
