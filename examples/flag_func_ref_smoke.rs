// flag_func_ref_smoke — Func and BoolFunc, against Go 1.25.5.
//
// These define flags whose "value" is a CALLBACK. Each occurrence
// calls fn, so they accumulate where a normal flag overwrites — the
// usual way to collect a repeatable option. Row one checks that, and
// that the trailing word stays positional.
//
// BoolFunc additionally reports IsBoolFlag, which is the part a port
// gets wrong: `-v` must stand alone WITHOUT consuming the next
// argument, and `-v=false` must still reach the callback. Row two has
// both, and asserts "positional" is still an argument rather than the
// flag's value.
//
// Row three is the error contract: Go documents that a non-nil return
// "will be treated as a flag value parsing error", so it comes back
// wrapped exactly like a bad integer would —
// `invalid value "v" for flag -x: boom`.
//
// GO[] is the verbatim output of tools/gen_flag_func_ref.go under
// scripts/goref.sh.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::flag;
use goish::fmt;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 3] = [
    "func err=<nil> got=[a b] nargs=1 a0=\"rest\"",
    "boolfunc err=<nil> seen=[true false] nargs=1 a0=\"positional\"",
    "func-error err=invalid value \"v\" for flag -x: boom",
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

#[goish::main]
fn main() { goish::go!(stack(1024*1024), move || { run(); }); loop { goish::runtime::sched::Gosched(); } }

fn argv(v: &[&'static str]) -> goish::goslice::slice<string> {
    let mut s = goish::make!([]string, 0);
    for a in v { s = goish::append!(s, string::from_static(a)); }
    s
}

fn join(v: &Vec<string>) -> string {
    let mut out = string::from_static("[");
    for (i, x) in v.iter().enumerate() {
        if i > 0 { out = out + string::from_static(" "); }
        out = out + x.clone();
    }
    out + string::from_static("]")
}

fn run() {
    let got: Arc<goish::sync::Mutex<Vec<string>>> = Arc::new(goish::sync::Mutex::new(Vec::new()));
    let mut fs = flag::NewFlagSet();
    { let g = got.clone();
      fs.Func("tag", "add a tag", move |s: string| { g.Lock().push(s); goish::errors::nil }); }
    let err = fs.Parse(&argv(&["-tag", "a", "-tag", "b", "rest"]));
    chk(fmt::Sprintf!("func err=%v got=%s nargs=%d a0=%q", err, join(&got.Lock()), fs.NArg() as i64, fs.Arg(0)));

    let seen: Arc<goish::sync::Mutex<Vec<string>>> = Arc::new(goish::sync::Mutex::new(Vec::new()));
    let mut fs2 = flag::NewFlagSet();
    { let g = seen.clone();
      fs2.BoolFunc("v", "verbose", move |s: string| { g.Lock().push(s); goish::errors::nil }); }
    let err2 = fs2.Parse(&argv(&["-v", "-v=false", "positional"]));
    chk(fmt::Sprintf!("boolfunc err=%v seen=%s nargs=%d a0=%q", err2, join(&seen.Lock()), fs2.NArg() as i64, fs2.Arg(0)));

    let mut fs3 = flag::NewFlagSet();
    fs3.Func("x", "fails", |_s: string| goish::errors::New(string::from_static("boom")));
    let err3 = fs3.Parse(&argv(&["-x", "v"]));
    chk(fmt::Sprintf!("func-error err=%v", err3));
    let f = FAILED.load(Ordering::Relaxed);
    let seen_n = SEEN.load(Ordering::Relaxed);
    if f == 0 && seen_n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", seen_n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of %d (ran %d)\n", f as i64, GO.len() as i64, seen_n as i64);
    goish::os::Exit(1);
}
