// flag_usage_ref_smoke — -h prints a header, not just the flag list.
//
// Go's defaultUsage (flag.go:684) writes "Usage of <name>:" — or
// "Usage:" for an unnamed set — BEFORE the flag list. goish printed
// only the list, so `-h` output differed from Go's on its very first
// line, in the text a user reads when they ask for help.
//
// It was uncovered because the existing flag_ref_smoke drives
// PrintDefaults directly and asserts THAT byte for byte; nothing
// exercised the usage() path that -h takes.
//
// Only the unnamed row is asserted here: goish's FlagSet carries no
// name, because its NewFlagSet takes neither of Go's two parameters
// (ROADMAP §2o). GO_NAMED records Go's other branch so the difference
// is visible rather than implied — when NewFlagSet gains a name, this
// smoke gains a row.
//
// GO[] is the verbatim output of tools/gen_flag_usage_ref.go under
// scripts/goref.sh.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::bytes;
use goish::flag;
use goish::fmt;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 1] =
    ["name=\"\" err=flag: help requested out=\"Usage:\\n  -s string\\n    \\ta string (default \\\"def\\\")\\n\""];

/// Go's named branch, for reference: goish has no FlagSet name to put
/// in it yet (ROADMAP §2o).
#[allow(dead_code)]
static GO_NAMED: &str =
    "name=\"prog\" err=flag: help requested out=\"Usage of prog:\\n  -s string\\n    \\ta string (default \\\"def\\\")\\n\"";

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
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let buf = Arc::new(goish::sync::Mutex::new(bytes::Buffer::new()));
    let mut fs = flag::NewFlagSet();
    fs.SetOutput(buf.clone());
    let _ = fs.String("s", "def", "a string");
    let mut args = goish::make!([]string, 0);
    args = goish::append!(args, string::from_static("-h"));
    let err = fs.Parse(&args);
    chk(fmt::Sprintf!(
        "name=%q err=%v out=%q",
        string::from_static(""),
        err,
        goish::string::from_bytes(&buf.Lock().Bytes())
    ));

    let f = FAILED.load(Ordering::Relaxed);
    let seen = SEEN.load(Ordering::Relaxed);
    if f == 0 && seen == GO.len() {
        fmt::Printf!("\nok %d/%d\n", seen as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of %d (ran %d)\n", f as i64, GO.len() as i64, seen as i64);
    goish::os::Exit(1);
}
