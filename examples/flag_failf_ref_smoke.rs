// flag_failf_ref_smoke — a bad flag EXPLAINS itself on the output.
//
// Go's failf (flag.go:1058) prints before it returns: sprintf writes
// the message to Output, then usage() writes the flag list. So `-nope`
// produces an explanation a user can read, not just an error value the
// program might swallow. This holds under ContinueOnError, where the
// error is returned as well.
//
// goish built the same error and printed NOTHING. The error VALUE
// matched Go exactly, which is why the existing flag_ref_smoke — which
// asserts parse errors — passed throughout: it never looked at the
// output buffer. Two well-tested things with a gap between them.
//
// GO[] is the verbatim output of tools/gen_flag_failf_ref.go under
// scripts/goref.sh against Go 1.25.5.

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

static GO: [&str; 2] = [
    "args=[-nope] err=flag provided but not defined: -nope out=\"flag provided but not defined: -nope\\nUsage:\\n  -s string\\n    \\ta string (default \\\"def\\\")\\n\"",
    "args=[-s] err=flag needs an argument: -s out=\"flag needs an argument: -s\\nUsage:\\n  -s string\\n    \\ta string (default \\\"def\\\")\\n\"",
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
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    for args in [["-nope"], ["-s"]].iter() {
        let buf = Arc::new(goish::sync::Mutex::new(bytes::Buffer::new()));
        let mut fs = flag::NewFlagSet();
        fs.SetOutput(buf.clone());
        let _ = fs.String("s", "def", "a string");
        let mut a = goish::make!([]string, 0);
        for x in args.iter() {
            a = goish::append!(a, string::from_static(x));
        }
        let err = fs.Parse(&a);
        chk(fmt::Sprintf!(
            "args=[%s] err=%v out=%q",
            string::from_static(args[0]),
            err,
            goish::string::from_bytes(&buf.Lock().Bytes())
        ));
    }

    let f = FAILED.load(Ordering::Relaxed);
    let seen = SEEN.load(Ordering::Relaxed);
    if f == 0 && seen == GO.len() {
        fmt::Printf!("\nok %d/%d\n", seen as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of %d (ran %d)\n", f as i64, GO.len() as i64, seen as i64);
    goish::os::Exit(1);
}
