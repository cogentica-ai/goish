// flag_errorhandling_probe — the ExitOnError half of §2o, which cannot
// be asserted in-process because the whole point is that the process
// STOPS.
//
// Driven as a subprocess by flag_errorhandling_smoke. argv[1] selects
// the case:
//
//   bad    a flag that was never defined  -> Go exits 2
//   help   -help on an ExitOnError set    -> Go exits 0
//   ok     a well-formed parse            -> falls through, exits 7
//   panic  the same bad flag on a PanicOnError set -> panics
//
// The panic case is here rather than in the driver because goish's
// `recover!()` does not resume execution, so a panic cannot be
// asserted in-process at all.
//
// The `ok` case is the control: without it, "exited 2" proves nothing,
// because a probe that always exited 2 would pass the first row too.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::flag::{self, ErrorHandling};
use goish::{os, slice, string};

#[goish::main]
fn main() {
    let args = os::Args();
    let which: string = if args.Len() > 1 {
        args[1i64].clone()
    } else {
        string("")
    };

    let policy = if (which.as_ref() as &str) == "panic" {
        ErrorHandling::PanicOnError
    } else {
        ErrorHandling::ExitOnError
    };
    let mut fs = flag::NewFlagSet("prog", policy);
    let _v = fs.Bool("v", false, "verbose");
    // Nothing should reach stderr for the `ok` case, so send the usage
    // output somewhere the driver can ignore; the exit code is the
    // assertion.
    let argv: slice<string> = match which.as_ref() as &str {
        "bad" | "panic" => goish::slice!([]string{ "-nope" }),
        "help" => goish::slice!([]string{ "-help" }),
        _ => goish::slice!([]string{ "-v" }),
    };

    let _ = fs.Parse(&argv);

    // Only the `ok` case can get here: the other two exit inside Parse.
    os::Exit(7);
}
