// flag_definer_panic_probe — Go's definition-time panics, driven as
// subprocesses because goish's `recover!()` does not resume.
//
// argv[1] selects the case:
//
//   dash   flag.Bool("-x", …)          -> flag "-x" begins with -
//   equals flag.Bool("a=b", …)         -> flag "a=b" contains =
//   dup    two flags named "dup"       -> prog flag redefined: dup
//   anon   the same, on an UNNAMED set -> flag redefined: dup
//   ok     a well-formed definition    -> exits 7
//
// `ok` is the control: "panicked" proves nothing if every case panics.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::flag::{self, ErrorHandling};
use goish::{os, string};

#[goish::main]
fn main() {
    let args = os::Args();
    let which: string = if args.Len() > 1 {
        args[1i64].clone()
    } else {
        string("")
    };

    match which.as_ref() as &str {
        "dash" => {
            let mut fs = flag::NewFlagSet("prog", ErrorHandling::ContinueOnError);
            let _ = fs.Bool("-x", false, "u");
        }
        "equals" => {
            let mut fs = flag::NewFlagSet("prog", ErrorHandling::ContinueOnError);
            let _ = fs.Bool("a=b", false, "u");
        }
        "dup" => {
            let mut fs = flag::NewFlagSet("prog", ErrorHandling::ContinueOnError);
            let _ = fs.Bool("dup", false, "u");
            let _ = fs.Int("dup", 0, "u");
        }
        "anon" => {
            let mut fs = flag::NewFlagSet("", ErrorHandling::ContinueOnError);
            let _ = fs.Bool("dup", false, "u");
            let _ = fs.Int("dup", 0, "u");
        }
        _ => {
            let mut fs = flag::NewFlagSet("prog", ErrorHandling::ContinueOnError);
            let _ = fs.Bool("fine", false, "u");
        }
    }

    // Only `ok` reaches here.
    os::Exit(7);
}
