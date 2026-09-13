// flag_var_smoke — `flag.Var` lets a caller define a flag of their OWN
// type (ROADMAP §2p).
//
// Go's `Var(value Value, name, usage)` is the package's extension
// point: a program implements `String()` and `Set(string) error` and
// gets a flag of its own type, which is how every non-trivial CLI adds
// a repeated option, an enum, or a parsed struct.
//
// goish stored every flag as one arm of a CLOSED enum — Bool, Int,
// Duration, … — so `Var` had nothing to accept. `flag.Value` existed
// and was even exported, but only for READING (`Flag.Value`); there was
// no way to supply one. The enum has a `Custom` arm now.
//
// ONE DELIBERATE DIVERGENCE, and it is forced. Go takes a pointer the
// caller already holds:
//
//     var v myType
//     flag.Var(&v, "x", "usage")   // caller keeps reading v
//
// Rust ownership does not allow that — the value moves into the
// FlagSet. So `Var` hands back a `ValueHandle`, which is the same shape
// every other goish definer already uses.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::flag::{self, ErrorHandling, Value};
use goish::{errors, fmt, int, os, string};

static mut FAILED: int = 0;

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("[ok] %s\n", name);
    } else {
        unsafe { FAILED += 1 };
        fmt::Printf!("[!!] %s — %s\n", name, detail);
    }
}

/// A caller's own flag type: a repeatable option that accumulates, and
/// rejects the empty string. This is the shape `Func` cannot express —
/// it has a value with a `String()` of its own, which is what shows up
/// in a `-help` listing.
struct tagList {
    tags: Vec<string>,
}

impl Value for tagList {
    fn String(&self) -> string {
        let mut out = string::new();
        for (i, t) in self.tags.iter().enumerate() {
            if i > 0 {
                out = out + string(",");
            }
            out = out + t.clone();
        }
        return out;
    }

    fn Set(&mut self, s: string) -> goish::error {
        if s.Len() == 0 {
            return errors::New(string("empty tag"));
        }
        self.tags.push(s);
        return errors::nil;
    }
}

/// A user type that answers Go's `boolFlag` question, so `-x` may stand
/// alone without eating the next argument.
struct counter {
    n: int,
}

impl Value for counter {
    fn String(&self) -> string {
        return goish::strconv::Itoa(self.n);
    }
    fn Set(&mut self, _s: string) -> goish::error {
        self.n += 1;
        return errors::nil;
    }
    fn IsBoolFlag(&self) -> bool {
        return true;
    }
}

#[goish::main]
fn main() {
    // ── a user type, defined and parsed ─────────────────────────────
    let mut fs = flag::NewFlagSet("prog", ErrorHandling::ContinueOnError);
    let tags = fs.Var(
        alloc::boxed::Box::new(tagList { tags: Vec::new() }),
        "tag",
        "add a tag (repeatable)",
    );
    let e = fs.Parse(&goish::slice!([]string{ "-tag", "a", "-tag", "b", "rest" }));
    check(
        "a Var flag parses, repeatedly",
        e.IsNil() && tags.lock().String() == "a,b",
        fmt::Sprintf!("err=%v value=%q", e, tags.lock().String()),
    );
    check(
        "and the positional after it survives",
        fs.NArg() == 1 && fs.Arg(0) == "rest",
        fmt::Sprintf!("nargs=%d arg0=%q", fs.NArg(), fs.Arg(0)),
    );

    // ── the caller's Set error is returned verbatim ─────────────────
    let mut fs2 = flag::NewFlagSet("prog", ErrorHandling::ContinueOnError);
    let buf = goish::bytes::NewBufferString(string(""));
    fs2.SetOutput(buf);
    let _ = fs2.Var(
        alloc::boxed::Box::new(tagList { tags: Vec::new() }),
        "tag",
        "add a tag",
    );
    let e2 = fs2.Parse(&goish::slice!([]string{ "-tag", "" }));
    // Measured against Go 1.25.5: the caller's error is WRAPPED, as
    // `invalid value %q for flag -%s: %v`, not returned raw. Asserting
    // the whole string rather than a substring is what pins that — a
    // `Contains("empty tag")` would pass on the unwrapped error too.
    check(
        "the caller's Set error is wrapped exactly as Go wraps it",
        !e2.IsNil() && e2.Error() == "invalid value \"\" for flag -tag: empty tag",
        if e2.IsNil() { string("<nil>") } else { e2.Error() },
    );

    // ── IsBoolFlag: the standalone-flag question ────────────────────
    //
    // Go asks the Value, not the enum. Without this the counter would
    // swallow "rest" as its argument, and NArg would be 0 — which is
    // exactly what makes this row worth asserting rather than assuming.
    let mut fs3 = flag::NewFlagSet("prog", ErrorHandling::ContinueOnError);
    let c = fs3.Var(
        alloc::boxed::Box::new(counter { n: 0 }),
        "v",
        "increase verbosity",
    );
    let e3 = fs3.Parse(&goish::slice!([]string{ "-v", "-v", "rest" }));
    check(
        "a Value answering IsBoolFlag stands alone",
        e3.IsNil() && c.lock().String() == "2",
        fmt::Sprintf!("err=%v n=%q", e3, c.lock().String()),
    );
    check(
        "and does NOT eat the next argument",
        fs3.NArg() == 1 && fs3.Arg(0) == "rest",
        fmt::Sprintf!("nargs=%d arg0=%q", fs3.NArg(), fs3.Arg(0)),
    );

    // ── the default is captured at definition time, as Go does ──────
    let mut fs4 = flag::NewFlagSet("prog", ErrorHandling::ContinueOnError);
    let _ = fs4.Var(
        alloc::boxed::Box::new(tagList {
            tags: Vec::new(),
        }),
        "tag",
        "add a tag",
    );
    let f = fs4.Lookup(string("tag"));
    match f {
        Some(fl) => {
            check(
                "the flag is Lookup-able and carries the caller's type name",
                fl.Name == "tag",
                fl.Name.clone(),
            );
            check(
                "and its Value is the caller's, readable through flag.Value",
                fl.Value.String() == "",
                fl.Value.String(),
            );
        }
        None => {
            check("the flag is Lookup-able", false, string("Lookup returned None"));
            check("and its Value is readable", false, string("no flag"));
        }
    }

    let n = unsafe { FAILED };
    if n == 0 {
        fmt::Printf!("\nok 7/7\n");
        os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", n);
    os::Exit(1);
}
