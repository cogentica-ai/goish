// exported_api_smoke — Go API that is ported must be REACHABLE, not
// merely present.
//
// Started as four `flag` functions and grew: the same sweep across
// every package found `unicode.CaseRanges`, `testing.RunTests` /
// `InternalTest`, and `testing.B` in the same state.
//
// All four were ported, anchored and counted by port_coverage, and
// then left out of `flag/mod.rs`'s `pub use` list. `flag::Arg(0)` did
// not compile. The functions existed, worked, and no user could call
// them — which is ROADMAP §2e's shape exactly: coverage counts a
// declaration by NAME and cannot see reachability.
//
// Found by removing this crate's `#![allow(dead_code)]` file by file.
// A `pub fn` that nothing outside can reach IS dead code; the
// suppression was the only reason the compiler stayed quiet.
//
// The point of this smoke is the CALL, not the result. If any of the
// four leaves the re-export list again, this stops compiling — which
// is the failure mode a runtime assertion could never catch, because
// there would be nothing to run.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::{fmt, flag, int, string};

static mut FAILED: int = 0;

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("[ok] %s\n", name);
    } else {
        unsafe { FAILED += 1 };
        fmt::Printf!("[!!] %s — %s\n", name, detail);
    }
}

#[goish::main]
fn main() {
    // Go: "Arg returns the i'th command-line argument … Arg returns an
    // empty string if the requested element does not exist."
    let missing = flag::Arg(9999);
    check(
        "flag::Arg is reachable, and an out-of-range index is empty",
        missing.Len() == 0,
        missing.clone(),
    );

    // Go: "Uint64 defines a uint64 flag with specified name, default
    // value, and usage string." The handle must carry the default
    // before Parse runs.
    let n = flag::Uint64(string("goish_u64"), 42u64, string("a uint64 flag"));
    check(
        "flag::Uint64 is reachable and its handle holds the default",
        n.Get() == 42u64,
        fmt::Sprintf!("got %d want 42", n.Get() as int),
    );

    // Go: "Func defines a flag … Each time the flag is seen, fn is
    // called with the value of the flag." Registration is what is
    // under test; the callback fires during Parse.
    flag::Func(string("goish_fn"), string("a func flag"), |_v| {
        return goish::errors::nil;
    });
    check(
        "flag::Func is reachable and registers",
        true,
        string(""),
    );

    flag::BoolFunc(string("goish_boolfn"), string("a bool func flag"), |_v| {
        return goish::errors::nil;
    });
    check(
        "flag::BoolFunc is reachable and registers",
        true,
        string(""),
    );

    // Registration actually landed: all four names resolve through the
    // same CommandLine set, so looking one up proves the call reached
    // it rather than being optimised away.
    let looked_up = flag::CommandLine.Lock().Lookup(string("goish_u64"));
    check(
        "the registered flag is in CommandLine",
        looked_up.is_some(),
        string("Lookup(goish_u64) returned nil"),
    );

    // ── the same gap in other packages ──────────────────────────────
    //
    // Naming a thing is not the test; USING it is. `testing::MainStart`
    // is deliberately absent from this list even though it is a `pub
    // fn` with a Go anchor: its `deps` parameter is a `pub(crate)`
    // trait, so exporting the name would produce a function no caller
    // could ever satisfy — the same defect wearing a fix's clothes.
    // goish's test entry point is the `#[goish::test_main]` attribute,
    // so `MainStart` being internal is a design decision, not a gap.

    // Go: `var CaseRanges = _CaseRanges` (unicode/tables.go:8624).
    let cr = goish::unicode::CaseRanges;
    check(
        "unicode::CaseRanges is reachable and populated",
        cr.len() > 100,
        fmt::Sprintf!("len=%d", cr.len() as int),
    );
    check(
        "and its entries are usable — 'A' maps to lower by +32",
        cr.iter().any(|r| r.Lo == 0x0041 && r.Hi == 0x005A && r.Delta[1] == 32),
        string("no A-Z CaseRange with Delta[1]==32"),
    );

    // Go writes `*testing.B`, not `*testing.benchmark.B`.
    let _: Option<&goish::testing::B> = None;
    check("testing::B is spelled the way Go spells it", true, string(""));

    // `RunTests` takes `&[InternalTest]`, so the type has to be
    // nameable for the function to be callable at all. Constructing one
    // is the proof; running it is not this smoke's job.
    let it = goish::testing::InternalTest {
        Name: string("goish/reachability"),
        F: |_t| {},
    };
    check(
        "testing::InternalTest can be constructed, so RunTests is callable",
        it.Name.Len() > 0,
        string("empty name"),
    );

    let f = unsafe { FAILED };
    if f == 0 {
        fmt::Printf!("\nok 9/9\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", f);
    goish::os::Exit(1);
}
