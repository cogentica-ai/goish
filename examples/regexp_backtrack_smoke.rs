// regexp_backtrack_smoke — the nested-quantifier ANSWERS are right,
// and the cost is not.
//
// goish's regexp is a backtracking matcher where Go's simulates an NFA
// (RE2). Go's package documentation promises "guaranteed to run in
// time linear in the size of the input"; this does not keep that
// promise, and the difference is exponential rather than constant-
// factor. Measured 2026-09-05 with `(a+)+$` against n 'a's then '!',
// against a Go that answers every size in under a millisecond:
//
//     n=10      5 ms          n=20   5,939 ms
//     n=14     95 ms          n=21  13,124 ms
//     n=18  1,419 ms          n=22  27,338 ms
//
// n=24 did not finish inside a 60-second timeout. Each character
// roughly doubles the work, so n=30 is about two hours.
//
// This file deliberately does NOT assert on timing — a clock
// assertion in CI is flaky, and the numbers above belong in a comment
// where they can be read rather than in a threshold that will one day
// fail for an unrelated reason. What it asserts is that the ANSWERS
// match Go, because that is the part a future RE2 rewrite must not
// change, and it keeps n small enough that this stays a fast test.
//
// The divergence itself is recorded in src/regexp/mod.rs and
// ROADMAP.md 2c.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::regexp;
use goish::strings;
use goish::types::int;

#[goish::main]
fn main() {
    let mut bad: int = 0;

    // The pathological shape, at sizes that stay quick.
    let re = regexp::MustCompile("(a+)+$");
    for (n, want) in [(4i64, false), (8, false), (12, false)].iter() {
        let s = strings::Repeat("a", *n) + "!";
        let got = re.MatchString(&s);
        if got == *want {
            fmt::Printf!("[ok] (a+)+$ n=%-3d match=%v\n", *n as int, got);
        } else {
            fmt::Printf!("[!!] (a+)+$ n=%-3d match=%v want=%v\n", *n as int, got, *want);
            bad += 1;
        }
    }

    // The same pattern WITH the trailing anchor satisfied: it must
    // match, and quickly, because no backtracking is needed.
    let s = strings::Repeat("a", 12);
    if re.MatchString(&s) {
        fmt::Printf!("[ok] (a+)+$ matching input          match=true\n");
    } else {
        fmt::Printf!("[!!] (a+)+$ matching input          match=false\n");
        bad += 1;
    }

    // A nested quantifier that Go and goish both answer instantly,
    // pinned so a future engine change has a correctness baseline.
    let re2 = regexp::MustCompile("^(a|aa)+$");
    for (s, want) in [("aaaa", true), ("aaab", false)].iter() {
        let got = re2.MatchString(*s);
        if got == *want {
            fmt::Printf!("[ok] ^(a|aa)+$ %-6s match=%v\n", *s, got);
        } else {
            fmt::Printf!("[!!] ^(a|aa)+$ %-6s match=%v want=%v\n", *s, got, *want);
            bad += 1;
        }
    }

    if bad == 0 {
        fmt::Printf!("regexp_backtrack_smoke: all checks passed\n");
    } else {
        fmt::Printf!("regexp_backtrack_smoke: %v FAILED\n", bad);
    }
}
