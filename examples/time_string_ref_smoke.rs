// time_string_ref_smoke — Time.String against a running Go.
// (time/format.go, time/time.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_time_string_ref.go` run in
// `package time_test` by `scripts/goref.sh`.
//
// `Time.String` did not exist, and neither did the `fmt::Format` bridge
// for `Time`. In Go, `fmt.Println(t)` is the most ordinary thing anyone
// does with a time; in goish the macro did not compile — the error was
// `the method fmt_arg exists ... but its trait bounds were not
// satisfied`, which reads as a macro problem rather than a missing
// method. Splitting time/mod.rs one `.rs` per `.go` is what surfaced
// it: `String` is declared in format.go, and format.go's GOISH018 list
// named it along with the other 25 functions that file is missing.
//
// String is not a separate renderer. Go calls Format with one fixed
// layout — "2006-01-02 15:04:05.999999999 -0700 MST" — and appends the
// monotonic reading when there is one. The `.999999999` chunk is the
// interesting part: it trims trailing zeros and disappears entirely
// when the fraction is zero, so the vectors below walk one nanosecond,
// one microsecond, a tenth, a hundredth and a full nine digits.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::time;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// (sec, nsec, want) — Go 1.25.5, verbatim.
const CASES: [(int, int, &str); 12] = [
    (0, 0, "1970-01-01 00:00:00 +0000 UTC"),
    (1, 0, "1970-01-01 00:00:01 +0000 UTC"),
    (-1, 0, "1969-12-31 23:59:59 +0000 UTC"),
    (
        1_700_000_000,
        123_456_789,
        "2023-11-14 22:13:20.123456789 +0000 UTC",
    ),
    (1_700_000_000, 0, "2023-11-14 22:13:20 +0000 UTC"),
    (
        1_700_000_000,
        100_000_000,
        "2023-11-14 22:13:20.1 +0000 UTC",
    ),
    (
        1_700_000_000,
        120_000_000,
        "2023-11-14 22:13:20.12 +0000 UTC",
    ),
    (1_700_000_000, 1, "2023-11-14 22:13:20.000000001 +0000 UTC"),
    (
        1_700_000_000,
        999_999_999,
        "2023-11-14 22:13:20.999999999 +0000 UTC",
    ),
    (1_700_000_000, 1_000, "2023-11-14 22:13:20.000001 +0000 UTC"),
    (-62_135_596_800, 0, "0001-01-01 00:00:00 +0000 UTC"),
    (
        253_402_300_799,
        999_999_999,
        "9999-12-31 23:59:59.999999999 +0000 UTC",
    ),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Time.String over the fractional-second boundaries.
    {
        let mut ok = true;
        let mut i = 0;
        while i < CASES.len() {
            let (sec, nsec, want) = CASES[i];
            if time::Unix(sec, nsec).String() != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "Time.String trims the fraction");
    }

    // 2. The zero Time renders as year 1, not as the epoch — the same
    //    invariant time_zero_smoke pins, reached through String.
    {
        let z = time::Time::default();
        let ok = z.String() == s("0001-01-01 00:00:00 +0000 UTC");
        report(&mut failed, ok, " 2", "the zero Time prints as year 1");
    }

    // 3. `%v`, `%s` and a bare Println! all reach String — in Go via
    //    the Stringer interface, here via the fmt::Format bridge. All
    //    three of these failed to COMPILE before the bridge existed.
    {
        let mut ok = true;
        let t = time::Unix(1_700_000_000, 123_456_789);
        let want = s("2023-11-14 22:13:20.123456789 +0000 UTC");
        if fmt::Sprintf!("%v", t) != want {
            ok = false;
        }
        if fmt::Sprintf!("%s", t) != want {
            ok = false;
        }
        if fmt::Sprint!(t) != want {
            ok = false;
        }
        report(&mut failed, ok, " 3", "%v, %s and Sprint reach String");
    }

    // 4. Explicitly formatting with String's own layout gives the same
    //    answer — which is the claim String makes about itself.
    {
        let mut ok = true;
        let mut i = 0;
        while i < CASES.len() {
            let (sec, nsec, want) = CASES[i];
            let t = time::Unix(sec, nsec);
            if t.Format("2006-01-02 15:04:05.999999999 -0700 MST") != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "String is Format with one layout");
    }

    // 5. A Time carrying a monotonic reading gets Go's ` m=±ddd.nnnnnnnnn`
    //    suffix. The value is machine-dependent, so this checks the
    //    shape: the wall part still parses, and the suffix is there
    //    with a sign and a nine-digit fraction.
    {
        let mut ok = true;
        let now = time::Now();
        let text = now.String();
        let b = text.as_bytes();
        // " m=" appears, and the tail after it is [+-]digits.digits.
        let mut at: i64 = -1;
        let mut i = 0usize;
        while i + 3 <= b.len() {
            if b[i] == b' ' && b[i + 1] == b'm' && b[i + 2] == b'=' {
                at = i as i64;
            }
            i += 1;
        }
        if at < 0 {
            ok = false;
        } else {
            let tail = &b[at as usize + 3..];
            if tail.is_empty() || (tail[0] != b'+' && tail[0] != b'-') {
                ok = false;
            }
            let mut dots = 0;
            let mut frac = 0;
            let mut j = 1usize;
            while j < tail.len() {
                if tail[j] == b'.' {
                    dots += 1;
                } else if dots == 1 {
                    frac += 1;
                }
                j += 1;
            }
            if dots != 1 || frac != 9 {
                ok = false;
            }
            // The wall part is still the ordinary rendering.
            if at < 20 {
                ok = false;
            }
        }
        // A Time without a monotonic reading has no suffix at all.
        if time::Unix(1, 0).String() != s("1970-01-01 00:00:01 +0000 UTC") {
            ok = false;
        }
        report(&mut failed, ok, " 5", "the monotonic suffix, when present");
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
