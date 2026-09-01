// fmt_star_ref_smoke — `%*d` and `%.*f` against a running Go.
// (fmt/print.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_fmt_star_ref.go` run in `package
// fmt_test` by `scripts/goref.sh`.
//
// `%*d` takes its WIDTH from an argument and `%.*f` its precision, and
// goish's format scanner did not know `*` at all. It was not a flag,
// not a width digit, not a precision, so it fell through to the VERB
// slot: `Sprintf("%*d", 6, 42)` consumed the 6 as the operand, rendered
// it under the meaningless verb `*`, and copied the `d` out as a
// literal. The result was "6d" — the width printed as if it were the
// value, the value never printed at all, and no padding anywhere. The
// same for `%*s`: `Sprintf("%*s", 3, "a")` gave "3s".
//
// That shape is the recurring one in this tree: it compiles, it runs,
// and it produces plausible-looking output that is wrong. A column
// built with `%*s` came out holding its own width.
//
// The vectors pin the whole surface: both signs of width, the zero and
// minus flags interacting with a negative width, `*` on both sides of
// the dot, and Go's three refusals — a non-integer operand, a magnitude
// past a million, and a negative precision.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
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

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
fn eq(failed: &mut int, got: string, want: &str, what: &str) {
    if got == s(want) {
        fmt::Println!("[ok]", what, "PASS");
    } else {
        fmt::Printf!("[!!] %s FAIL got %q want %q\n", s(what), got, s(want));
        *failed += 1;
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The bug itself, both verbs. Go: "    42" and "  a"; goish gave
    //    "6d" and "3s".
    {
        let mut ok = true;
        if fmt::Sprintf!("%*d", 6, 42) != s("    42") {
            ok = false;
        }
        if fmt::Sprintf!("%*s", 3, "a") != s("  a") {
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 1",
            "%*d and %*s take the width from an arg",
        );
    }

    // 2. The width argument's SIGN carries the alignment: Go turns a
    //    negative width into the '-' flag and a positive one. So
    //    `%*d` of (-6, 42) is left-aligned, the same as `%-*d` of
    //    (6, 42), and both differ from `%*d` of (6, 42).
    {
        eq(&mut failed, fmt::Sprintf!("%-*d", 6, 42), "42    ", "%-*d");
        eq(
            &mut failed,
            fmt::Sprintf!("%*d", -6, 42),
            "42    ",
            "%*d negative",
        );
        eq(
            &mut failed,
            fmt::Sprintf!("%*d", 0, 42),
            "42",
            "%*d zero width",
        );
    }

    // 3. The zero flag pads with zeros for a positive width and is
    //    DROPPED for a negative one — Go: "Do not pad with zeros to the
    //    right."
    {
        eq(&mut failed, fmt::Sprintf!("%0*d", 6, 42), "000042", "%0*d");
        eq(
            &mut failed,
            fmt::Sprintf!("%0*d", -6, 42),
            "42    ",
            "%0*d negative",
        );
    }

    // 4. A `*` width applies to every verb, not just the numeric ones,
    //    and composes with the '#' flag.
    {
        eq(&mut failed, fmt::Sprintf!("%*q", 6, "a"), "   \"a\"", "%*q");
        eq(&mut failed, fmt::Sprintf!("%*x", 5, 255), "   ff", "%*x");
        eq(&mut failed, fmt::Sprintf!("%#*x", 6, 255), "  0xff", "%#*x");
        eq(&mut failed, fmt::Sprintf!("%*v", 6, true), "  true", "%*v");
        eq(&mut failed, fmt::Sprintf!("%*t", 6, true), "  true", "%*t");
    }

    // 5. `.*` on the precision side, including both stars at once.
    {
        eq(
            &mut failed,
            fmt::Sprintf!("%.*f", 2, 3.14159),
            "3.14",
            "%.*f",
        );
        eq(
            &mut failed,
            fmt::Sprintf!("%.*f", 0, 3.14159),
            "3",
            "%.*f zero",
        );
        eq(
            &mut failed,
            fmt::Sprintf!("%.*s", 2, "abcdef"),
            "ab",
            "%.*s",
        );
        eq(&mut failed, fmt::Sprintf!("%.*d", 4, 42), "0042", "%.*d");
        eq(
            &mut failed,
            fmt::Sprintf!("%*.*f", 10, 2, 3.14159),
            "      3.14",
            "%*.*f",
        );
        eq(
            &mut failed,
            fmt::Sprintf!("%-*.*f", 10, 2, 3.14159),
            "3.14      ",
            "%-*.*f",
        );
    }

    // 6. Two `*` verbs in one format string consume their arguments in
    //    order, interleaved with the values. Go: "   1     2".
    {
        eq(
            &mut failed,
            fmt::Sprintf!("%*d %*d", 4, 1, 5, 2),
            "   1     2",
            "two %*d",
        );
    }

    // 7. Go's three refusals. A non-integer width, and a magnitude past
    //    a million, are both `%!(BADWIDTH)` — and the operand is
    //    CONSUMED either way, so the value still prints after the
    //    marker rather than being eaten by it. A negative `*` precision
    //    is `%!(BADPREC)` and the verb then falls back to its own
    //    default, which for %f is six places — NOT "no precision".
    {
        eq(
            &mut failed,
            fmt::Sprintf!("%*d", "x", 42),
            "%!(BADWIDTH)42",
            "%*d non-integer width",
        );
        eq(
            &mut failed,
            fmt::Sprintf!("%*d", 2000000, 42),
            "%!(BADWIDTH)42",
            "%*d width past a million",
        );
        eq(
            &mut failed,
            fmt::Sprintf!("%*d", -2000000, 42),
            "%!(BADWIDTH)42",
            "%*d width past minus a million",
        );
        eq(
            &mut failed,
            fmt::Sprintf!("%.*f", "x", 3.14),
            "%!(BADPREC)3.140000",
            "%.*f non-integer precision",
        );
        eq(
            &mut failed,
            fmt::Sprintf!("%.*f", -1, 3.14159),
            "%!(BADPREC)3.141590",
            "%.*f negative precision",
        );
    }

    // 8. A `*` that eats the last argument leaves the VERB with none,
    //    and Go reports that separately: the width was fine, the value
    //    is missing. With no arguments at all both markers appear, in
    //    the order the scanner hits them.
    {
        eq(
            &mut failed,
            fmt::Sprintf!("%*d", 6),
            "%!d(MISSING)",
            "%*d width but no value",
        );
        eq(
            &mut failed,
            fmt::Sprintf!("%*d"),
            "%!(BADWIDTH)%!d(MISSING)",
            "%*d with nothing",
        );
        eq(
            &mut failed,
            fmt::Sprintf!("%.*f", 2),
            "%!f(MISSING)",
            "%.*f precision but no value",
        );
    }

    // 9. `%*` with no verb after it is Go's NOVERB, and `%*%` is a
    //    literal percent — the width argument is still consumed by the
    //    star, but a literal takes no padding.
    {
        eq(
            &mut failed,
            fmt::Sprintf!("%*", 6),
            "%!(NOVERB)",
            "%* with no verb",
        );
        eq(&mut failed, fmt::Sprintf!("%*%", 6), "%", "%*%");
    }

    if failed == 0 {
        fmt::Println!("ok - all star-width checks match Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
