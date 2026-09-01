// fmt_printer_ref_smoke — the printer's flags and spacing against Go.
// (fmt/print.go, fmt/format.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_fmt_printer_ref.go` run in `package
// fmt_test` by `scripts/goref.sh`.
//
// Splitting fmt/mod.rs one `.rs` per `.go` put the printer next to
// print.go and format.go for the first time. Six defects, all of them
// the kind that produce plausible-looking output:
//
//   * `Sprint` never inserted the separator. Go adds a space between
//     two operands "when neither is a string", so `Sprint(1, 2)` is
//     "1 2"; goish gave "12". `Sprint("a", 1)` was right by accident,
//     because that pair takes no space either way. The code said so —
//     "Slim: keep the same shape as print_impl — concat without
//     inserting spaces".
//   * Precision did nothing for strings. Go trims the INPUT to `prec`
//     RUNES before the verb renders it, so `%.2q` of "abc" is `"ab"`
//     quoted and `%.2x` is the hex of "ab". `%.1s` of "abc" came back
//     "abc".
//   * Precision did nothing for integers either, where it means
//     minimum digits: `%.5d` of 42 is "00042".
//   * Zero-padding went in front of the sign: `%05d` of -42 gave
//     "00-42" instead of "-0042".
//   * The '+' flag was parsed and then dropped for every verb but 'v',
//     and ' ' was not parsed at all, so `%+d` and `% d` of 42 both gave
//     "42" rather than "+42" and " 42".
//   * `%x` of a NEGATIVE integer printed the two's complement:
//     "ffffffffffffff01" for -255, where Go prints sign-and-magnitude,
//     "-ff". Same for %b, %o and %X.
//
// Still divergent, and deliberately not checked here: the three
// wrong-call forms that carry the operand's TYPE — `%!z(int=1)`,
// `%!s(int=1)`, `%!(EXTRA int=2)`. goish's FmtArg does not carry a type
// name (that is %T, still unported), so it prints the value alone.
// `%!(NOVERB)` and `%!d(MISSING)`, which need no type, are checked.

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

// go: none — goish idiom: compare one rendering against Go's, and say
//     which one differed when it does.
fn eq(ok: &mut bool, tag: &str, got: string, want: &str) {
    if got != s(want) {
        fmt::Println!(
            "   ",
            tag,
            "want",
            fmt::Sprintf!("%q", s(want)),
            "got",
            fmt::Sprintf!("%q", got)
        );
        *ok = false;
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Sprint's operand spacing: a space between two operands when
    //    NEITHER is a string.
    {
        let mut ok = true;
        eq(&mut ok, "sprint1", fmt::Sprint!("a", "b"), "ab");
        eq(&mut ok, "sprint2", fmt::Sprint!(1i64, 2i64), "1 2");
        eq(&mut ok, "sprint3", fmt::Sprint!("a", 1i64), "a1");
        eq(&mut ok, "sprint4", fmt::Sprint!(1i64, "a"), "1a");
        eq(
            &mut ok,
            "sprint5",
            fmt::Sprint!(1i64, 2i64, "a", "b", 3i64),
            "1 2ab3",
        );
        eq(&mut ok, "sprint6", fmt::Sprint!(true, false), "true false");
        eq(&mut ok, "sprint8", fmt::Sprint!("x"), "x");
        // Sprintln always separates and always terminates.
        eq(&mut ok, "sprintln1", fmt::Sprintln!("a", "b"), "a b\n");
        eq(&mut ok, "sprintln2", fmt::Sprintln!(1i64, 2i64), "1 2\n");
        report(&mut failed, ok, " 1", "Sprint spaces non-string operands");
    }

    // 2. Width and precision on strings. Precision trims the input, so
    //    it composes with quoting and with hex.
    {
        let mut ok = true;
        eq(&mut ok, "w1", fmt::Sprintf!("[%5s]", "ab"), "[   ab]");
        eq(&mut ok, "w2", fmt::Sprintf!("[%-5s]", "ab"), "[ab   ]");
        eq(&mut ok, "w3", fmt::Sprintf!("[%.1s]", "abc"), "[a]");
        eq(&mut ok, "w4", fmt::Sprintf!("[%5.1s]", "abc"), "[    a]");
        eq(&mut ok, "w5", fmt::Sprintf!("[%.0s]", "abc"), "[]");
        eq(&mut ok, "pq1", fmt::Sprintf!("%.2q", "abc"), "\"ab\"");
        eq(&mut ok, "pq2", fmt::Sprintf!("%.2v", "abc"), "ab");
        eq(&mut ok, "pq3", fmt::Sprintf!("%.2x", "abc"), "6162");
        eq(&mut ok, "pq4", fmt::Sprintf!("%.2s", "ab"), "ab");
        report(&mut failed, ok, " 2", "precision trims the string input");
    }

    // 3. The numeric flags: width, '-', '0', '+' and ' ', and precision
    //    as a minimum digit count.
    {
        let mut ok = true;
        eq(&mut ok, "w6", fmt::Sprintf!("[%5d]", 42i64), "[   42]");
        eq(&mut ok, "w7", fmt::Sprintf!("[%-5d]", 42i64), "[42   ]");
        eq(&mut ok, "w8", fmt::Sprintf!("[%05d]", 42i64), "[00042]");
        eq(&mut ok, "w9", fmt::Sprintf!("[%05d]", -42i64), "[-0042]");
        eq(&mut ok, "w10", fmt::Sprintf!("[%+d]", 42i64), "[+42]");
        eq(&mut ok, "w11", fmt::Sprintf!("[%+d]", -42i64), "[-42]");
        eq(&mut ok, "pq5", fmt::Sprintf!("%.2d", 12345i64), "12345");
        eq(&mut ok, "pq6", fmt::Sprintf!("%.5d", 42i64), "00042");
        eq(&mut ok, "pq7", fmt::Sprintf!("%+05d", 42i64), "+0042");
        eq(&mut ok, "pq8", fmt::Sprintf!("%+x", 255i64), "+ff");
        eq(&mut ok, "pq12", fmt::Sprintf!("% d", 42i64), " 42");
        // '+' is a numeric flag only: Go leaves %+s and %+q alone, and
        // %+v of an integer is just the integer.
        eq(&mut ok, "pq9", fmt::Sprintf!("%+v", 42i64), "42");
        eq(&mut ok, "pq10", fmt::Sprintf!("%+s", "a"), "a");
        eq(&mut ok, "pq11", fmt::Sprintf!("%+q", "a"), "\"a\"");
        eq(&mut ok, "w12", fmt::Sprintf!("[%5t]", true), "[ true]");
        eq(&mut ok, "w13", fmt::Sprintf!("[%5q]", "ab"), "[ \"ab\"]");
        eq(&mut ok, "w14", fmt::Sprintf!("[%5x]", "ab"), "[ 6162]");
        report(&mut failed, ok, " 3", "the numeric flags, sign included");
    }

    // 4. The bases. A negative integer prints as sign-and-magnitude in
    //    every base, not as the two's complement of the machine word.
    {
        let mut ok = true;
        eq(&mut ok, "x1", fmt::Sprintf!("%x", "abc"), "616263");
        eq(&mut ok, "x4", fmt::Sprintf!("%x", 255i64), "ff");
        eq(&mut ok, "x5", fmt::Sprintf!("%X", 255i64), "FF");
        eq(&mut ok, "x6", fmt::Sprintf!("%o", 8i64), "10");
        eq(&mut ok, "x7", fmt::Sprintf!("%b", 5i64), "101");
        eq(&mut ok, "x8", fmt::Sprintf!("%x", -255i64), "-ff");
        eq(&mut ok, "x9", fmt::Sprintf!("%X", -255i64), "-FF");
        eq(&mut ok, "x10", fmt::Sprintf!("%b", -5i64), "-101");
        eq(&mut ok, "x11", fmt::Sprintf!("%o", -8i64), "-10");
        report(&mut failed, ok, " 4", "negative integers in every base");
    }

    // 5. A wrong call is output, not an error. These two need no type
    //    name, so they are Go's exactly.
    {
        let mut ok = true;
        eq(&mut ok, "bad1", fmt::Sprintf!("%d"), "%!d(MISSING)");
        eq(
            &mut ok,
            "bad2",
            fmt::Sprintf!("%d %d", 1i64),
            "1 %!d(MISSING)",
        );
        eq(&mut ok, "bad7", fmt::Sprintf!("abc"), "abc");
        eq(&mut ok, "bad9", fmt::Sprintf!("%"), "%!(NOVERB)");
        eq(&mut ok, "bad10", fmt::Sprintf!("%!"), "%!!(MISSING)");
        eq(&mut ok, "bad11", fmt::Sprintf!("100%%"), "100%");
        report(
            &mut failed,
            ok,
            " 5",
            "a wrong call is output, not an error",
        );
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
