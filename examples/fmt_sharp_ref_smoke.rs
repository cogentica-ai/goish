// fmt_sharp_ref_smoke — the '#' flag against a running Go.
// (fmt/format.go, fmt/print.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_fmt_sharp_ref.go` run in `package
// fmt_test` by `scripts/goref.sh`.
//
// goish's printf scanner did not know '#' was a flag. It parsed the
// flags it knew ('-', '0', '+', ' '), then the width, then the
// precision, and then took the next byte as the VERB — so in `%#x` the
// verb was '#', the argument was consumed by a verb that means nothing,
// and the real 'x' was copied to the output as a literal. Every `%#x`
// in a ported program printed garbage, and so did `%#v`, `%#o`, `%#q`
// and `%#U`.
//
// `%O` and `%U` did not exist either: both fell through to the decimal
// default, so `%U` of 'x' printed "120".
//
// The prefixes are applied where the width is known, because Go inserts
// them between the sign and the ZERO PADDING — `%#08x` of 255 is
// "0x000000ff", ten characters wide, not eight. Go turns a zero-padding
// width into a digit precision first, and the prefix does not count
// toward it.

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

// go: none — goish idiom: compare one rendering against Go's and say
//     what differed.
fn eq(ok: &mut bool, what: &str, got: string, want: &str) {
    if got != s(want) {
        fmt::Println!("   ", s(what), "got", got, "want", s(want));
        *ok = false;
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The integer bases, signed. Columns are Go's, verbatim:
    //    (n, %b, %#b, %o, %#o, %O, %#O, %x, %#x, %X, %#X)
    //
    //    Note `%#o` of 0 is "0" and not "00": Go adds the leading zero
    //    only when the first digit is not already one.
    {
        let mut ok = true;
        let cases: [(
            i64,
            &str,
            &str,
            &str,
            &str,
            &str,
            &str,
            &str,
            &str,
            &str,
            &str,
        ); 8] = [
            (
                0, "0", "0b0", "0", "0", "0o0", "0o0", "0", "0x0", "0", "0X0",
            ),
            (
                1, "1", "0b1", "1", "01", "0o1", "0o01", "1", "0x1", "1", "0X1",
            ),
            (
                7, "111", "0b111", "7", "07", "0o7", "0o07", "7", "0x7", "7", "0X7",
            ),
            (
                8, "1000", "0b1000", "10", "010", "0o10", "0o010", "8", "0x8", "8", "0X8",
            ),
            (
                255,
                "11111111",
                "0b11111111",
                "377",
                "0377",
                "0o377",
                "0o0377",
                "ff",
                "0xff",
                "FF",
                "0XFF",
            ),
            (
                256,
                "100000000",
                "0b100000000",
                "400",
                "0400",
                "0o400",
                "0o0400",
                "100",
                "0x100",
                "100",
                "0X100",
            ),
            (
                -1, "-1", "-0b1", "-1", "-01", "-0o1", "-0o01", "-1", "-0x1", "-1", "-0X1",
            ),
            (
                -255,
                "-11111111",
                "-0b11111111",
                "-377",
                "-0377",
                "-0o377",
                "-0o0377",
                "-ff",
                "-0xff",
                "-FF",
                "-0XFF",
            ),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (n, b, sb, o, so, cap_o, s_cap_o, x, sx, cap_x, s_cap_x) = cases[i];
            eq(&mut ok, "%b", fmt::Sprintf!("%b", n), b);
            eq(&mut ok, "%#b", fmt::Sprintf!("%#b", n), sb);
            eq(&mut ok, "%o", fmt::Sprintf!("%o", n), o);
            eq(&mut ok, "%#o", fmt::Sprintf!("%#o", n), so);
            eq(&mut ok, "%O", fmt::Sprintf!("%O", n), cap_o);
            eq(&mut ok, "%#O", fmt::Sprintf!("%#O", n), s_cap_o);
            eq(&mut ok, "%x", fmt::Sprintf!("%x", n), x);
            eq(&mut ok, "%#x", fmt::Sprintf!("%#x", n), sx);
            eq(&mut ok, "%X", fmt::Sprintf!("%X", n), cap_x);
            eq(&mut ok, "%#X", fmt::Sprintf!("%#X", n), s_cap_x);
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 1",
            "the integer bases, with and without #",
        );
    }

    // 2. Unsigned takes the same prefixes.
    {
        let mut ok = true;
        let cases: [(u64, &str, &str, &str, &str); 4] = [
            (0, "0b0", "0", "0x0", "0X0"),
            (1, "0b1", "01", "0x1", "0X1"),
            (255, "0b11111111", "0377", "0xff", "0XFF"),
            (4096, "0b1000000000000", "010000", "0x1000", "0X1000"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (n, b, o, x, cx) = cases[i];
            eq(&mut ok, "u %#b", fmt::Sprintf!("%#b", n), b);
            eq(&mut ok, "u %#o", fmt::Sprintf!("%#o", n), o);
            eq(&mut ok, "u %#x", fmt::Sprintf!("%#x", n), x);
            eq(&mut ok, "u %#X", fmt::Sprintf!("%#X", n), cx);
            i += 1;
        }
        report(&mut failed, ok, " 2", "unsigned takes the same prefixes");
    }

    // 3. Strings take %x/%#x too, and the prefix appears ONCE — not per
    //    byte — and not at all for an empty string.
    {
        let mut ok = true;
        let cases: [(&str, &str, &str, &str, &str); 4] = [
            ("", "", "", "", ""),
            ("a", "61", "0x61", "61", "0X61"),
            ("abc", "616263", "0x616263", "616263", "0X616263"),
            ("\u{ff}\u{0}", "c3bf00", "0xc3bf00", "C3BF00", "0XC3BF00"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (v, x, sx, cx, scx) = cases[i];
            eq(&mut ok, "s %x", fmt::Sprintf!("%x", v), x);
            eq(&mut ok, "s %#x", fmt::Sprintf!("%#x", v), sx);
            eq(&mut ok, "s %X", fmt::Sprintf!("%X", v), cx);
            eq(&mut ok, "s %#X", fmt::Sprintf!("%#X", v), scx);
            i += 1;
        }
        report(&mut failed, ok, " 3", "a string's hex takes one prefix");
    }

    // 4. `%#q` back-quotes when strconv.CanBackquote allows it, and
    //    falls back to `%q` when it does not. Go: "a\nb" cannot be
    //    back-quoted, and neither can a string containing a backquote.
    {
        let mut ok = true;
        let cases: [(&str, &str, &str); 6] = [
            ("abc", "\"abc\"", "`abc`"),
            ("a\nb", "\"a\\nb\"", "\"a\\nb\""),
            ("a`b", "\"a`b\"", "\"a`b\""),
            ("a\"b", "\"a\\\"b\"", "`a\"b`"),
            ("h\u{e9}llo", "\"h\u{e9}llo\"", "`h\u{e9}llo`"),
            ("a\tb", "\"a\\tb\"", "`a\tb`"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (v, q, sq) = cases[i];
            eq(&mut ok, "%q", fmt::Sprintf!("%q", v), q);
            eq(&mut ok, "%#q", fmt::Sprintf!("%#q", v), sq);
            i += 1;
        }
        report(&mut failed, ok, " 4", "%#q back-quotes, or falls back");
    }

    // 5. `%U` and `%#U`. At least four hex digits, upper case, and with
    //    '#' the character in single quotes — but only when it is
    //    printable, so '\n' and U+10FFFF get none.
    {
        let mut ok = true;
        let cases: [(i64, &str, &str); 5] = [
            (0x78, "U+0078", "U+0078 'x'"),
            (0xE9, "U+00E9", "U+00E9 '\u{e9}'"),
            (0x0A, "U+000A", "U+000A"),
            (0x10FFFF, "U+10FFFF", "U+10FFFF"),
            (0, "U+0000", "U+0000"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (r, u, su) = cases[i];
            eq(&mut ok, "%U", fmt::Sprintf!("%U", r), u);
            eq(&mut ok, "%#U", fmt::Sprintf!("%#U", r), su);
            i += 1;
        }
        report(&mut failed, ok, " 5", "%U and %#U");
    }

    // 6. Width and zero padding compose with '#'. This is the check
    //    that pins WHERE the prefix goes: Go turns a zero-padding width
    //    into a digit precision and adds the prefix on top, so `%#08x`
    //    of 255 is ten characters and `%08x` of 255 is eight.
    {
        let mut ok = true;
        eq(&mut ok, "%#8x", fmt::Sprintf!("%#8x", 255), "    0xff");
        eq(&mut ok, "%#-8x", fmt::Sprintf!("%#-8x|", 255), "0xff    |");
        eq(&mut ok, "%#08x", fmt::Sprintf!("%#08x", 255), "0x000000ff");
        eq(&mut ok, "%08x", fmt::Sprintf!("%08x", 255), "000000ff");
        eq(&mut ok, "%#8o", fmt::Sprintf!("%#8o", 8), "     010");
        eq(&mut ok, "%#08b", fmt::Sprintf!("%#08b", 5), "0b00000101");
        report(
            &mut failed,
            ok,
            " 6",
            "the prefix does not count toward %0N",
        );
    }

    // 7. '#' on a verb that does not use it is not an error in Go — it
    //    is simply ignored.
    {
        let mut ok = true;
        eq(&mut ok, "%#s", fmt::Sprintf!("%#s", "ab"), "ab");
        eq(&mut ok, "%#d", fmt::Sprintf!("%#d", 42), "42");
        eq(&mut ok, "%#f", fmt::Sprintf!("%#f", 1.5), "1.500000");
        eq(&mut ok, "%#c", fmt::Sprintf!("%#c", 0x78), "x");
        report(&mut failed, ok, " 7", "# is ignored where it means nothing");
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
