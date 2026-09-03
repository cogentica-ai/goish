// fmt_badverb_ref_smoke — %!verb(type=value) against a running Go.
// (fmt/print.go badVerb, printArg; fmt/format.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_fmt_badverb_ref.go` run in `package
// fmt_test` by `scripts/goref.sh`.
//
// Go never silently prints a value under a verb its type does not take.
// It emits `%!verb(type=value)` — a marker that survives into logs and
// golden files and says exactly what went wrong.
//
// goish had no such machinery anywhere in its printer. `%d` of a string
// printed the string. `%s` of an int printed the int. `%z` of anything
// printed the value. Every one of those is a mistake in the caller that
// Go makes loud and goish made invisible — and the invisible version is
// the worse one, because the output still looks like output.
//
// The same gap covered `%T`, which worked only for `interface{}`-typed
// values: `%T` of a plain string rendered the STRING. And extra
// arguments were dropped in silence, where Go appends
// `%!(EXTRA type=value)`.
//
// Note on the type names: several Go types share one Rust type — goish's
// `int` and `int64` are both `i64`, and `uint`, `uint64` and `uintptr`
// are all `u64` — so `%T` prints the unqualified name and a Go `int64`
// reports "int". There is no information left in the value to do better
// with.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::slice;
use goish::types::{byte, int};
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
        fmt::Println!(
            "   ",
            s(what),
            "got",
            fmt::Sprintf!("%q", got),
            "want",
            s(want)
        );
        *ok = false;
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. A string takes v, s, q, x and X — and nothing else. Go: d,
    //    b, o, O, c, U, e, f, g, t and any unknown verb all become the
    //    marker.
    {
        let mut ok = true;
        let v = s("ab");
        eq(&mut ok, "%v", fmt::Sprintf!("%v", v.clone()), "ab");
        eq(&mut ok, "%s", fmt::Sprintf!("%s", v.clone()), "ab");
        eq(&mut ok, "%q", fmt::Sprintf!("%q", v.clone()), "\"ab\"");
        eq(&mut ok, "%x", fmt::Sprintf!("%x", v.clone()), "6162");
        eq(&mut ok, "%X", fmt::Sprintf!("%X", v.clone()), "6162");
        eq(&mut ok, "%T", fmt::Sprintf!("%T", v.clone()), "string");
        for (verb, want) in [
            ("%d", "%!d(string=ab)"),
            ("%b", "%!b(string=ab)"),
            ("%o", "%!o(string=ab)"),
            ("%c", "%!c(string=ab)"),
            ("%U", "%!U(string=ab)"),
            ("%e", "%!e(string=ab)"),
            ("%f", "%!f(string=ab)"),
            ("%g", "%!g(string=ab)"),
            ("%t", "%!t(string=ab)"),
        ] {
            let got = fmt::Sprintv(
                verb,
                goish::slice!([]goish::Any{goish::Any::new(v.clone())}),
            );
            eq(&mut ok, verb, got, want);
        }
        // Go: "%!O(string=ab)" — the marker, with no "0o" in front of
        // it, because badVerb writes it instead of ever reaching
        // fmtInteger.
        eq(
            &mut ok,
            "%O",
            fmt::Sprintf!("%O", v.clone()),
            "%!O(string=ab)",
        );
        report(
            &mut failed,
            ok,
            " 1",
            "a string takes v s q x X and no more",
        );
    }

    // 2. An integer takes v, d, b, o, O, x, X, c, q and U. Go: s, e,
    //    f, g, t and p are all markers — and `%q` of an int is the RUNE
    //    quote, which is easy to mistake for a bad verb and is not one.
    {
        let mut ok = true;
        let n: int = 42;
        eq(&mut ok, "%v", fmt::Sprintf!("%v", n), "42");
        eq(&mut ok, "%d", fmt::Sprintf!("%d", n), "42");
        eq(&mut ok, "%b", fmt::Sprintf!("%b", n), "101010");
        eq(&mut ok, "%o", fmt::Sprintf!("%o", n), "52");
        eq(&mut ok, "%O", fmt::Sprintf!("%O", n), "0o52");
        eq(&mut ok, "%x", fmt::Sprintf!("%x", n), "2a");
        eq(&mut ok, "%X", fmt::Sprintf!("%X", n), "2A");
        eq(&mut ok, "%c", fmt::Sprintf!("%c", n), "*");
        eq(&mut ok, "%q", fmt::Sprintf!("%q", n), "'*'");
        eq(&mut ok, "%U", fmt::Sprintf!("%U", n), "U+002A");
        eq(&mut ok, "%T", fmt::Sprintf!("%T", n), "int");
        eq(&mut ok, "%s", fmt::Sprintf!("%s", n), "%!s(int=42)");
        eq(&mut ok, "%e", fmt::Sprintf!("%e", n), "%!e(int=42)");
        eq(&mut ok, "%f", fmt::Sprintf!("%f", n), "%!f(int=42)");
        eq(&mut ok, "%g", fmt::Sprintf!("%g", n), "%!g(int=42)");
        eq(&mut ok, "%t", fmt::Sprintf!("%t", n), "%!t(int=42)");
        // Go: byte(65) and rune('x') report uint8 and int32.
        let b: byte = 65;
        eq(&mut ok, "byte %T", fmt::Sprintf!("%T", b), "uint8");
        eq(&mut ok, "byte %s", fmt::Sprintf!("%s", b), "%!s(uint8=65)");
        eq(&mut ok, "byte %c", fmt::Sprintf!("%c", b), "A");
        let r: goish::types::rune = 120;
        eq(&mut ok, "rune %T", fmt::Sprintf!("%T", r), "int32");
        eq(&mut ok, "rune %U", fmt::Sprintf!("%U", r), "U+0078");
        report(
            &mut failed,
            ok,
            " 2",
            "an integer takes v d b o O x X c q U",
        );
    }

    // 3. A float takes v, b, e, E, f, F, g, G, x and X. Go: s, q, d, o,
    //    O, c, U and t are markers.
    {
        let mut ok = true;
        let x = 3.5f64;
        eq(&mut ok, "%v", fmt::Sprintf!("%v", x), "3.5");
        eq(&mut ok, "%e", fmt::Sprintf!("%e", x), "3.500000e+00");
        eq(&mut ok, "%f", fmt::Sprintf!("%f", x), "3.500000");
        eq(&mut ok, "%g", fmt::Sprintf!("%g", x), "3.5");
        eq(&mut ok, "%T", fmt::Sprintf!("%T", x), "float64");
        eq(&mut ok, "%s", fmt::Sprintf!("%s", x), "%!s(float64=3.5)");
        eq(&mut ok, "%q", fmt::Sprintf!("%q", x), "%!q(float64=3.5)");
        eq(&mut ok, "%d", fmt::Sprintf!("%d", x), "%!d(float64=3.5)");
        eq(&mut ok, "%o", fmt::Sprintf!("%o", x), "%!o(float64=3.5)");
        eq(&mut ok, "%c", fmt::Sprintf!("%c", x), "%!c(float64=3.5)");
        eq(&mut ok, "%U", fmt::Sprintf!("%U", x), "%!U(float64=3.5)");
        eq(&mut ok, "%t", fmt::Sprintf!("%t", x), "%!t(float64=3.5)");
        let f32v = 1.5f32;
        eq(&mut ok, "f32 %T", fmt::Sprintf!("%T", f32v), "float32");
        eq(
            &mut ok,
            "f32 %d",
            fmt::Sprintf!("%d", f32v),
            "%!d(float32=1.5)",
        );
        report(&mut failed, ok, " 3", "a float takes v b e E f F g G x X");
    }

    // 4. A bool takes v and t, and nothing else at all.
    {
        let mut ok = true;
        eq(&mut ok, "%v", fmt::Sprintf!("%v", true), "true");
        eq(&mut ok, "%t", fmt::Sprintf!("%t", true), "true");
        eq(&mut ok, "%T", fmt::Sprintf!("%T", true), "bool");
        for (verb, want) in [
            ("%s", "%!s(bool=true)"),
            ("%q", "%!q(bool=true)"),
            ("%d", "%!d(bool=true)"),
            ("%x", "%!x(bool=true)"),
            ("%c", "%!c(bool=true)"),
            ("%f", "%!f(bool=true)"),
        ] {
            let got = fmt::Sprintv(verb, goish::slice!([]goish::Any{goish::Any::new(true)}));
            eq(&mut ok, verb, got, want);
        }
        report(&mut failed, ok, " 4", "a bool takes v and t");
    }

    // 5. `[]byte` is the exception: %s, %q, %x and %X treat it as text
    //    and every other verb walks the slice, so the marker comes from
    //    each ELEMENT's own table. Go: e="[%!e(uint8=97) %!e(uint8=98)]".
    {
        let mut ok = true;
        let b = goish::bytes("ab");
        eq(&mut ok, "%T", fmt::Sprintf!("%T", b.clone()), "[]uint8");
        eq(&mut ok, "%v", fmt::Sprintf!("%v", b.clone()), "[97 98]");
        eq(&mut ok, "%s", fmt::Sprintf!("%s", b.clone()), "ab");
        eq(&mut ok, "%x", fmt::Sprintf!("%x", b.clone()), "6162");
        eq(&mut ok, "%d", fmt::Sprintf!("%d", b.clone()), "[97 98]");
        eq(
            &mut ok,
            "%b",
            fmt::Sprintf!("%b", b.clone()),
            "[1100001 1100010]",
        );
        eq(&mut ok, "%c", fmt::Sprintf!("%c", b.clone()), "[a b]");
        eq(
            &mut ok,
            "%U",
            fmt::Sprintf!("%U", b.clone()),
            "[U+0061 U+0062]",
        );
        eq(
            &mut ok,
            "%e",
            fmt::Sprintf!("%e", b.clone()),
            "[%!e(uint8=97) %!e(uint8=98)]",
        );
        eq(
            &mut ok,
            "%t",
            fmt::Sprintf!("%t", b.clone()),
            "[%!t(uint8=97) %!t(uint8=98)]",
        );
        report(
            &mut failed,
            ok,
            " 5",
            "[]byte: text verbs whole, the rest per element",
        );
    }

    // 6. Extra arguments. Go: `Sprintf("%d", 1, 2)` is "1%!(EXTRA
    //    int=2)"; a format with no verb at all still reports them; and
    //    several are comma-separated. goish dropped them in silence, so
    //    an argument that went nowhere left no trace.
    {
        let mut ok = true;
        let one: int = 1;
        let two: int = 2;
        eq(
            &mut ok,
            "one extra",
            fmt::Sprintf!("%d", one, two),
            "1%!(EXTRA int=2)",
        );
        eq(
            &mut ok,
            "no verb",
            fmt::Sprintf!("x", one),
            "x%!(EXTRA int=1)",
        );
        eq(
            &mut ok,
            "two extras",
            fmt::Sprintf!("%d", one, s("s"), 2.5f64),
            "1%!(EXTRA string=s, float64=2.5)",
        );
        // Missing arguments were already reported; check they still are.
        eq(
            &mut ok,
            "missing",
            fmt::Sprintf!("%d %d", one),
            "1 %!d(MISSING)",
        );
        eq(&mut ok, "noverb", fmt::Sprintf!("abc%"), "abc%!(NOVERB)");
        // Go: "%!" is the unknown verb '!', so it takes the marker too.
        eq(&mut ok, "bang", fmt::Sprintf!("%!", one), "%!!(int=1)");
        // Go: `%#z` drops the flag from the marker.
        eq(&mut ok, "sharp z", fmt::Sprintf!("%#z", one), "%!z(int=1)");
        report(
            &mut failed,
            ok,
            " 6",
            "extra, missing and unknown are all reported",
        );
    }

    // 7. The gap that remains, recorded rather than hidden. The '#'
    //    flag's base prefix and a WIDTH are both applied by the format
    //    scanner over the FINISHED bytes, so over a composite they used
    //    to wrap the whole rendering instead of distributing to each
    //    element:
    //
    //      Go   `%O` of []byte("ab")   ->  "[0o141 0o142]"
    //      goish (before)              ->  "0o[141 142]"
    //      Go   `%3d` of []int{1,2,30} ->  "[  1   2  30]"
    //      goish (before)              ->  "[1 2 30]"
    //
    //    Both had one root cause: goish's `Format` trait carried the
    //    verb and the precision but neither the width nor the flags.
    //    Both are fixed — the compound renderers take a width and repeat
    //    the base prefix per element — so these assert Go's answers now.
    //    A bad-verb marker takes no prefix, which is why the map case
    //    below reads `%!O(string=a)` and not `0o%!O(string=a)`.
    {
        let mut ok = true;
        eq(
            &mut ok,
            "%O over []byte",
            fmt::Sprintf!("%O", goish::bytes("ab")),
            "[0o141 0o142]",
        );
        let ii: slice<int> = goish::slice!([]int{1, 2, 30});
        eq(
            &mut ok,
            "%3d over []int",
            fmt::Sprintf!("%3d", ii),
            "[  1   2  30]",
        );
        report(&mut failed, ok, " 7", "width and flags reach each element");
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
