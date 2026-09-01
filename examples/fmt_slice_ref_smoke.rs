// fmt_slice_ref_smoke — printing slices and maps, against a running Go.
// (fmt/print.go printValue, fmt/format.go fmtBytes)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_fmt_slice_ref.go` run in `package
// fmt_test` by `scripts/goref.sh`.
//
// Go's printer reflects over the value, so a `[]string` or a
// `map[string]int` needs no per-type support. goish's dispatches on the
// `Format` trait, and `slice<T>` had an impl for exactly one T: `byte`.
// Every other slice, and every map, failed to compile AT THE CALL —
// `fmt.Println(names)` on a `[]string`, about as ordinary as Go gets,
// was a type error. That is how this was found: writing a probe for
// something else, the probe would not build.
//
// `[]byte` was wrong in the other direction. In Go `%v` and `%d` print
// the NUMBERS and only `%s`, `%q`, `%x`, `%X` treat the bytes as text;
// goish sent every verb to the text path. So `fmt.Println(b)` on
// `[]byte("abc")` printed "abc" where Go prints "[97 98 99]", and a
// byte slice that is not valid UTF-8 printed replacement characters
// where Go prints a list of numbers.
//
// A map prints with its keys SORTED, because Go's map iteration order
// is randomised and a printer that followed it would give a different
// string on every run.

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

    // 1. `[]byte`: %v and %d are the numbers, %s/%q/%x/%X the text.
    //    Go: bytes v="[1 2 255]" s="\x01\x02\xff" q="\"\\x01\\x02\\xff\""
    //    x="0102ff" X="0102FF" d="[1 2 255]".
    {
        let mut ok = true;
        let raw: slice<byte> = goish::slice!([]u8{1u8, 2u8, 255u8});
        eq(
            &mut ok,
            "raw %v",
            fmt::Sprintf!("%v", raw.clone()),
            "[1 2 255]",
        );
        eq(
            &mut ok,
            "raw %d",
            fmt::Sprintf!("%d", raw.clone()),
            "[1 2 255]",
        );
        eq(
            &mut ok,
            "raw %x",
            fmt::Sprintf!("%x", raw.clone()),
            "0102ff",
        );
        eq(
            &mut ok,
            "raw %X",
            fmt::Sprintf!("%X", raw.clone()),
            "0102FF",
        );
        eq(
            &mut ok,
            "raw %q",
            fmt::Sprintf!("%q", raw.clone()),
            "\"\\x01\\x02\\xff\"",
        );
        // Go: abc v="[97 98 99]" s="abc" q="\"abc\"" x="616263".
        let abc = goish::bytes("abc");
        eq(
            &mut ok,
            "abc %v",
            fmt::Sprintf!("%v", abc.clone()),
            "[97 98 99]",
        );
        eq(&mut ok, "abc %s", fmt::Sprintf!("%s", abc.clone()), "abc");
        eq(
            &mut ok,
            "abc %q",
            fmt::Sprintf!("%q", abc.clone()),
            "\"abc\"",
        );
        eq(
            &mut ok,
            "abc %x",
            fmt::Sprintf!("%x", abc.clone()),
            "616263",
        );
        // Go: bempty v="[]" s="" x="" — and a nil []byte is "[]" too.
        let e: slice<byte> = slice::new();
        eq(&mut ok, "empty %v", fmt::Sprintf!("%v", e.clone()), "[]");
        eq(&mut ok, "empty %s", fmt::Sprintf!("%s", e.clone()), "");
        eq(&mut ok, "empty %x", fmt::Sprintf!("%x", e.clone()), "");
        report(&mut failed, ok, " 1", "[]byte: %v is numbers, %s is text");
    }

    // 2. A `[]string`. Go: strs v="[a b c ]" s="[a b c ]"
    //    q="[\"a\" \"b c\" \"\"]" — the trailing space is the empty
    //    third element, and the brackets are always there.
    {
        let mut ok = true;
        let ss: slice<string> =
            goish::slice!([]string{string::from("a"), string::from("b c"), string::from("")});
        eq(
            &mut ok,
            "strs %v",
            fmt::Sprintf!("%v", ss.clone()),
            "[a b c ]",
        );
        eq(
            &mut ok,
            "strs %s",
            fmt::Sprintf!("%s", ss.clone()),
            "[a b c ]",
        );
        eq(
            &mut ok,
            "strs %q",
            fmt::Sprintf!("%q", ss.clone()),
            "[\"a\" \"b c\" \"\"]",
        );
        // Go: empty v="[]" nil="[]".
        let se: slice<string> = slice::new();
        eq(&mut ok, "empty %v", fmt::Sprintf!("%v", se), "[]");
        report(&mut failed, ok, " 2", "a []string renders as [a b c]");
    }

    // 3. The verb reaches each ELEMENT. Go: ints v="[1 2 30]"
    //    x="[1 2 1e]" X="[1 2 1E]" b="[1 10 11110]"
    //    q="['\x01' '\x02' '\x1e']" — %q on an int is the rune quote,
    //    per element, exactly as it would be on the int alone.
    {
        let mut ok = true;
        let ii: slice<int> = goish::slice!([]int{1, 2, 30});
        eq(
            &mut ok,
            "ints %v",
            fmt::Sprintf!("%v", ii.clone()),
            "[1 2 30]",
        );
        eq(
            &mut ok,
            "ints %d",
            fmt::Sprintf!("%d", ii.clone()),
            "[1 2 30]",
        );
        eq(
            &mut ok,
            "ints %x",
            fmt::Sprintf!("%x", ii.clone()),
            "[1 2 1e]",
        );
        eq(
            &mut ok,
            "ints %X",
            fmt::Sprintf!("%X", ii.clone()),
            "[1 2 1E]",
        );
        eq(
            &mut ok,
            "ints %b",
            fmt::Sprintf!("%b", ii.clone()),
            "[1 10 11110]",
        );
        eq(
            &mut ok,
            "ints %q",
            fmt::Sprintf!("%q", ii.clone()),
            "['\\x01' '\\x02' '\\x1e']",
        );
        // Go: neg v="[-1 -255]" x="[-1 -ff]".
        let neg: slice<int> = goish::slice!([]int{-1, -255});
        eq(
            &mut ok,
            "neg %v",
            fmt::Sprintf!("%v", neg.clone()),
            "[-1 -255]",
        );
        eq(
            &mut ok,
            "neg %x",
            fmt::Sprintf!("%x", neg.clone()),
            "[-1 -ff]",
        );
        report(&mut failed, ok, " 3", "the verb applies to each element");
    }

    // 4. Precision reaches each element too, and nesting works.
    //    Go: floats v="[1 1.5]" f="[1.000000 1.500000]"
    //    .2f="[1.00 1.50]"; nested v="[[1 2] [3] []]".
    {
        let mut ok = true;
        let ff: slice<f64> = goish::slice!([]f64{1.0, 1.5});
        eq(
            &mut ok,
            "floats %v",
            fmt::Sprintf!("%v", ff.clone()),
            "[1 1.5]",
        );
        eq(
            &mut ok,
            "floats %f",
            fmt::Sprintf!("%f", ff.clone()),
            "[1.000000 1.500000]",
        );
        eq(
            &mut ok,
            "floats %.2f",
            fmt::Sprintf!("%.2f", ff.clone()),
            "[1.00 1.50]",
        );
        let bb: slice<bool> = goish::slice!([]bool{true, false});
        eq(
            &mut ok,
            "bools %v",
            fmt::Sprintf!("%v", bb.clone()),
            "[true false]",
        );
        eq(
            &mut ok,
            "bools %t",
            fmt::Sprintf!("%t", bb.clone()),
            "[true false]",
        );
        let n1: slice<int> = goish::slice!([]int{1, 2});
        let n2: slice<int> = goish::slice!([]int{3});
        let n3: slice<int> = slice::new();
        let nested: slice<slice<int>> = goish::slice!([]slice<int>{n1, n2, n3});
        eq(
            &mut ok,
            "nested %v",
            fmt::Sprintf!("%v", nested),
            "[[1 2] [3] []]",
        );
        report(&mut failed, ok, " 4", "precision and nesting reach through");
    }

    // 5. Maps, with the keys SORTED. Go: map v="map[a:1 b:2 c:3]",
    //    mapi v="map[1:a 2:b 3:c]", mapempty v="map[]".
    //
    //    The sort is the point: Go's map iteration order is randomised,
    //    and a printer that followed it would produce a different
    //    string on every run.
    {
        let mut ok = true;
        let mut m: goish::map<string, int> = goish::make!(map[string]int);
        m.Set(s("b"), 2);
        m.Set(s("a"), 1);
        m.Set(s("c"), 3);
        eq(
            &mut ok,
            "map %v",
            fmt::Sprintf!("%v", m.clone()),
            "map[a:1 b:2 c:3]",
        );
        // Go: q="map[\"a\":'\x01' \"b\":'\x02' \"c\":'\x03']" — the verb
        // reaches keys and values alike.
        eq(
            &mut ok,
            "map %q",
            fmt::Sprintf!("%q", m.clone()),
            "map[\"a\":'\\x01' \"b\":'\\x02' \"c\":'\\x03']",
        );
        let mut mi: goish::map<int, string> = goish::make!(map[int]string);
        mi.Set(3, s("c"));
        mi.Set(1, s("a"));
        mi.Set(2, s("b"));
        eq(
            &mut ok,
            "mapi %v",
            fmt::Sprintf!("%v", mi),
            "map[1:a 2:b 3:c]",
        );
        let me: goish::map<string, int> = goish::make!(map[string]int);
        eq(&mut ok, "mapempty %v", fmt::Sprintf!("%v", me), "map[]");
        report(&mut failed, ok, " 5", "a map prints with its keys sorted");
    }

    // 6. Println's spacing over composites. Go, for these values:
    //    "[a b c ] [1 2 30] [65 66]".
    {
        let ss: slice<string> =
            goish::slice!([]string{string::from("a"), string::from("b c"), string::from("")});
        let ii: slice<int> = goish::slice!([]int{1, 2, 30});
        let got = fmt::Sprintf!("%v %v %v", ss, ii, goish::bytes("AB"));
        let mut ok = true;
        eq(&mut ok, "println", got, "[a b c ] [1 2 30] [65 66]");
        report(&mut failed, ok, " 6", "composites compose with the rest");
    }

    // 7. Two divergences from Go that are recorded here rather than
    //    hidden, because both are in the printer's flag plumbing rather
    //    than in the composite rendering:
    //
    //    * a WIDTH is applied to the bracketed whole, where Go applies
    //      it per element: Go's `%3d` of []int{1,2,30} is
    //      "[  1   2  30]" and goish's is "[1 2 30]". goish's `Format`
    //      trait carries the verb and the precision but not the width,
    //      which `do_format` applies over the finished bytes.
    //    * a verb the element type does not take renders the element
    //      instead of Go's `%!verb(type=value)`: Go's `%d` of
    //      []string{"a"} is "[%!d(string=a)]" and goish's is "[a]".
    //      The bad-verb machinery does not exist anywhere in goish's
    //      printer yet, for slices or for scalars.
    //
    //    This check asserts what goish DOES, so that the day either is
    //    fixed the assertion fails and points here.
    {
        let mut ok = true;
        let ii: slice<int> = goish::slice!([]int{1, 2, 30});
        eq(
            &mut ok,
            "width (diverges)",
            fmt::Sprintf!("%3d", ii),
            "[1 2 30]",
        );
        let one: slice<string> = goish::slice!([]string{string::from("a")});
        eq(
            &mut ok,
            "badverb (diverges)",
            fmt::Sprintf!("%d", one),
            "[a]",
        );
        report(
            &mut failed,
            ok,
            " 7",
            "the two known gaps, pinned as they are",
        );
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
