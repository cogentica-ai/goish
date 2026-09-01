// regexp_replace_ref_smoke — the Replace family against a running Go.
// (regexp/regexp.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_regexp_api_ref.go` run in `package
// regexp_test` by `scripts/goref.sh`.
//
// `ReplaceAllString` did no $-expansion at all. It copied the
// replacement template through byte for byte, which is precisely Go's
// ReplaceAllLiteralString — so `re.ReplaceAllString(s, "$1")` emitted
// the two characters `$1` where Go substitutes the first capture. No
// error, no panic, and output that looks like output.
//
// It also had its own match loop rather than Go's `replaceAll`, and got
// the empty-match rule wrong: Go inserts the replacement "but not for a
// match of the empty string immediately after another match.
// (Otherwise, we get double replacement for patterns that match both
// empty and nonempty strings.)" `a*` over "bab" replaced four times
// where Go replaces three.
//
// The engine itself was already right — every Find, FindAll and Split
// vector in the reference already matched — which is what made these
// two worth finding: they sit in the one place a caller cannot check by
// eye.
//
// Expansion needs the subexpression names, and goish parsed
// `(?P<name>…)` and threw the name away, so `SubexpNames`,
// `SubexpIndex` and `$name` had nothing to look at. `(?P<>a)` — an
// EMPTY name, which Go rejects — compiled.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::regexp;
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

    // 1. ReplaceAllString expands $, ReplaceAllLiteralString does not.
    //    (pattern, input, template, want_expanded, want_literal)
    {
        let mut ok = true;
        let cases: [(&str, &str, &str, &str, &str); 13] = [
            ("(a)(b)", "ab", "$2$1", "ba", "$2$1"),
            ("(a)(b)", "ab", "${2}${1}", "ba", "${2}${1}"),
            // $0 is the whole match.
            ("(a)(b)", "ab", "$0!", "ab!", "$0!"),
            // Go: "a reference to an out of range … index … is replaced
            // with an empty slice."
            ("(a)(b)", "ab", "$3", "", "$3"),
            // A trailing '$' with no name after it is raw text.
            ("(a)(b)", "ab", "x$", "x$", "x$"),
            // Go: "Treat $$ as $."
            ("(a)(b)", "ab", "$$", "$", "$$"),
            ("(?P<x>a)(?P<y>b)", "ab", "$y-$x", "b-a", "$y-$x"),
            ("(?P<x>a)(?P<y>b)", "ab", "${y}${x}", "ba", "${y}${x}"),
            ("(a)", "aa", "[$1]", "[a][a]", "[$1][$1]"),
            ("a*", "bab", "-", "-b-b-", "-b-b-"),
            ("x*", "abc", "-", "-a-b-c-", "-a-b-c-"),
            ("\\d", "a1b2", "<$0>", "a<1>b<2>", "a<$0>b<$0>"),
            // The one that shows why a name is letters, digits AND
            // underscores: `$1c` is the NAME "1c", not group 1 followed
            // by a 'c'. No group is called "1c", so it expands to
            // nothing — and the whole match is replaced by nothing.
            ("(a)b", "ab", "$1c", "", "$1c"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (pat, inp, repl, want, want_lit) = cases[i];
            let re = regexp::MustCompile(pat);
            eq(&mut ok, pat, re.ReplaceAllString(inp, repl), want);
            eq(
                &mut ok,
                pat,
                re.ReplaceAllLiteralString(inp, repl),
                want_lit,
            );
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 1",
            "ReplaceAllString expands $, Literal does not",
        );
    }

    // 2. The empty-match rule on its own, because it is the one a
    //    hand-written loop gets wrong. `a*` over "bab" matches empty at
    //    0, "a" at [1,2], empty at [2,2] — and that third one is
    //    suppressed because it ends where the previous match ended.
    {
        let mut ok = true;
        let re = regexp::MustCompile("a*");
        eq(
            &mut ok,
            "a* over bab",
            re.ReplaceAllString("bab", "-"),
            "-b-b-",
        );
        eq(&mut ok, "a* over aaa", re.ReplaceAllString("aaa", "-"), "-");
        eq(&mut ok, "a* over b", re.ReplaceAllString("b", "-"), "-b-");
        eq(&mut ok, "a* over ''", re.ReplaceAllString("", "-"), "-");
        // A pattern that can only match empty replaces between every
        // rune, and once at each end.
        let x = regexp::MustCompile("x*");
        eq(
            &mut ok,
            "x* over abc",
            x.ReplaceAllString("abc", "-"),
            "-a-b-c-",
        );
        report(
            &mut failed,
            ok,
            " 2",
            "an empty match after a match is skipped",
        );
    }

    // 3. ReplaceAllStringFunc runs over the same skeleton, so it gets
    //    the same empty-match rule — and does NOT expand what the
    //    callback returns. Go: "the replacement returned by repl is
    //    substituted directly, without using Expand."
    {
        let mut ok = true;
        let re = regexp::MustCompile("\\d+");
        eq(
            &mut ok,
            "func upper",
            re.ReplaceAllStringFunc("a12b345", |m| s("<") + m + s(">")),
            "a<12>b<345>",
        );
        let star = regexp::MustCompile("a*");
        eq(
            &mut ok,
            "func a*",
            star.ReplaceAllStringFunc("bab", |_| s("-")),
            "-b-b-",
        );
        // The callback's own '$' is left alone.
        eq(
            &mut ok,
            "func no expand",
            re.ReplaceAllStringFunc("a1", |_| s("$0")),
            "a$0",
        );
        report(
            &mut failed,
            ok,
            " 3",
            "ReplaceAllStringFunc does not expand",
        );
    }

    // 4. Subexpression metadata. Go: names[0] is always "" and the rest
    //    line up with the capture indices; SubexpIndex is -1 for a name
    //    that is not there, and for the empty name.
    {
        let mut ok = true;
        // (pattern, NumSubexp, names joined by '|', SubexpIndex("y"))
        let cases: [(&str, int, &str, int); 4] = [
            ("(a)(b)", 2, "||", -1),
            ("(?P<x>a)(?P<y>b)", 2, "|x|y", 2),
            ("a", 0, "", -1),
            ("(a(b))", 2, "||", -1),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (pat, n, joined, idx) = cases[i];
            let re = regexp::MustCompile(pat);
            if re.NumSubexp() != n {
                fmt::Println!("   ", s(pat), "NumSubexp", re.NumSubexp(), "want", n);
                ok = false;
            }
            let names = re.SubexpNames();
            let mut got = string::new();
            let mut k = 0;
            while k < names.len() {
                if k > 0 {
                    got = got + s("|");
                }
                got = got + names[k].clone();
                k += 1;
            }
            eq(&mut ok, pat, got, joined);
            if re.SubexpIndex("y") != idx {
                ok = false;
            }
            // Go: SubexpIndex("") is -1 even though names[0] is "".
            if re.SubexpIndex("") != -1 {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "SubexpNames/NumSubexp/SubexpIndex");
    }

    // 5. Patterns Go REJECTS that goish used to compile. An empty
    //    named capture, and a well-formed brace whose counts are
    //    impossible — `a{2,1}` built a repetition that could never be
    //    satisfied and matched nothing at all.
    //
    //    The message text still differs from Go's: Go says "error
    //    parsing regexp: invalid repeat count: `{2,1}`", quoting the
    //    offending FRAGMENT, where goish says "regexp: invalid repeat
    //    count: `a{2,1}`" and quotes the whole pattern. Aligning the
    //    wording and the span is its own unit; what is checked here is
    //    that the pattern is refused at all.
    {
        let mut ok = true;
        for pat in ["(?P<>a)", "a{2,1}", "a{1001}", "(", "a**", "[z-a]", "\\"] {
            let (_, e) = regexp::Compile(pat);
            if e.IsNil() {
                fmt::Println!("   ", s(pat), "compiled, Go rejects it");
                ok = false;
            }
        }
        // …and ones Go accepts, including the brace that is a literal
        // because it does not parse as a repetition at all.
        for pat in ["a{,3}", "a{2,}", "a{2}", "a{0,1000}", "(?P<x>a)", "(?:a)"] {
            let (_, e) = regexp::Compile(pat);
            if !e.IsNil() {
                fmt::Println!("   ", s(pat), "rejected:", e.Error());
                ok = false;
            }
        }
        // Go: `a{,3}` is the five-character literal string.
        let lit = regexp::MustCompile("a{,3}");
        if !lit.MatchString("a{,3}") || lit.MatchString("aaa") {
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 5",
            "impossible counts and empty names are refused",
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
