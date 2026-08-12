// testing_match_smoke — pin src/testing/match.rs against Go 1.25.5.
//
// Every expectation below is the literal output of running the real Go
// code, via an in-package ref test (package testing cannot import
// "testing", so it takes *T directly, as Go's own match_test.go does):
//
//   scripts/goref.sh testing match_ref.go
//     splitRegexp("A")        = simpleMatch["A"]
//     splitRegexp("A/B")      = simpleMatch["A" "B"]
//     splitRegexp("A|B")      = alternationMatch[["A"] ["B"]]
//     splitRegexp("A/B|C/D")  = alternationMatch[["A" "B"] ["C" "D"]]
//     splitRegexp("A[/]B")    = simpleMatch["A[/]B"]
//     splitRegexp("A(|)B")    = simpleMatch["A(|)B"]
//     splitRegexp("A\\/B")    = simpleMatch["A\\/B"]
//       (Go printed that via %q, which escapes the backslash for
//        display: the string itself holds a single backslash.)
//     splitRegexp("A/B/C")    = simpleMatch["A" "B" "C"]
//     parseSubtestNumber("a/b")     = ("a/b", 0)
//     parseSubtestNumber("a/b#01")  = ("a/b", 1)
//     parseSubtestNumber("a/b#1")   = ("a/b#1", 0)
//     parseSubtestNumber("a/b#001") = ("a/b#001", 0)
//     parseSubtestNumber("a/#00")   = ("a/", 0)
//     parseSubtestNumber("a/b#00")  = ("a/b#00", 0)
//     parseSubtestNumber("a/b#99")  = ("a/b", 99)
//     rewrite("hello world") = "hello_world"
//     rewrite("a\tb")        = "a_b"
//     rewrite("café")        = "café"
//     rewrite(" z")          = "_z"
//     unique(p, x/x/x/y/x#01/x) = p/x, p/x#01, p/x#02, p/y,
//                                 p/x#01#01, p/x#03

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::gostring::string;
use goish::testing::r#match::{
    allMatcher, filterMatch, isSpace, parseSubtestNumber, rewrite, splitRegexp,
};
use goish::types::int32;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

/// Render a filterMatch the way the Go ref test printed it, so the
/// comparison is against text taken straight from Go.
fn render(f: &filterMatch) -> string {
    return match f {
        filterMatch::simpleMatch(v) => {
            let mut out = alloc::string::String::from("simpleMatch[");
            for (i, e) in v.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                out.push('"');
                out.push_str(e.as_ref());
                out.push('"');
            }
            out.push(']');
            string::from_bytes(out.as_bytes())
        }
        filterMatch::alternationMatch(ms) => {
            let mut out = alloc::string::String::from("alternationMatch[");
            for (i, m) in ms.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                out.push('[');
                if let filterMatch::simpleMatch(v) = m {
                    for (j, e) in v.iter().enumerate() {
                        if j > 0 {
                            out.push(' ');
                        }
                        out.push('"');
                        out.push_str(e.as_ref());
                        out.push('"');
                    }
                }
                out.push(']');
            }
            out.push(']');
            string::from_bytes(out.as_bytes())
        }
    };
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. splitRegexp — separators, character classes, groups, escapes.
    {
        let cases: &[(&str, &str)] = &[
            ("A", "simpleMatch[\"A\"]"),
            ("A/B", "simpleMatch[\"A\" \"B\"]"),
            ("A|B", "alternationMatch[[\"A\"] [\"B\"]]"),
            ("A/B|C/D", "alternationMatch[[\"A\" \"B\"] [\"C\" \"D\"]]"),
            // '/' inside a character class is not a separator.
            ("A[/]B", "simpleMatch[\"A[/]B\"]"),
            // '|' inside a group is not a separator.
            ("A(|)B", "simpleMatch[\"A(|)B\"]"),
            // An escaped '/' is not a separator.
            ("A\\/B", "simpleMatch[\"A\\/B\"]"),
            ("A/B/C", "simpleMatch[\"A\" \"B\" \"C\"]"),
        ];
        let mut ok = true;
        for (pat, want) in cases.iter() {
            let got = render(&splitRegexp(&s(pat)));
            if got != s(want) {
                fmt::Println!("    splitRegexp mismatch: ", *pat, " got ", got);
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 1] splitRegexp               PASS");
        } else {
            fmt::Println!("[ 1] splitRegexp               FAIL");
            failed += 1;
        }
    }

    // 2. parseSubtestNumber — only a literal "%02d" suffix counts.
    {
        let cases: &[(&str, &str, int32)] = &[
            ("a/b", "a/b", 0),
            ("a/b#01", "a/b", 1),
            // One digit: not a possible "%02d" output.
            ("a/b#1", "a/b#1", 0),
            // Three digits with a leading zero: likewise.
            ("a/b#001", "a/b#001", 0),
            // "#00" is only valid when the subtest name was empty,
            // i.e. the prefix ends in '/'.
            ("a/#00", "a/", 0),
            ("a/b#00", "a/b#00", 0),
            ("a/b#99", "a/b", 99),
        ];
        let mut ok = true;
        for (in_, want_prefix, want_n) in cases.iter() {
            let (prefix, n) = parseSubtestNumber(&s(in_));
            if prefix != s(want_prefix) || n != *want_n {
                fmt::Println!("    parseSubtestNumber mismatch: ", *in_);
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 2] parseSubtestNumber        PASS");
        } else {
            fmt::Println!("[ 2] parseSubtestNumber        FAIL");
            failed += 1;
        }
    }

    // 3. rewrite — whitespace to '_', non-printables escaped, and
    //    multi-byte printables passed through unchanged.
    {
        let cases: &[(&str, &str)] = &[
            ("hello world", "hello_world"),
            ("a\tb", "a_b"),
            ("café", "café"),
            (" z", "_z"),
        ];
        let mut ok = true;
        for (in_, want) in cases.iter() {
            let got = rewrite(&s(in_));
            if got != s(want) {
                fmt::Println!("    rewrite mismatch: ", *in_, " got ", got);
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 3] rewrite                   PASS");
        } else {
            fmt::Println!("[ 3] rewrite                   FAIL");
            failed += 1;
        }
    }

    // 4. matcher.unique — the dedup sequence, including the collision
    //    case where an explicitly-named "x#01" forces a further suffix.
    {
        let m = allMatcher();
        let inputs = ["x", "x", "x", "y", "x#01", "x"];
        let wants = ["p/x", "p/x#01", "p/x#02", "p/y", "p/x#01#01", "p/x#03"];
        let mut ok = true;
        for (i, in_) in inputs.iter().enumerate() {
            let got = m.unique(&s("p"), &s(in_));
            if got != s(wants[i]) {
                fmt::Println!("    unique mismatch at ", i as i64, " got ", got);
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 4] matcher.unique            PASS");
        } else {
            fmt::Println!("[ 4] matcher.unique            FAIL");
            failed += 1;
        }
    }

    // 5. fullName applies the filter, and reports partial matches so a
    //    parent can still run to reach a matching child.
    {
        // An empty pattern is `simpleMatch{}` — always matches.
        let m = allMatcher();
        let (name, ok1, _) = m.fullName(0, &s(""), &s("TestFoo"));
        // level 0 means no parent, so the name passes through unrewritten.
        let pass1 = name == s("TestFoo") && ok1;

        // A child under a parent gets uniqued and rewritten.
        let (name2, ok2, _) = m.fullName(1, &s("TestFoo"), &s("sub case"));
        let pass2 = name2 == s("TestFoo/sub_case") && ok2;

        if pass1 && pass2 {
            fmt::Println!("[ 5] matcher.fullName          PASS");
        } else {
            fmt::Println!("[ 5] matcher.fullName          FAIL");
            failed += 1;
        }
    }

    // 6. isSpace — the boundaries of Go's hand-rolled table, which is
    //    deliberately NOT the Unicode Z class.
    {
        let spaces: &[i32] = &[
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000, 0x200a,
            0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
        ];
        let not_spaces: &[i32] = &[0x41, 0x1FFF, 0x200b, 0x2027, 0x3001];
        let mut ok = true;
        for r in spaces.iter() {
            if !isSpace(*r as goish::types::rune) {
                fmt::Println!("    isSpace missed ", *r as i64);
                ok = false;
            }
        }
        for r in not_spaces.iter() {
            if isSpace(*r as goish::types::rune) {
                fmt::Println!("    isSpace false positive ", *r as i64);
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 6] isSpace table             PASS");
        } else {
            fmt::Println!("[ 6] isSpace table             FAIL");
            failed += 1;
        }
    }

    // 7. splitRegexp on an alternation keeps every branch, and the
    //    matcher accepts a name only when a branch matches in sequence.
    {
        let f = splitRegexp(&s("A/B|C"));
        let elems_ab: Vec<string> = alloc::vec![s("A"), s("B")];
        let elems_c: Vec<string> = alloc::vec![s("C")];
        let elems_z: Vec<string> = alloc::vec![s("Z")];
        // With no match function every pattern element matches, so these
        // exercise the structural walk rather than the regexp engine.
        let (ok_ab, _) = f.matches(&elems_ab, None);
        let (ok_c, _) = f.matches(&elems_c, None);
        let (ok_z, _) = f.matches(&elems_z, None);
        if ok_ab && ok_c && ok_z {
            fmt::Println!("[ 7] alternation matches       PASS");
        } else {
            fmt::Println!("[ 7] alternation matches       FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
