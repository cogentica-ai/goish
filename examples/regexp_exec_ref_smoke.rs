// regexp_exec_ref_smoke — the NFA, stage 4a of §2c. END TO END.
//
// Parse, simplify, compile, execute. 73 (pattern, subject) pairs under
// both match semantics — leftmost-first and leftmost-longest — compared
// against Go's PUBLIC `FindStringSubmatchIndex`, which is the contract
// the whole stack owes regardless of which of Go's three engines
// answered it. 146 rows.
//
// ─── the two rows this whole section exists for ──────────────────────
//
//   "(a+)+$"   against 22 'a's then '!'   -> nil
//   "(x+x+)+y" against 22 'x's            -> nil
//
// goish's backtracking matcher takes 27 SECONDS on the first of those,
// doubling per character; twenty-five bytes hang the process. This
// engine answers both immediately, and not because it is faster —
// because it CANNOT be slow. `add` refuses to enqueue a pc already on
// the queue, so each position does at most O(len(prog)) work and the
// match is O(len(prog) × len(input)). There is nowhere for a blowup to
// go.
//
// (This example does not TIME anything: a timing assertion is a flake
// waiting to happen on shared CI. The bound is structural, and the
// perturbation that proves the smoke can see a wrong answer is in the
// commit message.)
//
// ─── what else the corpus holds down ─────────────────────────────────
//
//   "a|ab" vs "ab|a"     leftmost-FIRST takes the earlier alternative,
//                        leftmost-LONGEST the longer one. The two
//                        semantics differ on exactly these rows, and
//                        the difference lives in one branch of `step`.
//   "a*?" / "a+?" / "a??"  non-greedy, where the Out/Arg swap decides.
//   "(a*)*" on "aa"      the nullable-star fix, visible in the captures
//   `\b` / `\B` / `(?m)^` the lazyFlag, which is the only part of the
//                        machine that looks at neighbouring runes
//   "" and "^$"          zero-width matches, where `width == 0` is what
//                        stops the loop
//
// Go's prefix fast path and its onepass and backtrack engines are not
// ported — all three are OPTIMISATIONS over this one, which is why Go
// falls back to it. See the file header of src/regexp/exec.rs.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::regexp::exec;
use goish::types::int;
use goish::{fmt, string, strconv};

static mut FAILED: int = 0;
static mut RUN: int = 0;

const GO: [&str; 146] = [
    r#"  0 first "a"                "a"                          [0 1]"#,
    r#"  0 long  "a"                "a"                          [0 1]"#,
    r#"  1 first "a"                "b"                          nil"#,
    r#"  1 long  "a"                "b"                          nil"#,
    r#"  2 first "a"                "ba"                         [1 2]"#,
    r#"  2 long  "a"                "ba"                         [1 2]"#,
    r#"  3 first "a"                ""                           nil"#,
    r#"  3 long  "a"                ""                           nil"#,
    r#"  4 first "abc"              "xxabcyy"                    [2 5]"#,
    r#"  4 long  "abc"              "xxabcyy"                    [2 5]"#,
    r#"  5 first "abc"              "ab"                         nil"#,
    r#"  5 long  "abc"              "ab"                         nil"#,
    r#"  6 first "a|b"              "cb"                         [1 2]"#,
    r#"  6 long  "a|b"              "cb"                         [1 2]"#,
    r#"  7 first "a|ab"             "ab"                         [0 1]"#,
    r#"  7 long  "a|ab"             "ab"                         [0 2]"#,
    r#"  8 first "ab|a"             "ab"                         [0 2]"#,
    r#"  8 long  "ab|a"             "ab"                         [0 2]"#,
    r#"  9 first "a*"               ""                           [0 0]"#,
    r#"  9 long  "a*"               ""                           [0 0]"#,
    r#" 10 first "a*"               "aaa"                        [0 3]"#,
    r#" 10 long  "a*"               "aaa"                        [0 3]"#,
    r#" 11 first "a*"               "baaa"                       [0 0]"#,
    r#" 11 long  "a*"               "baaa"                       [0 0]"#,
    r#" 12 first "a+"               "aaa"                        [0 3]"#,
    r#" 12 long  "a+"               "aaa"                        [0 3]"#,
    r#" 13 first "a+"               "b"                          nil"#,
    r#" 13 long  "a+"               "b"                          nil"#,
    r#" 14 first "a?"               "aa"                         [0 1]"#,
    r#" 14 long  "a?"               "aa"                         [0 1]"#,
    r#" 15 first "a*?"              "aaa"                        [0 0]"#,
    r#" 15 long  "a*?"              "aaa"                        [0 3]"#,
    r#" 16 first "a+?"              "aaa"                        [0 1]"#,
    r#" 16 long  "a+?"              "aaa"                        [0 3]"#,
    r#" 17 first "a??"              "aa"                         [0 0]"#,
    r#" 17 long  "a??"              "aa"                         [0 1]"#,
    r#" 18 first "(a)(b)"           "ab"                         [0 2 0 1 1 2]"#,
    r#" 18 long  "(a)(b)"           "ab"                         [0 2 0 1 1 2]"#,
    r#" 19 first "(a)|(b)"          "b"                          [0 1 -1 -1 0 1]"#,
    r#" 19 long  "(a)|(b)"          "b"                          [0 1 -1 -1 0 1]"#,
    r#" 20 first "(a*)(b*)"         "aabb"                       [0 4 0 2 2 4]"#,
    r#" 20 long  "(a*)(b*)"         "aabb"                       [0 4 0 2 2 4]"#,
    r#" 21 first "(a+)(a*)"         "aaa"                        [0 3 0 3 3 3]"#,
    r#" 21 long  "(a+)(a*)"         "aaa"                        [0 3 0 3 3 3]"#,
    r#" 22 first "(a*)*"            "aa"                         [0 2 0 2]"#,
    r#" 22 long  "(a*)*"            "aa"                         [0 2 0 2]"#,
    r#" 23 first "(a|b)*"           "abab"                       [0 4 3 4]"#,
    r#" 23 long  "(a|b)*"           "abab"                       [0 4 3 4]"#,
    r#" 24 first "^a"               "a"                          [0 1]"#,
    r#" 24 long  "^a"               "a"                          [0 1]"#,
    r#" 25 first "^a"               "ba"                         nil"#,
    r#" 25 long  "^a"               "ba"                         nil"#,
    r#" 26 first "a$"               "ba"                         [1 2]"#,
    r#" 26 long  "a$"               "ba"                         [1 2]"#,
    r#" 27 first "a$"               "ab"                         nil"#,
    r#" 27 long  "a$"               "ab"                         nil"#,
    r#" 28 first "\\Aa"             "a"                          [0 1]"#,
    r#" 28 long  "\\Aa"             "a"                          [0 1]"#,
    r#" 29 first "a\\z"             "ba"                         [1 2]"#,
    r#" 29 long  "a\\z"             "ba"                         [1 2]"#,
    r#" 30 first "\\ba\\b"          "x a y"                      [2 3]"#,
    r#" 30 long  "\\ba\\b"          "x a y"                      [2 3]"#,
    r#" 31 first "\\Ba\\B"          "xay"                        [1 2]"#,
    r#" 31 long  "\\Ba\\B"          "xay"                        [1 2]"#,
    r#" 32 first "(?m)^b"           "a\nb"                       [2 3]"#,
    r#" 32 long  "(?m)^b"           "a\nb"                       [2 3]"#,
    r#" 33 first "(?m)a$"           "a\nb"                       [0 1]"#,
    r#" 33 long  "(?m)a$"           "a\nb"                       [0 1]"#,
    r#" 34 first "^b"               "a\nb"                       nil"#,
    r#" 34 long  "^b"               "a\nb"                       nil"#,
    r#" 35 first "[a-z]+"           "123abc456"                  [3 6]"#,
    r#" 35 long  "[a-z]+"           "123abc456"                  [3 6]"#,
    r#" 36 first "[^a-z]+"          "abc123def"                  [3 6]"#,
    r#" 36 long  "[^a-z]+"          "abc123def"                  [3 6]"#,
    r#" 37 first "."                "\n"                         nil"#,
    r#" 37 long  "."                "\n"                         nil"#,
    r#" 38 first "(?s)."            "\n"                         [0 1]"#,
    r#" 38 long  "(?s)."            "\n"                         [0 1]"#,
    r#" 39 first ".*"               "ab\ncd"                     [0 2]"#,
    r#" 39 long  ".*"               "ab\ncd"                     [0 2]"#,
    r#" 40 first "(?i)abc"          "xABCy"                      [1 4]"#,
    r#" 40 long  "(?i)abc"          "xABCy"                      [1 4]"#,
    r#" 41 first "(?i)k"            "K"                          [0 3]"#,
    r#" 41 long  "(?i)k"            "K"                          [0 3]"#,
    r#" 42 first "(?i)K"            "k"                          [0 1]"#,
    r#" 42 long  "(?i)K"            "k"                          [0 1]"#,
    r#" 43 first "a{2,3}"           "aaaa"                       [0 3]"#,
    r#" 43 long  "a{2,3}"           "aaaa"                       [0 3]"#,
    r#" 44 first "a{2,}"            "aaaa"                       [0 4]"#,
    r#" 44 long  "a{2,}"            "aaaa"                       [0 4]"#,
    r#" 45 first "a{0}"             "aaa"                        [0 0]"#,
    r#" 45 long  "a{0}"             "aaa"                        [0 0]"#,
    r#" 46 first "(a){2,3}"         "aaaa"                       [0 3 2 3]"#,
    r#" 46 long  "(a){2,3}"         "aaaa"                       [0 3 2 3]"#,
    r#" 47 first "\\d+"             "abc123"                     [3 6]"#,
    r#" 47 long  "\\d+"             "abc123"                     [3 6]"#,
    r#" 48 first "\\w+"             " abc "                      [1 4]"#,
    r#" 48 long  "\\w+"             " abc "                      [1 4]"#,
    r#" 49 first "\\s+"             "a  b"                       [1 3]"#,
    r#" 49 long  "\\s+"             "a  b"                       [1 3]"#,
    r#" 50 first ""                 ""                           [0 0]"#,
    r#" 50 long  ""                 ""                           [0 0]"#,
    r#" 51 first ""                 "abc"                        [0 0]"#,
    r#" 51 long  ""                 "abc"                        [0 0]"#,
    r#" 52 first "()"               "a"                          [0 0 0 0]"#,
    r#" 52 long  "()"               "a"                          [0 0 0 0]"#,
    r#" 53 first "(?:)"             "a"                          [0 0]"#,
    r#" 53 long  "(?:)"             "a"                          [0 0]"#,
    r#" 54 first "abc|abd|aef"      "aef"                        [0 3]"#,
    r#" 54 long  "abc|abd|aef"      "aef"                        [0 3]"#,
    r#" 55 first "a(b|c)d"          "acd"                        [0 3 1 2]"#,
    r#" 55 long  "a(b|c)d"          "acd"                        [0 3 1 2]"#,
    r#" 56 first "(a+)+$"           "aaaaaaaaaaaaaaaaaaaaaa!"    nil"#,
    r#" 56 long  "(a+)+$"           "aaaaaaaaaaaaaaaaaaaaaa!"    nil"#,
    r#" 57 first "(a+)+$"           "aaaaaaaaaaaaaaaaaaaaaa"     [0 22 0 22]"#,
    r#" 57 long  "(a+)+$"           "aaaaaaaaaaaaaaaaaaaaaa"     [0 22 0 22]"#,
    r#" 58 first "(x+x+)+y"         "xxxxxxxxxxxxxxxxxxxxxx"     nil"#,
    r#" 58 long  "(x+x+)+y"         "xxxxxxxxxxxxxxxxxxxxxx"     nil"#,
    r#" 59 first "[a-z]+@[a-z]+"    "mail me at bob@example now" [11 22]"#,
    r#" 59 long  "[a-z]+@[a-z]+"    "mail me at bob@example now" [11 22]"#,
    r#" 60 first "héllo"            "say héllo"                  [4 10]"#,
    r#" 60 long  "héllo"            "say héllo"                  [4 10]"#,
    r#" 61 first "一+"               "x一一y"                       [1 7]"#,
    r#" 61 long  "一+"               "x一一y"                       [1 7]"#,
    r#" 62 first "(?:ab)+"          "ababab"                     [0 6]"#,
    r#" 62 long  "(?:ab)+"          "ababab"                     [0 6]"#,
    r#" 63 first "(ab)+"            "ababab"                     [0 6 4 6]"#,
    r#" 63 long  "(ab)+"            "ababab"                     [0 6 4 6]"#,
    r#" 64 first "a(?:b|c)*d"       "abcbcd"                     [0 6]"#,
    r#" 64 long  "a(?:b|c)*d"       "abcbcd"                     [0 6]"#,
    r#" 65 first "(a)(b)(c)(d)(e)"  "abcde"                      [0 5 0 1 1 2 2 3 3 4 4 5]"#,
    r#" 65 long  "(a)(b)(c)(d)(e)"  "abcde"                      [0 5 0 1 1 2 2 3 3 4 4 5]"#,
    r#" 66 first "x*"               "yyy"                        [0 0]"#,
    r#" 66 long  "x*"               "yyy"                        [0 0]"#,
    r#" 67 first "(x*)(y*)"         "xxyy"                       [0 4 0 2 2 4]"#,
    r#" 67 long  "(x*)(y*)"         "xxyy"                       [0 4 0 2 2 4]"#,
    r#" 68 first "^$"               ""                           [0 0]"#,
    r#" 68 long  "^$"               ""                           [0 0]"#,
    r#" 69 first "^$"               "a"                          nil"#,
    r#" 69 long  "^$"               "a"                          nil"#,
    r#" 70 first "(?m)^$"           "a\n\nb"                     [2 2]"#,
    r#" 70 long  "(?m)^$"           "a\n\nb"                     [2 2]"#,
    r#" 71 first "a|"               "b"                          [0 0]"#,
    r#" 71 long  "a|"               "b"                          [0 0]"#,
    r#" 72 first "|a"               "a"                          [0 0]"#,
    r#" 72 long  "|a"               "a"                          [0 1]"#,
];

/// The corpus, decoded from the reference's own source.
const CASES: [(&str, &str); 73] = [
    ("a", "a"),
    ("a", "b"),
    ("a", "ba"),
    ("a", ""),
    ("abc", "xxabcyy"),
    ("abc", "ab"),
    ("a|b", "cb"),
    ("a|ab", "ab"),
    ("ab|a", "ab"),
    ("a*", ""),
    ("a*", "aaa"),
    ("a*", "baaa"),
    ("a+", "aaa"),
    ("a+", "b"),
    ("a?", "aa"),
    ("a*?", "aaa"),
    ("a+?", "aaa"),
    ("a??", "aa"),
    ("(a)(b)", "ab"),
    ("(a)|(b)", "b"),
    ("(a*)(b*)", "aabb"),
    ("(a+)(a*)", "aaa"),
    ("(a*)*", "aa"),
    ("(a|b)*", "abab"),
    ("^a", "a"),
    ("^a", "ba"),
    ("a$", "ba"),
    ("a$", "ab"),
    ("\\Aa", "a"),
    ("a\\z", "ba"),
    ("\\ba\\b", "x a y"),
    ("\\Ba\\B", "xay"),
    ("(?m)^b", "a\nb"),
    ("(?m)a$", "a\nb"),
    ("^b", "a\nb"),
    ("[a-z]+", "123abc456"),
    ("[^a-z]+", "abc123def"),
    (".", "\n"),
    ("(?s).", "\n"),
    (".*", "ab\ncd"),
    ("(?i)abc", "xABCy"),
    ("(?i)k", "\u{212a}"),
    ("(?i)\u{212a}", "k"),
    ("a{2,3}", "aaaa"),
    ("a{2,}", "aaaa"),
    ("a{0}", "aaa"),
    ("(a){2,3}", "aaaa"),
    ("\\d+", "abc123"),
    ("\\w+", " abc "),
    ("\\s+", "a  b"),
    ("", ""),
    ("", "abc"),
    ("()", "a"),
    ("(?:)", "a"),
    ("abc|abd|aef", "aef"),
    ("a(b|c)d", "acd"),
    ("(a+)+$", "aaaaaaaaaaaaaaaaaaaaaa!"),
    ("(a+)+$", "aaaaaaaaaaaaaaaaaaaaaa"),
    ("(x+x+)+y", "xxxxxxxxxxxxxxxxxxxxxx"),
    ("[a-z]+@[a-z]+", "mail me at bob@example now"),
    ("h\u{e9}llo", "say h\u{e9}llo"),
    ("\u{4e00}+", "x\u{4e00}\u{4e00}y"),
    ("(?:ab)+", "ababab"),
    ("(ab)+", "ababab"),
    ("a(?:b|c)*d", "abcbcd"),
    ("(a)(b)(c)(d)(e)", "abcde"),
    ("x*", "yyy"),
    ("(x*)(y*)", "xxyy"),
    ("^$", ""),
    ("^$", "a"),
    ("(?m)^$", "a\n\nb"),
    ("a|", "b"),
    ("|a", "a"),
];

fn line(ln: &mut usize, got: string) {
    unsafe { RUN += 1 };
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        unsafe { FAILED += 1 };
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!(
            "[!!] line %d\n  got  %q\n  want %q\n",
            *ln as int + 1,
            got,
            GO[*ln]
        );
        unsafe { FAILED += 1 };
    }
    *ln += 1;
}

/// `%-Ns`, padded by RUNE count as Go's fmt measures it.
fn l(s: string, w: int) -> string {
    let mut o = s;
    while goish::len(&goish::runes(o.clone())) < w {
        o = o + string::from_static(" ");
    }
    return o;
}

/// `%Nd`
fn d(v: i64, w: int) -> string {
    let mut o = strconv::Itoa(int::from(v));
    while o.Len() < w {
        o = string::from_static(" ") + o;
    }
    return o;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    for (i, (pat, sub)) in CASES.iter().enumerate() {
        for longest in [false, true].iter() {
            let p = string::from_static(pat);
            let s = string::from_static(sub);
            let name = if *longest { "long " } else { "first" };
            let head = d(i as i64, int::from(3))
                + string::from_static(" ")
                + l(string::from_static(name), int::from(5))
                + string::from_static(" ")
                + l(strconv::Quote(p.clone()), int::from(18))
                + string::from_static(" ")
                + l(strconv::Quote(s.clone()), int::from(28))
                + string::from_static(" ");
            match exec::__exec(&p, &s, *longest) {
                None => line(&mut ln, head + string::from_static("nil")),
                Some(m) => {
                    let mut body = string::from_static("[");
                    for (j, v) in m.iter().enumerate() {
                        if j > 0 {
                            body = body + string::from_static(" ");
                        }
                        body = body + strconv::Itoa(*v);
                    }
                    line(&mut ln, head + body + string::from_static("]"));
                }
            }
        }
    }

    // ── the linear-time bound, ASSERTED rather than timed ──────────
    //
    // A wall-clock assertion is a flake waiting to happen on shared CI.
    // The machine counts its `add` calls instead, which is the actual
    // property: `add` refuses a pc already on the queue, so the count
    // is bounded by O(len(prog) x len(input)) and NOTHING can make it
    // exponential.
    //
    // Measured on the backtracker this replaces, in a release build:
    // `(a+)+$` against n 'a's and a '!' took 90ms at n=14, 1.5s at
    // n=18, 6.2s at n=20 — doubling per character, so n=30 is about
    // two hours. Here the same pattern is 42µs at n=22 and 334µs at
    // n=200.
    //
    // The assertion is a RATIO, so it does not encode today's constant
    // factor: doubling the input must at most triple the work. A
    // backtracker fails this by a factor of 2^100.
    let redos = string::from_static("(a+)+$");
    let mut prev: i64 = 0;
    let mut prev_n: usize = 0;
    for n in [25usize, 50, 100, 200, 400].iter() {
        let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let mut k = 0usize;
        while k < *n {
            v.push(b'a');
            k += 1;
        }
        v.push(b'!');
        let sub = string::from_bytes(&v);
        let (m, steps) = exec::__exec_steps(&redos, &sub, false);
        unsafe { RUN += 1 };
        let matched_wrong = m.is_some();
        let grew_too_fast = prev > 0 && steps > prev * 3;
        if matched_wrong || grew_too_fast {
            unsafe { FAILED += 1 };
            fmt::Printf!(
                "[!!] REDOS n=%d steps=%d (n=%d was %d) match=%v
",
                *n as int,
                int::from(steps),
                prev_n as int,
                int::from(prev),
                m.is_some()
            );
        } else {
            fmt::Printf!(
                "[ok] REDOS n=%d steps=%d no match, growth within 3x
",
                *n as int,
                int::from(steps)
            );
        }
        prev = steps;
        prev_n = *n;
    }

    let run = unsafe { RUN };
    let f = unsafe { FAILED };
    if run != GO.len() as int + 5 {
        fmt::Printf!("\nFAIL ran %d of %d rows\n", run, GO.len() as int + 5);
        goish::os::Exit(1);
    }
    if f == 0 {
        fmt::Printf!("\nok %d/%d\n", run, run);
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", f);
    goish::os::Exit(1);
}
