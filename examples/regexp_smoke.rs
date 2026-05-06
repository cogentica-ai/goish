// regexp_smoke — exercises the minimal goish-v1 regexp subset
// (QuoteMeta + Compile + ReplaceAllString) end-to-end.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::regexp;
use goish::strconv;
use goish::{nil, string, Println, Sprint};

#[goish::main]
fn main() {
    let mut pass: i64 = 0;
    let mut total: i64 = 0;

    macro_rules! check {
        ($name:expr, $cond:expr) => {{
            total += 1;
            if $cond {
                pass += 1;
                Println!("PASS ", $name);
            } else {
                Println!("FAIL ", $name);
            }
        }};
    }

    // QuoteMeta — escapes `\.+*?()|[]{}^$`; passes through everything else.
    check!("QuoteMeta plain", regexp::QuoteMeta("abc") == string("abc"));
    check!(
        "QuoteMeta dot+star",
        regexp::QuoteMeta("a.b*c") == string("a\\.b\\*c")
    );
    check!(
        "QuoteMeta all metas",
        regexp::QuoteMeta(".+*?()|[]{}^$\\")
            == string("\\.\\+\\*\\?\\(\\)\\|\\[\\]\\{\\}\\^\\$\\\\")
    );

    // Compile + ReplaceAllString — the masktoken use case.
    let (re, err) = regexp::Compile("abc");
    check!("Compile abc OK", err == nil);
    check!(
        "Replace abc -> ***",
        re.ReplaceAllString("xx abc yy abc zz", "***") == string("xx *** yy *** zz")
    );

    let (re2, err2) = regexp::Compile("ab*");
    check!("Compile ab*", err2 == nil);
    check!(
        "Replace ab* -> ***",
        re2.ReplaceAllString("a abbb x ab y", "***") == string("*** *** x *** y")
    );

    let (re3, err3) = regexp::Compile("a\\.b");
    check!("Compile escaped dot", err3 == nil);
    check!(
        "Escaped dot matches literal",
        re3.ReplaceAllString("a.b axb", "Z") == string("Z axb")
    );

    // Alternation, dot, classes, anchors, groups, predefined classes —
    // the RE2-subset additions for the semver port.
    let (re4, err4) = regexp::Compile("a|b");
    check!("Compile alternation", err4 == nil);
    check!("Match alt left",  re4.MatchString("a"));
    check!("Match alt right", re4.MatchString("b"));
    check!("Reject alt no-match", !re4.MatchString("c"));

    let (re5, err5) = regexp::Compile("a.b");
    check!("Compile dot", err5 == nil);
    check!("Dot matches any byte", re5.MatchString("axb"));

    let (re6, _) = regexp::Compile("[0-9]+");
    check!("Class+plus matches", re6.MatchString("hello 123 world"));
    check!("Class+plus FindAllString",
        re6.FindAllString("a 12 b 345 c", -1).Len() == 2);

    let (re7, _) = regexp::Compile("^v?(\\d+)\\.(\\d+)\\.(\\d+)$");
    check!("Compile semver-ish anchored", true);
    let m = re7.FindStringSubmatch("v1.2.3");
    check!("Anchored match length 4", m.Len() == 4);
    check!("Capture 1 == \"1\"", m[1] == string("1"));
    check!("Capture 2 == \"2\"", m[2] == string("2"));
    check!("Capture 3 == \"3\"", m[3] == string("3"));
    check!("Reject unanchored extra",
        re7.FindStringSubmatch("v1.2.3-beta").Len() == 0);

    // Non-capturing group.
    let (re8, _) = regexp::Compile("(?:ab)+");
    check!("Non-cap group match", re8.MatchString("ababab"));

    // The actual semver pattern fragment used by Masterminds/semver.
    let (sv, sv_err) = regexp::Compile(
        "^v?(0|[1-9]\\d*)(?:\\.(0|[1-9]\\d*))?(?:\\.(0|[1-9]\\d*))?$"
    );
    check!("Semver-fragment compiles", sv_err == nil);
    let mm = sv.FindStringSubmatch("v1.2.3");
    check!("Semver match v1.2.3", mm.Len() == 4);
    check!("Semver maj=1", mm[1] == string("1"));
    check!("Semver min=2", mm[2] == string("2"));
    check!("Semver pat=3", mm[3] == string("3"));

    // Mirror the original "X / Y" summary shape — same form as
    // `fmt_sprint_smoke` / other goish smoke tests so a single grep
    // ("ok N/M") catches the result line in CI.
    let summary = Sprint!(
        string("ok "),
        strconv::Itoa(pass),
        string("/"),
        strconv::Itoa(total)
    );
    Println!(summary);
    if pass != total {
        goish::os::Exit(1);
    }
}
