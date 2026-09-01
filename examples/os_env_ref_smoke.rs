// os_env_ref_smoke — os.Expand's shell rules against a running Go.
// (os/env.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_os_env_ref.go` run in `package os_test`
// by `scripts/goref.sh`.
//
// `Expand`'s rules are SHELL rules, and they are not what a
// hand-written scanner guesses. goish's got three things wrong:
//
//   * `$$` was treated as an ESCAPE producing a literal `$`. Go has no
//     such escape — `$` is a shell special variable, so `$$` expands
//     `mapping("$")`, which under `ExpandEnv` is the empty string. A
//     program printing `os.ExpandEnv("cost: $$5")` got "cost: $5" from
//     goish and "cost: 5" from Go.
//   * The other shell specials — `*`, `#`, `@`, `!`, `?`, `-` — were
//     not recognised, so `$*` came out as the literal `$*` where Go
//     expands `mapping("*")`.
//   * An unterminated `${` swallowed the rest of the string as a
//     variable name: `"a${b"` expanded `mapping("b")` in goish where
//     Go eats the `${` as bad syntax and leaves "ab".
//
// Ported verbatim: Expand, getShellName, isShellSpecialVar, isAlphaNum.
// os/env.go now has its own file and every declaration is anchored —
// the first of os's 47 Go files to be split out of the 2094-line
// module root.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::os;
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

// go: none — goish idiom: the Go reference's mapping function, which
//     wraps any unknown name in angle brackets so the smoke can see
//     WHICH name the scanner extracted, not just that something was
//     substituted.
fn mapping(k: string) -> string {
    let known: [(&str, &str); 6] = [
        ("FOO", "<foo>"),
        ("BAR", "<bar>"),
        ("FOO_BAR", "<fb>"),
        ("A_B_1", "<ab1>"),
        ("_", "<us>"),
        ("foo", "<lower>"),
    ];
    let mut i = 0usize;
    while i < known.len() {
        if k == s(known[i].0) {
            return s(known[i].1);
        }
        i += 1;
    }
    return s("<") + k + s(">");
}

// (input, want) for os.Expand with the reference mapping below —
// Go 1.25.5 verbatim.
const CASES: [(&str, &str); 48] = [
    ("", ""),
    ("no vars", "no vars"),
    ("$", "$"),
    ("$$", "<$>"),
    ("$$$", "<$>$"),
    ("a$$b", "a<$>b"),
    ("$FOO", "<foo>"),
    ("${FOO}", "<foo>"),
    ("$FOO bar", "<foo> bar"),
    ("${FOO}bar", "<foo>bar"),
    ("$FOO$BAR", "<foo><bar>"),
    ("${FOO}${BAR}", "<foo><bar>"),
    ("$UNSET", "<UNSET>"),
    ("${UNSET}", "<UNSET>"),
    ("${}", ""),
    ("${", ""),
    ("${FOO", "FOO"),
    ("$}", "$}"),
    ("a${", "a"),
    ("a${b", "ab"),
    ("x${FOO}y${", "x<foo>y"),
    ("$1", "<1>"),
    ("$9", "<9>"),
    ("$0", "<0>"),
    ("$*", "<*>"),
    ("$#", "<#>"),
    ("$@", "<@>"),
    ("$!", "<!>"),
    ("$?", "<?>"),
    ("$-", "<->"),
    ("${*}", "<*>"),
    ("${#}", "<#>"),
    ("${1}", "<1>"),
    ("${-}", "<->"),
    ("$FOO_BAR", "<fb>"),
    ("$FOO-BAR", "<foo>-BAR"),
    ("$FOO.BAR", "<foo>.BAR"),
    ("$_", "<us>"),
    ("${_}", "<us>"),
    ("$ FOO", "$ FOO"),
    ("a$", "a$"),
    ("$$FOO", "<$>FOO"),
    ("${FOO}}", "<foo>}"),
    ("$${FOO}", "<$>{FOO}"),
    ("\\$FOO", "\\<foo>"),
    ("$foo", "<lower>"),
    ("${a b}", "<a b>"),
    ("${A_B_1}", "<ab1>"),
];

const WANT_ENV1: &str = "a v1 b v1 c  d";

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Every expansion, including the shell specials, the `$$`
    //    non-escape and the malformed `${` forms.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < CASES.len() {
            let (input, want) = CASES[i];
            let got = os::Expand(s(input), mapping);
            if got != s(want) {
                fmt::Println!(
                    "   ",
                    fmt::Sprintf!("%q", s(input)),
                    "want",
                    fmt::Sprintf!("%q", s(want)),
                    "got",
                    fmt::Sprintf!("%q", got)
                );
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "48 expansions, shell rules and all");
    }

    // 2. ExpandEnv over the real environment, and the Getenv /
    //    LookupEnv split between "unset" and "set to empty".
    {
        let mut ok = true;
        let _ = os::Setenv("GOISH_T1", "v1");
        let _ = os::Unsetenv("GOISH_T2");
        if os::ExpandEnv("a $GOISH_T1 b ${GOISH_T1} c $GOISH_T2 d") != s(WANT_ENV1) {
            ok = false;
        }
        let (v1, ok1) = os::LookupEnv("GOISH_T1");
        if v1 != s("v1") || !ok1 {
            ok = false;
        }
        let (v2, ok2) = os::LookupEnv("GOISH_T2");
        if !v2.as_bytes().is_empty() || ok2 {
            ok = false;
        }
        if !os::Getenv("GOISH_T2").as_bytes().is_empty() {
            ok = false;
        }
        // Set to the empty string: LookupEnv says present, Getenv says "".
        let _ = os::Setenv("GOISH_T2", "");
        let (v3, ok3) = os::LookupEnv("GOISH_T2");
        if !v3.as_bytes().is_empty() || !ok3 {
            ok = false;
        }
        // Go rejects a key containing '=' or an empty key.
        if os::Setenv("BAD=KEY", "x").IsNil() {
            ok = false;
        }
        if os::Setenv("", "x").IsNil() {
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 2",
            "ExpandEnv, Getenv, LookupEnv, Setenv",
        );
    }

    if failed == 0 {
        fmt::Println!("ok 2/2");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 2");
        syscall::Exit(1);
    }
}
