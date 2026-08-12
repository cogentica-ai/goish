// slogtest_checks_smoke — the conformance checks a slog.Handler must
// pass, from testing/slogtest.
//
// Two behaviours are worth more than "the check returns a message":
//
//  * hasAttr delegates to hasKey FIRST and returns its message
//    unchanged. So a missing key reports "missing key", not a value
//    mismatch against a zero — which is what a handler author actually
//    needs to see. Check 3 pins that delegation.
//
//  * inGroup distinguishes "group absent" from "group present but not
//    a map". A handler that emitted a group as a flat string would
//    otherwise look like a failing check *inside* the group rather
//    than a structural error. Check 5 pins both messages.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::testing::slogtest::{hasAttr, hasKey, inGroup, missingKey};
use goish::{fmt, map, syscall, Any};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn m(pairs: &[(&str, Any)]) -> map<string, Any> {
    let mut out: map<string, Any> = map::new();
    for (k, v) in pairs.iter() {
        out.Set(s(k), v.clone());
    }
    return out;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. hasKey: present passes, absent reports the key.
    {
        let rec = m(&[("msg", Any::new(s("hello")))]);
        let ok = hasKey(s("msg"))(&rec).Len() == 0;
        let bad = hasKey(s("time"))(&rec);
        if ok && bad == s("missing key \"time\"") {
            fmt::Println!("[ 1] hasKey                    PASS");
        } else {
            fmt::Println!("[ 1] hasKey                    FAIL [", bad, "]");
            failed += 1;
        }
    }

    // 2. missingKey is the mirror — a handler that emits a key it was
    //    told to suppress is as wrong as one that omits a required key.
    {
        let rec = m(&[("msg", Any::new(s("hello")))]);
        let ok = missingKey(s("time"))(&rec).Len() == 0;
        let bad = missingKey(s("msg"))(&rec);
        if ok && bad == s("unexpected key \"msg\"") {
            fmt::Println!("[ 2] missingKey                PASS");
        } else {
            fmt::Println!("[ 2] missingKey                FAIL [", bad, "]");
            failed += 1;
        }
    }

    // 3. hasAttr on a MISSING key reports "missing key", not a value
    //    mismatch. This is the delegation Go does on its first line.
    {
        let rec = m(&[("msg", Any::new(s("hello")))]);
        let got = hasAttr(s("level"), Any::new(s("INFO")))(&rec);
        if got == s("missing key \"level\"") {
            fmt::Println!("[ 3] hasAttr delegates to hasKey PASS");
        } else {
            fmt::Println!("[ 3] hasAttr delegates to hasKey FAIL [", got, "]");
            failed += 1;
        }
    }

    // 4. hasAttr on a present key compares the value.
    {
        let rec = m(&[("level", Any::new(s("INFO")))]);
        let ok = hasAttr(s("level"), Any::new(s("INFO")))(&rec).Len() == 0;
        let bad = hasAttr(s("level"), Any::new(s("WARN")))(&rec).Len() > 0;
        if ok && bad {
            fmt::Println!("[ 4] hasAttr compares values   PASS");
        } else {
            fmt::Println!("[ 4] hasAttr compares values   FAIL");
            failed += 1;
        }
    }

    // 5. inGroup separates "absent" from "not a map", and descends
    //    into a real group.
    {
        let inner = m(&[("a", Any::new(s("1")))]);
        let rec = m(&[
            ("g", Any::new(inner)),
            ("flat", Any::new(s("not a map"))),
        ]);

        let descends = inGroup(s("g"), hasKey(s("a")))(&rec).Len() == 0;
        let absent = inGroup(s("nope"), hasKey(s("a")))(&rec);
        let notmap = inGroup(s("flat"), hasKey(s("a")))(&rec);

        if descends
            && absent == s("missing group \"nope\"")
            && notmap == s("value for group \"flat\" is not map[string]any")
        {
            fmt::Println!("[ 5] inGroup distinguishes     PASS");
        } else {
            fmt::Println!("[ 5] inGroup distinguishes     FAIL [", absent, "] [", notmap, "]");
            failed += 1;
        }
    }

    // 6. A check inside a group that fails reports the inner problem,
    //    so a handler author sees which attribute is wrong rather than
    //    just "the group is wrong".
    {
        let inner = m(&[("a", Any::new(s("1")))]);
        let rec = m(&[("g", Any::new(inner))]);
        let got = inGroup(s("g"), hasKey(s("b")))(&rec);
        if got == s("missing key \"b\"") {
            fmt::Println!("[ 6] inner failure surfaces    PASS");
        } else {
            fmt::Println!("[ 6] inner failure surfaces    FAIL [", got, "]");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
