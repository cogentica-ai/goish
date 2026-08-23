// testing_flags_smoke — the two testing flag value types that carry
// real parsing logic: -test.benchtime and -test.v.
//
// durationOrCountFlag is the interesting one. `-benchtime` accepts
// EITHER a duration ("2s") or an iteration count ("100x"), and Go
// stores them in two separate fields rather than a tagged union, with
// `n > 0` as the discriminator. Three details follow from that and are
// each easy to get wrong:
//
//   * A successful Set REPLACES the whole struct — Go writes
//     `*f = durationOrCountFlag{n: int(n)}`. So parsing "100x" clears
//     any duration AND clears allowZero. Writing it as a field
//     assignment instead would leave allowZero set and let a later
//     Set("0") through. Check 5 pins this.
//   * allowZero gates zero in both branches, so "0x" and "0s" are
//     rejected by default but accepted when it is set.
//   * String() round-trips through whichever field is live.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::testing::benchmark::durationOrCountFlag;
use goish::testing::{self, chattyFlag, shouldFailFast};
use goish::time;
use goish::{errors, fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

/// Attr rejects a key containing whitespace, reporting through Errorf
/// rather than panicking — so it fails its own test and nothing else.
fn attr_bad_key(t: &mut testing::T) {
    t.Attr(s("has space"), s("v"));
}

/// …and a tab counts too: Go tests the key with unicode.IsSpace, not
/// against a literal ' '.
fn attr_tab_key(t: &mut testing::T) {
    t.Attr(s("has\ttab"), s("v"));
}

/// A newline in the VALUE is rejected on the other branch, because it
/// would forge a record boundary in the test output stream.
fn attr_bad_value(t: &mut testing::T) {
    t.Attr(s("key"), s("line1\nline2"));
}

/// A clean attribute is accepted. goish has no chatty printer wired up
/// yet, so this emits nothing — but it must not FAIL, which is what a
/// validation check with an inverted condition would do.
fn attr_ok(t: &mut testing::T) {
    t.Attr(s("key"), s("value"));
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. A count parses into n, leaving d zero.
    {
        let mut f = durationOrCountFlag::default();
        let err = f.Set(s("100x"));
        if err == errors::nil && f.n == 100 && f.d == time::Duration(0) {
            fmt::Println!("[ 1] count parses              PASS");
        } else {
            fmt::Println!("[ 1] count parses              FAIL n=", f.n);
            failed += 1;
        }
    }

    // 2. A duration parses into d, leaving n zero — which matters
    //    because n is the discriminator String() reads.
    {
        let mut f = durationOrCountFlag::default();
        let err = f.Set(s("2s"));
        if err == errors::nil && f.n == 0 && f.d == 2 * time::Second {
            fmt::Println!("[ 2] duration parses           PASS");
        } else {
            fmt::Println!("[ 2] duration parses           FAIL");
            failed += 1;
        }
    }

    // 3. Zero and negative are rejected in both branches while
    //    allowZero is unset, and the two branches report different
    //    messages so a user can tell which one they hit.
    {
        let mut a = durationOrCountFlag::default();
        let e1 = a.Set(s("0x"));
        let mut b = durationOrCountFlag::default();
        let e2 = b.Set(s("0s"));
        let mut c = durationOrCountFlag::default();
        let e3 = c.Set(s("-1x"));
        let mut d = durationOrCountFlag::default();
        let e4 = d.Set(s("garbage"));

        if e1.Error() == s("invalid count")
            && e2.Error() == s("invalid duration")
            && e3.Error() == s("invalid count")
            && e4.Error() == s("invalid duration")
        {
            fmt::Println!("[ 3] zero and junk rejected    PASS");
        } else {
            fmt::Println!("[ 3] zero and junk rejected    FAIL");
            failed += 1;
        }
    }

    // 4. allowZero opens both branches to zero.
    {
        let mut a = durationOrCountFlag {
            allowZero: true,
            ..Default::default()
        };
        let e1 = a.Set(s("0x"));
        let mut b = durationOrCountFlag {
            allowZero: true,
            ..Default::default()
        };
        let e2 = b.Set(s("0s"));
        if e1 == errors::nil && e2 == errors::nil {
            fmt::Println!("[ 4] allowZero permits zero    PASS");
        } else {
            fmt::Println!("[ 4] allowZero permits zero    FAIL");
            failed += 1;
        }
    }

    // 5. A successful Set replaces the WHOLE value, so allowZero does
    //    not survive it. This is what a field-assignment rewrite would
    //    break: the second Set("0x") below would then succeed.
    {
        let mut f = durationOrCountFlag {
            allowZero: true,
            ..Default::default()
        };
        let first = f.Set(s("5x"));
        let survived = f.allowZero;
        let second = f.Set(s("0x"));
        if first == errors::nil && !survived && second.Error() == s("invalid count") {
            fmt::Println!("[ 5] Set replaces the value    PASS");
        } else {
            fmt::Println!("[ 5] Set replaces the value    FAIL");
            failed += 1;
        }
    }

    // 6. …and a duration Set clears a previously-parsed count, so the
    //    discriminator cannot end up reading a stale n.
    {
        let mut f = durationOrCountFlag::default();
        let _ = f.Set(s("100x"));
        let _ = f.Set(s("3s"));
        if f.n == 0 && f.d == 3 * time::Second {
            fmt::Println!("[ 6] duration clears count     PASS");
        } else {
            fmt::Println!("[ 6] duration clears count     FAIL n=", f.n);
            failed += 1;
        }
    }

    // 7. String() reports whichever field is live, in the spelling the
    //    flag accepts back.
    {
        let mut a = durationOrCountFlag::default();
        let _ = a.Set(s("42x"));
        let mut b = durationOrCountFlag::default();
        let _ = b.Set(s("1500ms"));
        if a.String() == s("42x") && b.String() == s("1.5s") {
            fmt::Println!("[ 7] String round-trips        PASS");
        } else {
            fmt::Println!(
                "[ 7] String round-trips        FAIL [",
                a.String(),
                "] [",
                b.String(),
                "]"
            );
            failed += 1;
        }
    }

    // 8. chattyFlag.Get returns a STRING under -v=test2json and a BOOL
    //    otherwise. flag.Getter callers type-switch on it, so the two
    //    shapes have to stay distinguishable — returning the bool in
    //    both cases would compile and silently lose test2json framing.
    {
        let json = chattyFlag {
            on: true,
            json: true,
        };
        let plain = chattyFlag {
            on: true,
            json: false,
        };
        let gj = json.Get();
        let gp = plain.Get();
        let isStr = gj.As::<string>().is_some();
        let isBool = gp.As::<bool>() == Some(&true);
        if isStr && gj.As::<string>() == Some(&s("test2json")) && isBool {
            fmt::Println!("[ 8] chattyFlag.Get shapes     PASS");
        } else {
            fmt::Println!("[ 8] chattyFlag.Get shapes     FAIL");
            failed += 1;
        }
    }

    // 9. prefix() is the framing marker under test2json and empty
    //    otherwise — the byte test2json splits records on.
    {
        let json = chattyFlag {
            on: true,
            json: true,
        };
        let plain = chattyFlag {
            on: true,
            json: false,
        };
        let p = json.prefix();
        if p.Len() == 1 && p.as_bytes()[0] == 0x16 && plain.prefix().Len() == 0 {
            fmt::Println!("[ 9] chattyFlag.prefix         PASS");
        } else {
            fmt::Println!("[ 9] chattyFlag.prefix         FAIL");
            failed += 1;
        }
    }

    // 10. Attr's two rejection paths fail the test they are called
    //     from, and a clean attribute does not. Both directions,
    //     because a check whose condition is inverted passes whichever
    //     one you test alone.
    {
        fmt::Println!("--- Attr validation (the FAILs below are expected):");
        let bad_key = testing::Main(&[("AttrBadKey", attr_bad_key)]);
        let tab_key = testing::Main(&[("AttrTabKey", attr_tab_key)]);
        let bad_val = testing::Main(&[("AttrBadValue", attr_bad_value)]);
        let good = testing::Main(&[("AttrOK", attr_ok)]);
        if bad_key != 0 && tab_key != 0 && bad_val != 0 && good == 0 {
            fmt::Println!("[10] Attr validates            PASS");
        } else {
            fmt::Println!("[10] Attr validates            FAIL");
            failed += 1;
        }
    }

    // 11. shouldFailFast needs BOTH halves: the flag AND a failure.
    //     Either alone must be false, or -failfast would stop a green
    //     run, or a single failure would stop a run nobody asked to
    //     stop. Init has not run here, so no flag is registered and the
    //     answer is false regardless of how many tests failed above —
    //     and several deliberately did.
    {
        if !shouldFailFast() {
            fmt::Println!("[11] failfast needs both       PASS");
        } else {
            fmt::Println!("[11] failfast needs both       FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 11/11");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 11");
        syscall::Exit(1);
    }
}
