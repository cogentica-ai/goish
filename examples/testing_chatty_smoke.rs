// testing_chatty_smoke — pin chattyFlag, marker, prefix and
// fmtDuration against Go 1.25.5.
//
//   scripts/goref.sh testing chatty_ref.go
//     Set("true")      -> on=true  json=false  String="true"
//     Set("false")     -> on=false json=false  String="false"
//     Set("test2json") -> on=true  json=true   String="test2json"
//     Set("yes")       -> err="invalid flag -test.v=yes", state untouched
//     Set("1")         -> err="invalid flag -test.v=1"
//     Set("")          -> err="invalid flag -test.v="
//     test2json then false -> on=false json=false  (both cleared)
//     IsBoolFlag=true   marker=22 (0x16)
//     prefix(json=false)="" prefix(json=true)="\x16"
//     fmtDuration(0)        = "0.00s"
//     fmtDuration(1.5s)     = "1.50s"
//     fmtDuration(2m)       = "120.00s"   (always seconds, never "2m0s")
//     fmtDuration(1.234ms)  = "0.00s"     (rounds away to nothing)
//     fmtDuration(999ms)    = "1.00s"     (rounds up across the second)
//     fmtDuration(1.005s)   = "1.00s"     (half-to-even, not 1.01s)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::gostring::string;
use goish::testing::{chattyFlag, fmtDuration, marker, prefix};
use goish::time;
use goish::{errors, fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The three accepted spellings.
    {
        let cases: &[(&str, bool, bool, &str)] = &[
            ("true", true, false, "true"),
            ("false", false, false, "false"),
            ("test2json", true, true, "test2json"),
        ];
        let mut ok = true;
        for (arg, want_on, want_json, want_str) in cases.iter() {
            let mut f = chattyFlag::default();
            let err = f.Set(s(arg));
            if err != errors::nil
                || f.on != *want_on
                || f.json != *want_json
                || f.String() != s(want_str)
            {
                fmt::Println!("    Set(", *arg, ") wrong");
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 1] chattyFlag.Set accepted   PASS");
        } else {
            fmt::Println!("[ 1] chattyFlag.Set accepted   FAIL");
            failed += 1;
        }
    }

    // 2. Anything else is an error, with Go's exact message, and the
    //    flag is left alone rather than being coerced to false.
    {
        let cases: &[(&str, &str)] = &[
            ("yes", "invalid flag -test.v=yes"),
            ("1", "invalid flag -test.v=1"),
            ("", "invalid flag -test.v="),
        ];
        let mut ok = true;
        for (arg, want_msg) in cases.iter() {
            let mut f = chattyFlag::default();
            let err = f.Set(s(arg));
            if err == errors::nil || err.Error() != s(want_msg) || f.on || f.json {
                fmt::Println!("    Set(", *arg, ") -> ", err.Error());
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 2] chattyFlag.Set rejected   PASS");
        } else {
            fmt::Println!("[ 2] chattyFlag.Set rejected   FAIL");
            failed += 1;
        }
    }

    // 3. Setting false after test2json clears BOTH fields — `json`
    //    must not survive being turned off.
    {
        let mut f = chattyFlag::default();
        f.Set(s("test2json"));
        let mid = f.on && f.json && f.String() == s("test2json");
        f.Set(s("false"));
        if mid && !f.on && !f.json && f.String() == s("false") {
            fmt::Println!("[ 3] false clears json too     PASS");
        } else {
            fmt::Println!("[ 3] false clears json too     FAIL");
            failed += 1;
        }
    }

    // 4. IsBoolFlag and the framing marker.
    {
        let f = chattyFlag::default();
        if f.IsBoolFlag() && marker == 0x16 {
            fmt::Println!("[ 4] IsBoolFlag and marker     PASS");
        } else {
            fmt::Println!("[ 4] IsBoolFlag and marker     FAIL");
            failed += 1;
        }
    }

    // 5. prefix is the marker only in json mode.
    {
        let off = prefix(false);
        let on = prefix(true);
        if off == s("") && on.Len() == 1 && on.as_bytes()[0] == 0x16 {
            fmt::Println!("[ 5] chattyPrinter prefix      PASS");
        } else {
            fmt::Println!("[ 5] chattyPrinter prefix      FAIL");
            failed += 1;
        }
    }

    // 6. fmtDuration always renders seconds to two places — never Go's
    //    Duration.String() form. Includes the rounding cases.
    {
        let cases: &[(i64, &str)] = &[
            (0, "0.00s"),
            (1_500_000_000, "1.50s"),
            (1_000_000_000, "1.00s"),
            (120_000_000_000, "120.00s"),
            (1_234_000, "0.00s"),
            (999_000_000, "1.00s"),
            (1_005_000_000, "1.00s"),
        ];
        let mut ok = true;
        for (ns, want) in cases.iter() {
            let got = fmtDuration(time::Duration(*ns));
            if got != s(want) {
                fmt::Println!("    fmtDuration(", *ns, ") = ", got, " want ", *want);
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 6] fmtDuration               PASS");
        } else {
            fmt::Println!("[ 6] fmtDuration               FAIL");
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
