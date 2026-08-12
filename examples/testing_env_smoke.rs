// testing_env_smoke — t.Setenv, t.Chdir and parseCpuList.
//
// The property worth pinning in Setenv is the ASYMMETRY of its restore.
// If the variable existed, cleanup puts back its old value; if it did
// NOT exist, cleanup *unsets* it rather than leaving an empty string
// behind. Those are different states — LookupEnv can tell them apart —
// and a restore that always assigned "" would look correct in every
// test that happens to check Getenv.
//
// Checks 1 and 2 are the two halves of that.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::testing::{self, parseCpuList};
use goish::{errors, fmt, os, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

/// Sets a variable that already exists; cleanup must restore the old
/// value, not unset it.
fn TestSetenvExisting(t: &mut testing::T) {
    os::Setenv(s("GOISH_SMOKE_EXISTING"), s("original"));
    t.Setenv(s("GOISH_SMOKE_EXISTING"), s("changed"));
    let (v, ok) = os::LookupEnv(s("GOISH_SMOKE_EXISTING"));
    if !ok || v != s("changed") {
        t.Error(s("Setenv did not take effect"));
    }
}

/// Sets a variable that does not exist; cleanup must UNSET it, so a
/// later LookupEnv reports ok=false rather than ("", true).
fn TestSetenvAbsent(t: &mut testing::T) {
    os::Unsetenv(s("GOISH_SMOKE_ABSENT"));
    t.Setenv(s("GOISH_SMOKE_ABSENT"), s("temporary"));
    let (v, ok) = os::LookupEnv(s("GOISH_SMOKE_ABSENT"));
    if !ok || v != s("temporary") {
        t.Error(s("Setenv did not take effect"));
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // Establish the pre-state, then run the two tests so their cleanups
    // fire, then inspect what was restored.
    os::Setenv(s("GOISH_SMOKE_EXISTING"), s("original"));
    os::Unsetenv(s("GOISH_SMOKE_ABSENT"));

    let tests: &[(&str, testing::TestFn)] = &[
        ("TestSetenvExisting", TestSetenvExisting),
        ("TestSetenvAbsent", TestSetenvAbsent),
    ];
    let code = testing::Main(tests);
    fmt::Println!("");

    // 1. A pre-existing variable is restored to its OLD value.
    {
        let (v, ok) = os::LookupEnv(s("GOISH_SMOKE_EXISTING"));
        if ok && v == s("original") {
            fmt::Println!("[ 1] existing var restored     PASS");
        } else {
            fmt::Println!("[ 1] existing var restored     FAIL");
            failed += 1;
        }
    }

    // 2. A previously-absent variable is UNSET, not emptied. This is
    //    the half a naive restore gets wrong.
    {
        let (_, ok) = os::LookupEnv(s("GOISH_SMOKE_ABSENT"));
        if !ok {
            fmt::Println!("[ 2] absent var unset again    PASS");
        } else {
            fmt::Println!("[ 2] absent var unset again    FAIL (left set)");
            failed += 1;
        }
    }

    // 3. Both tests passed on their own terms.
    {
        if code == 0 {
            fmt::Println!("[ 3] Setenv took effect        PASS");
        } else {
            fmt::Println!("[ 3] Setenv took effect        FAIL");
            failed += 1;
        }
    }

    // 4. parseCpuList: values, whitespace, and empty entries.
    {
        let (l1, e1) = parseCpuList(s("1,2,4"));
        let ok1 = e1 == errors::nil && l1.Len() == 3 && l1[0] == 1 && l1[2] == 4;
        // Whitespace is trimmed and empty entries skipped.
        let (l2, e2) = parseCpuList(s(" 2 , ,3 "));
        let ok2 = e2 == errors::nil && l2.Len() == 2 && l2[0] == 2 && l2[1] == 3;
        if ok1 && ok2 {
            fmt::Println!("[ 4] parseCpuList parses       PASS");
        } else {
            fmt::Println!("[ 4] parseCpuList parses       FAIL");
            failed += 1;
        }
    }

    // 5. An empty list defaults to one entry, the current GOMAXPROCS —
    //    never an empty list, which would run each test zero times.
    {
        let (l, e) = parseCpuList(s(""));
        if e == errors::nil && l.Len() == 1 && l[0] >= 1 {
            fmt::Println!("[ 5] empty list defaults       PASS");
        } else {
            fmt::Println!("[ 5] empty list defaults       FAIL");
            failed += 1;
        }
    }

    // 6. A malformed or non-positive entry is an error.
    {
        let (_, e1) = parseCpuList(s("1,zero,3"));
        let (_, e2) = parseCpuList(s("0"));
        let (_, e3) = parseCpuList(s("-2"));
        if e1 != errors::nil && e2 != errors::nil && e3 != errors::nil {
            fmt::Println!("[ 6] bad cpu values rejected   PASS");
        } else {
            fmt::Println!("[ 6] bad cpu values rejected   FAIL");
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
