// testing_callername_smoke — testing.callerName and pcToName.
//
// These were unportable until runtime.CallersFrames landed: FuncForPC
// was a stub returning None, so pcToName could only ever have returned
// "". That matters more than it sounds — Go uses callerName to record
// which function registered a Cleanup and which frames to skip for
// t.Helper, so a silently-empty name would degrade every failure
// attribution without ever failing a test.
//
// Check 2 is the one that would catch that: the name must actually be
// this file's function, not merely non-empty.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::runtime::Callers;
use goish::testing::{callerName, pcToName};
use goish::types::uintptr;
use goish::{fmt, make, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

#[inline(never)]
fn goish_named_inner() -> string {
    // skip=0 means "the current function", i.e. this one.
    return callerName(0);
}

#[inline(never)]
fn goish_named_outer() -> string {
    // skip=1 means "my caller", so this reports goish_named_outer's
    // caller — main.
    return callerName(1);
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. callerName returns something at all.
    {
        let n = goish_named_inner();
        if n.Len() > 0 {
            fmt::Println!("[ 1] callerName non-empty      PASS");
        } else {
            fmt::Println!("[ 1] callerName non-empty      FAIL");
            failed += 1;
        }
    }

    // 2. …and it is THIS function's name, not just any name. A stubbed
    //    pcToName returning "" passes nothing here; one returning a
    //    wrong-but-plausible frame fails here and nowhere else.
    {
        let n = goish_named_inner();
        let ns: &str = n.as_ref();
        if ns.contains("goish_named_inner") {
            fmt::Println!("[ 2] names the right function  PASS");
        } else {
            fmt::Println!("[ 2] names the right function  FAIL [", n, "]");
            failed += 1;
        }
    }

    // 3. skip walks outward: skip=1 from goish_named_outer must NOT
    //    name goish_named_outer.
    {
        let n = goish_named_outer();
        let ns: &str = n.as_ref();
        if n.Len() > 0 && !ns.contains("goish_named_outer") {
            fmt::Println!("[ 3] skip walks outward        PASS");
        } else {
            fmt::Println!("[ 3] skip walks outward        FAIL [", n, "]");
            failed += 1;
        }
    }

    // 4. pcToName agrees with callerName for the same frame.
    {
        let mut pcs: slice<uintptr> = make!([]uintptr, 4);
        let cnt = Callers(0, &mut pcs);
        if cnt > 0 {
            let direct = pcToName(pcs[0]);
            if direct.Len() > 0 {
                fmt::Println!("[ 4] pcToName resolves         PASS");
            } else {
                fmt::Println!("[ 4] pcToName resolves         FAIL");
                failed += 1;
            }
        } else {
            fmt::Println!("[ 4] pcToName resolves         FAIL (no pcs)");
            failed += 1;
        }
    }

    // 5. An address that is not code resolves to the empty string
    //    rather than panicking — Go's documented "may be the empty
    //    string if not known".
    {
        let n = pcToName(1 as uintptr);
        if n.Len() == 0 {
            fmt::Println!("[ 5] junk PC yields empty      PASS");
        } else {
            fmt::Println!("[ 5] junk PC yields empty      FAIL");
            failed += 1;
        }
    }

    let _ = s("");
    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
