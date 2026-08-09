// errors_join_smoke — exercise errors::Join.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::errors;
use goish::goslice::slice;
use goish::{string, syscall};

fn errs(items: &[goish::error]) -> slice<goish::error> {
    let mut s: slice<goish::error> = slice::__from_vec(alloc::vec::Vec::new());
    for it in items.iter() {
        s = goish::append!(s, it.clone());
    }
    s
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let e1 = errors::New(string("first"));
    let e2 = errors::New(string("second"));
    let e3 = errors::New(string("third"));

    // 1. All-nil → nil.
    {
        let nil_a = errors::nil.clone();
        let nil_b = errors::nil.clone();
        let j = errors::Join(errs(&[nil_a, nil_b]));
        if j.IsNil() {
            fmt::Println!("[ 1] all nil → nil             PASS");
        } else {
            fmt::Println!("[ 1] all nil → nil             FAIL");
            failed += 1;
        }
    }

    // 2. Single non-nil → that error verbatim.
    {
        let nil_a = errors::nil.clone();
        let j = errors::Join(errs(&[nil_a, e1.clone()]));
        if !j.IsNil() && j.Error() == "first" {
            fmt::Println!("[ 2] single non-nil            PASS");
        } else {
            fmt::Println!("[ 2] single non-nil            FAIL");
            failed += 1;
        }
    }

    // 3. Two errors → newline-joined message.
    {
        let j = errors::Join(errs(&[e1.clone(), e2.clone()]));
        if !j.IsNil() && j.Error() == "first\nsecond" {
            fmt::Println!("[ 3] two joined                PASS");
        } else {
            fmt::Println!("[ 3] two joined                FAIL got={}", j.Error());
            failed += 1;
        }
    }

    // 4. Three errors with a nil mixed in.
    {
        let nil_a = errors::nil.clone();
        let j = errors::Join(errs(&[e1.clone(), nil_a, e2.clone(), e3.clone()]));
        if !j.IsNil() && j.Error() == "first\nsecond\nthird" {
            fmt::Println!("[ 4] mixed nil + non-nil       PASS");
        } else {
            fmt::Println!("[ 4] mixed nil + non-nil       FAIL got={}", j.Error());
            failed += 1;
        }
    }

    // 5. Empty input → nil.
    {
        let j = errors::Join(errs(&[]));
        if j.IsNil() {
            fmt::Println!("[ 5] empty → nil               PASS");
        } else {
            fmt::Println!("[ 5] empty → nil               FAIL");
            failed += 1;
        }
    }

    // 6. errors::Is on the first wrapped sentinel.
    {
        let j = errors::Join(errs(&[e1.clone(), e2.clone()]));
        if errors::Is(j, e1.clone()) {
            fmt::Println!("[ 6] Is(joined, first)         PASS");
        } else {
            fmt::Println!("[ 6] Is(joined, first)         FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 6", failed);
        syscall::Exit(1);
    }
}
