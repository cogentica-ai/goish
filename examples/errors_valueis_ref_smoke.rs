// errors_valueis_ref_smoke — errors::Is on a COMPARABLE value error.
//
// Go's errors.Is compares two interface values with `==`, which for a
// comparable dynamic type is a type-AND-value comparison. So a named
// int32 error matches another of the same value with no hook at all.
// goish's `error` is an `Arc<dyn ErrorTrait>` and `==` on it is POINTER
// identity, so the same value converted twice produced two handles that
// did not match (issue #12) — and `Is(wrapped, Code(7))` was false,
// which is exactly the routing decision lsproto makes on ErrorCode.
//
// `errors::ValueIs` is the fix, written as a one-liner in the type's
// `Is` hook — Go's own extension point, the one `syscall.Errno` uses.
//
// The `both_render_same` row is why this cannot be done automatically
// by comparing messages: Code(7) and Code(9) BOTH render as "code", so
// a message comparison would call two distinct codes equal. Rust cannot
// derive value equality from `dyn Any` without specialization, so
// opting in per type is the honest option.
//
// The multi_* rows pin issue #11 (several %w operands each stay
// reachable), which already held — they are here so it stays that way.
//
// GO[] is the verbatim output of tools/gen_errors_valueis_ref.go under
// scripts/goref.sh.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

use goish::errors::{self, error, ErrorTrait};
use goish::gostring::string;
use goish::types::int;
use goish::fmt;

const GO: [&str; 9] = [
    "same_handle       true",
    "same_value        true",
    "different_value   false",
    "both_render_same  true",
    "through_wrap      true",
    "wrap_wrong_value  false",
    "multi_msg         \"left: right\"",
    "multi_left        true",
    "multi_right       true",
];

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Code(i32);

impl ErrorTrait for Code {
    fn Error(&self) -> string {
        return string::from_static("code");
    }
    // The one line that makes a comparable value error behave as Go's
    // does. Without it every row below that compares two separately
    // converted values is false.
    fn Is(&self, target: &error) -> bool {
        return errors::ValueIs(self, target);
    }
}

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let a: error = Code(7).into();
    let b: error = Code(7).into();
    let c: error = Code(9).into();

    chk(&mut ln, &fmt::Sprintf!("%-17s %v", string::from_static("same_handle"),
        errors::Is(a.clone(), a.clone())));
    chk(&mut ln, &fmt::Sprintf!("%-17s %v", string::from_static("same_value"),
        errors::Is(a.clone(), b)));
    chk(&mut ln, &fmt::Sprintf!("%-17s %v", string::from_static("different_value"),
        errors::Is(a.clone(), c.clone())));
    chk(&mut ln, &fmt::Sprintf!("%-17s %v", string::from_static("both_render_same"),
        a.Error() == c.Error()));

    let w = fmt::Errorf!("ctx: %w", a);
    let t7: error = Code(7).into();
    let t9: error = Code(9).into();
    chk(&mut ln, &fmt::Sprintf!("%-17s %v", string::from_static("through_wrap"),
        errors::Is(w.clone(), t7)));
    chk(&mut ln, &fmt::Sprintf!("%-17s %v", string::from_static("wrap_wrong_value"),
        errors::Is(w, t9)));

    let left = errors::New(string::from_static("left"));
    let right = errors::New(string::from_static("right"));
    let m = fmt::Errorf!("%w: %w", left.clone(), right.clone());
    chk(&mut ln, &fmt::Sprintf!("%-17s %q", string::from_static("multi_msg"), m.Error()));
    chk(&mut ln, &fmt::Sprintf!("%-17s %v", string::from_static("multi_left"),
        errors::Is(m.clone(), left)));
    chk(&mut ln, &fmt::Sprintf!("%-17s %v", string::from_static("multi_right"),
        errors::Is(m, right)));

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    let f = FAILED.load(core::sync::atomic::Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ln as i64, GO.len() as i64);
}
