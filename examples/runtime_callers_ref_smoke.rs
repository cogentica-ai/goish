// runtime_callers_ref_smoke — `Callers` and its skip semantics
// (issue #9's foundation).
//
// A profile sample IS a stack, so `runtime::Callers` is what
// runtime/pprof needs before any protobuf matters (issue #9). It was
// already implemented — `collect_frames` over `segv::walk_frames`,
// bounds-checked against the running G — and had never been diffed
// against Go.
//
// What is pinned is `skip`, because an off-by-one there produces a
// stack that looks entirely plausible and attributes every sample one
// frame too deep. Go's doc: 0 identifies "the frame for Callers itself"
// and 1 "the caller of Callers". Measured
// (tools/gen_callers_ref.go):
//
//     skip=0 top=Callers
//     skip=1 top=three
//     skip=2 top=two
//     skip=3 top=one
//     empty_dst  0
//
// The rows assert the NAME at the top of the stack, not how many
// frames came back: a `skip` that is off by one returns the right COUNT
// and the wrong stack, so a count-based check passes while every sample
// is attributed one frame too deep. That is the failure this file
// exists to catch, and it is the one I made in a throwaway
// reimplementation before finding `Callers` already existed.
//
// goish's names are Rust symbols, so the rows compare a SUFFIX — the
// function's own name — rather than Go's package-qualified form.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::runtime::symbolize::{self, SymInfo};
use goish::strings;
use goish::types::int;

static FAILED: AtomicUsize = AtomicUsize::new(0);

/// Go's rows, with the function name only — goish's symbols are Rust
/// paths, so the assertion is that the frame is IN that function.
const GO: [(&str, &str); 4] = [
    ("skip=0", "Callers"),
    ("skip=1", "three"),
    ("skip=2", "two"),
    ("skip=3", "one"),
];

#[inline(never)]
fn three(skip: int, pcs: &mut goish::slice<goish::types::uintptr>) -> int {
    return goish::runtime::Callers(skip, pcs);
}

#[inline(never)]
fn two(skip: int, pcs: &mut goish::slice<goish::types::uintptr>) -> int {
    return three(skip, pcs);
}

#[inline(never)]
fn one(skip: int, pcs: &mut goish::slice<goish::types::uintptr>) -> int {
    return two(skip, pcs);
}

/// The name of the function a PC falls in, or "<none>".
fn top_name(pc: u64) -> string {
    let mut si = SymInfo::default();
    if !symbolize::symbolize(pc, &mut si) {
        return string::from_static("<unsymbolised>");
    }
    return string::from_bytes(&si.fn_name[..si.fn_name_len]);
}

fn check(cond: bool, what: &string) {
    if cond {
        fmt::Printf!("[ok] %s\n", what);
    } else {
        fmt::Printf!("[!!] %s\n", what);
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
}

#[goish::main]
fn main() {
    for (label, want) in GO.iter() {
        let skip = match *label {
            "skip=0" => 0i64,
            "skip=1" => 1i64,
            "skip=2" => 2i64,
            _ => 3i64,
        };
        let mut pcs = goish::make!([]goish::types::uintptr, 16);
        let n = one(int::from(skip), &mut pcs);
        let name = if n > int::from(0) {
            top_name(pcs[int::from(0)] as u64)
        } else {
            string::from_static("<none>")
        };
        // Rust symbols are mangled and package-qualified differently
        // from Go's, so the row asserts the function's own name appears
        // in the frame rather than an exact match.
        let ok = strings::Contains(&name, *want);
        check(
            ok,
            &fmt::Sprintf!(
                "%-8s top contains %-10s (got %s, %d frames)",
                string::from_bytes(label.as_bytes()),
                string::from_bytes(want.as_bytes()),
                name,
                n
            ),
        );
    }

    // A zero-length destination records nothing, as Go's does.
    let mut none = goish::make!([]goish::types::uintptr, 0);
    let n = goish::runtime::Callers(int::from(0), &mut none);
    check(
        n == int::from(0),
        &fmt::Sprintf!("empty_dst records nothing (got %d)", n),
    );

    // The stack must reach the runtime entry, which is what makes a
    // sample attributable rather than a stub: one frame would also
    // "work" and say nothing.
    let mut pcs = goish::make!([]goish::types::uintptr, 32);
    let n = one(int::from(1), &mut pcs);
    check(
        n >= int::from(4),
        &fmt::Sprintf!("a real stack is deep (got %d frames)", n),
    );
    let mut saw_entry = false;
    for i in 0..(n as usize) {
        if strings::Contains(&top_name(pcs[int::from(i as i64)] as u64), "goish_main") {
            saw_entry = true;
        }
    }
    check(saw_entry, &string::from_static("the walk reaches __goish_main"));

    let f = FAILED.load(Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok\n");
}
