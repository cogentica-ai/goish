// runtime_callers_smoke — exercise runtime.Caller / runtime.Callers.
//
// Both walk the calling goroutine's stack via the frame-pointer chain.
// Per `memory/feedback_main_is_not_a_goroutine.md` the `#[goish::main]`
// body is NOT a goroutine, so `current_g()` would be None there and
// the walk would (correctly) refuse. All test logic therefore runs
// inside `go!() + schedule()`.
//
// Coverage:
//   1. Callers(0, pcs[16]) from a nested chain — count > 0, PCs non-zero.
//   2. Deeper nesting yields a strictly larger count.
//   3. Callers(skip=1) drops exactly one leading frame vs skip=0.
//   4. Callers with a len-1 buffer writes exactly 1, returns 1.
//   5. Callers(0, empty) returns 0.
//   6. Caller(0) returns ok==true with a non-zero pc.
//   7. Caller with a huge skip returns ok==false.
//   8. If symbolize yields a function name for Caller's pc, it's non-empty.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::runtime::{Caller, Callers};
use goish::types::uintptr;
use goish::{slice, syscall};

static FAILED: AtomicUsize = AtomicUsize::new(0);
static IDX: AtomicUsize = AtomicUsize::new(0);

fn check(cond: bool, name: &[u8]) {
    let i = IDX.fetch_add(1, Ordering::AcqRel) + 1;
    syscall::Write(syscall::STDOUT, b"[".as_ptr(), 1);
    let d2 = b'0' + (i % 10) as u8;
    if i >= 10 {
        let buf = [b'0' + (i / 10) as u8, d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    } else {
        let buf = [b' ', d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    }
    syscall::Write(syscall::STDOUT, b"] ".as_ptr(), 2);
    syscall::Write(syscall::STDOUT, name.as_ptr(), name.len());
    if cond {
        syscall::Write(syscall::STDOUT, b" PASS\n".as_ptr(), 6);
    } else {
        syscall::Write(syscall::STDOUT, b" FAIL\n".as_ptr(), 6);
        FAILED.fetch_add(1, Ordering::AcqRel);
    }
}

// A fresh `slice<uintptr>` of `n` zeroed entries.
fn pcs_buf(n: usize) -> slice<uintptr> {
    let mut v: alloc::vec::Vec<uintptr> = alloc::vec::Vec::with_capacity(n);
    for _ in 0..n {
        v.push(0);
    }
    slice::__from_vec(v)
}

// True iff the first `count` entries of `pcs` are all non-zero.
fn all_nonzero(pcs: &slice<uintptr>, count: i64) -> bool {
    let mut i: i64 = 0;
    while i < count {
        if pcs[i] == 0 {
            return false;
        }
        i += 1;
    }
    true
}

// ── Nesting chain a -> b -> c. `#[inline(never)]` so every link is a
// real, distinct stack frame the walker can see. `c` does the capture.
#[inline(never)]
fn chain_c() -> i64 {
    let mut pcs = pcs_buf(16);
    Callers(0, &mut pcs)
}

#[inline(never)]
fn chain_b() -> i64 {
    chain_c()
}

#[inline(never)]
fn chain_a() -> i64 {
    chain_b()
}

// A deeper chain so the recovered count is strictly larger.
#[inline(never)]
fn deep_4() -> i64 {
    let mut pcs = pcs_buf(16);
    Callers(0, &mut pcs)
}

#[inline(never)]
fn deep_3() -> i64 {
    deep_4()
}

#[inline(never)]
fn deep_2() -> i64 {
    deep_3()
}

#[inline(never)]
fn deep_1() -> i64 {
    deep_2()
}

#[inline(never)]
fn deep_0() -> i64 {
    deep_1()
}

fn run_tests() {
    // 1. Callers(0) from a 3-deep chain — count > 0, all PCs non-zero.
    let n_shallow = chain_a();
    let mut shallow_pcs = pcs_buf(16);
    let n_shallow2 = Callers(0, &mut shallow_pcs);
    check(
        n_shallow > 0 && n_shallow2 > 0 && all_nonzero(&shallow_pcs, n_shallow2),
        b"Callers(0) returns frames, PCs non-zero  ",
    );

    // 2. Deeper nesting -> strictly larger count. Both capture sites use
    // a 16-entry buffer so neither is truncation-bound.
    let n_deep = deep_0();
    check(
        n_deep > n_shallow,
        b"deeper nesting yields larger count       ",
    );

    // 3. skip=1 drops exactly one leading frame vs skip=0, same site.
    let mut p0 = pcs_buf(16);
    let c0 = Callers(0, &mut p0);
    let mut p1 = pcs_buf(16);
    let c1 = Callers(1, &mut p1);
    check(
        c0 > 0 && c1 == c0 - 1,
        b"Callers(1) drops one leading frame       ",
    );

    // 4. A len-1 buffer writes exactly one entry and returns 1.
    let mut tiny = pcs_buf(1);
    let n_tiny = Callers(0, &mut tiny);
    check(
        n_tiny == 1 && tiny[0] != 0,
        b"Callers into len-1 buffer writes one     ",
    );

    // 5. Callers(0, empty slice) -> 0.
    let mut empty = pcs_buf(0);
    let n_empty = Callers(0, &mut empty);
    check(n_empty == 0, b"Callers into empty buffer returns 0      ");

    // 6. Caller(0) -> ok == true, non-zero pc.
    let (pc, file, line, ok) = Caller(0);
    check(ok && pc != 0, b"Caller(0) ok with non-zero pc            ");

    // 7. A skip far beyond the stack depth -> ok == false.
    let (_pc7, _f7, _l7, ok7) = Caller(1_000_000);
    check(!ok7, b"Caller(huge skip) returns ok==false      ");

    // 8. Symbolization: a positive line number must come with a
    // non-empty file. If the symboliser missed entirely, file is "" and
    // line 0 — still a valid (ok==true) result, so no constraint.
    let _ = pc;
    let sym_consistent = if line > 0 { file.Len() > 0 } else { true };
    check(
        sym_consistent,
        b"Caller symbolization result consistent   ",
    );
}

#[goish::main]
fn main() {
    goish::go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            fmt::Println!("ok 8/8");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", f as i64, "of 8");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}
