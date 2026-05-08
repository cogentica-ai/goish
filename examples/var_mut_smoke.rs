// var_mut_smoke — exercise the `goish::var!` macro arms that emit
// atomic-backed mutable package-level globals (the runtime side of
// closing the rs/xid `pid ^= …` and `objectIDCounter` blockers).
//
// Coverage:
//   1. `pub mut N: int32 = …` routes to atomic::Int32.
//   2. `pub mut N: int = …` (Goish int = i64) routes to atomic::Int64.
//   3. `pub mut N: uint32 = …` routes to atomic::Uint32.
//   4. `pub mut N: uint = …` (Goish uint = u64) routes to atomic::Uint64.
//   5. `pub mut N: uintptr = …` routes to atomic::Uintptr.
//   6. `pub mut N: bool = …` routes to atomic::Bool.
//   7. The Xor compound op (added this session) returns the previous
//      value and updates in place.
//   8. The Add compound op returns the new value (Go's post-add
//      convention) — confirmed via objectIDCounter-style increment.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::syscall;

goish::var! {
    pub mut PID32: int32 = 0;
    pub mut PID: int = 0;
    pub mut COUNTER32: uint32 = 0;
    pub mut COUNTER: uint = 0;
    pub mut PTR: uintptr = 0;
    pub mut READY: bool = false;
}

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn ok_line(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn fail(msg: &[u8]) {
    FAILED.fetch_add(1, Ordering::AcqRel);
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    let nl: &[u8] = b"\n";
    syscall::Write(syscall::STDERR, nl.as_ptr(), nl.len());
}

#[goish::main]
fn main() {
    // 1. int32 — Store/Load/Xor.
    PID32.Store(7);
    if PID32.Load() != 7 {
        fail(b"PID32 Load mismatch");
    } else {
        ok_line(b"PASS: PID32 Load/Store\n");
    }
    let prev = PID32.Xor(0b011);
    if prev != 7 || PID32.Load() != 7 ^ 0b011 {
        fail(b"PID32 Xor wrong return / state");
    } else {
        ok_line(b"PASS: PID32 Xor returns prev + updates\n");
    }

    // 2. int (= i64) — same surface as Int64, must accept i64 args.
    PID.Store(0x1_0000_0000_i64);
    if PID.Load() != 0x1_0000_0000_i64 {
        fail(b"PID i64 round-trip failed");
    } else {
        ok_line(b"PASS: PID (int = i64) Load/Store\n");
    }

    // 3. uint32 — Add returns the post-add value (Go convention).
    let new_v = COUNTER32.Add(1);
    if new_v != 1 || COUNTER32.Load() != 1 {
        fail(b"COUNTER32 Add wrong return");
    } else {
        ok_line(b"PASS: COUNTER32 Add returns new value\n");
    }

    // 4. uint (= u64) — Add behaves the same on Uint64.
    let new_v = COUNTER.Add(42);
    if new_v != 42 || COUNTER.Load() != 42 {
        fail(b"COUNTER (uint = u64) Add wrong return");
    } else {
        ok_line(b"PASS: COUNTER (uint = u64) Add\n");
    }

    // 5. uintptr — Xor returns prev, updates in place.
    PTR.Store(0xAA);
    let prev = PTR.Xor(0x0F);
    if prev != 0xAA || PTR.Load() != 0xAA ^ 0x0F {
        fail(b"PTR Xor wrong return / state");
    } else {
        ok_line(b"PASS: PTR (uintptr) Xor\n");
    }

    // 6. bool — atomic Load/Store.
    if READY.Load() {
        fail(b"READY default should be false");
    } else {
        READY.Store(true);
        if !READY.Load() {
            fail(b"READY Store true didn't take");
        } else {
            ok_line(b"PASS: READY Load/Store\n");
        }
    }

    // 7. Free-fn variants — confirm AddUint32, XorInt64 dispatch.
    let prev = goish::sync::atomic::AddUint32(&COUNTER32, 1);
    if prev != 2 {
        fail(b"AddUint32 free-fn wrong return");
    } else {
        ok_line(b"PASS: AddUint32 free-fn\n");
    }
    let prev = goish::sync::atomic::XorInt64(&PID, 0xFF);
    if prev != 0x1_0000_0000_i64 {
        fail(b"XorInt64 free-fn wrong return");
    } else {
        ok_line(b"PASS: XorInt64 free-fn\n");
    }

    if FAILED.load(Ordering::Acquire) > 0 {
        ok_line(b"FAIL: var_mut_smoke had failures\n");
        syscall::Exit(1);
    }
    ok_line(b"OK var_mut_smoke\n");
}
