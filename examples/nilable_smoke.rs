// nilable_smoke — exercise `goish::nilable<T>` API + Deref behaviour.
//
// Coverage:
//   1. nilable::new(t) is non-nil; nilable::nil() / Default is nil.
//   2. `x == nil` / `nil == x` works via PartialEq<Nil>.
//   3. Deref: `(*x).field` (no panic for non-nil); `x.method()` auto-derefs.
//   4. From<Nil> coerces `nil.into()` to nil-shaped nilable.
//   5. Clone preserves nil-ness and inner T equality.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::nilable::nilable;
use goish::nilval::Nil;
use goish::syscall;

#[derive(Clone, Default)]
struct Box {
    n: i64,
    label: u8,
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
    // 1. new vs nil constructors.
    let b = nilable::new(Box { n: 7, label: 0xAA });
    if b.IsNil() {
        fail(b"new(...) should not be nil");
    } else {
        ok_line(b"PASS: nilable::new is non-nil\n");
    }
    let z: nilable<Box> = nilable::nil();
    if !z.IsNil() {
        fail(b"nil() should be nil");
    } else {
        ok_line(b"PASS: nilable::nil is nil\n");
    }

    // 2. Equality with Nil sentinel.
    if z != Nil {
        fail(b"nil_z != Nil failed");
    } else {
        ok_line(b"PASS: nilable == Nil\n");
    }
    if b == Nil {
        fail(b"non-nil should not equal Nil");
    } else {
        ok_line(b"PASS: non-nil != Nil\n");
    }

    // 3. Deref / field access on non-nil.
    if b.n != 7 || b.label != 0xAA {
        fail(b"Deref field access wrong on non-nil");
    } else {
        ok_line(b"PASS: Deref field access\n");
    }

    // 4. From<Nil> coercion.
    let from_nil: nilable<Box> = Nil.into();
    if !from_nil.IsNil() {
        fail(b"From<Nil> didn't yield nil");
    } else {
        ok_line(b"PASS: From<Nil> coerces to nil\n");
    }

    // 5. Clone semantics.
    let b2 = b.clone();
    if b2.IsNil() || b2.n != 7 {
        fail(b"Clone preserves field");
    } else {
        ok_line(b"PASS: Clone of non-nil preserves field\n");
    }
    let z2: nilable<Box> = z.clone();
    if !z2.IsNil() {
        fail(b"Clone of nil should be nil");
    } else {
        ok_line(b"PASS: Clone of nil stays nil\n");
    }

    if FAILED.load(Ordering::Acquire) > 0 {
        ok_line(b"FAIL: nilable_smoke had failures\n");
        syscall::Exit(1);
    }
    ok_line(b"OK nilable_smoke\n");
}
