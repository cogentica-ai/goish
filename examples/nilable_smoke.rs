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

use goish::nilable;
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

    // 3. Field access via Must() narrowing (Deref/DerefMut were
    //    removed — direct `b.n` is now a compile error).
    {
        let inner = b.Must();
        if inner.n != 7 || inner.label != 0xAA {
            fail(b"Field access wrong on non-nil");
        } else {
            ok_line(b"PASS: Must() field access\n");
        }
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
    if b2.IsNil() || b2.Must().n != 7 {
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

    // 6. Safe accessors — non-panicking read paths.
    if b.Try().map(|t| t.n).unwrap_or(0) != 7 {
        fail(b"Try on non-nil should return Some(&T)");
    } else {
        ok_line(b"PASS: Try() returns Some on non-nil\n");
    }
    if z.Try().is_some() {
        fail(b"Try on nil should return None");
    } else {
        ok_line(b"PASS: Try() returns None on nil\n");
    }
    if z.OrDefault().n != 0 {
        fail(b"OrDefault on nil should give zero");
    } else {
        ok_line(b"PASS: OrDefault() falls back to default\n");
    }
    if z.OrElse(|| Box { n: 99, label: 0 }).n != 99 {
        fail(b"OrElse on nil should call closure");
    } else {
        ok_line(b"PASS: OrElse() falls back to closure\n");
    }
    let len = b.If(|t| t.n).unwrap_or(-1);
    if len != 7 {
        fail(b"If on non-nil should run closure");
    } else {
        ok_line(b"PASS: If() runs closure on non-nil\n");
    }
    if z.If(|t| t.n).is_some() {
        fail(b"If on nil should be None");
    } else {
        ok_line(b"PASS: If() returns None on nil\n");
    }
    let mut taken = nilable::new(Box { n: 5, label: 0 });
    if let Some(t) = taken.Take() {
        if t.n != 5 || !taken.IsNil() {
            fail(b"Take should hand over the value and leave nil");
        } else {
            ok_line(b"PASS: Take() removes value, leaves nil\n");
        }
    } else {
        fail(b"Take on non-nil should return Some");
    }

    if FAILED.load(Ordering::Acquire) > 0 {
        ok_line(b"FAIL: nilable_smoke had failures\n");
        syscall::Exit(1);
    }
    ok_line(b"OK nilable_smoke\n");
}
