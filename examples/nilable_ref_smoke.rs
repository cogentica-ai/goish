// nilable_ref_smoke — exercise `goish::nilable_ref<T>` /
// `nilable_refmut<T>` API + niche-optimisation + bridge methods.
//
// Coverage:
//   1. nilable_ref::new(&t) is non-nil; nilable_ref::nil() is nil.
//   2. niche optimisation: sizeof(nilable_ref<T>) == sizeof(&T).
//   3. Must() / Try() / OrElse() / If().
//   4. Nil sentinel equality (== nil, nil ==, From<Nil>).
//   5. &T → nilable_ref<T> via .into().
//   6. nilable<T>::Borrow() bridge — owned → borrow cell.
//   7. nilable<T>::BorrowMut() bridge — owned → exclusive borrow.
//   8. nilable_refmut::MustMut() / TryMut() / IfMut().

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
extern crate goish;

use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::nilable;
use goish::nilable_ref;
use goish::nilable_refmut;
use goish::nilval::Nil;
use goish::syscall;

#[derive(Clone, Default)]
struct Box {
    n: i64,
    #[allow(dead_code)]
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
    // 1. Constructors.
    let b = Box { n: 7, label: 0xAA };
    let r: nilable_ref<Box> = nilable_ref::new(&b);
    if r.IsNil() {
        fail(b"nilable_ref::new(&b) should not be nil");
    } else {
        ok_line(b"PASS: nilable_ref::new is non-nil\n");
    }
    let z: nilable_ref<Box> = nilable_ref::nil();
    if !z.IsNil() {
        fail(b"nilable_ref::nil() should be nil");
    } else {
        ok_line(b"PASS: nilable_ref::nil is nil\n");
    }

    // 2. Niche optimisation — Option<&T> is pointer-sized.
    if size_of::<nilable_ref<Box>>() != size_of::<&Box>() {
        fail(b"sizeof(nilable_ref<T>) should equal sizeof(&T)");
    } else {
        ok_line(b"PASS: niche optimisation holds\n");
    }

    // 3. Must / Try / OrElse / If.
    if r.Must().n != 7 {
        fail(b"Must().n wrong on non-nil");
    } else {
        ok_line(b"PASS: Must() returns inner\n");
    }
    if r.Try().map(|t| t.n).unwrap_or(0) != 7 {
        fail(b"Try() should return Some on non-nil");
    } else {
        ok_line(b"PASS: Try() returns Some on non-nil\n");
    }
    if z.Try().is_some() {
        fail(b"Try() should return None on nil");
    } else {
        ok_line(b"PASS: Try() returns None on nil\n");
    }
    let fallback = Box { n: 99, label: 0 };
    if z.OrElse(|| &fallback).n != 99 {
        fail(b"OrElse() should hand back fallback on nil");
    } else {
        ok_line(b"PASS: OrElse() falls back on nil\n");
    }
    if r.OrElse(|| &fallback).n != 7 {
        fail(b"OrElse() should hand back inner on non-nil");
    } else {
        ok_line(b"PASS: OrElse() returns inner on non-nil\n");
    }
    if r.If(|t| t.n).unwrap_or(-1) != 7 {
        fail(b"If() should run closure on non-nil");
    } else {
        ok_line(b"PASS: If() runs on non-nil\n");
    }
    if z.If(|t| t.n).is_some() {
        fail(b"If() should be None on nil");
    } else {
        ok_line(b"PASS: If() None on nil\n");
    }

    // 4. Nil-sentinel equality.
    if z != Nil {
        fail(b"z != Nil failed");
    } else {
        ok_line(b"PASS: nilable_ref == Nil when nil\n");
    }
    if r == Nil {
        fail(b"r == Nil should be false on non-nil");
    } else {
        ok_line(b"PASS: nilable_ref != Nil when non-nil\n");
    }
    let from_nil: nilable_ref<Box> = Nil.into();
    if !from_nil.IsNil() {
        fail(b"From<Nil> didn't yield nil");
    } else {
        ok_line(b"PASS: From<Nil> coerces nilable_ref\n");
    }

    // 5. &T → nilable_ref<T> via .into().
    let lifted: nilable_ref<Box> = (&b).into();
    if lifted.Must().n != 7 {
        fail(b"&T -> nilable_ref via into() didn't lift");
    } else {
        ok_line(b"PASS: &T -> nilable_ref via .into()\n");
    }

    // 6. nilable<T>::Borrow() bridge.
    let owned = nilable::new(Box { n: 11, label: 0xBB });
    let borrowed = owned.Borrow();
    if borrowed.IsNil() || borrowed.Must().n != 11 {
        fail(b"nilable::Borrow() should view non-nil inner");
    } else {
        ok_line(b"PASS: nilable<T>.Borrow() views inner\n");
    }
    let nil_owned: nilable<Box> = nilable::nil();
    if !nil_owned.Borrow().IsNil() {
        fail(b"nilable::nil().Borrow() should yield nil");
    } else {
        ok_line(b"PASS: nil.Borrow() yields nil ref\n");
    }

    // 7. nilable<T>::BorrowMut() bridge.
    let mut owned_mut = nilable::new(Box { n: 13, label: 0 });
    {
        let bm = owned_mut.BorrowMut();
        if bm.IsNil() {
            fail(b"BorrowMut on unique should be non-nil");
        }
        bm.IfMut(|t| t.n = 99);
    }
    if owned_mut.Must().n != 99 {
        fail(b"BorrowMut + IfMut should mutate through");
    } else {
        ok_line(b"PASS: BorrowMut() yields mutable view\n");
    }
    let mut nil_mut: nilable<Box> = nilable::nil();
    if !nil_mut.BorrowMut().IsNil() {
        fail(b"nil.BorrowMut() should yield nil");
    } else {
        ok_line(b"PASS: nil.BorrowMut() yields nil refmut\n");
    }

    // 8. nilable_refmut MustMut / TryMut.
    let mut local = Box { n: 21, label: 0 };
    {
        let mr: nilable_refmut<Box> = nilable_refmut::new(&mut local);
        let inner = mr.MustMut();
        inner.n = 42;
    }
    if local.n != 42 {
        fail(b"nilable_refmut::MustMut() should yield &mut T");
    } else {
        ok_line(b"PASS: nilable_refmut MustMut mutates\n");
    }
    let null_mr: nilable_refmut<Box> = nilable_refmut::nil();
    if null_mr.TryMut().is_some() {
        fail(b"nil refmut TryMut should be None");
    } else {
        ok_line(b"PASS: nil refmut TryMut is None\n");
    }

    if FAILED.load(Ordering::Acquire) > 0 {
        ok_line(b"FAIL: nilable_ref_smoke had failures\n");
        syscall::Exit(1);
    }
    ok_line(b"OK nilable_ref_smoke\n");
}
