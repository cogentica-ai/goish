// nilable_conversions — every direction across the pointer-shape
// matrix.
//
//                 ┌──────────────┬──────────────────────────────────┐
//                 │ non-null     │ nullable                         │
//   ┌─────────────┼──────────────┼──────────────────────────────────┤
//   │ owned       │ T            │ nilable<T>                       │
//   │ borrowed    │ &T  / &mut T │ nilable<&T> / nilable<&mut T>    │
//   └─────────────┴──────────────┴──────────────────────────────────┘
//
// Every cell is reachable from every other, with these realities:
//
//   - Cells in the "nullable" column may be Nil. Conversion that
//     crosses INTO a non-null cell requires a narrowing (Must / Try /
//     Borrow + Must) that panics on absent values.
//   - Cells in the "borrowed" row carry a lifetime. Conversion BACK
//     to the "owned" row requires materialising a fresh T — i.e. a
//     `.clone()` call against an inner reference. So borrow→owned
//     requires `T: Clone`.
//   - The borrow-immut → borrow-mut upgrade does NOT exist in safe
//     Rust. You can downgrade `&mut T` → `&T` (reborrow), but not the
//     other way.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::nilable;
use goish::nilable_ref;
use goish::nilable_refmut;
use goish::nilval::Nil;
use goish::syscall;

#[derive(Default, Clone)]
struct T {
    x: i64,
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
    // ─── Owned T entry points ─────────────────────────────────────
    let t = T { x: 7 };
    ok_line(b"-- starting --\n");

    // ── 1. T → nilable<T> ─── owned, may-be-nil container ──────────
    let owned: nilable<T> = nilable::new(T { x: 7 });
    if owned.Must().x != 7 {
        fail(b"1. T -> nilable<T> via nilable::new");
    } else {
        ok_line(b"PASS: 1. T -> nilable<T>            (nilable::new)\n");
    }

    // ── 2. T → &T ─── inherent borrow, no Goish API needed ────────
    let r: &T = &t;
    if r.x != 7 {
        fail(b"2. T -> &T");
    } else {
        ok_line(b"PASS: 2. T -> &T                    (& operator)\n");
    }

    // ── 3. &T → nilable<&T> ─── borrow-nullable cell lift ─────────
    let from_ref: nilable_ref<'_, T> = (&t).into();
    if from_ref.Must().x != 7 {
        fail(b"3. &T -> nilable<&T>");
    } else {
        ok_line(b"PASS: 3. &T -> nilable<&T>          (From<&T>)\n");
    }

    // ── 4. &mut T → nilable<&mut T> ─── exclusive-borrow lift ─────
    let mut t4 = T { x: 11 };
    {
        let from_mut: nilable_refmut<'_, T> = (&mut t4).into();
        from_mut.MustMut().x = 42;
    }
    if t4.x != 42 {
        fail(b"4. &mut T -> nilable<&mut T>");
    } else {
        ok_line(b"PASS: 4. &mut T -> nilable<&mut T>  (From<&mut T>)\n");
    }

    // ── 5. nilable<T> → nilable<&T> ─── the Borrow() bridge ───────
    // The owned cell views as a borrow-nullable. Inner T stays owned
    // by `owned`; the borrow's lifetime is `&owned`'s.
    let view: nilable_ref<'_, T> = owned.Borrow();
    if view.Must().x != 7 {
        fail(b"5. nilable<T> -> nilable<&T>");
    } else {
        ok_line(b"PASS: 5. nilable<T> -> nilable<&T>  (.Borrow())\n");
    }

    // ── 6. nilable<T> → nilable<&mut T> ─── the BorrowMut() bridge ─
    // Panics if the inner Arc is shared (refcount > 1) — match
    // MustMut's policy.
    let mut owned_mut: nilable<T> = nilable::new(T { x: 50 });
    {
        let mut_view: nilable_refmut<'_, T> = owned_mut.BorrowMut();
        mut_view.MustMut().x = 99;
    }
    if owned_mut.Must().x != 99 {
        fail(b"6. nilable<T> -> nilable<&mut T>");
    } else {
        ok_line(b"PASS: 6. nilable<T> -> nilable<&mut T> (.BorrowMut())\n");
    }

    // ── 7. nilable<T> → T ─── consuming narrow ─────────────────────
    // Panics on nil or on shared (Arc::try_unwrap).
    let extract = nilable::new(T { x: 21 });
    let taken: T = extract.MustTake();
    if taken.x != 21 {
        fail(b"7. nilable<T> -> T (MustTake)");
    } else {
        ok_line(b"PASS: 7. nilable<T> -> T            (MustTake)\n");
    }

    // ── 8. nilable<T> → &T ─── borrow narrow ───────────────────────
    let owned8: nilable<T> = nilable::new(T { x: 12 });
    let inner: &T = owned8.Must();
    if inner.x != 12 {
        fail(b"8. nilable<T> -> &T (Must)");
    } else {
        ok_line(b"PASS: 8. nilable<T> -> &T           (Must)\n");
    }

    // ── 9. nilable<T> → &mut T ─── mut-borrow narrow ───────────────
    // Panics on nil or shared.
    let mut owned9: nilable<T> = nilable::new(T { x: 33 });
    {
        let m: &mut T = owned9.MustMut();
        m.x = 34;
    }
    if owned9.Must().x != 34 {
        fail(b"9. nilable<T> -> &mut T (MustMut)");
    } else {
        ok_line(b"PASS: 9. nilable<T> -> &mut T       (MustMut)\n");
    }

    // ── 10. nilable<&T> → &T ─── borrow extract ────────────────────
    let owned10 = T { x: 4 };
    let nr: nilable_ref<'_, T> = (&owned10).into();
    let extracted: &T = nr.Must();
    if extracted.x != 4 {
        fail(b"10. nilable<&T> -> &T (Must)");
    } else {
        ok_line(b"PASS: 10. nilable<&T> -> &T          (Must)\n");
    }

    // ── 11. nilable<&T> → nilable<T> ─── borrow → owned via clone ──
    // Materialise a fresh T by cloning the inner. Requires T: Clone.
    // Goish doesn't ship a one-liner for this — the transpiler emits
    // the explicit construction at sites where the slot pressure
    // demands it. Shown by hand here.
    let owned11 = T { x: 88 };
    let view11: nilable_ref<'_, T> = (&owned11).into();
    let back_to_owned: nilable<T> = match view11.Try() {
        Some(r) => nilable::new(r.clone()),
        None => Nil.into(),
    };
    if back_to_owned.Must().x != 88 {
        fail(b"11. nilable<&T> -> nilable<T>");
    } else {
        ok_line(b"PASS: 11. nilable<&T> -> nilable<T>  (clone + new)\n");
    }

    // ── 12. nilable<&mut T> → &mut T ─── exclusive-borrow extract ──
    let mut owned12 = T { x: 1 };
    {
        let mrr: nilable_refmut<'_, T> = (&mut owned12).into();
        let r12: &mut T = mrr.MustMut();
        r12.x = 100;
    }
    if owned12.x != 100 {
        fail(b"12. nilable<&mut T> -> &mut T (MustMut)");
    } else {
        ok_line(b"PASS: 12. nilable<&mut T> -> &mut T  (MustMut)\n");
    }

    // ── 13. nilable<&mut T> → nilable<&T> ─── downgrade ────────────
    // The `Must(&self) -> &T` method on nilable_refmut lets you take
    // a read-only view without consuming the mut borrow. Wrap the
    // result to produce a borrow-nullable nilable_ref.
    let mut owned13 = T { x: 7 };
    let mrr13: nilable_refmut<'_, T> = (&mut owned13).into();
    let downgraded: nilable_ref<'_, T> = nilable_ref::new(mrr13.Must());
    if downgraded.Must().x != 7 {
        fail(b"13. nilable<&mut T> -> nilable<&T>");
    } else {
        ok_line(b"PASS: 13. nilable<&mut T> -> nilable<&T> (downgrade)\n");
    }

    // ── 14. Nil sentinel → every nullable cell ────────────────────
    let _nil_o: nilable<T> = Nil.into();
    let _nil_r: nilable_ref<'_, T> = Nil.into();
    let _nil_m: nilable_refmut<'_, T> = Nil.into();
    ok_line(b"PASS: 14. Nil -> {nilable<T>, nilable<&T>, nilable<&mut T>}\n");

    // ── 15. Each nullable cell equality with Nil ──────────────────
    let n_owned: nilable<T> = Nil.into();
    let n_ref: nilable_ref<'_, T> = Nil.into();
    let n_mut: nilable_refmut<'_, T> = Nil.into();
    if n_owned != Nil || n_ref != Nil || n_mut != Nil {
        fail(b"15. nullable cells should == Nil");
    } else {
        ok_line(b"PASS: 15. each nullable == Nil      (PartialEq<Nil>)\n");
    }

    // ── 16. Non-null cells != Nil ─────────────────────────────────
    let nn_owned: nilable<T> = nilable::new(T { x: 1 });
    let nn_t = T { x: 1 };
    let nn_ref: nilable_ref<'_, T> = (&nn_t).into();
    let mut nn_t2 = T { x: 1 };
    let nn_mut: nilable_refmut<'_, T> = (&mut nn_t2).into();
    if nn_owned == Nil || nn_ref == Nil || nn_mut == Nil {
        fail(b"16. non-null cells should != Nil");
    } else {
        ok_line(b"PASS: 16. non-null cells != Nil\n");
    }

    // ── Conversions that DO NOT exist in safe Rust ────────────────
    // 17. nilable<&T> → nilable<&mut T> — cannot upgrade an immutable
    //     borrow to mutable. Goish has no API surface for this. The
    //     compile-time error message would be helpful; we can't
    //     demonstrate it here without UB.
    // 18. &T → &mut T — same.
    ok_line(b"NOTE: immut -> mut upgrade is rejected by Rust (safe code)\n");

    if FAILED.load(Ordering::Acquire) > 0 {
        ok_line(b"FAIL: nilable_conversions had failures\n");
        syscall::Exit(1);
    }
    ok_line(b"OK nilable_conversions\n");
}
