// list_smoke — exercise the container/list package.
// (container/list/list.go)
//
// Checks 1-15 are hand-written. Checks 16-20 replay a sequence printed
// by a running Go 1.25.5 (tools/gen_list_ref.go, run through
// scripts/goref.sh), so the link surgery in `move`, `insertValue` and
// `remove` is compared against Go's, element order by element order —
// including the cases Go documents as no-ops.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::container::list;
use goish::fmt;
use goish::syscall;
use goish::types::int;

// Walk a list front→back, collecting Values (T = int).
fn collect(l: &list::List<int>) -> alloc::vec::Vec<int> {
    let mut out = alloc::vec::Vec::new();
    let mut cur = l.Front();
    while let Some(e) = cur {
        out.push(e.Value());
        cur = e.Next();
    }
    out
}

// Walk a list back→front.
fn collect_rev(l: &list::List<int>) -> alloc::vec::Vec<int> {
    let mut out = alloc::vec::Vec::new();
    let mut cur = l.Back();
    while let Some(e) = cur {
        out.push(e.Value());
        cur = e.Prev();
    }
    out
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. New() + Len() — empty list reports 0.
    {
        let l: list::List<int> = list::New();
        if l.Len() == 0 && l.Front().is_none() && l.Back().is_none() {
            fmt::Println!("[ 1] New empty                PASS");
        } else {
            fmt::Println!("[ 1] New empty                FAIL");
            failed += 1;
        }
    }

    // 2. PushBack — basic append.
    {
        let l: list::List<int> = list::New();
        l.PushBack(1);
        l.PushBack(2);
        l.PushBack(3);
        let want: alloc::vec::Vec<int> = alloc::vec![1, 2, 3];
        if collect(&l) == want && l.Len() == 3 {
            fmt::Println!("[ 2] PushBack                 PASS");
        } else {
            fmt::Println!("[ 2] PushBack                 FAIL");
            failed += 1;
        }
    }

    // 3. PushFront — prepend.
    {
        let l: list::List<int> = list::New();
        l.PushFront(1);
        l.PushFront(2);
        l.PushFront(3);
        let want: alloc::vec::Vec<int> = alloc::vec![3, 2, 1];
        if collect(&l) == want {
            fmt::Println!("[ 3] PushFront                PASS");
        } else {
            fmt::Println!("[ 3] PushFront                FAIL");
            failed += 1;
        }
    }

    // 4. Front/Back/Next/Prev traversal — round-trip 1..5.
    {
        let l: list::List<int> = list::New();
        for i in 1..=5 {
            l.PushBack(i);
        }
        let fwd = collect(&l);
        let rev = collect_rev(&l);
        let want_fwd: alloc::vec::Vec<int> = alloc::vec![1, 2, 3, 4, 5];
        let want_rev: alloc::vec::Vec<int> = alloc::vec![5, 4, 3, 2, 1];
        if fwd == want_fwd && rev == want_rev {
            fmt::Println!("[ 4] Front/Back/Next/Prev     PASS");
        } else {
            fmt::Println!("[ 4] Front/Back/Next/Prev     FAIL");
            failed += 1;
        }
    }

    // 5. Remove — middle element, returns its value.
    {
        let l: list::List<int> = list::New();
        l.PushBack(10);
        let m = l.PushBack(20);
        l.PushBack(30);
        let v = l.Remove(&m);
        let want: alloc::vec::Vec<int> = alloc::vec![10, 30];
        if v == 20 && collect(&l) == want && l.Len() == 2 {
            fmt::Println!("[ 5] Remove middle            PASS");
        } else {
            fmt::Println!("[ 5] Remove middle            FAIL v=", v);
            failed += 1;
        }
    }

    // 6. InsertBefore / InsertAfter.
    {
        let l: list::List<int> = list::New();
        let a = l.PushBack(1);
        l.PushBack(3);
        // Insert 2 between a (=1) and 3 — i.e. after a.
        let _ = l.InsertAfter(2, &a).unwrap();
        // Insert 0 before a.
        let _ = l.InsertBefore(0, &a).unwrap();
        let want: alloc::vec::Vec<int> = alloc::vec![0, 1, 2, 3];
        if collect(&l) == want {
            fmt::Println!("[ 6] InsertBefore/After       PASS");
        } else {
            fmt::Println!("[ 6] InsertBefore/After       FAIL");
            failed += 1;
        }
    }

    // 7. MoveToFront / MoveToBack.
    {
        let l: list::List<int> = list::New();
        l.PushBack(1);
        let m = l.PushBack(2);
        l.PushBack(3);
        l.MoveToFront(&m);
        let after_front = collect(&l);
        l.MoveToBack(&m);
        let after_back = collect(&l);
        let want_front: alloc::vec::Vec<int> = alloc::vec![2, 1, 3];
        let want_back: alloc::vec::Vec<int> = alloc::vec![1, 3, 2];
        if after_front == want_front && after_back == want_back {
            fmt::Println!("[ 7] MoveToFront/Back         PASS");
        } else {
            fmt::Println!("[ 7] MoveToFront/Back         FAIL");
            failed += 1;
        }
    }

    // 8. MoveBefore / MoveAfter (within same list).
    {
        let l: list::List<int> = list::New();
        let a = l.PushBack(1);
        let b = l.PushBack(2);
        let c = l.PushBack(3);
        // Move b before a → [2, 1, 3]
        l.MoveBefore(&b, &a);
        let s1 = collect(&l);
        // Move b after c → [1, 3, 2]
        l.MoveAfter(&b, &c);
        let s2 = collect(&l);
        let want1: alloc::vec::Vec<int> = alloc::vec![2, 1, 3];
        let want2: alloc::vec::Vec<int> = alloc::vec![1, 3, 2];
        if s1 == want1 && s2 == want2 {
            fmt::Println!("[ 8] MoveBefore/After         PASS");
        } else {
            fmt::Println!("[ 8] MoveBefore/After         FAIL");
            failed += 1;
        }
    }

    // 9. PushBackList — concatenate.
    {
        let l1: list::List<int> = list::New();
        l1.PushBack(1);
        l1.PushBack(2);
        let l2: list::List<int> = list::New();
        l2.PushBack(3);
        l2.PushBack(4);
        l1.PushBackList(&l2);
        let want: alloc::vec::Vec<int> = alloc::vec![1, 2, 3, 4];
        if collect(&l1) == want && l2.Len() == 2 && collect(&l2) == alloc::vec![3, 4] {
            fmt::Println!("[ 9] PushBackList             PASS");
        } else {
            fmt::Println!("[ 9] PushBackList             FAIL");
            failed += 1;
        }
    }

    // 10. PushFrontList — prepend in reverse iteration.
    {
        let l1: list::List<int> = list::New();
        l1.PushBack(3);
        l1.PushBack(4);
        let l2: list::List<int> = list::New();
        l2.PushBack(1);
        l2.PushBack(2);
        l1.PushFrontList(&l2);
        let want: alloc::vec::Vec<int> = alloc::vec![1, 2, 3, 4];
        if collect(&l1) == want {
            fmt::Println!("[10] PushFrontList            PASS");
        } else {
            fmt::Println!("[10] PushFrontList            FAIL");
            failed += 1;
        }
    }

    // 11. Init — clears.
    {
        let l: list::List<int> = list::New();
        l.PushBack(1);
        l.PushBack(2);
        l.Init();
        if l.Len() == 0 && l.Front().is_none() && l.Back().is_none() {
            fmt::Println!("[11] Init clears              PASS");
        } else {
            fmt::Println!("[11] Init clears              FAIL");
            failed += 1;
        }
    }

    // 12. SetValue — visible through any handle to that node.
    {
        let l: list::List<int> = list::New();
        let e = l.PushBack(7);
        let e2 = e.clone();
        e.SetValue(42);
        // Both handles see 42; the list's Front() also reflects it.
        let f = l.Front().unwrap();
        if e.Value() == 42 && e2.Value() == 42 && f.Value() == 42 {
            fmt::Println!("[12] SetValue shared          PASS");
        } else {
            fmt::Println!("[12] SetValue shared          FAIL");
            failed += 1;
        }
    }

    // 13. Remove + Value still readable on a removed handle.
    {
        let l: list::List<int> = list::New();
        let e = l.PushBack(99);
        let v = l.Remove(&e);
        // Handle persists; Value() returns the captured cell.
        if v == 99 && e.Value() == 99 && l.Len() == 0 {
            fmt::Println!("[13] Remove preserves Value   PASS");
        } else {
            fmt::Println!("[13] Remove preserves Value   FAIL v=", v);
            failed += 1;
        }
    }

    // 14. Cross-list move ignored (mark belongs to other list).
    {
        let l1: list::List<int> = list::New();
        let l2: list::List<int> = list::New();
        let e1 = l1.PushBack(1);
        let mark2 = l2.PushBack(2);
        // l1.MoveBefore(e1, mark2) — mark2 is not in l1, must no-op.
        l1.MoveBefore(&e1, &mark2);
        // l2.InsertBefore(99, &e1) — e1 is not in l2, must return None.
        let opt = l2.InsertBefore(99, &e1);
        if l1.Len() == 1 && l2.Len() == 1 && opt.is_none() {
            fmt::Println!("[14] Cross-list rejected      PASS");
        } else {
            fmt::Println!("[14] Cross-list rejected      FAIL");
            failed += 1;
        }
    }

    // 15. Stress: repeated Push/Remove keeps invariants.
    {
        let l: list::List<int> = list::New();
        let mut handles: alloc::vec::Vec<list::Element<int>> = alloc::vec::Vec::new();
        for i in 0..50 {
            handles.push(l.PushBack(i));
        }
        // Remove every other element — even indices stay.
        let mut i = 1;
        while i < handles.len() {
            l.Remove(&handles[i]);
            i += 2;
        }
        let want: alloc::vec::Vec<int> = (0..50).filter(|x| x % 2 == 0).collect();
        if collect(&l) == want && l.Len() == 25 {
            fmt::Println!("[15] Stress push/remove       PASS");
        } else {
            fmt::Println!("[15] Stress push/remove       FAIL");
            failed += 1;
        }
    }

    // 16. The Go-checked move sequence. Every step's element order is
    //     what a running Go printed for the same calls.
    {
        let l = list::List::<int>::New();
        let e1 = l.PushBack(1);
        let e2 = l.PushBack(2);
        let e3 = l.PushBack(3);
        let e4 = l.PushFront(0);
        let mut ok = collect(&l) == alloc::vec![0, 1, 2, 3] && l.Len() == 4;
        l.MoveToFront(&e3);
        ok = ok && collect(&l) == alloc::vec![3, 0, 1, 2];
        l.MoveToBack(&e4);
        ok = ok && collect(&l) == alloc::vec![3, 1, 2, 0];
        // Already before e2, so this is a no-op — Go prints the same.
        l.MoveBefore(&e1, &e2);
        ok = ok && collect(&l) == alloc::vec![3, 1, 2, 0];
        l.MoveAfter(&e1, &e2);
        ok = ok && collect(&l) == alloc::vec![3, 2, 1, 0];
        if ok {
            fmt::Println!("[16] move sequence vs Go      PASS");
        } else {
            fmt::Println!("[16] move sequence vs Go      FAIL");
            failed += 1;
        }
    }

    // 17. The documented no-ops: an element of another list, and
    //     moving an element relative to itself. Neither list changes.
    {
        let l = list::List::<int>::New();
        let e1 = l.PushBack(1);
        let _ = l.PushBack(2);
        let other = list::List::<int>::New();
        let oe = other.PushBack(99);

        l.MoveToFront(&oe);
        l.MoveToBack(&oe);
        l.MoveBefore(&oe, &e1);
        l.MoveAfter(&e1, &e1);
        let foreign_insert = l.InsertBefore(7, &oe);
        let foreign_insert2 = l.InsertAfter(7, &oe);

        if collect(&l) == alloc::vec![1, 2]
            && collect(&other) == alloc::vec![99]
            && foreign_insert.is_none()
            && foreign_insert2.is_none()
            && l.Len() == 2
        {
            fmt::Println!("[17] foreign/self no-ops      PASS");
        } else {
            fmt::Println!("[17] foreign/self no-ops      FAIL");
            failed += 1;
        }
    }

    // 18. insertValue through InsertBefore/InsertAfter, then Remove —
    //     which returns the value even for an element of another list,
    //     and leaves this list's length alone when it does.
    {
        let l = list::List::<int>::New();
        let e1 = l.PushBack(1);
        let e2 = l.PushBack(2);
        let e3 = l.PushBack(3);
        let e4 = l.PushFront(0);
        l.MoveToFront(&e3);
        l.MoveToBack(&e4);
        l.MoveAfter(&e1, &e2);
        let _ = l.InsertBefore(10, &e2);
        let _ = l.InsertAfter(20, &e2);
        let mut ok = collect(&l) == alloc::vec![3, 10, 2, 20, 1, 0];

        let other = list::List::<int>::New();
        let oe = other.PushBack(99);
        ok = ok && l.Remove(&e3) == 3;
        ok = ok && collect(&l) == alloc::vec![10, 2, 20, 1, 0] && l.Len() == 5;
        ok = ok && l.Remove(&oe) == 99;
        ok = ok && collect(&l) == alloc::vec![10, 2, 20, 1, 0] && l.Len() == 5;
        if ok {
            fmt::Println!("[18] insert/Remove vs Go      PASS");
        } else {
            fmt::Println!("[18] insert/Remove vs Go      FAIL");
            failed += 1;
        }
    }

    // 19. PushBackList / PushFrontList, including the aliased case Go
    //     documents (`l.PushBackList(l)`), where the loop is bounded by
    //     the length captured before the first insert.
    {
        let a = list::List::<int>::New();
        let _ = a.PushBack(24);
        let _ = a.PushBack(25);
        let b = list::List::<int>::New();
        let _ = b.PushBack(1);
        let _ = b.PushBack(2);
        a.PushBackList(&b);
        let mut ok = collect(&a) == alloc::vec![24, 25, 1, 2];
        a.PushFrontList(&b);
        ok = ok && collect(&a) == alloc::vec![1, 2, 24, 25, 1, 2];

        let c = list::List::<int>::New();
        let _ = c.PushBack(16);
        let _ = c.PushBack(17);
        c.PushBackList(&c);
        ok = ok && collect(&c) == alloc::vec![16, 17, 16, 17] && c.Len() == 4;

        let d = list::List::<int>::New();
        let _ = d.PushBack(16);
        let _ = d.PushBack(17);
        d.PushFrontList(&d);
        ok = ok && collect(&d) == alloc::vec![16, 17, 16, 17] && d.Len() == 4;
        if ok {
            fmt::Println!("[19] Push*List vs Go          PASS");
        } else {
            fmt::Println!("[19] Push*List vs Go          FAIL");
            failed += 1;
        }
    }

    // 20. Init clears, and the list is usable again afterwards —
    //     which is what lazyInit exists to guarantee in Go.
    {
        let l = list::List::<int>::New();
        let _ = l.PushBack(1);
        let _ = l.PushBack(2);
        l.Init();
        let mut ok = l.Len() == 0 && l.Front().is_none() && l.Back().is_none();
        ok = ok && collect(&l).is_empty();
        let _ = l.PushBack(7);
        let _ = l.PushFront(6);
        ok = ok && collect(&l) == alloc::vec![6, 7] && l.Len() == 2;
        if ok {
            fmt::Println!("[20] Init then reuse          PASS");
        } else {
            fmt::Println!("[20] Init then reuse          FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 20/20");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 20");
        syscall::Exit(1);
    }
}
