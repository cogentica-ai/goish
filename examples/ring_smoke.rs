// ring_smoke — exercise the container/ring package.
// Mirrors Go's example_test.go (Len, Next, Prev, Do, Move, Link,
// Unlink) plus edge cases (n<=0, single element, empty Do).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::container::ring;
use goish::fmt;
use goish::syscall;
use goish::types::int;

// Initialise an n-element ring with 0..n stored at successive
// positions. Returns the head handle (still pointing at element with
// value 0 if no rotation), matching Go's example pattern of advancing
// once per iteration so r ends up back at the head.
fn fill(r: &ring::Ring<int>, n: int) -> ring::Ring<int> {
    let mut cur = r.clone();
    let mut i: int = 0;
    while i < n {
        cur.SetValue(i);
        cur = cur.Next();
        i += 1;
    }
    cur
}

// Walk a ring once forward starting at r and collect values. r must
// not be empty.
fn collect(r: &ring::Ring<int>) -> alloc::vec::Vec<int> {
    let mut out = alloc::vec::Vec::new();
    r.Do(|v| out.push(*v));
    out
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. New(0) and New(-1) return None (Go: nil).
    {
        let r0 = ring::New::<int>(0);
        let rneg = ring::New::<int>(-3);
        if r0.is_none() && rneg.is_none() {
            fmt::Println!("[ 1] New(<=0) -> None           PASS");
        } else {
            fmt::Println!("[ 1] New(<=0) -> None           FAIL");
            failed += 1;
        }
    }

    // 2. New(4).Len() == 4 (Go: ExampleRing_Len).
    {
        let r = ring::New::<int>(4).expect("ring of 4");
        if r.Len() == 4 {
            fmt::Println!("[ 2] New(4).Len() == 4          PASS");
        } else {
            fmt::Println!("[ 2] New(4).Len() == 4          FAIL got=", r.Len());
            failed += 1;
        }
    }

    // 3. Next() walks forward (Go: ExampleRing_Next).
    {
        let r = ring::New::<int>(5).expect("ring of 5");
        let _ = fill(&r, 5);
        // After fill, cur returns back to r since fill advances n
        // times around an n-ring. So r still points at value 0.
        let mut got: alloc::vec::Vec<int> = alloc::vec::Vec::new();
        let mut cur = r.clone();
        for _ in 0..5 {
            got.push(cur.Value().expect("value set"));
            cur = cur.Next();
        }
        let want: alloc::vec::Vec<int> = alloc::vec![0, 1, 2, 3, 4];
        if got == want {
            fmt::Println!("[ 3] Next forward walk          PASS");
        } else {
            fmt::Println!("[ 3] Next forward walk          FAIL");
            failed += 1;
        }
    }

    // 4. Prev() walks backward (Go: ExampleRing_Prev).
    {
        let r = ring::New::<int>(5).expect("ring of 5");
        let _ = fill(&r, 5);
        let mut got: alloc::vec::Vec<int> = alloc::vec::Vec::new();
        let mut cur = r.clone();
        for _ in 0..5 {
            cur = cur.Prev();
            got.push(cur.Value().expect("value set"));
        }
        let want: alloc::vec::Vec<int> = alloc::vec![4, 3, 2, 1, 0];
        if got == want {
            fmt::Println!("[ 4] Prev backward walk         PASS");
        } else {
            fmt::Println!("[ 4] Prev backward walk         FAIL");
            failed += 1;
        }
    }

    // 5. Do() iterates forward (Go: ExampleRing_Do).
    {
        let r = ring::New::<int>(5).expect("ring of 5");
        let _ = fill(&r, 5);
        let got = collect(&r);
        let want: alloc::vec::Vec<int> = alloc::vec![0, 1, 2, 3, 4];
        if got == want {
            fmt::Println!("[ 5] Do forward iteration       PASS");
        } else {
            fmt::Println!("[ 5] Do forward iteration       FAIL");
            failed += 1;
        }
    }

    // 6. Move(3) — rotate forward (Go: ExampleRing_Move).
    {
        let r = ring::New::<int>(5).expect("ring of 5");
        let _ = fill(&r, 5);
        let r2 = r.Move(3);
        let got = collect(&r2);
        let want: alloc::vec::Vec<int> = alloc::vec![3, 4, 0, 1, 2];
        if got == want {
            fmt::Println!("[ 6] Move(3) rotate forward     PASS");
        } else {
            fmt::Println!("[ 6] Move(3) rotate forward     FAIL");
            failed += 1;
        }
    }

    // 7. Move(-2) — rotate backward.
    {
        let r = ring::New::<int>(5).expect("ring of 5");
        let _ = fill(&r, 5);
        let r2 = r.Move(-2);
        let got = collect(&r2);
        let want: alloc::vec::Vec<int> = alloc::vec![3, 4, 0, 1, 2];
        if got == want {
            fmt::Println!("[ 7] Move(-2) rotate backward   PASS");
        } else {
            fmt::Println!("[ 7] Move(-2) rotate backward   FAIL");
            failed += 1;
        }
    }

    // 8. Link two rings (Go: ExampleRing_Link).
    {
        let r = ring::New::<int>(2).expect("r");
        let s = ring::New::<int>(2).expect("s");
        let lr = r.Len();
        let ls = s.Len();
        // Initialise r with 0s.
        let mut rr = r.clone();
        for _ in 0..lr {
            rr.SetValue(0);
            rr = rr.Next();
        }
        // Initialise s with 1s.
        let mut ss = s.clone();
        for _ in 0..ls {
            ss.SetValue(1);
            ss = ss.Next();
        }
        // Link r and s. Go's expected output starts at rs which is
        // r.Next() (the post-link iteration order from rs):
        //   0, 0, 1, 1
        let rs = rr.Link(&ss);
        let got = collect(&rs);
        let want: alloc::vec::Vec<int> = alloc::vec![0, 0, 1, 1];
        if got == want && rs.Len() == 4 {
            fmt::Println!("[ 8] Link two rings             PASS");
        } else {
            fmt::Println!("[ 8] Link two rings             FAIL");
            failed += 1;
        }
    }

    // 9. Unlink (Go: ExampleRing_Unlink).
    {
        let r = ring::New::<int>(6).expect("ring of 6");
        let _ = fill(&r, 6);
        // Unlink three elements starting from r.Next() — those are
        // values 1, 2, 3.
        let removed = r.Unlink(3).expect("Unlink(>0) returns subring");
        // Removed subring contains 1, 2, 3.
        let got_removed = collect(&removed);
        let want_removed: alloc::vec::Vec<int> = alloc::vec![1, 2, 3];
        // Remaining ring contains 0, 4, 5.
        let got_remaining = collect(&r);
        let want_remaining: alloc::vec::Vec<int> = alloc::vec![0, 4, 5];
        if got_removed == want_removed
            && got_remaining == want_remaining
            && r.Len() == 3
            && removed.Len() == 3
        {
            fmt::Println!("[ 9] Unlink(3) splits ring      PASS");
        } else {
            fmt::Println!("[ 9] Unlink(3) splits ring      FAIL");
            failed += 1;
        }
    }

    // 10. Unlink(0) returns None and leaves ring intact.
    {
        let r = ring::New::<int>(4).expect("ring of 4");
        let _ = fill(&r, 4);
        let none = r.Unlink(0);
        let got = collect(&r);
        let want: alloc::vec::Vec<int> = alloc::vec![0, 1, 2, 3];
        if none.is_none() && got == want && r.Len() == 4 {
            fmt::Println!("[10] Unlink(0) -> None          PASS");
        } else {
            fmt::Println!("[10] Unlink(0) -> None          FAIL");
            failed += 1;
        }
    }

    // 11. Single-element ring — Next/Prev/Move all return same node.
    {
        let r = ring::New::<int>(1).expect("ring of 1");
        r.SetValue(42);
        let n = r.Next();
        let p = r.Prev();
        let m = r.Move(7); // wraps around 7 times to same node
        if r.Len() == 1 && n.Value() == Some(42) && p.Value() == Some(42) && m.Value() == Some(42) {
            fmt::Println!("[11] Single-element ring        PASS");
        } else {
            fmt::Println!("[11] Single-element ring        FAIL");
            failed += 1;
        }
    }

    // 12. Fresh Ring::new() — uninitialised, lazy-init on Next().
    {
        let r: ring::Ring<int> = ring::Ring::new();
        // Pre-init Len: walking next/prev should self-init.
        let n = r.Next();
        let p = r.Prev();
        // After init, ring is 1-element pointing at self.
        if r.Len() == 1 && n.Value().is_none() && p.Value().is_none() {
            fmt::Println!("[12] Lazy init via Next/Prev    PASS");
        } else {
            fmt::Println!("[12] Lazy init via Next/Prev    FAIL");
            failed += 1;
        }
    }

    // 13. Move(0) returns the same node (no rotation).
    {
        let r = ring::New::<int>(3).expect("ring of 3");
        let _ = fill(&r, 3);
        let r2 = r.Move(0);
        if r2.Value() == Some(0) && r.Value() == Some(0) {
            fmt::Println!("[13] Move(0) no-op              PASS");
        } else {
            fmt::Println!("[13] Move(0) no-op              FAIL");
            failed += 1;
        }
    }

    // 14. Aliased handle — clone() shares the same node.
    {
        let r = ring::New::<int>(3).expect("ring of 3");
        let alias = r.clone();
        r.SetValue(99);
        if alias.Value() == Some(99) {
            fmt::Println!("[14] Clone aliases same node    PASS");
        } else {
            fmt::Println!("[14] Clone aliases same node    FAIL");
            failed += 1;
        }
    }

    // 15. Stress: 32-element ring round-trip via Next->Prev.
    {
        let r = ring::New::<int>(32).expect("ring of 32");
        let _ = fill(&r, 32);
        // Walk forward 32 steps then back 32 steps; should land on r
        // with value 0.
        let mut cur = r.clone();
        for _ in 0..32 {
            cur = cur.Next();
        }
        for _ in 0..32 {
            cur = cur.Prev();
        }
        if cur.Value() == Some(0) && r.Len() == 32 {
            fmt::Println!("[15] 32-elt forward+back        PASS");
        } else {
            fmt::Println!("[15] 32-elt forward+back        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 15/15");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 15");
        syscall::Exit(1);
    }
}
