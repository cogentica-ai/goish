// slices_reverse_repeat_smoke — exercise slices.Reverse + slices.Repeat
// (slices/slices.go:481 + 512).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::slices;
use goish::types::int;
use goish::{syscall, Println};

fn make_int_slice(xs: &[int]) -> slice<int> {
    let mut v: alloc::vec::Vec<int> = alloc::vec::Vec::with_capacity(xs.len());
    for x in xs {
        v.push(*x);
    }
    slice::__from_vec(v)
}

fn slice_eq(a: &slice<int>, b: &[int]) -> bool {
    if a.Len() as usize != b.len() {
        return false;
    }
    let mut i: i64 = 0;
    while (i as usize) < b.len() {
        if a[i] != b[i as usize] {
            return false;
        }
        i += 1;
    }
    true
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Reverse on [1,2,3,4,5] → [5,4,3,2,1].
    {
        let mut s = make_int_slice(&[1, 2, 3, 4, 5]);
        slices::Reverse(&mut s);
        if slice_eq(&s, &[5, 4, 3, 2, 1]) {
            Println!("[ 1] Reverse 5 elem             PASS");
        } else {
            Println!("[ 1] Reverse 5 elem             FAIL");
            failed += 1;
        }
    }

    // 2. Reverse on even-length [1,2,3,4] → [4,3,2,1].
    {
        let mut s = make_int_slice(&[1, 2, 3, 4]);
        slices::Reverse(&mut s);
        if slice_eq(&s, &[4, 3, 2, 1]) {
            Println!("[ 2] Reverse 4 elem             PASS");
        } else {
            Println!("[ 2] Reverse 4 elem             FAIL");
            failed += 1;
        }
    }

    // 3. Reverse on single-element slice — unchanged.
    {
        let mut s = make_int_slice(&[42]);
        slices::Reverse(&mut s);
        if slice_eq(&s, &[42]) {
            Println!("[ 3] Reverse 1 elem             PASS");
        } else {
            Println!("[ 3] Reverse 1 elem             FAIL");
            failed += 1;
        }
    }

    // 4. Reverse on empty slice — no panic.
    {
        let mut s: slice<int> = slice::__from_vec(alloc::vec::Vec::new());
        slices::Reverse(&mut s);
        if s.Len() == 0 {
            Println!("[ 4] Reverse empty             PASS");
        } else {
            Println!("[ 4] Reverse empty             FAIL");
            failed += 1;
        }
    }

    // 5. Repeat ([1,2], 3) → [1,2,1,2,1,2].
    {
        let s = make_int_slice(&[1, 2]);
        let r = slices::Repeat(&s, 3);
        if slice_eq(&r, &[1, 2, 1, 2, 1, 2]) {
            Println!("[ 5] Repeat (1,2)*3            PASS");
        } else {
            Println!("[ 5] Repeat (1,2)*3            FAIL");
            failed += 1;
        }
    }

    // 6. Repeat (s, 0) → empty.
    {
        let s = make_int_slice(&[1, 2, 3]);
        let r = slices::Repeat(&s, 0);
        if r.Len() == 0 {
            Println!("[ 6] Repeat *0 empty           PASS");
        } else {
            Println!("[ 6] Repeat *0 empty           FAIL len=", r.Len());
            failed += 1;
        }
    }

    // 7. Repeat (empty, 5) → empty.
    {
        let s: slice<int> = slice::__from_vec(alloc::vec::Vec::new());
        let r = slices::Repeat(&s, 5);
        if r.Len() == 0 {
            Println!("[ 7] Repeat empty*5            PASS");
        } else {
            Println!("[ 7] Repeat empty*5            FAIL");
            failed += 1;
        }
    }

    // 8. Repeat ([7], 4) → [7,7,7,7].
    {
        let s = make_int_slice(&[7]);
        let r = slices::Repeat(&s, 4);
        if slice_eq(&r, &[7, 7, 7, 7]) {
            Println!("[ 8] Repeat (7)*4              PASS");
        } else {
            Println!("[ 8] Repeat (7)*4              FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
