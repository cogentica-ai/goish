// slices_insert_replace_grow_clip_smoke — exercise slices.Insert,
// slices.Replace, slices.Grow, slices.Clip
// (slices/slices.go:135 + 260 + 420 + 433).

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

    // 1. Insert at front: Insert([1,2,3], 0, [9]) → [9,1,2,3].
    {
        let s = make_int_slice(&[1, 2, 3]);
        let v = make_int_slice(&[9]);
        let r = slices::Insert(s, 0, &v);
        if slice_eq(&r, &[9, 1, 2, 3]) {
            Println!("[ 1] Insert at 0              PASS");
        } else {
            Println!("[ 1] Insert at 0              FAIL");
            failed += 1;
        }
    }

    // 2. Insert in middle: Insert([1,2,5], 2, [3,4]) → [1,2,3,4,5].
    {
        let s = make_int_slice(&[1, 2, 5]);
        let v = make_int_slice(&[3, 4]);
        let r = slices::Insert(s, 2, &v);
        if slice_eq(&r, &[1, 2, 3, 4, 5]) {
            Println!("[ 2] Insert in middle         PASS");
        } else {
            Println!("[ 2] Insert in middle         FAIL");
            failed += 1;
        }
    }

    // 3. Insert at end (i == len): Insert([1,2], 2, [3,4]) → [1,2,3,4].
    {
        let s = make_int_slice(&[1, 2]);
        let v = make_int_slice(&[3, 4]);
        let r = slices::Insert(s, 2, &v);
        if slice_eq(&r, &[1, 2, 3, 4]) {
            Println!("[ 3] Insert at end            PASS");
        } else {
            Println!("[ 3] Insert at end            FAIL");
            failed += 1;
        }
    }

    // 4. Insert empty v: returns s unchanged.
    {
        let s = make_int_slice(&[1, 2, 3]);
        let v: slice<int> = slice::__from_vec(alloc::vec::Vec::new());
        let r = slices::Insert(s, 1, &v);
        if slice_eq(&r, &[1, 2, 3]) {
            Println!("[ 4] Insert empty v unchanged PASS");
        } else {
            Println!("[ 4] Insert empty v unchanged FAIL");
            failed += 1;
        }
    }

    // 5. Replace [i:j) with v: Replace([1,2,3,4,5], 1, 4, [9]) → [1,9,5].
    {
        let s = make_int_slice(&[1, 2, 3, 4, 5]);
        let v = make_int_slice(&[9]);
        let r = slices::Replace(s, 1, 4, &v);
        if slice_eq(&r, &[1, 9, 5]) {
            Println!("[ 5] Replace shrink           PASS");
        } else {
            Println!("[ 5] Replace shrink           FAIL");
            failed += 1;
        }
    }

    // 6. Replace expanding: Replace([1,2,5], 1, 2, [3,4]) → [1,3,4,5].
    {
        let s = make_int_slice(&[1, 2, 5]);
        let v = make_int_slice(&[3, 4]);
        let r = slices::Replace(s, 1, 2, &v);
        if slice_eq(&r, &[1, 3, 4, 5]) {
            Println!("[ 6] Replace expand           PASS");
        } else {
            Println!("[ 6] Replace expand           FAIL");
            failed += 1;
        }
    }

    // 7. Replace i == j (delegates to Insert): Replace([1,2,3], 1, 1, [9]) → [1,9,2,3].
    {
        let s = make_int_slice(&[1, 2, 3]);
        let v = make_int_slice(&[9]);
        let r = slices::Replace(s, 1, 1, &v);
        if slice_eq(&r, &[1, 9, 2, 3]) {
            Println!("[ 7] Replace i==j → Insert    PASS");
        } else {
            Println!("[ 7] Replace i==j → Insert    FAIL");
            failed += 1;
        }
    }

    // 8. Replace tail: Replace([1,2,3], 2, 3, [9,9]) → [1,2,9,9].
    {
        let s = make_int_slice(&[1, 2, 3]);
        let v = make_int_slice(&[9, 9]);
        let r = slices::Replace(s, 2, 3, &v);
        if slice_eq(&r, &[1, 2, 9, 9]) {
            Println!("[ 8] Replace tail expand      PASS");
        } else {
            Println!("[ 8] Replace tail expand      FAIL");
            failed += 1;
        }
    }

    // 9. Grow preserves contents and length.
    {
        let s = make_int_slice(&[1, 2, 3]);
        let r = slices::Grow(s, 100);
        if slice_eq(&r, &[1, 2, 3]) {
            Println!("[ 9] Grow keeps content+len   PASS");
        } else {
            Println!("[ 9] Grow keeps content+len   FAIL");
            failed += 1;
        }
    }

    // 10. Grow on empty slice — still empty after.
    {
        let s: slice<int> = slice::__from_vec(alloc::vec::Vec::new());
        let r = slices::Grow(s, 50);
        if r.Len() == 0 {
            Println!("[10] Grow empty               PASS");
        } else {
            Println!("[10] Grow empty               FAIL");
            failed += 1;
        }
    }

    // 11. Clip preserves contents and length.
    {
        let s = make_int_slice(&[1, 2, 3, 4]);
        let r = slices::Clip(s);
        if slice_eq(&r, &[1, 2, 3, 4]) {
            Println!("[11] Clip keeps content+len   PASS");
        } else {
            Println!("[11] Clip keeps content+len   FAIL");
            failed += 1;
        }
    }

    // 12. Clip after Grow — still preserves data.
    {
        let s = make_int_slice(&[7, 8, 9]);
        let g = slices::Grow(s, 1000);
        let r = slices::Clip(g);
        if slice_eq(&r, &[7, 8, 9]) {
            Println!("[12] Grow+Clip round-trip     PASS");
        } else {
            Println!("[12] Grow+Clip round-trip     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
