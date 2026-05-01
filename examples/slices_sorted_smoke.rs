// slices_sorted_smoke — exercise slices.Sorted, SortedFunc,
// SortedStableFunc.  (Go 1.23+ sort.go: Sorted, SortedFunc.)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::slices;
use goish::string;
use goish::types::int;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Sorted on int slice — ascending.
    {
        let xs: slice<int> = slice::__from_vec(alloc::vec![3, 1, 4, 1, 5, 9, 2, 6]);
        let out = slices::Sorted(&xs);
        let raw: &[int] = &out;
        if raw == [1, 1, 2, 3, 4, 5, 6, 9] {
            Println!("[ 1] Sorted ints               PASS");
        } else {
            Println!("[ 1] Sorted ints               FAIL");
            failed += 1;
        }
    }

    // 2. Sorted preserves the input.
    {
        let xs: slice<int> = slice::__from_vec(alloc::vec![3, 1, 2]);
        let _ = slices::Sorted(&xs);
        let raw: &[int] = &xs;
        if raw == [3, 1, 2] {
            Println!("[ 2] Sorted preserves input    PASS");
        } else {
            Println!("[ 2] Sorted preserves input    FAIL");
            failed += 1;
        }
    }

    // 3. Sorted on empty.
    {
        let xs: slice<int> = slice::__from_vec(alloc::vec![]);
        let out = slices::Sorted(&xs);
        if out.Len() == 0 {
            Println!("[ 3] Sorted empty              PASS");
        } else {
            Println!("[ 3] Sorted empty              FAIL");
            failed += 1;
        }
    }

    // 4. Sorted on strings.
    {
        let xs: slice<string> =
            slice::__from_vec(alloc::vec![string("c"), string("a"), string("b")]);
        let out = slices::Sorted(&xs);
        if out[0] == string("a") && out[1] == string("b") && out[2] == string("c") {
            Println!("[ 4] Sorted strings            PASS");
        } else {
            Println!("[ 4] Sorted strings            FAIL");
            failed += 1;
        }
    }

    // 5. SortedFunc — descending.
    {
        let xs: slice<int> = slice::__from_vec(alloc::vec![3, 1, 4, 1, 5]);
        let out = slices::SortedFunc(&xs, |a, b| *b - *a);
        let raw: &[int] = &out;
        if raw == [5, 4, 3, 1, 1] {
            Println!("[ 5] SortedFunc descending     PASS");
        } else {
            Println!("[ 5] SortedFunc descending     FAIL");
            failed += 1;
        }
    }

    // 6. SortedFunc by absolute value.
    {
        let xs: slice<int> = slice::__from_vec(alloc::vec![-3, 1, -2, 4, -5]);
        let out = slices::SortedFunc(&xs, |a, b| a.abs() - b.abs());
        let raw: &[int] = &out;
        if raw == [1, -2, -3, 4, -5] {
            Println!("[ 6] SortedFunc by abs         PASS");
        } else {
            Println!("[ 6] SortedFunc by abs         FAIL");
            failed += 1;
        }
    }

    // 7. SortedStableFunc — equal keys keep insertion order.
    {
        // Pairs of (key, value); sort by key only — stable preserves
        // value ordering for equal keys.
        let pairs: slice<(int, int)> = slice::__from_vec(alloc::vec![
            (1, 10),
            (2, 20),
            (1, 11),
            (2, 21),
            (1, 12),
        ]);
        let out = slices::SortedStableFunc(&pairs, |a, b| a.0 - b.0);
        let raw: &[(int, int)] = &out;
        if raw == [(1, 10), (1, 11), (1, 12), (2, 20), (2, 21)] {
            Println!("[ 7] SortedStableFunc          PASS");
        } else {
            Println!("[ 7] SortedStableFunc          FAIL");
            failed += 1;
        }
    }

    // 8. Sorted single element.
    {
        let xs: slice<int> = slice::__from_vec(alloc::vec![42]);
        let out = slices::Sorted(&xs);
        if out.Len() == 1 && out[0] == 42 {
            Println!("[ 8] Sorted single             PASS");
        } else {
            Println!("[ 8] Sorted single             FAIL");
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
