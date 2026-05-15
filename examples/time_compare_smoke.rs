// time_compare_smoke — exercise Time.Compare (time.go:288).
//
// Validates: -1 / 0 / +1 ordering across (sec, nsec, monotonic) inputs.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::time::{Date, Now, Sleep, Microsecond};
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Earlier sec < later sec → -1.
    {
        let t1 = Date(2026, 5, 1, 0, 0, 0, 0, goish::time::UTC);
        let t2 = Date(2026, 5, 2, 0, 0, 0, 0, goish::time::UTC);
        if t1.Compare(t2) == -1 {
            Println!("[ 1] earlier sec → -1          PASS");
        } else {
            Println!("[ 1] earlier sec → -1          FAIL got={}", t1.Compare(t2));
            failed += 1;
        }
    }

    // 2. Later sec > earlier sec → +1.
    {
        let t1 = Date(2026, 5, 2, 0, 0, 0, 0, goish::time::UTC);
        let t2 = Date(2026, 5, 1, 0, 0, 0, 0, goish::time::UTC);
        if t1.Compare(t2) == 1 {
            Println!("[ 2] later sec → +1            PASS");
        } else {
            Println!("[ 2] later sec → +1            FAIL got={}", t1.Compare(t2));
            failed += 1;
        }
    }

    // 3. Equal time (same Date input) → 0.
    {
        let t1 = Date(2026, 5, 1, 12, 30, 0, 0, goish::time::UTC);
        let t2 = Date(2026, 5, 1, 12, 30, 0, 0, goish::time::UTC);
        if t1.Compare(t2) == 0 {
            Println!("[ 3] equal → 0                 PASS");
        } else {
            Println!("[ 3] equal → 0                 FAIL got={}", t1.Compare(t2));
            failed += 1;
        }
    }

    // 4. Same sec, earlier nsec → -1.
    {
        let t1 = Date(2026, 5, 1, 0, 0, 0, 100, goish::time::UTC);
        let t2 = Date(2026, 5, 1, 0, 0, 0, 200, goish::time::UTC);
        if t1.Compare(t2) == -1 {
            Println!("[ 4] same sec, lower nsec → -1 PASS");
        } else {
            Println!("[ 4] same sec, lower nsec → -1 FAIL got={}", t1.Compare(t2));
            failed += 1;
        }
    }

    // 5. Same sec, later nsec → +1.
    {
        let t1 = Date(2026, 5, 1, 0, 0, 0, 999, goish::time::UTC);
        let t2 = Date(2026, 5, 1, 0, 0, 0, 100, goish::time::UTC);
        if t1.Compare(t2) == 1 {
            Println!("[ 5] same sec, higher nsec→ +1 PASS");
        } else {
            Println!("[ 5] same sec, higher nsec→ +1 FAIL");
            failed += 1;
        }
    }

    // 6. Monotonic comparison: Now() before / after Sleep.
    {
        let t1 = Now();
        Sleep(Microsecond * 100);
        let t2 = Now();
        if t1.Compare(t2) == -1 && t2.Compare(t1) == 1 {
            Println!("[ 6] monotonic Now→Sleep→Now   PASS");
        } else {
            Println!("[ 6] monotonic Now→Sleep→Now   FAIL");
            failed += 1;
        }
    }

    // 7. Compare is consistent with Equal.
    {
        let t1 = Date(2026, 5, 1, 12, 0, 0, 0, goish::time::UTC);
        let t2 = Date(2026, 5, 1, 12, 0, 0, 0, goish::time::UTC);
        if t1.Compare(t2) == 0 && t1.Equal(t2) {
            Println!("[ 7] Compare ↔ Equal           PASS");
        } else {
            Println!("[ 7] Compare ↔ Equal           FAIL");
            failed += 1;
        }
    }

    // 8. Compare is anti-symmetric.
    {
        let t1 = Date(2026, 5, 1, 0, 0, 0, 0, goish::time::UTC);
        let t2 = Date(2026, 6, 1, 0, 0, 0, 0, goish::time::UTC);
        if t1.Compare(t2) + t2.Compare(t1) == 0 {
            Println!("[ 8] anti-symmetric            PASS");
        } else {
            Println!("[ 8] anti-symmetric            FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 8", failed);
        syscall::Exit(1);
    }
}
