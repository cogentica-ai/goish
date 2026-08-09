// cmp_smoke — exercise cmp.Less / cmp.Compare / cmp.Or.
// (cmp/cmp.go:28, 40, 69)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::cmp;
use goish::string;
use goish::types::int;
use goish::{syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Less — int comparison.
    {
        let a: int = 1;
        let b: int = 2;
        if cmp::Less(&a, &b) && !cmp::Less(&b, &a) && !cmp::Less(&a, &a) {
            fmt::Println!("[ 1] Less int                  PASS");
        } else {
            fmt::Println!("[ 1] Less int                  FAIL");
            failed += 1;
        }
    }

    // 2. Less — string comparison (lexicographic).
    {
        let a = string("apple");
        let b = string("banana");
        if cmp::Less(&a, &b) && !cmp::Less(&b, &a) {
            fmt::Println!("[ 2] Less string               PASS");
        } else {
            fmt::Println!("[ 2] Less string               FAIL");
            failed += 1;
        }
    }

    // 3. Compare — int.
    {
        let a: int = 1;
        let b: int = 2;
        if cmp::Compare(&a, &b) == -1
            && cmp::Compare(&b, &a) == 1
            && cmp::Compare(&a, &a) == 0
        {
            fmt::Println!("[ 3] Compare int               PASS");
        } else {
            fmt::Println!("[ 3] Compare int               FAIL");
            failed += 1;
        }
    }

    // 4. Compare — negative numbers.
    {
        let a: int = -5;
        let b: int = 5;
        if cmp::Compare(&a, &b) == -1 && cmp::Compare(&b, &a) == 1 {
            fmt::Println!("[ 4] Compare neg               PASS");
        } else {
            fmt::Println!("[ 4] Compare neg               FAIL");
            failed += 1;
        }
    }

    // 5. Compare — string.
    {
        let a = string("aaa");
        let b = string("aab");
        if cmp::Compare(&a, &b) == -1 {
            fmt::Println!("[ 5] Compare string            PASS");
        } else {
            fmt::Println!("[ 5] Compare string            FAIL");
            failed += 1;
        }
    }

    // 6. Or — int returns first non-zero.
    {
        let zeros: [int; 4] = [0, 0, 7, 9];
        let result: int = cmp::Or(&zeros);
        if result == 7 {
            fmt::Println!("[ 6] Or int first-nonzero      PASS");
        } else {
            fmt::Println!("[ 6] Or int first-nonzero      FAIL");
            failed += 1;
        }
    }

    // 7. Or — all zeros returns zero.
    {
        let zeros: [int; 3] = [0, 0, 0];
        let result: int = cmp::Or(&zeros);
        if result == 0 {
            fmt::Println!("[ 7] Or int all-zero           PASS");
        } else {
            fmt::Println!("[ 7] Or int all-zero           FAIL");
            failed += 1;
        }
    }

    // 8. Or — string, first non-empty wins.
    {
        let candidates = [string(""), string(""), string("found")];
        let result = cmp::Or(&candidates);
        if result == string("found") {
            fmt::Println!("[ 8] Or string non-empty       PASS");
        } else {
            fmt::Println!("[ 8] Or string non-empty       FAIL");
            failed += 1;
        }
    }

    // 9. Or — empty input returns zero.
    {
        let empty: [int; 0] = [];
        let result: int = cmp::Or(&empty);
        if result == 0 {
            fmt::Println!("[ 9] Or empty                  PASS");
        } else {
            fmt::Println!("[ 9] Or empty                  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 9/9");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 9");
        syscall::Exit(1);
    }
}
