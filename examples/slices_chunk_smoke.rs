// slices_chunk_smoke — exercise slices.Chunk (slim).
// (slices/iter.go:97)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec;
use goish::fmt;
use goish::goslice::slice;
use goish::slices;
use goish::types::int;
use goish::{syscall};

fn make_int_slice(v: alloc::vec::Vec<int>) -> slice<int> {
    slice::<int>::__from_vec(v)
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Chunk — even split [1..6] / 2.
    {
        let s = make_int_slice(vec![1, 2, 3, 4, 5, 6]);
        let cs = slices::Chunk(s, 2);
        let raw: &[slice<int>] = &cs;
        let ok = raw.len() == 3
            && {
                let c0: &[int] = &raw[0];
                c0 == &[1i64, 2]
            }
            && {
                let c1: &[int] = &raw[1];
                c1 == &[3i64, 4]
            }
            && {
                let c2: &[int] = &raw[2];
                c2 == &[5i64, 6]
            };
        if ok {
            fmt::Println!("[ 1] Chunk even               PASS");
        } else {
            fmt::Println!("[ 1] Chunk even               FAIL");
            failed += 1;
        }
    }

    // 2. Chunk — leftover tail.
    {
        let s = make_int_slice(vec![1, 2, 3, 4, 5]);
        let cs = slices::Chunk(s, 2);
        let raw: &[slice<int>] = &cs;
        let ok = raw.len() == 3
            && {
                let c0: &[int] = &raw[0];
                c0 == &[1i64, 2]
            }
            && {
                let c1: &[int] = &raw[1];
                c1 == &[3i64, 4]
            }
            && {
                let c2: &[int] = &raw[2];
                c2 == &[5i64]
            };
        if ok {
            fmt::Println!("[ 2] Chunk leftover           PASS");
        } else {
            fmt::Println!("[ 2] Chunk leftover           FAIL");
            failed += 1;
        }
    }

    // 3. Chunk — n larger than len.
    {
        let s = make_int_slice(vec![1, 2, 3]);
        let cs = slices::Chunk(s, 10);
        let raw: &[slice<int>] = &cs;
        let ok = raw.len() == 1 && {
            let c0: &[int] = &raw[0];
            c0 == &[1i64, 2, 3]
        };
        if ok {
            fmt::Println!("[ 3] Chunk n>len              PASS");
        } else {
            fmt::Println!("[ 3] Chunk n>len              FAIL");
            failed += 1;
        }
    }

    // 4. Chunk — empty input → empty output (no empty chunk).
    {
        let s = make_int_slice(vec![]);
        let cs = slices::Chunk(s, 4);
        let raw: &[slice<int>] = &cs;
        if raw.is_empty() {
            fmt::Println!("[ 4] Chunk empty in            PASS");
        } else {
            fmt::Println!("[ 4] Chunk empty in            FAIL");
            failed += 1;
        }
    }

    // 5. Chunk — n == 1 yields single-element chunks.
    {
        let s = make_int_slice(vec![7, 8, 9]);
        let cs = slices::Chunk(s, 1);
        let raw: &[slice<int>] = &cs;
        let ok = raw.len() == 3
            && {
                let c0: &[int] = &raw[0];
                c0 == &[7i64]
            }
            && {
                let c1: &[int] = &raw[1];
                c1 == &[8i64]
            }
            && {
                let c2: &[int] = &raw[2];
                c2 == &[9i64]
            };
        if ok {
            fmt::Println!("[ 5] Chunk n=1                 PASS");
        } else {
            fmt::Println!("[ 5] Chunk n=1                 FAIL");
            failed += 1;
        }
    }

    // 6. Chunk — chunks are independent (mutating one doesn't touch others).
    {
        let s = make_int_slice(vec![10, 20, 30, 40]);
        let cs = slices::Chunk(s, 2);
        let raw: &[slice<int>] = &cs;
        // Read elements directly — chunks should equal expected values
        // and not be aliased to a single shared backing.
        let c0: &[int] = &raw[0];
        let c1: &[int] = &raw[1];
        if c0 == &[10i64, 20] && c1 == &[30i64, 40] {
            fmt::Println!("[ 6] Chunk independent         PASS");
        } else {
            fmt::Println!("[ 6] Chunk independent         FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
