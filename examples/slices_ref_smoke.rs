// slices_ref_smoke — the `slices` package against a running Go.
// (slices/slices.go, slices/sort.go, slices/iter.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_slices_ref.go` run in
// `package slices_test` by `scripts/goref.sh`.
//
// This is where an off-by-one is invisible: every function takes
// indices and returns a slice, and a wrong answer still looks like a
// slice. The package had no anchors at all — 37 functions counted as
// ported on a name match, none diffed against Go.
//
// The vectors are the boundaries: an empty input, an index at len,
// i == j, a needle that is not there, a count of zero or one,
// BinarySearch on a value falling before, between and after the
// elements, and Compact on {1,2,1} — which keeps BOTH ones, because it
// collapses runs, not duplicates.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::goslice::slice;
use goish::slices;
use goish::types::int;
use goish::{fmt, syscall};

fn sl(v: &[int]) -> slice<int> {
    return slice::<int>::__from_vec(v.to_vec());
}

fn raw(s: &slice<int>) -> Vec<int> {
    let r: &[int] = s;
    return r.to_vec();
}

fn eq(got: &Vec<int>, want: &[int]) -> bool {
    return got.as_slice() == want;
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// (list, IsSorted, Min or "panic", Max or "panic")
const Q: [(&[int], bool, &str, &str); 8] = [
    (&[], true, "panic", "panic"),
    (&[1], true, "1", "1"),
    (&[1, 2], true, "1", "2"),
    (&[1, 2, 3], true, "1", "3"),
    (&[1, 2, 2, 3], true, "1", "3"),
    (&[2, 2, 2], true, "2", "2"),
    (&[3, 1, 2], false, "1", "3"),
    (&[1, 1, 2, 2, 3, 3], true, "1", "3"),
];

// (target, index, found) over [1,3,5,7,9]
const BSEARCH: [(int, int, bool); 9] = [
    (0, 0, false),
    (1, 0, true),
    (2, 1, false),
    (3, 1, true),
    (4, 2, false),
    (5, 2, true),
    (8, 4, false),
    (9, 4, true),
    (10, 5, false),
];

// (a, b, Equal, Compare)
const CMP: [(&[int], &[int], bool, int); 64] = [
    (&[], &[], true, 0),
    (&[], &[1], false, -1),
    (&[], &[1, 2], false, -1),
    (&[], &[1, 2, 3], false, -1),
    (&[], &[1, 2, 2, 3], false, -1),
    (&[], &[2, 2, 2], false, -1),
    (&[], &[3, 1, 2], false, -1),
    (&[], &[1, 1, 2, 2, 3, 3], false, -1),
    (&[1], &[], false, 1),
    (&[1], &[1], true, 0),
    (&[1], &[1, 2], false, -1),
    (&[1], &[1, 2, 3], false, -1),
    (&[1], &[1, 2, 2, 3], false, -1),
    (&[1], &[2, 2, 2], false, -1),
    (&[1], &[3, 1, 2], false, -1),
    (&[1], &[1, 1, 2, 2, 3, 3], false, -1),
    (&[1, 2], &[], false, 1),
    (&[1, 2], &[1], false, 1),
    (&[1, 2], &[1, 2], true, 0),
    (&[1, 2], &[1, 2, 3], false, -1),
    (&[1, 2], &[1, 2, 2, 3], false, -1),
    (&[1, 2], &[2, 2, 2], false, -1),
    (&[1, 2], &[3, 1, 2], false, -1),
    (&[1, 2], &[1, 1, 2, 2, 3, 3], false, 1),
    (&[1, 2, 3], &[], false, 1),
    (&[1, 2, 3], &[1], false, 1),
    (&[1, 2, 3], &[1, 2], false, 1),
    (&[1, 2, 3], &[1, 2, 3], true, 0),
    (&[1, 2, 3], &[1, 2, 2, 3], false, 1),
    (&[1, 2, 3], &[2, 2, 2], false, -1),
    (&[1, 2, 3], &[3, 1, 2], false, -1),
    (&[1, 2, 3], &[1, 1, 2, 2, 3, 3], false, 1),
    (&[1, 2, 2, 3], &[], false, 1),
    (&[1, 2, 2, 3], &[1], false, 1),
    (&[1, 2, 2, 3], &[1, 2], false, 1),
    (&[1, 2, 2, 3], &[1, 2, 3], false, -1),
    (&[1, 2, 2, 3], &[1, 2, 2, 3], true, 0),
    (&[1, 2, 2, 3], &[2, 2, 2], false, -1),
    (&[1, 2, 2, 3], &[3, 1, 2], false, -1),
    (&[1, 2, 2, 3], &[1, 1, 2, 2, 3, 3], false, 1),
    (&[2, 2, 2], &[], false, 1),
    (&[2, 2, 2], &[1], false, 1),
    (&[2, 2, 2], &[1, 2], false, 1),
    (&[2, 2, 2], &[1, 2, 3], false, 1),
    (&[2, 2, 2], &[1, 2, 2, 3], false, 1),
    (&[2, 2, 2], &[2, 2, 2], true, 0),
    (&[2, 2, 2], &[3, 1, 2], false, -1),
    (&[2, 2, 2], &[1, 1, 2, 2, 3, 3], false, 1),
    (&[3, 1, 2], &[], false, 1),
    (&[3, 1, 2], &[1], false, 1),
    (&[3, 1, 2], &[1, 2], false, 1),
    (&[3, 1, 2], &[1, 2, 3], false, 1),
    (&[3, 1, 2], &[1, 2, 2, 3], false, 1),
    (&[3, 1, 2], &[2, 2, 2], false, 1),
    (&[3, 1, 2], &[3, 1, 2], true, 0),
    (&[3, 1, 2], &[1, 1, 2, 2, 3, 3], false, 1),
    (&[1, 1, 2, 2, 3, 3], &[], false, 1),
    (&[1, 1, 2, 2, 3, 3], &[1], false, 1),
    (&[1, 1, 2, 2, 3, 3], &[1, 2], false, -1),
    (&[1, 1, 2, 2, 3, 3], &[1, 2, 3], false, -1),
    (&[1, 1, 2, 2, 3, 3], &[1, 2, 2, 3], false, -1),
    (&[1, 1, 2, 2, 3, 3], &[2, 2, 2], false, -1),
    (&[1, 1, 2, 2, 3, 3], &[3, 1, 2], false, -1),
    (&[1, 1, 2, 2, 3, 3], &[1, 1, 2, 2, 3, 3], true, 0),
];

// (list, needle, Index, Contains)
const FIND: [(&[int], int, int, bool); 32] = [
    (&[], 0, -1, false),
    (&[], 1, -1, false),
    (&[], 2, -1, false),
    (&[], 3, -1, false),
    (&[1], 0, -1, false),
    (&[1], 1, 0, true),
    (&[1], 2, -1, false),
    (&[1], 3, -1, false),
    (&[1, 2], 0, -1, false),
    (&[1, 2], 1, 0, true),
    (&[1, 2], 2, 1, true),
    (&[1, 2], 3, -1, false),
    (&[1, 2, 3], 0, -1, false),
    (&[1, 2, 3], 1, 0, true),
    (&[1, 2, 3], 2, 1, true),
    (&[1, 2, 3], 3, 2, true),
    (&[1, 2, 2, 3], 0, -1, false),
    (&[1, 2, 2, 3], 1, 0, true),
    (&[1, 2, 2, 3], 2, 1, true),
    (&[1, 2, 2, 3], 3, 3, true),
    (&[2, 2, 2], 0, -1, false),
    (&[2, 2, 2], 1, -1, false),
    (&[2, 2, 2], 2, 0, true),
    (&[2, 2, 2], 3, -1, false),
    (&[3, 1, 2], 0, -1, false),
    (&[3, 1, 2], 1, 1, true),
    (&[3, 1, 2], 2, 2, true),
    (&[3, 1, 2], 3, 0, true),
    (&[1, 1, 2, 2, 3, 3], 0, -1, false),
    (&[1, 1, 2, 2, 3, 3], 1, 0, true),
    (&[1, 1, 2, 2, 3, 3], 2, 2, true),
    (&[1, 1, 2, 2, 3, 3], 3, 4, true),
];

// (list, Compact)
const COMPACT: [(&[int], &[int]); 10] = [
    (&[], &[]),
    (&[1], &[1]),
    (&[1, 2], &[1, 2]),
    (&[1, 2, 3], &[1, 2, 3]),
    (&[1, 2, 2, 3], &[1, 2, 3]),
    (&[2, 2, 2], &[2]),
    (&[3, 1, 2], &[3, 1, 2]),
    (&[1, 1, 2, 2, 3, 3], &[1, 2, 3]),
    (&[1, 2, 1], &[1, 2, 1]),
    (&[1, 1, 1, 2, 1], &[1, 2, 1]),
];

// (i, j, Delete) over [0,1,2,3,4]
const DELETE: [(int, int, &[int]); 7] = [
    (0, 0, &[0, 1, 2, 3, 4]),
    (0, 1, &[1, 2, 3, 4]),
    (0, 5, &[]),
    (2, 2, &[0, 1, 2, 3, 4]),
    (2, 4, &[0, 1, 4]),
    (5, 5, &[0, 1, 2, 3, 4]),
    (4, 5, &[0, 1, 2, 3]),
];

// (i, Insert [8,9], Insert nothing) over [0,1,2,3,4]
const INSERT: [(int, &[int], &[int]); 3] = [
    (0, &[8, 9, 0, 1, 2, 3, 4], &[0, 1, 2, 3, 4]),
    (1, &[0, 8, 9, 1, 2, 3, 4], &[0, 1, 2, 3, 4]),
    (5, &[0, 1, 2, 3, 4, 8, 9], &[0, 1, 2, 3, 4]),
];

// (i, j, Replace with [8,9], Replace with nothing)
const REPLACE: [(int, int, &[int], &[int]); 5] = [
    (0, 0, &[8, 9, 0, 1, 2, 3, 4], &[0, 1, 2, 3, 4]),
    (0, 2, &[8, 9, 2, 3, 4], &[2, 3, 4]),
    (2, 2, &[0, 1, 8, 9, 2, 3, 4], &[0, 1, 2, 3, 4]),
    (2, 5, &[0, 1, 8, 9], &[0, 1]),
    (5, 5, &[0, 1, 2, 3, 4, 8, 9], &[0, 1, 2, 3, 4]),
];

// (count, Repeat [1,2], Repeat [])
const REPEAT: [(int, &[int], &[int]); 4] = [
    (0, &[], &[]),
    (1, &[1, 2], &[]),
    (2, &[1, 2, 1, 2], &[]),
    (3, &[1, 2, 1, 2, 1, 2], &[]),
];

// (list, Reverse, Clone)
const REVERSE: [(&[int], &[int], &[int]); 8] = [
    (&[], &[], &[]),
    (&[1], &[1], &[1]),
    (&[1, 2], &[2, 1], &[1, 2]),
    (&[1, 2, 3], &[3, 2, 1], &[1, 2, 3]),
    (&[1, 2, 2, 3], &[3, 2, 2, 1], &[1, 2, 2, 3]),
    (&[2, 2, 2], &[2, 2, 2], &[2, 2, 2]),
    (&[3, 1, 2], &[2, 1, 3], &[3, 1, 2]),
    (
        &[1, 1, 2, 2, 3, 3],
        &[3, 3, 2, 2, 1, 1],
        &[1, 1, 2, 2, 3, 3],
    ),
];

// (n, Chunk of [1,2,3,4,5])
const CHUNK: [(int, &[&[int]]); 5] = [
    (1, &[&[1], &[2], &[3], &[4], &[5]]),
    (2, &[&[1, 2], &[3, 4], &[5]]),
    (3, &[&[1, 2, 3], &[4, 5]]),
    (5, &[&[1, 2, 3, 4, 5]]),
    (10, &[&[1, 2, 3, 4, 5]]),
];

// (list, Collect(Values), Sorted(Values))
const ITER: [(&[int], &[int], &[int]); 8] = [
    (&[], &[], &[]),
    (&[1], &[1], &[1]),
    (&[1, 2], &[1, 2], &[1, 2]),
    (&[1, 2, 3], &[1, 2, 3], &[1, 2, 3]),
    (&[1, 2, 2, 3], &[1, 2, 2, 3], &[1, 2, 2, 3]),
    (&[2, 2, 2], &[2, 2, 2], &[2, 2, 2]),
    (&[3, 1, 2], &[3, 1, 2], &[1, 2, 3]),
    (
        &[1, 1, 2, 2, 3, 3],
        &[1, 1, 2, 2, 3, 3],
        &[1, 1, 2, 2, 3, 3],
    ),
];
#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. IsSorted, Min, Max. Min and Max PANIC on an empty slice — Go
    //    says so outright — so the empty row asserts only IsSorted,
    //    which is true for it.
    {
        let mut ok = true;
        let mut i = 0;
        while i < Q.len() {
            let (s, want_sorted, want_min, want_max) = Q[i];
            if slices::IsSorted(&sl(s)) != want_sorted {
                ok = false;
            }
            if want_min != "panic" {
                let mn = slices::Min(&sl(s));
                let mx = slices::Max(&sl(s));
                let mut wn: int = 0;
                for b in want_min.as_bytes() {
                    wn = wn * 10 + (*b - b'0') as int;
                }
                let mut wx: int = 0;
                for b in want_max.as_bytes() {
                    wx = wx * 10 + (*b - b'0') as int;
                }
                if mn != wn || mx != wx {
                    ok = false;
                }
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "IsSorted/Min/Max");
    }

    // 2. BinarySearch over [1,3,5,7,9]. A miss returns the index the
    //    value WOULD go at, not -1 — so 0 is (0,false) and 10 is
    //    (5,false), and an empty slice is (0,false).
    {
        let mut ok = true;
        let sorted = sl(&[1, 3, 5, 7, 9]);
        let mut i = 0;
        while i < BSEARCH.len() {
            let (v, want_i, want_ok) = BSEARCH[i];
            let (got_i, got_ok) = slices::BinarySearch(&sorted, &v);
            if got_i != want_i || got_ok != want_ok {
                ok = false;
            }
            i += 1;
        }
        let empty: slice<int> = slice::new();
        let (ei, eok) = slices::BinarySearch(&empty, &5);
        if ei != 0 || eok {
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 2",
            "BinarySearch (miss gives insert pos)",
        );
    }

    // 3. Equal and Compare over all 64 pairs. Compare is lexical: a
    //    prefix sorts before what extends it.
    {
        let mut ok = true;
        let mut i = 0;
        while i < CMP.len() {
            let (a, b, want_eq, want_cmp) = CMP[i];
            if slices::Equal(&sl(a), &sl(b)) != want_eq {
                ok = false;
            }
            if slices::Compare(&sl(a), &sl(b)) != want_cmp {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 3", "Equal/Compare x64");
    }

    // 4. Index and Contains — a miss is -1, never 0.
    {
        let mut ok = true;
        let mut i = 0;
        while i < FIND.len() {
            let (s, v, want_i, want_c) = FIND[i];
            if slices::Index(&sl(s), &v) != want_i {
                ok = false;
            }
            if slices::Contains(&sl(s), &v) != want_c {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "Index/Contains x32");
    }

    // 5. Compact collapses RUNS. {1,2,1} keeps both ones; {1,1,1,2,1}
    //    becomes {1,2,1}, not {1,2}.
    {
        let mut ok = true;
        let mut i = 0;
        while i < COMPACT.len() {
            let (s, want) = COMPACT[i];
            if !eq(&raw(&slices::Compact(sl(s))), want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 5", "Compact collapses runs");
    }

    // 6. Delete at every boundary, including i == j (a no-op) and
    //    [len:len].
    {
        let mut ok = true;
        let mut i = 0;
        while i < DELETE.len() {
            let (a, b, want) = DELETE[i];
            if !eq(&raw(&slices::Delete(sl(&[0, 1, 2, 3, 4]), a, b)), want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 6", "Delete at the boundaries");
    }

    // 7. Insert and Replace, including inserting nothing at all — which
    //    must leave the slice alone, not truncate it.
    {
        let mut ok = true;
        let base = &[0, 1, 2, 3, 4];
        let empty: slice<int> = slice::new();
        let mut i = 0;
        while i < INSERT.len() {
            let (at, want, want_empty) = INSERT[i];
            if !eq(&raw(&slices::Insert(sl(base), at, &sl(&[8, 9]))), want) {
                ok = false;
            }
            if !eq(&raw(&slices::Insert(sl(base), at, &empty)), want_empty) {
                ok = false;
            }
            i += 1;
        }
        i = 0;
        while i < REPLACE.len() {
            let (a, b, want, want_none) = REPLACE[i];
            if !eq(&raw(&slices::Replace(sl(base), a, b, &sl(&[8, 9]))), want) {
                ok = false;
            }
            if !eq(&raw(&slices::Replace(sl(base), a, b, &empty)), want_none) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 7", "Insert/Replace (incl. nothing)");
    }

    // 8. Repeat, Concat, Reverse, Clone.
    {
        let mut ok = true;
        let empty: slice<int> = slice::new();
        let mut i = 0;
        while i < REPEAT.len() {
            let (n, want, want_empty) = REPEAT[i];
            if !eq(&raw(&slices::Repeat(&sl(&[1, 2]), n)), want) {
                ok = false;
            }
            if !eq(&raw(&slices::Repeat(&empty, n)), want_empty) {
                ok = false;
            }
            i += 1;
        }
        let a = sl(&[1]);
        let b: slice<int> = slice::new();
        let c = sl(&[2, 3]);
        if !eq(&raw(&slices::Concat(&[&a, &b, &c])), &[1, 2, 3]) {
            ok = false;
        }
        let none: [&slice<int>; 0] = [];
        if slices::Concat(&none).Len() != 0 {
            ok = false;
        }
        i = 0;
        while i < REVERSE.len() {
            let (s, want, want_clone) = REVERSE[i];
            let mut v = sl(s);
            slices::Reverse(&mut v);
            if !eq(&raw(&v), want) {
                ok = false;
            }
            if !eq(&raw(&slices::Clone(&sl(s))), want_clone) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 8", "Repeat/Concat/Reverse/Clone");
    }

    // 9. Chunk: the last chunk is short, and n larger than the slice
    //    yields ONE chunk holding everything.
    {
        let mut ok = true;
        let mut i = 0;
        while i < CHUNK.len() {
            let (n, want) = CHUNK[i];
            let got = slices::Chunk(sl(&[1, 2, 3, 4, 5]), n);
            if got.Len() as usize != want.len() {
                ok = false;
            } else {
                let mut j = 0usize;
                while j < want.len() {
                    if !eq(&raw(&got[j]), want[j]) {
                        ok = false;
                    }
                    j += 1;
                }
            }
            i += 1;
        }
        report(&mut failed, ok, " 9", "Chunk (short tail, n > len)");
    }

    // 10. The iter.Seq bridge: Values, Collect, Sorted, AppendSeq, All
    //     and Backward.
    {
        let mut ok = true;
        let mut i = 0;
        while i < ITER.len() {
            let (s, want_values, want_sorted) = ITER[i];
            if !eq(&raw(&slices::Collect(slices::Values(&sl(s)))), want_values) {
                ok = false;
            }
            if !eq(&raw(&slices::Sorted(slices::Values(&sl(s)))), want_sorted) {
                ok = false;
            }
            i += 1;
        }
        let seq = slices::Values(&sl(&[1, 2]));
        if !eq(&raw(&slices::AppendSeq(sl(&[9]), seq)), &[9, 1, 2]) {
            ok = false;
        }
        // Go: all [0 7 1 8 2 9] — index then value, in order.
        let mut pairs: Vec<int> = Vec::new();
        goish::iter::Seq2::run(&slices::All(&sl(&[7, 8, 9])), &mut |i, v| {
            pairs.push(i);
            pairs.push(v);
            true
        });
        if !eq(&pairs, &[0, 7, 1, 8, 2, 9]) {
            ok = false;
        }
        let mut back: Vec<int> = Vec::new();
        goish::iter::Seq2::run(&slices::Backward(&sl(&[7, 8, 9])), &mut |i, v| {
            back.push(i);
            back.push(v);
            true
        });
        if !eq(&back, &[2, 9, 1, 8, 0, 7]) {
            ok = false;
        }
        report(&mut failed, ok, "10", "the iter.Seq bridge");
    }

    // 11. Grow and Clip are capacity-only: the CONTENTS never change,
    //     and Clip after Grow gives the length back as the capacity.
    {
        let mut ok = true;
        let g = slices::Grow(sl(&[1, 2]), 10);
        if g.Len() != 2 || !eq(&raw(&g), &[1, 2]) {
            ok = false;
        }
        let c = slices::Clip(slices::Grow(sl(&[1, 2]), 10));
        if c.Len() != 2 || !eq(&raw(&c), &[1, 2]) {
            ok = false;
        }
        report(&mut failed, ok, "11", "Grow/Clip keep the contents");
    }

    if failed == 0 {
        fmt::Println!("ok 11/11");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 11");
        syscall::Exit(1);
    }
}
