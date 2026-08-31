// sort_ref_smoke — the `sort` package against a running Go.
// (sort/sort.go, sort/search.go, sort/slice.go, sort/zsortinterface.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_sort_ref.go` run in `package sort_test`
// by `scripts/goref.sh`.
//
// `sort.Stable` was deferred, with "would need symmerge sort" as the
// reason. It does, and it is here now. Without it a caller who needed
// stability had only `slices::SortStableFunc!`, which takes a
// comparator over a concrete slice rather than a `sort::Interface` — so
// a type that sorts several parallel arrays through Swap had no stable
// option at all.
//
// Stability is only observable when two records compare EQUAL under
// Less and are distinguishable some other way, so every input below is
// (key, tag) pairs ordered by key alone: the KEYS say the sort worked,
// the TAGS say it was stable. Two inputs are long enough to cross the
// blockSize=20 boundary where symMerge takes over from the
// insertion-sort blocks, and one of those is 45 elements over 3 keys —
// fifteen ties each, which is where a merge that is subtly wrong shows
// up and a small input would not.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::goslice::slice;
use goish::gostring::string;
use goish::sort;
use goish::types::{float64, int};
use goish::{fmt, syscall};

// go: none — goish idiom: the Go reference's `byKey` — a sort.Interface
//     over (key, tag) records that orders by key alone, so ties are
//     everywhere and stability is observable.
struct ByKey {
    keys: Vec<int>,
    tags: Vec<int>,
}

impl sort::Interface for ByKey {
    fn Len(&self) -> int {
        return self.keys.len() as int;
    }
    fn Less(&self, i: int, j: int) -> bool {
        return self.keys[i as usize] < self.keys[j as usize];
    }
    fn Swap(&mut self, i: int, j: int) {
        self.keys.swap(i as usize, j as usize);
        self.tags.swap(i as usize, j as usize);
    }
}

fn byKey(c: &[(int, int)]) -> ByKey {
    let mut k: Vec<int> = Vec::new();
    let mut t: Vec<int> = Vec::new();
    for (a, b) in c.iter() {
        k.push(*a);
        t.push(*b);
    }
    return ByKey { keys: k, tags: t };
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

// The ten inputs, as (key, tag) pairs.
const CASES: [&[(int, int)]; 10] = [
    &[],
    &[(1, 0)],
    &[(1, 0), (1, 1)],
    &[(2, 0), (1, 1)],
    &[(1, 0), (1, 1), (1, 2)],
    &[(3, 0), (1, 1), (2, 2), (1, 3), (3, 4), (2, 5)],
    &[(1, 0), (2, 1), (3, 2), (4, 3)],
    &[(4, 0), (3, 1), (2, 2), (1, 3)],
    &[(0, 0), (1, 1), (2, 2), (0, 3), (1, 4), (2, 5), (0, 6), (1, 7), (2, 8), (0, 9), (1, 10), (2, 11), (0, 12), (1, 13), (2, 14), (0, 15), (1, 16), (2, 17), (0, 18), (1, 19), (2, 20), (0, 21), (1, 22), (2, 23), (0, 24), (1, 25), (2, 26), (0, 27), (1, 28), (2, 29), (0, 30), (1, 31), (2, 32), (0, 33), (1, 34), (2, 35), (0, 36), (1, 37), (2, 38), (0, 39), (1, 40), (2, 41), (0, 42), (1, 43), (2, 44)],
    &[(25, 0), (24, 1), (23, 2), (22, 3), (21, 4), (20, 5), (19, 6), (18, 7), (17, 8), (16, 9), (15, 10), (14, 11), (13, 12), (12, 13), (11, 14), (10, 15), (9, 16), (8, 17), (7, 18), (6, 19), (5, 20), (4, 21), (3, 22), (2, 23), (1, 24)],
];

// (case, Stable keys, Stable tags) — tags pin the STABILITY.
const STABLE: [(usize, &[int], &[int]); 10] = [
    (0, &[], &[]),
    (1, &[1], &[0]),
    (2, &[1, 1], &[0, 1]),
    (3, &[1, 2], &[1, 0]),
    (4, &[1, 1, 1], &[0, 1, 2]),
    (5, &[1, 1, 2, 2, 3, 3], &[1, 3, 2, 5, 0, 4]),
    (6, &[1, 2, 3, 4], &[0, 1, 2, 3]),
    (7, &[1, 2, 3, 4], &[3, 2, 1, 0]),
    (8, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2], &[0, 3, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 1, 4, 7, 10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43, 2, 5, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35, 38, 41, 44]),
    (9, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], &[24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]),
];

// (case, Sort keys) — Sort is not stable, so only keys.
const SORTK: [(usize, &[int]); 10] = [
    (0, &[]),
    (1, &[1]),
    (2, &[1, 1]),
    (3, &[1, 2]),
    (4, &[1, 1, 1]),
    (5, &[1, 1, 2, 2, 3, 3]),
    (6, &[1, 2, 3, 4]),
    (7, &[1, 2, 3, 4]),
    (8, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]),
    (9, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]),
];

// (case, Sort(Reverse) keys)
const REV: [(usize, &[int]); 8] = [
    (0, &[]),
    (1, &[1]),
    (2, &[1, 1]),
    (3, &[2, 1]),
    (4, &[1, 1, 1]),
    (5, &[3, 3, 2, 2, 1, 1]),
    (6, &[4, 3, 2, 1]),
    (7, &[4, 3, 2, 1]),
];

// (x, SearchInts) over [1,3,5,7,9]
const SEARCHINTS: [(int, int); 7] = [
    (0, 0),
    (1, 0),
    (2, 1),
    (3, 1),
    (8, 4),
    (9, 4),
    (10, 5),
];

// (x, SearchStrings) over ["a","c","e"]
const SEARCHSTRS: [(&str, int); 5] = [
    ("", 0),
    ("a", 0),
    ("b", 1),
    ("e", 2),
    ("f", 3),
];

// (x, SearchFloat64s) over [1.0, 2.5, 4.0]
const SEARCHF64: [(float64, int); 5] = [
    (0.0, 0),
    (1.0, 0),
    (2.0, 1),
    (4.0, 2),
    (5.0, 3),
];

// (n, Search always-false, Search always-true)
const SEARCHN: [(int, int, int); 3] = [
    (0, 0, 0),
    (1, 1, 0),
    (5, 5, 0),
];

// (target, Find index, Find found) over [1,3,5,7,9]
const FIND: [(int, int, bool); 4] = [
    (0, 0, false),
    (3, 1, true),
    (4, 2, false),
    (10, 5, false),
];
#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Stable over ten inputs. The TAGS are the assertion: for the
    //    45-element case Go leaves them [0 3 6 9 …], every tie in the
    //    order it found them, and any reordering at all is a failure.
    {
        let mut ok = true;
        let mut i = 0;
        while i < STABLE.len() {
            let (n, want_keys, want_tags) = STABLE[i];
            let mut d = byKey(CASES[n]);
            sort::Stable(&mut d);
            if !eq(&d.keys, want_keys) || !eq(&d.tags, want_tags) {
                ok = false;
            }
            if !sort::IsSorted(&d) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "Stable keeps ties in order");
    }

    // 2. Sort. Not stable in either language, so only the keys are
    //    checked — but they must be Go's, and IsSorted must agree.
    {
        let mut ok = true;
        let mut i = 0;
        while i < SORTK.len() {
            let (n, want_keys) = SORTK[i];
            let mut d = byKey(CASES[n]);
            sort::Sort(&mut d);
            if !eq(&d.keys, want_keys) || !sort::IsSorted(&d) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 2", "Sort orders the keys");
    }

    // 3. Reverse wraps an Interface and flips Less, so Sort(Reverse(d))
    //    is descending. The wrapper must forward Len and Swap
    //    untouched — Go gets that from embedding, goish writes it out.
    {
        let mut ok = true;
        let mut i = 0;
        while i < REV.len() {
            let (n, want_keys) = REV[i];
            let d = byKey(CASES[n]);
            let mut r = sort::Reverse(d);
            sort::Sort(&mut r);
            if !eq(&r.inner.keys, want_keys) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 3", "Reverse flips Less only");
    }

    // 4. The three convenience types. Float64Slice is the one with a
    //    rule: NaN sorts BEFORE everything, including -Inf, because
    //    floating-point `<` alone gives no consistent order for it.
    {
        let mut ok = true;
        let mut xs = sort::IntSlice(slice::<int>::__from_vec(alloc::vec![5, 2, 9, 2, 7]));
        xs.Sort();
        let got: &[int] = &xs.0;
        if got != &[2, 2, 5, 7, 9] || !sort::IntsAreSorted(&xs.0) {
            ok = false;
        }

        let mut ss = sort::StringSlice(slice::<string>::__from_vec(alloc::vec![
            string::from_bytes(b"pear"),
            string::from_bytes(b"apple"),
            string::from_bytes(b"fig"),
            string::from_bytes(b"apple"),
        ]));
        ss.Sort();
        let want = ["apple", "apple", "fig", "pear"];
        let mut j = 0usize;
        while j < want.len() {
            if ss.0[j] != string::from_bytes(want[j].as_bytes()) {
                ok = false;
            }
            j += 1;
        }
        if !sort::StringsAreSorted(&ss.0) {
            ok = false;
        }

        let nan = float64::NAN;
        let mut fs = sort::Float64Slice(slice::<float64>::__from_vec(alloc::vec![
            3.5,
            nan,
            1.5,
            float64::NEG_INFINITY,
            2.5,
            nan
        ]));
        fs.Sort();
        // Go: nan-first=true, then -Inf, then [1.5 2.5 3.5].
        if !fs.0[0].is_nan() || !fs.0[1].is_nan() {
            ok = false;
        }
        if fs.0[2] != float64::NEG_INFINITY {
            ok = false;
        }
        if fs.0[3] != 1.5 || fs.0[4] != 2.5 || fs.0[5] != 3.5 {
            ok = false;
        }
        if !sort::Float64sAreSorted(&fs.0) {
            ok = false;
        }
        report(&mut failed, ok, " 4", "IntSlice/StringSlice/Float64Slice");
    }

    // 5. Search and the three typed wrappers. A miss returns the
    //    insertion point, and Search over n=0 is 0 either way.
    {
        let mut ok = true;
        let a = slice::<int>::__from_vec(alloc::vec![1, 3, 5, 7, 9]);
        let mut i = 0;
        while i < SEARCHINTS.len() {
            let (x, want) = SEARCHINTS[i];
            if sort::SearchInts(&a, x) != want {
                ok = false;
            }
            i += 1;
        }
        let s = slice::<string>::__from_vec(alloc::vec![
            string::from_bytes(b"a"),
            string::from_bytes(b"c"),
            string::from_bytes(b"e"),
        ]);
        i = 0;
        while i < SEARCHSTRS.len() {
            let (x, want) = SEARCHSTRS[i];
            if sort::SearchStrings(&s, string::from_bytes(x.as_bytes())) != want {
                ok = false;
            }
            i += 1;
        }
        let f = slice::<float64>::__from_vec(alloc::vec![1.0, 2.5, 4.0]);
        i = 0;
        while i < SEARCHF64.len() {
            let (x, want) = SEARCHF64[i];
            if sort::SearchFloat64s(&f, x) != want {
                ok = false;
            }
            i += 1;
        }
        i = 0;
        while i < SEARCHN.len() {
            let (n, want_false, want_true) = SEARCHN[i];
            if sort::Search(n, |_| false) != want_false {
                ok = false;
            }
            if sort::Search(n, |_| true) != want_true {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 5", "Search + the typed wrappers");
    }

    // 6. Find: the comparator returns a sign, and the answer is the
    //    index plus whether it was an exact hit.
    {
        let mut ok = true;
        let a: [int; 5] = [1, 3, 5, 7, 9];
        let mut i = 0;
        while i < FIND.len() {
            let (target, want_i, want_found) = FIND[i];
            let (got_i, got_found) = sort::Find(5, |k| target - a[k as usize]);
            if got_i != want_i || got_found != want_found {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 6", "Find (sign comparator)");
    }

    // 7. SliceStable over the 45-element tie-heavy input — the same
    //    guarantee as Stable, reached through a closure instead of an
    //    Interface. SliceIsSorted agrees.
    {
        let mut ok = true;
        let (_, want_keys, want_tags) = STABLE[8];
        let src = CASES[8];
        let mut keys: Vec<int> = Vec::new();
        let mut tags: Vec<int> = Vec::new();
        for (k, t) in src.iter() {
            keys.push(*k);
            tags.push(*t);
        }
        // Sort an index permutation so both columns move together.
        let mut idx: Vec<int> = (0..keys.len() as int).collect();
        let mut iv = slice::<int>::__from_vec(idx.clone());
        let ks = keys.clone();
        sort::SliceStable(&mut iv, |a, b| ks[a as usize] < ks[b as usize]);
        idx = {
            let r: &[int] = &iv;
            r.to_vec()
        };
        let sk: Vec<int> = idx.iter().map(|i| keys[*i as usize]).collect();
        let st: Vec<int> = idx.iter().map(|i| tags[*i as usize]).collect();
        if !eq(&sk, want_keys) || !eq(&st, want_tags) {
            ok = false;
        }
        let mut sorted = slice::<int>::__from_vec(sk.clone());
        if !sort::SliceIsSorted(&mut sorted, |a, b| a < b) {
            ok = false;
        }
        report(&mut failed, ok, " 7", "SliceStable keeps ties in order");
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
