// go: file slices/sort.go decls: IsSorted, Min, Max, BinarySearch, IsSortedFunc, MinFunc, MaxFunc, BinarySearchFunc
//
// sort.go — IsSorted, Min, Max, BinarySearch and their Func
// variants. Sort/SortFunc/SortStableFunc are macros in the module
// root; see the note there.
//
// goishlint:ignore GOISH018 Sort, SortFunc, SortStableFunc, Next, nextPowerOfTwo, isNaN — Sort/SortFunc/SortStableFunc are macros in the module root, not functions, because they mutate in place and goish keeps such call sites free of a visible `&mut`; see the note there. `Next` and `nextPowerOfTwo` belong to `xorshift`, the PRNG pdqsort uses to break adversarial patterns, and `isNaN` is the NaN-ordering fixup — all three are the sort engine, which goish takes from Rust's stdlib.
// goishlint:ignore GOISH021 sortedHint, unknownHint, increasingHint, decreasingHint, xorshift — likewise the sort engine's internals: the hint pdqsort passes down about a partition's existing order, and the PRNG. Rust's `sort_unstable` carries its own equivalents.

extern crate alloc;

use crate::convert::int as toint;
use crate::goslice::slice;
use crate::types::int;

// go: sdk 1.25.5 slices/sort.go:42-49 IsSorted
pub fn IsSorted<T: Ord>(s: &slice<T>) -> bool {
    let raw: &[T] = s;
    for i in 1..raw.len() {
        if raw[i] < raw[i - 1] {
            return false;
        }
    }
    return true;
}

// go: sdk 1.25.5 slices/sort.go:65-74 Min
pub fn Min<T: Ord + Clone>(s: &slice<T>) -> T {
    let raw: &[T] = s;
    if raw.is_empty() {
        panic!("slices.Min: empty list");
    }
    let mut best = &raw[0];
    for v in &raw[1..] {
        if v < best {
            best = v;
        }
    }
    return best.clone();
}

// go: sdk 1.25.5 slices/sort.go:95-104 Max
pub fn Max<T: Ord + Clone>(s: &slice<T>) -> T {
    let raw: &[T] = s;
    if raw.is_empty() {
        panic!("slices.Max: empty list");
    }
    let mut best = &raw[0];
    for v in &raw[1..] {
        if v > best {
            best = v;
        }
    }
    return best.clone();
}

// go: sdk 1.25.5 slices/sort.go:126-143 BinarySearch
/// `BinarySearch(s, &target)` — assumes `s` is sorted ascending. Returns
/// `(index, found)`. When not found, `index` is the insertion point
/// (Go-faithful).
pub fn BinarySearch<T: Ord>(s: &slice<T>, target: &T) -> (int, bool) {
    let raw: &[T] = s;
    return match raw.binary_search(target) {
        Ok(i) => (toint(i), true),
        Err(i) => (toint(i), false),
    };
}

// go: sdk 1.25.5 slices/sort.go:53-60 IsSortedFunc
pub fn IsSortedFunc<T, F>(s: &slice<T>, mut cmp: F) -> bool
where
    F: FnMut(&T, &T) -> int,
{
    let raw: &[T] = s;
    for i in 1..raw.len() {
        if cmp(&raw[i], &raw[i - 1]) < 0 {
            return false;
        }
    }
    return true;
}

// go: sdk 1.25.5 slices/sort.go:79-90 MinFunc
pub fn MinFunc<T: Clone, F>(s: &slice<T>, mut cmp: F) -> T
where
    F: FnMut(&T, &T) -> int,
{
    let raw: &[T] = s;
    if raw.is_empty() {
        panic!("slices.MinFunc: empty list");
    }
    let mut best = &raw[0];
    for i in 1..raw.len() {
        if cmp(&raw[i], best) < 0 {
            best = &raw[i];
        }
    }
    return best.clone();
}

// go: sdk 1.25.5 slices/sort.go:109-120 MaxFunc
pub fn MaxFunc<T: Clone, F>(s: &slice<T>, mut cmp: F) -> T
where
    F: FnMut(&T, &T) -> int,
{
    let raw: &[T] = s;
    if raw.is_empty() {
        panic!("slices.MaxFunc: empty list");
    }
    let mut best = &raw[0];
    for i in 1..raw.len() {
        if cmp(&raw[i], best) > 0 {
            best = &raw[i];
        }
    }
    return best.clone();
}

// go: sdk 1.25.5 slices/sort.go:152-168 BinarySearchFunc
/// `BinarySearchFunc(s, &target, cmp)` — element type `T` and target type
/// `U` may differ. `cmp(&e, &target)` returns negative when `e` precedes
/// `target`, zero when matching, positive when following.
pub fn BinarySearchFunc<T, U, F>(s: &slice<T>, target: &U, mut cmp: F) -> (int, bool)
where
    F: FnMut(&T, &U) -> int,
{
    let raw: &[T] = s;
    let n = raw.len();
    let mut i = 0usize;
    let mut j = n;
    while i < j {
        let h = (i + j) >> 1; // (i+j) is bounded by 2*n; usize on 64-bit can't overflow for any realistic slice
        if cmp(&raw[h], target) < 0 {
            i = h + 1;
        } else {
            j = h;
        }
    }
    let found = i < n && cmp(&raw[i], target) == 0;
    return (toint(i), found);
}
