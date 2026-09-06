// go: file sort/search.go decls: Search, Find, SearchInts, SearchFloat64s, SearchStrings, IntSlice.Search, Float64Slice.Search, StringSlice.Search
//
// search.go — Search, Find, SearchInts, SearchFloat64s,
// SearchStrings.
//

extern crate alloc;

use crate::convert::{int as toint, uint64 as touint64};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{float64, int};

// ─── Search (search.go:58) ──────────────────────────────────────────

// go: sdk 1.25.5 sort/search.go:58-73 Search
/// `sort.Search(n, f)` — binary-search the smallest
/// index i in [0, n) at which `f(i)` is true. `f` must be monotone:
/// false on a (possibly empty) prefix, true on the rest. Returns `n`
/// if no such index exists.
pub fn Search<F>(n: int, mut f: F) -> int
where
    F: FnMut(int) -> bool,
{
    // Go: i, j := 0, n
    let mut i: int = 0;
    let mut j = n;
    while i < j {
        // Go: h := int(uint(i+j) >> 1)
        let h = toint((touint64(i)).wrapping_add(touint64(j)) >> 1);
        // Go: if !f(h) { i = h + 1 } else { j = h }
        if !f(h) {
            i = h + 1;
        } else {
            j = h;
        }
    }
    return i;
}

// go: sdk 1.25.5 sort/search.go:99-115 Find
/// `sort.Find(n, cmp)` (search.go:99) — binary search using a 3-way
/// `cmp(i)` returning `<0`, `0`, or `>0`. Returns `(i, found)` where
/// `i` is the insertion point and `found` is true iff `cmp(i) == 0`.
pub fn Find<F>(n: int, mut cmp: F) -> (int, bool)
where
    F: FnMut(int) -> int,
{
    // Go: i, j := 0, n
    let mut i: int = 0;
    let mut j = n;
    while i < j {
        let h = toint((touint64(i)).wrapping_add(touint64(j)) >> 1);
        // Go: if cmp(h) > 0 { i = h + 1 } else { j = h }
        if cmp(h) > 0 {
            i = h + 1;
        } else {
            j = h;
        }
    }
    // Go: return i, i < n && cmp(i) == 0
    let found = i < n && cmp(i) == 0;
    return (i, found);
}

// ─── SearchInts / SearchStrings / SearchFloat64s (search.go:123-141) ─

// go: sdk 1.25.5 sort/search.go:123-125 SearchInts
/// `sort.SearchInts(a, x)` (search.go:123). The slice must be sorted
/// in ascending order; returns the index where x is or would be
/// inserted.
pub fn SearchInts(a: &slice<int>, x: int) -> int {
    // Go: Search(len(a), func(i int) bool { return a[i] >= x })
    let raw: &[int] = a;
    return Search(toint(raw.len()), |i| raw[i as usize] >= x);
}

// go: sdk 1.25.5 sort/search.go:131-133 SearchFloat64s
/// `sort.SearchFloat64s(a, x)` (search.go:131).
pub fn SearchFloat64s(a: &slice<float64>, x: float64) -> int {
    let raw: &[float64] = a;
    return Search(toint(raw.len()), |i| raw[i as usize] >= x);
}

// go: sdk 1.25.5 sort/search.go:139-141 SearchStrings
/// `sort.SearchStrings(a, x)` (search.go:139).
pub fn SearchStrings<X: Into<string>>(a: &slice<string>, x: X) -> int {
    let x: string = x.into();
    let raw: &[string] = a;
    return Search(toint(raw.len()), |i| raw[i as usize] >= x);
}

// The three convenience-type methods Go declares in this file. They are
// one-line forwards to the free functions above, and goish carries the
// types they hang off — `IntSlice`, `Float64Slice` and `StringSlice`
// are in sort.rs. A note here used to say goish's "convenience types
// carry no Search", which was true and is the reason it was worth
// three lines rather than a waiver: a caller holding an IntSlice can
// now write `p.Search(x)` as in Go.

#[allow(non_snake_case)]
impl crate::sort::IntSlice {
    // go: sdk 1.25.5 sort/search.go:144-144 IntSlice.Search
    /// Go: "Search returns the result of applying SearchInts to the
    /// receiver and x."
    pub fn Search(&self, x: int) -> int {
        return SearchInts(&self.0, x);
    }
}

#[allow(non_snake_case)]
impl crate::sort::Float64Slice {
    // go: sdk 1.25.5 sort/search.go:147-147 Float64Slice.Search
    /// Go: "Search returns the result of applying SearchFloat64s to the
    /// receiver and x."
    pub fn Search(&self, x: crate::types::float64) -> int {
        return SearchFloat64s(&self.0, x);
    }
}

#[allow(non_snake_case)]
impl crate::sort::StringSlice {
    // go: sdk 1.25.5 sort/search.go:150-150 StringSlice.Search
    /// Go: "Search returns the result of applying SearchStrings to the
    /// receiver and x."
    pub fn Search<X: Into<string>>(&self, x: X) -> int {
        return SearchStrings(&self.0, x);
    }
}
