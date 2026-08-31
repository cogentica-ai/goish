// go: file slices/slices.go decls: Equal, Compare, Index, Contains, Compact, Concat, Delete, Clone, Reverse, Repeat, Insert, Replace, Grow, Clip, EqualFunc, CompareFunc, IndexFunc, ContainsFunc, DeleteFunc, CompactFunc
//
// slices.go — Equal, Compare, Index, Contains, Insert, Delete,
// Replace, Clone, Compact, Grow, Clip, Reverse, Concat, Repeat.
//
// goishlint:ignore GOISH018 rotateLeft, rotateRight, overlaps, startIdx — the four helpers Go's Insert/Delete/Replace use to edit a slice IN PLACE when the argument's capacity allows it, reusing the caller's backing array. `overlaps` and `startIdx` compare raw ELEMENT ADDRESSES to find out whether two slices share memory, which is what makes that reuse safe. goish's Insert/Delete/Replace build and return a new slice — the signatures take `slice<T>` by value and hand one back — so there is no aliasing question to answer and no in-place rotate to do. The cost is an allocation Go can sometimes avoid; the behaviour is the same.

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::int as toint;
use crate::goslice::slice;
use crate::types::int;

// go: sdk 1.25.5 slices/slices.go:20-30 Equal
pub fn Equal<T: PartialEq>(s1: &slice<T>, s2: &slice<T>) -> bool {
    let a: &[T] = s1;
    let b: &[T] = s2;
    return a == b;
}

// go: sdk 1.25.5 slices/slices.go:57-71 Compare
pub fn Compare<T: Ord>(s1: &slice<T>, s2: &slice<T>) -> int {
    use core::cmp::Ordering::*;
    let a: &[T] = s1;
    let b: &[T] = s2;
    return match a.cmp(b) {
        Less => -1,
        Equal => 0,
        Greater => 1,
    };
}

// go: sdk 1.25.5 slices/slices.go:96-103 Index
pub fn Index<T: PartialEq>(s: &slice<T>, v: &T) -> int {
    let raw: &[T] = s;
    let mut i = 0usize;
    while i < raw.len() {
        if &raw[i] == v {
            return toint(i);
        }
        i += 1;
    }
    return -1;
}

// go: sdk 1.25.5 slices/slices.go:117-119 Contains
pub fn Contains<T: PartialEq>(s: &slice<T>, v: &T) -> bool {
    return Index(s, v) >= 0;
}

// go: sdk 1.25.5 slices/slices.go:369-388 Compact
/// `Compact(s)` — removes consecutive equal elements. To dedupe across
/// the whole slice, sort first: `slices::Sort!(xs); let xs = slices::Compact(xs);`.
pub fn Compact<T: PartialEq>(s: slice<T>) -> slice<T> {
    let mut v = s.__into_vec();
    v.dedup();
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 slices/slices.go:489-505 Concat
/// `Concat(&[s1, s2, s3])` — concatenates in order.
pub fn Concat<T: Clone>(parts: &[&slice<T>]) -> slice<T> {
    let total: usize = parts.iter().map(|p| p.Len() as usize).sum();
    let mut v: Vec<T> = Vec::with_capacity(total);
    for p in parts {
        let raw: &[T] = p;
        v.extend_from_slice(raw);
    }
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 slices/slices.go:222-233 Delete
/// `Delete(s, i, j)` — returns a slice with elements `[i:j]` removed.
/// Panics on negative indices, on `j < i`, or on `j > len(s)` — matching
/// Go's runtime panic on bad slice index.
pub fn Delete<T>(s: slice<T>, i: int, j: int) -> slice<T> {
    if i < 0 || j < i {
        panic!("slices.Delete: invalid range");
    }
    let mut v = s.__into_vec();
    let iu = i as usize;
    let ju = j as usize;
    if ju > v.len() {
        panic!("slices.Delete: out of range");
    }
    v.drain(iu..ju);
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 slices/slices.go:353-361 Clone
/// `Clone(s)` — deep copy. Free-function form mirrors Go's
/// `slices.Clone(s)`. Equivalent to `s.clone()`.
pub fn Clone<T: Clone>(s: &slice<T>) -> slice<T> {
    return s.clone();
}

// go: sdk 1.25.5 slices/slices.go:481-485 Reverse
/// Line-by-line port of `slices.Reverse` (slices/slices.go:481) — reverse
/// the elements of `s` in place.
pub fn Reverse<T>(s: &mut slice<T>) {
    // Go: for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 { s[i], s[j] = s[j], s[i] }
    let raw: &mut [T] = s;
    let mut i: usize = 0;
    if raw.is_empty() {
        return;
    }
    let mut j: usize = raw.len() - 1;
    while i < j {
        raw.swap(i, j);
        i += 1;
        j -= 1;
    }
}

// go: sdk 1.25.5 slices/slices.go:512-529 Repeat
/// Line-by-line port of `slices.Repeat` (slices/slices.go:512) — return
/// a new slice that repeats `x` `count` times. Result length is
/// `len(x) * count`. Panics on negative `count` (Go semantics).
pub fn Repeat<T: Clone>(x: &slice<T>, count: int) -> slice<T> {
    // Go: if count < 0 { panic("cannot be negative") }
    if count < 0 {
        panic!("slices.Repeat: count cannot be negative");
    }
    let raw: &[T] = x;
    let n = raw.len();
    // Go: hi, lo := bits.Mul(uint(len(x)), uint(count))
    //     if hi > 0 || lo > maxInt { panic("overflow") }
    // Goish: usize::checked_mul covers both cases.
    let total = match n.checked_mul(count as usize) {
        Some(t) => t,
        None => panic!("slices.Repeat: len(x) * count overflows"),
    };
    // Go: newslice := make(S, int(lo)); copy + double-up loop.
    // Goish: doubling-copy mirrors Go's algorithm verbatim.
    let mut out: alloc::vec::Vec<T> = alloc::vec::Vec::with_capacity(total);
    if n == 0 || count == 0 {
        return slice::__from_vec(out);
    }
    // First copy of x.
    for el in raw.iter() {
        out.push(el.clone());
    }
    // Go: for n < len(newslice) { n += copy(newslice[n:], newslice[:n]) }
    let mut filled = n;
    while filled < total {
        let take = core::cmp::min(filled, total - filled);
        // Clone the prefix [0..take) to extend.
        for k in 0..take {
            let elem = out[k].clone();
            out.push(elem);
        }
        filled += take;
    }
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 slices/slices.go:135-214 Insert
/// Line-by-line port of `slices.Insert` (slices/slices.go:135) — insert
/// the values `v...` into `s` at index `i`. Returns the modified slice.
/// Panics if `i > len(s)` or `i < 0` (matches Go's bounds check).
///
/// Goish deviation: Go's `v ...E` variadic becomes `v: &slice<T>`. Goish
/// slices are not aliased the way Go slices are, so we don't need the
/// overlap detection / rotateRight branches — we always own the buffer.
pub fn Insert<T: Clone>(s: slice<T>, i: int, v: &slice<T>) -> slice<T> {
    // Go: _ = s[i:] // bounds check
    if i < 0 || (i as usize) > s.Len() as usize {
        panic!("slices.Insert: index out of range");
    }
    // Go: m := len(v); if m == 0 { return s }
    let m = v.Len() as usize;
    if m == 0 {
        return s;
    }
    // Goish: own the backing Vec and splice in.
    let mut out = s.__into_vec();
    let iu = i as usize;
    // Build the insert payload by cloning v elementwise.
    let raw_v: &[T] = v;
    let mut payload: alloc::vec::Vec<T> = alloc::vec::Vec::with_capacity(m);
    for el in raw_v.iter() {
        payload.push(el.clone());
    }
    // Vec::splice handles all the shifting in one shot.
    out.splice(iu..iu, payload);
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 slices/slices.go:260-347 Replace
/// Line-by-line port of `slices.Replace` (slices/slices.go:260) — replaces
/// `s[i:j]` with the given `v` and returns the modified slice. Panics if
/// `j > len(s)` or `i > j` (Go's bounds-check semantics).
///
/// Goish deviation: variadic `v...E` becomes `v: &slice<T>`; aliasing
/// concerns absent since the backing Vec is owned.
pub fn Replace<T: Clone>(s: slice<T>, i: int, j: int, v: &slice<T>) -> slice<T> {
    // Go: _ = s[i:j] // bounds check
    if i < 0 || j < i || (j as usize) > s.Len() as usize {
        panic!("slices.Replace: invalid range");
    }
    // Go: if i == j { return Insert(s, i, v...) }
    if i == j {
        return Insert(s, i, v);
    }
    let mut out = s.__into_vec();
    let iu = i as usize;
    let ju = j as usize;
    // Build the replacement payload by cloning v elementwise.
    let raw_v: &[T] = v;
    let mut payload: alloc::vec::Vec<T> = alloc::vec::Vec::with_capacity(raw_v.len());
    for el in raw_v.iter() {
        payload.push(el.clone());
    }
    out.splice(iu..ju, payload);
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 slices/slices.go:420-429 Grow
/// Line-by-line port of `slices.Grow` (slices/slices.go:420) — grows
/// the slice's capacity, if necessary, to guarantee space for another
/// `n` elements. Panics on negative `n`.
///
/// Goish: backing Vec is always owned, so we can call reserve directly.
pub fn Grow<T>(s: slice<T>, n: int) -> slice<T> {
    // Go: if n < 0 { panic("cannot be negative") }
    if n < 0 {
        panic!("slices.Grow: cannot be negative");
    }
    let mut v = s.__into_vec();
    // Go: if n -= cap(s) - len(s); n > 0 { ... }
    // Goish: reserve already amortizes; let Vec handle the math.
    v.reserve(n as usize);
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 slices/slices.go:433-435 Clip
/// Line-by-line port of `slices.Clip` (slices/slices.go:433) — drops
/// unused capacity. In Go: `s[:len(s):len(s)]`. In goish: shrink_to_fit.
pub fn Clip<T>(s: slice<T>) -> slice<T> {
    let mut v = s.__into_vec();
    v.shrink_to_fit();
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 slices/slices.go:37-48 EqualFunc
pub fn EqualFunc<T, U, F>(s1: &slice<T>, s2: &slice<U>, mut eq: F) -> bool
where
    F: FnMut(&T, &U) -> bool,
{
    let a: &[T] = s1;
    let b: &[U] = s2;
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if !eq(&a[i], &b[i]) {
            return false;
        }
    }
    return true;
}

// go: sdk 1.25.5 slices/slices.go:78-92 CompareFunc
pub fn CompareFunc<T, U, F>(s1: &slice<T>, s2: &slice<U>, mut cmp: F) -> int
where
    F: FnMut(&T, &U) -> int,
{
    let a: &[T] = s1;
    let b: &[U] = s2;
    let n = core::cmp::min(a.len(), b.len());
    for i in 0..n {
        let c = cmp(&a[i], &b[i]);
        if c != 0 {
            return if c < 0 { -1 } else { 1 };
        }
    }
    return if a.len() < b.len() {
        -1
    } else if a.len() > b.len() {
        1
    } else {
        0
    };
}

// go: sdk 1.25.5 slices/slices.go:107-114 IndexFunc
pub fn IndexFunc<T, F>(s: &slice<T>, mut pred: F) -> int
where
    F: FnMut(&T) -> bool,
{
    let raw: &[T] = s;
    let mut i = 0usize;
    while i < raw.len() {
        if pred(&raw[i]) {
            return toint(i);
        }
        i += 1;
    }
    return -1;
}

// go: sdk 1.25.5 slices/slices.go:123-125 ContainsFunc
pub fn ContainsFunc<T: Clone, F>(s: &slice<T>, pred: F) -> bool
where
    F: FnMut(T) -> bool,
{
    return IndexFuncOwned(s, pred) >= 0;
}

// go: none — goish idiom: `IndexFunc`'s predicate takes `&T`, which is
/// Internal: Go-shaped `IndexFunc` that passes elements by value (Go's
/// closure semantic). T must be Clone so the loop can hand each item
/// to `pred` by value. Used by `ContainsFunc`; exposed to goishc-
/// generated code via the alias-form below.
//     what Go's `func(E) bool` becomes when E is not Copy. A caller
//     whose predicate wants an owned `T` — because it was written
//     against a Go signature that passes by value — needs this one
//     instead. Same walk, same answer.
pub fn IndexFuncOwned<T: Clone, F>(s: &slice<T>, mut pred: F) -> int
where
    F: FnMut(T) -> bool,
{
    for (i, item) in s.iter().enumerate() {
        if pred(item.clone()) {
            return toint(i);
        }
    }
    return -1;
}

// go: sdk 1.25.5 slices/slices.go:239-253 DeleteFunc
/// `DeleteFunc(s, pred)` — returns a slice with every element `e` where
/// `pred(&e)` is true removed.
pub fn DeleteFunc<T, F>(s: slice<T>, mut pred: F) -> slice<T>
where
    F: FnMut(&T) -> bool,
{
    let mut v = s.__into_vec();
    v.retain(|e| !pred(e));
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 slices/slices.go:394-413 CompactFunc
/// `CompactFunc(s, eq)` — removes consecutive elements where `eq(&a, &b)`
/// is true. Sort first to dedupe globally.
pub fn CompactFunc<T, F>(s: slice<T>, mut eq: F) -> slice<T>
where
    F: FnMut(&T, &T) -> bool,
{
    let mut v = s.__into_vec();
    v.dedup_by(|a, b| eq(a, b));
    return slice::__from_vec(v);
}
