# WIP example — M12 `slices` package

A "uniq_sort" CLI: reads command-line args, parses each as int with
`strconv.Atoi`, sorts them, removes adjacent duplicates with
`slices.Compact`, and prints each value on its own line. Exercises the
high-traffic shape:

- `slices.Sort(xs)` — pdqsort over an `Ord` element type
- `slices.Compact(xs)` — adjacent-duplicate removal
- (Plus M10 `range!` and M11a `strconv.Atoi`/`Itoa`.)

This file is **not compiled**. It's the design target for M12.

---

## Go original

```go
package main

import (
    "fmt"
    "os"
    "slices"
    "strconv"
)

func main() {
    nums := make([]int, 0, len(os.Args)-1)
    for i, arg := range os.Args[1:] {
        n, err := strconv.Atoi(arg)
        if err != nil {
            fmt.Fprintf(os.Stderr, "arg %d: %v\n", i, err)
            os.Exit(1)
        }
        nums = append(nums, n)
    }
    slices.Sort(nums)
    nums = slices.Compact(nums)
    for _, n := range nums {
        fmt.Println(n)
    }
}
```

## Proposed goish v1 (target shape)

```rust
#![no_std]
#![no_main]

use goish::{int, len, make, nil, os, range, slices, strconv, Fprintf, Println};

#[goish::main]
fn main() {
    let all = os::Args();
    let args = all.slice(1, len(&all));
    let mut errf = os::Stderr();

    let mut nums = make!([]int, 0, len(&args));
    for (i, arg) in range!(args) {
        let (n, err) = strconv::Atoi(arg.clone());
        if err != nil {
            Fprintf!(errf, "arg %d: %v\n", i, err);
            os::Exit(1);
        }
        nums = append!(nums, n);
    }
    slices::Sort(&mut nums);
    let nums = slices::Compact(nums);
    for (_, n) in range!(nums) {
        Println!(*n);
    }
}
```

Run shape:
```
$ uniq_sort 3 1 4 1 5 9 2 6 5 3 5
1
2
3
4
5
6
9
```

---

## What this needs from M12

### Public functions (Go signatures)

For every function, an `&slice<T>` parameter is by-shared-reference (Go's
default for slice-arg) and an `&mut slice<T>` parameter is for in-place
mutation. Functions that conceptually return a possibly-shorter slice
take `slice<T>` by value and return it (no shared backing in v1).

| Go signature | goish proposed |
|---|---|
| `Sort[E cmp.Ordered](x []E)` | `pub fn Sort<T: Ord>(s: &mut slice<T>)` |
| `IsSorted[E cmp.Ordered](x []E) bool` | `pub fn IsSorted<T: Ord>(s: &slice<T>) -> bool` |
| `Reverse[E any](s []E)` | `pub fn Reverse<T>(s: &mut slice<T>)` |
| `Min[E cmp.Ordered](x []E) E` | `pub fn Min<T: Ord + Clone>(s: &slice<T>) -> T` (panics on empty, like Go) |
| `Max[E cmp.Ordered](x []E) E` | `pub fn Max<T: Ord + Clone>(s: &slice<T>) -> T` (panics on empty) |
| `BinarySearch[E cmp.Ordered](x []E, target E) (int, bool)` | `pub fn BinarySearch<T: Ord>(s: &slice<T>, target: &T) -> (int, bool)` |
| `Equal[E comparable](s1, s2 []E) bool` | `pub fn Equal<T: PartialEq>(s1: &slice<T>, s2: &slice<T>) -> bool` |
| `Compare[E cmp.Ordered](s1, s2 []E) int` | `pub fn Compare<T: Ord>(s1: &slice<T>, s2: &slice<T>) -> int` |
| `Index[E comparable](s []E, v E) int` | `pub fn Index<T: PartialEq>(s: &slice<T>, v: &T) -> int` |
| `Contains[E comparable](s []E, v E) bool` | `pub fn Contains<T: PartialEq>(s: &slice<T>, v: &T) -> bool` |
| `Compact[E comparable](s []E) []E` | `pub fn Compact<T: PartialEq>(s: slice<T>) -> slice<T>` |
| `Concat[E any](slices ...[]E) []E` | `pub fn Concat<T: Clone>(parts: &[&slice<T>]) -> slice<T>` |
| `Delete[E any](s []E, i, j int) []E` | `pub fn Delete<T>(s: slice<T>, i: int, j: int) -> slice<T>` |
| `Clone[E any](s []E) []E` | `pub fn Clone<T: Clone>(s: &slice<T>) -> slice<T>` (Go-shape free fn) |

### Skip for M12 launch (defer)

- **Closure variants** (`SortFunc`, `IndexFunc`, `ContainsFunc`,
  `DeleteFunc`, `CompactFunc`, `EqualFunc`, `CompareFunc`, `MinFunc`,
  `MaxFunc`, `BinarySearchFunc`, `IsSortedFunc`, `SortStableFunc`) — all
  need first-class function values; user-side `Box<dyn Fn>` story ships
  with M14+ (sync) where we cross goroutine boundaries.
- **Iter-based** (`All`, `Backward`, `Values`, `Sorted`, `SortedFunc`,
  `Chunk`, `AppendSeq`, `Collect`) — need an `iter` package, defer.
- **Insert / Replace** (variadic) — Rust macros could do it but the
  shape is awkward. Defer until we have a clear use case.
- **Grow / Clip** — capacity tuning; uncommon in idiomatic code.
- **Repeat** — small; can add easily later.

### Implementation notes

- **Sort**: defer to Rust's `[T]::sort_unstable()` (pdqsort, same
  algorithm Go uses since 1.21). Accessible via our `DerefMut<Target=[T]>`
  on `slice<T>`. Saves ~250 LOC of port; documented in code.
- **Compact**: in-place dedupe of *adjacent* equal elements (so user is
  expected to `Sort` first for full dedupe). Same Go semantic. Returns
  the slice truncated to the unique-prefix length.
- **Min/Max** panic on empty input — matches Go 1.21+ behaviour.
- **BinarySearch**: returns `(idx, found)`. `idx` is the insertion
  point when not found (Go-faithful).

---

## Output & verification

Once M12 ships, the example runs as:

```
$ cargo run --example uniq_sort -- 3 1 4 1 5 9 2 6 5 3 5
1
2
3
4
5
6
9
```

Plus `examples/slices_lib_smoke.rs` with assertions for: Sort + IsSorted,
Reverse round-trip, Min/Max, BinarySearch hit + miss, Equal/Compare on
strings, Index/Contains, Compact, Concat, Delete, Clone.

---

## Confirmation needed

1. **Scope**: 14-function set above (no closures, no iter, no Insert /
   Replace). yes / expand / shrink?
2. **`Sort` signature**: `&mut slice<T>` (Rust-explicit) — ok? Or do we
   bend toward Go's `slice<T>` by value with a return?
3. **Algorithm**: lean on Rust's `[T]::sort_unstable()` (already
   pdqsort) rather than porting Go's pdqsortOrdered. ok?

Defaults: 14-function set / `&mut` / lean on Rust's sort. Confirm and I'll
implement `src/slices/mod.rs` + `examples/uniq_sort.rs` +
`examples/slices_lib_smoke.rs`.
