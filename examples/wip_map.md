# WIP example — `map<K, V>` + `maps` package

A "wordcount" CLI: reads stdin word-by-word, counts occurrences in a
`map[string]int`, prints sorted by key. Smallest program that exercises:

- `make!(map<K, V>)` — Go's `make(map[K]V)`
- `m.Get(k)` / `m.Set(k, v)` — map read / write
- `m.Keys()` — collect keys as a slice
- `range!(m)` — iterate (k, v) pairs (sorted, since v1 backs with BTreeMap)
- `len(m)` — element count
- `delete!(m, k)` — Go's `delete(m, k)` builtin (we use a macro to keep
  syntax bare)

This file is **not compiled**. It's the design target for the milestone.

---

## Go original

```go
package main

import (
    "bufio"
    "fmt"
    "os"
    "slices"
    "strings"
)

func main() {
    counts := map[string]int{}
    sc := bufio.NewScanner(os.Stdin)
    sc.Split(bufio.ScanWords)
    for sc.Scan() {
        word := strings.ToLower(sc.Text())
        counts[word]++
    }

    keys := make([]string, 0, len(counts))
    for k := range counts {
        keys = append(keys, k)
    }
    slices.Sort(keys)

    for _, k := range keys {
        fmt.Printf("%6d %s\n", counts[k], k)
    }
}
```

## Proposed goish v1 (target shape)

```rust
#![no_std]
#![no_main]

use goish::{
    bufio, len, make, range, slices, string, strings, Printf,
};

#[goish::main]
fn main() {
    let mut counts = make!(map<string, int>);
    let mut sc = bufio::NewScanner(goish::os::Stdin());
    sc.Split(bufio::ScanWords);
    while sc.Scan() {
        let word = strings::ToLower(sc.Text());
        let (n, _) = counts.Get(word.clone());
        counts.Set(word, n + 1);
    }

    let mut keys = counts.Keys();
    slices::Sort!(keys);

    for (_, k) in range!(keys) {
        let (n, _) = counts.Get(k.clone());
        Printf!("%6d %s\n", n, k.clone());
    }
}
```

Run shape:
```
$ printf 'the quick brown fox\nThe lazy dog the\n' | wordcount
     1 brown
     1 dog
     1 fox
     1 lazy
     1 quick
     3 the
```

(Note: `the` and `The` collapse to 3 because we lower-case on read.)

---

## What this needs

### New type

```rust
pub struct map<K: Ord, V> {
    inner: alloc::collections::BTreeMap<K, V>,
}
```

V1 backs with `BTreeMap` from `alloc::collections` — pure Rust, no_std,
uses our dlmalloc allocator. **K: Ord** is the v1 trait bound.
Iteration is sorted by key (a happy accident vs Go's randomized
order — useful for tests).

A v2 milestone may swap the backing to a ported Go-style hashmap (~1500
LOC) for hash-keyed, randomized-iteration semantics. The public API
stays identical so user code is unaffected.

### Methods

```rust
impl<K: Ord + Clone, V: Clone + Default> map<K, V> {
    pub fn Get(&self, k: K) -> (V, bool);   // comma-ok form
    pub fn Has(&self, k: K) -> bool;
    pub fn Set(&mut self, k: K, v: V);
    pub fn Delete(&mut self, k: K);          // also via delete! macro
    pub fn Len(&self) -> int;
    pub fn Keys(&self) -> slice<K>;
    pub fn Values(&self) -> slice<V>;
}

impl<K: Ord, V> Len for map<K, V> { ... }    // len(m) free fn works
```

`Get` returns `(V, bool)` matching Go's comma-ok form. When key is
missing, `V::default()` is returned alongside `false`. `V: Default` is
required for this — fine for `int`, `string`, `slice<T>`, `bool`, etc.

`m[k]` indexing is **not provided** for v1. Go's silent zero-on-missing
is awkward to express in Rust without a Default-clone-on-read shape
that loses type clarity. Use `Get` instead.

### Builtins (macros)

```rust
make!(map<K, V>)            // empty map
make!(map<K, V>, hint)      // hint ignored for BTreeMap; reserved for hashmap port

delete!(m, k)               // m.Delete(k) without leaking &mut at call site
```

### `range!(m)` — iteration

Yields `(&K, &V)` per pair, sorted by K. Mirrors Go's `for k, v := range m`:

```rust
for (k, v) in range!(m) {
    Println!(k, "->", v);
}
```

### `maps` package (`src/maps/mod.rs`)

Match Go 1.21+ surface:

| Go | goish |
|---|---|
| `Keys[M ~map[K]V](m M) iter.Seq[K]` | `pub fn Keys<K, V>(m: &map<K, V>) -> slice<K>` *(slice for v1 — iter package later)* |
| `Values[M ~map[K]V](m M) iter.Seq[V]` | `pub fn Values<K, V>(m: &map<K, V>) -> slice<V>` |
| `Equal[M1, M2 ~map[K]V](m1, m2) bool` | `pub fn Equal<K, V>(m1: &map<K, V>, m2: &map<K, V>) -> bool` |
| `Clone[M ~map[K]V](m M) M` | `pub fn Clone<K, V>(m: &map<K, V>) -> map<K, V>` |
| `Copy[M1, M2 ~map[K]V](dst, src)` | `pub fn Copy<K, V>(dst: &mut map<K, V>, src: &map<K, V>)` |

Defer (need closures or iter.Seq):
- `EqualFunc`, `DeleteFunc`, `Insert`, `Collect`, `All` — when the
  `iter` package or a goish equivalent ships.

### v1 deviations from Go

- **K: Ord required** (BTreeMap backing). Go uses hash-equality; switch
  is silent when we port the runtime hashmap.
- **Iteration is sorted, not randomized.** Go intentionally randomizes
  to discourage relying on order — we expose the BTreeMap order. Tests
  that depend on order remain stable; rely on this only as a v1 detail.
- **No `m[k]` indexing.** Use `m.Get(k)`.
- **No `m[k] = v` syntax.** Use `m.Set(k, v)`.
- **No `m[k]++` shorthand.** Two-step: `let (n, _) = m.Get(k.clone()); m.Set(k, n + 1);`.

---

## Output & verification

```
$ printf 'the quick brown fox\nThe lazy dog the\n' | cargo run --example wordcount
     1 brown
     1 dog
     1 fox
     1 lazy
     1 quick
     3 the

$ printf '' | cargo run --example wordcount
(no output)
```

`examples/map_smoke.rs` covers: empty map, Set/Get/Has, Get on missing
returns (zero, false), Delete, Len, Keys/Values returning sorted slices,
range! iteration, `maps::Equal`, `maps::Clone`, `maps::Copy`.

---

## Confirmation needed

1. **Backing**: BTreeMap (sorted, K: Ord) for v1, port hashmap later? — yes / port-now
2. **`m[k]`**: skip for v1, require `Get`/`Set`? — yes / try-anyway
3. **`delete!(m, k)`** as macro: matches `make!`/`append!`/`copy!` style? — yes / use `m.Delete(k)`

Defaults: yes / yes / yes. Confirm and I'll implement.
