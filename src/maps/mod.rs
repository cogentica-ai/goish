// maps — Go's `maps` package (Go 1.21+), ported.
//
// Companion to `gomap::map<K, V>`. Provides the small functional API
// that complements method-style access:
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   ks := maps.Keys(m)                   let ks = maps::Keys(&m);
//   vs := maps.Values(m)                 let vs = maps::Values(&m);
//   ok := maps.Equal(m1, m2)             let ok = maps::Equal(&m1, &m2);
//   c := maps.Clone(m)                   let c = maps::Clone(&m);
//   maps.Copy(dst, src)                  maps::Copy(&mut dst, &src);
//
// `Insert`, `Collect` and `All` were deferred here while goish had no
// `iter` package. It has one, and all three are ported — `Insert` and
// `Collect` in `iter.rs`, since they come from Go's `maps/iter.go` and
// a module root ports no file of its own (GOISH015).
//
// In Go 1.21+, `Keys` and `Values` return `iter.Seq[K]`/`iter.Seq[V]`.
// Goish v1 returns `slice<K>`/`slice<V>` directly (BTreeMap-sorted)
// since we don't yet ship an iter package. Functionally equivalent for
// the common patterns: `for (_, k) in range!(maps::Keys(&m)) { ... }`.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

mod iter;
pub use iter::{All, Collect, Insert, Keys, Values};

use crate::gomap::map;

/// `maps.Equal(m1, m2)` — same keys with equal values.
pub fn Equal<K, V>(m1: &map<K, V>, m2: &map<K, V>) -> bool
where
    K: crate::gomap::GoHash + PartialEq,
    V: Default + PartialEq,
{
    let a = m1.__iter();
    if m1.Len() != m2.Len() {
        return false;
    }
    for (k, v1) in a {
        match find_key(m2, k) {
            Some(v2) if v2 == v1 => continue,
            _ => return false,
        }
    }
    true
}

/// `maps.Clone(m)` — deep copy.
pub fn Clone<K, V>(m: &map<K, V>) -> map<K, V>
where
    K: crate::gomap::GoHash + PartialEq + Clone,
    V: Default + Clone,
{
    let mut out: map<K, V> = map::new();
    for (k, v) in m.__iter() {
        out.Set(k.clone(), v.clone());
    }
    out
}

/// `maps.Copy(dst, src)` — overwrite-or-insert each pair from `src`
/// into `dst`. Existing keys in `dst` not in `src` are preserved.
pub fn Copy<K, V>(dst: &mut map<K, V>, src: &map<K, V>)
where
    K: crate::gomap::GoHash + PartialEq + Clone,
    V: Default + Clone,
{
    for (k, v) in src.__iter() {
        dst.Set(k.clone(), v.clone());
    }
}

/// `maps.EqualFunc(m1, m2, eq)` (maps.go:31) — like `Equal` but uses
/// `eq` to compare values. Keys are still compared with byte equality
/// via the underlying `BTreeMap`.
pub fn EqualFunc<K, V1, V2, F>(m1: &map<K, V1>, m2: &map<K, V2>, mut eq: F) -> bool
where
    K: crate::gomap::GoHash + PartialEq,
    V1: Default,
    V2: Default,
    F: FnMut(&V1, &V2) -> bool,
{
    // Go: if len(m1) != len(m2) { return false }
    if m1.Len() != m2.Len() {
        return false;
    }
    // Go: for k, v1 := range m1 { v2, ok := m2[k]; if !ok || !eq(v1, v2) { return false } }
    for (k, v1) in m1.__iter() {
        match find_key(m2, k) {
            Some(v2) if eq(v1, v2) => continue,
            _ => return false,
        }
    }
    true
}

/// `maps.DeleteFunc(m, del)` (maps.go:69) — delete every entry where
/// `del(k, v)` is true. Iteration order is the BTreeMap-sorted order;
/// matching pairs are collected first then removed to avoid mutating
/// while iterating.
pub fn DeleteFunc<K, V, F>(m: &mut map<K, V>, mut del: F)
where
    K: crate::gomap::GoHash + PartialEq + Clone,
    V: Default,
    F: FnMut(&K, &V) -> bool,
{
    // Go: for k, v := range m { if del(k, v) { delete(m, k) } }
    // Slim: collect first to keep BTreeMap iteration stable.
    let mut to_remove: Vec<K> = Vec::new();
    for (k, v) in m.__iter() {
        if del(k, v) {
            to_remove.push(k.clone());
        }
    }
    for k in to_remove {
        m.Delete(k);
    }
}

// Internal: linear-scan find (BTreeMap doesn't expose a generic-K
// borrowed-key path through our `map<K, V>` wrapper without a
// type-parameter tower). For Equal it's O(n log n); the alternative
// would be re-exposing more of BTreeMap's API.
fn find_key<'a, K, V>(m: &'a map<K, V>, key: &K) -> Option<&'a V>
where
    K: crate::gomap::GoHash + PartialEq,
    V: Default,
{
    for (k, v) in m.__iter() {
        if k == key {
            return Some(v);
        }
    }
    None
}
