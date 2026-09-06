// go: file maps/maps.go decls: Equal, EqualFunc, Clone, Copy, DeleteFunc
// goishlint:ignore GOISH018 clone — Go's `func clone(m any) any` is a
//     bodyless declaration linked to a runtime intrinsic that copies a
//     hmap wholesale. goish's `Clone` builds the new map by iterating,
//     which is what the Go source falls back to describing; there is no
//     runtime hook here to name.
//
// maps — Go's `maps` package: the small functional API over a map.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   ok := maps.Equal(m1, m2)             let ok = maps::Equal(&m1, &m2);
//   c := maps.Clone(m)                   let c = maps::Clone(&m);
//   maps.Copy(dst, src)                  maps::Copy(&mut dst, &src);
//
// The iterator half of the package — Keys, Values, All, Insert,
// Collect — comes from Go's maps/iter.go and lives in `iter.rs`, one
// `.rs` per `.go`.
//
// Deviations:
//   * Go's signatures are generic over `~map[K]V` so any named map type
//     satisfies them; goish takes `&map<K, V>` and `&mut map<K, V>`.
//   * Go's Clone dispatches to the runtime `clone` intrinsic; this
//     iterates.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::gomap::map;

// go: sdk 1.25.5 maps/maps.go:17-27 Equal
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
    return true;
}

// go: sdk 1.25.5 maps/maps.go:50-56 Clone
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
    return out;
}

// go: sdk 1.25.5 maps/maps.go:62-66 Copy
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

// go: sdk 1.25.5 maps/maps.go:31-41 EqualFunc
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
    return true;
}

// go: sdk 1.25.5 maps/maps.go:69-75 DeleteFunc
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

// go: none — goish helper. Go indexes the map directly (`v2, ok :=
// Internal: linear-scan find (BTreeMap doesn't expose a generic-K
// borrowed-key path through our `map<K, V>` wrapper without a
// type-parameter tower). For Equal it's O(n log n); the alternative
// would be re-exposing more of BTreeMap's API.
// m2[k]`); goish's map needs a lookup that borrows, and three of these
// functions want the same one.
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
    return None;
}
