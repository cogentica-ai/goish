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
// Deferred (need closures or `iter` package):
//   * EqualFunc, DeleteFunc, Insert, Collect, All — when an iter
//     equivalent ships.
//
// In Go 1.21+, `Keys` and `Values` return `iter.Seq[K]`/`iter.Seq[V]`.
// Goish v1 returns `slice<K>`/`slice<V>` directly (BTreeMap-sorted)
// since we don't yet ship an iter package. Functionally equivalent for
// the common patterns: `for (_, k) in range!(maps::Keys(&m)) { ... }`.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::gomap::map;
use crate::goslice::slice;

/// `maps.Keys(m)` — slice of keys, sorted (v1 BTreeMap backing).
pub fn Keys<K, V>(m: &map<K, V>) -> slice<K>
where
    K: Ord + Clone,
    V: Default,
{
    let v: Vec<K> = m.__iter().map(|(k, _)| k.clone()).collect();
    slice::__from_vec(v)
}

/// `maps.Values(m)` — slice of values, in key-sorted order.
pub fn Values<K, V>(m: &map<K, V>) -> slice<V>
where
    K: Ord,
    V: Default + Clone,
{
    let v: Vec<V> = m.__iter().map(|(_, v)| v.clone()).collect();
    slice::__from_vec(v)
}

/// `maps.Equal(m1, m2)` — same keys with equal values.
pub fn Equal<K, V>(m1: &map<K, V>, m2: &map<K, V>) -> bool
where
    K: Ord,
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
    K: Ord + Clone,
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
    K: Ord + Clone,
    V: Default + Clone,
{
    for (k, v) in src.__iter() {
        dst.Set(k.clone(), v.clone());
    }
}

// Internal: linear-scan find (BTreeMap doesn't expose a generic-K
// borrowed-key path through our `map<K, V>` wrapper without a
// type-parameter tower). For Equal it's O(n log n); the alternative
// would be re-exposing more of BTreeMap's API.
fn find_key<'a, K, V>(m: &'a map<K, V>, key: &K) -> Option<&'a V>
where
    K: Ord,
    V: Default,
{
    for (k, v) in m.__iter() {
        if k == key {
            return Some(v);
        }
    }
    None
}
