// go: file maps/iter.go decls: All, Keys, Values, Insert, Collect
//
// The iterator half of Go's `maps`: everything Go declares in
// maps/iter.go. `Keys`, `Values` and `All` were written into the module
// root before `iter.rs` existed; they belong here, one `.rs` per `.go`,
// and mod.rs re-exports them so no caller notices the move.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::gomap::map;

// go: sdk 1.25.5 maps/iter.go:50-54 Insert
/// `maps.Insert(m, seq)` — add every pair the sequence yields to `m`,
/// overwriting a key that is already present.
pub fn Insert<K, V, S>(m: &mut map<K, V>, seq: S)
where
    K: crate::gomap::GoHash + PartialEq + Clone + Send + Sync + 'static,
    V: Clone + Default + Send + Sync + 'static,
    S: crate::iter::Seq2<K, V>,
{
    // Go: for k, v := range seq { m[k] = v }
    seq.run(&mut |k: K, v: V| {
        m.Set(k, v);
        return true;
    });
}

// go: sdk 1.25.5 maps/iter.go:58-62 Collect
/// `maps.Collect(seq)` — a new map holding every pair the sequence
/// yields.
pub fn Collect<K, V, S>(seq: S) -> map<K, V>
where
    K: crate::gomap::GoHash + PartialEq + Clone + Send + Sync + 'static,
    V: Clone + Default + Send + Sync + 'static,
    S: crate::iter::Seq2<K, V>,
{
    // Go: m := make(map[K]V); Insert(m, seq); return m
    let mut m: map<K, V> = map::new();
    Insert(&mut m, seq);
    return m;
}

// go: sdk 1.25.5 maps/iter.go:25-33 Keys
/// `maps.Keys(m)` (iter.go:Keys, Go 1.23+) — `iter.Seq` over the
/// keys. Consumed via `slices::Collect(maps::Keys(&m))` /
/// `slices::Sorted(maps::Keys(&m))`, exactly like modern Go.
///
/// Goish deviation: the seq iterates a snapshot of the keys taken at
/// call time (Go iterates the live map with undefined interleaving
/// under mutation; a snapshot is the sound analogue).
pub fn Keys<K, V>(m: &map<K, V>) -> impl crate::iter::Seq<K>
where
    K: crate::gomap::GoHash + PartialEq + Clone + Send + Sync + 'static,
{
    let snap: Vec<K> = m.__iter().map(|(k, _)| k.clone()).collect();
    return move |yield_: &mut dyn FnMut(K) -> bool| {
        for k in &snap {
            if !yield_(k.clone()) {
                return;
            }
        }
    };
}
// go: sdk 1.25.5 maps/iter.go:38-46 Values
/// `maps.Values(m)` (iter.go:Values, Go 1.23+) — `iter.Seq` over the
/// values (snapshot semantics; see `Keys`).
pub fn Values<K, V>(m: &map<K, V>) -> impl crate::iter::Seq<V>
where
    K: crate::gomap::GoHash + PartialEq,
    V: Clone + Send + Sync + 'static,
{
    let snap: Vec<V> = m.__iter().map(|(_, v)| v.clone()).collect();
    return move |yield_: &mut dyn FnMut(V) -> bool| {
        for v in &snap {
            if !yield_(v.clone()) {
                return;
            }
        }
    };
}
// go: sdk 1.25.5 maps/iter.go:12-20 All
/// `maps.All(m)` (iter.go:All, Go 1.23+) — `iter.Seq2` over
/// (key, value) pairs (snapshot semantics; see `Keys`).
pub fn All<K, V>(m: &map<K, V>) -> impl crate::iter::Seq2<K, V>
where
    K: crate::gomap::GoHash + PartialEq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    let snap: Vec<(K, V)> = m.__iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    return move |yield_: &mut dyn FnMut(K, V) -> bool| {
        for (k, v) in &snap {
            if !yield_(k.clone(), v.clone()) {
                return;
            }
        }
    };
}
