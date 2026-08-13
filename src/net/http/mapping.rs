// go: package net/http
//
// go: file net/http/mapping.go decls: mapping.add, mapping.find, mapping.eachPair
//
// Go: "A mapping is a collection of key-value pairs where the keys are
// unique. A zero mapping is empty and ready to use. A mapping tries to
// pick a representation that makes [mapping.find] most efficient."
//
// The representation switch is the point of the type: below `maxSlice`
// pairs a linear scan of a slice beats a hash lookup, and the routing
// tree has a great many nodes with two or three children. Above it, the
// slice is converted to a map once and never scanned again.
//
// Go's `find` and `eachPair` tolerate a nil receiver. goish stores the
// mapping as a VALUE field on routingNode, never behind a pointer, so
// there is no nil to tolerate — the branch has no reachable caller and
// is not written.
//
// One representation divergence, forced. Go's many-pairs form is
// `m map[K]V` and `add` moves the slice's pairs into it. goish's `map`
// has no mutable value accessor — no `GetMut` — and routingNode.addChild
// needs `&mut V` back for the child it just inserted. So the entries
// always live in `s`, and `m` maps key -> INDEX into `s` once the pair
// count passes maxSlice. Same property the type exists for (linear scan
// while small, hash lookup once large), same observable behaviour from
// find/eachPair, and `&mut` on a value stays expressible.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::gomap::{map, GoHash};
use crate::types::int;

// go: sdk 1.25.5 net/http/mapping.go:15-18 entry
struct entry<K, V> {
    key: K,
    value: V,
}

// go: sdk 1.25.5 net/http/mapping.go:22-22 maxSlice
/// Go: "maxSlice is the maximum number of pairs for which a slice is
/// used. It is a variable for benchmarking."
const maxSlice: int = 8;

// go: sdk 1.25.5 net/http/mapping.go:10-13 mapping
pub struct mapping<K: GoHash + PartialEq + Clone, V> {
    /// Go: "for few pairs" — and, here, for all pairs; see the note.
    s: Vec<entry<K, V>>,
    /// Go: "for many pairs". goish holds an index into `s` rather than
    /// the value.
    m: Option<map<K, int>>,
}

impl<K: GoHash + PartialEq + Clone, V> Default for mapping<K, V> {
    // go: none — goish-only: Go says "a zero mapping is empty and ready
    // to use"; Rust needs that spelled as a Default impl.
    fn default() -> Self {
        // Go: "A zero mapping is empty and ready to use."
        return mapping {
            s: Vec::new(),
            m: None,
        };
    }
}

impl<K: GoHash + PartialEq + Clone, V> mapping<K, V> {
    // go: sdk 1.25.5 net/http/mapping.go:25-38 mapping.add
    /// Go: "add adds a key-value pair to the mapping."
    pub fn add(&mut self, k: K, v: V) {
        if self.m.is_none() && crate::int(self.s.len()) >= maxSlice {
            // Cross the threshold: index everything already stored.
            let mut m: map<K, int> = map::new();
            let mut i: int = 0;
            while i < crate::int(self.s.len()) {
                m.Set(self.s[crate::builtin::__make_size(i)].key.clone(), i);
                i += 1;
            }
            self.m = Some(m);
        }
        if let Some(m) = self.m.as_mut() {
            m.Set(k.clone(), crate::int(self.s.len()));
        }
        self.s.push(entry { key: k, value: v });
    }

    // go: none — goish-only: the index lookup both find and findMut
    // share. Go reads `h.m[k]` directly for the value.
    fn position(&self, k: &K) -> Option<usize> {
        if let Some(m) = self.m.as_ref() {
            let (i, found) = m.Get(k.clone());
            if !found {
                return None;
            }
            return Some(crate::builtin::__make_size(i));
        }
        let mut i: usize = 0;
        while i < self.s.len() {
            if self.s[i].key == *k {
                return Some(i);
            }
            i += 1;
        }
        return None;
    }

    // go: sdk 1.25.5 net/http/mapping.go:43-57 mapping.find
    /// Go: "find returns the value corresponding to the given key. The
    /// second return value is false if there is no value with that
    /// key."
    pub fn find(&self, k: &K) -> (Option<&V>, bool) {
        let i = match self.position(k) {
            Some(i) => i,
            None => return (None, false),
        };
        return (Some(&self.s[i].value), true);
    }

    // go: none — goish-only: Go's addChild does
    // `if c := n.findChild(key); c != nil { return c }` and then
    // inserts, keeping the pointer it found. goish's find hands back a
    // shared reference, so the mutable path needs its own entry point.
    pub fn findMut(&mut self, k: &K) -> Option<&mut V> {
        let i = match self.position(k) {
            Some(i) => i,
            None => return None,
        };
        return Some(&mut self.s[i].value);
    }

    // go: sdk 1.25.5 net/http/mapping.go:61-78 mapping.eachPair
    /// Go: "eachPair calls f for each pair in the mapping. If f returns
    /// false, pairs returns immediately."
    ///
    /// Go iterates the map when it has one, so the order is Go's map
    /// order — unspecified. Iterating `s` is the insertion order, which
    /// is stabler and no caller depends on the difference.
    pub fn eachPair(&self, f: &mut dyn FnMut(&K, &V) -> bool) {
        for e in self.s.iter() {
            if !f(&e.key, &e.value) {
                return;
            }
        }
    }
}
