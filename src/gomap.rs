// gomap — Go's `map[K]V`, ported.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   var m map[string]int                 let mut m: map<string, int> = ...
//   m := map[string]int{}                let mut m = make!(map[string]int);
//   m["foo"] = 42                        m["foo"] = 42;
//   v := m["foo"]                        let v = m["foo"];
//   v, ok := m["foo"]                    let (v, ok) = m.Get(string("foo"));
//   m["foo"]++                           m["foo"] += 1;
//   delete(m, "foo")                     delete!(m, string("foo"));
//   len(m)                               len(&m)
//   for k, v := range m                  for (k, v) in range!(m)
//
// v1 backing: `alloc::collections::BTreeMap<K, V>`. Pure Rust, no_std,
// uses our dlmalloc allocator. **K: Ord** is the v1 trait bound. A v2
// upgrade can swap in a ported Go-style hashmap for hash-keyed,
// randomized-iteration semantics; the public API stays identical.
//
// v1 deviations from Go:
//
//   * **K: Ord** (BTreeMap requirement). Iteration is sorted by key —
//     a happy v1 detail vs Go's deliberate randomization. Don't write
//     code that assumes randomized order; we'll port a hashmap later.
//   * **V: Default** is required at the struct level. Needed so
//     `m[k]` (Index) can return a reference to a stored zero on miss
//     (Rust can't fabricate `&V::default()` from thin air without a
//     place to keep it; we keep one zero per map).
//   * **No `m, ok := m[k]` comma-ok via brackets.** Use `m.Get(k)`.
//     Rust's `Index` returns `&V`, not `(V, bool)`, and overloading is
//     not available.
//   * **Non-Copy `V` reads need `.clone()` at the call site:**
//     `let s = m["k"].clone()` (Rust universal Index limitation).

#![allow(non_camel_case_types)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::borrow::Borrow;
use core::ops::{Index, IndexMut};

use crate::builtin::Len as LenTrait;
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::int;

pub struct map<K, V>
where
    K: Ord,
    V: Default,
{
    inner: BTreeMap<K, V>,
    /// Sentinel returned from `Index::index` when key is missing. Built
    /// once per map at construction; never mutated. Boxed so that
    /// `V` may itself transitively contain `map<K, V>` (e.g.,
    /// `json::Value` recursive enum) — a non-Box `V` field would make
    /// the type infinite-sized.
    zero: Box<V>,
}

// Clone implemented manually so the struct's trait bounds stay minimal
// (just `K: Ord`, `V: Default`); cloning additionally requires
// `K: Clone, V: Clone`.
impl<K, V> Clone for map<K, V>
where
    K: Ord + Clone,
    V: Default + Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            zero: self.zero.clone(),
        }
    }
}

impl<K, V> map<K, V>
where
    K: Ord,
    V: Default,
{
    /// Empty map. Equivalent to `make!(map[K]V)`.
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
            zero: Box::new(V::default()),
        }
    }

    /// `len(m)` — pair count.
    #[allow(non_snake_case)]
    pub fn Len(&self) -> int {
        self.inner.len() as int
    }

    /// `_, ok := m[k]` form — does the key exist?
    #[allow(non_snake_case)]
    pub fn Has(&self, k: K) -> bool {
        self.inner.contains_key(&k)
    }

    /// `v, ok := m[k]` — comma-ok form. Returns `(V::default(), false)`
    /// when the key is missing.
    #[allow(non_snake_case)]
    pub fn Get(&self, k: K) -> (V, bool)
    where
        V: Clone,
    {
        match self.inner.get(&k) {
            Some(v) => (v.clone(), true),
            None => (V::default(), false),
        }
    }

    /// `m[k] = v` (long form). Use bracket syntax `m[k] = v` for
    /// idiomatic call sites; this method is here for cases where the
    /// receiver is awkward to access via `&mut m[k]`.
    #[allow(non_snake_case)]
    pub fn Set(&mut self, k: K, v: V) {
        self.inner.insert(k, v);
    }

    /// `delete(m, k)` (long form). Use the `delete!(m, k)` macro at
    /// call sites for the Go-shaped syntax.
    #[allow(non_snake_case)]
    pub fn Delete(&mut self, k: K) {
        self.inner.remove(&k);
    }

    /// All keys, sorted (BTreeMap order).
    #[allow(non_snake_case)]
    pub fn Keys(&self) -> slice<K>
    where
        K: Clone,
    {
        let v: alloc::vec::Vec<K> = self.inner.keys().cloned().collect();
        slice::__from_vec(v)
    }

    /// All values, in key-sorted order.
    #[allow(non_snake_case)]
    pub fn Values(&self) -> slice<V>
    where
        V: Clone,
    {
        let v: alloc::vec::Vec<V> = self.inner.values().cloned().collect();
        slice::__from_vec(v)
    }

    /// Hidden hook used by `maps::Equal` and `maps::Copy` to walk pairs
    /// without exposing the BTreeMap dependency in the public API.
    #[doc(hidden)]
    pub fn __iter(&self) -> alloc::collections::btree_map::Iter<'_, K, V> {
        self.inner.iter()
    }
}

impl<K, V> Default for map<K, V>
where
    K: Ord,
    V: Default,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> LenTrait for map<K, V>
where
    K: Ord,
    V: Default,
{
    #[inline]
    fn __len(&self) -> int {
        self.inner.len() as int
    }
}

// ─── Index / IndexMut — generic by-value form ─────────────────────────

impl<K, V> Index<K> for map<K, V>
where
    K: Ord,
    V: Default,
{
    type Output = V;
    fn index(&self, key: K) -> &V {
        self.inner.get(&key).unwrap_or(&*self.zero)
    }
}

impl<K, V> IndexMut<K> for map<K, V>
where
    K: Ord,
    V: Default,
{
    fn index_mut(&mut self, key: K) -> &mut V {
        self.inner.entry(key).or_insert_with(V::default)
    }
}

// ─── Index<&str> / IndexMut<&str> — string-keyed maps only ────────────
//
// Lets `m["foo"]` work directly without `m[string("foo")]`. The Borrow
// impl on `string` (in gostring.rs) makes the read path zero-allocation;
// the write path allocates a `string` only when inserting a new key.

impl<V> Index<&str> for map<string, V>
where
    V: Default,
{
    type Output = V;
    fn index(&self, key: &str) -> &V {
        let lookup: &[u8] = key.as_bytes();
        // BTreeMap::get takes `&Q where K: Borrow<Q>`. K=string, Q=[u8].
        match (&self.inner as &BTreeMap<string, V>).get(lookup) {
            Some(v) => v,
            None => &*self.zero,
        }
    }
}

impl<V> IndexMut<&str> for map<string, V>
where
    V: Default,
{
    fn index_mut(&mut self, key: &str) -> &mut V {
        let lookup: &[u8] = key.as_bytes();
        if !self.inner.contains_key(lookup) {
            self.inner.insert(string::from(key), V::default());
        }
        self.inner.get_mut(lookup).expect("just inserted")
    }
}

// Borrow lookup for string keys uses byte slices internally (see
// `impl Borrow<[u8]> for string` in gostring.rs). Helper to keep that
// detail out of user code. Currently only used by the &str specializations.
#[doc(hidden)]
pub fn __get_string_keyed<'a, V: Default>(m: &'a map<string, V>, key: &str) -> Option<&'a V> {
    m.inner.get::<[u8]>(key.as_bytes())
}

// Wire `K: Ord` ↔ `Borrow<[u8]>` for the string case. The compiler
// already has `impl Borrow<[u8]> for string`; the use here is just to
// keep the path obvious to readers.
const _: fn() = || {
    fn assert_borrow<T: Borrow<[u8]>>() {}
    assert_borrow::<string>();
};
