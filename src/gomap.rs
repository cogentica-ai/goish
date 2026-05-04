// gomap — Go's `map[K]V`, ported with Go-faithful hash-table backing.
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
// **Hash-table implementation** (replacing v1's BTreeMap):
//
//   * Open-addressed buckets with overflow chaining (Go runtime's classic
//     design, not the experimental Swiss tables).
//   * 8 key/elem pairs per bucket (`BUCKET_COUNT = 8`).
//   * Per-map random hash seed (`hash0`) for hash-flooding resistance.
//   * Iteration order is bucket-walk order starting at a random bucket and
//     random intra-bucket offset — matches Go's non-deterministic semantics.
//   * Load-factor growth trigger (~6.5 avg per bucket) and same-size rehash
//     when overflow buckets exceed regular buckets.
//   * Immediate evacuation on growth (v1 simplification; Go does incremental
//     evacuation which requires oldbuckets tracking).
//
// Public-API discipline: lowercase goish types, `impl Into<string>` for
// string params, multi-return tuples.

#![allow(non_camel_case_types)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::ops::{Index, IndexMut};

use crate::builtin::Len as LenTrait;
use crate::goslice::slice;
use crate::gostring::string;
use crate::runtime::rand;
use crate::types::int;

// ═══════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════

/// Maximum key/elem pairs per bucket.
const BUCKET_COUNT: usize = 8;

/// Load-factor numerator   = 13
/// Load-factor denominator   = 2  →  trigger at ~6.5 entries / bucket.
const LOAD_FACTOR_NUM: usize = 13;
const LOAD_FACTOR_DEN: usize = 2;

/// Tophash sentinel: cell is empty and no more non-empty cells follow.
const _EMPTY_REST: u8 = 0;
/// Tophash sentinel: cell is empty (but following cells may be used).
const EMPTY_ONE: u8 = 1;
/// Minimum tophash for a normal filled cell.
const MIN_TOP_HASH: u8 = 5;

// ═══════════════════════════════════════════════════════════════════════
// GoHash — per-type hash function
// ═══════════════════════════════════════════════════════════════════════

/// Trait for types that can be used as map keys. Mirrors Go's built-in
/// map-key requirement (types comparable with `==`).
pub trait GoHash {
    /// Compute a 64-bit hash of `self` mixed with `seed`.
    /// The seed is the per-map `hash0` — each map instance gets a
    /// different seed so hash-flooding attacks are ineffective.
    fn go_hash(&self, seed: u64) -> u64;
}

/// Simple non-cryptographic byte-array hash (FNV-1a style).
#[inline]
pub fn hash_bytes(data: &[u8], seed: u64) -> u64 {
    let mut h = seed;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x010000000001b3);
    }
    h
}

/// Extract the top byte of a 64-bit hash for tophash storage.
#[inline]
fn tophash(hash: u64) -> u8 {
    let mut top = (hash >> 56) as u8;
    if top < MIN_TOP_HASH {
        top += MIN_TOP_HASH;
    }
    top
}

// ─── Implementations for built-in goish types ─────────────────────────

impl GoHash for string {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(self.as_bytes(), seed)
    }
}

impl GoHash for alloc::string::String {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(self.as_bytes(), seed)
    }
}

impl GoHash for int {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(&self.to_le_bytes(), seed)
    }
}

impl GoHash for crate::types::byte {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(&[*self], seed)
    }
}

impl GoHash for crate::types::rune {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(&self.to_le_bytes(), seed)
    }
}

impl GoHash for u64 {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(&self.to_le_bytes(), seed)
    }
}

impl GoHash for u32 {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(&self.to_le_bytes(), seed)
    }
}

impl GoHash for u16 {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(&self.to_le_bytes(), seed)
    }
}

impl GoHash for i8 {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(&[*self as u8], seed)
    }
}

impl GoHash for bool {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(&[*self as u8], seed)
    }
}

impl GoHash for usize {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(&self.to_le_bytes(), seed)
    }
}

impl GoHash for isize {
    fn go_hash(&self, seed: u64) -> u64 {
        hash_bytes(&self.to_le_bytes(), seed)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Bucket
// ═══════════════════════════════════════════════════════════════════════

struct Bucket<K, V> {
    /// Tophash array — one byte per slot.  Values < MIN_TOP_HASH are
    /// reserved sentinel states; >= MIN_TOP_HASH store the top byte of
    /// the key's hash for quick rejection during lookup.
    tophash: [u8; BUCKET_COUNT],
    /// Keys stored in this bucket.  `None` = empty slot.
    keys: [Option<K>; BUCKET_COUNT],
    /// Values stored in this bucket.  `None` = empty slot.
    elems: [Option<V>; BUCKET_COUNT],
    /// Overflow bucket chain — allocated when this bucket is full.
    overflow: Option<Box<Bucket<K, V>>>,
}

impl<K, V> Bucket<K, V> {
    fn new() -> Self {
        Self {
            tophash: [EMPTY_ONE; BUCKET_COUNT],
            keys: core::array::from_fn(|_| None),
            elems: core::array::from_fn(|_| None),
            overflow: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Map struct  (Go: hmap)
// ═══════════════════════════════════════════════════════════════════════

pub struct map<K, V>
where
    K: GoHash + PartialEq,
    V: Default,
{
    /// Number of live entries (Go: hmap.count). Must be first — known by
    /// the compiler for the `len()` builtin.
    count: int,
    /// log₂ of bucket array length.
    b: u8,
    /// Approximate number of overflow buckets.
    noverflow: u16,
    /// Per-map random hash seed (Go: hmap.hash0).
    hash0: u32,
    /// Bucket array — length is `1 << b`.
    buckets: Vec<Box<Bucket<K, V>>>,
    /// Sentinel returned from `Index::index` when key is missing.
    zero: Box<V>,
}

// ═══════════════════════════════════════════════════════════════════════
// Core operations
// ═══════════════════════════════════════════════════════════════════════

impl<K, V> map<K, V>
where
    K: GoHash + PartialEq,
    V: Default,
{
    /// Empty map. Equivalent to `make!(map[K]V)`.
    pub fn new() -> Self {
        Self {
            count: 0,
            b: 0,
            noverflow: 0,
            hash0: rand::cheaprand(),
            buckets: Vec::new(),
            zero: Box::new(V::default()),
        }
    }

    /// `len(m)` — pair count.
    #[allow(non_snake_case)]
    pub fn Len(&self) -> int {
        self.count
    }

    /// `_, ok := m[k]` form — does the key exist?
    #[allow(non_snake_case)]
    pub fn Has(&self, k: K) -> bool {
        if self.count == 0 || self.buckets.is_empty() {
            return false;
        }
        let hash = self.hash(&k);
        let mask = self.bucket_mask();
        let bucket_idx = (hash as usize) & mask;
        let top = tophash(hash);

        let mut bucket = &self.buckets[bucket_idx];
        loop {
            for i in 0..BUCKET_COUNT {
                if bucket.tophash[i] != top {
                    continue;
                }
                if let Some(ref key) = bucket.keys[i] {
                    if key == &k {
                        return true;
                    }
                }
            }
            match &bucket.overflow {
                Some(next) => bucket = next,
                None => return false,
            }
        }
    }

    /// `v, ok := m[k]` — comma-ok form. Returns `(V::default(), false)`
    /// when the key is missing.
    #[allow(non_snake_case)]
    pub fn Get(&self, k: K) -> (V, bool)
    where
        V: Clone,
    {
        if self.count == 0 || self.buckets.is_empty() {
            return (self.zero.as_ref().clone(), false);
        }
        let hash = self.hash(&k);
        let mask = self.bucket_mask();
        let bucket_idx = (hash as usize) & mask;
        let top = tophash(hash);

        let mut bucket = &self.buckets[bucket_idx];
        loop {
            for i in 0..BUCKET_COUNT {
                if bucket.tophash[i] != top {
                    continue;
                }
                if let Some(ref key) = bucket.keys[i] {
                    if key == &k {
                        if let Some(ref val) = bucket.elems[i] {
                            return (val.clone(), true);
                        }
                    }
                }
            }
            match &bucket.overflow {
                Some(next) => bucket = next,
                None => return (self.zero.as_ref().clone(), false),
            }
        }
    }

    /// `m[k] = v` (long form). Use bracket syntax `m[k] = v` for
    /// idiomatic call sites; this method is here for cases where the
    /// receiver is awkward to access via `&mut m[k]`.
    ///
    /// Generic over `Into<K>` / `Into<V>` so callers can pass `&str`
    /// literals against `map<string, …>` without wrapping each key.
    #[allow(non_snake_case)]
    pub fn Set<KI: Into<K>, VI: Into<V>>(&mut self, k: KI, v: VI) {
        let k = k.into();
        let v = v.into();
        if self.buckets.is_empty() {
            self.buckets.push(Box::new(Bucket::new()));
        }
        // Growth check (mirrors Go's mapassign pre-check)
        let count_after = self.count as usize + 1;
        if count_after > BUCKET_COUNT
            && count_after > (LOAD_FACTOR_NUM * (1usize << self.b)) / LOAD_FACTOR_DEN
        {
            self.grow(false);
        } else if self.too_many_overflow_buckets() {
            self.grow(true);
        }
        self.insert_no_grow(k, v);
    }

    /// `delete(m, k)` (long form). Use the `delete!(m, k)` macro at
    /// call sites for the Go-shaped syntax.
    #[allow(non_snake_case)]
    pub fn Delete(&mut self, k: K) {
        if self.count == 0 || self.buckets.is_empty() {
            return;
        }
        let hash = self.hash(&k);
        let mask = self.bucket_mask();
        let bucket_idx = (hash as usize) & mask;
        let top = tophash(hash);

        let bucket = &mut self.buckets[bucket_idx];
        Self::delete_from_bucket(bucket, top, &k, &mut self.count);
    }

    /// All keys, in bucket-walk order (Go's randomized iteration order).
    #[allow(non_snake_case)]
    pub fn Keys(&self) -> slice<K>
    where
        K: Clone,
    {
        let mut v: Vec<K> = Vec::with_capacity(self.count as usize);
        for (k, _) in self.__iter() {
            v.push(k.clone());
        }
        slice::__from_vec(v)
    }

    /// All values, in bucket-walk order.
    #[allow(non_snake_case)]
    pub fn Values(&self) -> slice<V>
    where
        V: Clone,
    {
        let mut v: Vec<V> = Vec::with_capacity(self.count as usize);
        for (_, val) in self.__iter() {
            v.push(val.clone());
        }
        slice::__from_vec(v)
    }

    /// Hidden hook used by `maps::Equal`, `maps::Copy`, `maps::Clone`
    /// to walk pairs without exposing implementation details.
    #[doc(hidden)]
    pub fn __iter(&self) -> MapRefIter<K, V> {
        MapRefIter::new(self)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════════════════

impl<K, V> map<K, V>
where
    K: GoHash + PartialEq,
    V: Default,
{
    #[inline]
    fn hash(&self, k: &K) -> u64 {
        k.go_hash(self.hash0 as u64)
    }

    #[inline]
    fn bucket_mask(&self) -> usize {
        if self.b == 0 {
            0
        } else {
            (1usize << self.b) - 1
        }
    }

    #[inline]
    fn too_many_overflow_buckets(&self) -> bool {
        let limit = if self.b > 15 { 15 } else { self.b };
        self.noverflow >= (1u16 << limit)
    }

    /// Immediate growth: allocate a new bucket array and re-insert all
    /// entries.  Go does this incrementally (evacuate); goish v1 does it
    /// all at once for simplicity.
    fn grow(&mut self, same_size: bool) {
        let old_buckets = core::mem::take(&mut self.buckets);

        if same_size {
            // Same number of buckets, just rehash to collapse overflow chains
            let n = 1usize << self.b;
            self.buckets.reserve(n);
            for _ in 0..n {
                self.buckets.push(Box::new(Bucket::new()));
            }
        } else {
            // Double bucket count
            self.b += 1;
            let n = 1usize << self.b;
            self.buckets.reserve(n);
            for _ in 0..n {
                self.buckets.push(Box::new(Bucket::new()));
            }
        }
        self.noverflow = 0;
        self.count = 0;

        // Re-insert every live entry
        for mut bucket in old_buckets {
            for i in 0..BUCKET_COUNT {
                if let (Some(k), Some(v)) = (bucket.keys[i].take(), bucket.elems[i].take()) {
                    self.insert_no_grow(k, v);
                }
            }
            let mut overflow = bucket.overflow.take();
            while let Some(mut ovf) = overflow {
                for i in 0..BUCKET_COUNT {
                    if let (Some(k), Some(v)) = (ovf.keys[i].take(), ovf.elems[i].take()) {
                        self.insert_no_grow(k, v);
                    }
                }
                overflow = ovf.overflow.take();
            }
        }
    }

    /// Insert a key/value pair assuming there is capacity (no growth).
    ///
    /// Single-pass: tracks the first empty slot while scanning for the
    /// existing key. If the key is found first, its value is updated. If
    /// the key is not found, the first empty slot is used (or a new
    /// overflow bucket is appended). This prevents duplicate-key insertion
    /// when a deleted slot appears before the existing key in the chain.
    fn insert_no_grow(&mut self, key: K, value: V) {
        let hash = self.hash(&key);
        let mask = self.bucket_mask();
        let bucket_idx = (hash as usize) & mask;
        let top = tophash(hash);

        // first_empty_ptr/slot: first empty slot across the entire chain.
        let mut first_empty_ptr: *mut Bucket<K, V> = core::ptr::null_mut();
        let mut first_empty_slot: usize = 0;
        let mut bucket_ptr: *mut Bucket<K, V> = &mut *self.buckets[bucket_idx];

        'search: loop {
            let b = unsafe { &mut *bucket_ptr };
            for i in 0..BUCKET_COUNT {
                if b.tophash[i] == top {
                    if let Some(ref k) = b.keys[i] {
                        if k == &key {
                            b.elems[i] = Some(value);
                            return; // existing key updated — count unchanged
                        }
                    }
                }
                if b.tophash[i] < MIN_TOP_HASH && first_empty_ptr.is_null() {
                    first_empty_ptr = bucket_ptr;
                    first_empty_slot = i;
                }
            }
            match b.overflow.as_mut() {
                Some(ovf) => bucket_ptr = ovf.as_mut(),
                None => break 'search,
            }
        }

        // Key not found. Insert at first empty slot, or append overflow.
        if !first_empty_ptr.is_null() {
            let ib = unsafe { &mut *first_empty_ptr };
            ib.tophash[first_empty_slot] = top;
            ib.keys[first_empty_slot] = Some(key);
            ib.elems[first_empty_slot] = Some(value);
        } else {
            // Every slot in the chain is occupied; append to last bucket.
            let last = unsafe { &mut *bucket_ptr };
            last.overflow = Some(Box::new(Bucket::new()));
            self.noverflow += 1;
            let ovf = last.overflow.as_mut().unwrap();
            ovf.tophash[0] = top;
            ovf.keys[0] = Some(key);
            ovf.elems[0] = Some(value);
        }
        self.count += 1;
    }

    /// Delete a key from a bucket chain.
    fn delete_from_bucket(bucket: &mut Bucket<K, V>, top: u8, key: &K, count: &mut int) {
        for i in 0..BUCKET_COUNT {
            if bucket.tophash[i] != top {
                continue;
            }
            if let Some(ref k) = bucket.keys[i] {
                if k == key {
                    bucket.tophash[i] = EMPTY_ONE;
                    bucket.keys[i] = None;
                    bucket.elems[i] = None;
                    *count -= 1;
                    return;
                }
            }
        }
        if let Some(next) = bucket.overflow.as_mut() {
            Self::delete_from_bucket(next, top, key, count);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Index / IndexMut
// ═══════════════════════════════════════════════════════════════════════

impl<K, V> Index<K> for map<K, V>
where
    K: GoHash + PartialEq,
    V: Default,
{
    type Output = V;
    fn index(&self, key: K) -> &V {
        if self.count == 0 || self.buckets.is_empty() {
            return self.zero.as_ref();
        }
        let hash = self.hash(&key);
        let mask = self.bucket_mask();
        let bucket_idx = (hash as usize) & mask;
        let top = tophash(hash);

        let mut bucket = &self.buckets[bucket_idx];
        loop {
            for i in 0..BUCKET_COUNT {
                if bucket.tophash[i] != top {
                    continue;
                }
                if let Some(ref k) = bucket.keys[i] {
                    if k == &key {
                        return bucket.elems[i].as_ref().unwrap();
                    }
                }
            }
            match &bucket.overflow {
                Some(next) => bucket = next,
                None => return self.zero.as_ref(),
            }
        }
    }
}

impl<K, V> IndexMut<K> for map<K, V>
where
    K: GoHash + PartialEq + Clone,
    V: Default,
{
    fn index_mut(&mut self, key: K) -> &mut V {
        if self.buckets.is_empty() {
            self.buckets.push(Box::new(Bucket::new()));
        }
        // Pre-grow if necessary so the returned reference stays valid
        let count_after = self.count as usize + 1;
        if count_after > BUCKET_COUNT
            && count_after > (LOAD_FACTOR_NUM * (1usize << self.b)) / LOAD_FACTOR_DEN
        {
            self.grow(false);
        } else if self.too_many_overflow_buckets() {
            self.grow(true);
        }

        let hash = self.hash(&key);
        let mask = self.bucket_mask();
        let bucket_idx = (hash as usize) & mask;
        let top = tophash(hash);

        // Same two-position single-pass as insert_no_grow.
        let mut first_empty_ptr: *mut Bucket<K, V> = core::ptr::null_mut();
        let mut first_empty_slot: usize = 0;
        let mut bucket_ptr: *mut Bucket<K, V> = &mut *self.buckets[bucket_idx];

        'search: loop {
            let b = unsafe { &mut *bucket_ptr };
            for i in 0..BUCKET_COUNT {
                if b.tophash[i] == top {
                    if let Some(ref k) = b.keys[i] {
                        if k == &key {
                            return b.elems[i].as_mut().unwrap();
                        }
                    }
                }
                if b.tophash[i] < MIN_TOP_HASH && first_empty_ptr.is_null() {
                    first_empty_ptr = bucket_ptr;
                    first_empty_slot = i;
                }
            }
            match b.overflow.as_mut() {
                Some(ovf) => bucket_ptr = ovf.as_mut(),
                None => break 'search,
            }
        }

        // Key not found — insert at first empty slot or append overflow.
        if !first_empty_ptr.is_null() {
            let ib = unsafe { &mut *first_empty_ptr };
            ib.tophash[first_empty_slot] = top;
            ib.keys[first_empty_slot] = Some(key);
            ib.elems[first_empty_slot] = Some(V::default());
            self.count += 1;
            return unsafe { (*first_empty_ptr).elems[first_empty_slot].as_mut().unwrap() };
        }
        let last = unsafe { &mut *bucket_ptr };
        last.overflow = Some(Box::new(Bucket::new()));
        self.noverflow += 1;
        let ovf = last.overflow.as_mut().unwrap();
        ovf.tophash[0] = top;
        ovf.keys[0] = Some(key);
        ovf.elems[0] = Some(V::default());
        self.count += 1;
        ovf.elems[0].as_mut().unwrap()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// &str convenience — lets `m["key"]` work when K = string
// ═══════════════════════════════════════════════════════════════════════

/// `m["literal"]` read for `map<string, V>` — converts `&str` to `string`
/// then delegates to `Index<string>`. Mirrors Go's implicit string coercion.
impl<V: Default> Index<&str> for map<string, V> {
    type Output = V;
    #[inline]
    fn index(&self, key: &str) -> &V {
        self.index(string::from(key))
    }
}

/// `m["literal"] = v` for `map<string, V>`.
impl<V: Default> IndexMut<&str> for map<string, V> {
    #[inline]
    fn index_mut(&mut self, key: &str) -> &mut V {
        self.index_mut(string::from(key))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Reference iterator (bucket-walk order, Go-randomized start)
// ═══════════════════════════════════════════════════════════════════════

/// Iterator yielding `(&K, &V)` in Go's bucket-walk order.
/// Snapshot semantics: reads the bucket array as it exists at creation
/// time.  Does not reflect subsequent mutations.
pub struct MapRefIter<'a, K, V> {
    buckets: &'a [Box<Bucket<K, V>>],
    /// Index of the bucket currently being walked.
    bucket: usize,
    /// Current overflow bucket in the chain, if any.
    overflow: Option<&'a Bucket<K, V>>,
    /// Current slot index (0..BUCKET_COUNT) within the bucket.
    slot: usize,
    /// Starting bucket (random).
    start_bucket: usize,
    /// Starting slot offset (random).
    offset: usize,
    /// How many buckets have been started.
    visited_buckets: usize,
    /// Total number of buckets in the array.
    total_buckets: usize,
    /// How many entries have been yielded so far.
    yielded: usize,
    /// Total live entries expected.
    total: usize,
}

impl<'a, K, V> MapRefIter<'a, K, V>
where
    K: GoHash + PartialEq,
    V: Default,
{
    fn new(m: &'a map<K, V>) -> Self {
        let total_buckets = m.buckets.len();
        let start_bucket = if total_buckets > 0 {
            (rand::cheaprand() as usize) % total_buckets
        } else {
            0
        };
        let offset = (rand::cheaprand() as usize) % BUCKET_COUNT;
        Self {
            buckets: &m.buckets,
            bucket: start_bucket,
            overflow: None,
            slot: 0,
            start_bucket,
            offset,
            visited_buckets: 0,
            total_buckets,
            yielded: 0,
            total: m.count as usize,
        }
    }
}

impl<'a, K, V> Iterator for MapRefIter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        if self.yielded >= self.total {
            return None;
        }
        loop {
            let b = if let Some(ovf) = self.overflow {
                // Continuing an overflow bucket from a prior yield.
                ovf
            } else if self.slot > 0 {
                // Resuming a main bucket mid-scan after a prior yield.
                &self.buckets[self.bucket]
            } else {
                // Advance to the next main bucket (slot==0 means exhausted or fresh start).
                if self.visited_buckets >= self.total_buckets {
                    return None;
                }
                self.bucket = (self.start_bucket + self.visited_buckets) % self.total_buckets;
                self.visited_buckets += 1;
                &self.buckets[self.bucket]
            };

            while self.slot < BUCKET_COUNT {
                let idx = (self.slot + self.offset) % BUCKET_COUNT;
                self.slot += 1;
                if let (Some(ref k), Some(ref v)) = (&b.keys[idx], &b.elems[idx]) {
                    self.yielded += 1;
                    return Some((k, v));
                }
            }

            // Move to overflow or next bucket
            self.slot = 0;
            if let Some(ref next) = b.overflow {
                self.overflow = Some(next);
            } else {
                self.overflow = None;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Nil support
// ═══════════════════════════════════════════════════════════════════════

impl<K, V> From<crate::nilval::Nil> for map<K, V>
where
    K: GoHash + PartialEq,
    V: Default,
{
    #[inline]
    fn from(_: crate::nilval::Nil) -> Self {
        Self::new()
    }
}

impl<K, V> PartialEq<crate::nilval::Nil> for map<K, V>
where
    K: GoHash + PartialEq,
    V: Default,
{
    #[inline]
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.count == 0
    }
}

impl<K, V> PartialEq<map<K, V>> for crate::nilval::Nil
where
    K: GoHash + PartialEq,
    V: Default,
{
    #[inline]
    fn eq(&self, other: &map<K, V>) -> bool {
        other.count == 0
    }
}

// ═══════════════════════════════════════════════════════════════════════
// LenTrait
// ═══════════════════════════════════════════════════════════════════════

impl<K, V> LenTrait for map<K, V>
where
    K: GoHash + PartialEq,
    V: Default,
{
    #[inline]
    fn __len(&self) -> int {
        self.count
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Clone
// ═══════════════════════════════════════════════════════════════════════

impl<K, V> Clone for map<K, V>
where
    K: GoHash + PartialEq + Clone,
    V: Default + Clone,
{
    fn clone(&self) -> Self {
        let mut out = Self::new();
        for (k, v) in self.__iter() {
            out.Set(k.clone(), v.clone());
        }
        out
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Default
// ═══════════════════════════════════════════════════════════════════════

impl<K, V> Default for map<K, V>
where
    K: GoHash + PartialEq,
    V: Default,
{
    fn default() -> Self {
        Self::new()
    }
}
