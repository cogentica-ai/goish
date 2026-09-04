// go: file sync/map.go decls: Map.Load, Map.Store, Map.Clear, Map.LoadOrStore, Map.LoadAndDelete, Map.Delete, Map.Swap, Map.CompareAndSwap, Map.CompareAndDelete, Map.Range
//
// map.go — Go's `sync.Map`.
//
// This file used to carry NO provenance anchors, like every other file
// under src/sync/: `port_coverage sync` reported 28 of its 30 ported
// names as UNVERIFIED, matching Go by name only. These are the
// primitives the rest of the tree is built on, so "matches by name" is
// a thin thing to rest on. This anchors map.go and diffs it against a
// running Go.
//
// goish deviations, all of them design rather than semantics:
//
//   * No `read`/`dirty` two-tier optimization. Go's Map keeps a
//     lock-free read-mostly path that hits the dirty map only on
//     misses; promotion of dirty→read is amortized over many calls.
//     Goish v1 backs the Map with a single `Mutex<gomap<K, V>>`. For
//     HTTP server contexts (per-request scratch maps, request-id →
//     metadata caches), the simpler design is sufficient; the more
//     elaborate scheme can be added later if profiling demands it.
//
//   * No `expunged` sentinel — entries either exist or don't. Go uses
//     expunged to track entries deleted-but-still-in-read; under a
//     single Mutex this is unnecessary.
//
//   * `Map<K, V>` is generic on key/value types rather than `any`.
//     Same generics-vs-interface trade as `sync::Pool`.
//
//   * `CompareAndSwap` and `CompareAndDelete` are ported in a second
//     impl block bound on `V: PartialEq`, which is what this file's
//     earlier note said the fix would be. They need to compare the
//     loaded value to the caller's expected one, and not every `V` a
//     goish Map can hold is comparable — so the two methods exist
//     exactly for the value types that can support them, rather than
//     not at all.

#![allow(non_snake_case)]
// goishlint:ignore GOISH018 loadReadOnly, missLocked, dirtyLocked, newEntry, swapLocked, tryCompareAndSwap, tryExpungeLocked, tryLoadOrStore, tryStore, unexpungeLocked, delete, trySwap, load — every one of these belongs to Go's read/dirty two-tier design: the lock-free read map, the expunged sentinel, and the amortised promotion of dirty to read. This Map is one mutex over one map, which is stated at the top of the file, so there is no second tier for them to operate on.
// goishlint:ignore GOISH021 entry, readOnly, expunged — the three types that design is built from, for the same reason.

extern crate alloc;

use crate::gomap::map as gomap;

use super::mutex::Mutex;

/// `sync.Map` — a thread-safe map keyed by `K`, holding values of `V`.
///
/// Construct with [`Map::new`].
pub struct Map<K, V>
where
    K: crate::gomap::GoHash + PartialEq + Send + 'static,
    V: Default + Send + Clone + 'static,
{
    inner: Mutex<gomap<K, V>>,
}

impl<K, V> Map<K, V>
where
    K: crate::gomap::GoHash + PartialEq + Clone + Send + 'static,
    V: Default + Clone + Send + 'static,
{
    // go: none — goish idiom: Go documents "the zero Map is empty and
    //     ready for use"; a Rust struct holding a Mutex needs a
    //     constructor, so the zero value is spelled `new()`/`default()`.
    /// Construct an empty Map.
    pub fn new() -> Self {
        return Map {
            inner: Mutex::new(gomap::new()),
        };
    }

    // go: sdk 1.25.5 sync/map.go:127-150 Map.Load
    /// Go: "Load returns the value stored in the map for a key, or nil
    /// if no value is present. The ok result indicates whether value
    /// was found in the map."
    pub fn Load(&self, key: K) -> (V, bool) {
        let g = self.inner.Lock();
        return g.Get(key);
    }

    // go: sdk 1.25.5 sync/map.go:161-164 Map.Store
    /// Go: "Store sets the value for a key."
    pub fn Store(&self, key: K, value: V) {
        let mut g = self.inner.Lock();
        g.Set(key, value);
    }

    // go: sdk 1.25.5 sync/map.go:231-264 Map.LoadOrStore
    /// Go: "LoadOrStore returns the existing value for the key if
    /// present. Otherwise, it stores and returns the given value. The
    /// loaded result is true if the value was loaded, false if stored."
    ///
    /// Note `loaded` reports whether it LOADED, not whether it stored —
    /// inverting it still compiles and still behaves on the common
    /// path.
    pub fn LoadOrStore(&self, key: K, value: V) -> (V, bool) {
        let mut g = self.inner.Lock();
        let (existing, present) = g.Get(key.clone());
        if present {
            return (existing, true);
        }
        g.Set(key, value.clone());
        return (value, false);
    }

    // go: sdk 1.25.5 sync/map.go:300-322 Map.LoadAndDelete
    /// Go: "LoadAndDelete deletes the value for a key, returning the
    /// previous value if any. The loaded result reports whether the key
    /// was present."
    pub fn LoadAndDelete(&self, key: K) -> (V, bool) {
        let mut g = self.inner.Lock();
        let (existing, present) = g.Get(key.clone());
        if present {
            g.Delete(key);
            return (existing, true);
        }
        return (V::default(), false);
    }

    // go: sdk 1.25.5 sync/map.go:324-326 Map.Delete
    /// Go: "Delete deletes the value for a key."
    pub fn Delete(&self, key: K) {
        let mut g = self.inner.Lock();
        g.Delete(key);
    }

    // go: sdk 1.25.5 sync/map.go:358-400 Map.Swap
    /// Go: "Swap swaps the value for a key and returns the previous
    /// value if any. The loaded result reports whether the key was
    /// present."
    pub fn Swap(&self, key: K, value: V) -> (V, bool) {
        let mut g = self.inner.Lock();
        let (prev, present) = g.Get(key.clone());
        g.Set(key, value);
        return (prev, present);
    }

    // go: sdk 1.25.5 sync/map.go:166-186 Map.Clear
    /// Go: "Clear deletes all the entries, resulting in an empty Map."
    pub fn Clear(&self) {
        let mut g = self.inner.Lock();
        // Replace with a fresh map. (gomap doesn't expose a clear()
        // helper in goish v1; replacement is functionally equivalent.)
        *g = gomap::new();
    }

    // go: sdk 1.25.5 sync/map.go:477-509 Map.Range
    /// Go: "Range calls f sequentially for each key and value present
    /// in the map. If f returns false, range stops the iteration."
    ///
    /// Slim: snapshots all entries under the Mutex before invoking
    /// `f`, so `f` may safely call back into the Map without
    /// deadlocking. Mirrors Go's documented "Range does not
    /// necessarily correspond to any consistent snapshot of the Map's
    /// contents" relaxation: we provide *a* consistent snapshot, but
    /// concurrent writes during traversal are not observed.
    pub fn Range<F>(&self, mut f: F)
    where
        F: FnMut(K, V) -> bool,
    {
        let snapshot: alloc::vec::Vec<(K, V)> = {
            let g = self.inner.Lock();
            // gomap doesn't expose a public iterator in goish v1;
            // use the internal __iter helper. If unavailable, fall
            // back to per-key Get under the lock.
            g.__iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (k, v) in snapshot {
            if !f(k, v) {
                return;
            }
        }
    }
}

impl<K, V> Map<K, V>
where
    K: crate::gomap::GoHash + PartialEq + Clone + Send + 'static,
    V: Default + Clone + Send + PartialEq + 'static,
{
    // go: sdk 1.25.5 sync/map.go:402-432 Map.CompareAndSwap
    /// Go: "CompareAndSwap swaps the old and new values for key if the
    /// value stored in the map is equal to old. The old value must be
    /// of a comparable type."
    ///
    /// Reports whether it SWAPPED — so a missing key is false, and a
    /// present key whose value does not match is false.
    pub fn CompareAndSwap(&self, key: K, old: V, new: V) -> bool {
        let mut g = self.inner.Lock();
        let (cur, present) = g.Get(key.clone());
        if !present || cur != old {
            return false;
        }
        g.Set(key, new);
        return true;
    }

    // go: sdk 1.25.5 sync/map.go:434-475 Map.CompareAndDelete
    /// Go: "CompareAndDelete deletes the entry for key if its value is
    /// equal to old. … If there is no current value for key in the map,
    /// CompareAndDelete returns false."
    pub fn CompareAndDelete(&self, key: K, old: V) -> bool {
        let mut g = self.inner.Lock();
        let (cur, present) = g.Get(key.clone());
        if !present || cur != old {
            return false;
        }
        g.Delete(key);
        return true;
    }
}

impl<K, V> Default for Map<K, V>
where
    K: crate::gomap::GoHash + PartialEq + Clone + Send + 'static,
    V: Default + Clone + Send + 'static,
{
    // go: none — goish idiom: see the note on `new`; this is the same
    //     zero value Go gets for free.
    fn default() -> Self {
        return Self::new();
    }
}
