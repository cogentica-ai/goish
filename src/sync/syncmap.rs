// sync::Map — Go's `sync.Map` (slim).
//
// Reference: /share/go/src/sync/map.go.
//
// Slim deviations:
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
//   * `CompareAndSwap` and `CompareAndDelete` not ported — they need
//     `V: PartialEq` to compare the loaded value to the caller's
//     expected old value, and not all V types are PartialEq. Easy to
//     add later as a separate `CompareAndSwap` impl block bound on
//     `V: PartialEq`.

#![allow(non_snake_case)]

extern crate alloc;

use crate::gomap::map as gomap;

use super::mutex::Mutex;

/// `sync.Map` — a thread-safe map keyed by `K`, holding values of `V`.
///
/// Construct with [`Map::new`].
pub struct Map<K, V>
where
    K: Ord + Send + 'static,
    V: Default + Send + Clone + 'static,
{
    inner: Mutex<gomap<K, V>>,
}

impl<K, V> Map<K, V>
where
    K: Ord + Clone + Send + 'static,
    V: Default + Clone + Send + 'static,
{
    /// Construct an empty Map. Mirrors Go's "the zero Map is empty
    /// and ready for use".
    pub fn new() -> Self {
        Map {
            inner: Mutex::new(gomap::new()),
        }
    }

    /// `(*Map).Load(key)` (map.go:127) — read the value for `key`.
    /// Returns `(value, ok)`; on miss, value is the zero V and ok=false.
    pub fn Load(&self, key: K) -> (V, bool) {
        let g = self.inner.Lock();
        g.Get(key)
    }

    /// `(*Map).Store(key, value)` (map.go:161) — write `value` for `key`.
    pub fn Store(&self, key: K, value: V) {
        let mut g = self.inner.Lock();
        g.Set(key, value);
    }

    /// `(*Map).LoadOrStore(key, value)` (map.go:231) — atomically loads
    /// the existing value for `key`, or stores `value` if absent.
    /// Returns `(actual, loaded)`: actual is the value present after
    /// the call; loaded=true if it was already there, false if just
    /// inserted.
    pub fn LoadOrStore(&self, key: K, value: V) -> (V, bool) {
        let mut g = self.inner.Lock();
        let (existing, present) = g.Get(key.clone());
        if present {
            return (existing, true);
        }
        g.Set(key, value.clone());
        (value, false)
    }

    /// `(*Map).LoadAndDelete(key)` (map.go:300) — atomically loads then
    /// deletes the value for `key`. Returns `(value, loaded)`.
    pub fn LoadAndDelete(&self, key: K) -> (V, bool) {
        let mut g = self.inner.Lock();
        let (existing, present) = g.Get(key.clone());
        if present {
            g.Delete(key);
            return (existing, true);
        }
        (V::default(), false)
    }

    /// `(*Map).Delete(key)` (map.go:324) — remove the entry for `key`,
    /// no-op if absent.
    pub fn Delete(&self, key: K) {
        let mut g = self.inner.Lock();
        g.Delete(key);
    }

    /// `(*Map).Swap(key, value)` (map.go:358) — atomically swaps in
    /// `value` for `key`. Returns `(previous, loaded)`: previous is
    /// the old value (or zero V), loaded is whether key was present.
    pub fn Swap(&self, key: K, value: V) -> (V, bool) {
        let mut g = self.inner.Lock();
        let (prev, present) = g.Get(key.clone());
        g.Set(key, value);
        (prev, present)
    }

    /// `(*Map).Clear()` (map.go:166) — delete all entries.
    pub fn Clear(&self) {
        let mut g = self.inner.Lock();
        // Replace with a fresh map. (gomap doesn't expose a clear()
        // helper in goish v1; replacement is functionally equivalent.)
        *g = gomap::new();
    }

    /// `(*Map).Range(f)` (map.go:477) — visit each (key, value); stop
    /// when `f` returns false.
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

impl<K, V> Default for Map<K, V>
where
    K: Ord + Clone + Send + 'static,
    V: Default + Clone + Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}
