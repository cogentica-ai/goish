// go: file crypto/internal/fips140cache/cache.go decls: Cache.Get, Cache.evict
//
// Package fips140cache provides a weak map that associates the lifetime of
// values with the lifetime of keys.
//
// It can be used to associate a precomputed value (such as an
// internal/fips140 PrivateKey value, which in FIPS 140-3 mode may have
// required an expensive pairwise consistency test) with a type that
// doesn't have private fields (such as an ed25519.PrivateKey), or that
// can't be safely modified because it may be concurrently copied (such as
// an ecdsa.PrivateKey).
//
// **This implementation never caches.** Go's map is keyed by
// `weak.Pointer[K]` and evicted by `runtime.AddCleanup` — a weak reference
// and a finalizer, both of which need a garbage collector. goish has no
// GC, and the keys involved (`ecdsa.PrivateKey` and friends) are plain
// values rather than `Arc`s, so there is no handle to weaken.
//
// That is a conforming implementation rather than a stub, and the
// distinction matters: Go documents Get as "**may** return the same value
// it returned from the previous call", and the cache as evicted "some time
// after k becomes unreachable". Recomputing every time satisfies both — it
// forfeits the optimization, not the contract. Every caller already has to
// handle `new` being invoked, because that is what happens on the first
// call and after any `check` failure.
//
// The cost is real and worth naming: in FIPS 140-3 mode each miss re-runs
// a pairwise consistency test. In goish `fips140::Enabled()` is false, so
// today that path is not taken at all.

#![allow(non_snake_case)]

extern crate alloc;
use core::marker::PhantomData;

use crate::error;

// Go: cache.go:21-23
//   type Cache[K, V any] struct { m sync.Map }
/// A weak map associating a precomputed value with the lifetime of a key.
/// See the file comment: the `sync.Map` has no counterpart here because
/// nothing is stored.
pub struct Cache<K, V> {
    _m: PhantomData<(K, V)>,
}

impl<K, V> Cache<K, V> {
    // go: none — Go's zero value is usable; Rust needs a constructor for
    // the PhantomData.
    pub const fn New() -> Self {
        return Cache { _m: PhantomData };
    }

    // go: sdk 1.25.5 crypto/internal/fips140cache/cache.go:25-48 Cache.Get
    /// Return the result of `new`, for an associated key k.
    ///
    /// If Get was called with k before and didn't return an error, Get may
    /// return the same value it returned from the previous call if `check`
    /// returns true on it. If `check` returns false, Get will call `new`
    /// again and return the result.
    ///
    /// This implementation always calls `new`; see the file comment.
    pub fn Get<N, C>(&self, k: &K, new: N, check: C) -> (V, error)
    where
        N: FnOnce() -> (V, error),
        C: Fn(&V) -> bool,
    {
        // Go: p := weak.Make(k); if cached, ok := c.m.Load(p); ok { … }
        //
        // Nothing is stored, so the load always misses and `check` is
        // never consulted. Both are named to keep the signature Go's.
        let _ = k;
        let _ = check;
        // Go: v, err := new(); if err != nil { return nil, err }
        //     if _, present := c.m.Swap(p, v); !present { runtime.AddCleanup(…) }
        //     return v, nil
        return new();
    }

    // go: sdk 1.25.5 crypto/internal/fips140cache/cache.go:50-52 Cache.evict
    ///
    /// Go registers this with `runtime.AddCleanup` to delete the entry once
    /// the key is unreachable. With nothing stored there is nothing to
    /// delete, and with no GC there is nothing to register it with.
    #[allow(dead_code)]
    fn evict(&self, k: &K) {
        let _ = k;
    }
}
