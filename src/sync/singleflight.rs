// sync/singleflight — duplicate function-call suppression.
//
// Reference: /share/go/src/internal/singleflight/singleflight.go (123 LOC).
//
// `singleflight.Group` makes sure only one execution is in-flight for
// a given key at a time. Used internally by Go's `net` (DNS resolver
// dedup) and `net/http` (Transport's connection-pool dedup); also
// exported publicly as `golang.org/x/sync/singleflight`.
//
// Slim deviations from Go (documented):
//
//   * `Group<V>` is generic over the value type `V` rather than `any`.
//     Goish has static dispatch — same trade as `sync::Pool` / `sync::Map`.
//
//   * Internal map is a Rust `BTreeMap<string, Arc<Call<V>>>` (not a
//     goish `gomap<K, V>`). Reason: `gomap` requires `V: Default`, but
//     `Arc<Call<V>>` does not implement `Default` without forcing a
//     default constraint onto user-supplied `V`. The public API is
//     unaffected — `Group::Do(key: string, fn) -> (V, error, bool)`.
//
//   * `Call.val any / err error / dups int / chans []chan<- Result` are
//     re-grouped: `wg`/`out`/`dups`/`chans` live on `Call<V>` directly.
//     `out` is `Mutex<Option<(V, error)>>` (filled by worker before
//     `wg.Done()`; read by waiters after `wg.Wait()`); `dups` is
//     `AtomicI64` (replaces Go's group-mu-protected int). The
//     observable behaviour matches Go.
//
//   * `DoChan` returns a goish `chan<Result<V>>` (buffered cap=1, just
//     like Go).
//
//   * `Do` runs `fn` in the calling goroutine (synchronous, like Go).
//     `DoChan` spawns a goroutine via `go!()` and posts the `Result`
//     to the returned channel.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, Ordering};

use crate::errors::{error, nil};
use crate::go;
use crate::gochan::chan;
use crate::gostring::string;

use super::mutex::Mutex;
use super::waitgroup::WaitGroup;

// Go: singleflight.go:36
//   type Result struct {
//       Val    any
//       Err    error
//       Shared bool
//   }
/// `singleflight.Result` — payload posted on the channel returned by
/// [`Group::DoChan`].
pub struct Result<V> {
    pub Val: V,
    pub Err: error,
    pub Shared: bool,
}

impl<V: Default> Default for Result<V> {
    fn default() -> Self {
        Result {
            Val: V::default(),
            Err: nil.clone(),
            Shared: false,
        }
    }
}

// Go: singleflight.go:12
//   type call struct {
//       wg sync.WaitGroup
//       val any
//       err error
//       dups  int
//       chans []chan<- Result
//   }
struct Call<V: Clone + Default + Send + 'static> {
    wg: WaitGroup,
    // Go: val any / err error.
    //   Written once by the worker before `wg.Done()`; read by all
    //   waiters after `wg.Wait()`. Sit under a Mutex<Option<>> so that
    //   the unsafe-pre/post-WG ordering doesn't escape into UnsafeCell.
    out: Mutex<Option<(V, error)>>,
    // Go: dups int — number of duplicate callers.
    dups: AtomicI64,
    // Go: chans []chan<- Result.
    chans: Mutex<Vec<chan<Result<V>>>>,
}

impl<V: Clone + Default + Send + 'static> Call<V> {
    fn new() -> Self {
        Call {
            wg: WaitGroup::new(),
            out: Mutex::new(None),
            dups: AtomicI64::new(0),
            chans: Mutex::new(Vec::new()),
        }
    }
}

struct GroupState<V: Clone + Default + Send + 'static> {
    // Go: m map[string]*call — lazily initialized.
    //   In goish, BTreeMap; lazy-init via Option<>.
    m: Option<BTreeMap<string, Arc<Call<V>>>>,
}

// Go: singleflight.go:29
//   type Group struct {
//       mu sync.Mutex       // protects m
//       m  map[string]*call // lazily initialized
//   }
/// `singleflight.Group` — a class of work in which only one execution
/// is in-flight per key at a time.
///
/// Generic over the value type `V` returned by the supplied function.
/// Construct with [`Group::new`].
pub struct Group<V: Clone + Default + Send + 'static> {
    state: Mutex<GroupState<V>>,
}

impl<V: Clone + Default + Send + 'static> Group<V> {
    /// Build an empty Group.
    pub fn new() -> Self {
        Group {
            state: Mutex::new(GroupState { m: None }),
        }
    }

    // Go: singleflight.go:47
    //   func (g *Group) Do(key string, fn func() (any, error)) (v any, err error, shared bool) {
    //       g.mu.Lock()
    //       if g.m == nil { g.m = make(map[string]*call) }
    //       if c, ok := g.m[key]; ok {
    //           c.dups++
    //           g.mu.Unlock()
    //           c.wg.Wait()
    //           return c.val, c.err, true
    //       }
    //       c := new(call)
    //       c.wg.Add(1)
    //       g.m[key] = c
    //       g.mu.Unlock()
    //       g.doCall(c, key, fn)
    //       return c.val, c.err, c.dups > 0
    //   }
    /// `Do` executes and returns the results of `fn`, ensuring that only
    /// one execution is in-flight for a given `key` at a time. If a
    /// duplicate caller arrives mid-flight, it waits for the in-flight
    /// call to complete and receives the same results. The `shared`
    /// boolean indicates whether `v` was given to multiple callers.
    pub fn Do<F>(&self, key: string, fn_: F) -> (V, error, bool)
    where
        F: FnOnce() -> (V, error),
    {
        // Go: g.mu.Lock(); if g.m == nil { g.m = make(...) }
        let mut s = self.state.Lock();
        if s.m.is_none() {
            s.m = Some(BTreeMap::new());
        }
        // Go: if c, ok := g.m[key]; ok { c.dups++; g.mu.Unlock(); c.wg.Wait(); return c.val, c.err, true }
        if let Some(c) = s.m.as_ref().unwrap().get(&key).cloned() {
            c.dups.fetch_add(1, Ordering::AcqRel);
            drop(s);
            c.wg.Wait();
            let out = c.out.Lock();
            let (v, e) = out.as_ref().expect("singleflight: result missing").clone();
            return (v, e, true);
        }
        // Go: c := new(call); c.wg.Add(1); g.m[key] = c; g.mu.Unlock()
        let c = Arc::new(Call::<V>::new());
        c.wg.Add(1);
        s.m.as_mut().unwrap().insert(key.clone(), c.clone());
        drop(s);

        // Go: g.doCall(c, key, fn)
        self.doCall(c.clone(), key, move || fn_());

        // Go: return c.val, c.err, c.dups > 0
        let out = c.out.Lock();
        let (v, e) = out.as_ref().expect("singleflight: result missing").clone();
        let shared = c.dups.load(Ordering::Acquire) > 0;
        (v, e, shared)
    }

    // Go: singleflight.go:69
    //   func (g *Group) DoChan(key string, fn func() (any, error)) <-chan Result {
    //       ch := make(chan Result, 1)
    //       g.mu.Lock()
    //       if g.m == nil { g.m = make(map[string]*call) }
    //       if c, ok := g.m[key]; ok {
    //           c.dups++
    //           c.chans = append(c.chans, ch)
    //           g.mu.Unlock()
    //           return ch
    //       }
    //       c := &call{chans: []chan<- Result{ch}}
    //       c.wg.Add(1)
    //       g.m[key] = c
    //       g.mu.Unlock()
    //       go g.doCall(c, key, fn)
    //       return ch
    //   }
    /// `DoChan` is like [`Do`] but returns a channel that will receive
    /// the result when it is ready. The channel is buffered with cap=1.
    pub fn DoChan<F>(self: &Arc<Self>, key: string, fn_: F) -> chan<Result<V>>
    where
        F: FnOnce() -> (V, error) + Send + 'static,
    {
        // Go: ch := make(chan Result, 1)
        let ch: chan<Result<V>> = chan::<Result<V>>::new_buffered(1);
        // Go: g.mu.Lock(); if g.m == nil { g.m = make(...) }
        let mut s = self.state.Lock();
        if s.m.is_none() {
            s.m = Some(BTreeMap::new());
        }
        // Go: if c, ok := g.m[key]; ok { c.dups++; c.chans = append(c.chans, ch); g.mu.Unlock(); return ch }
        if let Some(c) = s.m.as_ref().unwrap().get(&key).cloned() {
            c.dups.fetch_add(1, Ordering::AcqRel);
            c.chans.Lock().push(ch.clone());
            drop(s);
            return ch;
        }
        // Go: c := &call{chans: []chan<- Result{ch}}; c.wg.Add(1); g.m[key] = c; g.mu.Unlock()
        let c = Arc::new(Call::<V>::new());
        c.wg.Add(1);
        c.chans.Lock().push(ch.clone());
        s.m.as_mut().unwrap().insert(key.clone(), c.clone());
        drop(s);

        // Go: go g.doCall(c, key, fn)
        //   Library-internal go!() opts up to 64 KiB stack — closure
        //   captures user-supplied fn_ which may want a roomier stack
        //   in debug builds.
        const KB: usize = 1024;
        let g = self.clone();
        let c2 = c.clone();
        let key2 = key.clone();
        go!(stack(64 * KB), move || {
            g.doCall(c2, key2, fn_);
        });
        ch
    }

    // Go: singleflight.go:92
    //   func (g *Group) doCall(c *call, key string, fn func() (any, error)) {
    //       c.val, c.err = fn()
    //       g.mu.Lock()
    //       c.wg.Done()
    //       if g.m[key] == c { delete(g.m, key) }
    //       for _, ch := range c.chans {
    //           ch <- Result{c.val, c.err, c.dups > 0}
    //       }
    //       g.mu.Unlock()
    //   }
    fn doCall<F>(&self, c: Arc<Call<V>>, key: string, fn_: F)
    where
        F: FnOnce() -> (V, error),
    {
        // Go: c.val, c.err = fn()
        let (v, e) = fn_();
        *c.out.Lock() = Some((v.clone(), e.clone()));

        // Go: g.mu.Lock(); c.wg.Done(); if g.m[key] == c { delete(g.m, key) }
        let mut s = self.state.Lock();
        c.wg.Done();
        if let Some(m) = s.m.as_mut() {
            if let Some(existing) = m.get(&key).cloned() {
                if Arc::ptr_eq(&existing, &c) {
                    m.remove(&key);
                }
            }
        }
        // Go: for _, ch := range c.chans { ch <- Result{c.val, c.err, c.dups > 0} }
        let shared = c.dups.load(Ordering::Acquire) > 0;
        let chans = core::mem::take(&mut *c.chans.Lock());
        // Drop the group lock BEFORE channel sends. With cap=1 channels
        // and a fresh chan per Result this never blocks; but keeping the
        // group lock during sends would risk priority inversion if cap
        // were ever raised.
        drop(s);
        for ch in chans {
            ch.Send(Result {
                Val: v.clone(),
                Err: e.clone(),
                Shared: shared,
            });
        }
    }

    // Go: singleflight.go:111
    //   func (g *Group) ForgetUnshared(key string) bool {
    //       g.mu.Lock()
    //       defer g.mu.Unlock()
    //       c, ok := g.m[key]
    //       if !ok { return true }
    //       if c.dups == 0 { delete(g.m, key); return true }
    //       return false
    //   }
    /// `ForgetUnshared` tells the singleflight to forget about a key if
    /// no other goroutines are waiting for the same key. Returns
    /// whether the key was forgotten or unknown.
    pub fn ForgetUnshared(&self, key: string) -> bool {
        let mut s = self.state.Lock();
        let m = match s.m.as_mut() {
            None => return true,
            Some(m) => m,
        };
        let c = match m.get(&key).cloned() {
            None => return true,
            Some(c) => c,
        };
        if c.dups.load(Ordering::Acquire) == 0 {
            m.remove(&key);
            return true;
        }
        false
    }
}

impl<V: Clone + Default + Send + 'static> Default for Group<V> {
    fn default() -> Self {
        Self::new()
    }
}

// Suppress the "must use Arc<Self>" friction for Do() in the static
// path: Do does NOT spawn a goroutine, so it doesn't need Arc<Self>.
// Only DoChan does. The split mirrors the expected usage of
// `let g = Arc::new(Group::new())` for DoChan, while plain stack-local
// `Group::new()` works for Do.
//
// Note: we also bind a Default to make the macro `let g = Group::new();`
// work as a member of larger structs that derive Default.
unsafe impl<V: Clone + Default + Send + 'static> Sync for Group<V> {}
