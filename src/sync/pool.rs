// sync::Pool — Go's `sync.Pool` (slim).
//
// Reference: /share/go/src/sync/pool.go.
//
// Slim deviations:
//
//   * No per-P sharding. Go's Pool keeps a `[GOMAXPROCS]poolLocal`
//     fan-out for cache-line-isolated Get/Put under contention.
//     Goish v1 backs the Pool with a single `Mutex<Vec<T>>`. Right
//     trade for HTTP buffer-pool sites (the common case) where
//     contention is moderate; if profiling shows the Mutex hot, a
//     per-P shard can be added later.
//
//   * No GC-driven cleanup / victim cache. Go drains its Pool every
//     GC cycle (reducing footprint at quiet times). Goish has no
//     mark-sweep GC, so items live until the Pool itself is dropped.
//
//   * `Pool<T>` is generic on the item type rather than `any`. The
//     Go API stores `any` and round-trips through type assertion;
//     goish has no `any`, but generics achieve the same end with
//     compile-time type safety.
//
//   * `New` is a mandatory constructor passed at `Pool::new(f)` time
//     rather than a public field that can be flipped post-hoc. Get
//     therefore always returns a value (never nil) — eliminating the
//     `Get().(*Buffer)` assertion every Go caller has to write.
//
// Concurrency: backed by `sync::Mutex<Vec<T>>`, so Get/Put are safe
// across goroutines (mirrors Go's "safe for use by multiple
// goroutines simultaneously").

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::mutex::Mutex;

/// `sync.Pool` — a thread-safe set of temporary objects.
///
/// The Pool is generic over `T`, the item type. Construct with
/// [`Pool::new`], then [`Pool::Get`] to acquire and [`Pool::Put`] to
/// return.
pub struct Pool<T: Send + 'static> {
    items: Mutex<PoolState<T>>,
    new_fn: Arc<dyn Fn() -> T + Send + Sync + 'static>,
}

struct PoolState<T> {
    items: Vec<T>,
}

impl<T: Send + 'static> Pool<T> {
    /// Construct a new Pool whose `Get` calls `new_fn` to mint a fresh
    /// item when the pool is empty. Mirrors Go's:
    ///
    /// ```ignore
    /// var bufPool = sync.Pool{
    ///     New: func() any { return new(bytes.Buffer) },
    /// }
    /// ```
    ///
    /// Goish: `let buf_pool: Pool<Buffer> = Pool::new(|| Buffer::new());`
    pub fn new<F>(new_fn: F) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        Pool {
            items: Mutex::new(PoolState { items: Vec::new() }),
            new_fn: Arc::new(new_fn),
        }
    }

    /// `(*Pool).Get()` (pool.go:131) — selects an item from the Pool,
    /// removing it. If the Pool is empty, calls `New` to mint one.
    ///
    /// Slim: never returns nil — `New` is mandatory at construction.
    pub fn Get(&self) -> T {
        // Go: x := l.private; l.private = nil
        // Go: if x == nil { x, _ = l.shared.popHead() }
        {
            let mut g = self.items.Lock();
            if let Some(x) = g.items.pop() {
                return x;
            }
        }
        // Go: if x == nil && p.New != nil { x = p.New() }
        (self.new_fn)()
    }

    /// `(*Pool).Put(x)` (pool.go:99) — returns `x` to the Pool for
    /// later reuse.
    pub fn Put(&self, x: T) {
        // Go: if x == nil { return } — handled at the type level here
        // (the caller cannot pass nil since T is owned).
        let mut g = self.items.Lock();
        g.items.push(x);
    }

    /// Number of items currently held by the Pool. Not part of Go's
    /// API surface, but useful for tests and instrumentation.
    pub fn __len(&self) -> usize {
        let g = self.items.Lock();
        g.items.len()
    }
}
