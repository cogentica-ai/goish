// sync — Go's synchronization primitives.
//
// Go SDK reference: /share/go/src/sync/{mutex,waitgroup,once,rwmutex}.go
// (with the mutex implementation moved to internal/sync in Go 1.25).
//
// Goish v1 implements the user-facing API verbatim (Lock/Unlock,
// Add/Done/Wait, Do, RLock/RUnlock) but simplifies the internals:
// no futex (M17c will add one), no starvation mode (Go's lockSlow
// has ~140 LOC of CAS bookkeeping for tail-latency control). We use
// the simpler "FIFO handoff" model — fast-path CAS on the lock
// state-atom, slow-path park-on-contention via gopark with a
// SpinLock-protected wait queue.
//
// The handoff design: when an Unlock has waiters in the queue, the
// woken goroutine inherits ownership of the mutex directly (no
// re-CAS). This is fair (FIFO) and simple, but barging-friendly only
// at the start of contention; under sustained pressure it behaves
// like Go's starvation mode anyway.

#![allow(non_snake_case)]

pub mod atomic;
mod cond;
mod mutex;
mod once;
mod oncefunc;
mod pool;
mod rwmutex;
mod sema;
mod syncmap;
mod waitgroup;

pub use cond::{Cond, Locker, NewCond};
pub use mutex::{Mutex, MutexGuard};
pub use once::Once;
pub use oncefunc::{OnceFunc, OnceValue, OnceValues};
pub use pool::Pool;
pub use rwmutex::RWMutex;
pub use syncmap::Map;
pub use waitgroup::WaitGroup;
