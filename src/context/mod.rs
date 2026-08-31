// go: package context
//
// context — Go's `context` package, ported.
//
// Module root only: one `.rs` per Go `.go`, and the `pub use` surface.
// Go's package is a single file, so there is exactly one.
//
//   context.rs  context/context.go
//
// User-facing API surface (Goish v1):
//
//   trait Context {
//       fn Deadline(&self) -> Option<time::Time>;
//       fn Done(&self) -> chan<()>;
//       fn Err(&self) -> error;
//   }
//
//   fn Background() -> Arc<dyn Context>;
//   fn TODO()       -> Arc<dyn Context>;
//   fn WithCancel(parent)         -> (Arc<dyn Context>, CancelFunc);
//   fn WithDeadline(parent, time) -> (Arc<dyn Context>, CancelFunc);
//   fn WithTimeout(parent, dur)   -> (Arc<dyn Context>, CancelFunc);
//
//   static Canceled: error           // "context canceled"
//   static DeadlineExceeded: error   // "context deadline exceeded"
//
// Done() returns a `chan<()>` that is **closed** when the context is
// cancelled. For Background/TODO (never-cancellable), Done() returns
// a nil chan — `select!` skips nil-chan cases, matching Go's
// `<-ctx.Done()` blocking-forever semantic for non-cancellable
// contexts.
//
// Cancellation propagation: every derived context that has a
// non-nil parent.Done() spawns a watcher goroutine that does
// `parent.Done().Recv()` then cancels self. This is the simpler
// equivalent of Go's `propagateCancel` (context.go) — Go's runtime
// has a fast path that registers the child on the parent's children
// list when the parent is itself a *cancelCtx, avoiding the watcher
// goroutine. Goish v1 always uses the watcher; the cost (one
// goroutine per derived context) is acceptable at v1 scale.
//
// What v1 does include:
//   - WithValue(parent, key, value) — keyed value propagation. Keys
//     are `string` (Go uses `any` with type-tagged uniqueness; goish
//     callers should namespace their keys to avoid collision).

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;

#[path = "context.rs"]
mod context_go;
pub use context_go::*;
