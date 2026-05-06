// context — Go's `context` package.
//
// Reference: /share/go/src/context/context.go.
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
// What v1 does NOT include:
//   - WithDeadlineCause / WithTimeoutCause
//   - AfterFunc
//   - WithoutCancel
//
// What v1 does include:
//   - WithValue(parent, key, value) — keyed value propagation. Keys
//     are `string` (Go uses `any` with type-tagged uniqueness; goish
//     callers should namespace their keys to avoid collision).

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::errors::{error, ErrorTrait};
use crate::gochan::chan;
use crate::gostring::string;
use crate::sync::Mutex;
use crate::time::{Duration, Now, Time};

// ─── sentinel errors ─────────────────────────────────────────────

struct CanceledError;
impl ErrorTrait for CanceledError {
    fn Error(&self) -> string {
        string::from("context canceled")
    }
}

struct DeadlineExceededError;
impl ErrorTrait for DeadlineExceededError {
    fn Error(&self) -> string {
        string::from("context deadline exceeded")
    }
}

// context sentinels — Doctrine 2 marker form. Identity-stable so
// `errors::Is(err, context::Canceled)` works across goroutine boundaries.
crate::var! {
    /// `context.Canceled` — the error returned by `Err()` when a
    /// context is cancelled by `cancel()`. Mirrors context.go:167.
    pub Canceled: error = { CanceledError };

    /// `context.DeadlineExceeded` — the error returned by `Err()` when
    /// a context is cancelled by deadline expiry. Mirrors context.go:171.
    pub DeadlineExceeded: error = { DeadlineExceededError };
}

// ─── Context trait ───────────────────────────────────────────────

/// `context.Context` — carries deadline + cancellation signal.
/// Mirrors `context.Context` (context.go:71).
pub trait Context: Send + Sync {
    /// Deadline returns the time at which work should be cancelled,
    /// if a deadline is set. None = no deadline.
    fn Deadline(&self) -> Option<Time>;

    /// Done returns a chan<()> that is closed when the context is
    /// cancelled. For non-cancellable contexts (Background/TODO)
    /// Done returns a nil chan — receives on it block forever, and
    /// `select!` filters the case out.
    fn Done(&self) -> chan<()>;

    /// Err returns nil while Done is open; returns Canceled or
    /// DeadlineExceeded after cancellation.
    fn Err(&self) -> error;

    /// Value returns the value associated with this context for `key`,
    /// or `None` if no value is associated. Successive Value calls with
    /// the same key return the same value.
    ///
    /// Slim deviation: Go uses `any` for both key and value. Goish v1
    /// uses `string` keys (callers should namespace) and
    /// `Arc<dyn Any + Send + Sync>` values. The default impl returns
    /// `None`, so non-WithValue contexts inherit the empty answer
    /// without each having to implement Value.
    fn Value(&self, _key: &str) -> Option<Arc<dyn core::any::Any + Send + Sync>> {
        None
    }

    /// Internal: returns the cancellation cause (set by CancelCauseFunc).
    /// Default: same as Err() — contexts created with WithCancel have no
    /// separate cause. Overridden by CancelCauseCtx.
    fn __cause(&self) -> error {
        self.Err()
    }
}

/// `CancelFunc` — boxed cancel closure. Calling it cancels the
/// associated context (and its children); subsequent calls are
/// no-ops. Mirrors `context.CancelFunc` (context.go:231).
pub type CancelFunc = Box<dyn Fn() + Send + Sync>;

/// `CancelCauseFunc` — like CancelFunc but records a cause error.
/// `context.Cause(ctx)` returns it. Mirrors `context.CancelCauseFunc`
/// (context.go:239).
pub type CancelCauseFunc = Box<dyn Fn(error) + Send + Sync>;

// ─── empty context (Background / TODO) ───────────────────────────

struct EmptyCtx;

impl Context for EmptyCtx {
    fn Deadline(&self) -> Option<Time> {
        None
    }
    fn Done(&self) -> chan<()> {
        // nil chan: blocks forever, filtered by select!.
        chan::<()>::nil()
    }
    fn Err(&self) -> error {
        crate::errors::nil
    }
}

/// `context.Background()` — the root context. Never cancellable,
/// no deadline. Use as the top-level for main / init / tests.
/// Mirrors `Background()` (context.go:215).
pub fn Background() -> Arc<dyn Context> {
    Arc::new(EmptyCtx)
}

/// `context.TODO()` — placeholder when it's not yet clear which
/// context to use. Semantically identical to Background. Mirrors
/// `TODO()` (context.go:223).
pub fn TODO() -> Arc<dyn Context> {
    Arc::new(EmptyCtx)
}

// ─── cancel context (WithCancel / WithDeadline / WithTimeout) ────

struct CancelState {
    err: error,
    cause: error,
}

struct CancelCtx {
    parent_deadline: Option<Time>,
    own_deadline: Option<Time>,
    done: chan<()>,
    /// Verbatim Go-shape: a `sync.Mutex` wrapping the protected
    /// `CancelState`. Mirrors `cancelCtx { mu Mutex; err error; cause error }`.
    state: Mutex<CancelState>,
}

impl CancelCtx {
    fn cancel(&self, err: error) {
        self.cancel_with_cause(err.clone(), err);
    }

    fn cancel_with_cause(&self, err: error, cause: error) {
        {
            let mut s = self.state.Lock();
            if !s.err.IsNil() {
                return; // already cancelled
            }
            s.err = err;
            s.cause = cause;
            // Drop the guard before Close so any G that wakes from
            // Done.Recv and immediately calls Err() doesn't contend.
        }
        // Closing the chan wakes every Recv (and select!) on Done.
        self.done.Close();
    }
}

impl Context for CancelCtx {
    fn Deadline(&self) -> Option<Time> {
        self.own_deadline.or(self.parent_deadline)
    }
    fn Done(&self) -> chan<()> {
        self.done.clone()
    }
    fn Err(&self) -> error {
        self.state.Lock().err.clone()
    }
    fn __cause(&self) -> error {
        let s = self.state.Lock();
        if s.err.IsNil() {
            crate::errors::nil
        } else {
            s.cause.clone()
        }
    }
}

fn build_cancel_ctx(parent: &Arc<dyn Context>, own_deadline: Option<Time>) -> Arc<CancelCtx> {
    let me = Arc::new(CancelCtx {
        parent_deadline: parent.Deadline(),
        own_deadline,
        done: crate::make!(chan ()),
        state: Mutex::new(CancelState {
            err: crate::errors::nil,
            cause: crate::errors::nil,
        }),
    });

    // Watcher: if parent is cancellable, propagate cancellation.
    // Mirrors context.go:522-528 — select on BOTH parent.Done() and
    // own done. Without the own-done branch the watcher hangs forever
    // when the user cancels via the returned CancelFunc (parent never
    // fires), holding Arc<dyn Context> + Arc<CancelCtx> alive until
    // process exit.
    let parent_done = parent.Done();
    if !parent_done.is_nil() {
        let me_for_watch = me.clone();
        let parent_for_watch = parent.clone();
        let own_done = me.done.clone();
        crate::go!(stack(64 * crate::KB), move || {
            crate::select! {
                let _ = parent_done.Recv() => {
                    // Parent was cancelled — adopt its err.
                    let perr = parent_for_watch.Err();
                    let cancel_err: error = if perr.IsNil() { Canceled.into() } else { perr };
                    me_for_watch.cancel(cancel_err);
                },
                let _ = own_done.Recv() => {
                    // Child cancelled first; exit, releasing both Arcs.
                },
            }
        });
    }

    me
}

/// `WithCancel(parent)` — derive a context that can be cancelled
/// explicitly via the returned CancelFunc. Mirrors
/// `WithCancel` (context.go:240).
pub fn WithCancel(parent: Arc<dyn Context>) -> (Arc<dyn Context>, CancelFunc) {
    let ctx = build_cancel_ctx(&parent, None);
    let ctx_clone = ctx.clone();
    let cancel = Box::new(move || ctx_clone.cancel(Canceled.into()));
    (ctx, cancel)
}

/// `WithDeadline(parent, d)` — derive a context that auto-cancels
/// at time `d` (or earlier if cancel() is called). If parent has
/// an earlier deadline, returns WithCancel(parent) (no override).
/// Mirrors `WithDeadline` (context.go:625).
pub fn WithDeadline(parent: Arc<dyn Context>, d: Time) -> (Arc<dyn Context>, CancelFunc) {
    if let Some(parent_d) = parent.Deadline() {
        if !d.After(parent_d) {
            // Parent has earlier-or-equal deadline; just inherit.
            return WithCancel(parent);
        }
    }

    let ctx = build_cancel_ctx(&parent, Some(d));

    // Schedule a deadline-fire goroutine. If d has already passed,
    // cancel now; else spawn a Sleep + cancel goroutine.
    let now = Now();
    let until: Duration = d.Sub(now);
    if until.0 <= 0 {
        ctx.cancel(DeadlineExceeded.into());
    } else {
        let ctx_for_timer = ctx.clone();
        crate::go!(stack(64 * crate::KB), move || {
            crate::time::Sleep(until);
            ctx_for_timer.cancel(DeadlineExceeded.into());
        });
    }

    let ctx_clone = ctx.clone();
    let cancel = Box::new(move || ctx_clone.cancel(Canceled.into()));
    (ctx, cancel)
}

/// `WithTimeout(parent, d)` — `WithDeadline(parent, Now() + d)`.
/// Mirrors `WithTimeout` (context.go:703).
pub fn WithTimeout(parent: Arc<dyn Context>, d: Duration) -> (Arc<dyn Context>, CancelFunc) {
    let deadline = Now().Add(d);
    WithDeadline(parent, deadline)
}

/// `WithCancelCause(parent)` — like WithCancel but the returned func
/// accepts a cause error. `Cause(ctx)` returns it.
/// Mirrors `WithCancelCause` (context.go:260).
pub fn WithCancelCause(parent: Arc<dyn Context>) -> (Arc<dyn Context>, CancelCauseFunc) {
    let ctx = build_cancel_ctx(&parent, None);
    let ctx_clone = ctx.clone();
    let cancel = Box::new(move |cause: error| {
        let err: error = Canceled.into();
        let cause = if cause.IsNil() { err.clone() } else { cause };
        ctx_clone.cancel_with_cause(err, cause);
    });
    (ctx, cancel)
}

/// `Cause(c)` — returns a non-nil error explaining why a context was
/// cancelled. If cancelled via CancelCauseFunc(err), returns err.
/// Otherwise returns c.Err(). Returns nil if c is not cancelled.
/// Mirrors `Cause` (context.go:291).
pub fn Cause(c: &Arc<dyn Context>) -> error {
    c.__cause()
}

// ─── valueCtx (WithValue) — context.go:744 ───────────────────────

/// `valueCtx` (context.go:744) — pairs (key, value) with parent context.
struct ValueCtx {
    parent: Arc<dyn Context>,
    key: alloc::string::String,
    val: Arc<dyn core::any::Any + Send + Sync>,
}

impl Context for ValueCtx {
    fn Deadline(&self) -> Option<Time> {
        self.parent.Deadline()
    }
    fn Done(&self) -> chan<()> {
        self.parent.Done()
    }
    fn Err(&self) -> error {
        self.parent.Err()
    }
    fn Value(&self, key: &str) -> Option<Arc<dyn core::any::Any + Send + Sync>> {
        if self.key == key {
            return Some(self.val.clone());
        }
        self.parent.Value(key)
    }
}

/// `WithValue(parent, key, value)` (context.go:760) — derive a context
/// that maps `key` to `value`. Lookup via `ctx.Value(key)`.
pub fn WithValue<V>(parent: Arc<dyn Context>, key: &str, value: V) -> Arc<dyn Context>
where
    V: core::any::Any + Send + Sync + 'static,
{
    if key.is_empty() {
        // Match Go's panic on nil key (Go uses interface{}, nil key panics).
        panic!("nil key");
    }
    Arc::new(ValueCtx {
        parent,
        key: alloc::string::String::from(key),
        val: Arc::new(value),
    })
}
