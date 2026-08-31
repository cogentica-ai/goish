// go: file context/context.go decls: Canceled, deadlineExceededError.Error, deadlineExceededError.Timeout, deadlineExceededError.Temporary, emptyCtx.Deadline, emptyCtx.Done, emptyCtx.Err, Background, TODO, cancelCtx.cancel, timerCtx.Deadline, cancelCtx.Done, cancelCtx.Err, cancelCtx.Value, WithCancel, WithDeadline, WithTimeout, WithCancelCause, Cause, withoutCancelCtx.Deadline, withoutCancelCtx.Done, withoutCancelCtx.Err, withoutCancelCtx.Value, WithoutCancel, AfterFunc, WithDeadlineCause, WithTimeoutCause, valueCtx.Value, WithValue
//
// context.go — the Context interface, Background/TODO, the cancel,
// deadline, value and without-cancel derivations, and AfterFunc.
//
// goishlint:ignore GOISH018 String, contextName, stringify, init, propagateCancel, parentCancelCtx, removeChild — `String`/`contextName`/`stringify` render a context for `%v`, and goish's Context is a trait with no Stringer bridge; `init` builds Go's `closedchan`, which goish does not need because a closed `chan` is what `cancel` produces directly; `propagateCancel`, `parentCancelCtx` and `removeChild` serve the parent's `children` map, which goish replaces with a watcher goroutine — see the note on `build_cancel_ctx`.
// goishlint:ignore GOISH021 backgroundCtx, todoCtx, afterFuncer, afterFuncCtx, stopCtx, goroutines, cancelCtxKey, canceler, closedchan, stringer, timerCtx — `backgroundCtx` and `todoCtx` differ from `emptyCtx` only in their String(), which is not ported; `afterFuncer`/`afterFuncCtx`/`stopCtx`/`canceler`/`timerCtx` are the child-registration machinery the watcher replaces, and `AfterFunc` is written against the watcher instead; `cancelCtxKey` is the unexported key Go's `Cause` walks for, which is a trait method here; `goroutines` is a test-only counter; `closedchan` and `stringer` are covered by the GOISH018 waiver above.

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
    // go: sdk 1.25.5 context/context.go:167-167 Canceled
    // goishlint:ignore GOISH014 - the anchor names the GO symbol. Go's
    //     `Canceled` is `errors.New("context canceled")`, an
    //     *errorString with no named type; goish's `var!` sentinel needs
    //     a concrete type to hang the message on.
    fn Error(&self) -> string {
        return string::from("context canceled");
    }
}

/// The concrete type behind [`DeadlineExceeded`].
///
/// Go keeps `deadlineExceededError` unexported and hands callers the
/// `error` interface, which they then assert `net.Error` on. goish
/// cannot: `cast!` on an `error` handle downcasts the HANDLE, not what
/// it wraps, so an interface assertion against a wrapped error is a
/// silent miss. Exposing the type is how [`Timeout`](Self::Timeout) and
/// [`Temporary`](Self::Temporary) stay reachable at all. (That handle
/// limitation is wider than this package — `net::OpError::Timeout` hits
/// it too — and worth its own fix.)
pub struct DeadlineExceededError;
impl ErrorTrait for DeadlineExceededError {
    // go: sdk 1.25.5 context/context.go:175-175 deadlineExceededError.Error
    // goishlint:ignore GOISH014 - the anchor names the GO symbol.
    fn Error(&self) -> string {
        return string::from("context deadline exceeded");
    }
}

impl crate::net::net::timeout for DeadlineExceededError {
    // go: sdk 1.25.5 context/context.go:176-176 deadlineExceededError.Timeout
    // goishlint:ignore GOISH014 - the anchor names the GO symbol.
    /// Go: `func (deadlineExceededError) Timeout() bool { return true }`
    ///
    /// This is not decoration. `DeadlineExceeded` satisfies `net.Error`
    /// in Go, which is how a caller that already branches on
    /// `netErr.Timeout()` treats a context deadline the same as a
    /// socket one. Neither method was here, so it did not.
    fn Timeout(&self) -> bool {
        return true;
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl crate::net::net::temporary for DeadlineExceededError {
    // go: sdk 1.25.5 context/context.go:177-177 deadlineExceededError.Temporary
    // goishlint:ignore GOISH014 - the anchor names the GO symbol.
    /// Go: `func (deadlineExceededError) Temporary() bool { return true }`
    fn Temporary(&self) -> bool {
        return true;
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
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

// go: sdk 1.25.5 context/context.go:71-165 Context
/// `context.Context` — carries deadline + cancellation signal.
/// Mirrors `context.Context` (context.go:71).
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
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

    // go: none — goish idiom: Go's `Context.Value` is an interface
    //     METHOD with no body, and every concrete context implements
    //     it. goish gives the trait a default that returns None, so a
    //     context with no values of its own — Empty, and every future
    //     one — inherits the empty answer instead of writing it out.
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
        return None;
    }

    // go: none — goish idiom: Go's `Cause(c)` walks up looking for the
    //     unexported `cancelCtxKey`, which only a cancelCtx answers to.
    //     goish has no such key, so the walk is a trait method every
    //     context answers.
    /// Internal: returns the cancellation cause (set by CancelCauseFunc).
    /// Default: same as Err() — contexts created with WithCancel have no
    /// separate cause. Overridden by CancelCauseCtx.
    fn __cause(&self) -> error {
        return self.Err();
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
    // go: sdk 1.25.5 context/context.go:183-185 emptyCtx.Deadline
    fn Deadline(&self) -> Option<Time> {
        return None;
    }
    // go: sdk 1.25.5 context/context.go:187-189 emptyCtx.Done
    fn Done(&self) -> chan<()> {
        // nil chan: blocks forever, filtered by select!.
        return chan::<()>::nil();
    }
    // go: sdk 1.25.5 context/context.go:191-193 emptyCtx.Err
    fn Err(&self) -> error {
        return crate::errors::nil;
    }
}

// go: sdk 1.25.5 context/context.go:215-217 Background
/// `context.Background()` — the root context. Never cancellable,
/// no deadline. Use as the top-level for main / init / tests.
/// Mirrors `Background()` (context.go:215).
pub fn Background() -> Arc<dyn Context> {
    return Arc::new(EmptyCtx);
}

// go: sdk 1.25.5 context/context.go:223-225 TODO
/// `context.TODO()` — placeholder when it's not yet clear which
/// context to use. Behaves as Background does. Mirrors
/// `TODO()` (context.go:223).
pub fn TODO() -> Arc<dyn Context> {
    return Arc::new(EmptyCtx);
}

// ─── cancel context (WithCancel / WithDeadline / WithTimeout) ────

struct CancelState {
    err: error,
    cause: error,
}

struct CancelCtx {
    /// Parent context — Go's `cancelCtx` embeds `Context`
    /// (context.go:421) and delegates `Value` lookups to it; without
    /// this, a `WithCancel` in the chain would sever every ancestor
    /// `WithValue`.
    parent: Arc<dyn Context>,
    parent_deadline: Option<Time>,
    own_deadline: Option<Time>,
    done: chan<()>,
    /// Verbatim Go-shape: a `sync.Mutex` wrapping the protected
    /// `CancelState`. Mirrors `cancelCtx { mu Mutex; err error; cause error }`.
    state: Mutex<CancelState>,
}

impl CancelCtx {
    // go: none — goish idiom: Go's `(*cancelCtx).cancel` takes
    //     `removeFromParent bool` and unlinks the child from the
    //     parent's `children` map. goish has no such map — see the
    //     note on `build_cancel_ctx` — so the two-argument shape has
    //     nothing to say and this is the one-cause convenience.
    fn cancel(&self, err: error) {
        self.cancel_with_cause(err.clone(), err);
    }

    // go: sdk 1.25.5 context/context.go:549-579 cancelCtx.cancel
    // goishlint:ignore GOISH014 - the anchor names the GO symbol; this
    //     is Go's `cancel(removeFromParent, err, cause)` minus the
    //     parent-unlink argument, which goish's watcher design does not
    //     have.
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
    // go: sdk 1.25.5 context/context.go:669-671 timerCtx.Deadline
    // goishlint:ignore GOISH014 - the anchor names the GO symbol. Go
    //     splits the deadline out into a `timerCtx` that EMBEDS a
    //     cancelCtx; goish's CancelCtx carries the optional deadline
    //     itself, so one type answers where Go has two.
    fn Deadline(&self) -> Option<Time> {
        return self.own_deadline.or(self.parent_deadline);
    }
    // go: sdk 1.25.5 context/context.go:448-461 cancelCtx.Done
    fn Done(&self) -> chan<()> {
        return self.done.clone();
    }
    // go: sdk 1.25.5 context/context.go:463-471 cancelCtx.Err
    fn Err(&self) -> error {
        return self.state.Lock().err.clone();
    }
    // go: none — goish idiom: see `Context::__cause` above.
    fn __cause(&self) -> error {
        let s = self.state.Lock();
        return if s.err.IsNil() {
            crate::errors::nil
        } else {
            s.cause.clone()
        };
    }
    // go: sdk 1.25.5 context/context.go:441-446 cancelCtx.Value
    fn Value(&self, key: &str) -> Option<Arc<dyn core::any::Any + Send + Sync>> {
        // Go `(*cancelCtx).Value` (context.go:429): everything except
        // the internal cancelCtxKey delegates up the parent chain.
        return self.parent.Value(key);
    }
}

// go: none — goish idiom: Go's `propagateCancel` registers the child
//     on the parent's `children` map when the parent is itself a
//     cancelCtx, and falls back to a watcher goroutine otherwise
//     (context.go:294-323). goish always takes the watcher: one
//     goroutine per derived context, which exits as soon as EITHER side
//     fires, so nothing is held alive. `parentCancelCtx` and
//     `removeChild` exist only to serve the map, so neither is ported.
fn build_cancel_ctx(parent: &Arc<dyn Context>, own_deadline: Option<Time>) -> Arc<CancelCtx> {
    let me = Arc::new(CancelCtx {
        parent: parent.clone(),
        parent_deadline: parent.Deadline(),
        own_deadline,
        done: crate::make!(chan()),
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

    return me;
}

// go: sdk 1.25.5 context/context.go:240-243 WithCancel
/// `WithCancel(parent)` — derive a context that can be cancelled
/// explicitly via the returned CancelFunc. Mirrors
/// `WithCancel` (context.go:240).
pub fn WithCancel(parent: Arc<dyn Context>) -> (Arc<dyn Context>, CancelFunc) {
    let ctx = build_cancel_ctx(&parent, None);
    let ctx_clone = ctx.clone();
    let cancel = Box::new(move || ctx_clone.cancel(Canceled.into()));
    return (ctx, cancel);
}

// go: sdk 1.25.5 context/context.go:625-627 WithDeadline
/// `WithDeadline(parent, d)` — derive a context that auto-cancels
/// at time `d` (or earlier if cancel() is called). If parent has
/// an earlier deadline, returns WithCancel(parent) (no override).
/// Mirrors `WithDeadline` (context.go:625).
pub fn WithDeadline(parent: Arc<dyn Context>, d: Time) -> (Arc<dyn Context>, CancelFunc) {
    // Go: if cur, ok := parent.Deadline(); ok && cur.Before(d) {
    //         // The current deadline is already sooner than the new one.
    //         return WithCancel(parent)
    //     }
    //
    // This guard used to be inverted — `!d.After(parent_d)`, which
    // inherits when the NEW deadline is the sooner one. Both halves
    // were wrong, and the second half dangerously: a caller tightening
    // a deadline, `WithTimeout(ctx, time.Millisecond)` on an hour-long
    // parent, got `WithCancel(parent)` and no timer at all, so the
    // tighter deadline never fired.
    if let Some(parent_d) = parent.Deadline() {
        if parent_d.Before(d) {
            return WithCancel(parent);
        }
    }

    let ctx = build_cancel_ctx(&parent, Some(d));
    arm_deadline(&ctx, d, crate::errors::nil);

    let ctx_clone = ctx.clone();
    let cancel = Box::new(move || ctx_clone.cancel(Canceled.into()));
    return (ctx, cancel);
}

// go: none — goish idiom: Go's `timerCtx` holds a `time.Timer` and
//     cancels itself from the timer callback, with the cause stored on
//     the context. goish has no timer registry, so the deadline is a
//     goroutine that sleeps — the same shape as the cancel watcher
//     above. Factored out because `WithDeadline` and
//     `WithDeadlineCause` differ only in what they pass here.
fn arm_deadline(ctx: &Arc<CancelCtx>, d: Time, cause: error) {
    // Go: `if dur := time.Until(d); dur <= 0 { c.cancel(...) }`
    let until: Duration = d.Sub(Now());
    let err: error = DeadlineExceeded.into();
    let cause = if cause.IsNil() { err.clone() } else { cause };
    if until.0 <= 0 {
        ctx.cancel_with_cause(err, cause);
        return;
    }
    let ctx_for_timer = ctx.clone();
    crate::go!(stack(64 * crate::KB), move || {
        crate::time::Sleep(until);
        ctx_for_timer.cancel_with_cause(err, cause);
    });
}

// go: sdk 1.25.5 context/context.go:703-705 WithTimeout
/// `WithTimeout(parent, d)` — `WithDeadline(parent, Now() + d)`.
/// Mirrors `WithTimeout` (context.go:703).
pub fn WithTimeout(parent: Arc<dyn Context>, d: Duration) -> (Arc<dyn Context>, CancelFunc) {
    let deadline = Now().Add(d);
    return WithDeadline(parent, deadline);
}

// go: sdk 1.25.5 context/context.go:268-271 WithCancelCause
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
    return (ctx, cancel);
}

// go: sdk 1.25.5 context/context.go:288-306 Cause
/// `Cause(c)` — returns a non-nil error explaining why a context was
/// cancelled. If cancelled via CancelCauseFunc(err), returns err.
/// Otherwise returns c.Err(). Returns nil if c is not cancelled.
/// Mirrors `Cause` (context.go:291).
pub fn Cause(c: &Arc<dyn Context>) -> error {
    return c.__cause();
}

// ─── WithoutCancel — context.go:585 ──────────────────────────────

// go: sdk 1.25.5 context/context.go:592-594 withoutCancelCtx
/// `withoutCancelCtx` — keeps the parent's VALUES and drops everything
/// else: no deadline, no Done channel, no error, ever.
struct WithoutCancelCtx {
    c: Arc<dyn Context>,
}

impl Context for WithoutCancelCtx {
    // go: sdk 1.25.5 context/context.go:596-598 withoutCancelCtx.Deadline
    fn Deadline(&self) -> Option<Time> {
        return None;
    }
    // go: sdk 1.25.5 context/context.go:600-602 withoutCancelCtx.Done
    /// Go returns a nil channel, which blocks forever in a select —
    /// which is exactly what "never cancelled" means there. goish's
    /// nil `chan` behaves the same way.
    fn Done(&self) -> chan<()> {
        return chan::nil();
    }
    // go: sdk 1.25.5 context/context.go:604-606 withoutCancelCtx.Err
    fn Err(&self) -> error {
        return crate::errors::nil;
    }
    // go: none — goish idiom: `Cause` is a method on the trait here
    //     rather than a package function walking a private key, so a
    //     context that is never cancelled has to answer it too.
    fn __cause(&self) -> error {
        return crate::errors::nil;
    }
    // go: sdk 1.25.5 context/context.go:608-610 withoutCancelCtx.Value
    fn Value(&self, key: &str) -> Option<Arc<dyn core::any::Any + Send + Sync>> {
        return self.c.Value(key);
    }
}

// go: sdk 1.25.5 context/context.go:585-590 WithoutCancel
/// `context.WithoutCancel(parent)` — a copy of `parent` that is NOT
/// cancelled when parent is, and has no deadline.
///
/// This is what a handler reaches for when it starts work that must
/// outlive the request — a log flush, a metrics push — but still wants
/// the request's values. Without it the only options were to pass
/// `Background()` and lose every value, or to pass the request context
/// and have the work cancelled underneath.
pub fn WithoutCancel(parent: Arc<dyn Context>) -> Arc<dyn Context> {
    register_context_impls();
    return Arc::new(WithoutCancelCtx { c: parent });
}

// ─── AfterFunc — context.go:325 ──────────────────────────────────

// go: sdk 1.25.5 context/context.go:325-340 AfterFunc
/// `context.AfterFunc(ctx, f)` — arrange to call `f` in its own
/// goroutine once `ctx` is cancelled, and hand back a `stop`.
///
/// `stop()` returns true if it stopped `f` from running. False means
/// either the context was already cancelled and `f` has been started,
/// or `stop` was already called. It does NOT wait for `f`: a caller
/// that needs to know `f` finished has to coordinate with it.
///
/// Several `AfterFunc`s on one context are independent; one does not
/// replace another.
///
/// Go registers the callback as a child of the parent's cancelCtx.
/// goish has no child registry — see the note on `build_cancel_ctx` —
/// so this is a goroutine parked on the two channels, which is the
/// same shape the cancel watcher already uses.
pub fn AfterFunc<F>(ctx: Arc<dyn Context>, f: F) -> Box<dyn Fn() -> bool + Send + Sync>
where
    F: FnOnce() + Send + 'static,
{
    // `stopped` is the once: whoever flips it from false wins, and the
    // loser does nothing. Go spells the same race as a sync.Once.
    let stopped = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let stop_chan: chan<()> = crate::make!(chan());

    let done = ctx.Done();
    let fired = stopped.clone();
    let stop_rx = stop_chan.clone();
    crate::go!(stack(64 * crate::KB), move || {
        if done.is_nil() {
            // A context that can never be cancelled: wait only for stop.
            let _ = stop_rx.Recv();
            return;
        }
        crate::select! {
            let _ = done.Recv() => {
                // Cancelled. Claim the once; if stop() got here first,
                // do nothing.
                if !fired.swap(true, core::sync::atomic::Ordering::AcqRel) {
                    f();
                }
            },
            let _ = stop_rx.Recv() => {},
        }
    });

    let claimed = stopped.clone();
    return Box::new(move || {
        let was = claimed.swap(true, core::sync::atomic::Ordering::AcqRel);
        if !was {
            // We claimed it first, so f will not run. Wake the watcher
            // so it exits rather than holding the context alive.
            stop_chan.Close();
        }
        return !was;
    });
}

// ─── WithDeadlineCause / WithTimeoutCause — context.go:632, :710 ──

// go: sdk 1.25.5 context/context.go:632-657 WithDeadlineCause
/// `WithDeadline`, but the context carries `cause`: once the deadline
/// passes, `Cause(ctx)` returns `cause` where `Err(ctx)` still returns
/// `DeadlineExceeded`. That split is the point — `Err` is what a
/// caller branches on, `Cause` is what it logs.
pub fn WithDeadlineCause(
    parent: Arc<dyn Context>,
    d: Time,
    cause: error,
) -> (Arc<dyn Context>, CancelFunc) {
    // Same guard as `WithDeadline`: a parent that already expires
    // sooner wins, and the cause never comes into play.
    if let Some(parent_d) = parent.Deadline() {
        if parent_d.Before(d) {
            return WithCancel(parent);
        }
    }
    let ctx = build_cancel_ctx(&parent, Some(d));
    arm_deadline(&ctx, d, cause);
    let ctx_clone = ctx.clone();
    let cancel = Box::new(move || ctx_clone.cancel(Canceled.into()));
    return (ctx, cancel);
}

// go: sdk 1.25.5 context/context.go:710-712 WithTimeoutCause
/// `WithDeadlineCause(parent, Now().Add(timeout), cause)`.
pub fn WithTimeoutCause(
    parent: Arc<dyn Context>,
    timeout: Duration,
    cause: error,
) -> (Arc<dyn Context>, CancelFunc) {
    return WithDeadlineCause(parent, Now().Add(timeout), cause);
}

// ─── valueCtx (WithValue) — context.go:744 ───────────────────────

/// `valueCtx` (context.go:744) — pairs (key, value) with parent context.
struct ValueCtx {
    parent: Arc<dyn Context>,
    key: alloc::string::String,
    val: Arc<dyn core::any::Any + Send + Sync>,
}

impl Context for ValueCtx {
    // go: none — goish idiom: Go's `valueCtx` EMBEDS the parent
    //     Context, so Deadline, Done and Err are promoted for free and
    //     only Value is written out (context.go:744-748). Rust has no
    //     embedding, so the three forwards are spelled here.
    fn Deadline(&self) -> Option<Time> {
        return self.parent.Deadline();
    }
    // go: none — goish idiom: see `Deadline` above.
    fn Done(&self) -> chan<()> {
        return self.parent.Done();
    }
    // go: none — goish idiom: see `Deadline` above.
    fn Err(&self) -> error {
        return self.parent.Err();
    }
    // go: sdk 1.25.5 context/context.go:768-773 valueCtx.Value
    fn Value(&self, key: &str) -> Option<Arc<dyn core::any::Any + Send + Sync>> {
        if self.key == key {
            return Some(self.val.clone());
        }
        return self.parent.Value(key);
    }
}

// go: sdk 1.25.5 context/context.go:727-738 WithValue
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
    return Arc::new(ValueCtx {
        parent,
        key: alloc::string::String::from(key), // goishlint:ignore GOISH010 - `ValueCtx.key` is a Rust String, not a goish string: it is compared with `==` against a `&str` on every lookup, and goish's string has no such impl.
        val: Arc::new(value),
    });
}

// go: none — goish idiom: fill the `#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `context`'s concrete contexts into the `Context` registry.
/// Idempotent; called from `goish::init()`.
pub fn register_context_impls() {
    __goish_register_Context_impl::<CancelCtx>();
    __goish_register_Context_impl::<EmptyCtx>();
    __goish_register_Context_impl::<ValueCtx>();
    __goish_register_Context_impl::<WithoutCancelCtx>();
    // `DeadlineExceeded` satisfies net.Error in Go, so register both
    // views. Registration is not sufficient on its own — see the note
    // on `DeadlineExceededError` — but it is necessary.
    crate::net::net::__goish_register_timeout_impl::<DeadlineExceededError>();
    crate::net::net::__goish_register_temporary_impl::<DeadlineExceededError>();
}
