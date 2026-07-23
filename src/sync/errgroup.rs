// sync::errgroup — port of golang.org/x/sync/errgroup.
//
// Anchor: x/sync errgroup/errgroup.go (module cache v0.13.0; the
// surface typescript-go v0.21.0 consumes — WithContext / Go / Wait /
// SetLimit / TryGo — is unchanged across those versions).
//
// Go's Group is a plain struct shared by pointer; goish wraps the
// state in an Arc so the closures handed to `go!` can outlive the
// caller's borrow — `Group` is `Clone` and the zero value
// (`Group::new()` / `Default`) is valid, has no limit, and does not
// cancel on error, exactly like Go's `var g errgroup.Group`.
//
// Panic semantics note: this ports the pre-v0.14 behavior — a panic
// in a task is not caught and rethrown from Wait (an unrecovered
// goroutine panic aborts the process in Go and goish alike).

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;

use crate::context::{self, CancelCauseFunc, Context};
use crate::errors::{error, nil};
use crate::gochan::chan;
use crate::runtime::spin::SpinLock;
use crate::types::int;

// Go: type token struct{} — goish uses the unit type directly.

/// `errgroup.Group` — a collection of goroutines working on subtasks
/// of a common task. A Group should not be reused for different
/// tasks.
#[derive(Clone, Default)]
pub struct Group {
    inner: Arc<Inner>,
}

struct Inner {
    // Go: cancel func(error) — set only by WithContext, before the
    // Group is shared, so a plain immutable field suffices.
    cancel: Option<CancelCauseFunc>,

    // Go: wg sync.WaitGroup
    wg: crate::sync::WaitGroup,

    // Go: sem chan token — mutated by SetLimit (which must not run
    // while goroutines are active), read at every Go/TryGo.
    sem: SpinLock<Option<chan<()>>>,

    // Go: errOnce sync.Once; err error
    err_once: crate::sync::Once,
    err: SpinLock<error>,
}

impl Default for Inner {
    fn default() -> Self {
        Inner {
            cancel: None,
            wg: crate::sync::WaitGroup::new(),
            sem: SpinLock::new(None),
            err_once: crate::sync::Once::new(),
            err: SpinLock::new(crate::errors::nil),
        }
    }
}

/// `errgroup.WithContext(ctx)` — a new Group and an associated
/// Context derived from `ctx`. The derived Context is canceled the
/// first time a function passed to Go returns a non-nil error or the
/// first time Wait returns, whichever occurs first.
pub fn WithContext(ctx: Arc<dyn Context>) -> (Group, Arc<dyn Context>) {
    // Go: ctx, cancel := context.WithCancelCause(ctx)
    let (ctx, cancel) = context::WithCancelCause(ctx);
    (
        Group {
            inner: Arc::new(Inner {
                cancel: Some(cancel),
                ..Inner::default()
            }),
        },
        ctx,
    )
}

impl Group {
    /// A zero Group: valid, no limit, no cancel-on-error.
    pub fn new() -> Group {
        Group::default()
    }

    // Go: (*Group).done — release the semaphore slot, then Done.
    // Inlined into the spawned closures below (they hold the sem
    // handle captured at spawn time, matching Go's read of g.sem —
    // SetLimit during active goroutines is documented misuse).

    /// `(*Group).Wait()` — block until all function calls from Go
    /// have returned, then return the first non-nil error (if any).
    pub fn Wait(&self) -> error {
        self.inner.wg.Wait();
        let err = self.inner.err.lock().clone();
        if let Some(cancel) = &self.inner.cancel {
            cancel(err.clone());
        }
        err
    }

    /// `(*Group).Go(f)` — call `f` in a new goroutine. Blocks until
    /// the new goroutine can be added without exceeding the
    /// configured limit. The first call to return a non-nil error
    /// cancels the group's context, if any; the error is returned by
    /// Wait.
    pub fn Go<F>(&self, f: F)
    where
        F: FnOnce() -> error + Send + 'static,
    {
        // Go: if g.sem != nil { g.sem <- token{} }
        let sem = self.inner.sem.lock().clone();
        if let Some(s) = &sem {
            s.Send(());
        }
        self.spawn(sem, f);
    }

    /// `(*Group).TryGo(f)` — call `f` in a new goroutine only if the
    /// number of active goroutines is below the configured limit.
    /// Reports whether the goroutine was started.
    pub fn TryGo<F>(&self, f: F) -> bool
    where
        F: FnOnce() -> error + Send + 'static,
    {
        let sem = self.inner.sem.lock().clone();
        if let Some(s) = &sem {
            // Go: select { case g.sem <- token{}: default: return false }
            if s.__try_send(()).is_err() {
                return false;
            }
        }
        self.spawn(sem, f);
        true
    }

    // Shared tail of Go/TryGo (the Go source duplicates it inline).
    fn spawn<F>(&self, sem: Option<chan<()>>, f: F)
    where
        F: FnOnce() -> error + Send + 'static,
    {
        self.inner.wg.Add(1);
        let inner = self.inner.clone();
        crate::go!(move || {
            // Go: if err := f(); err != nil { g.errOnce.Do(...) }
            let err = f();
            if err != nil {
                inner.err_once.Do(|| {
                    *inner.err.lock() = err.clone();
                    if let Some(cancel) = &inner.cancel {
                        cancel(err.clone());
                    }
                });
            }
            // Go: defer g.done() — { if g.sem != nil { <-g.sem }; g.wg.Done() }
            if let Some(s) = &sem {
                let _ = s.Recv();
            }
            inner.wg.Done();
        });
    }

    /// `(*Group).SetLimit(n)` — limit active goroutines to at most
    /// `n`. Negative = no limit; zero prevents any new goroutines.
    /// Must not be modified while any goroutines are active (panics,
    /// like Go).
    pub fn SetLimit(&self, n: int) {
        let mut sem = self.inner.sem.lock();
        if n < 0 {
            *sem = None;
            return;
        }
        if let Some(s) = &*sem {
            if s.Len() != 0 {
                panic!(
                    "errgroup: modify limit while {} goroutines in the group are still active",
                    s.Len()
                );
            }
        }
        *sem = Some(chan::<()>::new_buffered(n as usize));
    }
}
