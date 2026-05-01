// sync::OnceFunc / OnceValue / OnceValues — Go 1.21+ helpers.
//
// Reference: /share/go/src/sync/oncefunc.go.
//
//   Go                                       goish
//   ─────────────────────────────────        ──────────────────────────────────
//   g := sync.OnceFunc(f)                    let g = sync::OnceFunc(f);
//   g(); g(); ...                            g(); g(); ...
//
//   v := sync.OnceValue(f)                   let v = sync::OnceValue(f);
//   x := v(); y := v(); ...                  let x = v(); let y = v();
//
//   p := sync.OnceValues(f)                  let p = sync::OnceValues(f);
//   x, y := p(); ...                         let (x, y) = p(); ...
//
// Slim deviation: Go re-panics with the same value on every call when
// `f` panics. Goish v1 doesn't capture/replay panics here — a
// panicking `f` either aborts the gor (panic="abort", default) or
// unwinds via the per-G cleanup path; subsequent callers will observe
// `Once.done == false` and try again. If callers need the
// "panic-once-then-poison" shape, wrap their own panic-handling
// around `OnceFunc`.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;

use super::{Mutex, Once};

/// `sync.OnceFunc(f)` (oncefunc.go:11) — return a closure that calls
/// `f` exactly once across all callers, racing them on the underlying
/// `Once`. Caller-side ergonomics match Go: the returned closure can
/// be passed around and invoked from any number of goroutines.
pub fn OnceFunc<F>(f: F) -> impl Fn() + Send + Sync + 'static
where
    F: FnOnce() + Send + 'static,
{
    // Go: d := struct { f func(); once Once; valid bool; p any }{f: f}
    // Slim: Once gates the run; Mutex<Option<F>> holds f until taken.
    // Both wrapped in Arc so the returned Fn (called repeatedly) can
    // re-share the inner state across calls.
    let once: Arc<Once> = Arc::new(Once::new());
    let slot: Arc<Mutex<Option<F>>> = Arc::new(Mutex::new(Some(f)));
    move || {
        let slot = slot.clone();
        // Go: d.once.Do(func() { ...; d.f(); ...; })
        once.Do(move || {
            // Go: d.f() then d.f = nil to drop f after invoking.
            let mut g = slot.Lock();
            if let Some(f) = g.take() {
                f();
            }
        });
    }
}

/// `sync.OnceValues(f)` (oncefunc.go:80) — return a closure that
/// invokes `f` exactly once and replays the produced `(T1, T2)`
/// pair on every subsequent call. Both `T1: Clone` and `T2: Clone`
/// so callers each receive an owned copy.
pub fn OnceValues<T1, T2, F>(f: F) -> impl Fn() -> (T1, T2) + Send + Sync + 'static
where
    T1: Clone + Send + 'static,
    T2: Clone + Send + 'static,
    F: FnOnce() -> (T1, T2) + Send + 'static,
{
    enum Slot<T1, T2, F> {
        Pending(F),
        Ready(T1, T2),
        Empty,
    }
    let once: Arc<Once> = Arc::new(Once::new());
    let slot: Arc<Mutex<Slot<T1, T2, F>>> = Arc::new(Mutex::new(Slot::Pending(f)));
    move || -> (T1, T2) {
        let slot = slot.clone();
        let s2 = slot.clone();
        // Go: d.once.Do(func() { d.r1, d.r2 = d.f(); ... })
        once.Do(move || {
            let mut g = slot.Lock();
            let cur = core::mem::replace(&mut *g, Slot::Empty);
            if let Slot::Pending(f) = cur {
                let (a, b) = f();
                *g = Slot::Ready(a, b);
            }
        });
        // Go: return d.r1, d.r2
        let g = s2.Lock();
        match &*g {
            Slot::Ready(a, b) => (a.clone(), b.clone()),
            _ => panic!("sync::OnceValues: producer didn't yield values"),
        }
    }
}

/// `sync.OnceValue(f)` (oncefunc.go:46) — return a closure that
/// invokes `f` exactly once and replays the produced value on every
/// subsequent call. `T: Clone` so callers can each receive an owned
/// copy of the cached result.
pub fn OnceValue<T, F>(f: F) -> impl Fn() -> T + Send + Sync + 'static
where
    T: Clone + Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    // Slim: keep f and result behind a single Mutex so the Once-guarded
    // run can transition from "have closure, no result" to
    // "no closure, have result" in one critical section.
    enum Slot<T, F> {
        Pending(F),
        Ready(T),
        Empty, // intermediate during transition.
    }
    let once: Arc<Once> = Arc::new(Once::new());
    let slot: Arc<Mutex<Slot<T, F>>> = Arc::new(Mutex::new(Slot::Pending(f)));
    move || -> T {
        let slot = slot.clone();
        let s2 = slot.clone();
        // Go: d.once.Do(func() { d.result = d.f(); ...; })
        once.Do(move || {
            let mut g = slot.Lock();
            let cur = core::mem::replace(&mut *g, Slot::Empty);
            if let Slot::Pending(f) = cur {
                let v = f();
                *g = Slot::Ready(v);
            }
        });
        // Go: return d.result
        let g = s2.Lock();
        match &*g {
            Slot::Ready(v) => v.clone(),
            // Pending is unreachable (Once.Do has run); Empty would mean
            // the producer panicked between replace and assign.  In slim
            // a panic inside f aborts the gor anyway — this branch is
            // defensive.
            _ => panic!("sync::OnceValue: producer didn't yield a value"),
        }
    }
}
