// go: file sync/oncefunc.go decls: OnceFunc, OnceValue, OnceValues
//
// oncefunc.go — the Go 1.21+ once helpers.
//
// This file carried NO provenance anchors, like the rest of src/sync/.
//
// goish deviation: Go's wrappers RE-PANIC with the original value on
// every later call if f panicked, and clear their captured f so it can
// be collected. goish's runtime does not unwind on panic — a panicking
// goroutine runs its defers and dies — so there is no panic to capture
// and replay, and that half has no counterpart here. The
// exactly-once and value-caching halves are diffed against Go in
// examples/sync_once_ref_smoke.rs.
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

// go: sdk 1.25.5 sync/oncefunc.go:11-44 OnceFunc
/// Go: "OnceFunc returns a function that invokes f only once. The
/// returned function may be called concurrently."
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

// go: sdk 1.25.5 sync/oncefunc.go:80-113 OnceValues
/// Go: "OnceValues returns a function that invokes f only once and
/// returns the values returned by f. The returned function may be
/// called concurrently."
///
/// goish adds `T1: Clone`/`T2: Clone` so each caller receives an owned
/// copy of the cached pair, where Go hands back the same values.
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

// go: sdk 1.25.5 sync/oncefunc.go:46-78 OnceValue
/// Go: "OnceValue returns a function that invokes f only once and
/// returns the value returned by f. The returned function may be called
/// concurrently."
///
/// The cached value is held in an `Option`, not compared against the
/// zero value — a function that legitimately returns 0 must still be
/// computed exactly once.
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
