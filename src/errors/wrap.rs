// go: file errors/wrap.go decls: Unwrap, Is, is, As, as

// wrap.go — Unwrap, and the Is/As tree walks.
//
// goishlint:ignore GOISH021 errorType — Go caches
// `reflectlite.TypeOf((*error)(nil)).Elem()` so `As` can check
// assignability at runtime. goish's `As` is generic over the target
// type and resolves it at compile time, so there is no type value to
// cache.

extern crate alloc;
use alloc::sync::Arc;

use core::any::{Any, TypeId};

use super::*;

// ─── Is / Unwrap ────────────────────────────────────────────────────────

/// Marker-or-error dispatch trait used by `errors::Is`. Implemented
/// reflexively for `error` (cheap clone) and emitted per-sentinel by the
/// `goish::var!` macro for marker ZSTs (returns the lazily-cached Arc).
///
/// Distinct from `Borrow<error>` so call sites stay unambiguous: only
/// `error` and macro-emitted markers satisfy this bound, never user
/// types that happen to expose a `Borrow<error>` accidentally.
pub trait IsTarget {
    /// Resolve to an owned `error`. For markers, this triggers the
    /// lazy cache lookup and clones the cached Arc; for `error` itself,
    /// it clones (one atomic refcount bump).
    fn __resolve(&self) -> error;
}

impl IsTarget for error {
    // go: none — goish idiom: Go's `errors.Is(err, target)` takes two
    //     `error` values. goish's sentinels are Copy ZSTs emitted by
    //     `var!`, so the target arrives as either an `error` or a
    //     marker; this is the marker's resolve step, and this impl is
    //     the identity case.
    #[inline]
    fn __resolve(&self) -> error {
        return self.clone();
    }
}

// go: sdk 1.25.5 errors/wrap.go:44-51 Is
/// `errors.Is(err, target)` — reports whether any error in `err`'s TREE
/// matches `target`.
///
/// The tree is `err` itself followed by the errors obtained by
/// repeatedly calling `Unwrap() error` or `Unwrap() []error`. When an
/// error wraps several — `errors::Join`'s result — Is examines it and
/// then walks its children depth-first. This used to be a single chain
/// that stepped only through `Unwrap()`, so `Is(Join(a, b), b)` was
/// FALSE: the walk went to `a` and stopped.
///
/// An error also matches if it implements `Is(error) bool` and that
/// returns true for the target — see [`ErrorTrait::Is`].
///
/// Generic over `IsTarget` so call sites can pass either an `error`
/// value or a sentinel marker (Copy ZST emitted by `goish::var!`).
pub fn Is<T: IsTarget>(err: error, target: T) -> bool {
    let target: error = target.__resolve();
    // Go: if err == nil || target == nil { return err == target }
    if err == nil || target == nil {
        return err == target;
    }
    // Go computes `reflectlite.TypeOf(target).Comparable()` and skips
    // the `==` arm for a target that would panic on comparison — a
    // struct holding a slice, say. Every goish `error` is an Arc handle
    // and comparing two is a pointer test, which never panics, so the
    // flag is always true here and is not threaded through.
    return is(err, &target);
}

// go: sdk 1.25.5 errors/wrap.go:53-78 is
/// The tree walk behind [`Is`]. Iterative down the single-parent spine,
/// recursive across a multi-error's children — exactly Go's shape.
// goishlint:ignore GOISH023 — the body ends in an infinite `loop` whose
//     every exit is a `return` from inside it, so there is no tail
//     expression to make explicit. Go writes the same shape: `for { … }`
//     with returns in the body.
fn is(err: error, target: &error) -> bool {
    let mut cur = err;
    loop {
        if cur.__ptr_eq(target) {
            return true;
        }
        // Go: if x, ok := err.(interface{ Is(error) bool }); ok && x.Is(target)
        if let Some(e) = cur.0.as_ref() {
            if e.Is(target) {
                return true;
            }
        }
        let e = match cur.0.as_ref() {
            Some(e) => e.clone(),
            None => return false,
        };
        // Go's type switch prefers `Unwrap() error`; a type with the
        // multi form has no single one, so the two are exclusive.
        let multi = e.UnwrapMulti();
        if !multi.is_empty() {
            for child in multi.into_iter() {
                if is(child, target) {
                    return true;
                }
            }
            return false;
        }
        let next = e.Unwrap();
        if next == nil {
            return false;
        }
        cur = next;
    }
}

// go: sdk 1.25.5 errors/wrap.go:17-25 Unwrap
/// `errors.Unwrap(err)` — return the next error in the chain, or `nil`
/// if `err` doesn't wrap anything.
pub fn Unwrap(err: error) -> error {
    return match &err.0 {
        Some(e) => e.Unwrap(),
        None => nil,
    };
}

// ─── As ─────────────────────────────────────────────────────────────────

// go: sdk 1.25.5 errors/wrap.go:97-114 As
/// `errors.As(err)` — finds the first error in `err`'s chain whose
/// concrete type is `T` and returns it.
///
/// Slim: Go's signature `As(err error, target any) bool` uses
/// reflection to mutate a caller-supplied target pointer. Goish
/// returns `Option<Arc<T>>` instead — idiomatic Rust, same effect.
/// The caller writes:
///
/// ```ignore
/// if let Some(pe) = errors::As::<ParseError>(err) {
///     /* use pe.line / pe.col */
/// }
/// ```
///
/// Slim deviations:
///   * No `As(any) bool` method on the error type — goish doesn't have
///     a `Box<dyn Any>`-shaped target, so the "error provides custom
///     As" extension point is omitted.
///
/// The tree IS walked: a `T` inside an `errors::Join` is found, through
/// [`ErrorTrait::UnwrapMulti`].
pub fn As<T: ErrorTrait>(err: error) -> Option<Arc<T>> {
    if err == nil {
        return None;
    }
    return as_(err);
}

// go: sdk 1.25.5 errors/wrap.go:116-145 as
// goishlint:ignore GOISH014 - the anchor names the GO symbol, `as`, which is a Rust keyword; the port is `as_`.
/// The tree walk behind [`As`]. Same shape as [`is`]: iterative down the
/// single-parent spine, recursive across a multi-error's children. It
/// used to walk only `Unwrap()`, so `As::<T>(Join(a, b))` could not find
/// a `T` sitting in `b`.
// goishlint:ignore GOISH023 — the body ends in an infinite `loop` whose
//     every exit is a `return` from inside it, so there is no tail
//     expression to make explicit. Go writes the same shape: `for { … }`
//     with returns in the body.
fn as_<T: ErrorTrait>(err: error) -> Option<Arc<T>> {
    let mut cur = err;
    loop {
        // Go: if reflectlite.TypeOf(err).AssignableTo(targetType)
        if let Some(arc) = cur.0.as_ref() {
            let dyn_ref: &dyn ErrorTrait = arc.as_ref();
            if (dyn_ref as &dyn Any).type_id() == TypeId::of::<T>() {
                // SAFETY: the type id matches, so the data behind the
                // fat pointer is a `T`. Convert Arc<dyn ErrorTrait> →
                // Arc<T> by stripping the vtable from the fat pointer.
                let arc_clone = arc.clone();
                let raw = Arc::into_raw(arc_clone) as *const T;
                return Some(unsafe { Arc::from_raw(raw) });
            }
        }
        let e = match cur.0.as_ref() {
            Some(e) => e.clone(),
            None => return None,
        };
        let multi = e.UnwrapMulti();
        if !multi.is_empty() {
            for child in multi.into_iter() {
                if let Some(found) = as_::<T>(child) {
                    return Some(found);
                }
            }
            return None;
        }
        let next = e.Unwrap();
        if next == nil {
            return None;
        }
        cur = next;
    }
}

// ─── AsIface ────────────────────────────────────────────────────────

// go: none — goish idiom: Go writes an interface assertion on an error
//     directly — `if t, ok := err.(interface{ Timeout() bool }); ok` —
//     because a Go `error` IS the interface value and asserting on it
//     reaches the concrete type underneath.
//
//     goish's `error` is a HANDLE around `Arc<dyn ErrorTrait>`, and
//     `cast!` downcasts whatever it is handed. Handed an `error` it
//     asks the registry for `TypeId::of::<error>()`, which nothing ever
//     registers, so the assertion MISSES — silently, and for every
//     error. `net::OpError::Timeout` was written that way and had never
//     once returned true.
//
//     This is that assertion, spelled so it reaches through the handle.
//     Like Go's, it looks at the error ITSELF and does not walk the
//     chain: `errors::As` and `errors::Is` are the walking ones.
/// Go's `v, ok := err.(SomeInterface)` — assert an interface on the
/// concrete error behind the handle.
///
/// Returns `(&T, true)` on a hit. On a miss the first element is the
/// process-wide nil sentinel for `T`, and calling a method on it panics
/// exactly as a method call on Go's nil interface does — so a guarded
/// `if ok { … }` is the safe, Go-faithful use, the same contract
/// [`crate::cast!`] has.
///
/// The concrete type must be registered for `T` —
/// `__goish_register_<T>_impl::<Concrete>()` — or this misses. That is
/// the same requirement `cast!` carries.
pub fn AsIface<T>(err: &error) -> (&T, bool)
where
    T: ?Sized + crate::goany::DowncastableFromAny + crate::goany::NilDyn,
{
    if let Some(arc) = err.0.as_ref() {
        let dyn_err: &dyn ErrorTrait = arc.as_ref();
        let any_ref: &(dyn Any + Send + Sync) = dyn_err;
        if let Some(v) = T::from_any(any_ref) {
            return (v, true);
        }
    }
    return (T::__goish_nil_ref(), false);
}
