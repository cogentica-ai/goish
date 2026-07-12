//! `goish::Any` — Go's `interface{}` (a.k.a. `any`).
//!
//! Newtype around `Arc<dyn core::any::Any + Send + Sync>`. The wrap
//! exists for one specific reason: **to give the type a `Default`
//! impl that doesn't violate the orphan rule**. Rust's coherence
//! refuses `impl Default for Arc<dyn Any+Send+Sync>` because both
//! `Arc` and `Any` are foreign — `Any` (this newtype) is local, so
//! we can land Default plus any other crate-defined trait impls
//! (`From<T>`, `MustAs`, …) cleanly.
//!
//! Layout: `#[repr(transparent)]` — `Any` and the inner Arc have
//! identical ABI / size / alignment. We don't currently exploit
//! that with explicit transmutes, but the guarantee keeps the door
//! open for forwarding through-the-wrap with zero runtime cost
//! later.
//!
//! ## Why a newtype, not a type alias
//!
//! A type alias (`pub type Any = Arc<dyn Any+Send+Sync>`) would
//! still hit the orphan rule for Default. The newtype is the
//! cheapest path to a complete trait surface.
//!
//! ## What lives on `Any`
//!
//! - `Default::default()` → `Any` wrapping `__NilMarker` (the
//!   distinguished "this came from `nil`" sentinel; matches the
//!   nil-equality contract in nilval.rs).
//! - `Any::new<T>(v)` → upcast any `T: 'static + Send + Sync` to
//!   `Any`.
//! - `Any::As<T>()` / `Any::MustAs<T>()` → downcast (Option / panic).
//! - `Any::IsNil()` → recognises the `nil`-shape (matches nilval.rs's
//!   `__NilMarker` / `()` predicates).
//! - `From<Nil>` → bare `nil.into()` produces `Any`.
//! - `PartialEq<Nil>` → `if x == nil` works on Any-typed bindings.
//!
//! Format and Reflect impls live in their respective modules
//! (fmt/mod.rs, reflect/mod.rs) and forward through `.0`.
//!
//! ## Migration from `Arc<dyn Any+Send+Sync>`
//!
//! The transpiler's `interface{}` lowering used to spell as
//! `alloc::sync::Arc<dyn core::any::Any + Send + Sync>` directly;
//! it now spells as `goish::Any`. Every existing impl living on the
//! raw Arc form is mirrored here so call-site behaviour stays
//! identical.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::sync::Arc;
use core::any::Any as CoreAny;

use crate::nilval::{nil, Nil};

// ─────────────────────────────────────────────────────────────────────
// AnyVal — `dyn Any` extended with type-erased equality
// ─────────────────────────────────────────────────────────────────────
//
// Go's `interface{} == interface{}` compares dynamic type + dynamic
// value. Plain `core::any::Any` only carries the type (via TypeId), not
// the value comparator — Rust's coherence rejects a blanket
// `PartialEq<Any> for dyn Any` because there's no way to discharge the
// stored value's PartialEq without specialization.
//
// `AnyVal` solves this by baking a `dyn_eq` method into the vtable. The
// blanket impl over `T: 'static + Send + Sync + PartialEq` discharges
// the bound at the call site (every value stored in `Any` must be
// PartialEq) and supplies a TypeId-gated equality check.
//
// Non-comparable Go types (slices, maps, funcs) need bespoke PartialEq
// impls before they can flow through `Any`. Matches Go's compile-time
// check at `==` sites, except Goish moves the rejection to
// `Any::new<T>` instead of the equality site — earlier and more
// precise.

/// Storage trait for `goish::Any`'s inner Arc. Combines `core::any::Any`
/// (for TypeId + downcast) with a `dyn_eq` slot that drives
/// `PartialEq<Any> for Any`. Blanket-impl'd over any
/// `T: 'static + Send + Sync + PartialEq` — every concrete type
/// emitted through the transpiler's `interface{}` lowering satisfies
/// this once its struct derives PartialEq (which Goish ports already
/// do for Go-struct equality).
pub trait AnyVal: 'static + Send + Sync {
    /// View as `&(dyn Any + Send + Sync)` — what the downcast and
    /// trait-registry machinery already consume.
    fn __any_send_sync(&self) -> &(dyn CoreAny + Send + Sync);

    /// View as `&mut dyn Any` — `MustAsMut` drives in-place
    /// `downcast_mut::<T>()` through this.
    fn __any_mut(&mut self) -> &mut dyn CoreAny;

    /// Type-erased equality. Returns true iff `other`'s dynamic type
    /// matches `Self` AND the values are PartialEq-equal. Symmetric
    /// because identical TypeIds drive both directions through the
    /// same concrete `eq`.
    fn dyn_eq(&self, other: &dyn CoreAny) -> bool;

    /// The concrete value's type name (`core::any::type_name::<T>()`),
    /// captured at wrap time. Backs `fmt`'s `%T` (Go's
    /// `fmt.Sprintf("%T", v)`). Best-effort: it is the Rust type path
    /// (e.g. `"alloc::string::String"`), not Go's name (`"string"`) —
    /// diagnostic-grade, like Go's own `%T` string.
    fn __goish_type_name(&self) -> &'static str;
}

impl<T: 'static + Send + Sync + PartialEq> AnyVal for T {
    #[inline]
    fn __any_send_sync(&self) -> &(dyn CoreAny + Send + Sync) {
        self
    }

    #[inline]
    fn __any_mut(&mut self) -> &mut dyn CoreAny {
        self
    }

    #[inline]
    fn dyn_eq(&self, other: &dyn CoreAny) -> bool {
        match other.downcast_ref::<T>() {
            Some(o) => self == o,
            None => false,
        }
    }

    #[inline]
    fn __goish_type_name(&self) -> &'static str {
        core::any::type_name::<T>()
    }
}

/// `interface{}` / `any`. See module docs.
#[repr(transparent)]
pub struct Any(pub(crate) Arc<dyn AnyVal>);

impl Clone for Any {
    #[inline]
    fn clone(&self) -> Self {
        Any(Arc::clone(&self.0))
    }
}

impl Any {
    /// Wrap an owned value of any
    /// `T: 'static + Send + Sync + PartialEq`. The PartialEq bound
    /// powers `PartialEq<Any> for Any`; types that lack it cannot
    /// flow through `Any` — matches Go's "comparing uncomparable" check
    /// (slices, maps, funcs) but moves the rejection from the `==`
    /// site to the wrap site.
    #[inline]
    pub fn new<T: 'static + Send + Sync + PartialEq>(value: T) -> Self {
        Any(Arc::new(value))
    }

    /// Wrap a function-shaped value (typically `Arc<dyn Fn(...) -> R +
    /// Send + Sync>`) into `Any` without requiring `PartialEq`. Go's
    /// `func` values are non-comparable except against `nil`; the
    /// emitted Goish-side `dyn_eq` follows that contract — two
    /// `Any`-wrapped fn values always compare unequal to each other.
    ///
    /// The transpiler routes here at every "fn-item / closure
    /// flowing into an `Any` slot" site. Manual callers reach for it
    /// when storing closures in `map<K, goish::Any>` or `slice<goish::
    /// Any>` — anywhere `Any::new` would otherwise demand `PartialEq`
    /// on a type that has no comparable shape.
    #[inline]
    pub fn new_fn<T: 'static + Send + Sync>(value: T) -> Self {
        Any(Arc::new(__FnSlot(value)))
    }

    /// `&dyn Any` borrow at the inner Arc. Used by Format / Reflect
    /// forwarders and by the type-assertion lowering.
    #[inline]
    pub fn as_any(&self) -> &(dyn CoreAny + Send + Sync) {
        self.0.__any_send_sync()
    }

    /// Goish equivalent of Go's comma-ok type assertion `v, ok := x.(T)`.
    /// Returns `Some(&T)` when the wrapped value's runtime type is `T`.
    ///
    /// Two specialisations through `DowncastableFromAny`:
    ///
    /// * `T: Sized + 'static` — goes via `Any::downcast_ref::<T>()`.
    /// * `T = dyn Trait` (unsized) — consults the per-trait registry
    ///   that `#[goish::interface]` emits. Returns `Some(&dyn Trait)`
    ///   iff the wrapped value's concrete type was registered as
    ///   implementing `Trait`.
    ///
    /// Foundation: open-world type-class lookup. Each
    /// `impl Trait for Concrete` registers via
    /// `goish::any::register_trait_impl::<Trait, Concrete>()` so the
    /// `&dyn Any → &dyn Trait` cast is available at runtime. Mirrors
    /// Go's structural-interface satisfaction (assertion `x.(I)`) within
    /// Rust's nominal trait system.
    #[inline]
    pub fn As<T: ?Sized + DowncastableFromAny>(&self) -> Option<&T> {
        T::from_any(self.as_any())
    }

    /// Mut-borrow downcast — panics on miss OR if the Arc is shared
    /// (refcount > 1). Mirrors `nilable<T>::MustMut` semantics: the
    /// caller asserts both that the dynamic type is T and that no
    /// other handle aliases the same allocation. Used by the
    /// transpiler's lowering of Go's `x.(map[K]V)[k] = v` shape — the
    /// type-assertion-then-index-assign pattern needs `&mut map<K,V>`
    /// to drive `Set`, which `MustAs` (returning `&T`) can't provide.
    ///
    /// Goish-shared-mutation rule: shared `interface{}` values can't
    /// yield `&mut T` directly without breaking Arc aliasing. Wrap T
    /// in `sync::Mutex` for shared mutation, or guarantee uniqueness
    /// at the call site (which the gojsonpointer pattern does — the
    /// map is held only by the slice element being indexed).
    #[inline]
    #[track_caller]
    pub fn MustAsMut<T: 'static + Send + Sync + PartialEq>(&mut self) -> &mut T {
        let inner: &mut dyn AnyVal = Arc::get_mut(&mut self.0)
            .expect(
                "interface conversion: Any is shared (refcount > 1) — \
                 mutation through MustAsMut requires unique ownership",
            );
        inner.__any_mut().downcast_mut::<T>().unwrap_or_else(|| {
            panic!(
                "interface conversion: any is not {}",
                core::any::type_name::<T>()
            )
        })
    }

    /// Goish equivalent of Go's must-form type assertion `x.(T)` —
    /// panics on miss with a Go-shape diagnostic. The `interface
    /// conversion: …` text matches Go's runtime panic so log output
    /// reads naturally for ports.
    #[inline]
    pub fn MustAs<T: 'static>(&self) -> &T {
        self.As::<T>().unwrap_or_else(|| {
            panic!(
                "interface conversion: any is not {}",
                core::any::type_name::<T>()
            )
        })
    }

    /// Concrete type name of the wrapped value — backs `fmt`'s `%T`
    /// (Go's `fmt.Sprintf("%T", v)` / `reflect.TypeOf(v).String()`).
    /// Captured at wrap time via `core::any::type_name`; best-effort
    /// Rust path, not Go's spelling (see `AnyVal::__goish_type_name`).
    #[inline]
    pub fn TypeName(&self) -> &'static str {
        self.0.__goish_type_name()
    }

    /// Comma-ok type assertion — Goish equivalent of Go's `v, ok := x.(T)`.
    /// Returns owned T plus true on success; returns `T::default()` plus
    /// false on miss. Requires `T: Default + Clone` so the false branch
    /// can yield T's zero value (mirroring Go's interface-assertion
    /// contract) and the true branch can materialise owned T from the
    /// borrow returned by `As`. Only emitted by the transpiler for
    /// concrete T — trait-object targets stay on `As` (their false
    /// branch has no zero value).
    #[inline]
    pub fn AsTuple<T: 'static + Default + Clone + DowncastableFromAny>(&self) -> (T, bool) {
        match self.As::<T>() {
            Some(v) => (v.clone(), true),
            None => (T::default(), false),
        }
    }

    /// True iff this `Any` was produced from `nil` (or is the
    /// equivalent zero-value `()`-payload). The payload check is
    /// `is::<Nil>()` — there's exactly one nil sentinel type
    /// (`Nil` from nilval), shared by every nil-shape construction
    /// path in the crate.
    #[inline]
    pub fn IsNil(&self) -> bool {
        let any = self.as_any();
        any.is::<Nil>() || any.is::<()>()
    }
}

impl PartialEq<Any> for Any {
    /// Go's `interface{} == interface{}` — same dynamic type AND equal
    /// dynamic values. Dispatched through the inner Arc's `dyn_eq`
    /// vtable, which the blanket impl pins to the wrapped type's
    /// PartialEq. Asymmetric-TypeId comparisons return false (Go's
    /// behavior — interfaces of different dynamic types compare unequal
    /// even when their values "look" similar).
    #[inline]
    fn eq(&self, other: &Any) -> bool {
        self.0.dyn_eq(other.as_any())
    }
}

/// Default → wraps `Nil`, the universal nil sentinel. Matches the
/// `From<Nil>` payload exactly so partially-keyed struct literals
/// fill `Any` fields with the same value `nil.into()` produces.
impl Default for Any {
    #[inline]
    fn default() -> Self {
        Any(Arc::new(nil))
    }
}

/// Bare `nil` → `Any` via `nil.into()` at return / let / struct-field
/// positions. Matches nilval.rs's `From<Nil> for Arc<dyn Any+...>`.
impl From<Nil> for Any {
    #[inline]
    fn from(_: Nil) -> Self {
        Any(Arc::new(nil))
    }
}

impl PartialEq<Nil> for Any {
    #[inline]
    fn eq(&self, _: &Nil) -> bool {
        self.IsNil()
    }
}

impl PartialEq<Any> for Nil {
    #[inline]
    fn eq(&self, other: &Any) -> bool {
        other.IsNil()
    }
}

// Nil-shape sentinel: `Nil` itself (from nilval.rs). All `From<Nil>`
// paths land `Arc::new(nil)`, all IsNil predicates probe `is::<Nil>()`
// — single nil semantics, no auxiliary marker types.

// ─────────────────────────────────────────────────────────────────────
// __FnSlot — `Any::new_fn` payload wrapper
// ─────────────────────────────────────────────────────────────────────
//
// Backing storage for `Any::new_fn`. Wraps any
// `T: 'static + Send + Sync` (no PartialEq) and supplies a custom
// `AnyVal` impl that:
//
//   1. Forwards `__any_send_sync` / `__any_mut` to the inner value,
//      so `Any::As::<T>()`, reflect::ValueOf, and every other
//      `downcast_ref`-based consumer sees the bare `T` (the
//      `__FnSlot` wrapper is transparent at the dyn-Any surface).
//   2. Stamps `dyn_eq` to always return false — matching Go's
//      contract that func values are not comparable except against
//      nil. The blanket `impl AnyVal for T: PartialEq` is bypassed
//      because `T` here has no PartialEq.
//
// Public surface: `goish::Any::new_fn(value)`. The transpiler routes
// fn-item lifts through `new_fn`; manual callers reach for it when
// storing closures in `Any`. Callers never see __FnSlot — it's an
// internal storage detail.
#[doc(hidden)]
pub struct __FnSlot<T: 'static + Send + Sync>(pub T);

impl<T: 'static + Send + Sync> AnyVal for __FnSlot<T> {
    /// Expose the inner T — `downcast_ref::<T>()` sees it directly
    /// so reflect / type-assertion paths work without seeing the
    /// __FnSlot wrapper.
    #[inline]
    fn __any_send_sync(&self) -> &(dyn CoreAny + Send + Sync) {
        &self.0
    }

    /// Inner-T mut view. Mirrors the blanket AnyVal impl's
    /// downcast_mut handoff — drives `Any::MustAsMut::<T>()` for
    /// fn-typed slots (rare; included for parity).
    #[inline]
    fn __any_mut(&mut self) -> &mut dyn CoreAny {
        &mut self.0
    }

    /// Go semantics: func values are non-comparable except against
    /// nil. Two `Any`-wrapped fn values always compare unequal.
    #[inline]
    fn dyn_eq(&self, _other: &dyn CoreAny) -> bool {
        false
    }

    /// Name the inner `T` (what `__any_send_sync` exposes), not the
    /// `__FnSlot` wrapper — keeps `%T` consistent with downcast/reflect.
    #[inline]
    fn __goish_type_name(&self) -> &'static str {
        core::any::type_name::<T>()
    }
}

// ─────────────────────────────────────────────────────────────────────
// DowncastableFromAny — helper trait for `Any::As<T>`
// ─────────────────────────────────────────────────────────────────────

/// Witnesses that `Self` can be extracted from a `&dyn CoreAny + Send +
/// Sync`. Two impl families:
///
/// 1. **Blanket `impl<T: 'static + Sized>`** — concrete struct/enum
///    targets via `CoreAny::downcast_ref::<T>()`.
///
/// 2. **Per-trait `impl DowncastableFromAny for dyn UserTrait`** emitted
///    by `#[goish::interface]`. Consults a registry populated by
///    `register_trait_impl::<UserTrait, Concrete>()` calls (one per
///    `impl UserTrait for Concrete` in the program). Returns
///    `Some(&dyn UserTrait)` when the wrapped value's concrete type
///    was registered.
///
/// Coherence: the blanket requires `Sized`; `dyn Trait: !Sized` so the
/// per-trait impls don't overlap. Matches Rust 1.70+'s coherence rules
/// (no negative impls needed).
pub trait DowncastableFromAny: 'static {
    /// Try to view a `&dyn Any+Send+Sync` as `&Self`. Returns `None`
    /// when the wrapped concrete type doesn't match (or, for trait
    /// targets, isn't registered as implementing `Self`).
    fn from_any(any_ref: &(dyn CoreAny + Send + Sync)) -> Option<&Self>;
}

impl<T: 'static + Sized> DowncastableFromAny for T {
    #[inline]
    fn from_any(any_ref: &(dyn CoreAny + Send + Sync)) -> Option<&Self> {
        any_ref.downcast_ref::<T>()
    }
}

/// Mutable mirror of [`DowncastableFromAny`]. Drives the `&mut` arm of
/// the interface assertion — `cast!(&mut *box, J)` — recovering a
/// `&mut Self` from a `&mut dyn Any`. Two impl families, symmetric to
/// the immutable trait: a `Sized` blanket via `downcast_mut`, and the
/// per-trait impl emitted by `#[goish::interface]` routing through the
/// trait's mutable registry lookup.
///
/// Returns `Option` (not the nil-sentinel tuple `cast!` uses for the
/// immutable form): there is no sound shared `&'static mut` nil, and
/// `&mut` is exclusive, so the honest miss value is `None`.
pub trait DowncastableFromAnyMut: 'static {
    /// Try to view a `&mut (dyn Any + Send + Sync)` as `&mut Self`.
    fn from_any_mut(any_ref: &mut (dyn CoreAny + Send + Sync)) -> Option<&mut Self>;
}

impl<T: 'static + Sized> DowncastableFromAnyMut for T {
    #[inline]
    fn from_any_mut(any_ref: &mut (dyn CoreAny + Send + Sync)) -> Option<&mut Self> {
        any_ref.downcast_mut::<T>()
    }
}

// ─────────────────────────────────────────────────────────────────────
// HasDynAny + AsExt — `<thing>.As::<T>()` on borrowed-trait carriers
// ─────────────────────────────────────────────────────────────────────

/// Witnesses that `Self` exposes a `&dyn Any + Send + Sync` view.
/// Two impl families:
///
/// 1. **Blanket `impl<T: 'static + Sized + Send + Sync>`** — concrete
///    sized types upcast directly via subtype coercion.
///
/// 2. **Per-trait `impl HasDynAny for dyn Trait + Send + Sync`**
///    emitted by `#[goish::interface]`. Routes through the trait's
///    `__as_dyn_any` method (also added by the macro, default body
///    returns `None`). Concrete impls override the default to return
///    `Some(self)` — the transpiler emits this override at every
///    `impl Trait for ConcreteStruct` site.
///
/// Why not Any-as-supertrait: adding `core::any::Any` as a supertrait
/// of every user trait would require `Self: 'static`, which breaks
/// common forwarding impls like
/// `impl<R: Reader + ?Sized> Reader for &mut R` (the borrow lifetime
/// isn't 'static). Routing through a trait method with a default body
/// avoids the constraint while still letting concrete impls expose
/// their Any view.
pub trait HasDynAny {
    /// Returns the wrapped value's `&dyn Any` view when the concrete
    /// type registered one. Default is `None` (the type is opaque
    /// from the Any-perspective). Concrete impls of
    /// `#[goish::interface]`-decorated traits override to `Some(self)`.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn CoreAny + Send + Sync)>;
}

impl<T: 'static + Sized + Send + Sync> HasDynAny for T {
    #[inline]
    fn __goish_as_dyn_any(&self) -> Option<&(dyn CoreAny + Send + Sync)> {
        Some(self)
    }
}

/// Mutable mirror of [`HasDynAny`] — exposes a `&mut dyn Any` view.
/// Same two impl families: a `Sized` blanket returning `Some(self)`,
/// and the per-trait `impl HasDynAnyMut for dyn Trait + Send + Sync`
/// emitted by `#[goish::interface]`, which routes through the trait's
/// `__goish_as_dyn_any_mut` method (default `None`; concrete impls
/// override to `Some(self)`, emitted at every `impl Trait for C` site
/// alongside the `__goish_as_dyn_any` override).
pub trait HasDynAnyMut {
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn CoreAny + Send + Sync)>;
}

impl<T: 'static + Sized + Send + Sync> HasDynAnyMut for T {
    #[inline]
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn CoreAny + Send + Sync)> {
        Some(self)
    }
}

/// Blanket extension that makes `.As::<T>()` available on any borrowed
/// carrier that exposes a `&dyn Any` view via `HasDynAny`. Drives Go's
/// interface-borrow downcast `b, ok := rd.(*Reader)` where rd is
/// `&mut dyn io::Reader` — the transpiler emits `rd.As::<Reader>()`,
/// and method resolution picks AsExt's impl (the inherent `Any::As`
/// lives on `goish::Any`, the newtype, and takes precedence on that
/// exact type).
///
/// Naming: `As` (capital, Goish-style) keeps the surface uniform with
/// `goish::Any::As<T>`. Method-resolution priority:
///
///   1. Inherent `Any::As<T>` on the newtype `goish::Any` — wins for
///      that exact receiver.
///   2. AsExt::As<T> blanket — wins for `&dyn Trait` borrows and bare
///      concrete types alike.
pub trait AsExt {
    /// `Some(&T)` when the wrapped value's runtime type is `T`. For
    /// `T = dyn Trait`, consults the per-trait registry populated by
    /// `__goish_register_<trait>_impl::<Concrete>()` calls. For a
    /// Sized + 'static `T`, falls through to `downcast_ref::<T>()`.
    fn As<T: ?Sized + DowncastableFromAny>(&self) -> Option<&T>;
}

impl<U> AsExt for U
where
    U: ?Sized + HasDynAny,
{
    #[inline]
    fn As<T: ?Sized + DowncastableFromAny>(&self) -> Option<&T> {
        let any_ref = self.__goish_as_dyn_any()?;
        T::from_any(any_ref)
    }
}

/// Mutable mirror of [`AsExt`] — `.AsMut::<T>()` on any carrier that
/// exposes a `&mut dyn Any` view via [`HasDynAnyMut`]. Backs the
/// `cast!(&mut *box, J)` arm. `AsMut` (PascalCase) is distinct from
/// `core::convert::AsMut::as_mut`, so there is no method-resolution
/// clash.
pub trait AsExtMut {
    /// `Some(&mut T)` when the wrapped value's runtime type is `T`. For
    /// `T = dyn Trait`, consults the per-trait registry via
    /// `DowncastableFromAnyMut::from_any_mut`.
    fn AsMut<T: ?Sized + DowncastableFromAnyMut>(&mut self) -> Option<&mut T>;
}

impl<U> AsExtMut for U
where
    U: ?Sized + HasDynAnyMut,
{
    #[inline]
    fn AsMut<T: ?Sized + DowncastableFromAnyMut>(&mut self) -> Option<&mut T> {
        let any_ref = self.__goish_as_dyn_any_mut()?;
        T::from_any_mut(any_ref)
    }
}

// ─────────────────────────────────────────────────────────────────────
// NilDyn + type_assert! backing — Go's comma-ok interface assertion
// ─────────────────────────────────────────────────────────────────────

/// Compile-time witness that a `#[goish::interface]`-decorated trait
/// has a full nil sentinel (i.e. its supertrait clause contains only
/// `Send`/`Sync` markers, no foreign traits).
///
/// Emitted by the macro alongside every decorated trait. The
/// `cast!` macro const-asserts on this before calling
/// `__cast_iface`; traits with composite supertraits (e.g.
/// `Object: metav1::Object + runtime::Object`) set this to `false`,
/// causing `cast!` to emit a clear compile-time error directing the
/// user to `AsExt::As::<ConcreteType>()` instead.
#[doc(hidden)]
pub trait __HasNilSentinel {
    const __GOISH_HAS_NIL_SENTINEL: bool;
}

/// Backs the false branch of a comma-ok interface type assertion
/// (`let (v, ok) = goish::cast!(x, Iface)` — Go's
/// `v, ok := x.(Iface)`). When the downcast misses, `v` is bound to
/// this process-wide nil interface value: every method panics with
/// `"method call on nil <Iface> interface"`, exactly as invoking a
/// method on Go's nil interface does.
///
/// `#[goish::interface]` emits the `impl NilDyn for dyn Trait` for
/// every interface; the body hands back a `&'static` borrow of the
/// trait's zero-sized nil sentinel (`__Nil<Trait>`).
pub trait NilDyn {
    /// The process-wide nil interface value of type `Self`.
    fn __goish_nil_ref() -> &'static Self;
}

/// Runtime backing for the `cast!` macro — Go's comma-ok interface
/// type assertion `v, ok := x.(Iface)`.
///
/// `carrier` is the interface value being asserted: a `&dyn Trait`
/// borrow, or `&goish::Any`. On a hit returns `(&Target, true)`; on a
/// miss `(<nil Target>, false)` — the nil value coming from
/// [`NilDyn`], so a guarded `if ok { v.M() }` is safe and an
/// unguarded call panics like Go's nil-interface-method call.
#[inline]
pub fn __cast_iface<'a, Target, Carrier>(
    carrier: &'a Carrier,
) -> (&'a Target, bool)
where
    Target: ?Sized + DowncastableFromAny + NilDyn,
    Carrier: ?Sized + HasDynAny,
{
    match AsExt::As::<Target>(carrier) {
        Some(v) => (v, true),
        None => (Target::__goish_nil_ref(), false),
    }
}

/// Runtime backing for the `cast!(&mut x, Iface)` macro arm — the
/// mutable interface assertion. Returns `Some(&mut Target)` on a hit,
/// `None` on a miss. No nil sentinel: `&mut` is exclusive, so the only
/// honest miss value is `None` (guard with `if let Some(..)`).
///
/// Only type-checks where the carrier is uniquely borrowed (`&mut dyn
/// Trait`, owned `Box`, or `Any` with refcount 1) — Rust enforces the
/// aliasing discipline Go leaves to the programmer.
#[inline]
pub fn __cast_iface_mut<'a, Target, Carrier>(
    carrier: &'a mut Carrier,
) -> Option<&'a mut Target>
where
    Target: ?Sized + DowncastableFromAnyMut,
    Carrier: ?Sized + HasDynAnyMut,
{
    AsExtMut::AsMut::<Target>(carrier)
}

/// Consume `Box<dyn Trait>` (or `Box<U>` for any `U: HasDynAny`) and
/// extract the underlying concrete `T` when the runtime type matches.
/// Returns the box unchanged on miss. This is the consuming counterpart
/// to `AsExt::As`, needed for Go's `b, ok := rd.(*T); if ok { return b }`
/// pattern where the receiver must escape the type-assert as an owned
/// `T` (then re-wrapped in `nilable<T>`).
///
/// Why this isn't just `AsExt::As` + manual unwrap: `As` returns a
/// borrow tied to the box's lifetime — sound for read-only access but
/// can't yield an owned `T`. This helper does the safe pointer dance:
///
///   1. Probe `__goish_as_dyn_any` to verify `TypeId::of::<T>()` matches.
///   2. Extract the data pointer from the fat pointer via `*mut U as
///      *mut ()`. Per the Rust reference, casting `*mut dyn Trait` to
///      `*mut ()` extracts the data half of the fat pointer.
///   3. Reinterpret as `*mut T`. Sound because step 1 verified
///      identity.
///
/// Object-safety: only constraints are `T: 'static + Send + Sync` so
/// the recovered value carries the same Send/Sync bounds the box did.
#[inline]
pub fn try_consume_box<U, T>(b: alloc::boxed::Box<U>) -> Result<T, alloc::boxed::Box<U>>
where
    U: ?Sized + HasDynAny,
    T: 'static + Send + Sync,
{
    use core::any::TypeId;
    let matches = b
        .__goish_as_dyn_any()
        .map(|a| a.type_id() == TypeId::of::<T>())
        .unwrap_or(false);
    if !matches {
        return Err(b);
    }
    let raw: *mut U = alloc::boxed::Box::into_raw(b);
    let data_ptr: *mut T = raw as *mut () as *mut T;
    // SAFETY: step 1 verified TypeId equality, so the layout at
    // `data_ptr` is exactly that of `T`. We reconstruct the Box and
    // move the value out. The original Box's allocator and metadata
    // are abandoned via into_raw — Box::from_raw takes ownership of
    // the same allocation. Since *mut U and *mut T point to the same
    // bytes (per fat-pointer data half == thin pointer for the
    // concrete type), the Box::from_raw->deref->move pattern is sound.
    Ok(*unsafe { alloc::boxed::Box::from_raw(data_ptr) })
}

// ─────────────────────────────────────────────────────────────────────
// Trait-impl registry for `Any::As::<dyn Trait>()`
// ─────────────────────────────────────────────────────────────────────
//
// Per-trait static — each `#[goish::interface]` expansion creates a
// `static __<TRAIT>_PROBES: TraitRegistry<dyn Trait+Send+Sync>` and a
// `register_<trait>_impl::<Concrete>()` helper. The `from_any` impl
// scans that static.
//
// Per-trait separation is needed because the cast fn signature is
// trait-specific (returns `&dyn Trait+Send+Sync`, a fat pointer with
// a Trait-specific vtable). A trait-agnostic registry storing
// `*const ()` would lose the vtable on cast.

use core::any::TypeId;
use crate::runtime::spin::SpinLock;
use alloc::vec::Vec;

/// Per-concrete-impl probe entry within a single trait's registry.
/// `cast` reads `&(dyn Any + Send + Sync)` and returns `&Trait`
/// (a fat pointer with Trait's vtable). Trait-specific because the
/// vtable layout is trait-specific.
///
/// The macro emits one `TraitRegistry<dyn Trait+Send+Sync>` per
/// `#[goish::interface]`-decorated trait.
#[doc(hidden)]
pub struct TraitProbe<Trait: ?Sized + 'static> {
    pub concrete: TypeId,
    pub cast: fn(&(dyn CoreAny + Send + Sync)) -> &Trait,
    /// Mutable cast — the `&mut` mirror of `cast`. Backs
    /// `cast!(&mut x, Trait)` via `lookup_mut`. Emitted by the macro
    /// alongside `cast`.
    pub cast_mut: fn(&mut (dyn CoreAny + Send + Sync)) -> &mut Trait,
}

/// Per-trait registry. The macro creates a `static`
/// `SpinLock<TraitRegistry<dyn Trait + Send + Sync>>` and exposes a
/// `register_<trait>_impl(probe)` free function. The `from_any` impl
/// for `dyn Trait + Send + Sync` scans this registry.
#[doc(hidden)]
pub struct TraitRegistry<Trait: ?Sized + 'static> {
    pub probes: Vec<TraitProbe<Trait>>,
}

impl<Trait: ?Sized + 'static> TraitRegistry<Trait> {
    /// `const fn` so the macro can put one in a `static` slot.
    pub const fn new() -> Self {
        Self { probes: Vec::new() }
    }

    /// Records `(concrete, cast)` once per concrete type. Repeat
    /// registrations for the same concrete are no-ops — the
    /// transpiler emits at every impl site, and re-running across
    /// crates re-runs the registration.
    pub fn register(&mut self, probe: TraitProbe<Trait>) {
        if self.probes.iter().any(|e| e.concrete == probe.concrete) {
            return;
        }
        self.probes.push(probe);
    }

    /// Linear scan over registered probes. Returns the first match's
    /// `&Trait`. O(n) in the number of impls per trait — typically
    /// small (single-digit) per Goish program.
    pub fn lookup<'a>(
        &self,
        any_ref: &'a (dyn CoreAny + Send + Sync),
    ) -> Option<&'a Trait> {
        let concrete = (*any_ref).type_id();
        for probe in &self.probes {
            if probe.concrete == concrete {
                return Some((probe.cast)(any_ref));
            }
        }
        None
    }

    /// Mutable mirror of [`lookup`](Self::lookup): returns the first
    /// match's `&mut Trait` via the probe's `cast_mut`.
    pub fn lookup_mut<'a>(
        &self,
        any_ref: &'a mut (dyn CoreAny + Send + Sync),
    ) -> Option<&'a mut Trait> {
        let concrete = (*any_ref).type_id();
        for probe in &self.probes {
            if probe.concrete == concrete {
                return Some((probe.cast_mut)(any_ref));
            }
        }
        None
    }
}

/// Convenience for the proc-macro: locks the registry, inserts one
/// probe. The macro emits one of these per trait, named like
/// `register_<trait>_impl`.
pub fn register_with<Trait: ?Sized + 'static>(
    registry: &SpinLock<TraitRegistry<Trait>>,
    probe: TraitProbe<Trait>,
) {
    let mut guard = registry.lock();
    guard.register(probe);
}

/// Convenience for the proc-macro: locks the registry, scans for a
/// match. Used by the `from_any` impl emitted per trait.
pub fn lookup_with<'a, Trait: ?Sized + 'static>(
    registry: &SpinLock<TraitRegistry<Trait>>,
    any_ref: &'a (dyn CoreAny + Send + Sync),
) -> Option<&'a Trait> {
    let guard = registry.lock();
    // SAFETY of the lifetime: `guard` borrows the registry's Vec; the
    // returned `&Trait` is a fresh pointer constructed from `any_ref`
    // (lifetime 'a, distinct from the registry). The vtable is
    // 'static (per Rust's type system) and the data pointer is
    // any_ref's. Detaching the lifetime from `guard` is sound — the
    // result doesn't borrow registry storage. We use a manual
    // lifetime extension via the `cast` fn pointer signature.
    guard.lookup(any_ref).map(|t| {
        // The `&Trait` we got has lifetime tied to `guard`'s borrow
        // of the SpinLock. Re-cast through the trait's data pointer
        // + 'static vtable to detach. cast fn doesn't capture
        // `guard`-bound state, so the result is sound.
        let raw = t as *const Trait;
        unsafe { &*raw }
    })
}

/// Mutable mirror of [`lookup_with`]: locks the registry, scans for a
/// match, returns `&mut Trait`. Used by the `from_any_mut` impl the
/// macro emits per trait.
pub fn lookup_with_mut<'a, Trait: ?Sized + 'static>(
    registry: &SpinLock<TraitRegistry<Trait>>,
    any_ref: &'a mut (dyn CoreAny + Send + Sync),
) -> Option<&'a mut Trait> {
    let guard = registry.lock();
    // Same lifetime-detach rationale as `lookup_with`: the returned
    // `&mut Trait` is built from `any_ref` (lifetime 'a) with a
    // 'static vtable; it does not borrow the guard's storage.
    guard.lookup_mut(any_ref).map(|t| {
        let raw = t as *mut Trait;
        unsafe { &mut *raw }
    })
}
