//! Smoke tests for `#[goish::interface]` auto-composite detection.
//!
//! Verifies that:
//!  1. Composite supertraits (anything beyond Send/Sync) → nil sentinel
//!     skipped, but HasDynAny + AsExt downcast still work.
//!  2. Trivial supertraits (only Send/Sync markers or empty) → full emit
//!     retained, including nil sentinel, cast!(), and nil equality.
#![no_std]
#![no_main]
#![allow(non_snake_case, dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use goish::any::AsExt;
use goish::any::__HasNilSentinel;
use goish::fmt;
use goish::syscall;
use goish::testing;

// ─── Simulated "foreign" supertrait ────────────────────────────────────────
//
// In real usage this would live in a separate crate (e.g. metav1::Object).
// Using a local definition here so the test file compiles without needing
// external crates.  The macro's composite-detection cares only about the
// supertrait clause TEXT — any path other than pure Send/Sync markers triggers
// composite mode.
pub trait Foreign: Send + Sync {
    fn foreign_method(&self) -> u32 {
        0
    }
}

// ── Composite-supertrait trait ──────────────────────────────────────────────
//
// `Composite: Foreign + Send + Sync` → auto-detected as composite because
// `Foreign` is not a marker trait.  The macro skips the nil sentinel (struct
// + impl + Hook + nilable + NilDyn) but still emits:
//   • the trait redecl with `__is_nil_iface` and `__goish_as_dyn_any` defaults
//   • `impl __HasNilSentinel for dyn Composite + Send + Sync` { false }
//   • the HasDynAny impl
//   • the DowncastableFromAny registry
#[goish::interface]
pub trait Composite: Foreign + Send + Sync {
    fn local_method(&self) -> u32;
}

#[derive(Default, Clone)]
pub struct Concrete {
    pub n: u32,
}
impl Foreign for Concrete {
    fn foreign_method(&self) -> u32 {
        self.n
    }
}
impl Composite for Concrete {
    fn local_method(&self) -> u32 {
        self.n + 1
    }
    fn __goish_as_dyn_any(
        &self,
    ) -> ::core::option::Option<&(dyn ::core::any::Any + ::core::marker::Send + ::core::marker::Sync)>
    {
        Some(self)
    }
}

#[derive(Default, Clone)]
pub struct Other;
impl Foreign for Other {}
impl Composite for Other {
    fn local_method(&self) -> u32 {
        0
    }
    fn __goish_as_dyn_any(
        &self,
    ) -> ::core::option::Option<&(dyn ::core::any::Any + ::core::marker::Send + ::core::marker::Sync)>
    {
        Some(self)
    }
}

// ─── Sister trait with TRIVIAL supertraits — nil sentinel still works ──────

#[goish::interface]
pub trait Trivial: Send + Sync {
    fn m(&self) -> u32;
}

#[derive(Default, Clone)]
pub struct TConcrete {
    pub n: u32,
}
impl Trivial for TConcrete {
    fn m(&self) -> u32 {
        self.n
    }
    fn __goish_as_dyn_any(
        &self,
    ) -> ::core::option::Option<&(dyn ::core::any::Any + ::core::marker::Send + ::core::marker::Sync)>
    {
        Some(self)
    }
}

// ── Test 1: downcast hit ────────────────────────────────────────────────────
fn test_composite_arc_downcasts_to_concrete(t: &mut testing::T) {
    let arc: Arc<dyn Composite> = Arc::new(Concrete { n: 7 });
    let r: &(dyn Composite + Send + Sync) = &*arc;
    match r.As::<Concrete>() {
        Some(got) => {
            if got.n != 7 {
                t.Fatal(fmt::Sprintf!("n: got %d, want 7", got.n));
            }
            if got.local_method() != 8 {
                t.Fatal(fmt::Sprintf!("local_method: got %d, want 8", got.local_method()));
            }
        }
        None => t.Fatal(fmt::Sprintf!("expected Some(&Concrete), got None")),
    }
}

// ── Test 2: downcast miss ───────────────────────────────────────────────────
fn test_composite_arc_miss_returns_none(t: &mut testing::T) {
    let arc: Arc<dyn Composite> = Arc::new(Concrete::default());
    let r: &(dyn Composite + Send + Sync) = &*arc;
    if r.As::<Other>().is_some() {
        t.Fatal(fmt::Sprintf!("expected None for wrong concrete type, got Some"));
    }
}

// ── Test 3: __GOISH_HAS_NIL_SENTINEL is false for composite ────────────────
//
// Verifies the compile-time witness constant emitted by the macro.
// cast!(carrier, Composite) would const-assert on this and emit a clear
// error directing the user to AsExt::As::<ConcreteType>() instead.
fn test_composite_has_nil_sentinel_is_false(t: &mut testing::T) {
    let composite_has_sentinel =
        <dyn Composite + Send + Sync as __HasNilSentinel>::__GOISH_HAS_NIL_SENTINEL;
    if composite_has_sentinel {
        t.Fatal(fmt::Sprintf!(
            "composite trait should report __GOISH_HAS_NIL_SENTINEL = false, got true"
        ));
    }
    let trivial_has_sentinel =
        <dyn Trivial + Send + Sync as __HasNilSentinel>::__GOISH_HAS_NIL_SENTINEL;
    if !trivial_has_sentinel {
        t.Fatal(fmt::Sprintf!(
            "trivial trait should report __GOISH_HAS_NIL_SENTINEL = true, got false"
        ));
    }
}

// ── Test 4: trivial trait retains cast!() and nil sentinel ─────────────────
fn test_trivial_keeps_cast_and_nil_sentinel(t: &mut testing::T) {
    use goish::cast;
    use goish::any::NilDyn;

    // Register TConcrete in the per-trait registry so cast! can find it.
    __goish_register_Trivial_impl::<TConcrete>();

    let concrete = TConcrete { n: 5 };
    // cast! works on a &dyn Trivial+Send+Sync borrow
    let r: &(dyn Trivial + Send + Sync) = &concrete;
    let (tref, ok) = cast!(r, Trivial);
    if !ok {
        t.Fatal(fmt::Sprintf!("cast! returned ok=false, expected true"));
    }
    if tref.m() != 5 {
        t.Fatal(fmt::Sprintf!("m: got %d, want 5", tref.m()));
    }

    // nil sentinel exists: __is_nil_iface() returns true on the nil sentinel.
    let nil_ref: &(dyn Trivial + Send + Sync) =
        <dyn Trivial + Send + Sync as NilDyn>::__goish_nil_ref();
    if !nil_ref.__is_nil_iface() {
        t.Fatal(fmt::Sprintf!("nil sentinel __is_nil_iface should be true"));
    }
}

#[goish::main]
fn main() {
    let tests: &[(&str, testing::TestFn)] = &[
        ("TestCompositeArcDowncastsToConcrete", test_composite_arc_downcasts_to_concrete),
        ("TestCompositeArcMissReturnsNone", test_composite_arc_miss_returns_none),
        ("TestCompositeHasNilSentinelIsFalse", test_composite_has_nil_sentinel_is_false),
        ("TestTrivialKeepsCastAndNilSentinel", test_trivial_keeps_cast_and_nil_sentinel),
    ];
    let code = testing::Main(tests);
    syscall::Exit(code as i32);
}
