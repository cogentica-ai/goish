//! SCRATCH EXPERIMENT — not a real port. Goal: find the cleanest interface
//! definition + impl + cast! call site, and what `#[goish::interface]` would
//! need to change to deliver it.
//!
//! FINDINGS (asserted below so this file passing = findings reproduced):
//!   Q1: cast! carrier MUST be `dyn Trait + Send + Sync` explicitly. A bare
//!       `&dyn Read` is rejected (`dyn Read: HasDynAny` unsatisfied) even when
//!       `Read: Send + Sync` is a supertrait — the macro only emits HasDynAny
//!       for the `+ Send + Sync` form. So the Send+Sync *default* idea does NOT
//!       clean the call site by itself.
//!   Q2: a CLEAN `impl Read for T {}` is NOT castable today — cast! returns
//!       ok=false. Recovery requires each impl to hand-write
//!       `fn __goish_as_dyn_any(&self) -> Option<&(dyn Any+Send+Sync)> { Some(self) }`.
//!   Q3: a blanket-impl'd `as_any` SUPERTRAIT (the downcast-rs pattern) makes a
//!       clean impl recoverable with ZERO per-impl boilerplate — the mechanism
//!       `#[goish::interface]` could adopt to make impls clean.
#![no_std]
#![no_main]
#![allow(non_snake_case, dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use goish::cast;
use goish::fmt;
use goish::syscall;
use goish::testing;
use goish::int;

// ── Proposed spellings (local prototypes) ─────────────────────────────────
// d!(Trait)  => the Send+Sync interface-object TYPE (for fields/returns/args).
macro_rules! d {
    ($p:path) => { dyn $p + ::core::marker::Send + ::core::marker::Sync };
}
// dcast!(value, Iface) => Go's `value.(Iface)` with NO carrier local: folds the
// reborrow into the cast. Works for Box/Arc/&dyn interface values.
macro_rules! dcast {
    ($v:expr, $iface:path) => { goish::cast!(&*$v, $iface) };
}

#[goish::interface]
pub trait Read: Send + Sync {
    fn Read(&self) -> int;
}

#[goish::interface]
pub trait Seek: Send + Sync {
    fn Seek(&self) -> int;
}

// CLEAN impl: no __goish_as_dyn_any override.
#[derive(Default)]
struct CleanBuf {
    n: int,
}
impl Read for CleanBuf {
    fn Read(&self) -> int {
        self.n
    }
}
impl Seek for CleanBuf {
    fn Seek(&self) -> int {
        self.n + 100
    }
}

// HOOKED impl: with the mandatory override boilerplate.
#[derive(Default)]
struct HookedBuf {
    n: int,
}
impl Read for HookedBuf {
    fn Read(&self) -> int {
        self.n
    }
    fn __goish_as_dyn_any(
        &self,
    ) -> ::core::option::Option<&(dyn ::core::any::Any + ::core::marker::Send + ::core::marker::Sync)>
    {
        Some(self)
    }
}
impl Seek for HookedBuf {
    fn Seek(&self) -> int {
        self.n + 100
    }
    fn __goish_as_dyn_any(
        &self,
    ) -> ::core::option::Option<&(dyn ::core::any::Any + ::core::marker::Send + ::core::marker::Sync)>
    {
        Some(self)
    }
}

// ── Q3 setup: the blanket-supertrait pattern (no #[goish::interface]) ───────
// A supertrait whose single method is provided by ONE blanket impl, so every
// 'static+Send+Sync concrete satisfies it for free — no per-impl code.
pub trait ScratchAny {
    fn scratch_as_any(&self) -> &(dyn ::core::any::Any + Send + Sync);
}
impl<T: 'static + Send + Sync> ScratchAny for T {
    fn scratch_as_any(&self) -> &(dyn ::core::any::Any + Send + Sync) {
        self
    }
}
pub trait Read3: ScratchAny + Send + Sync {
    fn Read(&self) -> int;
}
#[derive(Default)]
struct CleanBuf3 {
    n: int,
}
// CLEAN impl — no as_any boilerplate; scratch_as_any comes from the blanket.
impl Read3 for CleanBuf3 {
    fn Read(&self) -> int {
        self.n
    }
}

// go: none — scratch test entrypoint
#[goish::main]
fn main() {
    __goish_register_Seek_impl::<CleanBuf>();
    __goish_register_Seek_impl::<HookedBuf>();

    let tests: &[(&str, testing::TestFn)] = &[
        ("Q1_hooked_explicit_carrier_works", q1_hooked_explicit_carrier_works),
        ("Q2_clean_impl_not_castable_today", q2_clean_impl_not_castable_today),
        ("Q3_blanket_supertrait_recovers_clean_impl", q3_blanket_supertrait_recovers_clean_impl),
        ("Q4_clean_spelling_no_carrier_local", q4_clean_spelling_no_carrier_local),
    ];
    let code = testing::Main(tests);
    syscall::Exit(goish::int32(code));
}

// Q1: baseline — explicit `+ Send + Sync` carrier + hooked impl casts fine.
fn q1_hooked_explicit_carrier_works(t: &mut testing::T) {
    let b: Box<dyn Read + Send + Sync> = Box::new(HookedBuf { n: 7 });
    let r: &(dyn Read + Send + Sync) = &*b;
    let (s, ok) = cast!(r, Seek);
    if !ok {
        t.Fatal(fmt::Sprintf!("Q1: explicit-carrier + hooked-impl cast! ok=false"));
    }
    if s.Seek() != 107 {
        t.Fatal(fmt::Sprintf!("Q1: Seek()=%d want 107", s.Seek()));
    }
}

// Q2: documents the gap — a CLEAN impl (no override) is NOT castable today.
fn q2_clean_impl_not_castable_today(t: &mut testing::T) {
    let b: Box<dyn Read + Send + Sync> = Box::new(CleanBuf { n: 5 });
    let r: &(dyn Read + Send + Sync) = &*b;
    let (_s, ok) = cast!(r, Seek);
    if ok {
        t.Fatal(fmt::Sprintf!(
            "Q2: CLEAN impl unexpectedly cast OK — the boilerplate gap is fixed?!"
        ));
    }
    // ok==false reproduces the finding: the override is mandatory today.
}

// Q3: PROOF — a blanket-impl'd `scratch_as_any` supertrait recovers a CLEAN
// impl with ZERO per-impl boilerplate. This is what the macro could adopt.
fn q3_blanket_supertrait_recovers_clean_impl(t: &mut testing::T) {
    let b: Box<dyn Read3 + Send + Sync> = Box::new(CleanBuf3 { n: 42 });
    let r: &(dyn Read3 + Send + Sync) = &*b;
    let any = r.scratch_as_any();
    match any.downcast_ref::<CleanBuf3>() {
        Some(c) => {
            if c.n != 42 {
                t.Fatal(fmt::Sprintf!("Q3: recovered n=%d want 42", c.n));
            }
        }
        None => t.Fatal(fmt::Sprintf!(
            "Q3: blanket-supertrait recovery returned None (pattern does NOT work)"
        )),
    }
}

// Q4: the proposed clean call-site spelling. `Box<d!(Read)>` (no `+ Send + Sync`
// spelled) and `dcast!(b, Seek)` (no `let r: &(dyn ...)` carrier local).
// Uses HookedBuf because the impl-boilerplate macro change isn't applied yet;
// this isolates the SPELLING ergonomics from the impl-cleanliness change.
fn q4_clean_spelling_no_carrier_local(t: &mut testing::T) {
    let b: Box<d!(Read)> = Box::new(HookedBuf { n: 11 });
    let (s, ok) = dcast!(b, Seek);
    if !ok {
        t.Fatal(fmt::Sprintf!("Q4: dcast! ok=false"));
    }
    if s.Seek() != 111 {
        t.Fatal(fmt::Sprintf!("Q4: Seek()=%d want 111", s.Seek()));
    }
}
