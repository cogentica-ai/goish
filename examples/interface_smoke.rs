// interface smoke — verifies `#[goish::interface]` semantics:
//
//   1. A concrete impl satisfies the trait normally.
//   2. `<Trait>Ref::default()` returns the auto-generated nil
//      sentinel; the wrapper newtype sidesteps the orphan rule that
//      would otherwise reject `impl Default for Arc<dyn LocalTrait>`.
//   3. Comparing the default Ref against `goish::nil` returns true.
//   4. Comparing a non-nil Ref against `goish::nil` returns false.
//   5. The trait carries `Send + Sync` supertraits — a value can be
//      moved into a struct with `T: Send + Sync` bounds.
//   6. `nil.into()` flows into a Ref slot via the auto-emitted
//      `From<Nil>` impl.
//   7. `concrete.into()` flows into a Ref slot via the auto-emitted
//      `From<T>` impl.
//   8. Method dispatch through the Ref works (Deref<Target = dyn T>).
//   9. `#[derive(Default)]` works on a struct that holds a Ref field
//      — the field initialises to the nil sentinel.

#![no_std]
#![no_main]

extern crate alloc;

use goish::{int, nil, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond { die(msg); }
}

// ── A user-declared interface with the new attribute ────────────────
#[goish::interface]
pub trait Greeter {
    fn name(&self) -> int;
    fn level(&self) -> int;
}

// A concrete impl. Does NOT need to override `__is_nil_iface` — the
// default returns false.
struct Hi;
impl Greeter for Hi {
    fn name(&self) -> int { 42 }
    fn level(&self) -> int { 7 }
}

// A struct that holds an interface field via the Ref wrapper.
// `#[derive(Default)]` should compile because GreeterRef has Default.
#[derive(Default)]
struct Holder {
    pub g: GreeterRef,
    pub n: int,
}

#[goish::main]
fn main() {
    // 1. Default GreeterRef = nil sentinel.
    let null: GreeterRef = Default::default();
    check(null == nil, b"interface: default GreeterRef != nil\n");
    check(nil == null, b"interface: nil != default GreeterRef\n");

    // 2. nil.into() flows into a GreeterRef slot (via From<Nil>).
    let null2: GreeterRef = nil.into();
    check(null2 == nil, b"interface: nil.into() != nil\n");

    // 3. Concrete impl flows into GreeterRef via From<T>.
    let real: GreeterRef = Hi.into();
    check(real != nil, b"interface: concrete impl == nil (wrong)\n");
    check(nil != real, b"interface: nil == concrete impl (wrong)\n");

    // 4. Method dispatch on the concrete works through Deref to dyn.
    check(real.name() == 42, b"interface: real.name() != 42\n");
    check(real.level() == 7, b"interface: real.level() != 7\n");

    // 5. #[derive(Default)] on a struct holding a Ref field compiles
    //    AND produces a sensible default state.
    let h: Holder = Default::default();
    check(h.g == nil, b"interface: derived Default field != nil\n");
    check(h.n == 0, b"interface: derived Default int != 0\n");

    // 6. Clone via the wrapper bumps the internal Arc's refcount.
    let real2 = real.clone();
    check(real2.name() == 42, b"interface: cloned ref dispatch wrong\n");

    // 7. Send + Sync are inherited — moving into a closure with those
    //    bounds compiles.
    let _: alloc::boxed::Box<dyn Fn() -> int + Send + Sync> =
        alloc::boxed::Box::new(move || real2.name());

    const OK: &[u8] = b"interface_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
