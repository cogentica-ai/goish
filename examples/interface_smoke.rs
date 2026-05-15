// interface_smoke — verifies `#[goish::interface]` semantics for a
// user-declared interface:
//
//   1. A concrete impl satisfies the trait; direct dispatch works.
//   2. An interface value stored as `Box<dyn Trait + Send + Sync>`
//      dispatches to the concrete impl.
//   3. `nil.into()` yields the auto-generated nil sentinel; its
//      `__is_nil_iface()` reports true.
//   4. A non-nil interface value reports `__is_nil_iface()` false.
//   5. `&dyn Trait` borrow dispatch works.
//   6. The trait carries `Send + Sync` supertraits — a value moves
//      into a `Send + Sync`-bounded closure.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;

use goish::{int, nil, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// ── A user-declared interface with the attribute ────────────────────
#[goish::interface]
pub trait Greeter {
    fn name(&self) -> int;
    fn level(&self) -> int;
}

// A concrete impl. Does NOT override `__is_nil_iface` — the default
// returns false.
struct Hi;
impl Greeter for Hi {
    fn name(&self) -> int {
        42
    }
    fn level(&self) -> int {
        7
    }
}

#[goish::main]
fn main() {
    // 1. Direct concrete dispatch.
    let h = Hi;
    check(h.name() == 42, b"interface: Hi.name() != 42\n");
    check(h.level() == 7, b"interface: Hi.level() != 7\n");

    // 2. Stored as Box<dyn Greeter> — dispatch through the trait object.
    let boxed: Box<dyn Greeter + Send + Sync> = Box::new(Hi);
    check(boxed.name() == 42, b"interface: boxed.name() != 42\n");
    check(boxed.level() == 7, b"interface: boxed.level() != 7\n");

    // 3. nil.into() → the auto-generated nil sentinel.
    let null: Box<dyn Greeter + Send + Sync> = nil.into();
    check(null.__is_nil_iface(), b"interface: nil sentinel not nil\n");

    // 4. A non-nil value reports not-nil.
    check(!boxed.__is_nil_iface(), b"interface: concrete reports nil\n");

    // 5. &dyn Greeter borrow dispatch.
    let r: &(dyn Greeter + Send + Sync) = &Hi;
    check(r.name() == 42, b"interface: &dyn name() != 42\n");
    check(r.level() == 7, b"interface: &dyn level() != 7\n");

    // 6. Send + Sync are inherited — moving into a closure with those
    //    bounds compiles and dispatches.
    let owned: Box<dyn Greeter + Send + Sync> = Box::new(Hi);
    let f: Box<dyn Fn() -> int + Send + Sync> = Box::new(move || owned.name());
    check(f() == 42, b"interface: closure dispatch != 42\n");

    const OK: &[u8] = b"interface_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
