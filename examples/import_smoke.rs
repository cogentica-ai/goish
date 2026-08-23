// import smoke — verifies `goish::import!` at file scope:
//
//   1. Emits `use` lines (alias works, plain path works).
//   2. Registers a `.init_array` slot whose dispatcher is called
//      automatically by #[goish::main]'s prelude — BEFORE any code
//      in `fn main` runs.
//   3. Two separate `import!` invocations both fire (linker
//      concatenates their `.init_array` slots).
//
// We use inline sub-modules as stand-in "ports" so the test stays
// self-contained.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};
use goish::syscall;

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// Counters that the inline ports' init() functions tick. Using a
// counter (not just a bool) so we can detect double-init too.
static FAKE_PORT_A_RAN: AtomicU32 = AtomicU32::new(0);
static FAKE_PORT_B_RAN: AtomicU32 = AtomicU32::new(0);

mod fake_port_a {
    use super::FAKE_PORT_A_RAN;
    use core::sync::atomic::Ordering;
    #[goish::init]
    fn init() {
        FAKE_PORT_A_RAN.fetch_add(1, Ordering::Relaxed);
    }
}

mod fake_port_b {
    use super::FAKE_PORT_B_RAN;
    use core::sync::atomic::Ordering;
    #[goish::init]
    fn init() {
        FAKE_PORT_B_RAN.fetch_add(1, Ordering::Relaxed);
    }
}

// File-scope import — the macro emits `use fake_port_a as fpa;`
// AND a .init_array slot calling fake_port_a::init(). We use the
// alias form for both so the emitted `use` lines don't collide
// with the in-scope `mod fake_port_*` declarations above.
goish::import! {
    fake_port_a as fpa,
}

// Second import! invocation in the same crate. The counter inside
// the proc-macro gives this its own unique fn name and slot, so
// both land in `.init_array`.
goish::import! {
    fake_port_b as fpb,
}

#[goish::main]
fn main() {
    // By the time main is reached, #[goish::main]'s prelude has
    // already called `goish::__run_pkg_inits()` which walked
    // `.init_array` and dispatched both fake_port_*::init() bodies.
    check(
        FAKE_PORT_A_RAN.load(Ordering::Relaxed) == 1,
        b"import: fake_port_a init ran wrong number of times\n",
    );
    check(
        FAKE_PORT_B_RAN.load(Ordering::Relaxed) == 1,
        b"import: fake_port_b init ran wrong number of times\n",
    );

    // Aliases resolve at function scope too. Re-calling init() is
    // idempotent — state machine returns immediately.
    fpa::init();
    fpb::init();
    check(
        FAKE_PORT_A_RAN.load(Ordering::Relaxed) == 1,
        b"import: alias re-ran fake_port_a init\n",
    );
    check(
        FAKE_PORT_B_RAN.load(Ordering::Relaxed) == 1,
        b"import: alias re-ran fake_port_b init\n",
    );

    const OK: &[u8] = b"import_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
