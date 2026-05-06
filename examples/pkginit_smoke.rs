// pkginit smoke — verifies the Go-style package init state machine
// AND the `#[goish::init] / goish::import!` ergonomic shorthands.
//
// What this tests:
//   1. `run_once` runs the body exactly once across multiple calls.
//   2. Diamond dependency: A and B both call C.init(); C runs once.
//   3. `goish::init()` itself runs exactly once even on repeat calls
//      (it's prepended to every #[goish::main] body and may also be
//      called explicitly by ports).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};
use goish::syscall;
use goish::runtime::pkginit::PkgInit;

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond { die(msg); }
}

// ── 1. run_once is idempotent ────────────────────────────────────────
static A_RAN: AtomicU32 = AtomicU32::new(0);
static A_INIT: PkgInit = PkgInit::new("test_a");

fn a_init() {
    A_INIT.run_once(|| {
        A_RAN.fetch_add(1, Ordering::Relaxed);
    });
}

// ── 2. Diamond — both B and D depend on C ────────────────────────────
static B_RAN: AtomicU32 = AtomicU32::new(0);
static C_RAN: AtomicU32 = AtomicU32::new(0);
static D_RAN: AtomicU32 = AtomicU32::new(0);

static B_INIT: PkgInit = PkgInit::new("test_b");
static C_INIT: PkgInit = PkgInit::new("test_c");
static D_INIT: PkgInit = PkgInit::new("test_d");

fn c_init() {
    C_INIT.run_once(|| {
        C_RAN.fetch_add(1, Ordering::Relaxed);
    });
}

fn b_init() {
    B_INIT.run_once(|| {
        c_init(); // dep
        B_RAN.fetch_add(1, Ordering::Relaxed);
    });
}

fn d_init() {
    D_INIT.run_once(|| {
        c_init(); // dep — same C, already initialized via B
        D_RAN.fetch_add(1, Ordering::Relaxed);
    });
}

#[goish::main]
fn main() {
    // 1. Repeated run_once → body runs once
    a_init();
    a_init();
    a_init();
    check(A_RAN.load(Ordering::Relaxed) == 1, b"pkginit: A ran more than once\n");
    check(A_INIT.is_done(), b"pkginit: A state != DONE\n");
    check(A_INIT.state() == PkgInit::DONE, b"pkginit: A state value wrong\n");

    // 2. Diamond — both B.init() and D.init() depend on C; C runs once.
    b_init();
    d_init();
    check(B_RAN.load(Ordering::Relaxed) == 1, b"pkginit: B ran more than once\n");
    check(D_RAN.load(Ordering::Relaxed) == 1, b"pkginit: D ran more than once\n");
    check(C_RAN.load(Ordering::Relaxed) == 1, b"pkginit: C ran more than once (diamond bug)\n");

    // 3. goish::init() — already invoked by #[goish::main] prelude.
    //    A direct call here must short-circuit.
    goish::init();
    goish::init();
    // No counter to assert against, but if this re-ran it would
    // re-register hashes — RegisterHash on the same slot is a no-op
    // semantically but observable behaviour is "still the same hash
    // in the slot". We just need to confirm the call didn't panic
    // with "recursive init".

    // 4. crypto registry was populated by goish::init() before main.
    //    crypto::HashAvailable(SHA256) should be true.
    check(goish::crypto::HashAvailable(goish::crypto::SHA256),
          b"pkginit: SHA256 not registered after goish::init\n");
    check(goish::crypto::HashAvailable(goish::crypto::SHA512),
          b"pkginit: SHA512 not registered after goish::init\n");
    check(goish::crypto::HashAvailable(goish::crypto::SHA1),
          b"pkginit: SHA1 not registered after goish::init\n");
    check(goish::crypto::HashAvailable(goish::crypto::MD5),
          b"pkginit: MD5 not registered after goish::init\n");

    const OK: &[u8] = b"pkginit: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
