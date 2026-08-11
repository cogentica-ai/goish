// fips140_mode_smoke — the FIPS-mode switches: crypto/fips140,
// crypto/tls/internal/fips140tls, and crypto/internal/fips140only.
//
// goish has no GODEBUG, so FIPS 140-3 mode cannot be turned on and every
// one of these reports "off". That is the whole observable surface, and
// it is worth pinning: a port that accidentally reported FIPS mode ON
// would make crypto/tls reject perfectly good configurations, and one
// that hard-coded Required() to false would make Force() silently do
// nothing.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::crypto::fips140;
use goish::crypto::internal::fips140only;
use goish::crypto::tls::internal::fips140tls;
use goish::fmt;

static mut FAILED: bool = false;

fn check(name: &str, got: goish::string, want: &str) {
    if got == goish::string::from(want) {
        fmt::Printf!("PASS: %s\n", goish::string::from(name));
    } else {
        fmt::Printf!(
            "FAIL: %s\n  got  %s\n  want %s\n",
            goish::string::from(name),
            got,
            goish::string::from(want)
        );
        unsafe { FAILED = true };
    }
}

#[goish::main]
fn main() {
    // Enabled() must not panic: its guard is
    // `fips140.Enabled && !check.Verified`, and reaching the panic would
    // mean the two constants had drifted apart.
    check(
        "crypto/fips140.Enabled() is false",
        fmt::Sprintf!("%v", fips140::Enabled()),
        "false",
    );
    check(
        "fips140only.Enabled is false",
        fmt::Sprintf!("%v", fips140only::Enabled),
        "false",
    );

    // fips140tls seeds `required` from fips140.Enabled(), so it starts off.
    check(
        "fips140tls.Required() starts false",
        fmt::Sprintf!("%v", fips140tls::Required()),
        "false",
    );

    // Force is not a no-op — it really sets the flag.
    fips140tls::Force();
    check(
        "Force() makes Required() true",
        fmt::Sprintf!("%v", fips140tls::Required()),
        "true",
    );
    // Idempotent.
    fips140tls::Force();
    check(
        "Force() is idempotent",
        fmt::Sprintf!("%v", fips140tls::Required()),
        "true",
    );

    // Go documents Force as impossible to undo *except in tests*, which
    // is exactly what TestingOnlyAbandon is for.
    fips140tls::TestingOnlyAbandon();
    check(
        "TestingOnlyAbandon() undoes Force()",
        fmt::Sprintf!("%v", fips140tls::Required()),
        "false",
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_mode_smoke OK\n");
}
