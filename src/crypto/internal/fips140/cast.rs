// go: file crypto/internal/fips140/cast.go decls: fatal, CAST, PCT
//
//
// Deviations: Go's `failfipscast` is a GODEBUG key that simulates a CAST
// or PCT failure during FIPS 140-3 functional testing. goish has no
// GODEBUG (see crypto/internal/fips140only), so the injection point is
// absent and `err` is used as returned. Go's
// `strings.ContainsAny(name, ",#=:")` is spelled with `str::contains`
// because `name` is a `&str` here, not a goish `string` — the four
// characters are the same four.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use super::fips140::{debug, Enabled_};
use crate::error;
use crate::fmt;
use crate::gostring::string;

// go: sdk 1.25.5 crypto/internal/fips140/cast.go:24-56 CAST
/// Run the named Cryptographic Algorithm Self-Test (if operated in FIPS
/// mode) and abort the program (stopping the module input/output and
/// entering the "error state") if the self-test fails.
///
/// CASTs are mandatory self-checks that must be performed by FIPS 140-3
/// modules before the algorithm is used. See Implementation Guidance
/// 10.3.A.
///
/// The name must not contain commas, colons, hashes, or equal signs.
pub fn CAST<F>(name: &str, f: F)
where
    F: FnOnce() -> error,
{
    // Go: if strings.ContainsAny(name, ",#=:") { panic(…) }
    if name.contains(|c| c == ',' || c == '#' || c == '=' || c == ':') {
        panic!("fips: invalid self-test name");
    }
    // Go: if !Enabled { return }
    if !Enabled_ {
        return;
    }

    let mut err = f();
    // Go: if name == failfipscast { err = errors.New("simulated CAST failure") }
    if name == failfipscast {
        err = crate::errors::New("simulated CAST failure");
    }
    // Go: if err != nil { fatal("FIPS 140-3 self-test failed: " + name + …) }
    if err != crate::nil {
        fatal_self_test("self-test", name, &err);
    }
    // Go: if debug { println("FIPS 140-3 self-test passed:", name) }
    if debug {
        fmt::Printf!(
            "FIPS 140-3 self-test passed: %s\n",
            string::from_bytes(name.as_bytes())
        );
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/cast.go:58-89 PCT
/// Run the named Pairwise Consistency Test (if operated in FIPS mode) and
/// abort the program (stopping the module input/output and entering the
/// "error state") if the test fails.
///
/// PCTs are mandatory for every generated (but not imported) key pair,
/// including ephemeral keys (which effectively doubles the cost of key
/// establishment). See Implementation Guidance 10.3.A Additional
/// Comment 1.
///
/// The name must not contain commas, colons, hashes, or equal signs.
pub fn PCT<F>(name: &str, f: F)
where
    F: FnOnce() -> error,
{
    // Go: if strings.ContainsAny(name, ",#=:") { panic(…) }
    if name.contains(|c| c == ',' || c == '#' || c == '=' || c == ':') {
        panic!("fips: invalid self-test name");
    }
    // Go: if !Enabled { return }
    if !Enabled_ {
        return;
    }

    let mut err = f();
    // Go: if name == failfipscast { err = errors.New("simulated PCT failure") }
    if name == failfipscast {
        err = crate::errors::New("simulated PCT failure");
    }
    if err != crate::nil {
        fatal_self_test("PCT", name, &err);
    }
    // Go: if debug { println("FIPS 140-3 PCT passed:", name) }
    if debug {
        fmt::Printf!(
            "FIPS 140-3 PCT passed: %s\n",
            string::from_bytes(name.as_bytes())
        );
    }
}

/// Go: `var failfipscast = godebug.Value("#failfipscast")` — a GODEBUG
/// key allowing simulation of a CAST or PCT failure, as required during
/// FIPS 140-3 functional testing. The value is the whole name of the
/// target CAST or PCT. goish has no GODEBUG, so it is always empty and
/// never equals a self-test name.
const failfipscast: &str = "";

// go: sdk 1.25.5 crypto/internal/fips140/cast.go:16-17 fatal
/// Go declares this `//go:linkname`; the runtime defines it, aborting
/// without running deferred functions so the module stops producing
/// output. goish's nearest equivalent is `panic!`, which under
/// `panic = "abort"` has the same effect.
fn fatal(msg: string) -> ! {
    let raw: &str = msg.as_ref();
    panic!("{}", raw)
}

// go: none — Go inlines the message concatenation at both call sites;
// factoring it out keeps `fatal`'s own body the one-liner Go's is.
fn fatal_self_test(kind: &str, name: &str, err: &error) -> ! {
    let mut msg = string::from_static("FIPS 140-3 ");
    msg = msg + string::from_bytes(kind.as_bytes());
    msg = msg + string::from_static(" failed: ");
    msg = msg + string::from_bytes(name.as_bytes());
    msg = msg + string::from_static(": ");
    msg = msg + err.Error();
    fatal(msg)
}
