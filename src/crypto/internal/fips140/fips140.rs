// go: file crypto/internal/fips140/fips140.go decls: Supported, Name, Version
//
// goishlint:ignore GOISH018 — fips140.go's `init()` reads
// `godebug.Value("#fips140")` and sets `Enabled`/`debug` from it. goish
// has no GODEBUG (see crypto/internal/fips140only for why a stub of
// internal/godebug would be inventing rather than porting), so both flags
// are `const false` and there is nothing for an init to do.

#![allow(non_snake_case, non_upper_case_globals)]

use super::notasan::asanEnabled;
use super::notboring::boringEnabled;
use crate::error;
use crate::errors;
use crate::gostring::string;

/// Go: `var Enabled bool`, set by `init()` from GODEBUG. Always false in
/// goish — there is no validated module to enter.
pub(crate) const Enabled_: bool = false;

/// Go: `var debug bool`, set by `init()` when GODEBUG=fips140=debug.
pub(crate) const debug: bool = false;

// go: none — Go's `Enabled` is a package-level `var bool`, not a
// function. goish exposes it as one so call sites read
// `fips140::Enabled()`; the value is the `Enabled_` constant above, which
// is what GOISH021 matches against Go's var.
pub fn Enabled() -> bool {
    return Enabled_;
}

// go: sdk 1.25.5 crypto/internal/fips140/fips140.go:31-59 Supported
/// Return an error if FIPS 140-3 mode can't be enabled.
pub fn Supported() -> error {
    // Keep this in sync with fipsSupported in cmd/dist/test.go.

    // ASAN disapproves of reading swaths of global memory in
    // fips140/check. One option would be to expose runtime.asanunpoison
    // through crypto/internal/fips140deps and then call it to unpoison
    // the range before reading it, but it is unclear whether that would
    // then cause false negatives. For now, FIPS+ASAN doesn't need to
    // work.
    if asanEnabled {
        return errors::New("FIPS 140-3 mode is incompatible with ASAN");
    }

    // Go switches on runtime.GOARCH/GOOS to reject wasm, windows/386,
    // windows/arm, openbsd and aix. goish builds only for
    // x86_64-unknown-linux-gnu, which is none of those, so the switch has
    // no reachable arm and is elided rather than encoded as a comparison
    // between constants that cannot differ.

    if boringEnabled {
        return errors::New("FIPS 140-3 mode is incompatible with GOEXPERIMENT=boringcrypto");
    }

    // Go: return nil
    return crate::nil.into();
}

// go: sdk 1.25.5 crypto/internal/fips140/fips140.go:61-63 Name
pub fn Name() -> string {
    // Go: return "Go Cryptographic Module"
    return string::from_static("Go Cryptographic Module");
}

// go: sdk 1.25.5 crypto/internal/fips140/fips140.go:65-71 Version
/// Return the formal version (such as "v1.0.0") if building against a
/// frozen module with GOFIPS140. Otherwise, it returns "latest".
pub fn Version() -> string {
    // This return value is replaced by mkzip.go, it must not be changed
    // or moved to a different file.
    // Go: return "latest" //mkzip:version
    return string::from_static("latest");
}
