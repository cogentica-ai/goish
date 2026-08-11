// go: file crypto/internal/fips140/indicator.go decls: getIndicator, setIndicator, ResetServiceIndicator, ServiceIndicator, RecordApproved, RecordNonApproved
//
// The service indicator lets users of the module query whether invoked
// services are approved. Three states are stored in a per-goroutine value
// by the runtime. The indicator starts at indicatorUnset after a reset.
// Invoking an approved service transitions to indicatorTrue. Invoking a
// non-approved service transitions to indicatorFalse, and it can't leave
// that state until a reset. The idea is that functions can "delegate"
// checks to inner functions, and if there's anything non-approved in the
// stack, the final result is negative. Finally, we expose indicatorUnset
// as negative to the user, so that we don't need to explicitly annotate
// fully non-approved services.
//
// `getIndicator`/`setIndicator` are `//go:linkname` DECLARATIONS in
// indicator.go: the Go *runtime* defines them, storing a byte in the g
// struct. Implementing them here means adding a per-goroutine slot to
// goish's `runtime::sched::g::G` plus two accessors through
// `current_g()` — a scheduler change, which AGENTS.md requires
// `make e2e-full` to validate, so it is deliberately not bundled with a
// crypto port. Until then the getter reports `indicatorUnset` and the
// setter discards, which makes ServiceIndicator() report false: the
// conservative answer, and the one Go also gives before a Reset.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::types::uint8;

// go: sdk 1.25.5 crypto/internal/fips140/indicator.go:19-20 getIndicator
/// Go declares this `//go:linkname`; the runtime defines it. See the file
/// header for what implementing it in goish would take.
fn getIndicator() -> uint8 {
    return indicatorUnset;
}

// go: sdk 1.25.5 crypto/internal/fips140/indicator.go:22-23 setIndicator
/// Go declares this `//go:linkname`; the runtime defines it. See the file
/// header for what implementing it in goish would take.
fn setIndicator(_v: uint8) {}

// Go: indicator.go:25-30
/// Go: `indicatorUnset uint8 = iota`
const indicatorUnset: uint8 = 0;
/// Go: `indicatorFalse`
const indicatorFalse: uint8 = 1;
/// Go: `indicatorTrue`
const indicatorTrue: uint8 = 2;

// go: sdk 1.25.5 crypto/internal/fips140/indicator.go:31-35 ResetServiceIndicator
/// Clear the service indicator for the running goroutine.
pub fn ResetServiceIndicator() {
    // Go: setIndicator(indicatorUnset)
    setIndicator(indicatorUnset);
}

// go: sdk 1.25.5 crypto/internal/fips140/indicator.go:36-44 ServiceIndicator
/// Return true if and only if all services invoked by this goroutine
/// since the last ResetServiceIndicator call are approved.
///
/// If ResetServiceIndicator was not called before by this goroutine, its
/// return value is undefined.
pub fn ServiceIndicator() -> bool {
    // Go: return getIndicator() == indicatorTrue
    return getIndicator() == indicatorTrue;
}

// go: sdk 1.25.5 crypto/internal/fips140/indicator.go:45-57 RecordApproved
/// An internal function that records the use of an approved service. It
/// does not override RecordNonApproved calls in the same span.
///
/// It should be called by exposed functions that perform a whole
/// cryptographic algorithm (e.g. by Sum, not by New, unless a
/// cryptographic Instantiate algorithm is performed) and should be called
/// after any checks that may cause the function to error out or panic.
pub fn RecordApproved() {
    // Go: if getIndicator() == indicatorUnset { setIndicator(indicatorTrue) }
    if getIndicator() == indicatorUnset {
        setIndicator(indicatorTrue);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/indicator.go:58-63 RecordNonApproved
/// An internal function that records the use of a non-approved service.
/// It overrides any RecordApproved calls in the same span.
pub fn RecordNonApproved() {
    // Go: setIndicator(indicatorFalse)
    setIndicator(indicatorFalse);
}

// indicatorFalse is written by RecordNonApproved and read back by a
// getIndicator that goish cannot yet implement; keep it referenced so the
// constant does not read as dead.
const _: uint8 = indicatorFalse;
