// go: file crypto/subtle/dit.go decls: WithDataIndependentTiming
//
// Deviation: Go consults `internal/runtime/sys.DITSupported`, which is a
// PSTATE.DIT feature test that is false on every architecture except
// arm64 with FEAT_DIT. goish targets x86_64 only, so the flag is
// statically false and this reduces to the documented "executes f
// immediately with no other side-effects" path. The LockOSThread /
// EnableDIT / deferred DisableDIT arm is unreachable here and is
// therefore not ported.

#![allow(non_snake_case)]

// go: sdk 1.25.5 crypto/subtle/dit.go:30-50 WithDataIndependentTiming
/// Enable architecture-specific data-independent-timing features for the
/// duration of `f`. On x86_64 no such feature exists, so `f` runs directly.
pub fn WithDataIndependentTiming<F: FnOnce()>(f: F) {
    // Go: if !sys.DITSupported { f(); return }  — always taken on amd64.
    f();
}
