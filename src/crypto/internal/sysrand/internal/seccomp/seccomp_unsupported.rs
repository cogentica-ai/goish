// go: file crypto/internal/sysrand/internal/seccomp/seccomp_unsupported.go decls: DisableGetrandom
//
// crypto/internal/sysrand/internal/seccomp — ask the kernel to make
// getrandom(2) fail, so that sysrand's fallback path can be exercised.
//
// Go ships this package twice behind mutually exclusive build tags, and
// goish takes the second route, not by preference but by construction:
//
//   seccomp_linux.go        //go:build linux && cgo  — installs a real
//                           seccomp filter via cgo, calling prctl(2) and
//                           seccomp(2) through a C helper.
//   seccomp_unsupported.go  //go:build !linux || !cgo — returns an error.
//
// goish has no cgo at all, so `!cgo` holds and the unsupported route is
// the one a goish build compiles. The returned error is not a stand-in
// for the cgo version: on this platform getrandom genuinely cannot be
// disabled, which is exactly what Go reports here too.
//
// The single caller in Go is sysrand's own test, which uses it to force
// the /dev/urandom fallback and skips when it returns an error. goish
// does not port Go tests, so nothing calls this yet; it is ported for
// package completeness and behaves as Go's does.

#![allow(non_snake_case)]

use crate::error;

// go: sdk 1.25.5 crypto/internal/sysrand/internal/seccomp/seccomp_unsupported.go:11-13 DisableGetrandom
/// `seccomp.DisableGetrandom()` — make `getrandom(2)` fail for the
/// calling process. Always an error here: see the route note above.
pub fn DisableGetrandom() -> error {
    // Go: return errors.New("disabling getrandom is not supported on this system")
    return crate::errors::New("disabling getrandom is not supported on this system");
}
