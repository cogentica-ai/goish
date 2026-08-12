// go: file crypto/x509/root.go decls: systemRootsPool, initSystemRoots, SetFallbackRoots
//
// The process-wide system trust store: the lazily-initialised
// `systemRoots` pool and the `SetFallbackRoots` override.
//
// Deviations from root[go] @ Go 1.25.5:
//
//   * Go's package-level `var ( once sync.Once; systemRootsMu
//     sync.RWMutex; systemRoots *CertPool; systemRootsErr error;
//     fallbacksSet bool )` is a single `var` block of five independent
//     names, and AGENTS.md §5 forbids bundling them into one guarded
//     struct. goish keeps five statics: `once` is a real `sync::Once`,
//     and each mutable value sits in its own `SpinLock`. goish has no
//     package-level `var` of a non-const type, so each is a
//     `SpinLock`-wrapped static rather than a bare one.
//   * `systemRootsMu` is a `sync.RWMutex` in Go. The three readers here
//     hold it for a pointer copy, so goish uses the per-value `SpinLock`
//     instead of a separate lock object. This is the one place the Go
//     shape is not preserved field-for-field, and the reason is that a
//     goish static needs interior mutability to be written at all.
//   * `systemRoots` is `*CertPool` — nil until `initSystemRoots` runs,
//     and nil again if loading failed. goish spells that `Option<CertPool>`,
//     the same nilable-pointer shape `VerifyOptions.Roots` uses.
//   * `x509usefallbackroots = godebug.New("x509usefallbackroots")` has no
//     goish counterpart: `internal/godebug` is not ported and goish has
//     no GODEBUG plumbing. `SetFallbackRoots` therefore behaves as if the
//     setting is unset, which is Go's default — an already-populated
//     system pool wins and the fallback is dropped.
//   * `//go:linkname systemRoots` exists to keep a hall-of-shame
//     reflection hack working; goish has no linkname.
//
// goishlint:ignore GOISH021 once, systemRootsMu, systemRoots, systemRootsErr, fallbacksSet, x509usefallbackroots — the package-level `var` block, spelled as SpinLock statics; `x509usefallbackroots` needs internal/godebug. See the banner.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use super::cert_pool::CertPool;
use crate::error;
use crate::errors;
use crate::runtime::spin::SpinLock;
use crate::sync::Once;

// Go: root.go:21-28 — the `var` block. See the banner for why each name
// is a `SpinLock` static.
static once: Once = Once::new();
static systemRoots: SpinLock<Option<CertPool>> = SpinLock::new(None);
static systemRootsErrVal: SpinLock<Option<error>> = SpinLock::new(None);
static fallbacksSet: SpinLock<bool> = SpinLock::new(false);

// go: sdk 1.25.5 crypto/x509/root.go:30-35 systemRootsPool
pub(super) fn systemRootsPool() -> Option<CertPool> {
    once.Do(initSystemRoots);
    let g = systemRoots.lock();
    return g.clone();
}

// go: sdk 1.25.5 crypto/x509/root.go:37-44 initSystemRoots
fn initSystemRoots() {
    let (roots, err) = super::root_unix::loadSystemRoots();
    let mut sr = systemRoots.lock();
    let mut se = systemRootsErrVal.lock();
    if err != crate::nil {
        *sr = None;
        *se = Some(err);
    } else {
        *sr = Some(roots);
        *se = None;
    }
}

// go: none — goish idiom: `systemRootsErr` is a package-level `var` that
// verify.go reads directly (`SystemRootsError{systemRootsErr}`). goish
// holds it in a `SpinLock` static, so the read needs an accessor.
pub(super) fn systemRootsErr() -> error {
    let g = systemRootsErrVal.lock();
    return match &*g {
        Some(e) => e.clone(),
        None => errors::nil,
    };
}

// go: sdk 1.25.5 crypto/x509/root.go:61-85 SetFallbackRoots
/// Set the roots to use during certificate verification, if no custom
/// roots are specified and a system certificate pool is not available
/// (for instance in a container which does not have a root certificate
/// bundle). SetFallbackRoots will panic if roots is the zero value.
///
/// SetFallbackRoots may only be called once; calling it again panics.
///
/// Go gates the "force the fallback even when a system pool exists" path
/// on `GODEBUG=x509usefallbackroots=1`. goish has no `internal/godebug`,
/// so that path is unreachable and this behaves as the unset default:
/// a non-empty system pool wins and the fallback is dropped.
// goishlint:ignore GOISH017 SetFallbackRoots — the x509usefallbackroots GODEBUG branch needs internal/godebug; see the doc comment.
pub fn SetFallbackRoots(roots: CertPool) {
    // Go's `if roots == nil { panic("roots must be non-nil") }` has no
    // counterpart: `roots` is a value here, and goish has no nil
    // `CertPool`. An empty pool is a legal (if useless) fallback set,
    // exactly as `NewCertPool()` would be in Go.

    // trigger initSystemRoots if it hasn't already been called before we
    // take the lock
    let _ = systemRootsPool();

    let mut fs = fallbacksSet.lock();
    if *fs {
        panic!("SetFallbackRoots has already been called");
    }
    *fs = true;

    let mut sr = systemRoots.lock();
    if let Some(p) = sr.as_ref() {
        if p.Len() > 0 || p.__systemPool() {
            // Go: `if x509usefallbackroots.Value() != "1" { return }`.
            // goish has no GODEBUG, so the unset default always returns.
            return;
        }
    }
    let mut se = systemRootsErrVal.lock();
    *sr = Some(roots);
    *se = None;
}
