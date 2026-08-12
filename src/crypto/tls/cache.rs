// go: file crypto/tls/cache.go decls: weakCertCache.newCert
//
// crypto/tls — the parsed-certificate cache.
//
// Go: "weakCertCache provides a cache of *x509.Certificates, allowing
// multiple connections to reuse parsed certificates, instead of
// re-parsing the certificate for every connection, which is an
// expensive operation."
//
// **This implementation never caches**, for the same reason
// `crypto/internal/fips140cache` does not: Go's map holds
// `weak.Pointer[x509.Certificate]` values evicted by
// `runtime.AddCleanup` — a weak reference and a finalizer, both of
// which need a garbage collector. goish has neither.
//
// That is a conforming implementation rather than a stub. `newCert` is
// pure memoisation over `x509.ParseCertificate`: caching or not, it
// returns a certificate parsed from exactly those DER bytes, or the
// error `ParseCertificate` gave. Nothing observable turns on which. The
// cost is the one Go's doc comment names — a re-parse per connection —
// and it is forfeiting the optimization, not the contract.
//
// Caching without weak pointers is not an option worth taking: the map
// is keyed by the DER of every certificate the process has ever seen,
// so a strong-referenced map would grow without bound in exactly the
// long-lived server Go wrote this for.
//
// goishlint:ignore GOISH019 weakCertCache — the record is `struct{ sync.Map }`, and with no map to hold it degenerates to a unit; see the banner.
// goishlint:ignore GOISH021 weakCertCache, globalCertCache — same.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use crate::crypto::x509;
use crate::error;
use crate::goslice::slice;
use crate::types::byte;

// Go: cache.go:16 — `type weakCertCache struct{ sync.Map }`
/// Go's `weakCertCache`. The embedded `sync.Map` is absent; see the
/// banner.
pub(crate) struct weakCertCache;

impl weakCertCache {
    // go: sdk 1.25.5 crypto/tls/cache.go:19-41 weakCertCache.newCert
    /// Go: parse `der`, returning a previously parsed certificate for
    /// the same bytes when one is still live.
    ///
    /// Deviation: goish always parses. See the banner — the whole body
    /// of Go's version is the weak-pointer bookkeeping, and the value
    /// it returns is `x509.ParseCertificate(der)` either way.
    pub(crate) fn newCert(&self, der: slice<byte>) -> (Option<x509::Certificate>, error) {
        // Go: cert, err := x509.ParseCertificate(der)
        //     if err != nil { return nil, err }
        //     return cert, nil
        let (cert, err) = x509::ParseCertificate(der);
        if err != crate::errors::nil {
            return (None, err);
        }
        return (Some(cert), crate::errors::nil);
    }
}

// Go: cache.go:43 — `var globalCertCache = new(weakCertCache)`
pub(crate) static globalCertCache: weakCertCache = weakCertCache;
