// go: file crypto/x509/cert_pool.go decls: NewCertPool, len, cert, Clone, AddCert, addCertFunc, AppendCertsFromPEM, Subjects, Equal, AddCertWithConstraint
//
// A set of certificates.
//
// Deviations from cert_pool[go] @ Go 1.25.5:
//
//   * `lazyCert.getCert func() (*Certificate, error)` is a closure that
//     re-parses the DER on demand, guarded by a `sync.Once`. It exists
//     to keep the ~150 system roots unparsed until a chain build needs
//     them; it is a memory optimisation, not semantics. goish stores the
//     already-parsed `Certificate` in the field instead, and `cert(n)`
//     hands it back with a nil error. AGENTS.md §5 rule 3 bans a
//     `Box<dyn Fn>` field, and the honest alternative to a trait object
//     here is the value the closure would have returned.
//   * `lazyCert.constraint func([]*Certificate) error` is read only by
//     `Certificate.Verify`, which is not ported (verify.go needs
//     net/netip). The field is absent and `AddCertWithConstraint` is
//     `AddCert` plus a documented no-op constraint slot — see its own
//     comment.
//   * `haveSum map[sum224]bool` keys on a `[28]byte` array. goish's
//     `map<K, V>` needs `K: GoHash`, which `[byte; 28]` does not
//     implement, so the key is `string::from_bytes(&sum)` — the same 28
//     bytes, in the only keyable carrier goish has for them. `sum224`
//     itself keeps Go's shape and is what `sha256::Sum224` returns.
//   * `findPotentialParents` and `contains` are chain-building helpers
//     read only by verify.go; they are absent.
//   * `SystemCertPool` needs `systemRootsPool` / `loadSystemRoots` from
//     root.go and root_unix.go, which read the filesystem for the
//     platform trust store. Absent.
//
// goishlint:ignore GOISH018 findPotentialParents, contains, SystemCertPool — chain-building and platform-trust-store helpers; see the banner.
// goishlint:ignore GOISH019 potentialParent — the row type of findPotentialParents, which is not ported.
// goishlint:ignore GOISH021 potentialParent — the row type of findPotentialParents, which is not ported.
// goishlint:ignore GOISH020 addCertFunc, AddCertWithConstraint — Go passes the cert as a `getCert func() (*Certificate, error)` closure and a `constraint func([]*Certificate) error`; goish stores the parsed value and drops the constraint, so each loses one parameter. See the banner.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use super::parser::ParseCertificate;
use super::x509::Certificate;
use crate::crypto::sha256;
use crate::encoding::pem;
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::int;
use crate::types::byte;

// Go: cert_pool.go:14 — `type sum224 [sha256.Size224]byte`
pub(super) type sum224 = [byte; 28];

// Go: cert_pool.go:16-36
/// A set of certificates.
#[derive(Clone, Default)]
pub struct CertPool {
    /// cert.RawSubject => index into lazyCerts
    byName: map<string, slice<int>>,

    /// Contains the certificates of the pool. Go stores funcs that return
    /// a certificate, lazily parsing it as needed; see the banner.
    lazyCerts: slice<lazyCert>,

    /// Maps from sum224(cert.Raw) to true. It's used only for AddCert
    /// duplicate detection, to avoid CertPool.contains calls in the
    /// AddCert path.
    haveSum: map<string, bool>,

    /// Indicates whether this is a special pool derived from the system
    /// roots.
    systemPool: bool,
}

// Go: cert_pool.go:38-61
/// Minimal metadata about a Cert plus the cert itself. See the banner for
/// why the `getCert` closure and the `constraint` closure are not fields.
#[derive(Clone, Default)]
struct lazyCert {
    /// The Certificate.RawSubject value. It's the same as the
    /// CertPool.byName key, but in `slice<byte>` form to make
    /// CertPool.Subjects (as used by crypto/tls) do fewer allocations.
    rawSubject: slice<byte>,

    /// The certificate.
    getCert: Certificate,
}

// go: sdk 1.25.5 crypto/x509/cert_pool.go:63-69 NewCertPool
/// Return a new, empty CertPool.
pub fn NewCertPool() -> CertPool {
    return CertPool {
        byName: map::new(),
        lazyCerts: slice::__from_vec(Vec::<lazyCert>::new()),
        haveSum: map::new(),
        systemPool: false,
    };
}

impl CertPool {
    // go: sdk 1.25.5 crypto/x509/cert_pool.go:71-78 CertPool.len
    /// The number of certs in the set. Go's nil-receiver case is the zero
    /// value here, whose `lazyCerts` is empty.
    pub(super) fn len(&self) -> int {
        return self.lazyCerts.Len();
    }

    // go: none — goish idiom: `len` is unexported in Go and reachable
    // from a test only through the package. goish's e2e examples live
    // outside the crate, so the same count needs a public name.
    pub fn Len(&self) -> int {
        return self.len();
    }

    // go: sdk 1.25.5 crypto/x509/cert_pool.go:80-84 CertPool.cert
    /// Cert index n in s. Go also returns the per-cert `constraint`
    /// closure and an error from the lazy parse; neither exists here, see
    /// the banner.
    pub(super) fn cert(&self, n: int) -> Certificate {
        return self.lazyCerts[n].getCert.clone();
    }

    // go: sdk 1.25.5 crypto/x509/cert_pool.go:86-104 CertPool.Clone
    /// Return a copy of s.
    pub fn Clone(&self) -> CertPool {
        // Go rebuilds the maps entry by entry so the copy shares no
        // backing; goish's `map` and `slice` are owned values whose
        // `Clone` already deep-copies.
        return CertPool {
            byName: self.byName.clone(),
            lazyCerts: self.lazyCerts.clone(),
            haveSum: self.haveSum.clone(),
            systemPool: self.systemPool,
        };
    }

    // go: sdk 1.25.5 crypto/x509/cert_pool.go:179-187 CertPool.AddCert
    /// Add a certificate to a pool.
    pub fn AddCert(&mut self, cert: Certificate) {
        // Go panics on a nil *Certificate; the goish shape has no nil
        // pointer, and an unparsed zero value has no RawSubject, which
        // `addCertFunc` documents as required.
        if cert.Raw.Len() == 0 {
            panic!("adding nil Certificate to CertPool");
        }
        let sum = sha256::Sum224(cert.Raw.clone());
        let rawSubject = string::from_bytes(&cert.RawSubject);
        self.addCertFunc(sum, rawSubject, cert);
    }

    // go: sdk 1.25.5 crypto/x509/cert_pool.go:189-211 CertPool.addCertFunc
    /// Add metadata about a certificate to a pool, along with the
    /// certificate itself. The rawSubject is Certificate.RawSubject and
    /// must be non-empty.
    fn addCertFunc(&mut self, rawSum224: sum224, rawSubject: string, getCert: Certificate) {
        // Check that the certificate isn't being added twice.
        let sumKey = string::from_bytes(&rawSum224);
        let (have, _) = self.haveSum.Get(sumKey.clone());
        if have {
            return;
        }

        self.haveSum.Set(sumKey, true);
        self.lazyCerts = crate::append!(
            self.lazyCerts.clone(),
            lazyCert {
                rawSubject: crate::convert::bytes(rawSubject.clone()),
                getCert: getCert,
            }
        );
        let (idxs, _) = self.byName.Get(rawSubject.clone());
        self.byName
            .Set(rawSubject, crate::append!(idxs, self.lazyCerts.Len() - 1));
    }

    // go: sdk 1.25.5 crypto/x509/cert_pool.go:213-251 CertPool.AppendCertsFromPEM
    /// Attempt to parse a series of PEM encoded certificates. It appends
    /// any certificates found to s and reports whether any certificates
    /// were successfully parsed.
    ///
    /// On many Linux systems, /etc/ssl/cert.pem will contain the system
    /// wide set of root CAs in a format suitable for this function.
    pub fn AppendCertsFromPEM(&mut self, pemCerts: slice<byte>) -> bool {
        let mut ok = false;
        let mut pemCerts = pemCerts;
        while pemCerts.Len() > 0 {
            let (block, rest) = pem::Decode(pemCerts);
            pemCerts = rest;
            let block = match block {
                None => break,
                Some(b) => b,
            };
            if block.Type != "CERTIFICATE" || block.Headers.Len() != 0 {
                continue;
            }

            let certBytes = block.Bytes;
            let (cert, err) = ParseCertificate(certBytes);
            if err != crate::nil {
                continue;
            }
            let sum = sha256::Sum224(cert.Raw.clone());
            let rawSubject = string::from_bytes(&cert.RawSubject);
            self.addCertFunc(sum, rawSubject, cert);
            ok = true;
        }

        return ok;
    }

    // go: sdk 1.25.5 crypto/x509/cert_pool.go:253-264 CertPool.Subjects
    /// Return a list of the DER-encoded subjects of all of the
    /// certificates in the pool.
    ///
    /// Deprecated: if s was returned by `SystemCertPool`, Subjects will
    /// not include the system roots.
    pub fn Subjects(&self) -> slice<slice<byte>> {
        let mut res: Vec<slice<byte>> = Vec::with_capacity(self.len() as usize);
        for (_, lc) in crate::range!(self.lazyCerts.clone()) {
            res.push(lc.rawSubject.clone());
        }
        return slice::__from_vec(res);
    }

    // go: sdk 1.25.5 crypto/x509/cert_pool.go:266-280 CertPool.Equal
    /// Report whether s and other are equal.
    pub fn Equal(&self, other: &CertPool) -> bool {
        if self.systemPool != other.systemPool || self.haveSum.Len() != other.haveSum.Len() {
            return false;
        }
        for (h, _) in crate::range!(self.haveSum.clone()) {
            let (have, _) = other.haveSum.Get(h.clone());
            if !have {
                return false;
            }
        }
        return true;
    }

    // go: sdk 1.25.5 crypto/x509/cert_pool.go:282-294 CertPool.AddCertWithConstraint
    /// Add a certificate to the pool with the additional constraint.
    ///
    /// **The constraint is not stored.** Go passes it to
    /// `Certificate.Verify`, which runs it against every chain rooted by
    /// `cert`; `Verify` is not ported (verify.go needs net/netip), so a
    /// stored constraint would have no reader. Rather than keep a
    /// `Box<dyn Fn>` field that nothing consumes, this is `AddCert` and
    /// the constraint parameter is absent. It comes back with `Verify`.
    pub fn AddCertWithConstraint(&mut self, cert: Certificate) {
        self.AddCert(cert);
    }
}
