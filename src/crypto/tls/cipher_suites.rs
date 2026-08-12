// go: file crypto/tls/cipher_suites.go decls: CipherSuites, InsecureCipherSuites, CipherSuiteName
//
// (no functions yet — this file ports cipher_suites.go's ID constants
// and ordering tables only; the `decls:` manifest lists ported *funcs*,
// and the suite records and AEAD constructors are still to come.)
//
// crypto/tls — cipher suite IDs and the preference ordering.
//
// **Partial port.** cipher_suites.go is 724 lines; the rest of it is the
// `cipherSuite` / `cipherSuiteTLS13` records and the AEAD, CBC and MAC
// constructors that hang off them, which need the record layer. What is
// here is the ID surface and the ordering tables — the part `defaults.go`
// needs, and the part that is pure data.
//
// goishlint:ignore GOISH018 aeadAESGCM, aeadAESGCMTLS13, aeadChaCha20Poly1305, BlockSize, cipher3DES, cipherAES, cipherRC4, cipherSuiteByID, cipherSuiteTLS13ByID, ecdheECDSAKA, ecdheRSAKA, explicitNonceLen, isAESGCMPreferred, macSHA1, macSHA256, mutualCipherSuite, mutualCipherSuiteTLS13, newConstantTimeHash, NonceSize, Open, Overhead, Reset, rsaKA, Seal, selectCipherSuite, Size, Sum, tls10MAC, Write — the cipherSuite/cipherSuiteTLS13 records and the AEAD, CBC and MAC constructors that hang off them; every one needs the record layer. See ROADMAP.md.
// goishlint:ignore GOISH021 aead, aeadNonceLength, aesgcmCiphers, cipherSuitesTLS13, cipherSuiteTLS13, constantTimeHash, cthWrapper, noncePrefixLength, prefixNonceAEAD, suiteECDHE, suiteECSign, suiteSHA384, suiteTLS12, xorNonceAEAD — same.
//
// The preference order is a security-relevant table: it decides which
// suite a handshake picks. It is transcribed in Go's exact order,
// comments included, and pinned element-by-element against a running Go
// in `examples/tls_common_smoke.rs`.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

extern crate alloc;

use crate::types::uint16;

// Go: cipher_suites.go:116-160 — "A list of cipher suite IDs that are,
// or have been, implemented by this package."
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml

// TLS 1.0 - 1.2 cipher suites.
pub const TLS_RSA_WITH_RC4_128_SHA: uint16 = 0x0005;
pub const TLS_RSA_WITH_3DES_EDE_CBC_SHA: uint16 = 0x000a;
pub const TLS_RSA_WITH_AES_128_CBC_SHA: uint16 = 0x002f;
pub const TLS_RSA_WITH_AES_256_CBC_SHA: uint16 = 0x0035;
pub const TLS_RSA_WITH_AES_128_CBC_SHA256: uint16 = 0x003c;
pub const TLS_RSA_WITH_AES_128_GCM_SHA256: uint16 = 0x009c;
pub const TLS_RSA_WITH_AES_256_GCM_SHA384: uint16 = 0x009d;
pub const TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: uint16 = 0xc007;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: uint16 = 0xc009;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: uint16 = 0xc00a;
pub const TLS_ECDHE_RSA_WITH_RC4_128_SHA: uint16 = 0xc011;
pub const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: uint16 = 0xc012;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: uint16 = 0xc013;
pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: uint16 = 0xc014;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: uint16 = 0xc023;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: uint16 = 0xc027;
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: uint16 = 0xc02f;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: uint16 = 0xc02b;
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: uint16 = 0xc030;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: uint16 = 0xc02c;
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: uint16 = 0xcca8;
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: uint16 = 0xcca9;

// TLS 1.3 cipher suites.
pub const TLS_AES_128_GCM_SHA256: uint16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: uint16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: uint16 = 0x1303;

/// `TLS_FALLBACK_SCSV` isn't a standard cipher suite but an indicator
/// that the client is doing version fallback. See RFC 7507.
pub const TLS_FALLBACK_SCSV: uint16 = 0x5600;

// Legacy names for the corresponding cipher suites with the correct
// _SHA256 suffix, retained for backward compatibility.
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305: uint16 =
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305: uint16 =
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;

// Go: cipher_suites.go — `var cipherSuitesPreferenceOrder = []uint16{…}`
//
// "The order of the cipher suites is a security-relevant decision: it
// picks the suite when both peers support several." Go's comments are
// kept verbatim below.
/// Preference order when AES-GCM hardware support is available.
pub(crate) const cipherSuitesPreferenceOrder: &[uint16] = &[
    // AEADs w/ ECDHE
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
    // CBC w/ ECDHE
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    // AEADs w/o ECDHE
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    // CBC w/o ECDHE
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    // 3DES
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    // CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    // RC4
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    TLS_RSA_WITH_RC4_128_SHA,
];

/// Preference order when AES-GCM has no hardware support, so
/// ChaCha20-Poly1305 comes first.
pub(crate) const cipherSuitesPreferenceOrderNoAES: &[uint16] = &[
    // ChaCha20Poly1305
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
    // AES-GCM w/ ECDHE
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    // The rest of cipherSuitesPreferenceOrder.
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    TLS_RSA_WITH_RC4_128_SHA,
];

// Go declares the three sets below as `map[uint16]bool`. goish has no
// const map, so each is a sorted slice queried by a helper — the only
// use in Go is membership (`disabledCipherSuites[c]`), so a set is a
// set. Same members, checked against Go.

// go: none — goish idiom: the `map[uint16]bool` membership test.
fn contains(set: &[uint16], c: uint16) -> bool {
    let mut i = 0usize;
    while i < set.len() {
        if set[i] == c {
            return true;
        }
        i += 1;
    }
    return false;
}

/// Go: `var disabledCipherSuites = map[uint16]bool{…}` — suites off by
/// default because they are weak.
pub(crate) const disabledCipherSuites: &[uint16] = &[
    // CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    // RC4
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    TLS_RSA_WITH_RC4_128_SHA,
];

/// Go: `var rsaKexCiphers = map[uint16]bool{…}` — the RSA key-exchange
/// suites, off unless `GODEBUG=tlsrsakex=1`.
pub(crate) const rsaKexCiphers: &[uint16] = &[
    TLS_RSA_WITH_RC4_128_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
];

/// Go: `var tdesCiphers = map[uint16]bool{…}` — the 3DES suites, off
/// unless `GODEBUG=tls3des=1`.
pub(crate) const tdesCiphers: &[uint16] = &[
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
];

// go: none — goish idiom: the three membership helpers Go spells as a
// map index. Named after the tables so call sites read like Go's.
pub(crate) fn isDisabledCipherSuite(c: uint16) -> bool {
    return contains(disabledCipherSuites, c);
}

// go: none — goish idiom: see `isDisabledCipherSuite`.
pub(crate) fn isRSAKexCipher(c: uint16) -> bool {
    return contains(rsaKexCiphers, c);
}

// go: none — goish idiom: see `isDisabledCipherSuite`.
pub(crate) fn isTDESCipher(c: uint16) -> bool {
    return contains(tdesCiphers, c);
}


// ─── The public CipherSuite surface ───────────────────────────────────

// Go: cipher_suites.go:44-46
//   var ( supportedUpToTLS12 = []uint16{VersionTLS10, VersionTLS11, VersionTLS12}
//         supportedOnlyTLS12 = []uint16{VersionTLS12}
//         supportedOnlyTLS13 = []uint16{VersionTLS13} )
const supportedUpToTLS12: &[uint16] = &[
    super::common::VersionTLS10,
    super::common::VersionTLS11,
    super::common::VersionTLS12,
];
const supportedOnlyTLS12: &[uint16] = &[super::common::VersionTLS12];
const supportedOnlyTLS13: &[uint16] = &[super::common::VersionTLS13];

// Go: cipher_suites.go:19-34
//   type CipherSuite struct { ID uint16; Name string;
//                             SupportedVersions []uint16; Insecure bool }
/// `tls.CipherSuite` — a TLS cipher suite, as returned by
/// [`CipherSuites`] and [`InsecureCipherSuites`].
#[derive(Clone, Default, PartialEq)]
pub struct CipherSuite {
    pub ID: uint16,
    pub Name: crate::gostring::string,
    /// The TLS protocol versions that can negotiate this suite.
    pub SupportedVersions: crate::goslice::slice<uint16>,
    /// True if the suite has known security issues due to its
    /// primitives, design, or implementation.
    pub Insecure: bool,
}

// go: none — goish idiom: Go writes these as composite literals inside
// the two functions below; naming the constructor keeps each row on one
// line, as Go's are.
fn cs(id: uint16, name: &'static str, vers: &[uint16], insecure: bool) -> CipherSuite {
    return CipherSuite {
        ID: id,
        Name: crate::gostring::string::from_static(name),
        SupportedVersions: crate::goslice::slice::__from_vec(vers.to_vec()),
        Insecure: insecure,
    };
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:56-75 CipherSuites
/// The cipher suites currently implemented by this package, excluding
/// those with security issues — see [`InsecureCipherSuites`].
///
/// The list is sorted by ID. Note that the default cipher suites
/// selected by this package might depend on logic that cannot be
/// captured by a static list, and might not match those returned here.
pub fn CipherSuites() -> crate::goslice::slice<CipherSuite> {
    return crate::goslice::slice::__from_vec(alloc::vec![
        cs(TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256", supportedOnlyTLS13, false),
        cs(TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384", supportedOnlyTLS13, false),
        cs(TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256", supportedOnlyTLS13, false),
        cs(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", supportedUpToTLS12, false),
        cs(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", supportedUpToTLS12, false),
        cs(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", supportedUpToTLS12, false),
        cs(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", supportedUpToTLS12, false),
        cs(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", supportedOnlyTLS12, false),
        cs(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", supportedOnlyTLS12, false),
        cs(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", supportedOnlyTLS12, false),
        cs(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", supportedOnlyTLS12, false),
        cs(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", supportedOnlyTLS12, false),
        cs(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", supportedOnlyTLS12, false),
    ]);
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:77-98 InsecureCipherSuites
/// The cipher suites currently implemented by this package that have
/// security issues.
///
/// Most applications should not use the cipher suites in this list, and
/// should only use those returned by [`CipherSuites`].
pub fn InsecureCipherSuites() -> crate::goslice::slice<CipherSuite> {
    // Go: This list includes legacy RSA kex, RC4, CBC_SHA256, and 3DES
    // cipher suites. See cipherSuitesPreferenceOrder for details.
    return crate::goslice::slice::__from_vec(alloc::vec![
        cs(TLS_RSA_WITH_RC4_128_SHA, "TLS_RSA_WITH_RC4_128_SHA", supportedUpToTLS12, true),
        cs(TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", supportedUpToTLS12, true),
        cs(TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA", supportedUpToTLS12, true),
        cs(TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA", supportedUpToTLS12, true),
        cs(TLS_RSA_WITH_AES_128_CBC_SHA256, "TLS_RSA_WITH_AES_128_CBC_SHA256", supportedOnlyTLS12, true),
        cs(TLS_RSA_WITH_AES_128_GCM_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256", supportedOnlyTLS12, true),
        cs(TLS_RSA_WITH_AES_256_GCM_SHA384, "TLS_RSA_WITH_AES_256_GCM_SHA384", supportedOnlyTLS12, true),
        cs(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", supportedUpToTLS12, true),
        cs(TLS_ECDHE_RSA_WITH_RC4_128_SHA, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", supportedUpToTLS12, true),
        cs(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", supportedUpToTLS12, true),
        cs(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", supportedOnlyTLS12, true),
        cs(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", supportedOnlyTLS12, true),
    ]);
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:100-114 CipherSuiteName
/// The IANA name of the cipher suite, or a fallback of the form
/// `"0x0042"` for an unknown ID.
pub fn CipherSuiteName(id: uint16) -> crate::gostring::string {
    // Go: for _, c := range CipherSuites() { if c.ID == id { return c.Name } }
    for (_, c) in crate::range!(CipherSuites()) {
        if c.ID == id {
            return c.Name.clone();
        }
    }
    // Go: for _, c := range InsecureCipherSuites() { … }
    for (_, c) in crate::range!(InsecureCipherSuites()) {
        if c.ID == id {
            return c.Name.clone();
        }
    }
    // Go: return fmt.Sprintf("0x%04X", id)
    return crate::fmt::Sprintf!("0x%04X", id);
}
