// go: file crypto/tls/cipher_suites.go decls: CipherSuites, InsecureCipherSuites, CipherSuiteName, prefixNonceAEAD.NonceSize, prefixNonceAEAD.Overhead, prefixNonceAEAD.explicitNonceLen, prefixNonceAEAD.Seal, prefixNonceAEAD.Open, xorNonceAEAD.NonceSize, xorNonceAEAD.Overhead, xorNonceAEAD.explicitNonceLen, xorNonceAEAD.Seal, xorNonceAEAD.Open, aeadAESGCM, aeadAESGCMTLS13, aeadChaCha20Poly1305, cthWrapper.Size, cthWrapper.BlockSize, cthWrapper.Reset, cthWrapper.Write, cthWrapper.Sum, newConstantTimeHash, macSHA1, macSHA256, tls10MAC, mutualCipherSuiteTLS13, cipherSuiteTLS13ByID, cipherRC4, cipher3DES, cipherAES, rsaKA, ecdheECDSAKA, ecdheRSAKA, selectCipherSuite, isAESGCMPreferred, mutualCipherSuite, cipherSuiteByID
//
// crypto/tls — cipher suite IDs, the preference ordering, and the
// record-layer primitives the suites name.
//
// **Partial port.** What is here is everything that does not need the
// handshake: the ID surface, the ordering tables, the two nonce
// wrappers and their three AEAD constructors, the two MACs and the
// constant-time SHA-1 they hash through, `tls10MAC`, and the TLS 1.3
// suite table with its two lookups. What is not here is the
// `cipherSuite` record for TLS 1.0-1.2 — its `ka` field is a
// `keyAgreement` constructor, so the record cannot exist before
// key_agreement.go's two implementations do — and the three block-cipher
// constructors, which return Go's `any` for the record layer to assert
// back to a `cipher.Stream` or `cipher.BlockMode`.
//
//
// The preference order is a security-relevant table: it decides which
// suite a handshake picks. It is transcribed in Go's exact order,
// comments included, and pinned element-by-element against a running Go
// in `examples/tls_common_smoke.rs`. So are the AEAD ciphertexts and the
// MACs — every hex string in that example came out of `goref.sh`.

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


// ─── The AEAD, MAC and TLS 1.3 suite records ──────────────────────────
//
// Everything below here is the half of cipher_suites.go that builds the
// record-layer primitives. It needs nothing from the handshake: given a
// key and a nonce prefix it hands back a sealer.

use crate::crypto;
use crate::crypto::aes;
use crate::crypto::chacha20poly1305;
use crate::crypto::hmac;
use crate::crypto::internal::fips140::aes::gcm;
use crate::crypto::sha1;
use crate::crypto::sha256;
use crate::error;
use crate::goslice::slice;
use crate::hash::{Hash, HashFunc};
use crate::io::Writer as _;
use crate::types::{byte, int};
use alloc::boxed::Box;

// go: none — goish-only: Go's `cipher.AEAD` is satisfied structurally,
// so `*gcm.GCMForTLS12` — whose `Seal` advances a nonce counter through
// a pointer receiver — is a `cipher.AEAD`. goish's `cipher::AEAD` takes
// `&self` and so cannot host a stateful sealer. This restates the same
// four methods with `&mut self`, and is what the two nonce wrappers
// below hold in the field Go declares as `aead cipher.AEAD`.
pub(crate) trait mutAEAD {
    fn NonceSize(&self) -> int;
    fn Overhead(&self) -> int;
    fn Seal(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additionalData: slice<byte>,
    ) -> slice<byte>;
    fn Open(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additionalData: slice<byte>,
    ) -> (slice<byte>, error);
}

impl mutAEAD for gcm::GCMForTLS12 {
    // go: none — goish-only: Go asserts `*gcm.GCMForTLS12` to
    // `cipher.AEAD` structurally; goish spells the impl.
    fn NonceSize(&self) -> int {
        return gcm::GCMForTLS12::NonceSize(self);
    }
    // go: none — goish-only: see `NonceSize` above.
    fn Overhead(&self) -> int {
        return gcm::GCMForTLS12::Overhead(self);
    }
    // go: none — goish-only: see `NonceSize` above.
    fn Seal(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additionalData: slice<byte>,
    ) -> slice<byte> {
        return gcm::GCMForTLS12::Seal(self, dst, nonce, plaintext, additionalData);
    }
    // go: none — goish-only: see `NonceSize` above.
    fn Open(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additionalData: slice<byte>,
    ) -> (slice<byte>, error) {
        return gcm::GCMForTLS12::Open(self, dst, nonce, ciphertext, additionalData);
    }
}

impl mutAEAD for gcm::GCMForTLS13 {
    // go: none — goish-only: see `mutAEAD`.
    fn NonceSize(&self) -> int {
        return gcm::GCMForTLS13::NonceSize(self);
    }
    // go: none — goish-only: see `mutAEAD`.
    fn Overhead(&self) -> int {
        return gcm::GCMForTLS13::Overhead(self);
    }
    // go: none — goish-only: see `mutAEAD`.
    fn Seal(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additionalData: slice<byte>,
    ) -> slice<byte> {
        return gcm::GCMForTLS13::Seal(self, dst, nonce, plaintext, additionalData);
    }
    // go: none — goish-only: see `mutAEAD`.
    fn Open(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additionalData: slice<byte>,
    ) -> (slice<byte>, error) {
        return gcm::GCMForTLS13::Open(self, dst, nonce, ciphertext, additionalData);
    }
}

impl mutAEAD for chacha20poly1305::ChaCha20Poly1305 {
    // go: none — goish-only: see `mutAEAD`. ChaCha20-Poly1305 is
    // stateless, so every method forwards to the `cipher::AEAD` impl.
    fn NonceSize(&self) -> int {
        return crate::crypto::cipher::AEAD::NonceSize(self);
    }
    // go: none — goish-only: see `mutAEAD`.
    fn Overhead(&self) -> int {
        return crate::crypto::cipher::AEAD::Overhead(self);
    }
    // go: none — goish-only: see `mutAEAD`.
    fn Seal(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additionalData: slice<byte>,
    ) -> slice<byte> {
        return crate::crypto::cipher::AEAD::Seal(self, dst, nonce, plaintext, additionalData);
    }
    // go: none — goish-only: see `mutAEAD`.
    fn Open(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additionalData: slice<byte>,
    ) -> (slice<byte>, error) {
        return crate::crypto::cipher::AEAD::Open(self, dst, nonce, ciphertext, additionalData);
    }
}

// Go: cipher_suites.go:446-453
//   type aead interface {
//       cipher.AEAD
//       explicitNonceLen() int
//   }
/// The record layer's AEAD: a `cipher.AEAD` that also reports how many
/// bytes of explicit nonce ride in each record — eight for the older
/// AEADs and zero for the modern ones.
pub(crate) trait aead: mutAEAD {
    fn explicitNonceLen(&self) -> int;
}

// Go: cipher_suites.go:455-458
//   const ( aeadNonceLength = 12; noncePrefixLength = 4 )
pub(crate) const aeadNonceLength: int = 12;
pub(crate) const noncePrefixLength: int = 4;

// Go: cipher_suites.go:462-466
//   type prefixNonceAEAD struct { nonce [aeadNonceLength]byte; aead cipher.AEAD }
/// Wraps an AEAD and prefixes a fixed portion of the nonce to each call.
pub(crate) struct prefixNonceAEAD {
    /// The fixed part of the nonce lives in the first four bytes.
    nonce: [byte; aeadNonceLength as usize],
    aead: Box<dyn mutAEAD + Send + Sync>,
}

impl mutAEAD for prefixNonceAEAD {
    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:468-468 prefixNonceAEAD.NonceSize
    fn NonceSize(&self) -> int {
        // Go: return aeadNonceLength - noncePrefixLength
        return aeadNonceLength - noncePrefixLength;
    }

    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:469-469 prefixNonceAEAD.Overhead
    fn Overhead(&self) -> int {
        // Go: return f.aead.Overhead()
        return self.aead.Overhead();
    }

    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:472-475 prefixNonceAEAD.Seal
    fn Seal(
        &mut self,
        out: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additionalData: slice<byte>,
    ) -> slice<byte> {
        // Go: copy(f.nonce[4:], nonce)
        copyIntoNonce(&mut self.nonce, nonce);
        // Go: return f.aead.Seal(out, f.nonce[:], plaintext, additionalData)
        let full = slice::__from_vec(self.nonce.to_vec());
        return self.aead.Seal(out, full, plaintext, additionalData);
    }

    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:477-480 prefixNonceAEAD.Open
    fn Open(
        &mut self,
        out: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additionalData: slice<byte>,
    ) -> (slice<byte>, error) {
        // Go: copy(f.nonce[4:], nonce)
        copyIntoNonce(&mut self.nonce, nonce);
        // Go: return f.aead.Open(out, f.nonce[:], ciphertext, additionalData)
        let full = slice::__from_vec(self.nonce.to_vec());
        return self.aead.Open(out, full, ciphertext, additionalData);
    }
}

impl aead for prefixNonceAEAD {
    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:470-470 prefixNonceAEAD.explicitNonceLen
    fn explicitNonceLen(&self) -> int {
        // Go: return f.NonceSize()
        return mutAEAD::NonceSize(self);
    }
}

// go: none — goish-only: Go writes `copy(f.nonce[4:], nonce)`; a fixed
// Rust array needs the bound spelled out. Same truncating semantics as
// Go's `copy`.
fn copyIntoNonce(dst: &mut [byte; aeadNonceLength as usize], nonce: slice<byte>) {
    let src: &[byte] = &nonce;
    let mut i: usize = 0;
    while i < src.len() && noncePrefixLength as usize + i < dst.len() {
        dst[noncePrefixLength as usize + i] = src[i];
        i += 1;
    }
}

// Go: cipher_suites.go:484-487
//   type xorNonceAEAD struct { nonceMask [aeadNonceLength]byte; aead cipher.AEAD }
/// Wraps an AEAD by XORing a fixed pattern into the nonce before each
/// call.
pub(crate) struct xorNonceAEAD {
    nonceMask: [byte; aeadNonceLength as usize],
    aead: Box<dyn mutAEAD + Send + Sync>,
}

impl mutAEAD for xorNonceAEAD {
    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:489-489 xorNonceAEAD.NonceSize
    fn NonceSize(&self) -> int {
        // Go: return 8 // 64-bit sequence number
        return 8;
    }

    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:490-490 xorNonceAEAD.Overhead
    fn Overhead(&self) -> int {
        // Go: return f.aead.Overhead()
        return self.aead.Overhead();
    }

    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:493-503 xorNonceAEAD.Seal
    fn Seal(
        &mut self,
        out: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additionalData: slice<byte>,
    ) -> slice<byte> {
        // Go: for i, b := range nonce { f.nonceMask[4+i] ^= b }
        xorIntoNonceMask(&mut self.nonceMask, nonce.clone());
        // Go: result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
        let masked = slice::__from_vec(self.nonceMask.to_vec());
        let result = self.aead.Seal(out, masked, plaintext, additionalData);
        // Go: for i, b := range nonce { f.nonceMask[4+i] ^= b }
        xorIntoNonceMask(&mut self.nonceMask, nonce);

        // Go: return result
        return result;
    }

    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:505-515 xorNonceAEAD.Open
    fn Open(
        &mut self,
        out: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additionalData: slice<byte>,
    ) -> (slice<byte>, error) {
        // Go: for i, b := range nonce { f.nonceMask[4+i] ^= b }
        xorIntoNonceMask(&mut self.nonceMask, nonce.clone());
        // Go: result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
        let masked = slice::__from_vec(self.nonceMask.to_vec());
        let (result, err) = self.aead.Open(out, masked, ciphertext, additionalData);
        // Go: for i, b := range nonce { f.nonceMask[4+i] ^= b }
        xorIntoNonceMask(&mut self.nonceMask, nonce);

        // Go: return result, err
        return (result, err);
    }
}

impl aead for xorNonceAEAD {
    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:491-491 xorNonceAEAD.explicitNonceLen
    fn explicitNonceLen(&self) -> int {
        // Go: return 0
        return 0;
    }
}

// go: none — goish-only: Go writes the `for i, b := range nonce` loop
// inline in both Seal and Open, twice each. A fixed Rust array needs
// the bound spelled out, so the loop is named instead of repeated.
fn xorIntoNonceMask(mask: &mut [byte; aeadNonceLength as usize], nonce: slice<byte>) {
    for (i, b) in crate::range!(nonce) {
        mask[noncePrefixLength as usize + i as usize] ^= *b;
    }
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:517-539 aeadAESGCM
/// AES-GCM with TLS 1.2's explicit-nonce discipline (RFC 5288).
pub(crate) fn aeadAESGCM(key: slice<byte>, noncePrefix: slice<byte>) -> Box<dyn aead + Send + Sync> {
    // Go: if len(noncePrefix) != noncePrefixLength { panic(…) }
    if noncePrefix.Len() != noncePrefixLength {
        panic!("tls: internal error: wrong nonce length");
    }
    // Go: aes, err := aes.NewCipher(key); if err != nil { panic(err) }
    let (block, err) = aes::NewCipher(key);
    if err != crate::errors::nil {
        panic!("tls: internal error: aes.NewCipher");
    }
    // Go: boring.Unreachable(); aead, err = gcm.NewGCMForTLS12(aes.(*fipsaes.Block))
    //     if err != nil { panic(err) }
    let (g, err) = gcm::NewGCMForTLS12(&block.unwrap());
    if err != crate::errors::nil {
        panic!("tls: internal error: gcm.NewGCMForTLS12");
    }

    // Go: ret := &prefixNonceAEAD{aead: aead}
    //     copy(ret.nonce[:], noncePrefix)
    //     return ret
    let mut ret = prefixNonceAEAD {
        nonce: [0u8; aeadNonceLength as usize],
        aead: Box::new(g.unwrap()),
    };
    copyPrefix(&mut ret.nonce, noncePrefix);
    return Box::new(ret);
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:551-573 aeadAESGCMTLS13
/// AES-GCM with TLS 1.3's XOR-masked nonce discipline (RFC 8446 §5.3).
pub(crate) fn aeadAESGCMTLS13(
    key: slice<byte>,
    nonceMask: slice<byte>,
) -> Box<dyn aead + Send + Sync> {
    // Go: if len(nonceMask) != aeadNonceLength { panic(…) }
    if nonceMask.Len() != aeadNonceLength {
        panic!("tls: internal error: wrong nonce length");
    }
    // Go: aes, err := aes.NewCipher(key); if err != nil { panic(err) }
    let (block, err) = aes::NewCipher(key);
    if err != crate::errors::nil {
        panic!("tls: internal error: aes.NewCipher");
    }
    // Go: boring.Unreachable(); aead, err = gcm.NewGCMForTLS13(aes.(*fipsaes.Block))
    let (g, err) = gcm::NewGCMForTLS13(&block.unwrap());
    if err != crate::errors::nil {
        panic!("tls: internal error: gcm.NewGCMForTLS13");
    }

    // Go: ret := &xorNonceAEAD{aead: aead}
    //     copy(ret.nonceMask[:], nonceMask)
    //     return ret
    let mut ret = xorNonceAEAD {
        nonceMask: [0u8; aeadNonceLength as usize],
        aead: Box::new(g.unwrap()),
    };
    copyPrefix(&mut ret.nonceMask, nonceMask);
    return Box::new(ret);
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:575-587 aeadChaCha20Poly1305
/// ChaCha20-Poly1305 with TLS 1.3's XOR-masked nonce discipline.
pub(crate) fn aeadChaCha20Poly1305(
    key: slice<byte>,
    nonceMask: slice<byte>,
) -> Box<dyn aead + Send + Sync> {
    // Go: if len(nonceMask) != aeadNonceLength { panic(…) }
    if nonceMask.Len() != aeadNonceLength {
        panic!("tls: internal error: wrong nonce length");
    }
    // Go: aead, err := chacha20poly1305.New(key); if err != nil { panic(err) }
    let (c, err) = chacha20poly1305::New(key);
    if err != crate::errors::nil {
        panic!("tls: internal error: chacha20poly1305.New");
    }

    // Go: ret := &xorNonceAEAD{aead: aead}
    //     copy(ret.nonceMask[:], nonceMask)
    //     return ret
    let mut ret = xorNonceAEAD {
        nonceMask: [0u8; aeadNonceLength as usize],
        aead: Box::new(c.unwrap()),
    };
    copyPrefix(&mut ret.nonceMask, nonceMask);
    return Box::new(ret);
}

// go: none — goish-only: Go writes `copy(ret.nonce[:], noncePrefix)`;
// a fixed Rust array needs the bound spelled out.
fn copyPrefix(dst: &mut [byte; aeadNonceLength as usize], src: slice<byte>) {
    let raw: &[byte] = &src;
    let mut i: usize = 0;
    while i < raw.len() && i < dst.len() {
        dst[i] = raw[i];
        i += 1;
    }
}

// Go: cipher_suites.go:589-592
//   type constantTimeHash interface { hash.Hash; ConstantTimeSum(b []byte) []byte }
/// A `hash.Hash` whose checksum can be taken in constant time.
pub(crate) trait constantTimeHash: Hash {
    fn ConstantTimeSum(&self, b: slice<byte>) -> slice<byte>;
}

impl constantTimeHash for sha1::Digest {
    // go: none — goish-only: Go satisfies `constantTimeHash` structurally
    // from `*sha1.digest`; goish spells the impl.
    fn ConstantTimeSum(&self, b: slice<byte>) -> slice<byte> {
        return sha1::Digest::ConstantTimeSum(self, b);
    }
}

// Go: cipher_suites.go:596-598
//   type cthWrapper struct { h constantTimeHash }
/// Wraps any `hash.Hash` that implements `ConstantTimeSum` and replaces
/// every call to `Sum` with that, to obtain a `ConstantTimeSum`-based
/// HMAC.
pub(crate) struct cthWrapper {
    h: Box<dyn constantTimeHash + Send + Sync>,
}

impl crate::io::Writer for cthWrapper {
    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:603-603 cthWrapper.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: return c.h.Write(p)
        return self.h.Write(p);
    }
}

impl Hash for cthWrapper {
    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:604-604 cthWrapper.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: return c.h.ConstantTimeSum(b)
        return self.h.ConstantTimeSum(b);
    }

    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:602-602 cthWrapper.Reset
    fn Reset(&mut self) {
        // Go: c.h.Reset()
        self.h.Reset();
    }

    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:600-600 cthWrapper.Size
    fn Size(&self) -> int {
        // Go: return c.h.Size()
        return self.h.Size();
    }

    // go: sdk 1.25.5 crypto/tls/cipher_suites.go:601-601 cthWrapper.BlockSize
    fn BlockSize(&self) -> int {
        // Go: return c.h.BlockSize()
        return self.h.BlockSize();
    }
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:606-611 newConstantTimeHash
/// Deviation: Go takes `func() hash.Hash` and asserts the result to
/// `constantTimeHash` at each call — a runtime assertion goish cannot
/// spell on a boxed `hash::Hash`. The parameter is therefore typed as
/// the constructor Go's assertion demands, which moves the same failure
/// from a panic to a compile error.
pub(crate) fn newConstantTimeHash(
    h: fn() -> Box<dyn constantTimeHash + Send + Sync>,
) -> HashFunc {
    // Go: boring.Unreachable()
    // Go: return func() hash.Hash { return &cthWrapper{h().(constantTimeHash)} }
    return HashFunc::New(move || {
        let w: Box<dyn Hash + Send + Sync> = Box::new(cthWrapper { h: h() });
        return w;
    });
}

// go: none — goish-only: the one constructor Go passes to
// `newConstantTimeHash`, spelled at the type its assertion demands.
fn newSHA1ConstantTime() -> Box<dyn constantTimeHash + Send + Sync> {
    return Box::new(sha1::New());
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:429-438 macSHA1
/// A SHA-1 based constant-time MAC.
pub(crate) fn macSHA1(key: slice<byte>) -> Box<dyn Hash + Send + Sync> {
    // Go: h := sha1.New
    // Go: if !boring.Enabled { h = newConstantTimeHash(h) }
    //
    // goish has no BoringCrypto, so the branch is always taken — the
    // constant-time checksum is a Lucky13 countermeasure and dropping it
    // would be a silent security regression.
    let h = newConstantTimeHash(newSHA1ConstantTime);
    // Go: return hmac.New(h, key)
    return Box::new(hmac::New(h, key));
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:440-444 macSHA256
/// A SHA-256 based MAC. Supported only in TLS 1.2, and currently used
/// only by disabled-by-default cipher suites.
pub(crate) fn macSHA256(key: slice<byte>) -> Box<dyn Hash + Send + Sync> {
    // Go: return hmac.New(sha256.New, key)
    return Box::new(hmac::New(
        sha256::NewHash as fn() -> Box<dyn Hash + Send + Sync>,
        key,
    ));
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:613-624 tls10MAC
/// The TLS 1.0 MAC function. RFC 2246, Section 6.2.3.
pub(crate) fn tls10MAC(
    h: &mut dyn Hash,
    out: slice<byte>,
    seq: slice<byte>,
    header: slice<byte>,
    data: slice<byte>,
    extra: slice<byte>,
) -> slice<byte> {
    // Go: h.Reset(); h.Write(seq); h.Write(header); h.Write(data)
    h.Reset();
    let _ = h.Write(seq);
    let _ = h.Write(header);
    let _ = h.Write(data);
    // Go: res := h.Sum(out)
    let res = h.Sum(out);
    // Go: if extra != nil { h.Write(extra) }
    //
    // The extra write is a Lucky13 countermeasure: it keeps the number
    // of compression-function blocks constant regardless of padding, and
    // deliberately does not affect `res`.
    // goish slices carry no nil/empty distinction; `len(extra) != 0`
    // is observably identical, since writing zero bytes to a hash is a
    // no-op either way.
    if extra.Len() != 0 {
        let _ = h.Write(extra);
    }
    // Go: return res
    return res;
}

// Go: cipher_suites.go:196-201
//   type cipherSuiteTLS13 struct { id uint16; keyLen int
//                                  aead func(key, fixedNonce []byte) aead
//                                  hash crypto.Hash }
/// Defines only the pair of AEAD algorithm and hash algorithm to be used
/// with HKDF. See RFC 8446, Appendix B.4.
pub(crate) struct cipherSuiteTLS13 {
    pub(crate) id: uint16,
    pub(crate) keyLen: int,
    pub(crate) aead: fn(slice<byte>, slice<byte>) -> Box<dyn aead + Send + Sync>,
    pub(crate) hash: crypto::Hash,
}

// Go: cipher_suites.go:213-217
//   var cipherSuitesTLS13 = []*cipherSuiteTLS13{ … }
pub(crate) static cipherSuitesTLS13: &[cipherSuiteTLS13] = &[
    cipherSuiteTLS13 {
        id: TLS_AES_128_GCM_SHA256,
        keyLen: 16,
        aead: aeadAESGCMTLS13,
        hash: crypto::SHA256,
    },
    cipherSuiteTLS13 {
        id: TLS_CHACHA20_POLY1305_SHA256,
        keyLen: 32,
        aead: aeadChaCha20Poly1305,
        hash: crypto::SHA256,
    },
    cipherSuiteTLS13 {
        id: TLS_AES_256_GCM_SHA384,
        keyLen: 32,
        aead: aeadAESGCMTLS13,
        hash: crypto::SHA384,
    },
];

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:664-671 mutualCipherSuiteTLS13
/// The TLS 1.3 suite the peer asked for, if we have it.
pub(crate) fn mutualCipherSuiteTLS13(
    have: slice<uint16>,
    want: uint16,
) -> Option<&'static cipherSuiteTLS13> {
    // Go: for _, id := range have { if id == want { return cipherSuiteTLS13ByID(id) } }
    for (_, id) in crate::range!(have) {
        if *id == want {
            return cipherSuiteTLS13ByID(*id);
        }
    }
    // Go: return nil
    return None;
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:673-680 cipherSuiteTLS13ByID
/// The TLS 1.3 suite record for `id`, or nil.
pub(crate) fn cipherSuiteTLS13ByID(id: uint16) -> Option<&'static cipherSuiteTLS13> {
    // Go: for _, cipherSuite := range cipherSuitesTLS13 {
    //         if cipherSuite.id == id { return cipherSuite }
    //     }
    for cipherSuite in cipherSuitesTLS13 {
        if cipherSuite.id == id {
            return Some(cipherSuite);
        }
    }
    // Go: return nil
    return None;
}


// ─── The TLS 1.0-1.2 cipherSuite record ───────────────────────────────

use super::key_agreement::{ecdheKeyAgreement, keyAgreement, rsaKeyAgreement};
use crate::crypto::cipher;
use crate::crypto::des;
use crate::crypto::rc4;
use crate::types::uint8;

// Go: cipher_suites.go:116-134
//   const ( suiteECDHE = 1 << iota; suiteECSign; suiteTLS12; suiteSHA384 )
/// Go: "suiteECDHE indicates that the cipher suite involves elliptic
/// curve Diffie-Hellman. This means that it should only be selected when
/// the client indicates that it supports ECC with a curve and point
/// format that we're happy with."
pub(crate) const suiteECDHE: int = 1 << 0;
/// Go: "suiteECSign indicates that the cipher suite involves an ECDSA or
/// EdDSA signature and therefore may only be selected when the server's
/// certificate is ECDSA or EdDSA. If this is not set then the cipher
/// suite is RSA based."
pub(crate) const suiteECSign: int = 1 << 1;
/// Go: "suiteTLS12 indicates that the cipher suite should only be
/// advertised and accepted when using TLS 1.2."
pub(crate) const suiteTLS12: int = 1 << 2;
/// Go: "suiteSHA384 indicates that the cipher suite uses SHA384 as the
/// handshake hash."
pub(crate) const suiteSHA384: int = 1 << 3;

// go: none — goish-only: Go's three block-cipher constructors return
// `any`, which the record layer type-asserts back to a `cipher.Stream`
// (RC4) or a `cipher.BlockMode` (CBC). goish's `Any` is an
// `Arc<dyn AnyVal>` and cannot hand out the `&mut` either of those
// needs, so the closed set of two is spelled as a sum type. Same two
// cases, same constructors.
pub(crate) enum anyCipher {
    Stream(rc4::Cipher),
    BlockMode(Box<dyn cipher::BlockMode + Send + Sync>),
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:408-411 cipherRC4
pub(crate) fn cipherRC4(key: slice<byte>, _iv: slice<byte>, _isRead: bool) -> anyCipher {
    // Go: cipher, _ := rc4.NewCipher(key); return cipher
    let (c, _) = rc4::NewCipher(key);
    return anyCipher::Stream(c.unwrap());
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:413-419 cipher3DES
pub(crate) fn cipher3DES(key: slice<byte>, iv: slice<byte>, isRead: bool) -> anyCipher {
    // Go: block, _ := des.NewTripleDESCipher(key)
    //     if isRead { return cipher.NewCBCDecrypter(block, iv) }
    //     return cipher.NewCBCEncrypter(block, iv)
    let (block, _) = des::NewTripleDESCipher(key);
    let block = block.unwrap();
    if isRead {
        return anyCipher::BlockMode(Box::new(cipher::NewCBCDecrypter(block, iv)));
    }
    return anyCipher::BlockMode(Box::new(cipher::NewCBCEncrypter(block, iv)));
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:421-427 cipherAES
pub(crate) fn cipherAES(key: slice<byte>, iv: slice<byte>, isRead: bool) -> anyCipher {
    // Go: block, _ := aes.NewCipher(key)
    //     if isRead { return cipher.NewCBCDecrypter(block, iv) }
    //     return cipher.NewCBCEncrypter(block, iv)
    let (block, _) = aes::NewCipher(key);
    let block = block.unwrap();
    if isRead {
        return anyCipher::BlockMode(Box::new(cipher::NewCBCDecrypter(block, iv)));
    }
    return anyCipher::BlockMode(Box::new(cipher::NewCBCEncrypter(block, iv)));
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:626-628 rsaKA
pub(crate) fn rsaKA(_version: uint16) -> Box<dyn keyAgreement + Send + Sync> {
    // Go: return rsaKeyAgreement{}
    return Box::new(rsaKeyAgreement::default());
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:630-635 ecdheECDSAKA
pub(crate) fn ecdheECDSAKA(version: uint16) -> Box<dyn keyAgreement + Send + Sync> {
    // Go: return &ecdheKeyAgreement{isRSA: false, version: version}
    let mut ka = ecdheKeyAgreement::default();
    ka.isRSA = false;
    ka.version = version;
    return Box::new(ka);
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:637-642 ecdheRSAKA
pub(crate) fn ecdheRSAKA(version: uint16) -> Box<dyn keyAgreement + Send + Sync> {
    // Go: return &ecdheKeyAgreement{isRSA: true, version: version}
    let mut ka = ecdheKeyAgreement::default();
    ka.isRSA = true;
    ka.version = version;
    return Box::new(ka);
}

// Go: cipher_suites.go:136-149
//   type cipherSuite struct { id uint16; keyLen, macLen, ivLen int
//                             ka func(version uint16) keyAgreement
//                             flags int
//                             cipher func(key, iv []byte, isRead bool) any
//                             mac func(key []byte) hash.Hash
//                             aead func(key, fixedNonce []byte) aead }
/// Go: "A cipherSuite is a TLS 1.0–1.2 cipher suite, and defines the key
/// exchange mechanism, as well as the cipher+MAC pair or the AEAD."
///
/// Go leaves `cipher`/`mac` nil on an AEAD suite and `aead` nil on a
/// CBC one; `Option` carries that.
pub(crate) struct cipherSuite {
    pub id: uint16,
    /// Go: "the lengths, in bytes, of the key material needed for each
    /// component."
    pub keyLen: int,
    pub macLen: int,
    pub ivLen: int,
    pub ka: fn(uint16) -> Box<dyn keyAgreement + Send + Sync>,
    /// Go: "flags is a bitmask of the suite* values, above."
    pub flags: int,
    pub cipher: Option<fn(slice<byte>, slice<byte>, bool) -> anyCipher>,
    pub mac: Option<fn(slice<byte>) -> Box<dyn Hash + Send + Sync>>,
    pub aead: Option<fn(slice<byte>, slice<byte>) -> Box<dyn aead + Send + Sync>>,
}

// go: none — goish-only: Go writes each row of `cipherSuites` as a
// composite literal with positional fields. Naming the constructor keeps
// every row on one line, as Go's are.
const fn cs12(
    id: uint16,
    keyLen: int,
    macLen: int,
    ivLen: int,
    ka: fn(uint16) -> Box<dyn keyAgreement + Send + Sync>,
    flags: int,
    cipher: Option<fn(slice<byte>, slice<byte>, bool) -> anyCipher>,
    mac: Option<fn(slice<byte>) -> Box<dyn Hash + Send + Sync>>,
    aead: Option<fn(slice<byte>, slice<byte>) -> Box<dyn aead + Send + Sync>>,
) -> cipherSuite {
    return cipherSuite { id, keyLen, macLen, ivLen, ka, flags, cipher, mac, aead };
}

// Go: cipher_suites.go:151-174
//   var cipherSuites = []*cipherSuite{ … }
pub(crate) static cipherSuites: &[cipherSuite] = &[
    cs12(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheRSAKA, suiteECDHE | suiteTLS12, None, None, Some(aeadChaCha20Poly1305)),
    cs12(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, None, None, Some(aeadChaCha20Poly1305)),
    cs12(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12, None, None, Some(aeadAESGCM)),
    cs12(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, None, None, Some(aeadAESGCM)),
    cs12(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12 | suiteSHA384, None, None, Some(aeadAESGCM)),
    cs12(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, None, None, Some(aeadAESGCM)),
    cs12(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdheRSAKA, suiteECDHE | suiteTLS12, Some(cipherAES), Some(macSHA256), None),
    cs12(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheRSAKA, suiteECDHE, Some(cipherAES), Some(macSHA1), None),
    cs12(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, Some(cipherAES), Some(macSHA256), None),
    cs12(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECSign, Some(cipherAES), Some(macSHA1), None),
    cs12(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheRSAKA, suiteECDHE, Some(cipherAES), Some(macSHA1), None),
    cs12(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECSign, Some(cipherAES), Some(macSHA1), None),
    cs12(TLS_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, rsaKA, suiteTLS12, None, None, Some(aeadAESGCM)),
    cs12(TLS_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, rsaKA, suiteTLS12 | suiteSHA384, None, None, Some(aeadAESGCM)),
    cs12(TLS_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, rsaKA, suiteTLS12, Some(cipherAES), Some(macSHA256), None),
    cs12(TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, rsaKA, 0, Some(cipherAES), Some(macSHA1), None),
    cs12(TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, rsaKA, 0, Some(cipherAES), Some(macSHA1), None),
    cs12(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, ecdheRSAKA, suiteECDHE, Some(cipher3DES), Some(macSHA1), None),
    cs12(TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, rsaKA, 0, Some(cipher3DES), Some(macSHA1), None),
    cs12(TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0, rsaKA, 0, Some(cipherRC4), Some(macSHA1), None),
    cs12(TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheRSAKA, suiteECDHE, Some(cipherRC4), Some(macSHA1), None),
    cs12(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheECDSAKA, suiteECDHE | suiteECSign, Some(cipherRC4), Some(macSHA1), None),
];

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:178-192 selectCipherSuite
/// Go: "selectCipherSuite returns the first TLS 1.0–1.2 cipher suite
/// from ids which is also in supportedIDs and passes the ok filter."
///
/// goishlint:ignore GOISH008 selectCipherSuite — Go's `ok func(*cipherSuite) bool` is a predicate over an unexported type; `&dyn Fn` is the goish spelling
pub(crate) fn selectCipherSuite(
    ids: slice<uint16>,
    supportedIDs: slice<uint16>,
    ok: &dyn Fn(&'static cipherSuite) -> bool,
) -> Option<&'static cipherSuite> {
    // Go: for _, id := range ids {
    //         candidate := cipherSuiteByID(id)
    //         if candidate == nil || !ok(candidate) { continue }
    //         for _, suppID := range supportedIDs { if id == suppID { return candidate } }
    //     }
    for (_, id) in crate::range!(ids) {
        let candidate = cipherSuiteByID(*id);
        if candidate.is_none() || !ok(candidate.unwrap()) {
            continue;
        }
        for (_, suppID) in crate::range!(supportedIDs.clone()) {
            if *id == *suppID {
                return candidate;
            }
        }
    }
    // Go: return nil
    return None;
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:393-406 isAESGCMPreferred
/// Go: "isAESGCMPreferred returns whether we have hardware support for
/// AES-GCM, and the first known cipher in the peer's preference list is
/// an AES-GCM cipher, implying the peer also has hardware support for
/// it."
///
/// Deviation: `hasAESGCMHardwareSupport` is Go's `internal/cpu` feature
/// probe, which goish does not port. goish's single target is
/// x86_64-unknown-linux-gnu, and AES-NI + PCLMULQDQ have been present on
/// every x86-64 part since Westmere, so the constant is `true` — the
/// same value Go computes on this target.
pub(crate) fn isAESGCMPreferred(ciphers: slice<uint16>) -> bool {
    // Go: if !hasAESGCMHardwareSupport { return false }
    if !hasAESGCMHardwareSupport {
        return false;
    }
    // Go: for _, cID := range ciphers {
    //         if c := cipherSuiteByID(cID); c != nil { return aesgcmCiphers[cID] }
    //         if c := cipherSuiteTLS13ByID(cID); c != nil { return aesgcmCiphers[cID] }
    //     }
    for (_, cID) in crate::range!(ciphers) {
        if cipherSuiteByID(*cID).is_some() {
            return contains(aesgcmCiphers, *cID);
        }
        if cipherSuiteTLS13ByID(*cID).is_some() {
            return contains(aesgcmCiphers, *cID);
        }
    }
    // Go: return false
    return false;
}

/// Go: `var hasAESGCMHardwareSupport = …` — see [`isAESGCMPreferred`].
pub(crate) const hasAESGCMHardwareSupport: bool = true;

// Go: cipher_suites.go:379-388
//   var aesgcmCiphers = map[uint16]bool{ … }
pub(crate) const aesgcmCiphers: &[uint16] = &[
    // TLS 1.2
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    // TLS 1.3
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
];

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:646-653 mutualCipherSuite
/// Go: "mutualCipherSuite returns a cipherSuite given a list of
/// supported ciphersuites and the id requested by the peer."
pub(crate) fn mutualCipherSuite(
    have: slice<uint16>,
    want: uint16,
) -> Option<&'static cipherSuite> {
    // Go: for _, id := range have { if id == want { return cipherSuiteByID(id) } }
    for (_, id) in crate::range!(have) {
        if *id == want {
            return cipherSuiteByID(*id);
        }
    }
    // Go: return nil
    return None;
}

// go: sdk 1.25.5 crypto/tls/cipher_suites.go:655-662 cipherSuiteByID
pub(crate) fn cipherSuiteByID(id: uint16) -> Option<&'static cipherSuite> {
    // Go: for _, cipherSuite := range cipherSuites {
    //         if cipherSuite.id == id { return cipherSuite }
    //     }
    for cipherSuite in cipherSuites {
        if cipherSuite.id == id {
            return Some(cipherSuite);
        }
    }
    // Go: return nil
    return None;
}
