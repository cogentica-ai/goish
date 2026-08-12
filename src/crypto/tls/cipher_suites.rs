// go: file crypto/tls/cipher_suites.go decls:
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
// The preference order is a security-relevant table: it decides which
// suite a handshake picks. It is transcribed in Go's exact order,
// comments included, and pinned element-by-element against a running Go
// in `examples/tls_common_smoke.rs`.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

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
