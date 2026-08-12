// go: file crypto/tls/defaults.go decls: defaultCurvePreferences, defaultSupportedSignatureAlgorithms, supportedCipherSuites, defaultCipherSuites
//
// crypto/tls — the default algorithm preferences.
//
// Deviations from defaults[go] @ Go 1.25.5:
//
//   * `internal/godebug` is not ported, so `tlsmlkem`, `tlsrsakex` and
//     `tls3des` are absent and every `GODEBUG` branch takes the unset
//     default — which is what Go does when the variable is not set.
//     The guarded branches are ported in full rather than collapsed,
//     because they are real Go code and a future godebug port needs
//     them. `godebugValue` below is the single place that answers
//     "unset", so wiring godebug up later is one function.
//     goishlint:ignore GOISH021 tlsmlkem, tlsrsakex, tls3des — godebug vars; see above
//   * `defaultCipherSuitesTLS13` / `defaultCipherSuitesTLS13NoAES` are
//     `var` in Go and `const` here; nothing mutates them.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use super::cipher_suites::{
    cipherSuitesPreferenceOrder, cipherSuitesPreferenceOrderNoAES, isDisabledCipherSuite,
    isRSAKexCipher, isTDESCipher, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
};
use super::common::{
    CurveID, SignatureScheme, CurveP256, CurveP384, CurveP521, ECDSAWithP256AndSHA256,
    ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, ECDSAWithSHA1, Ed25519, PKCS1WithSHA1,
    PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PSSWithSHA256, PSSWithSHA384, PSSWithSHA512,
    X25519, X25519MLKEM768,
};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::uint16;

// go: none — goish idiom: `internal/godebug` is not ported. Go's
// `godebug.New("x").Value()` returns "" when the setting is unset, and
// every caller below compares against a specific string, so "" takes
// the default branch exactly as an unset GODEBUG does in Go. One
// function so that porting internal/godebug is a one-line change here.
fn godebugValue(_name: &'static str) -> string {
    return string::from_static("");
}

// go: sdk 1.25.5 crypto/tls/defaults.go:20-25 defaultCurvePreferences
/// The default key-exchange group preference order.
pub(crate) fn defaultCurvePreferences() -> slice<CurveID> {
    // Go: if tlsmlkem.Value() == "0" {
    //         return []CurveID{X25519, CurveP256, CurveP384, CurveP521}
    //     }
    if godebugValue("tlsmlkem") == string::from_static("0") {
        return slice::__from_vec(alloc::vec![X25519, CurveP256, CurveP384, CurveP521]);
    }
    // Go: return []CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384, CurveP521}
    return slice::__from_vec(alloc::vec![
        X25519MLKEM768,
        X25519,
        CurveP256,
        CurveP384,
        CurveP521
    ]);
}

// go: sdk 1.25.5 crypto/tls/defaults.go:31-46 defaultSupportedSignatureAlgorithms
/// The default signature-scheme preference order, most preferred first.
pub(crate) fn defaultSupportedSignatureAlgorithms() -> slice<SignatureScheme> {
    // Go: return []SignatureScheme{PSSWithSHA256, …}
    return slice::__from_vec(alloc::vec![
        PSSWithSHA256,
        ECDSAWithP256AndSHA256,
        Ed25519,
        PSSWithSHA384,
        PSSWithSHA512,
        PKCS1WithSHA256,
        PKCS1WithSHA384,
        PKCS1WithSHA512,
        ECDSAWithP384AndSHA384,
        ECDSAWithP521AndSHA512,
        PKCS1WithSHA1,
        ECDSAWithSHA1,
    ]);
}

// go: sdk 1.25.5 crypto/tls/defaults.go:51-57 supportedCipherSuites
/// Every TLS 1.0-1.2 suite this package implements, in preference order.
pub(crate) fn supportedCipherSuites(aesGCMPreferred: bool) -> slice<uint16> {
    // Go: if aesGCMPreferred { return slices.Clone(cipherSuitesPreferenceOrder) }
    //     else { return slices.Clone(cipherSuitesPreferenceOrderNoAES) }
    if aesGCMPreferred {
        return slice::__from_vec(cipherSuitesPreferenceOrder.to_vec());
    }
    return slice::__from_vec(cipherSuitesPreferenceOrderNoAES.to_vec());
}

// go: sdk 1.25.5 crypto/tls/defaults.go:59-66 defaultCipherSuites
/// `supportedCipherSuites` minus the suites disabled by default.
pub(crate) fn defaultCipherSuites(aesGCMPreferred: bool) -> slice<uint16> {
    // Go: cipherSuites := supportedCipherSuites(aesGCMPreferred)
    let cipherSuites = supportedCipherSuites(aesGCMPreferred);
    // Go: return slices.DeleteFunc(cipherSuites, func(c uint16) bool {
    //         return disabledCipherSuites[c] ||
    //             tlsrsakex.Value() != "1" && rsaKexCiphers[c] ||
    //             tls3des.Value() != "1" && tdesCiphers[c]
    //     })
    let one = string::from_static("1");
    let rsakexOff = godebugValue("tlsrsakex") != one;
    let tdesOff = godebugValue("tls3des") != one;
    let mut out: Vec<uint16> = Vec::new();
    for (_, c) in crate::range!(cipherSuites) {
        let c: uint16 = *c;
        let drop = isDisabledCipherSuite(c)
            || (rsakexOff && isRSAKexCipher(c))
            || (tdesOff && isTDESCipher(c));
        if !drop {
            out.push(c);
        }
    }
    return slice::__from_vec(out);
}

// Go: defaults.go:64-68
//   var defaultCipherSuitesTLS13 = []uint16{…}
/// The TLS 1.3 suites, AES first.
pub(crate) const defaultCipherSuitesTLS13: &[uint16] = &[
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
];

// Go: defaults.go:70-74
//   var defaultCipherSuitesTLS13NoAES = []uint16{…}
/// The TLS 1.3 suites when AES has no hardware support.
pub(crate) const defaultCipherSuitesTLS13NoAES: &[uint16] = &[
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
];
