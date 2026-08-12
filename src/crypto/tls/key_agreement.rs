// go: file crypto/tls/key_agreement.go decls: sha1Hash, md5SHA1Hash, hashForServerKeyExchange
//
// crypto/tls — the TLS 1.2 ServerKeyExchange transcript hashes.
//
// **Partial port.** key_agreement.go is 382 lines; the rest of it is the
// `keyAgreement` interface and its two implementations
// (`rsaKeyAgreement`, `ecdheKeyAgreement`), whose methods all take a
// `*Config`, a `*Certificate` and the handshake messages. Those land
// with the handshake state machine. What is here is the hashing the
// signature is computed over, which depends on nothing but the version
// and the signature type.
//
// goishlint:ignore GOISH018 generateServerKeyExchange, processClientKeyExchange, processServerKeyExchange, generateClientKeyExchange — the keyAgreement implementations; each takes a *Config and *Certificate. See ROADMAP.md.
// goishlint:ignore GOISH019 rsaKeyAgreement, ecdheKeyAgreement — same.
// goishlint:ignore GOISH021 keyAgreement, rsaKeyAgreement, ecdheKeyAgreement, errClientKeyExchange, errServerKeyExchange — same.

#![allow(non_snake_case, dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use super::common::{signatureECDSA, signatureEd25519, VersionTLS12};
use crate::crypto;
use crate::crypto::md5;
use crate::crypto::sha1;
use crate::goslice::slice;
use crate::hash::Hash as HashTrait;
use crate::io::Writer as _;
use crate::types::{byte, uint16, uint8};

// go: sdk 1.25.5 crypto/tls/key_agreement.go:246-252 sha1Hash
/// SHA-1 over the concatenation of `slices`.
pub(crate) fn sha1Hash(slices: &[slice<byte>]) -> slice<byte> {
    // Go: hsha1 := sha1.New()
    let mut hsha1 = sha1::New();
    // Go: for _, slice := range slices { hsha1.Write(slice) }
    for s in slices {
        let _ = hsha1.Write(s.clone());
    }
    // Go: return hsha1.Sum(nil)
    return hsha1.Sum(slice::__from_vec(Vec::new()));
}

// go: sdk 1.25.5 crypto/tls/key_agreement.go:254-264 md5SHA1Hash
/// MD5 concatenated with SHA-1, the TLS 1.0/1.1 signature digest.
pub(crate) fn md5SHA1Hash(slices: &[slice<byte>]) -> slice<byte> {
    // Go: md5sha1 := make([]byte, md5.Size+sha1.Size)
    let mut md5sha1: Vec<byte> = alloc::vec![0u8; (md5::Size + sha1::Size) as usize];
    // Go: hmd5 := md5.New(); for _, slice := range slices { hmd5.Write(slice) }
    let mut hmd5 = md5::New();
    for s in slices {
        let _ = hmd5.Write(s.clone());
    }
    // Go: copy(md5sha1, hmd5.Sum(nil))
    let d5 = hmd5.Sum(slice::__from_vec(Vec::new()));
    let raw5: &[byte] = &d5;
    md5sha1[..raw5.len()].copy_from_slice(raw5);
    // Go: copy(md5sha1[md5.Size:], sha1Hash(slices))
    let d1 = sha1Hash(slices);
    let raw1: &[byte] = &d1;
    md5sha1[md5::Size as usize..].copy_from_slice(raw1);
    // Go: return md5sha1
    return slice::__from_vec(md5sha1);
}

// go: sdk 1.25.5 crypto/tls/key_agreement.go:268-291 hashForServerKeyExchange
/// The digest the ServerKeyExchange signature is computed over.
///
/// Deviation: Go's `slices ...[]byte` is variadic; goish has no
/// variadics, so the caller passes the slice of slices Go would build.
/// goishlint:ignore GOISH020 hashForServerKeyExchange — Go's variadic tail is one parameter here
pub(crate) fn hashForServerKeyExchange(
    sigType: uint8,
    hashFunc: crypto::Hash,
    version: uint16,
    slices: &[slice<byte>],
) -> slice<byte> {
    // Go: if sigType == signatureEd25519 {
    //         var signed []byte
    //         for _, slice := range slices { signed = append(signed, slice...) }
    //         return signed
    //     }
    //
    // Ed25519 signs the message whole — no pre-hash. See RFC 8032.
    if sigType == signatureEd25519 {
        let mut signed: Vec<byte> = Vec::new();
        for s in slices {
            let raw: &[byte] = s;
            signed.extend_from_slice(raw);
        }
        return slice::__from_vec(signed);
    }
    // Go: if version >= VersionTLS12 {
    //         h := hashFunc.New()
    //         for _, slice := range slices { h.Write(slice) }
    //         return h.Sum(nil)
    //     }
    if version >= VersionTLS12 {
        let mut h = hashFunc.New();
        for s in slices {
            let _ = h.Write(s.clone());
        }
        return h.Sum(slice::__from_vec(Vec::new()));
    }
    // Go: if sigType == signatureECDSA { return sha1Hash(slices) }
    if sigType == signatureECDSA {
        return sha1Hash(slices);
    }
    // Go: return md5SHA1Hash(slices)
    return md5SHA1Hash(slices);
}
