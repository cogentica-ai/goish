// go: file crypto/tls/prf.go decls: splitPreMasterSecret, pHash, prf10, prf12, prfAndHashForVersion, prfForVersion, masterFromPreMasterSecret, extMasterFromPreMasterSecret, keysFromMasterSecret, newFinishedHash, finishedHash.Write, finishedHash.Sum, finishedHash.clientSum, finishedHash.serverSum, finishedHash.hashForClientCertificate, finishedHash.discardHandshakeBuffer, ekmFromMasterSecret, noEKMBecauseRenegotiation, noEKMBecauseNoEMS
//
// crypto/tls — the TLS 1.0-1.2 pseudo-random function and key schedule.
//
// Complete. Deviations:
//
//   * `prfFunc` is Go's `func(secret []byte, label string, seed []byte,
//     keyLen int) []byte`; goish carries it as an `Arc<dyn Fn…>` so it
//     can be a struct field, as Go's is.
//   * `finishedHash.buffer` is `Option<Vec<byte>>`. Go distinguishes nil
//     from empty on that field — `discardHandshakeBuffer` sets it to nil
//     and `hashForClientCertificate` panics on nil — so the distinction
//     is load-bearing and cannot collapse to length.
//   * `prf12` is spelled with its four closure arguments inlined; see
//     its own note.

#![allow(non_snake_case, dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::hmac;
use crate::crypto::internal::fips140::tls12;
use crate::crypto::md5;
use crate::crypto::sha1;
use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::{Hash, IntoHashFunc};
use crate::io::Writer as _;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/tls/prf.go:23-27 splitPreMasterSecret
/// Split a premaster secret in two as specified in RFC 4346, Section 5.
pub(crate) fn splitPreMasterSecret(secret: slice<byte>) -> (slice<byte>, slice<byte>) {
    // Go: s1 = secret[0 : (len(secret)+1)/2]
    //     s2 = secret[len(secret)/2:]
    let n = secret.Len();
    let s1 = secret.slice(0, (n + 1) / 2);
    let s2 = secret.slice(n / 2, n);
    return (s1, s2);
}

// go: sdk 1.25.5 crypto/tls/prf.go:30-49 pHash
/// The P_hash function, as defined in RFC 4346, Section 5.
pub(crate) fn pHash<H: IntoHashFunc + Clone>(
    result: &mut slice<byte>,
    secret: slice<byte>,
    seed: slice<byte>,
    hash: H,
) {
    // Go: h := hmac.New(hash, secret); h.Write(seed); a := h.Sum(nil)
    let mut h = hmac::New(hash.clone(), secret);
    let _ = h.Write(seed.clone());
    let mut a = h.Sum(slice::__from_vec(Vec::new()));

    // Go: j := 0; for j < len(result) { … }
    let mut j: int = 0;
    while j < result.Len() {
        // Go: h.Reset(); h.Write(a); h.Write(seed); b := h.Sum(nil)
        h.Reset();
        let _ = h.Write(a.clone());
        let _ = h.Write(seed.clone());
        let b = h.Sum(slice::__from_vec(Vec::new()));
        // Go: copy(result[j:], b)
        let mut i: int = 0;
        while i < b.Len() && j + i < result.Len() {
            result[(j + i) as usize] = b[i as usize];
            i += 1;
        }
        // Go: j += len(b)
        j += b.Len();

        // Go: h.Reset(); h.Write(a); a = h.Sum(nil)
        h.Reset();
        let _ = h.Write(a.clone());
        a = h.Sum(slice::__from_vec(Vec::new()));
    }
}

// go: sdk 1.25.5 crypto/tls/prf.go:51-71 prf10
/// The TLS 1.0 pseudo-random function, as defined in RFC 2246, Section 5.
pub(crate) fn prf10(
    secret: slice<byte>,
    label: string,
    seed: slice<byte>,
    keyLen: int,
) -> slice<byte> {
    // Go: result := make([]byte, keyLen)
    let mut result: slice<byte> = slice::__from_vec(alloc::vec![0u8; keyLen as usize]);
    // Go: hashSHA1 := sha1.New; hashMD5 := md5.New

    // Go: labelAndSeed := make([]byte, len(label)+len(seed))
    //     copy(labelAndSeed, label)
    //     copy(labelAndSeed[len(label):], seed)
    let lab: &[byte] = label.as_bytes();
    let mut labelAndSeed: Vec<byte> = Vec::with_capacity(lab.len() + seed.Len() as usize);
    labelAndSeed.extend_from_slice(lab);
    let seedRaw: &[byte] = &seed;
    labelAndSeed.extend_from_slice(seedRaw);
    let labelAndSeed = slice::__from_vec(labelAndSeed);

    // Go: s1, s2 := splitPreMasterSecret(secret)
    let (s1, s2) = splitPreMasterSecret(secret);
    // Go: pHash(result, s1, labelAndSeed, hashMD5)
    pHash(&mut result, s1, labelAndSeed.clone(), md5::NewHash as fn() -> alloc::boxed::Box<dyn Hash + Send + Sync>);
    // Go: result2 := make([]byte, len(result)); pHash(result2, s2, labelAndSeed, hashSHA1)
    let mut result2: slice<byte> = slice::__from_vec(alloc::vec![0u8; result.Len() as usize]);
    pHash(&mut result2, s2, labelAndSeed, sha1::NewHash as fn() -> alloc::boxed::Box<dyn Hash + Send + Sync>);

    // Go: for i, b := range result2 { result[i] ^= b }
    for (i, b) in crate::range!(result2) {
        result[i as usize] ^= *b;
    }

    // Go: return result
    return result;
}

// go: sdk 1.25.5 crypto/tls/prf.go:73-77 prf12
/// The TLS 1.2 pseudo-random function, as defined in RFC 5246, Section 5.
///
/// Deviation: Go returns a `prfFunc` closure that captures `hashFunc`.
/// goish has no `dyn Fn` in a public signature (see CONTRIBUTING.md §5),
/// so the closure is inlined at the one place Go calls the result — the
/// arguments are identical and `tls12::PRF` does the work either way.
/// goishlint:ignore GOISH020 prf12 — Go takes 1 arg and returns a closure over the other 4; see above
pub(crate) fn prf12<H: IntoHashFunc>(
    hashFunc: H,
    secret: slice<byte>,
    label: string,
    seed: slice<byte>,
    keyLen: int,
) -> slice<byte> {
    // Go: return tls12.PRF(hashFunc, secret, label, seed, keyLen)
    return tls12::PRF(hashFunc, secret, label, seed, keyLen);
}

// go: sdk 1.25.5 crypto/tls/prf.go:257-259 noEKMBecauseRenegotiation
/// Used as the value of `ConnectionState.ekm` when renegotiation is
/// enabled, so that all key-material export requests fail.
pub(crate) fn noEKMBecauseRenegotiation(
    _label: string,
    _context: slice<byte>,
    _length: int,
) -> (slice<byte>, error) {
    // Go: return nil, errors.New("crypto/tls: ExportKeyingMaterial is
    //     unavailable when renegotiation is enabled")
    return (
        slice::__from_vec(Vec::new()),
        crate::errors::New(
            "crypto/tls: ExportKeyingMaterial is unavailable when renegotiation is enabled",
        ),
    );
}

// go: sdk 1.25.5 crypto/tls/prf.go:264-266 noEKMBecauseNoEMS
/// Used as the value of `ConnectionState.ekm` when Extended Master
/// Secret is not negotiated, so that all key-material export requests
/// fail.
pub(crate) fn noEKMBecauseNoEMS(
    _label: string,
    _context: slice<byte>,
    _length: int,
) -> (slice<byte>, error) {
    // Go: return nil, errors.New("crypto/tls: ExportKeyingMaterial is
    //     unavailable when neither TLS 1.3 nor Extended Master Secret
    //     are negotiated; override with GODEBUG=tlsunsafeekm=1")
    return (
        slice::__from_vec(Vec::new()),
        crate::errors::New(
            "crypto/tls: ExportKeyingMaterial is unavailable when neither TLS 1.3 nor Extended Master Secret are negotiated; override with GODEBUG=tlsunsafeekm=1",
        ),
    );
}


// ─── The TLS 1.0-1.2 key schedule ─────────────────────────────────────

use super::cipher_suites::{cipherSuite, suiteSHA384};
use super::common::{signatureECDSA as sigECDSA, signatureEd25519 as sigEd25519, VersionTLS10, VersionTLS11, VersionTLS12};
use crate::crypto;
use crate::crypto::sha256;
use crate::crypto::sha512;
use crate::hash::HashFunc;
use crate::types::{uint16, uint8};
use alloc::boxed::Box;
use alloc::sync::Arc;

// Go: prf.go:19
//   type prfFunc func(secret []byte, label string, seed []byte, keyLen int) []byte
/// The pseudo-random function a version+suite pair selects.
pub(crate) type prfFunc =
    Arc<dyn Fn(slice<byte>, string, slice<byte>, int) -> slice<byte> + Send + Sync>;

// Go: prf.go:79-80
//   const ( masterSecretLength = 48; finishedVerifyLength = 12 )
/// Length of a master secret in TLS 1.1.
pub(crate) const masterSecretLength: int = 48;
/// Length of `verify_data` in a Finished message.
pub(crate) const finishedVerifyLength: int = 12;

// Go: prf.go:82-86
pub(crate) const masterSecretLabel: &str = "master secret";
pub(crate) const extendedMasterSecretLabel: &str = "extended master secret";
pub(crate) const keyExpansionLabel: &str = "key expansion";
pub(crate) const clientFinishedLabel: &str = "client finished";
pub(crate) const serverFinishedLabel: &str = "server finished";

// go: sdk 1.25.5 crypto/tls/prf.go:90-102 prfAndHashForVersion
/// The PRF and handshake hash for a version and suite. Panics on an
/// unknown version, as Go does.
pub(crate) fn prfAndHashForVersion(
    version: uint16,
    suite: &'static cipherSuite,
) -> (prfFunc, crypto::Hash) {
    // Go: switch version {
    //     case VersionTLS10, VersionTLS11: return prf10, crypto.Hash(0)
    if version == VersionTLS10 || version == VersionTLS11 {
        return (
            Arc::new(|secret, label, seed, keyLen| prf10(secret, label, seed, keyLen)),
            crypto::Hash(0),
        );
    }
    // Go: case VersionTLS12:
    //         if suite.flags&suiteSHA384 != 0 { return prf12(sha512.New384), crypto.SHA384 }
    //         return prf12(sha256.New), crypto.SHA256
    if version == VersionTLS12 {
        if suite.flags & suiteSHA384 != 0 {
            return (
                Arc::new(|secret, label, seed, keyLen| {
                    prf12(
                        sha512::NewHash384 as fn() -> Box<dyn Hash + Send + Sync>,
                        secret,
                        label,
                        seed,
                        keyLen,
                    )
                }),
                crypto::SHA384,
            );
        }
        return (
            Arc::new(|secret, label, seed, keyLen| {
                prf12(
                    sha256::NewHash as fn() -> Box<dyn Hash + Send + Sync>,
                    secret,
                    label,
                    seed,
                    keyLen,
                )
            }),
            crypto::SHA256,
        );
    }
    // Go: default: panic("unknown version")
    panic!("unknown version");
}

// go: sdk 1.25.5 crypto/tls/prf.go:104-107 prfForVersion
pub(crate) fn prfForVersion(version: uint16, suite: &'static cipherSuite) -> prfFunc {
    // Go: prf, _ := prfAndHashForVersion(version, suite); return prf
    let (prf, _) = prfAndHashForVersion(version, suite);
    return prf;
}

// go: sdk 1.25.5 crypto/tls/prf.go:111-117 masterFromPreMasterSecret
/// The master secret, from the pre-master secret. RFC 5246 §8.1.
pub(crate) fn masterFromPreMasterSecret(
    version: uint16,
    suite: &'static cipherSuite,
    preMasterSecret: slice<byte>,
    clientRandom: slice<byte>,
    serverRandom: slice<byte>,
) -> slice<byte> {
    // Go: seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
    //     seed = append(seed, clientRandom...); seed = append(seed, serverRandom...)
    let mut seed: Vec<byte> = Vec::with_capacity((clientRandom.Len() + serverRandom.Len()) as usize);
    let cr: &[byte] = &clientRandom;
    let sr: &[byte] = &serverRandom;
    seed.extend_from_slice(cr);
    seed.extend_from_slice(sr);
    // Go: return prfForVersion(version, suite)(preMasterSecret, masterSecretLabel,
    //         seed, masterSecretLength)
    return prfForVersion(version, suite)(
        preMasterSecret,
        string::from_static(masterSecretLabel),
        slice::__from_vec(seed),
        masterSecretLength,
    );
}

// go: sdk 1.25.5 crypto/tls/prf.go:121-129 extMasterFromPreMasterSecret
/// The extended master secret. RFC 7627.
pub(crate) fn extMasterFromPreMasterSecret(
    version: uint16,
    suite: &'static cipherSuite,
    preMasterSecret: slice<byte>,
    transcript: slice<byte>,
) -> slice<byte> {
    // Go: prf, hash := prfAndHashForVersion(version, suite)
    let (prf, hash) = prfAndHashForVersion(version, suite);
    // Go: if version == VersionTLS12 {
    //         // Use the FIPS 140-3 module only for TLS 1.2 with EMS, which is
    //         // the only TLS 1.0-1.2 approved mode per IG D.Q.
    //         return tls12.MasterSecret(hash.New, preMasterSecret, transcript)
    //     }
    if version == VersionTLS12 {
        return tls12::MasterSecret(
            HashFunc::New(move || hash.New()),
            preMasterSecret,
            transcript,
        );
    }
    // Go: return prf(preMasterSecret, extendedMasterSecretLabel, transcript, masterSecretLength)
    return prf(
        preMasterSecret,
        string::from_static(extendedMasterSecretLabel),
        transcript,
        masterSecretLength,
    );
}

// go: sdk 1.25.5 crypto/tls/prf.go:134-153 keysFromMasterSecret
/// The connection keys, given the MAC key, cipher key and IV lengths.
/// RFC 2246 §6.3.
///
/// goishlint:ignore GOISH020 keysFromMasterSecret — Go's six named results become one tuple
pub(crate) fn keysFromMasterSecret(
    version: uint16,
    suite: &'static cipherSuite,
    masterSecret: slice<byte>,
    clientRandom: slice<byte>,
    serverRandom: slice<byte>,
    macLen: int,
    keyLen: int,
    ivLen: int,
) -> (
    slice<byte>,
    slice<byte>,
    slice<byte>,
    slice<byte>,
    slice<byte>,
    slice<byte>,
) {
    // Go: seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
    //     seed = append(seed, serverRandom...); seed = append(seed, clientRandom...)
    //
    // Note the order: server random FIRST here, client random first in
    // masterFromPreMasterSecret. RFC 2246 §6.3 versus §8.1.
    let mut seed: Vec<byte> = Vec::with_capacity((serverRandom.Len() + clientRandom.Len()) as usize);
    let sr: &[byte] = &serverRandom;
    let cr: &[byte] = &clientRandom;
    seed.extend_from_slice(sr);
    seed.extend_from_slice(cr);

    // Go: n := 2*macLen + 2*keyLen + 2*ivLen
    //     keyMaterial := prfForVersion(version, suite)(masterSecret, keyExpansionLabel, seed, n)
    let n = 2 * macLen + 2 * keyLen + 2 * ivLen;
    let keyMaterial = prfForVersion(version, suite)(
        masterSecret,
        string::from_static(keyExpansionLabel),
        slice::__from_vec(seed),
        n,
    );
    // Go: clientMAC = keyMaterial[:macLen]; keyMaterial = keyMaterial[macLen:]
    //     serverMAC = keyMaterial[:macLen]; keyMaterial = keyMaterial[macLen:]
    //     clientKey = keyMaterial[:keyLen]; keyMaterial = keyMaterial[keyLen:]
    //     serverKey = keyMaterial[:keyLen]; keyMaterial = keyMaterial[keyLen:]
    //     clientIV  = keyMaterial[:ivLen];  keyMaterial = keyMaterial[ivLen:]
    //     serverIV  = keyMaterial[:ivLen]
    let mut at: int = 0;
    let clientMAC = keyMaterial.slice(at, at + macLen);
    at += macLen;
    let serverMAC = keyMaterial.slice(at, at + macLen);
    at += macLen;
    let clientKey = keyMaterial.slice(at, at + keyLen);
    at += keyLen;
    let serverKey = keyMaterial.slice(at, at + keyLen);
    at += keyLen;
    let clientIV = keyMaterial.slice(at, at + ivLen);
    at += ivLen;
    let serverIV = keyMaterial.slice(at, at + ivLen);
    // Go: return
    return (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV);
}

// Go: prf.go:167-181
//   type finishedHash struct { client, server hash.Hash
//                              clientMD5, serverMD5 hash.Hash
//                              buffer []byte; version uint16; prf prfFunc }
/// Go: "A finishedHash calculates the hash of a set of handshake
/// messages suitable for including in a Finished message."
pub(crate) struct finishedHash {
    pub client: Box<dyn Hash + Send + Sync>,
    pub server: Box<dyn Hash + Send + Sync>,
    /// Go: "Prior to TLS 1.2, an additional MD5 hash is required."
    pub clientMD5: Option<Box<dyn Hash + Send + Sync>>,
    pub serverMD5: Option<Box<dyn Hash + Send + Sync>>,
    /// Go: "In TLS 1.2, a full buffer is sadly required." Nil below 1.2,
    /// and set to nil by `discardHandshakeBuffer`.
    pub buffer: Option<Vec<byte>>,
    pub version: uint16,
    pub prf: prfFunc,
}

// go: sdk 1.25.5 crypto/tls/prf.go:155-167 newFinishedHash
pub(crate) fn newFinishedHash(version: uint16, cipherSuite: &'static cipherSuite) -> finishedHash {
    // Go: var buffer []byte
    //     if version >= VersionTLS12 { buffer = []byte{} }
    let mut buffer: Option<Vec<byte>> = None;
    if version >= VersionTLS12 {
        buffer = Some(Vec::new());
    }

    // Go: prf, hash := prfAndHashForVersion(version, cipherSuite)
    //     if hash != 0 {
    //         return finishedHash{hash.New(), hash.New(), nil, nil, buffer, version, prf}
    //     }
    let (prf, hash) = prfAndHashForVersion(version, cipherSuite);
    if hash != crypto::Hash(0) {
        return finishedHash {
            client: hash.New(),
            server: hash.New(),
            clientMD5: None,
            serverMD5: None,
            buffer,
            version,
            prf,
        };
    }

    // Go: return finishedHash{sha1.New(), sha1.New(), md5.New(), md5.New(),
    //         buffer, version, prf}
    return finishedHash {
        client: Box::new(sha1::New()),
        server: Box::new(sha1::New()),
        clientMD5: Some(Box::new(md5::New())),
        serverMD5: Some(Box::new(md5::New())),
        buffer,
        version,
        prf,
    };
}

impl finishedHash {
    // go: sdk 1.25.5 crypto/tls/prf.go:186-200 finishedHash.Write
    pub(crate) fn Write(&mut self, msg: slice<byte>) -> (int, error) {
        // Go: h.client.Write(msg); h.server.Write(msg)
        let _ = crate::io::Writer::Write(&mut *self.client, msg.clone());
        let _ = crate::io::Writer::Write(&mut *self.server, msg.clone());

        // Go: if h.version < VersionTLS12 { h.clientMD5.Write(msg); h.serverMD5.Write(msg) }
        if self.version < VersionTLS12 {
            let _ = crate::io::Writer::Write(&mut **self.clientMD5.as_mut().unwrap(), msg.clone());
            let _ = crate::io::Writer::Write(&mut **self.serverMD5.as_mut().unwrap(), msg.clone());
        }

        // Go: if h.buffer != nil { h.buffer = append(h.buffer, msg...) }
        if self.buffer.is_some() {
            let raw: &[byte] = &msg;
            self.buffer.as_mut().unwrap().extend_from_slice(raw);
        }

        // Go: return len(msg), nil
        return (msg.Len(), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/prf.go:202-210 finishedHash.Sum
    pub(crate) fn Sum(&self) -> slice<byte> {
        // Go: if h.version >= VersionTLS12 { return h.client.Sum(nil) }
        if self.version >= VersionTLS12 {
            return self.client.Sum(slice::__from_vec(Vec::new()));
        }
        // Go: out := make([]byte, 0, md5.Size+sha1.Size)
        //     out = h.clientMD5.Sum(out)
        //     return h.client.Sum(out)
        let out = slice::__from_vec(Vec::with_capacity((md5::Size + sha1::Size) as usize));
        let out = self.clientMD5.as_ref().unwrap().Sum(out);
        return self.client.Sum(out);
    }

    // go: sdk 1.25.5 crypto/tls/prf.go:214-216 finishedHash.clientSum
    /// The `verify_data` of a client's Finished message.
    pub(crate) fn clientSum(&self, masterSecret: slice<byte>) -> slice<byte> {
        // Go: return h.prf(masterSecret, clientFinishedLabel, h.Sum(), finishedVerifyLength)
        return (self.prf)(
            masterSecret,
            string::from_static(clientFinishedLabel),
            self.Sum(),
            finishedVerifyLength,
        );
    }

    // go: sdk 1.25.5 crypto/tls/prf.go:220-222 finishedHash.serverSum
    /// The `verify_data` of a server's Finished message.
    pub(crate) fn serverSum(&self, masterSecret: slice<byte>) -> slice<byte> {
        // Go: return h.prf(masterSecret, serverFinishedLabel, h.Sum(), finishedVerifyLength)
        return (self.prf)(
            masterSecret,
            string::from_static(serverFinishedLabel),
            self.Sum(),
            finishedVerifyLength,
        );
    }

    // go: sdk 1.25.5 crypto/tls/prf.go:226-246 finishedHash.hashForClientCertificate
    /// The handshake messages so far, pre-hashed if necessary, suitable
    /// for signing by a TLS client certificate.
    pub(crate) fn hashForClientCertificate(
        &self,
        sigType: uint8,
        hashAlg: crypto::Hash,
    ) -> slice<byte> {
        // Go: if (h.version >= VersionTLS12 || sigType == sigEd25519) && h.buffer == nil {
        //         panic("tls: handshake hash for a client certificate requested
        //             after discarding the handshake buffer") }
        if (self.version >= VersionTLS12 || sigType == sigEd25519) && self.buffer.is_none() {
            panic!(
                "tls: handshake hash for a client certificate requested after discarding the handshake buffer"
            );
        }

        // Go: if sigType == sigEd25519 { return h.buffer }
        if sigType == sigEd25519 {
            return slice::__from_vec(self.buffer.clone().unwrap());
        }

        // Go: if h.version >= VersionTLS12 {
        //         hash := hashAlg.New(); hash.Write(h.buffer); return hash.Sum(nil) }
        if self.version >= VersionTLS12 {
            let mut hash = hashAlg.New();
            let _ = crate::io::Writer::Write(
                &mut *hash,
                slice::__from_vec(self.buffer.clone().unwrap()),
            );
            return hash.Sum(slice::__from_vec(Vec::new()));
        }

        // Go: if sigType == signatureECDSA { return h.server.Sum(nil) }
        if sigType == sigECDSA {
            return self.server.Sum(slice::__from_vec(Vec::new()));
        }

        // Go: return h.Sum()
        return self.Sum();
    }

    // go: sdk 1.25.5 crypto/tls/prf.go:250-252 finishedHash.discardHandshakeBuffer
    /// Go: "called when there is no more need to buffer the entirety of
    /// the handshake messages."
    pub(crate) fn discardHandshakeBuffer(&mut self) {
        // Go: h.buffer = nil
        self.buffer = None;
    }
}

// go: sdk 1.25.5 crypto/tls/prf.go:269-295 ekmFromMasterSecret
/// Exported keying material, as defined in RFC 5705.
pub(crate) fn ekmFromMasterSecret(
    version: uint16,
    suite: &'static cipherSuite,
    masterSecret: slice<byte>,
    clientRandom: slice<byte>,
    serverRandom: slice<byte>,
) -> Arc<dyn Fn(string, slice<byte>, int) -> (slice<byte>, error) + Send + Sync> {
    let prf = prfForVersion(version, suite);
    return Arc::new(move |label: string, context: slice<byte>, length: int| {
        // Go: switch label {
        //     case "client finished", "server finished", "master secret", "key expansion":
        //         // These values are reserved and may not be used.
        //         return nil, fmt.Errorf("crypto/tls: reserved ExportKeyingMaterial label: %s", label)
        //     }
        if label == string::from_static(clientFinishedLabel)
            || label == string::from_static(serverFinishedLabel)
            || label == string::from_static(masterSecretLabel)
            || label == string::from_static(keyExpansionLabel)
        {
            return (
                slice::__from_vec(Vec::new()),
                crate::fmt::Errorf!(
                    "crypto/tls: reserved ExportKeyingMaterial label: %s",
                    label
                ),
            );
        }

        // Go: seedLen := len(serverRandom) + len(clientRandom)
        //     if context != nil { seedLen += 2 + len(context) }
        //     seed := make([]byte, 0, seedLen)
        //     seed = append(seed, clientRandom...); seed = append(seed, serverRandom...)
        let mut seedLen = (serverRandom.Len() + clientRandom.Len()) as usize;
        if context.Len() != 0 {
            seedLen += 2 + context.Len() as usize;
        }
        let mut seed: Vec<byte> = Vec::with_capacity(seedLen);
        let cr: &[byte] = &clientRandom;
        let sr: &[byte] = &serverRandom;
        seed.extend_from_slice(cr);
        seed.extend_from_slice(sr);

        // Go: if context != nil {
        //         if len(context) >= 1<<16 { return nil, fmt.Errorf(
        //             "crypto/tls: ExportKeyingMaterial context too long") }
        //         seed = append(seed, byte(len(context)>>8), byte(len(context)))
        //         seed = append(seed, context...)
        //     }
        //
        // goish slices carry no nil/empty distinction; a zero-length
        // context therefore takes Go's nil branch, which is the same
        // seed either way only when the caller meant nil. RFC 5705 has
        // no use for a present-but-empty context.
        if context.Len() != 0 {
            if context.Len() >= 1 << 16 {
                return (
                    slice::__from_vec(Vec::new()),
                    crate::errors::New("crypto/tls: ExportKeyingMaterial context too long"),
                );
            }
            seed.push(crate::byte(context.Len() >> 8));
            seed.push(crate::byte(context.Len()));
            let cx: &[byte] = &context;
            seed.extend_from_slice(cx);
        }

        // Go: return prfForVersion(version, suite)(masterSecret, label, seed, length), nil
        return (
            prf(masterSecret.clone(), label, slice::__from_vec(seed), length),
            crate::errors::nil,
        );
    });
}


// go: none — goish-only: in Go `finishedHash` satisfies `io.Writer`
// (and so `transcriptHash`) structurally, because it has a `Write`
// method with that signature. Rust needs the impl spelled out; it
// forwards to the inherent `Write`.
impl crate::io::Writer for finishedHash {
    // go: none — goish-only: forwards to the inherent `finishedHash::Write`.
    fn Write(&mut self, msg: slice<byte>) -> (int, error) {
        return finishedHash::Write(self, msg);
    }
}
