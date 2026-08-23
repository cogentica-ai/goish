// go: file crypto/tls/key_agreement.go decls: sha1Hash, md5SHA1Hash, hashForServerKeyExchange, rsaKeyAgreement.generateServerKeyExchange, rsaKeyAgreement.processClientKeyExchange, rsaKeyAgreement.processServerKeyExchange, rsaKeyAgreement.generateClientKeyExchange, ecdheKeyAgreement.generateServerKeyExchange, ecdheKeyAgreement.processClientKeyExchange, ecdheKeyAgreement.processServerKeyExchange, ecdheKeyAgreement.generateClientKeyExchange
//
// crypto/tls — the TLS 1.0-1.2 key agreements.
//
// Complete: the `keyAgreement` interface, both implementations, and the
// three transcript hashes the ServerKeyExchange signature is computed
// over.
//
// Two deviations run through the file:
//
//   * Every trait method takes `&mut self`. Go's `rsaKeyAgreement` has
//     value receivers and `ecdheKeyAgreement` pointer receivers; Rust
//     needs one shape, and the ECDHE side genuinely mutates.
//   * Go's `nil` returns for a message become `Option`.
//
// Nothing here is reachable from goish's own handshake yet — the live
// client is TLS 1.3 only and does not consult a `keyAgreement`. The
// exchange is exercised end to end in `examples/tls_common_smoke.rs`.

#![allow(non_snake_case, dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use super::common::{signatureECDSA, signatureEd25519, VersionTLS12};
use crate::crypto;
use crate::crypto::md5;
use crate::crypto::sha1;
use crate::goslice::slice;
use crate::io::Writer as _;
use crate::types::{byte, int, uint16, uint8};

// go: sdk 1.25.5 crypto/tls/key_agreement.go:108-114 sha1Hash
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

// go: sdk 1.25.5 crypto/tls/key_agreement.go:118-127 md5SHA1Hash
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

// go: sdk 1.25.5 crypto/tls/key_agreement.go:133-153 hashForServerKeyExchange
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

// ─── The keyAgreement interface and its two implementations ───────────

use super::common::{
    isSupportedSignatureAlgorithm, signaturePKCS1v15, signatureRSAPSS, Certificate, CurveID,
    SignatureScheme,
};
use super::handshake_messages::{
    clientHelloMsg, clientKeyExchangeMsg, serverHelloMsg, serverKeyExchangeMsg,
};
use super::key_schedule::{curveForCurveID, generateECDHEKey};
use super::Config;
use crate::crypto::ecdh;
use crate::crypto::rsa;
use crate::crypto::x509;
use crate::error;
use crate::gostring::string;

// Go: key_agreement.go:22-36
//   type keyAgreement interface {
//       generateServerKeyExchange(*Config, *Certificate, *clientHelloMsg, *serverHelloMsg) (*serverKeyExchangeMsg, error)
//       processClientKeyExchange(*Config, *Certificate, *clientKeyExchangeMsg, uint16) ([]byte, error)
//       processServerKeyExchange(*Config, *clientHelloMsg, *serverHelloMsg, *x509.Certificate, *serverKeyExchangeMsg) error
//       generateClientKeyExchange(*Config, *clientHelloMsg, *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error)
//   }
/// Go: "A keyAgreement implements the client and server side of a TLS
/// 1.0–1.2 key agreement protocol by generating and processing key
/// exchange messages."
///
/// Deviation: every method takes `&mut self`. Go's `rsaKeyAgreement` has
/// value receivers and `ecdheKeyAgreement` pointer receivers; Rust needs
/// one shape, and the ECDHE side genuinely mutates. Go's nil returns
/// become `Option`.
pub(crate) trait keyAgreement {
    /// Go: "In the case that the key agreement protocol doesn't use a
    /// ServerKeyExchange message, generateServerKeyExchange can return
    /// nil, nil."
    fn generateServerKeyExchange(
        &mut self,
        config: &Config,
        cert: &Certificate,
        clientHello: &clientHelloMsg,
        hello: &serverHelloMsg,
    ) -> (Option<serverKeyExchangeMsg>, error);

    fn processClientKeyExchange(
        &mut self,
        config: &Config,
        cert: &Certificate,
        ckx: &clientKeyExchangeMsg,
        version: uint16,
    ) -> (slice<byte>, error);

    /// Go: "This method may not be called if the server doesn't send a
    /// ServerKeyExchange message."
    fn processServerKeyExchange(
        &mut self,
        config: &Config,
        clientHello: &clientHelloMsg,
        serverHello: &serverHelloMsg,
        cert: &x509::Certificate,
        skx: &serverKeyExchangeMsg,
    ) -> error;

    fn generateClientKeyExchange(
        &mut self,
        config: &Config,
        clientHello: &clientHelloMsg,
        cert: &x509::Certificate,
    ) -> (slice<byte>, Option<clientKeyExchangeMsg>, error);

    // go: none — goish-only: Go type-asserts `keyAgreement.(*ecdheKeyAgreement)`;
    // goish needs an Any hook on the trait object for the downcast.
    fn asAny(&self) -> &dyn core::any::Any;
}

crate::var! {
    /// Go: `var errClientKeyExchange = errors.New(…)`
    pub(crate) errClientKeyExchange: error = "tls: invalid ClientKeyExchange message";
    /// Go: `var errServerKeyExchange = errors.New(…)`
    pub(crate) errServerKeyExchange: error = "tls: invalid ServerKeyExchange message";
}

// Go: key_agreement.go:42
//   type rsaKeyAgreement struct{}
/// Go: "rsaKeyAgreement implements the standard TLS key agreement where
/// the client encrypts the pre-master secret to the server's public
/// key."
#[derive(Clone, Copy, Default)]
pub(crate) struct rsaKeyAgreement {}

impl keyAgreement for rsaKeyAgreement {
    // go: none — goish-only: the Any hook for Go's type assertions.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }

    // go: sdk 1.25.5 crypto/tls/key_agreement.go:46-48 rsaKeyAgreement.generateServerKeyExchange
    fn generateServerKeyExchange(
        &mut self,
        _config: &Config,
        _cert: &Certificate,
        _clientHello: &clientHelloMsg,
        _hello: &serverHelloMsg,
    ) -> (Option<serverKeyExchangeMsg>, error) {
        // Go: return nil, nil
        return (None, crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/key_agreement.go:50-76 rsaKeyAgreement.processClientKeyExchange
    fn processClientKeyExchange(
        &mut self,
        config: &Config,
        cert: &Certificate,
        ckx: &clientKeyExchangeMsg,
        _version: uint16,
    ) -> (slice<byte>, error) {
        // Go: if len(ckx.ciphertext) < 2 { return nil, errClientKeyExchange }
        if ckx.ciphertext.Len() < 2 {
            return (slice::__from_vec(Vec::new()), errClientKeyExchange.into());
        }
        // Go: ciphertextLen := int(ckx.ciphertext[0])<<8 | int(ckx.ciphertext[1])
        //     if ciphertextLen != len(ckx.ciphertext)-2 { return nil, errClientKeyExchange }
        let ciphertextLen = (crate::int(ckx.ciphertext[0]) << 8) | crate::int(ckx.ciphertext[1]);
        if ciphertextLen != ckx.ciphertext.Len() - 2 {
            return (slice::__from_vec(Vec::new()), errClientKeyExchange.into());
        }
        // Go: ciphertext := ckx.ciphertext[2:]
        let ciphertext = ckx.ciphertext.slice(2, ckx.ciphertext.Len());

        // Go: priv, ok := cert.PrivateKey.(crypto.Decrypter)
        //     if !ok { return nil, errors.New("tls: certificate private key
        //         does not implement crypto.Decrypter") }
        let priv_ = decrypterOf(&cert.PrivateKey);
        if priv_.is_none() {
            return (
                slice::__from_vec(Vec::new()),
                crate::errors::New(
                    "tls: certificate private key does not implement crypto.Decrypter",
                ),
            );
        }
        // Go: Perform constant time RSA PKCS #1 v1.5 decryption
        // Go: preMasterSecret, err := priv.Decrypt(config.rand(), ciphertext,
        //         &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 48})
        let mut r = config.rand();
        let opts: crate::crypto::DecrypterOpts =
            alloc::boxed::Box::new(rsa::PKCS1v15DecryptOptions { SessionKeyLen: 48 });
        let (preMasterSecret, err) = priv_.unwrap().Decrypt(&mut *r, ciphertext, Some(&opts));
        if err != crate::errors::nil {
            return (slice::__from_vec(Vec::new()), err);
        }
        // Go: We don't check the version number in the premaster secret.
        // For one, by checking it, we would leak information about the
        // validity of the encrypted pre-master secret. Secondly, it
        // provides only a small benefit against a downgrade attack and
        // some implementations send the wrong version anyway. See the
        // discussion at the end of section 7.4.7.1 of RFC 4346.
        return (preMasterSecret, crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/key_agreement.go:78-80 rsaKeyAgreement.processServerKeyExchange
    fn processServerKeyExchange(
        &mut self,
        _config: &Config,
        _clientHello: &clientHelloMsg,
        _serverHello: &serverHelloMsg,
        _cert: &x509::Certificate,
        _skx: &serverKeyExchangeMsg,
    ) -> error {
        // Go: return errors.New("tls: unexpected ServerKeyExchange")
        return crate::errors::New("tls: unexpected ServerKeyExchange");
    }

    // go: sdk 1.25.5 crypto/tls/key_agreement.go:82-105 rsaKeyAgreement.generateClientKeyExchange
    fn generateClientKeyExchange(
        &mut self,
        config: &Config,
        clientHello: &clientHelloMsg,
        cert: &x509::Certificate,
    ) -> (slice<byte>, Option<clientKeyExchangeMsg>, error) {
        // Go: preMasterSecret := make([]byte, 48)
        //     preMasterSecret[0] = byte(clientHello.vers >> 8)
        //     preMasterSecret[1] = byte(clientHello.vers)
        //     _, err := io.ReadFull(config.rand(), preMasterSecret[2:])
        let mut preMasterSecret: slice<byte> = slice::__from_vec(alloc::vec![0u8; 48]);
        preMasterSecret[0] = crate::byte(clientHello.vers >> 8);
        preMasterSecret[1] = crate::byte(clientHello.vers);
        let mut tail: slice<byte> = slice::__from_vec(alloc::vec![0u8; 46]);
        let mut r = config.rand();
        let (_, err) = crate::io::ReadFull(&mut *r, &mut tail);
        if err != crate::errors::nil {
            return (slice::__from_vec(Vec::new()), None, err);
        }
        let mut i: int = 0;
        while i < 46 {
            preMasterSecret[(2 + i) as usize] = tail[i as usize];
            i += 1;
        }

        // Go: rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
        //     if !ok { return nil, nil, errors.New("tls: server certificate
        //         contains incorrect key type for selected ciphersuite") }
        let rsaKey = cert.PublicKey.As::<rsa::PublicKey>();
        if rsaKey.is_none() {
            return (
                slice::__from_vec(Vec::new()),
                None,
                crate::errors::New(
                    "tls: server certificate contains incorrect key type for selected ciphersuite",
                ),
            );
        }
        // Go: encrypted, err := rsa.EncryptPKCS1v15(config.rand(), rsaKey, preMasterSecret)
        let mut r2 = config.rand();
        let (encrypted, err) =
            rsa::EncryptPKCS1v15(&mut *r2, rsaKey.unwrap(), preMasterSecret.clone());
        if err != crate::errors::nil {
            return (slice::__from_vec(Vec::new()), None, err);
        }
        // Go: ckx := new(clientKeyExchangeMsg)
        //     ckx.ciphertext = make([]byte, len(encrypted)+2)
        //     ckx.ciphertext[0] = byte(len(encrypted) >> 8)
        //     ckx.ciphertext[1] = byte(len(encrypted))
        //     copy(ckx.ciphertext[2:], encrypted)
        let mut ckx = clientKeyExchangeMsg::default();
        let n = encrypted.Len();
        let mut ct: Vec<byte> = alloc::vec![0u8; (n + 2) as usize];
        ct[0] = crate::byte(n >> 8);
        ct[1] = crate::byte(n);
        let raw: &[byte] = &encrypted;
        ct[2..].copy_from_slice(raw);
        ckx.ciphertext = slice::__from_vec(ct);
        // Go: return preMasterSecret, ckx, nil
        return (preMasterSecret, Some(ckx), crate::errors::nil);
    }
}

// go: none — goish-only: `crypto::PrivateKey` is `Arc<dyn core::any::Any>`,
// so `.As::<dyn Decrypter>()` on it resolves through the blanket
// `HasDynAny for T: Sized` and probes the Arc's own TypeId. The payload
// has to be dereferenced first — the same trap auth[rs]'s `signerOf`
// documents.
pub(crate) fn decrypterOf(
    key: &crate::crypto::PrivateKey,
) -> Option<&(dyn crate::crypto::Decrypter + Send + Sync)> {
    return <dyn crate::crypto::Decrypter + Send + Sync as crate::goany::DowncastableFromAny>::from_any(&**key);
}

// Go: key_agreement.go:155-173
//   type ecdheKeyAgreement struct { version uint16; isRSA bool
//                                   key *ecdh.PrivateKey
//                                   ckx *clientKeyExchangeMsg
//                                   preMasterSecret []byte
//                                   curveID CurveID
//                                   signatureAlgorithm SignatureScheme }
/// Go: "ecdheKeyAgreement implements a TLS key agreement where the
/// server generates an ephemeral EC public/private key pair and signs
/// it."
#[derive(Clone, Default)]
pub(crate) struct ecdheKeyAgreement {
    pub version: uint16,
    pub isRSA: bool,
    pub key: Option<ecdh::PrivateKey>,
    /// Go: "ckx and preMasterSecret are generated in
    /// processServerKeyExchange and returned in generateClientKeyExchange."
    pub ckx: Option<clientKeyExchangeMsg>,
    pub preMasterSecret: slice<byte>,
    /// Go: "curveID and signatureAlgorithm are set by
    /// processServerKeyExchange and generateServerKeyExchange."
    pub curveID: CurveID,
    pub signatureAlgorithm: SignatureScheme,
}

impl keyAgreement for ecdheKeyAgreement {
    // go: none — goish-only: the Any hook for Go's type assertions.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }

    // go: sdk 1.25.5 crypto/tls/key_agreement.go:175-264 ecdheKeyAgreement.generateServerKeyExchange
    fn generateServerKeyExchange(
        &mut self,
        config: &Config,
        cert: &Certificate,
        clientHello: &clientHelloMsg,
        hello: &serverHelloMsg,
    ) -> (Option<serverKeyExchangeMsg>, error) {
        // Go: for _, c := range clientHello.supportedCurves {
        //         if config.supportsCurve(ka.version, c) { ka.curveID = c; break }
        //     }
        for c in clientHello.supportedCurves.iter() {
            if config.supportsCurve(self.version, CurveID(*c)) {
                self.curveID = CurveID(*c);
                break;
            }
        }

        // Go: if ka.curveID == 0 { return nil, errors.New("tls: no supported
        //     elliptic curves offered") }
        if self.curveID == CurveID(0) {
            return (
                None,
                crate::errors::New("tls: no supported elliptic curves offered"),
            );
        }
        // Go: if _, ok := curveForCurveID(ka.curveID); !ok {
        //         return nil, errors.New("tls: CurvePreferences includes unsupported curve") }
        let (_, ok) = curveForCurveID(self.curveID);
        if !ok {
            return (
                None,
                crate::errors::New("tls: CurvePreferences includes unsupported curve"),
            );
        }

        // Go: key, err := generateECDHEKey(config.rand(), ka.curveID)
        //     if err != nil { return nil, err }
        //     ka.key = key
        let mut r = config.rand();
        let (key, err) = generateECDHEKey(&mut *r, self.curveID);
        if err != crate::errors::nil {
            return (None, err);
        }
        let key = key.unwrap();
        self.key = Some(key.clone());

        // Go: See RFC 4492, Section 5.4.
        // Go: ecdhePublic := key.PublicKey().Bytes()
        //     serverECDHEParams := make([]byte, 1+2+1+len(ecdhePublic))
        //     serverECDHEParams[0] = 3 // named curve
        //     serverECDHEParams[1] = byte(ka.curveID >> 8)
        //     serverECDHEParams[2] = byte(ka.curveID)
        //     serverECDHEParams[3] = byte(len(ecdhePublic))
        //     copy(serverECDHEParams[4:], ecdhePublic)
        let ecdhePublic = key.PublicKey().Bytes();
        let epLen = ecdhePublic.Len();
        let mut serverECDHEParams: Vec<byte> = alloc::vec![0u8; (4 + epLen) as usize];
        serverECDHEParams[0] = 3; // named curve
        serverECDHEParams[1] = crate::byte(self.curveID.0 >> 8);
        serverECDHEParams[2] = crate::byte(self.curveID.0);
        serverECDHEParams[3] = crate::byte(epLen);
        let epRaw: &[byte] = &ecdhePublic;
        serverECDHEParams[4..].copy_from_slice(epRaw);
        let serverECDHEParams = slice::__from_vec(serverECDHEParams);

        // Go: priv, ok := cert.PrivateKey.(crypto.Signer)
        //     if !ok { return nil, fmt.Errorf("tls: certificate private key of
        //         type %T does not implement crypto.Signer", cert.PrivateKey) }
        //
        // The `%T` stops at the fixed prefix — see auth[rs]'s banner.
        let priv_ = super::auth::signerOf(&cert.PrivateKey);
        if priv_.is_none() {
            return (
                None,
                crate::errors::New("tls: certificate private key does not implement crypto.Signer"),
            );
        }
        let priv_ = priv_.unwrap();

        // Go: var sigType uint8; var sigHash crypto.Hash
        //     if ka.version >= VersionTLS12 {
        //         ka.signatureAlgorithm, err = selectSignatureScheme(ka.version, cert,
        //             clientHello.supportedSignatureAlgorithms)
        //         …
        //     } else {
        //         sigType, sigHash, err = legacyTypeAndHashFromPublicKey(priv.Public())
        //     }
        let sigType: uint8;
        let sigHash: crate::crypto::Hash;
        if self.version >= super::common::VersionTLS12 {
            let peerAlgs: Vec<SignatureScheme> = clientHello
                .supportedSignatureAlgorithms
                .iter()
                .map(|v| SignatureScheme(*v))
                .collect();
            let (sa, err) =
                super::auth::selectSignatureScheme(self.version, cert, slice::__from_vec(peerAlgs));
            if err != crate::errors::nil {
                return (None, err);
            }
            self.signatureAlgorithm = sa;
            let (st, sh, err) = super::auth::typeAndHashFromSignatureScheme(sa);
            if err != crate::errors::nil {
                return (None, err);
            }
            sigType = st;
            sigHash = sh;
            // Go: if sigHash == crypto.SHA1 { tlssha1.Value(); tlssha1.IncNonDefault() }
            //
            // godebug counters are not ported; the branch has no other
            // effect.
        } else {
            let pubAny = super::auth::anyOfPublicKey(&priv_.Public());
            let (st, sh, err) = super::auth::legacyTypeAndHashFromPublicKey(&pubAny);
            if err != crate::errors::nil {
                return (None, err);
            }
            sigType = st;
            sigHash = sh;
        }
        // Go: if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
        //         return nil, errors.New("tls: certificate cannot be used with
        //             the selected cipher suite") }
        if ((sigType == signaturePKCS1v15) || (sigType == signatureRSAPSS)) != self.isRSA {
            return (
                None,
                crate::errors::New(
                    "tls: certificate cannot be used with the selected cipher suite",
                ),
            );
        }

        // Go: signed := hashForServerKeyExchange(sigType, sigHash, ka.version,
        //         clientHello.random, hello.random, serverECDHEParams)
        let signed = hashForServerKeyExchange(
            sigType,
            sigHash,
            self.version,
            &[
                slice::__from_vec(clientHello.random.clone()),
                slice::__from_vec(hello.random.clone()),
                serverECDHEParams.clone(),
            ],
        );

        // Go: signOpts := crypto.SignerOpts(sigHash)
        //     if sigType == signatureRSAPSS {
        //         signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash} }
        //     sig, err := priv.Sign(config.rand(), signed, signOpts)
        let pssOpts;
        let signOpts: &dyn crate::crypto::SignerOpts = if sigType == signatureRSAPSS {
            pssOpts = rsa::PSSOptions {
                SaltLength: rsa::PSSSaltLengthEqualsHash,
                Hash: sigHash,
            };
            &pssOpts
        } else {
            &sigHash
        };
        let mut r2 = config.rand();
        let (sig, err) = priv_.Sign(&mut *r2, signed, signOpts);
        if err != crate::errors::nil {
            return (
                None,
                crate::errors::New(
                    string::from("tls: failed to sign ECDHE parameters: ") + err.Error(),
                ),
            );
        }

        // Go: skx := new(serverKeyExchangeMsg)
        //     sigAndHashLen := 0
        //     if ka.version >= VersionTLS12 { sigAndHashLen = 2 }
        //     skx.key = make([]byte, len(serverECDHEParams)+sigAndHashLen+2+len(sig))
        //     copy(skx.key, serverECDHEParams)
        //     k := skx.key[len(serverECDHEParams):]
        //     if ka.version >= VersionTLS12 {
        //         k[0] = byte(ka.signatureAlgorithm >> 8)
        //         k[1] = byte(ka.signatureAlgorithm)
        //         k = k[2:]
        //     }
        //     k[0] = byte(len(sig) >> 8)
        //     k[1] = byte(len(sig))
        //     copy(k[2:], sig)
        let mut skx = serverKeyExchangeMsg::default();
        let mut sigAndHashLen: int = 0;
        if self.version >= super::common::VersionTLS12 {
            sigAndHashLen = 2;
        }
        let pLen = serverECDHEParams.Len();
        let sLen = sig.Len();
        let mut k: Vec<byte> = alloc::vec![0u8; (pLen + sigAndHashLen + 2 + sLen) as usize];
        let pRaw: &[byte] = &serverECDHEParams;
        k[..pLen as usize].copy_from_slice(pRaw);
        let mut at = pLen as usize;
        if self.version >= super::common::VersionTLS12 {
            k[at] = crate::byte(self.signatureAlgorithm.0 >> 8);
            k[at + 1] = crate::byte(self.signatureAlgorithm.0);
            at += 2;
        }
        k[at] = crate::byte(sLen >> 8);
        k[at + 1] = crate::byte(sLen);
        let sRaw: &[byte] = &sig;
        k[at + 2..].copy_from_slice(sRaw);
        skx.key = slice::__from_vec(k);

        // Go: return skx, nil
        return (Some(skx), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/key_agreement.go:266-281 ecdheKeyAgreement.processClientKeyExchange
    fn processClientKeyExchange(
        &mut self,
        _config: &Config,
        _cert: &Certificate,
        ckx: &clientKeyExchangeMsg,
        _version: uint16,
    ) -> (slice<byte>, error) {
        // Go: if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
        //         return nil, errClientKeyExchange }
        if ckx.ciphertext.Len() == 0 || crate::int(ckx.ciphertext[0]) != ckx.ciphertext.Len() - 1 {
            return (slice::__from_vec(Vec::new()), errClientKeyExchange.into());
        }
        if self.key.is_none() {
            return (slice::__from_vec(Vec::new()), errClientKeyExchange.into());
        }
        let key = self.key.clone().unwrap();

        // Go: peerKey, err := ka.key.Curve().NewPublicKey(ckx.ciphertext[1:])
        //     if err != nil { return nil, errClientKeyExchange }
        let raw = ckx.ciphertext.slice(1, ckx.ciphertext.Len());
        let (peerKey, err) = key.Curve().NewPublicKey(&raw);
        if err != crate::errors::nil {
            return (slice::__from_vec(Vec::new()), errClientKeyExchange.into());
        }
        // Go: preMasterSecret, err := ka.key.ECDH(peerKey)
        //     if err != nil { return nil, errClientKeyExchange }
        let (preMasterSecret, err) = key.ECDH(&peerKey);
        if err != crate::errors::nil {
            return (slice::__from_vec(Vec::new()), errClientKeyExchange.into());
        }

        // Go: return preMasterSecret, nil
        return (preMasterSecret, crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/key_agreement.go:280-374 ecdheKeyAgreement.processServerKeyExchange
    fn processServerKeyExchange(
        &mut self,
        config: &Config,
        clientHello: &clientHelloMsg,
        serverHello: &serverHelloMsg,
        cert: &x509::Certificate,
        skx: &serverKeyExchangeMsg,
    ) -> error {
        // Go: if len(skx.key) < 4 { return errServerKeyExchange }
        //     if skx.key[0] != 3 { return errors.New("tls: server selected unsupported curve") }
        //     ka.curveID = CurveID(skx.key[1])<<8 | CurveID(skx.key[2])
        if skx.key.Len() < 4 {
            return errServerKeyExchange.into();
        }
        if skx.key[0] != 3 {
            return crate::errors::New("tls: server selected unsupported curve");
        }
        self.curveID = CurveID((crate::uint16(skx.key[1]) << 8) | crate::uint16(skx.key[2]));

        // Go: publicLen := int(skx.key[3])
        //     if publicLen+4 > len(skx.key) { return errServerKeyExchange }
        //     serverECDHEParams := skx.key[:4+publicLen]
        //     publicKey := serverECDHEParams[4:]
        let publicLen = crate::int(skx.key[3]);
        if publicLen + 4 > skx.key.Len() {
            return errServerKeyExchange.into();
        }
        let serverECDHEParams = skx.key.slice(0, 4 + publicLen);
        let publicKey = serverECDHEParams.slice(4, serverECDHEParams.Len());

        // Go: sig := skx.key[4+publicLen:]
        //     if len(sig) < 2 { return errServerKeyExchange }
        let mut sig = skx.key.slice(4 + publicLen, skx.key.Len());
        if sig.Len() < 2 {
            return errServerKeyExchange.into();
        }

        // Go: if !slices.Contains(clientHello.supportedCurves, ka.curveID) {
        //         return errors.New("tls: server selected unoffered curve") }
        if !clientHello.supportedCurves.contains(&self.curveID.0) {
            return crate::errors::New("tls: server selected unoffered curve");
        }

        // Go: if _, ok := curveForCurveID(ka.curveID); !ok {
        //         return errors.New("tls: server selected unsupported curve") }
        let (_, ok) = curveForCurveID(self.curveID);
        if !ok {
            return crate::errors::New("tls: server selected unsupported curve");
        }

        // Go: key, err := generateECDHEKey(config.rand(), ka.curveID)
        //     if err != nil { return err }
        //     ka.key = key
        let mut r = config.rand();
        let (key, err) = generateECDHEKey(&mut *r, self.curveID);
        if err != crate::errors::nil {
            return err;
        }
        let key = key.unwrap();
        self.key = Some(key.clone());

        // Go: peerKey, err := key.Curve().NewPublicKey(publicKey)
        //     if err != nil { return errServerKeyExchange }
        let (peerKey, err) = key.Curve().NewPublicKey(&publicKey);
        if err != crate::errors::nil {
            return errServerKeyExchange.into();
        }
        // Go: ka.preMasterSecret, err = key.ECDH(peerKey)
        //     if err != nil { return errServerKeyExchange }
        let (pms, err) = key.ECDH(&peerKey);
        if err != crate::errors::nil {
            return errServerKeyExchange.into();
        }
        self.preMasterSecret = pms;

        // Go: ourPublicKey := key.PublicKey().Bytes()
        //     ka.ckx = new(clientKeyExchangeMsg)
        //     ka.ckx.ciphertext = make([]byte, 1+len(ourPublicKey))
        //     ka.ckx.ciphertext[0] = byte(len(ourPublicKey))
        //     copy(ka.ckx.ciphertext[1:], ourPublicKey)
        let ourPublicKey = key.PublicKey().Bytes();
        let oLen = ourPublicKey.Len();
        let mut ct: Vec<byte> = alloc::vec![0u8; (1 + oLen) as usize];
        ct[0] = crate::byte(oLen);
        let oRaw: &[byte] = &ourPublicKey;
        ct[1..].copy_from_slice(oRaw);
        let mut ckx = clientKeyExchangeMsg::default();
        ckx.ciphertext = slice::__from_vec(ct);
        self.ckx = Some(ckx);

        // Go: var sigType uint8; var sigHash crypto.Hash
        //     if ka.version >= VersionTLS12 { … } else { … }
        let sigType: uint8;
        let sigHash: crate::crypto::Hash;
        if self.version >= super::common::VersionTLS12 {
            // Go: ka.signatureAlgorithm = SignatureScheme(sig[0])<<8 | SignatureScheme(sig[1])
            //     sig = sig[2:]
            //     if len(sig) < 2 { return errServerKeyExchange }
            self.signatureAlgorithm =
                SignatureScheme((crate::uint16(sig[0]) << 8) | crate::uint16(sig[1]));
            sig = sig.slice(2, sig.Len());
            if sig.Len() < 2 {
                return errServerKeyExchange.into();
            }
            // Go: if !isSupportedSignatureAlgorithm(ka.signatureAlgorithm,
            //         clientHello.supportedSignatureAlgorithms) {
            //         return errors.New("tls: certificate used with invalid signature algorithm") }
            let peerAlgs: Vec<SignatureScheme> = clientHello
                .supportedSignatureAlgorithms
                .iter()
                .map(|v| SignatureScheme(*v))
                .collect();
            if !isSupportedSignatureAlgorithm(self.signatureAlgorithm, slice::__from_vec(peerAlgs))
            {
                return crate::errors::New(
                    "tls: certificate used with invalid signature algorithm",
                );
            }
            // Go: sigType, sigHash, err = typeAndHashFromSignatureScheme(ka.signatureAlgorithm)
            let (st, sh, err) =
                super::auth::typeAndHashFromSignatureScheme(self.signatureAlgorithm);
            if err != crate::errors::nil {
                return err;
            }
            sigType = st;
            sigHash = sh;
        } else {
            // Go: sigType, sigHash, err = legacyTypeAndHashFromPublicKey(cert.PublicKey)
            let (st, sh, err) = super::auth::legacyTypeAndHashFromPublicKey(&cert.PublicKey);
            if err != crate::errors::nil {
                return err;
            }
            sigType = st;
            sigHash = sh;
        }
        // Go: if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
        //         return errServerKeyExchange }
        if ((sigType == signaturePKCS1v15) || (sigType == signatureRSAPSS)) != self.isRSA {
            return errServerKeyExchange.into();
        }

        // Go: sigLen := int(sig[0])<<8 | int(sig[1])
        //     if sigLen+2 != len(sig) { return errServerKeyExchange }
        //     sig = sig[2:]
        let sigLen = (crate::int(sig[0]) << 8) | crate::int(sig[1]);
        if sigLen + 2 != sig.Len() {
            return errServerKeyExchange.into();
        }
        let sig = sig.slice(2, sig.Len());

        // Go: signed := hashForServerKeyExchange(sigType, sigHash, ka.version,
        //         clientHello.random, serverHello.random, serverECDHEParams)
        let signed = hashForServerKeyExchange(
            sigType,
            sigHash,
            self.version,
            &[
                slice::__from_vec(clientHello.random.clone()),
                slice::__from_vec(serverHello.random.clone()),
                serverECDHEParams,
            ],
        );
        // Go: if err := verifyHandshakeSignature(sigType, cert.PublicKey, sigHash, signed, sig); err != nil {
        //         return errors.New("tls: invalid signature by the server certificate: " + err.Error()) }
        let err =
            super::auth::verifyHandshakeSignature(sigType, &cert.PublicKey, sigHash, signed, sig);
        if err != crate::errors::nil {
            return crate::errors::New(
                string::from("tls: invalid signature by the server certificate: ") + err.Error(),
            );
        }
        // Go: return nil
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/key_agreement.go:376-382 ecdheKeyAgreement.generateClientKeyExchange
    fn generateClientKeyExchange(
        &mut self,
        _config: &Config,
        _clientHello: &clientHelloMsg,
        _cert: &x509::Certificate,
    ) -> (slice<byte>, Option<clientKeyExchangeMsg>, error) {
        // Go: if ka.ckx == nil { return nil, nil, errors.New("tls: missing
        //     ServerKeyExchange message") }
        if self.ckx.is_none() {
            return (
                slice::__from_vec(Vec::new()),
                None,
                crate::errors::New("tls: missing ServerKeyExchange message"),
            );
        }
        // Go: return ka.preMasterSecret, ka.ckx, nil
        return (
            self.preMasterSecret.clone(),
            self.ckx.clone(),
            crate::errors::nil,
        );
    }
}
