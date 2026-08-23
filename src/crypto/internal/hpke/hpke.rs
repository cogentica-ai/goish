// go: file crypto/internal/hpke/hpke.go decls: hkdfKDF.LabeledExtract, hkdfKDF.LabeledExpand, newDHKem, dhKEM.ExtractAndExpand, dhKEM.Encap, dhKEM.Decap, aesGCMNew, newContext, SetupSender, SetupRecipient, context.nextNonce, context.incrementNonce, Sender.Seal, Recipient.Open, suiteID, ParseHPKEPublicKey, ParseHPKEPrivateKey, uint128.addOne, uint128.bitLen, uint128.bytes
//
// Hybrid Public Key Encryption (RFC 9180), as used by TLS Encrypted Client
// Hello.
//
// Deviations from hpke[go] @ Go 1.25.5:
//
//   * The three `Supported*` package-level maps hold structs with function
//     fields. goish spells them as `match` on the ID: every value is a
//     compile-time constant and every function is a top-level one, so a
//     map buys nothing here and would need a `Lazy` plus a carrier for the
//     func fields. The `Supported*` names survive as the lookup functions.
//   * `cipher.AEAD` is a trait object here (`Box<dyn AEAD + Send + Sync>`);
//     `aesGCMNew` and the chacha20poly1305 constructor are adapted to it
//     because goish's return concrete types.
//   * Constructors returning `(*T, error)` return `(T, error)` with the
//     zero value on the error path.
//   * `testingOnlyGenerateKey` is a nil func var set only by tests; Rust
//     `fn` pointers are not nullable, so it is an `Option`.
//
// goishlint:ignore GOISH021 — `SupportedKEMs`, `SupportedAEADs` and
// `SupportedKDFs` are Go `var` maps; see the first deviation. `KemID`,
// `AEADID` and `KDFID` are `uint16` aliases Go declares beside the
// constants and never uses in a signature.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto;
use crate::crypto::aes;
use crate::crypto::chacha20poly1305;
use crate::crypto::cipher::{self, AEAD};
use crate::crypto::ecdh;
use crate::crypto::hkdf;
use crate::crypto::rand;
use crate::errors;
use crate::goslice::slice;
use crate::internal::byteorder;
use crate::math::bits;
use crate::string;
use crate::types::byte;
use crate::{error, int, uint16, uint64, uint8};

// Go: hpke.go:22-23 — `var testingOnlyGenerateKey func() (*ecdh.PrivateKey, error)`
/// Only used during testing, to provide a fixed test key when checking the
/// RFC 9180 vectors.
const testingOnlyGenerateKey: Option<fn() -> (ecdh::PrivateKey, error)> = None;

// Go: hpke.go:25-27
//   type hkdfKDF struct { hash crypto.Hash }
pub(crate) struct hkdfKDF {
    hash: crypto::Hash,
}

impl hkdfKDF {
    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:29-36 hkdfKDF.LabeledExtract
    fn LabeledExtract(
        &self,
        sid: &slice<byte>,
        salt: &slice<byte>,
        label: &str,
        inputKey: &slice<byte>,
    ) -> (slice<byte>, error) {
        let mut labeledIKM: Vec<byte> =
            Vec::with_capacity(7 + sid.Len() as usize + label.len() + inputKey.Len() as usize);
        labeledIKM.extend_from_slice(b"HPKE-v1");
        labeledIKM.extend_from_slice(sid);
        labeledIKM.extend_from_slice(label.as_bytes());
        labeledIKM.extend_from_slice(inputKey);
        return hkdf::Extract(
            hashNew(self.hash),
            slice::__from_vec(labeledIKM),
            salt.clone(),
        );
    }

    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:38-46 hkdfKDF.LabeledExpand
    fn LabeledExpand(
        &self,
        suiteID: &slice<byte>,
        randomKey: &slice<byte>,
        label: &str,
        info: &slice<byte>,
        length: uint16,
    ) -> (slice<byte>, error) {
        let mut labeledInfo = byteorder::BEAppendUint16(
            slice::__from_vec(Vec::<byte>::with_capacity(
                2 + 7 + suiteID.Len() as usize + label.len() + info.Len() as usize,
            )),
            length,
        )
        .__into_vec();
        labeledInfo.extend_from_slice(b"HPKE-v1");
        labeledInfo.extend_from_slice(suiteID);
        labeledInfo.extend_from_slice(label.as_bytes());
        labeledInfo.extend_from_slice(info);
        return hkdf::Expand(
            hashNew(self.hash),
            randomKey.clone(),
            string::from_bytes(&labeledInfo),
            int(length),
        );
    }
}

// go: none — Go writes `kdf.hash.New`, a method value on crypto.Hash.
// Rust has no method values, so the closure that Go builds implicitly is
// spelled out here; the KDFs take a `HashFunc` factory.
fn hashNew(h: crypto::Hash) -> crate::hash::HashFunc {
    return crate::hash::HashFunc::New(move || h.New());
}

// Go: hpke.go:48-54
//   type dhKEM struct { dh ecdh.Curve; kdf hkdfKDF; suiteID []byte; nSecret uint16 }
/// Implements the KEM specified in RFC 9180, Section 4.1.
struct dhKEM {
    dh: &'static (dyn ecdh::Curve + Send + Sync),
    kdf: hkdfKDF,

    suiteID: slice<byte>,
    nSecret: uint16,
}

// Go: hpke.go:56 — `type KemID uint16`
pub type KemID = uint16;

// Go: hpke.go:58 — `const DHKEM_X25519_HKDF_SHA256 = 0x0020`
pub const DHKEM_X25519_HKDF_SHA256: uint16 = 0x0020;

// go: none — Go's `var SupportedKEMs = map[uint16]struct{…}{…}`; see the
// file header for why this is a lookup rather than a map.
pub(crate) fn SupportedKEMs(
    kemID: uint16,
) -> Option<(
    &'static (dyn ecdh::Curve + Send + Sync),
    crypto::Hash,
    uint16,
)> {
    if kemID == DHKEM_X25519_HKDF_SHA256 {
        return Some((ecdh::X25519(), crypto::SHA256, 32));
    }
    return None;
}

// go: sdk 1.25.5 crypto/internal/hpke/hpke.go:69-80 newDHKem
fn newDHKem(kemID: uint16) -> (Option<dhKEM>, error) {
    let suite = match SupportedKEMs(kemID) {
        None => return (None, errors::New("unsupported suite ID")),
        Some(s) => s,
    };
    return (
        Some(dhKEM {
            dh: suite.0,
            kdf: hkdfKDF { hash: suite.1 },
            suiteID: byteorder::BEAppendUint16(bytesOf(b"KEM"), kemID),
            nSecret: suite.2,
        }),
        crate::nil.into(),
    );
}

impl dhKEM {
    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:82-88 dhKEM.ExtractAndExpand
    fn ExtractAndExpand(
        &self,
        dhKey: &slice<byte>,
        kemContext: &slice<byte>,
    ) -> (slice<byte>, error) {
        let (eaePRK, err) = self
            .kdf
            .LabeledExtract(&self.suiteID, &empty(), "eae_prk", dhKey);
        if err != crate::nil {
            return (empty(), err);
        }
        return self.kdf.LabeledExpand(
            &self.suiteID,
            &eaePRK,
            "shared_secret",
            kemContext,
            self.nSecret,
        );
    }

    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:91-114 dhKEM.Encap
    fn Encap(&self, pubRecipient: &ecdh::PublicKey) -> (slice<byte>, slice<byte>, error) {
        let privEph;
        if let Some(gen) = testingOnlyGenerateKey {
            let (k, err) = gen();
            if err != crate::nil {
                return (empty(), empty(), err);
            }
            privEph = k;
        } else {
            let mut r = rand::Reader;
            let (k, err) = self.dh.GenerateKey(&mut r);
            if err != crate::nil {
                return (empty(), empty(), err);
            }
            privEph = k;
        }
        let (dhVal, err) = privEph.ECDH(pubRecipient);
        if err != crate::nil {
            return (empty(), empty(), err);
        }
        let encPubEph = privEph.PublicKey().Bytes();

        let encPubRecip = pubRecipient.Bytes();
        let kemContext = concat(&encPubEph, &encPubRecip);
        let (sharedSecret, err) = self.ExtractAndExpand(&dhVal, &kemContext);
        if err != crate::nil {
            return (empty(), empty(), err);
        }
        return (sharedSecret, encPubEph, crate::nil.into());
    }

    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:116-127 dhKEM.Decap
    fn Decap(
        &self,
        encPubEph: &slice<byte>,
        secRecipient: &ecdh::PrivateKey,
    ) -> (slice<byte>, error) {
        let (pubEph, err) = self.dh.NewPublicKey(encPubEph);
        if err != crate::nil {
            return (empty(), err);
        }
        let (dhVal, err) = secRecipient.ECDH(&pubEph);
        if err != crate::nil {
            return (empty(), err);
        }
        let kemContext = concat(encPubEph, &secRecipient.PublicKey().Bytes());
        return self.ExtractAndExpand(&dhVal, &kemContext);
    }
}

// Go: hpke.go:127-139
//   type context struct { aead cipher.AEAD; sharedSecret, suiteID, key,
//                         baseNonce, exporterSecret []byte; seqNum uint128 }
pub struct context {
    aead: Box<dyn AEAD + Send + Sync>,

    #[allow(dead_code)]
    sharedSecret: slice<byte>,

    #[allow(dead_code)]
    suiteID: slice<byte>,

    #[allow(dead_code)]
    key: slice<byte>,
    baseNonce: slice<byte>,
    #[allow(dead_code)]
    exporterSecret: slice<byte>,

    seqNum: uint128,
}

// Go: hpke.go:141-147 — `type Sender struct { *context }` / `type Recipient …`
pub struct Sender {
    context: context,
}

pub struct Recipient {
    context: context,
}

// go: sdk 1.25.5 crypto/internal/hpke/hpke.go:151-157 aesGCMNew
fn aesGCMNew(key: &slice<byte>) -> (Option<Box<dyn AEAD + Send + Sync>>, error) {
    let (block, err) = aes::NewCipher(key.clone());
    if err != crate::nil {
        return (None, err);
    }
    let (g, err) = cipher::NewGCM(block.unwrap());
    if err != crate::nil {
        return (None, err);
    }
    return (
        Some(Box::new(g.unwrap()) as Box<dyn AEAD + Send + Sync>),
        crate::nil.into(),
    );
}

// go: none — the chacha20poly1305 arm of Go's SupportedAEADs map, adapted
// to the trait object (goish's New returns the concrete type).
fn chachaNew(key: &slice<byte>) -> (Option<Box<dyn AEAD + Send + Sync>>, error) {
    let (c, err) = chacha20poly1305::New(key.clone());
    if err != crate::nil {
        return (None, err);
    }
    return (
        Some(Box::new(c.unwrap()) as Box<dyn AEAD + Send + Sync>),
        crate::nil.into(),
    );
}

// Go: hpke.go:157 — `type AEADID uint16`
pub type AEADID = uint16;

// Go: hpke.go:159-163 — the AEAD identifiers.
pub const AEAD_AES_128_GCM: uint16 = 0x0001;
pub const AEAD_AES_256_GCM: uint16 = 0x0002;
pub const AEAD_ChaCha20Poly1305: uint16 = 0x0003;

// go: none — Go's `var SupportedAEADs = map[uint16]struct{…}{…}`.
pub(crate) fn SupportedAEADs(
    aeadID: uint16,
) -> Option<(
    int,
    int,
    fn(&slice<byte>) -> (Option<Box<dyn AEAD + Send + Sync>>, error),
)> {
    if aeadID == AEAD_AES_128_GCM {
        return Some((16, 12, aesGCMNew));
    }
    if aeadID == AEAD_AES_256_GCM {
        return Some((32, 12, aesGCMNew));
    }
    if aeadID == AEAD_ChaCha20Poly1305 {
        return Some((
            int(chacha20poly1305::KeySize),
            int(chacha20poly1305::NonceSize),
            chachaNew,
        ));
    }
    return None;
}

// Go: hpke.go:174 — `type KDFID uint16`
pub type KDFID = uint16;

// Go: hpke.go:176 — `const KDF_HKDF_SHA256 = 0x0001`
pub const KDF_HKDF_SHA256: uint16 = 0x0001;

// go: none — Go's `var SupportedKDFs = map[uint16]func() *hkdfKDF{…}`.
pub(crate) fn SupportedKDFs(kdfID: uint16) -> Option<hkdfKDF> {
    if kdfID == KDF_HKDF_SHA256 {
        return Some(hkdfKDF {
            hash: crypto::SHA256,
        });
    }
    return None;
}

// go: sdk 1.25.5 crypto/internal/hpke/hpke.go:187-242 newContext
fn newContext(
    sharedSecret: &slice<byte>,
    kemID: uint16,
    kdfID: uint16,
    aeadID: uint16,
    info: &slice<byte>,
) -> (Option<context>, error) {
    let sid = suiteID(kemID, kdfID, aeadID);

    let kdf = match SupportedKDFs(kdfID) {
        None => return (None, errors::New("unsupported KDF id")),
        Some(k) => k,
    };

    let aeadInfo = match SupportedAEADs(aeadID) {
        None => return (None, errors::New("unsupported AEAD id")),
        Some(a) => a,
    };

    let (pskIDHash, err) = kdf.LabeledExtract(&sid, &empty(), "psk_id_hash", &empty());
    if err != crate::nil {
        return (None, err);
    }
    let (infoHash, err) = kdf.LabeledExtract(&sid, &empty(), "info_hash", info);
    if err != crate::nil {
        return (None, err);
    }
    let mut ksContext: Vec<byte> = alloc::vec![0u8];
    ksContext.extend_from_slice(&pskIDHash);
    ksContext.extend_from_slice(&infoHash);
    let ksContext = slice::__from_vec(ksContext);

    let (secret, err) = kdf.LabeledExtract(&sid, sharedSecret, "secret", &empty());
    if err != crate::nil {
        return (None, err);
    }
    // Nk - key size for AEAD
    let (key, err) = kdf.LabeledExpand(&sid, &secret, "key", &ksContext, uint16(aeadInfo.0));
    if err != crate::nil {
        return (None, err);
    }
    // Nn - nonce size for AEAD
    let (baseNonce, err) =
        kdf.LabeledExpand(&sid, &secret, "base_nonce", &ksContext, uint16(aeadInfo.1));
    if err != crate::nil {
        return (None, err);
    }
    // Nh - hash output size of the kdf
    let (exporterSecret, err) =
        kdf.LabeledExpand(&sid, &secret, "exp", &ksContext, uint16(kdf.hash.Size()));
    if err != crate::nil {
        return (None, err);
    }

    let (aead, err) = (aeadInfo.2)(&key);
    if err != crate::nil {
        return (None, err);
    }

    return (
        Some(context {
            aead: aead.unwrap(),
            sharedSecret: sharedSecret.clone(),
            suiteID: sid,
            key,
            baseNonce,
            exporterSecret,
            seqNum: uint128 { hi: 0, lo: 0 },
        }),
        crate::nil.into(),
    );
}

// go: sdk 1.25.5 crypto/internal/hpke/hpke.go:244-260 SetupSender
pub fn SetupSender(
    kemID: uint16,
    kdfID: uint16,
    aeadID: uint16,
    pubKey: &ecdh::PublicKey,
    info: &slice<byte>,
) -> (slice<byte>, Option<Sender>, error) {
    let (kem, err) = newDHKem(kemID);
    if err != crate::nil {
        return (empty(), None, err);
    }
    let kem = kem.unwrap();
    let (sharedSecret, encapsulatedKey, err) = kem.Encap(pubKey);
    if err != crate::nil {
        return (empty(), None, err);
    }

    let (ctx, err) = newContext(&sharedSecret, kemID, kdfID, aeadID, info);
    if err != crate::nil {
        return (empty(), None, err);
    }

    return (
        encapsulatedKey,
        Some(Sender {
            context: ctx.unwrap(),
        }),
        crate::nil.into(),
    );
}

// go: sdk 1.25.5 crypto/internal/hpke/hpke.go:262-278 SetupRecipient
pub fn SetupRecipient(
    kemID: uint16,
    kdfID: uint16,
    aeadID: uint16,
    priv_: &ecdh::PrivateKey,
    info: &slice<byte>,
    encPubEph: &slice<byte>,
) -> (Option<Recipient>, error) {
    let (kem, err) = newDHKem(kemID);
    if err != crate::nil {
        return (None, err);
    }
    let kem = kem.unwrap();
    let (sharedSecret, err) = kem.Decap(encPubEph, priv_);
    if err != crate::nil {
        return (None, err);
    }

    let (ctx, err) = newContext(&sharedSecret, kemID, kdfID, aeadID, info);
    if err != crate::nil {
        return (None, err);
    }

    return (
        Some(Recipient {
            context: ctx.unwrap(),
        }),
        crate::nil.into(),
    );
}

impl context {
    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:280-286 context.nextNonce
    fn nextNonce(&self) -> slice<byte> {
        let all = self.seqNum.bytes();
        let raw: &[byte] = &all;
        let start = 16 - self.aead.NonceSize() as usize;
        let mut nonce = raw[start..].to_vec();
        let base: &[byte] = &self.baseNonce;
        let mut i: usize = 0;
        while i < base.len() {
            nonce[i] ^= base[i];
            i += 1;
        }
        return slice::__from_vec(nonce);
    }

    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:288-295 context.incrementNonce
    fn incrementNonce(&mut self) {
        if self.seqNum.bitLen() >= (self.aead.NonceSize() * 8) - 1 {
            panic!("message limit reached");
        }
        self.seqNum = self.seqNum.addOne();
    }
}

impl Sender {
    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:297-301 Sender.Seal
    pub fn Seal(&mut self, aad: &slice<byte>, plaintext: &slice<byte>) -> (slice<byte>, error) {
        let ciphertext = self.context.aead.Seal(
            empty(),
            self.context.nextNonce(),
            plaintext.clone(),
            aad.clone(),
        );
        self.context.incrementNonce();
        return (ciphertext, crate::nil.into());
    }
}

impl Recipient {
    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:303-310 Recipient.Open
    pub fn Open(&mut self, aad: &slice<byte>, ciphertext: &slice<byte>) -> (slice<byte>, error) {
        let (plaintext, err) = self.context.aead.Open(
            empty(),
            self.context.nextNonce(),
            ciphertext.clone(),
            aad.clone(),
        );
        if err != crate::nil {
            return (empty(), err);
        }
        self.context.incrementNonce();
        return (plaintext, crate::nil.into());
    }
}

// go: sdk 1.25.5 crypto/internal/hpke/hpke.go:312-319 suiteID
fn suiteID(kemID: uint16, kdfID: uint16, aeadID: uint16) -> slice<byte> {
    let mut sid: Vec<byte> = Vec::with_capacity(4 + 2 + 2 + 2);
    sid.extend_from_slice(b"HPKE");
    let sid = byteorder::BEAppendUint16(slice::__from_vec(sid), kemID);
    let sid = byteorder::BEAppendUint16(sid, kdfID);
    let sid = byteorder::BEAppendUint16(sid, aeadID);
    return sid;
}

// go: sdk 1.25.5 crypto/internal/hpke/hpke.go:321-327 ParseHPKEPublicKey
pub fn ParseHPKEPublicKey(kemID: uint16, bytes: &slice<byte>) -> (ecdh::PublicKey, error) {
    let kemInfo = match SupportedKEMs(kemID) {
        None => {
            let (zero, _) = ecdh::X25519().NewPublicKey(&empty());
            return (zero, errors::New("unsupported KEM id"));
        }
        Some(k) => k,
    };
    return kemInfo.0.NewPublicKey(bytes);
}

// go: sdk 1.25.5 crypto/internal/hpke/hpke.go:329-335 ParseHPKEPrivateKey
pub fn ParseHPKEPrivateKey(kemID: uint16, bytes: &slice<byte>) -> (ecdh::PrivateKey, error) {
    let kemInfo = match SupportedKEMs(kemID) {
        None => {
            let (zero, _) = ecdh::X25519().NewPrivateKey(&empty());
            return (zero, errors::New("unsupported KEM id"));
        }
        Some(k) => k,
    };
    return kemInfo.0.NewPrivateKey(bytes);
}

// Go: hpke.go:324-326 — `type uint128 struct { hi, lo uint64 }`
#[derive(Clone, Copy)]
struct uint128 {
    hi: uint64,
    lo: uint64,
}

impl uint128 {
    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:341-344 uint128.addOne
    fn addOne(&self) -> uint128 {
        let (lo, carry) = bits::Add64(self.lo, 1, 0);
        return uint128 {
            hi: self.hi + carry,
            lo,
        };
    }

    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:346-348 uint128.bitLen
    fn bitLen(&self) -> int {
        return bits::Len64(self.hi) + bits::Len64(self.lo);
    }

    // go: sdk 1.25.5 crypto/internal/hpke/hpke.go:350-355 uint128.bytes
    fn bytes(&self) -> slice<byte> {
        let mut b = slice::__from_vec(alloc::vec![0u8; 16]);
        let mut hi = slice::__from_vec(alloc::vec![0u8; 8]);
        byteorder::BEPutUint64(&mut hi, self.hi);
        let mut lo = slice::__from_vec(alloc::vec![0u8; 8]);
        byteorder::BEPutUint64(&mut lo, self.lo);
        {
            let d: &mut [byte] = &mut b;
            let h: &[byte] = &hi;
            let l: &[byte] = &lo;
            d[0..8].copy_from_slice(h);
            d[8..16].copy_from_slice(l);
        }
        return b;
    }
}

// go: none — Go writes `[]byte("KEM")`.
fn bytesOf(s: &[u8]) -> slice<byte> {
    return slice::__from_vec(s.to_vec());
}

// go: none — Go writes a bare `nil` []byte at these call sites.
fn empty() -> slice<byte> {
    return slice::__from_vec(Vec::<byte>::new());
}

// go: none — Go writes `append(a, b...)`.
fn concat(a: &slice<byte>, b: &slice<byte>) -> slice<byte> {
    let ar: &[byte] = a;
    let br: &[byte] = b;
    let mut v = ar.to_vec();
    v.extend_from_slice(br);
    return slice::__from_vec(v);
}

// Keep the uint8 import honest.
const _: fn(uint16) -> byte = uint8;
