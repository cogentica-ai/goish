// go: file crypto/rsa/fips.go decls: PSSOptions.HashFunc, PSSOptions.saltLength, SignPSS, VerifyPSS, EncryptOAEP, DecryptOAEP, decryptOAEP, SignPKCS1v15, VerifyPKCS1v15, fipsError, fipsError2, checkFIPS140OnlyPublicKey, checkFIPS140OnlyPrivateKey
//
// The schemes the FIPS 140-3 module implements: RSASSA-PSS, RSAES-OAEP
// and RSASSA-PKCS1-v1_5 signing. Each entry point validates the key,
// converts it with `fipsPublicKey`/`fipsPrivateKey` and hands off to
// `crypto/internal/fips140/rsa`, then maps the module's sentinels back to
// this package's with `fipsError`.
//
// Deviations from fips[go] @ Go 1.25.5:
//
//   * The `boring.Enabled` branches are absent — goish has no cgo and so
//     no `crypto/internal/boring`. See rsa.rs's banner.
//   * Go passes the *same* `hash.Hash` value twice when the OAEP hash and
//     the MGF1 hash coincide (`decryptOAEP(hash, hash, …)`). Rust cannot
//     alias a `&mut`, so `decryptOAEP`'s second parameter is
//     `Option<&mut dyn hash::Hash>` and `None` spells "the same object as
//     `hash`". The arity, and the order the two are used in, are Go's.
//   * `defer hash.Reset()` becomes an explicit `Reset` on each return
//     path: `defer!` captures by move and cannot hold a `&mut dyn`.
//   * `fips140hash.Unwrap(hash)` is applied where this package *owns* the
//     hash (`hash.New()` in `SignPSS`/`VerifyPSS`), but not in
//     `EncryptOAEP`/`decryptOAEP`, whose `hash.Hash` arrives as a
//     borrow: goish's `Unwrap` takes and returns an owned
//     `Box<dyn hash::Hash>`. Unwrap only strips the FIPS service
//     indicator wrapper, which goish's hashes do not wear.
//   * For the same borrow reason `fips140only::ApprovedHash` — which
//     takes `&Box<dyn hash::Hash + Send + Sync>` — is checked in
//     `SignPSS`/`VerifyPSS` and skipped in `EncryptOAEP`/`decryptOAEP`.
//     Both guards sit behind `fips140only::Enabled`, a `const false` in
//     goish. `SignPSS`'s `ApprovedRandomReader` guard is omitted for the
//     reason rsa.rs's banner gives.
//   * Go computes `hashName := hash.String()` and passes the *name* to
//     `rsa.SignPKCS1v15`/`rsa.VerifyPKCS1v15`; goish's
//     `crypto/internal/fips140/rsa` takes the `crypto.Hash` id itself and
//     looks the DER prefix up from it, so there is no name to build.
//   * `SignPSS`/`VerifyPSS` take `Option<&PSSOptions>` where Go takes a
//     `*PSSOptions` that may be nil; `PSSOptions.saltLength`'s nil-receiver
//     branch therefore lives at the call site.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::crypto;
use crate::crypto::internal::fips140::rsa;
use crate::crypto::internal::fips140hash;
use crate::crypto::internal::fips140only;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::hash::Hash as HashTrait;
use crate::io;
use crate::nilval::nil;
use crate::types::{byte, int};

use super::rsa::{
    checkPublicKeySize, fipsPrivateKey, fipsPublicKey, ErrDecryption, ErrMessageTooLong,
    ErrVerification, PrivateKey, PublicKey,
};

// Go: fips.go:18-28 — `const ( PSSSaltLengthAuto = 0; … )`
/// PSSSaltLengthAuto causes the salt in a PSS signature to be as large as
/// possible when signing, and to be auto-detected when verifying.
///
/// When signing in FIPS 140-3 mode, the salt length is capped at the
/// length of the hash function used in the signature.
pub const PSSSaltLengthAuto: int = 0;
/// PSSSaltLengthEqualsHash causes the salt length to equal the length of
/// the hash used in the signature.
pub const PSSSaltLengthEqualsHash: int = -1;

// Go: fips.go:31-41
//   type PSSOptions struct { SaltLength int; Hash crypto.Hash }
/// `PSSOptions` contains options for creating and verifying PSS
/// signatures.
#[derive(Clone, Default)]
pub struct PSSOptions {
    /// SaltLength controls the length of the salt used in the PSS
    /// signature. It can either be a positive number of bytes, or one of
    /// the special `PSSSaltLength` constants.
    pub SaltLength: int,
    /// Hash is the hash function used to generate the message digest. If
    /// not zero, it overrides the hash function passed to [`SignPSS`].
    /// It's required when using `PrivateKey::Sign`.
    pub Hash: crypto::Hash,
}

impl PSSOptions {
    // go: sdk 1.25.5 crypto/rsa/fips.go:44-46 PSSOptions.HashFunc
    /// HashFunc returns `opts.Hash` so that [`PSSOptions`] implements
    /// `crypto::SignerOpts`.
    pub fn HashFunc(&self) -> crypto::Hash {
        return self.Hash;
    }

    // go: sdk 1.25.5 crypto/rsa/fips.go:48-53 PSSOptions.saltLength
    /// Go's receiver may be nil, in which case it reports
    /// [`PSSSaltLengthAuto`]; goish spells the nil case as a `None`
    /// `Option<&PSSOptions>` at the call site.
    fn saltLength(&self) -> int {
        return self.SaltLength;
    }
}

impl crypto::SignerOpts for PSSOptions {
    // go: none — goish idiom: `crypto.SignerOpts` is satisfied in Go by
    // the inherent `HashFunc` above; the trait impl forwards to it.
    fn HashFunc(&self) -> crypto::Hash {
        return PSSOptions::HashFunc(self);
    }

    // go: none — goish idiom: opts into the `#[goish::interface]`
    // downcast registry so that `PrivateKey::Sign` can spell Go's
    // `opts.(*PSSOptions)` assertion.
    fn __goish_as_dyn_any(
        &self,
    ) -> Option<&(dyn core::any::Any + core::marker::Send + core::marker::Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: Go writes `opts.saltLength()` on a possibly-nil
// `*PSSOptions`; goish's `Option<&PSSOptions>` needs the nil case spelled
// out, and three call sites want it.
fn saltLengthOf(opts: Option<&PSSOptions>) -> int {
    return match opts {
        Some(o) => o.saltLength(),
        None => PSSSaltLengthAuto,
    };
}

// go: sdk 1.25.5 crypto/rsa/fips.go:64-120 SignPSS
/// SignPSS calculates the signature of `digest` using PSS.
///
/// `digest` must be the result of hashing the input message using the
/// given hash function. `opts` may be `None`, in which case sensible
/// defaults are used. If `opts.Hash` is set, it overrides `hash`.
///
/// The signature is randomized depending on the message, key, and salt
/// size, using bytes from `rand`.
pub fn SignPSS(
    rand: &mut dyn io::Reader,
    priv_: &PrivateKey,
    hash: crypto::Hash,
    digest: slice<byte>,
    opts: Option<&PSSOptions>,
) -> (slice<byte>, error) {
    let err = checkPublicKeySize(&priv_.PublicKey);
    if err != nil {
        return (slice::default(), err);
    }

    let mut hash = hash;
    if let Some(o) = opts {
        if o.Hash != crypto::Hash(0) {
            hash = o.Hash;
        }
    }

    let mut h = fips140hash::Unwrap(hash.New());

    let err = checkFIPS140OnlyPrivateKey(priv_);
    if err != nil {
        return (slice::default(), err);
    }
    if fips140only::Enabled && !fips140only::ApprovedHash(&h) {
        return (
            slice::default(),
            errors::New(
                "crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode",
            ),
        );
    }
    // Go's `!fips140only.ApprovedRandomReader(rand)` guard follows here —
    // see rsa.rs's banner for why it is absent.

    let (k, err) = fipsPrivateKey(priv_);
    if err != nil {
        return (slice::default(), err);
    }
    let k = k.unwrap();

    let mut saltLength = saltLengthOf(opts);
    if fips140only::Enabled && saltLength > HashTrait::Size(h.as_ref()) {
        return (
            slice::default(),
            errors::New(
                "crypto/rsa: use of PSS salt longer than the hash is not allowed in FIPS 140-only mode",
            ),
        );
    }
    if saltLength == PSSSaltLengthAuto {
        let (maxSaltLength, err) = rsa::PSSMaxSaltLength(&k.PublicKey(), h.as_mut());
        if err != nil {
            return (slice::default(), fipsError(err));
        }
        saltLength = maxSaltLength;
    } else if saltLength == PSSSaltLengthEqualsHash {
        saltLength = HashTrait::Size(h.as_ref());
    } else if saltLength <= 0 {
        // If we get here saltLength is either > 0 or < -1; in the latter
        // case we fail out.
        return (
            slice::default(),
            errors::New("crypto/rsa: invalid PSS salt length"),
        );
    }

    let (sig, err) = rsa::SignPSS(rand, &k, h.as_mut(), digest, saltLength);
    return fipsError2(sig, err);
}

// go: sdk 1.25.5 crypto/rsa/fips.go:131-173 VerifyPSS
/// VerifyPSS verifies a PSS signature. A valid signature is indicated by
/// returning a nil error. `digest` must be the result of hashing the
/// input message using the given hash function. `opts` may be `None`, in
/// which case sensible defaults are used; `opts.Hash` is ignored.
///
/// The inputs are not considered confidential, and may leak through
/// timing side channels, or if an attacker has control of part of the
/// inputs.
pub fn VerifyPSS(
    pub_: &PublicKey,
    hash: crypto::Hash,
    digest: slice<byte>,
    sig: slice<byte>,
    opts: Option<&PSSOptions>,
) -> error {
    let err = checkPublicKeySize(pub_);
    if err != nil {
        return err;
    }

    let mut h = fips140hash::Unwrap(hash.New());

    let err = checkFIPS140OnlyPublicKey(pub_);
    if err != nil {
        return err;
    }
    if fips140only::Enabled && !fips140only::ApprovedHash(&h) {
        return errors::New(
            "crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode",
        );
    }

    let (k, err) = fipsPublicKey(pub_);
    if err != nil {
        return err;
    }
    let k = k.unwrap();

    let saltLength = saltLengthOf(opts);
    if fips140only::Enabled && saltLength > HashTrait::Size(h.as_ref()) {
        return errors::New(
            "crypto/rsa: use of PSS salt longer than the hash is not allowed in FIPS 140-only mode",
        );
    }
    if saltLength == PSSSaltLengthAuto {
        return fipsError(rsa::VerifyPSS(&k, h.as_mut(), digest, sig));
    }
    if saltLength == PSSSaltLengthEqualsHash {
        let hSize = HashTrait::Size(h.as_ref());
        return fipsError(rsa::VerifyPSSWithSaltLength(
            &k,
            h.as_mut(),
            digest,
            sig,
            hSize,
        ));
    }
    return fipsError(rsa::VerifyPSSWithSaltLength(
        &k,
        h.as_mut(),
        digest,
        sig,
        saltLength,
    ));
}

// go: sdk 1.25.5 crypto/rsa/fips.go:193-231 EncryptOAEP
/// EncryptOAEP encrypts the given message with RSA-OAEP.
///
/// OAEP is parameterised by a hash function that is used as a random
/// oracle. Encryption and decryption of a given message must use the same
/// hash function, and `sha256::New()` is a reasonable choice.
///
/// The `random` parameter is used as a source of entropy to ensure that
/// encrypting the same message twice doesn't result in the same
/// ciphertext.
///
/// The `label` parameter may contain arbitrary data that will not be
/// encrypted, but which gives important context to the message. If not
/// required it can be empty.
///
/// The message must be no longer than the length of the public modulus
/// minus twice the hash length, minus a further 2.
pub fn EncryptOAEP(
    hash: &mut dyn HashTrait,
    random: &mut dyn io::Reader,
    pub_: &PublicKey,
    msg: slice<byte>,
    label: slice<byte>,
) -> (slice<byte>, error) {
    let err = checkPublicKeySize(pub_);
    if err != nil {
        // Go registers `defer hash.Reset()` only *after* this check, so
        // this one return path leaves the hash alone.
        return (slice::default(), err);
    }

    let err = checkFIPS140OnlyPublicKey(pub_);
    if err != nil {
        hash.Reset();
        return (slice::default(), err);
    }

    let (k, err) = fipsPublicKey(pub_);
    if err != nil {
        hash.Reset();
        return (slice::default(), err);
    }
    let k = k.unwrap();

    // goish's `rsa::EncryptOAEP` takes `lHash` — Hash(label) — rather than
    // the OAEP hash plus the label, because the OAEP hash is used for
    // nothing else. Digesting the label here leaves `hash` free to be
    // passed on as the MGF1 hash, which is what Go's single `hash.Hash`
    // value does in sequence.
    hash.Reset();
    let _ = io::Writer::Write(hash, label);
    let lHash = hash.Sum(slice::default());
    let (out, err) = rsa::EncryptOAEP(lHash, hash, random, &k, msg);
    hash.Reset();
    return fipsError2(out, err);
}

// go: sdk 1.25.5 crypto/rsa/fips.go:243-246 DecryptOAEP
/// DecryptOAEP decrypts `ciphertext` using RSA-OAEP.
///
/// OAEP is parameterised by a hash function that is used as a random
/// oracle. Encryption and decryption of a given message must use the same
/// hash function, and `sha256::New()` is a reasonable choice.
///
/// The `random` parameter is legacy and ignored.
///
/// The `label` parameter must match the value given when encrypting. See
/// [`EncryptOAEP`] for details.
pub fn DecryptOAEP(
    hash: &mut dyn HashTrait,
    _random: &mut dyn io::Reader,
    priv_: &PrivateKey,
    ciphertext: slice<byte>,
    label: slice<byte>,
) -> (slice<byte>, error) {
    // Go: `defer hash.Reset()` plus `decryptOAEP(hash, hash, …)`; `None`
    // is how goish spells "the MGF1 hash is this same object".
    let (out, err) = decryptOAEP(hash, None, priv_, ciphertext, label);
    hash.Reset();
    return (out, err);
}

// go: sdk 1.25.5 crypto/rsa/fips.go:248-288 decryptOAEP
pub(super) fn decryptOAEP(
    hash: &mut dyn HashTrait,
    mgfHash: Option<&mut dyn HashTrait>,
    priv_: &PrivateKey,
    ciphertext: slice<byte>,
    label: slice<byte>,
) -> (slice<byte>, error) {
    let err = checkPublicKeySize(&priv_.PublicKey);
    if err != nil {
        return (slice::default(), err);
    }

    let err = checkFIPS140OnlyPrivateKey(priv_);
    if err != nil {
        return (slice::default(), err);
    }

    let (k, err) = fipsPrivateKey(priv_);
    if err != nil {
        return (slice::default(), err);
    }
    let k = k.unwrap();

    // See EncryptOAEP: the OAEP hash digests the label and nothing else,
    // so goish's `rsa::DecryptOAEP` takes `lHash` and the MGF1 hash.
    hash.Reset();
    let _ = io::Writer::Write(hash, label);
    let lHash = hash.Sum(slice::default());
    let (out, err) = match mgfHash {
        Some(m) => rsa::DecryptOAEP(lHash, m, &k, ciphertext),
        None => rsa::DecryptOAEP(lHash, hash, &k, ciphertext),
    };
    return fipsError2(out, err);
}

// go: sdk 1.25.5 crypto/rsa/fips.go:302-335 SignPKCS1v15
/// SignPKCS1v15 calculates the signature of `hashed` using
/// RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5. Note that `hashed` must
/// be the result of hashing the input message using the given hash
/// function. If `hash` is zero, `hashed` is signed directly. This isn't
/// advisable except for interoperability.
///
/// The `random` parameter is legacy and ignored.
///
/// This function is deterministic. Thus, if the set of possible messages
/// is small, an attacker may be able to build a map from messages to
/// signatures and identify the signed messages. As ever, signatures
/// provide authenticity, not confidentiality.
pub fn SignPKCS1v15(
    _random: &mut dyn io::Reader,
    priv_: &PrivateKey,
    hash: crypto::Hash,
    hashed: slice<byte>,
) -> (slice<byte>, error) {
    // Go binds `hashName = hash.String()` here and passes it on; goish's
    // fips140 layer takes the `crypto.Hash` id itself.
    if hash != crypto::Hash(0) {
        if hashed.Len() != hash.Size() {
            return (
                slice::default(),
                errors::New("crypto/rsa: input must be hashed message"),
            );
        }
    }

    let err = checkPublicKeySize(&priv_.PublicKey);
    if err != nil {
        return (slice::default(), err);
    }

    let err = checkFIPS140OnlyPrivateKey(priv_);
    if err != nil {
        return (slice::default(), err);
    }
    if fips140only::Enabled && !fips140only::ApprovedHash(&fips140hash::Unwrap(hash.New())) {
        return (
            slice::default(),
            errors::New(
                "crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode",
            ),
        );
    }

    let (k, err) = fipsPrivateKey(priv_);
    if err != nil {
        return (slice::default(), err);
    }
    let (sig, err) = rsa::SignPKCS1v15(&k.unwrap(), hash, hashed);
    return fipsError2(sig, err);
}

// go: sdk 1.25.5 crypto/rsa/fips.go:345-381 VerifyPKCS1v15
/// VerifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature. `hashed` is the
/// result of hashing the input message using the given hash function and
/// `sig` is the signature. A valid signature is indicated by returning a
/// nil error. If `hash` is zero then `hashed` is used directly. This
/// isn't advisable except for interoperability.
///
/// The inputs are not considered confidential, and may leak through
/// timing side channels, or if an attacker has control of part of the
/// inputs.
pub fn VerifyPKCS1v15(
    pub_: &PublicKey,
    hash: crypto::Hash,
    hashed: slice<byte>,
    sig: slice<byte>,
) -> error {
    // See SignPKCS1v15 for Go's `hashName`.
    if hash != crypto::Hash(0) {
        if hashed.Len() != hash.Size() {
            return errors::New("crypto/rsa: input must be hashed message");
        }
    }

    let err = checkPublicKeySize(pub_);
    if err != nil {
        return err;
    }

    let err = checkFIPS140OnlyPublicKey(pub_);
    if err != nil {
        return err;
    }
    if fips140only::Enabled && !fips140only::ApprovedHash(&fips140hash::Unwrap(hash.New())) {
        return errors::New(
            "crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode",
        );
    }

    let (k, err) = fipsPublicKey(pub_);
    if err != nil {
        return err;
    }
    return fipsError(rsa::VerifyPKCS1v15(&k.unwrap(), hash, hashed, sig));
}

// go: sdk 1.25.5 crypto/rsa/fips.go:383-393 fipsError
/// Map a `crypto/internal/fips140/rsa` sentinel onto this package's.
fn fipsError(err: error) -> error {
    if err == rsa::ErrDecryption {
        return ErrDecryption.into();
    }
    if err == rsa::ErrVerification {
        return ErrVerification.into();
    }
    if err == rsa::ErrMessageTooLong {
        return ErrMessageTooLong.into();
    }
    return err;
}

// go: sdk 1.25.5 crypto/rsa/fips.go:395-397 fipsError2
/// Go spreads a `(T, error)` call straight into this helper; Rust needs
/// the pair destructured first.
fn fipsError2<T>(x: T, err: error) -> (T, error) {
    return (x, fipsError(err));
}

// go: sdk 1.25.5 crypto/rsa/fips.go:399-419 checkFIPS140OnlyPublicKey
fn checkFIPS140OnlyPublicKey(pub_: &PublicKey) -> error {
    if !fips140only::Enabled {
        return nil.into();
    }
    if pub_.N == nil {
        return errors::New("crypto/rsa: public key missing N");
    }
    if pub_.N.BitLen() < 2048 {
        return errors::New(
            "crypto/rsa: use of keys smaller than 2048 bits is not allowed in FIPS 140-only mode",
        );
    }
    if pub_.N.BitLen() % 2 == 1 {
        return errors::New(
            "crypto/rsa: use of keys with odd size is not allowed in FIPS 140-only mode",
        );
    }
    if pub_.E <= 1 << 16 {
        return errors::New(
            "crypto/rsa: use of public exponent <= 2¹⁶ is not allowed in FIPS 140-only mode",
        );
    }
    if pub_.E & 1 == 0 {
        return errors::New(
            "crypto/rsa: use of even public exponent is not allowed in FIPS 140-only mode",
        );
    }
    return nil.into();
}

// go: sdk 1.25.5 crypto/rsa/fips.go:421-435 checkFIPS140OnlyPrivateKey
fn checkFIPS140OnlyPrivateKey(priv_: &PrivateKey) -> error {
    if !fips140only::Enabled {
        return nil.into();
    }
    let err = checkFIPS140OnlyPublicKey(&priv_.PublicKey);
    if err != nil {
        return err;
    }
    if priv_.Primes.Len() != 2 {
        return errors::New(
            "crypto/rsa: use of multi-prime keys is not allowed in FIPS 140-only mode",
        );
    }
    if priv_.Primes[0] == nil
        || priv_.Primes[1] == nil
        || priv_.Primes[0].BitLen() != priv_.Primes[1].BitLen()
    {
        return errors::New(
            "crypto/rsa: use of primes of different sizes is not allowed in FIPS 140-only mode",
        );
    }
    return nil.into();
}
