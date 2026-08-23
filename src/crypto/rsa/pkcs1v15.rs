// go: file crypto/rsa/pkcs1v15.go decls: EncryptPKCS1v15, DecryptPKCS1v15, DecryptPKCS1v15SessionKey, decryptPKCS1v15, nonZeroRandomBytes
//
// Encryption and decryption using PKCS #1 v1.5 padding — the EME-PKCS1-v1_5
// scheme. Only the RSA primitive itself is delegated to
// `crypto/internal/fips140/rsa` (`Encrypt` / `DecryptWithoutCheck`); the
// padding, and above all its constant-time removal, lives here exactly as
// it does in Go. That placement is deliberate: the FIPS 140-3 module ships
// v1.5 *signing* only, so v1.5 *encryption* is outside it.
//
// Deviations from pkcs1v15[go] @ Go 1.25.5:
//
//   * The `boring.Enabled` branches are absent — goish has no cgo and so
//     no `crypto/internal/boring`. See rsa.rs's banner.
//   * Go builds `EM` by taking two sub-slices of `em` that alias its
//     backing array (`ps, mm := em[2:…], em[…:]`) and filling them in
//     place. goish slices never share a mutable backing (AGENTS.md §2),
//     so `PS` is generated into its own buffer and copied in.
//   * `randutil.MaybeReadByte(random)` in `EncryptPKCS1v15` is omitted:
//     goish's `randutil::MaybeReadByte` wants
//     `&mut (dyn io::Reader + Send + Sync + 'static)` and this package's
//     readers are bare `&mut dyn io::Reader`. What is lost is Go's
//     deliberate perturbation of the reader stream, which exists to stop
//     callers depending on a deterministic ciphertext; correctness of the
//     padding is unaffected.
//   * `DecryptPKCS1v15` / `DecryptPKCS1v15SessionKey` name their unused
//     first parameter `_random`. Go keeps it as `random` and ignores it;
//     Rust warns unless the name is underscore-prefixed.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::internal::fips140::rsa;
use crate::crypto::internal::fips140only;
use crate::crypto::subtle;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::nilval::nil;
use crate::types::{byte, int};

use super::rsa::{
    checkPublicKeySize, fipsPrivateKey, fipsPublicKey, ErrDecryption, ErrMessageTooLong,
    PrivateKey, PublicKey,
};

// Go: pkcs1v15.go:21-27
//   type PKCS1v15DecryptOptions struct { SessionKeyLen int }
/// `PKCS1v15DecryptOptions` is for passing options to PKCS #1 v1.5
/// decryption using the `crypto::Decrypter` interface.
#[derive(Clone, Default)]
pub struct PKCS1v15DecryptOptions {
    /// SessionKeyLen is the length of the session key that is being
    /// decrypted. If not zero, then a padding error during decryption
    /// will cause a random plaintext of this length to be returned rather
    /// than an error. These alternatives happen in constant time.
    pub SessionKeyLen: int,
}

// go: sdk 1.25.5 crypto/rsa/pkcs1v15.go:42-92 EncryptPKCS1v15
/// EncryptPKCS1v15 encrypts the given message with RSA and the padding
/// scheme from PKCS #1 v1.5. The message must be no longer than the
/// length of the public modulus minus 11 bytes.
///
/// The `random` parameter is used as a source of entropy to ensure that
/// encrypting the same message twice doesn't result in the same
/// ciphertext.
///
/// WARNING: use of this function to encrypt plaintexts other than session
/// keys is dangerous. Use RSA OAEP in new protocols.
pub fn EncryptPKCS1v15(
    random: &mut dyn io::Reader,
    pub_: &PublicKey,
    msg: slice<byte>,
) -> (slice<byte>, error) {
    if fips140only::Enabled {
        return (
            slice::default(),
            errors::New(
                "crypto/rsa: use of PKCS#1 v1.5 encryption is not allowed in FIPS 140-only mode",
            ),
        );
    }

    let err = checkPublicKeySize(pub_);
    if err != nil {
        return (slice::default(), err);
    }

    // Go: randutil.MaybeReadByte(random) — see the banner.

    let k = pub_.Size();
    if msg.Len() > k - 11 {
        return (slice::default(), ErrMessageTooLong.into());
    }

    // EM = 0x00 || 0x02 || PS || 0x00 || M
    let mut em: Vec<byte> = alloc::vec![0u8; usize::try_from(k).unwrap_or(0)];
    em[1] = 2;
    let mut ps: slice<byte> =
        slice::__from_vec(alloc::vec![0u8; usize::try_from(k - msg.Len() - 3).unwrap_or(0)]);
    let err = nonZeroRandomBytes(&mut ps, random);
    if err != nil {
        return (slice::default(), err);
    }
    for (i, b) in crate::range!(ps) {
        em[2 + usize::try_from(i).unwrap_or(0)] = *b;
    }
    em[usize::try_from(k - msg.Len() - 1).unwrap_or(0)] = 0;
    let mstart = usize::try_from(k - msg.Len()).unwrap_or(0);
    for (i, b) in crate::range!(msg) {
        em[mstart + usize::try_from(i).unwrap_or(0)] = *b;
    }

    let (fk, err) = fipsPublicKey(pub_);
    if err != nil {
        return (slice::default(), err);
    }
    return rsa::Encrypt(&fk.unwrap(), slice::__from_vec(em));
}

// go: sdk 1.25.5 crypto/rsa/pkcs1v15.go:102-127 DecryptPKCS1v15
/// DecryptPKCS1v15 decrypts a plaintext using RSA and the padding scheme
/// from PKCS #1 v1.5. The `random` parameter is legacy and ignored.
///
/// Note that whether this function returns an error or not discloses
/// secret information. If an attacker can cause this function to run
/// repeatedly and learn whether each instance returned an error then they
/// can decrypt and forge signatures as if they had the private key. See
/// [`DecryptPKCS1v15SessionKey`] for a way of solving this problem.
pub fn DecryptPKCS1v15(
    _random: &mut dyn io::Reader,
    priv_: &PrivateKey,
    ciphertext: slice<byte>,
) -> (slice<byte>, error) {
    let err = checkPublicKeySize(&priv_.PublicKey);
    if err != nil {
        return (slice::default(), err);
    }

    let (valid, out, index, err) = decryptPKCS1v15(priv_, ciphertext);
    if err != nil {
        return (slice::default(), err);
    }
    if valid == 0 {
        return (slice::default(), ErrDecryption.into());
    }
    return (
        slice::__from_vec(out.as_ref()[usize::try_from(index).unwrap_or(0)..].to_vec()),
        nil.into(),
    );
}

// go: sdk 1.25.5 crypto/rsa/pkcs1v15.go:163-187 DecryptPKCS1v15SessionKey
/// DecryptPKCS1v15SessionKey decrypts a session key using RSA and the
/// padding scheme from PKCS #1 v1.5. The `random` parameter is legacy and
/// ignored.
///
/// It returns an error if the ciphertext is the wrong length or if the
/// ciphertext is greater than the public modulus. Otherwise, no error is
/// returned. If the padding is valid, the resulting plaintext message is
/// copied into `key`; otherwise `key` is unchanged. These alternatives
/// occur in constant time. It is intended that the user of this function
/// generate a random session key beforehand and continue the protocol
/// with the resulting value.
///
/// Note that if the session key is too small then it may be possible for
/// an attacker to brute-force it. Using at least a 16-byte key will
/// protect against this attack.
///
/// This method implements protections against Bleichenbacher chosen
/// ciphertext attacks described in RFC 3218 Section 2.3.2. The protections
/// are only effective if the rest of the protocol which uses
/// DecryptPKCS1v15SessionKey is designed with these considerations in
/// mind — in particular, if any subsequent operation leaks information
/// about the decrypted session key, the mitigations are defeated.
pub fn DecryptPKCS1v15SessionKey(
    _random: &mut dyn io::Reader,
    priv_: &PrivateKey,
    ciphertext: slice<byte>,
    key: &mut slice<byte>,
) -> error {
    let err = checkPublicKeySize(&priv_.PublicKey);
    if err != nil {
        return err;
    }

    let k = priv_.PublicKey.Size();
    if k - (key.Len() + 3 + 8) < 0 {
        return ErrDecryption.into();
    }

    let (valid, em, index, err) = decryptPKCS1v15(priv_, ciphertext);
    if err != nil {
        return err;
    }

    if em.Len() != k {
        // This should be impossible because decryptPKCS1v15 always
        // returns the full slice.
        return ErrDecryption.into();
    }

    let mut valid = valid;
    valid &= subtle::ConstantTimeEq(
        i32::try_from(em.Len() - index).unwrap_or(0),
        i32::try_from(key.Len()).unwrap_or(0),
    );
    let tail = slice::__from_vec(
        em.as_ref()[usize::try_from(em.Len() - key.Len()).unwrap_or(0)..].to_vec(),
    );
    subtle::ConstantTimeCopy(valid, key, &tail);
    return nil.into();
}

// go: sdk 1.25.5 crypto/rsa/pkcs1v15.go:195-249 decryptPKCS1v15
/// decryptPKCS1v15 decrypts `ciphertext` using `priv`. It returns one or
/// zero in `valid` that indicates whether the plaintext was correctly
/// structured. In either case, the plaintext is returned in `em` so that
/// it may be read independently of whether it was valid, in order to
/// maintain constant memory access patterns. If the plaintext was valid
/// then `index` contains the index of the original message in `em`, to
/// allow constant time padding removal.
fn decryptPKCS1v15(priv_: &PrivateKey, ciphertext: slice<byte>) -> (int, slice<byte>, int, error) {
    if fips140only::Enabled {
        return (
            0,
            slice::default(),
            0,
            errors::New(
                "crypto/rsa: use of PKCS#1 v1.5 encryption is not allowed in FIPS 140-only mode",
            ),
        );
    }

    let k = priv_.PublicKey.Size();
    if k < 11 {
        return (0, slice::default(), 0, ErrDecryption.into());
    }

    let (fk, err) = fipsPrivateKey(priv_);
    if err != nil {
        return (0, slice::default(), 0, err);
    }
    let (em, err) = rsa::DecryptWithoutCheck(&fk.unwrap(), ciphertext);
    if err != nil {
        return (0, slice::default(), 0, ErrDecryption.into());
    }

    let firstByteIsZero = subtle::ConstantTimeByteEq(em[0], 0);
    let secondByteIsTwo = subtle::ConstantTimeByteEq(em[1], 2);

    // The remainder of the plaintext must be a string of non-zero random
    // octets, followed by a 0, followed by the message.
    //   lookingForIndex: 1 iff we are still looking for the zero.
    //   index: the offset of the first zero byte.
    let mut lookingForIndex: int = 1;
    let mut index: int = 0;

    for (i, b) in crate::range!(em) {
        if i < 2 {
            continue;
        }
        let equals0 = subtle::ConstantTimeByteEq(*b, 0);
        index = subtle::ConstantTimeSelect(lookingForIndex & equals0, i, index);
        lookingForIndex = subtle::ConstantTimeSelect(equals0, 0, lookingForIndex);
    }

    // The PS padding must be at least 8 bytes long, and it starts two
    // bytes into em.
    let validPS = subtle::ConstantTimeLessOrEq(2 + 8, index);

    let valid = firstByteIsZero & secondByteIsTwo & (!lookingForIndex & 1) & validPS;
    index = subtle::ConstantTimeSelect(valid, index + 1, 0);
    return (valid, em, index, nil.into());
}

// go: sdk 1.25.5 crypto/rsa/pkcs1v15.go:252-271 nonZeroRandomBytes
/// nonZeroRandomBytes fills the given slice with non-zero random octets.
fn nonZeroRandomBytes(s: &mut slice<byte>, random: &mut dyn io::Reader) -> error {
    let (_, err) = io::ReadFull(random, s);
    if err != nil {
        return err;
    }

    let n = s.Len();
    let mut i: int = 0;
    while i < n {
        while s[i] == 0 {
            let mut one: slice<byte> = slice::__from_vec(alloc::vec![0u8; 1]);
            let (_, err) = io::ReadFull(random, &mut one);
            if err != nil {
                return err;
            }
            s[i] = one[0];
            // In tests, the PRNG may return all zeros so we do this to
            // break the loop.
            s[i] ^= 0x42;
        }
        i += 1;
    }

    return nil.into();
}
