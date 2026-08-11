// go: file crypto/internal/fips140/rsa/pkcs1v22.go decls: incCounter, mgf1XOR, emsaPSSEncode, emsaPSSVerify, PSSMaxSaltLength, SignPSS, VerifyPSS, VerifyPSSWithSaltLength, verifyPSS, checkApprovedHash, EncryptOAEP, DecryptOAEP
//
// The RSASSA-PSS signature scheme and the RSAES-OAEP encryption scheme
// according to RFC 8017, aka PKCS #1 v2.2.
//
// Per RFC 8017, Section 9.1
//
//     EM = MGF1 xor DB || H( 8*0x00 || mHash || salt ) || 0xbc
//
// where
//
//     DB = PS || 0x01 || salt
//
// and PS can be empty so
//
//     emLen = dbLen + hLen + 1 = psLen + sLen + hLen + 2
//
// Deviations from pkcs1v22[go] @ Go 1.25.5:
//
//   * Go's `hash hash.Hash` parameter is `&mut dyn crate::hash::Hash`.
//   * `drbg.ReadWithReaderDeterministic(rand, b)` is `read_with_reader`
//     (rsa.rs) — with FIPS mode off Go's body is `io.ReadFull`.
//   * OAEP takes the label DIGEST, not the label — see the GOISH020
//     waiver on EncryptOAEP/DecryptOAEP below.
//   * `checkApprovedHash` is a no-op — see its own comment.
//
// goishlint:ignore GOISH020 EncryptOAEP, DecryptOAEP — Go's signatures
// are `(hash, mgfHash hash.Hash, …, label []byte)`: the OAEP hash is
// used for exactly one thing, `lHash = Hash(label)`, and Go's own
// crypto/rsa callers pass the SAME hash.Hash object as both `hash` and
// `mgfHash`. Rust cannot hand one object out as two `&mut dyn Hash`
// borrows, so goish takes `lHash` already digested and drops the
// now-unused `label`: 6 params become 5, and 5 become 4. Same bytes on
// the wire; the digesting moves one frame up, into crypto/rsa.

extern crate alloc;

use super::cast::fipsSelfTest;
use super::rsa::{
    decrypt, encrypt, nil_bytes, noCheck, read_with_reader, withCheck,
    ErrDecryption, ErrMessageTooLong, ErrVerification, PrivateKey, PublicKey,
};
use crate::bytes;
use crate::crypto::internal::fips140;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::hash::Hash as HashTrait;
use crate::io;
use crate::types::{byte, int, uint};
use alloc::vec::Vec;

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:37-48 incCounter
/// `incCounter` increments a four byte, big-endian counter.
fn incCounter(c: &mut [byte; 4]) {
    c[3] = c[3].wrapping_add(1);
    if c[3] != 0 {
        return;
    }
    c[2] = c[2].wrapping_add(1);
    if c[2] != 0 {
        return;
    }
    c[1] = c[1].wrapping_add(1);
    if c[1] != 0 {
        return;
    }
    c[0] = c[0].wrapping_add(1);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:52-69 mgf1XOR
/// `mgf1XOR` XORs the bytes in `out` with a mask generated using the
/// MGF1 function specified in PKCS #1 v2.1.
fn mgf1XOR(out: &mut [byte], hash: &mut dyn HashTrait, seed: &[byte]) {
    let mut counter: [byte; 4] = [0, 0, 0, 0];
    let mut done: usize = 0;

    while done < out.len() {
        hash.Reset();
        // hash.Write(seed)
        {
            let s = slice::<byte>::__from_vec(seed.to_vec());
            let _ = hash.Write(s);
        }
        // hash.Write(counter[0:4])
        {
            let c = slice::<byte>::__from_vec(counter.to_vec());
            let _ = hash.Write(c);
        }
        let digest = hash.Sum(slice::<byte>::new());
        let dv = digest.to_vec();
        let mut i: usize = 0;
        while i < dv.len() && done < out.len() {
            out[done] ^= dv[i];
            done += 1;
            i += 1;
        }
        incCounter(&mut counter);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:71-144 emsaPSSEncode
/// `emsaPSSEncode` — the EMSA-PSS encoding operation, RFC 8017 §9.1.1.
fn emsaPSSEncode(
    mHash: &[byte],
    emBits: int,
    salt: &[byte],
    hash: &mut dyn HashTrait,
) -> (slice<byte>, error) {
    let hLen = usize::try_from(hash.Size()).unwrap_or(0);
    let sLen = salt.len();
    let emLen = usize::try_from((emBits + 7) / 8).unwrap_or(0);

    // 2. Let mHash = Hash(M), an octet string of length hLen.
    if mHash.len() != hLen {
        return (
            nil_bytes(),
            errors::New("crypto/rsa: input must be hashed with given hash"),
        );
    }

    // 3. If emLen < hLen + sLen + 2, output "encoding error" and stop.
    if emLen < hLen + sLen + 2 {
        return (nil_bytes(), ErrMessageTooLong.into());
    }

    let mut em: Vec<byte> = alloc::vec![0u8; emLen];
    let psLen = emLen - sLen - hLen - 2;
    // db = em[:psLen+1+sLen]; h = em[psLen+1+sLen : emLen-1].
    let db_end = psLen + 1 + sLen;
    let h_start = db_end;
    let h_end = emLen - 1;

    // 5-6. M' = 8*0x00 || mHash || salt ; H = Hash(M').
    let prefix: [byte; 8] = [0; 8];
    hash.Reset();
    let _ = hash.Write(slice::<byte>::__from_vec(prefix.to_vec()));
    let _ = hash.Write(slice::<byte>::__from_vec(mHash.to_vec()));
    let _ = hash.Write(slice::<byte>::__from_vec(salt.to_vec()));
    let h_digest = hash.Sum(slice::<byte>::new()).to_vec();
    {
        let mut i: usize = 0;
        while i < h_digest.len() && h_start + i < h_end {
            em[h_start + i] = h_digest[i];
            i += 1;
        }
    }

    // 7-8. DB = PS || 0x01 || salt.
    em[psLen] = 0x01;
    {
        let mut i: usize = 0;
        while i < sLen {
            em[psLen + 1 + i] = salt[i];
            i += 1;
        }
    }

    // 9-10. dbMask = MGF(H, emLen-hLen-1); maskedDB = DB xor dbMask.
    {
        // h sits inside em; copy it out to use as the MGF seed.
        let h_seed: Vec<byte> = em[h_start..h_end].to_vec();
        let mut db: Vec<byte> = em[..db_end].to_vec();
        mgf1XOR(&mut db, hash, &h_seed);
        // 11. Set the leftmost 8*emLen-emBits bits of maskedDB[0] to 0.
        let shift = uint::try_from(8 * int::try_from(emLen).unwrap_or(0) - emBits).unwrap_or(0);
        db[0] &= 0xffu8 >> shift;
        let mut i: usize = 0;
        while i < db.len() {
            em[i] = db[i];
            i += 1;
        }
    }

    // 12-13. EM = maskedDB || H || 0xbc.
    em[emLen - 1] = 0xbc;
    return (slice::<byte>::__from_vec(em), errors::nil);
}

const pssSaltLengthAutodetect: int = -1;

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:148-250 emsaPSSVerify
/// `emsaPSSVerify` — the EMSA-PSS verification operation, RFC 8017 §9.1.2.
fn emsaPSSVerify(
    mHash: &[byte],
    em: &[byte],
    emBits: int,
    sLen: int,
    hash: &mut dyn HashTrait,
) -> error {
    // The whole of this function does its length arithmetic in `int`,
    // as Go does: `sLen` is -1 in autodetect mode, and step 3 is what
    // keeps every slice index below in range.
    let hLen = hash.Size();
    let emLen = (emBits + 7) / 8;
    if emLen != int::try_from(em.len()).unwrap_or(0) {
        return errors::New("rsa: internal error: inconsistent length");
    }

    // 2. Let mHash = Hash(M), an octet string of length hLen.
    if hLen != int::try_from(mHash.len()).unwrap_or(0) {
        return ErrVerification.into();
    }

    // 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    let mut sLen = sLen;
    if emLen < hLen + sLen + 2 {
        return ErrVerification.into();
    }

    let emLenU = usize::try_from(emLen).unwrap_or(0);
    let hLenU = usize::try_from(hLen).unwrap_or(0);

    // 4. The rightmost octet of EM must be 0xbc.
    if em[emLenU - 1] != 0xbc {
        return ErrVerification.into();
    }

    // 5. maskedDB = em[:emLen-hLen-1]; h = em[emLen-hLen-1 : emLen-1].
    let db_end = emLenU - hLenU - 1;
    let mut db: Vec<byte> = em[..db_end].to_vec();
    let h: Vec<byte> = em[db_end..emLenU - 1].to_vec();

    // 6. The leftmost 8*emLen-emBits bits of maskedDB[0] must be zero.
    let shift = uint::try_from(8 * emLen - emBits).unwrap_or(0);
    let bitMask: byte = 0xffu8 >> shift;
    if em[0] & !bitMask != 0 {
        return ErrVerification.into();
    }

    // 7-8. dbMask = MGF(H, emLen-hLen-1); DB = maskedDB xor dbMask.
    mgf1XOR(&mut db, hash, &h);

    // 9. Zero the leftmost 8*emLen-emBits bits of DB[0].
    db[0] &= bitMask;

    // If we don't know the salt length, look for the 0x01 delimiter.
    if sLen == pssSaltLengthAutodetect {
        let psLen = bytes::IndexByte(slice::<byte>::__from_vec(db.clone()), 0x01);
        if psLen < 0 {
            return ErrVerification.into();
        }
        sLen = int::try_from(db.len()).unwrap_or(0) - psLen - 1;
    }

    // FIPS 186-5, Section 5.4(g): 0 <= sLen <= hLen.
    if sLen > hLen {
        fips140::RecordNonApproved();
    }

    // 10. The emLen-hLen-sLen-2 leftmost octets of DB must be zero, and
    //     the octet at position emLen-hLen-sLen-2 must be 0x01.
    let psLen = emLen - hLen - sLen - 2;
    let psLenU = usize::try_from(psLen).unwrap_or(0);
    {
        let mut i: usize = 0;
        while i < psLenU {
            if db[i] != 0x00 {
                return ErrVerification.into();
            }
            i += 1;
        }
    }
    if db[psLenU] != 0x01 {
        return ErrVerification.into();
    }

    // 11. salt is the last sLen octets of DB.
    let sLenU = usize::try_from(sLen).unwrap_or(0);
    let salt: Vec<byte> = db[db.len() - sLenU..].to_vec();

    // 12-13. M' = 8*0x00 || mHash || salt ; H' = Hash(M').
    hash.Reset();
    let prefix: [byte; 8] = [0; 8];
    let _ = hash.Write(slice::<byte>::__from_vec(prefix.to_vec()));
    let _ = hash.Write(slice::<byte>::__from_vec(mHash.to_vec()));
    let _ = hash.Write(slice::<byte>::__from_vec(salt));
    let h0 = hash.Sum(slice::<byte>::new()).to_vec();

    // 14. H == H' ?
    if !bytes::Equal(slice::<byte>::__from_vec(h0), slice::<byte>::__from_vec(h)) {
        return ErrVerification.into();
    }
    return errors::nil;
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:254-265 PSSMaxSaltLength
/// `PSSMaxSaltLength` returns the maximum salt length for a given public
/// key and hash function.
pub fn PSSMaxSaltLength(pub_: &PublicKey, hash: &mut dyn HashTrait) -> (int, error) {
    let saltLength = (pub_.N.BitLen() - 1 + 7) / 8 - 2 - hash.Size();
    if saltLength < 0 {
        return (0, ErrMessageTooLong.into());
    }
    // FIPS 186-5, Section 5.4(g): 0 <= sLen <= hLen.
    if fips140::Enabled() && saltLength > hash.Size() {
        return (hash.Size(), errors::nil);
    }
    return (saltLength, errors::nil);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:268-312 SignPSS
/// `SignPSS` calculates the signature of `hashed` using RSASSA-PSS.
pub fn SignPSS(
    rand: &mut dyn io::Reader,
    priv_: &PrivateKey,
    hash: &mut dyn HashTrait,
    hashed: slice<byte>,
    saltLength: int,
) -> (slice<byte>, error) {
    fipsSelfTest();
    fips140::RecordApproved();
    checkApprovedHash(hash);

    if saltLength < 0 {
        return (
            nil_bytes(),
            errors::New("crypto/rsa: salt length cannot be negative"),
        );
    }
    // FIPS 186-5, Section 5.4(g): 0 <= sLen <= hLen.
    if saltLength > hash.Size() {
        fips140::RecordNonApproved();
    }
    let mut salt: Vec<byte> = alloc::vec![0u8; usize::try_from(saltLength).unwrap_or(0)];
    {
        let err = read_with_reader(rand, &mut salt);
        if !err.IsNil() {
            return (nil_bytes(), err);
        }
    }

    let emBits = priv_.pub_.N.BitLen() - 1;
    let hashed_v = hashed.to_vec();
    let (em0, err) = emsaPSSEncode(&hashed_v, emBits, &salt, hash);
    if !err.IsNil() {
        return (nil_bytes(), err);
    }

    // RFC 8017: the octet length of EM is one less than k when modBits-1
    // is divisible by 8, and equal to k otherwise. Fix it by padding
    // inefficiently — it only happens for weird modulus sizes.
    let mut em = em0.to_vec();
    let k = usize::try_from(priv_.pub_.Size()).unwrap_or(0);
    if em.len() < k {
        let mut emNew: Vec<byte> = alloc::vec![0u8; k];
        let off = k - em.len();
        let mut i: usize = 0;
        while i < em.len() {
            emNew[off + i] = em[i];
            i += 1;
        }
        em = emNew;
    }

    return decrypt(priv_, slice::<byte>::__from_vec(em), withCheck);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:315-317 VerifyPSS
/// `VerifyPSS` verifies `sig` with RSASSA-PSS, automatically detecting
/// the salt length.
pub fn VerifyPSS(
    pub_: &PublicKey,
    hash: &mut dyn HashTrait,
    digest: slice<byte>,
    sig: slice<byte>,
) -> error {
    return verifyPSS(pub_, hash, digest, sig, pssSaltLengthAutodetect);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:320-325 VerifyPSSWithSaltLength
/// `VerifyPSSWithSaltLength` verifies `sig` with RSASSA-PSS and an
/// expected salt length.
pub fn VerifyPSSWithSaltLength(
    pub_: &PublicKey,
    hash: &mut dyn HashTrait,
    digest: slice<byte>,
    sig: slice<byte>,
    saltLength: int,
) -> error {
    if saltLength < 0 {
        return errors::New("crypto/rsa: salt length cannot be negative");
    }
    return verifyPSS(pub_, hash, digest, sig, saltLength);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:327-361 verifyPSS
fn verifyPSS(
    pub_: &PublicKey,
    hash: &mut dyn HashTrait,
    digest: slice<byte>,
    sig: slice<byte>,
    saltLength: int,
) -> error {
    fipsSelfTest();
    fips140::RecordApproved();
    checkApprovedHash(hash);
    let (fipsApproved, err) = super::rsa::checkPublicKey(pub_);
    if !err.IsNil() {
        return err;
    } else if !fipsApproved {
        fips140::RecordNonApproved();
    }

    if sig.Len() != pub_.Size() {
        return ErrVerification.into();
    }

    let emBits = pub_.N.BitLen() - 1;
    let emLen = usize::try_from((emBits + 7) / 8).unwrap_or(0);
    let (em0, err) = encrypt(pub_, sig);
    if !err.IsNil() {
        return ErrVerification.into();
    }

    // Like in SignPSS, deal with mismatches between emLen and the size
    // of the modulus: always encode to the size of the modulus and then
    // strip leading zeroes if necessary.
    let mut em = em0.to_vec();
    while em.len() > emLen && !em.is_empty() {
        if em[0] != 0 {
            return ErrVerification.into();
        }
        em.remove(0);
    }

    let digest_v = digest.to_vec();
    return emsaPSSVerify(&digest_v, &em, emBits, saltLength, hash);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:363-369 checkApprovedHash
/// Go switches on the concrete type of `hash` (`*sha256.Digest`,
/// `*sha512.Digest`, `*sha3.Digest`) and records non-approved use for
/// anything else. goish's `&mut dyn hash::Hash` carries no such type
/// switch, so this records nothing; `fips140::RecordApproved()` has
/// already run at every call site, and the CAST self-test still pins a
/// known-answer vector. FIPS-approval bookkeeping only — no bytes on
/// the wire depend on it.
fn checkApprovedHash(_hash: &mut dyn HashTrait) {}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:372-412 EncryptOAEP
/// `EncryptOAEP` encrypts the given message with RSAES-OAEP.
///
/// `lHash` is `Hash(label)`, precomputed by the caller — see the
/// GOISH020 waiver in the file header.
pub fn EncryptOAEP(
    lHash: slice<byte>,
    mgfHash: &mut dyn HashTrait,
    random: &mut dyn io::Reader,
    pub_: &PublicKey,
    msg: slice<byte>,
) -> (slice<byte>, error) {
    fipsSelfTest();
    fips140::RecordApproved();
    let (fipsApproved, err) = super::rsa::checkPublicKey(pub_);
    if !err.IsNil() {
        return (nil_bytes(), err);
    } else if !fipsApproved {
        fips140::RecordNonApproved();
    }
    let k = usize::try_from(pub_.Size()).unwrap_or(0);
    let lHash = lHash.to_vec();
    let hSize = lHash.len();
    let msg_v = msg.to_vec();
    // Signed comparison: k - 2*hSize - 2 can be negative for small keys.
    let maxMsg =
        int::try_from(k).unwrap_or(0) - 2 * int::try_from(hSize).unwrap_or(0) - 2;
    if int::try_from(msg_v.len()).unwrap_or(int::MAX) > maxMsg {
        return (nil_bytes(), ErrMessageTooLong.into());
    }

    // em = 0x00 || seed (hSize) || db (k-1-hSize).
    let mut em: Vec<byte> = alloc::vec![0u8; k];
    let seed_start = 1;
    let seed_end = 1 + hSize;
    let db_start = 1 + hSize;

    // db = lHash || PS(0x00..) || 0x01 || msg.
    {
        let mut i: usize = 0;
        while i < hSize {
            em[db_start + i] = lHash[i];
            i += 1;
        }
    }
    let db_len = k - db_start;
    // db[len(db)-len(msg)-1] = 1
    em[db_start + db_len - msg_v.len() - 1] = 1;
    {
        let mstart = db_start + db_len - msg_v.len();
        let mut i: usize = 0;
        while i < msg_v.len() {
            em[mstart + i] = msg_v[i];
            i += 1;
        }
    }

    // seed = random hSize bytes.
    {
        let mut seed: Vec<byte> = alloc::vec![0u8; hSize];
        let err = read_with_reader(random, &mut seed);
        if !err.IsNil() {
            return (nil_bytes(), err);
        }
        let mut i: usize = 0;
        while i < hSize {
            em[seed_start + i] = seed[i];
            i += 1;
        }
    }

    // mgf1XOR(db, mgfHash, seed); mgf1XOR(seed, mgfHash, db).
    {
        let seed_cur: Vec<byte> = em[seed_start..seed_end].to_vec();
        let mut db: Vec<byte> = em[db_start..k].to_vec();
        mgf1XOR(&mut db, mgfHash, &seed_cur);
        let mut i: usize = 0;
        while i < db.len() {
            em[db_start + i] = db[i];
            i += 1;
        }
    }
    {
        let db_cur: Vec<byte> = em[db_start..k].to_vec();
        let mut seed: Vec<byte> = em[seed_start..seed_end].to_vec();
        mgf1XOR(&mut seed, mgfHash, &db_cur);
        let mut i: usize = 0;
        while i < seed.len() {
            em[seed_start + i] = seed[i];
            i += 1;
        }
    }

    return encrypt(pub_, slice::<byte>::__from_vec(em));
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v22.go:415-473 DecryptOAEP
/// `DecryptOAEP` decrypts `ciphertext` using RSAES-OAEP.
///
/// `lHash` is `Hash(label)`, precomputed by the caller — see the
/// GOISH020 waiver in the file header.
pub fn DecryptOAEP(
    lHash: slice<byte>,
    mgfHash: &mut dyn HashTrait,
    priv_: &PrivateKey,
    ciphertext: slice<byte>,
) -> (slice<byte>, error) {
    fipsSelfTest();
    fips140::RecordApproved();

    let lHash = lHash.to_vec();
    let k = usize::try_from(priv_.pub_.Size()).unwrap_or(0);
    let hSize = lHash.len();
    if usize::try_from(ciphertext.Len()).unwrap_or(usize::MAX) > k || k < hSize * 2 + 2 {
        return (nil_bytes(), ErrDecryption.into());
    }

    let (emSlice, err) = decrypt(priv_, ciphertext, noCheck);
    if !err.IsNil() {
        return (nil_bytes(), err);
    }
    // bigmod's Bytes() is fixed-width at the modulus size, so `em` is
    // already the full k-byte encoded message Go relies on here.
    let mut em = emSlice.to_vec();

    use crate::crypto::subtle::{ConstantTimeByteEq, ConstantTimeSelect};
    let firstByteIsZero = ConstantTimeByteEq(em[0], 0);

    // seed = em[1 : hSize+1]; db = em[hSize+1:].
    let seed_start = 1;
    let seed_end = hSize + 1;
    let db_start = hSize + 1;

    // mgf1XOR(seed, mgfHash, db); mgf1XOR(db, mgfHash, seed).
    {
        let db_cur: Vec<byte> = em[db_start..k].to_vec();
        let mut seed: Vec<byte> = em[seed_start..seed_end].to_vec();
        mgf1XOR(&mut seed, mgfHash, &db_cur);
        let mut i: usize = 0;
        while i < seed.len() {
            em[seed_start + i] = seed[i];
            i += 1;
        }
    }
    {
        let seed_cur: Vec<byte> = em[seed_start..seed_end].to_vec();
        let mut db: Vec<byte> = em[db_start..k].to_vec();
        mgf1XOR(&mut db, mgfHash, &seed_cur);
        let mut i: usize = 0;
        while i < db.len() {
            em[db_start + i] = db[i];
            i += 1;
        }
    }

    // lHash2 = db[0:hSize].
    let lHash2: Vec<byte> = em[db_start..db_start + hSize].to_vec();

    // We have to validate the plaintext in constant time in order to
    // avoid attacks like Manger's chosen-ciphertext attack on OAEP.
    let lHash2Good =
        crate::crypto::subtle::ConstantTimeCompare(&slice::<byte>::__from_vec(lHash.clone()), &slice::<byte>::__from_vec(lHash2));

    // The remainder of the plaintext must be zero or more 0x00, followed
    // by 0x01, followed by the message.
    //   lookingForIndex: 1 iff we are still looking for the 0x01
    //   index: the offset of the first 0x01 byte
    //   invalid: 1 iff we saw a non-zero byte before the 0x01.
    let mut lookingForIndex: int = 1;
    let mut index: int = 0;
    let mut invalid: int = 0;
    let rest_start = db_start + hSize;
    {
        let mut i: usize = 0;
        let rest_len = k - rest_start;
        while i < rest_len {
            let b = em[rest_start + i];
            let equals0 = ConstantTimeByteEq(b, 0);
            let equals1 = ConstantTimeByteEq(b, 1);
            index = ConstantTimeSelect(
                lookingForIndex & equals1,
                int::try_from(i).unwrap_or(0),
                index,
            );
            lookingForIndex = ConstantTimeSelect(equals1, 0, lookingForIndex);
            invalid = ConstantTimeSelect(lookingForIndex & !equals0, 1, invalid);
            i += 1;
        }
    }

    if firstByteIsZero & lHash2Good & !invalid & !lookingForIndex != 1 {
        return (nil_bytes(), ErrDecryption.into());
    }

    let msg_off = rest_start + usize::try_from(index).unwrap_or(0) + 1;
    return (slice::<byte>::__from_vec(em[msg_off..].to_vec()), errors::nil);
}
