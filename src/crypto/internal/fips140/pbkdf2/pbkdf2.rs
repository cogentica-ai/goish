// go: file crypto/internal/fips140/pbkdf2/pbkdf2.go decls: divRoundUp, Key, setServiceIndicator
//
// crypto/internal/fips140/pbkdf2 — PBKDF2 (RFC 8018 / SP 800-132). The
// public crypto/pbkdf2 package is a thin wrapper over this.
//
// Deviations from pbkdf2[go] @ Go 1.25.5:
//
//   * The hash factory is `fn() -> Box<dyn Hash + Send + Sync>` rather
//     than Go's `func() Hash` generic, matching `hmac::New`.
//   * `setServiceIndicator` is ported for shape but its body is inert:
//     every branch calls `fips140.Record{Non,}Approved()`, and goish's
//     fips140 stub records nothing. Keeping it means the SP 800-132 salt
//     and key-length thresholds stay documented at the point they apply.
//   * cast[go]'s `init` is not ported (no CAST registry).

#![allow(non_snake_case)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::internal::fips140::hmac;
use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::Hash;
use crate::io;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/internal/fips140/pbkdf2/pbkdf2.go:19-21 divRoundUp
/// Divide `x+y-1` by `y`, rounding up if the result is not whole.
fn divRoundUp(x: int, y: int) -> int {
    // Go: return int((int64(x) + int64(y) - 1) / int64(y))
    return (x + y - 1) / y;
}

// go: sdk 1.25.5 crypto/internal/fips140/pbkdf2/pbkdf2.go:23-69 Key
/// `pbkdf2.Key(h, password, salt, iter, keyLength)` — derive a key.
pub fn Key(
    h: fn() -> Box<dyn Hash + Send + Sync>,
    password: string,
    salt: slice<byte>,
    iter: int,
    keyLength: int,
) -> (slice<byte>, error) {
    // Go: setServiceIndicator(salt, keyLength)
    setServiceIndicator(&salt, keyLength);

    // Go: if keyLength <= 0 { return nil, errors.New("pkbdf2: keyLength must be larger than 0") }
    if keyLength <= 0 {
        return (
            slice::__from_vec(Vec::new()),
            crate::errors::New("pkbdf2: keyLength must be larger than 0"),
        );
    }

    // Go: prf := hmac.New(h, []byte(password)); hmac.MarkAsUsedInKDF(prf)
    let pw: &[byte] = password.as_bytes();
    let mut prf = hmac::New(h, slice::__from_vec(pw.to_vec()));
    hmac::MarkAsUsedInKDF(&mut prf);
    // Go: hashLen := prf.Size(); numBlocks := divRoundUp(keyLength, hashLen)
    let hashLen = <hmac::HMAC as Hash>::Size(&prf);
    let numBlocks = divRoundUp(keyLength, hashLen);
    // Go: const maxBlocks = int64(1<<32 - 1)
    //     if keyLength+hashLen < keyLength || int64(numBlocks) > maxBlocks { … }
    let maxBlocks: i64 = (1i64 << 32) - 1;
    if keyLength + hashLen < keyLength || numBlocks > maxBlocks {
        return (
            slice::__from_vec(Vec::new()),
            crate::errors::New("pbkdf2: keyLength too long"),
        );
    }

    let hl = hashLen as usize;
    // Go: dk := make([]byte, 0, numBlocks*hashLen); U := make([]byte, hashLen)
    let mut dk: Vec<byte> = Vec::with_capacity((numBlocks as usize) * hl);
    let mut U: Vec<byte> = alloc::vec![0u8; hl];

    // Go: for block := 1; block <= numBlocks; block++ { … }
    //
    // For each block T_i = U_1 ^ U_2 ^ … ^ U_iter, where
    // U_1 = PRF(password, salt || uint(i)) and U_n = PRF(password, U_(n-1)).
    let mut block: int = 1;
    while block <= numBlocks {
        // Go: prf.Reset(); prf.Write(salt)
        <hmac::HMAC as Hash>::Reset(&mut prf);
        let _ = io::Writer::Write(&mut prf, salt.clone());
        // Go: buf[0..3] = big-endian block; prf.Write(buf[:4])
        let buf: [byte; 4] = [
            ((block >> 24) & 0xff) as byte,
            ((block >> 16) & 0xff) as byte,
            ((block >> 8) & 0xff) as byte,
            (block & 0xff) as byte,
        ];
        let _ = io::Writer::Write(&mut prf, slice::__from_vec(buf.to_vec()));
        // Go: dk = prf.Sum(dk)
        dk = prf.Sum(slice::__from_vec(dk)).__into_vec();
        // Go: T := dk[len(dk)-hashLen:]; copy(U, T)
        let tStart = dk.len() - hl;
        U[..hl].copy_from_slice(&dk[tStart..]);

        // Go: for n := 2; n <= iter; n++ { … U_n = PRF(password, U_(n-1)) … }
        let mut n: int = 2;
        while n <= iter {
            <hmac::HMAC as Hash>::Reset(&mut prf);
            let _ = io::Writer::Write(&mut prf, slice::__from_vec(U.clone()));
            // Go: U = U[:0]; U = prf.Sum(U)
            U = prf.Sum(slice::__from_vec(Vec::new())).__into_vec();
            // Go: for x := range U { T[x] ^= U[x] }
            let mut x: usize = 0;
            while x < U.len() {
                dk[tStart + x] ^= U[x];
                x += 1;
            }
            n += 1;
        }
        block += 1;
    }

    // Go: return dk[:keyLength], nil
    dk.truncate(keyLength as usize);
    return (slice::__from_vec(dk), crate::errors::nil);
}

// go: sdk 1.25.5 crypto/internal/fips140/pbkdf2/pbkdf2.go:71-88 setServiceIndicator
/// Record the SP 800-132 service-indicator decision for `salt` and
/// `keyLength`. The HMAC construction handles the hash-function
/// considerations; these are the two that remain.
///
/// Inert in goish: every branch calls `fips140.Record*Approved()`, which
/// the stub does not implement. Kept so the thresholds stay documented
/// where they apply.
fn setServiceIndicator(salt: &slice<byte>, keyLength: int) {
    // Go: if len(salt) < 128/8 { fips140.RecordNonApproved() }
    //
    // The randomly-generated portion of the salt shall be at least 128 bits.
    let _shortSalt = salt.Len() < 128 / 8;
    // Go: if keyLength < 112/8 { fips140.RecordNonApproved() }
    //
    // Per FIPS 140-3 IG C.M, key lengths below 112 bits are only allowed
    // for legacy use (verification only), which is not supported.
    let _shortKey = keyLength < 112 / 8;
    // Go: fips140.RecordApproved()
}
