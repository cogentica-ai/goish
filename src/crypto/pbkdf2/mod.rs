// crypto/pbkdf2 — PBKDF2 key derivation (RFC 8018 / PKCS #5 v2.1).
//
// Source files:
//   /nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/
//     crypto/pbkdf2/pbkdf2.go
//     crypto/internal/fips140/pbkdf2/pbkdf2.go  (inlined)
//
// Slim deviations:
//   * Hash factory is `fn() -> Box<dyn Hash>` instead of Go's
//     `func() H` generic.
//   * No FIPS service indicator (no `setServiceIndicator`).
//   * No FIPS-only key/salt minimum-length checks.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::hmac;
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::Hash;
use crate::io;
use crate::types::{byte, int};

// Go: fips140/pbkdf2/pbkdf2.go:19
//   func divRoundUp(x, y int) int {
//       return int((int64(x) + int64(y) - 1) / int64(y))
//   }
fn divRoundUp(x: int, y: int) -> int {
    let xl = x as i64;
    let yl = y as i64;
    ((xl + yl - 1) / yl) as int
}

// Go: pbkdf2.go:40 (and fips140/pbkdf2/pbkdf2.go:23)
//
//   func Key[Hash hash.Hash](h func() Hash, password string, salt []byte,
//                            iter, keyLength int) ([]byte, error)
pub fn Key(
    h: fn() -> Box<dyn Hash>,
    password: string,
    salt: slice<byte>,
    iter: int,
    keyLength: int,
) -> (slice<byte>, error) {
    // Go: if keyLength <= 0 { return nil, errors.New("pkbdf2: keyLength must be larger than 0") }
    // (Spelling matches Go source — "pkbdf2", not "pbkdf2".)
    if keyLength <= 0 {
        return (
            slice::__from_vec(Vec::new()),
            errors::New(string::from_static(
                "pkbdf2: keyLength must be larger than 0",
            )),
        );
    }

    // Go: prf := hmac.New(h, []byte(password))
    let pw_bytes: Vec<byte> = password.as_bytes().to_vec();
    let mut prf = hmac::New(h, slice::__from_vec(pw_bytes));
    // Go: hashLen := prf.Size()
    let hashLen = prf.Size();
    // Go: numBlocks := divRoundUp(keyLength, hashLen)
    let numBlocks = divRoundUp(keyLength, hashLen);
    // Go: const maxBlocks = int64(1<<32 - 1)
    const MAX_BLOCKS: i64 = (1i64 << 32) - 1;
    // Go: if keyLength+hashLen < keyLength || int64(numBlocks) > maxBlocks { return nil, errors.New("pbkdf2: keyLength too long") }
    let overflow = (keyLength as i64).checked_add(hashLen as i64).is_none();
    if overflow || (numBlocks as i64) > MAX_BLOCKS {
        return (
            slice::__from_vec(Vec::new()),
            errors::New(string::from_static("pbkdf2: keyLength too long")),
        );
    }

    // Go: var buf [4]byte
    let mut buf: [byte; 4] = [0; 4];
    // Go: dk := make([]byte, 0, numBlocks*hashLen)
    let mut dk: Vec<byte> = Vec::with_capacity((numBlocks * hashLen) as usize);
    // Go: U := make([]byte, hashLen)
    let mut U: Vec<byte> = alloc::vec![0; hashLen as usize];

    // Go: for block := 1; block <= numBlocks; block++ { ... }
    let mut block: int = 1;
    while block <= numBlocks {
        // Go: prf.Reset(); prf.Write(salt)
        prf.Reset();
        let _ = io::Writer::Write(&mut prf, salt.clone());
        // Go: buf[0] = byte(block >> 24); buf[1] = ...; buf[2] = ...; buf[3] = byte(block)
        let b32 = block as u32;
        buf[0] = (b32 >> 24) as byte;
        buf[1] = (b32 >> 16) as byte;
        buf[2] = (b32 >> 8) as byte;
        buf[3] = b32 as byte;
        // Go: prf.Write(buf[:4])
        let _ = io::Writer::Write(
            &mut prf,
            slice::__from_vec(buf.to_vec()),
        );
        // Go: dk = prf.Sum(dk)
        let dk_slice: slice<byte> = slice::__from_vec(dk);
        let summed = prf.Sum(dk_slice);
        dk = summed.__into_vec();
        // Go: T := dk[len(dk)-hashLen:]
        let dk_len_now = dk.len();
        let t_off = dk_len_now - hashLen as usize;
        // Go: copy(U, T)
        U.copy_from_slice(&dk[t_off..dk_len_now]);

        // Go: for n := 2; n <= iter; n++ { ... }
        let mut n: int = 2;
        while n <= iter {
            // Go: prf.Reset(); prf.Write(U)
            prf.Reset();
            let _ = io::Writer::Write(
                &mut prf,
                slice::__from_vec(U.clone()),
            );
            // Go: U = U[:0]; U = prf.Sum(U)
            U.clear();
            let u_slice: slice<byte> = slice::__from_vec(U);
            let summed_u = prf.Sum(u_slice);
            U = summed_u.__into_vec();
            // Go: for x := range U { T[x] ^= U[x] }
            for x in 0..U.len() {
                dk[t_off + x] ^= U[x];
            }
            n += 1;
        }
        block += 1;
    }

    // Go: return dk[:keyLength], nil
    dk.truncate(keyLength as usize);
    (slice::__from_vec(dk), nil)
}
