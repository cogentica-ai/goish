// crypto/hkdf — HKDF Extract / Expand / Key (RFC 5869).
//
// Source files:
//   go1.25.5/src/
//     crypto/hkdf/hkdf.go
//     crypto/internal/fips140/hkdf/hkdf.go  (inlined — Extract/Expand bodies)
//
// Slim deviations:
//   * Hash factory is `fn() -> Box<dyn Hash + Send + Sync>` instead of Go's
//     `func() H` generic, matching the convention already established
//     by `crypto::hmac::New`.
//   * No `crypto/internal/fips140hash.UnwrapNew` and no
//     `fips140only.Enabled` checks — goish has no FIPS service
//     indicator.
//   * `MarkAsUsedInKDF(extractor)` is omitted (no-op in goish).

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

// Go: hkdf.go:27 (and fips140/hkdf/hkdf.go:13)
//
//   func Extract[H hash.Hash](h func() H, secret, salt []byte) ([]byte, error)
//
// Slim: H is `Box<dyn Hash>`; FIPS check elided.
pub fn Extract(
    h: fn() -> Box<dyn Hash + Send + Sync>,
    secret: slice<byte>,
    salt: slice<byte>,
) -> (slice<byte>, error) {
    // Go: if salt == nil { salt = make([]byte, h().Size()) }
    let salt = {
        let raw: &[byte] = &salt;
        if raw.is_empty() {
            // Go: make([]byte, h().Size()) — zero-filled to hash size.
            let size = h().Size() as usize;
            slice::__from_vec(alloc::vec![0u8; size])
        } else {
            salt
        }
    };
    // Go: extractor := hmac.New(h, salt)
    let mut extractor = hmac::New(h, salt);
    // Go: extractor.Write(secret)
    let _ = io::Writer::Write(&mut extractor, secret);
    // Go: return extractor.Sum(nil), nil
    let empty: slice<byte> = slice::__from_vec(Vec::new());
    (extractor.Sum(empty), nil)
}

// Go: hkdf.go:42 (and fips140/hkdf/hkdf.go:27)
//
//   func Expand[H hash.Hash](h func() H, pseudorandomKey []byte,
//                            info string, keyLength int) ([]byte, error)
//
// Slim: H is `Box<dyn Hash>`; FIPS check elided.
pub fn Expand(
    h: fn() -> Box<dyn Hash + Send + Sync>,
    pseudorandomKey: slice<byte>,
    info: string,
    keyLength: int,
) -> (slice<byte>, error) {
    // Go: limit := fh().Size() * 255
    //     if keyLength > limit { return nil, errors.New("hkdf: requested key length too large") }
    let limit = (h().Size() as i64) * 255;
    if keyLength as i64 > limit {
        return (
            slice::__from_vec(Vec::new()),
            errors::New(string::from_static("hkdf: requested key length too large")),
        );
    }

    // Go: out := make([]byte, 0, keyLen)
    let mut out: Vec<byte> = Vec::with_capacity(keyLength as usize);
    // Go: expander := hmac.New(h, pseudorandomKey)
    let mut expander = hmac::New(h, pseudorandomKey);
    // Go: var counter uint8; var buf []byte
    let mut counter: u8 = 0;
    let mut buf: Vec<byte> = Vec::new();

    // Go: for len(out) < keyLen { ... }
    let key_len = keyLength as usize;
    while out.len() < key_len {
        // Go: counter++; if counter == 0 { panic("hkdf: counter overflow") }
        counter = counter.wrapping_add(1);
        if counter == 0 {
            panic!("hkdf: counter overflow");
        }
        // Go: if counter > 1 { expander.Reset() }
        if counter > 1 {
            expander.Reset();
        }
        // Go: expander.Write(buf)
        let _ = io::Writer::Write(
            &mut expander,
            slice::__from_vec(buf.clone()),
        );
        // Go: expander.Write([]byte(info))
        let info_raw: &[byte] = info.as_bytes();
        let _ = io::Writer::Write(
            &mut expander,
            slice::__from_vec(info_raw.to_vec()),
        );
        // Go: expander.Write([]byte{counter})
        let _ = io::Writer::Write(
            &mut expander,
            slice::__from_vec(alloc::vec![counter]),
        );
        // Go: buf = expander.Sum(buf[:0])
        buf.clear();
        let buf_slice: slice<byte> = slice::__from_vec(buf);
        let summed = expander.Sum(buf_slice);
        buf = summed.__into_vec();
        // Go: remain := keyLen - len(out)
        // Go: remain = min(remain, len(buf))
        let mut remain = key_len - out.len();
        if buf.len() < remain {
            remain = buf.len();
        }
        // Go: out = append(out, buf[:remain]...)
        out.extend_from_slice(&buf[..remain]);
    }

    (slice::__from_vec(out), nil)
}

// Go: hkdf.go:59 (and fips140/hkdf/hkdf.go:54)
//
//   func Key[Hash hash.Hash](h func() Hash, secret, salt []byte,
//                            info string, keyLength int) ([]byte, error)
//
// Slim: H is `Box<dyn Hash>`; FIPS check elided. Inlines `Extract`
// followed by `Expand`.
pub fn Key(
    h: fn() -> Box<dyn Hash + Send + Sync>,
    secret: slice<byte>,
    salt: slice<byte>,
    info: string,
    keyLength: int,
) -> (slice<byte>, error) {
    // Same cap check as Expand — Go performs it on `Key` before
    // calling Extract, so we mirror that ordering.
    let limit = (h().Size() as i64) * 255;
    if keyLength as i64 > limit {
        return (
            slice::__from_vec(Vec::new()),
            errors::New(string::from_static("hkdf: requested key length too large")),
        );
    }
    // Go: prk := Extract(h, secret, salt)
    let (prk, e) = Extract(h, secret, salt);
    if !e.IsNil() {
        return (slice::__from_vec(Vec::new()), e);
    }
    // Go: return Expand(h, prk, info, keyLen)
    Expand(h, prk, info, keyLength)
}
