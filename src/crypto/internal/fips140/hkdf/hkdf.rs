// go: file crypto/internal/fips140/hkdf/hkdf.go decls: Extract, Expand, Key
//
// crypto/internal/fips140/hkdf — HKDF (RFC 5869). The public crypto/hkdf
// package is a thin wrapper over this; the length validation and the
// FIPS-140-only checks live there, not here.
//
// Deviations from hkdf[go] @ Go 1.25.5:
//
//   * The hash factory is `impl IntoHashFunc` rather
//     than Go's `func() H` generic, matching `hmac::New`.
//   * `fips140.RecordNonApproved()` for short secrets is dropped: goish's
//     fips140 stub has no service indicator.
//   * cast[go]'s `init` is not ported (no CAST registry); the vector it
//     checks is covered by examples/crypto_kdf_smoke.rs.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::internal::fips140::hmac;
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::{Hash, IntoHashFunc};
use crate::io;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/internal/fips140/hkdf/hkdf.go:13-25 Extract
/// `hkdf.Extract(h, secret, salt)` — the RFC 5869 extract step.
pub fn Extract(
    h: impl IntoHashFunc,
    secret: slice<byte>,
    salt: slice<byte>,
) -> slice<byte> {
    let h = h.into_hash_func();
    // Go: if len(secret) < 112/8 { fips140.RecordNonApproved() } — no-op here.
    // Go: if salt == nil { salt = make([]byte, h().Size()) }
    let salt = {
        let raw: &[byte] = &salt;
        if raw.is_empty() {
            let size = h.Call().Size() as usize;
            slice::__from_vec(alloc::vec![0u8; size])
        } else {
            salt
        }
    };
    // Go: extractor := hmac.New(h, salt); hmac.MarkAsUsedInKDF(extractor)
    let mut extractor = hmac::New(h, salt);
    hmac::MarkAsUsedInKDF(&mut extractor);
    // Go: extractor.Write(secret)
    let _ = io::Writer::Write(&mut extractor, secret);
    // Go: return extractor.Sum(nil)
    return extractor.Sum(slice::__from_vec(Vec::new()));
}

// go: sdk 1.25.5 crypto/internal/fips140/hkdf/hkdf.go:27-52 Expand
/// `hkdf.Expand(h, pseudorandomKey, info, keyLen)` — the RFC 5869 expand
/// step. The caller is responsible for bounding `keyLen`; Go's public
/// wrapper does that.
pub fn Expand(
    h: impl IntoHashFunc,
    pseudorandomKey: slice<byte>,
    info: string,
    keyLen: int,
) -> slice<byte> {
    let h = h.into_hash_func();
    // Go: out := make([]byte, 0, keyLen)
    let key_len = keyLen as usize;
    let mut out: Vec<byte> = Vec::with_capacity(key_len);
    // Go: expander := hmac.New(h, pseudorandomKey); hmac.MarkAsUsedInKDF(expander)
    let mut expander = hmac::New(h, pseudorandomKey);
    hmac::MarkAsUsedInKDF(&mut expander);
    // Go: var counter uint8; var buf []byte
    let mut counter: u8 = 0;
    let mut buf: Vec<byte> = Vec::new();

    // Go: for len(out) < keyLen { … }
    while out.len() < key_len {
        // Go: counter++; if counter == 0 { panic("hkdf: counter overflow") }
        counter = counter.wrapping_add(1);
        if counter == 0 {
            panic!("hkdf: counter overflow");
        }
        // Go: if counter > 1 { expander.Reset() }
        //
        // This is the call that takes HMAC's FIPS 198-1 §6 cached-state
        // path once the inner hash is marshalable.
        if counter > 1 {
            <hmac::HMAC as Hash>::Reset(&mut expander);
        }
        // Go: expander.Write(buf)
        let _ = io::Writer::Write(&mut expander, slice::__from_vec(buf.clone()));
        // Go: expander.Write([]byte(info))
        let info_raw: &[byte] = info.as_bytes();
        let _ = io::Writer::Write(&mut expander, slice::__from_vec(info_raw.to_vec()));
        // Go: expander.Write([]byte{counter})
        let _ = io::Writer::Write(&mut expander, slice::__from_vec(alloc::vec![counter]));
        // Go: buf = expander.Sum(buf[:0])
        buf.clear();
        let summed = expander.Sum(slice::__from_vec(buf));
        buf = summed.__into_vec();
        // Go: remain := keyLen - len(out); remain = min(remain, len(buf))
        let mut remain = key_len - out.len();
        if buf.len() < remain {
            remain = buf.len();
        }
        // Go: out = append(out, buf[:remain]...)
        out.extend_from_slice(&buf[..remain]);
    }

    // Go: return out
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 crypto/internal/fips140/hkdf/hkdf.go:54-57 Key
/// `hkdf.Key(h, secret, salt, info, keyLen)` — Extract then Expand.
pub fn Key(
    h: impl IntoHashFunc,
    secret: slice<byte>,
    salt: slice<byte>,
    info: string,
    keyLen: int,
) -> slice<byte> {
    let h = h.into_hash_func();
    // Go: prk := Extract(h, secret, salt); return Expand(h, prk, info, keyLen)
    let prk = Extract(h.clone(), secret, salt);
    return Expand(h, prk, info, keyLen);
}
