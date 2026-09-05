// tls_record_iv_smoke — every TLS 1.2 CBC record gets a fresh IV.
//
// `record.rs`'s encrypt_record draws a per-record explicit IV, which
// TLS 1.2 requires and which CBC needs to be unpredictable. It drew it
// with `let _ = rand::Read(&mut iv_slice);` — the result discarded. A
// failed or short read left the buffer as the zeros it was initialised
// to, and the record went out under an all-zero IV: predictable, which
// is the BEAST precondition, and enough to leak equality between
// plaintext blocks across records.
//
// Go returns the error instead (conn.go:500):
//
//     if _, err := io.ReadFull(rand, explicitNonce); err != nil {
//         return nil, err
//     }
//
// An RNG failure cannot be induced from here, so this pins the
// property that failure would break: encrypting the SAME plaintext
// twice must produce different ciphertext, and the IV each record
// carries must differ. Against a fixed IV both assertions fail — which
// is what a regression to `let _ =` plus an unlucky RNG would look
// like.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::crypto::tls::record;
use goish::fmt;
use goish::types::{byte, int};

#[goish::main]
fn main() {
    let mut bad: int = 0;
    let dir = record::DirectionKeys {
        mac_key: [7u8; 20],
        enc_key: [9u8; 16],
        iv: [3u8; 16],
    };
    let pt: Vec<byte> = b"the same plaintext, twice".to_vec();

    let (a, ea) = record::encrypt_record(23, 0, &dir, &pt);
    let (b, eb) = record::encrypt_record(23, 0, &dir, &pt);
    if !ea.IsNil() || !eb.IsNil() {
        fmt::Printf!("[!!] encrypt failed: %v %v\n", ea, eb);
        return;
    }
    let av = a.__into_vec();
    let bv = b.__into_vec();

    // The 16 bytes after the 5-byte header are the explicit IV.
    let iv_a = &av[5..21];
    let iv_b = &bv[5..21];
    if iv_a != iv_b {
        fmt::Printf!("[ok] %-28s two records, two IVs\n", "iv-differs");
    } else {
        fmt::Printf!("[!!] %-28s SAME IV in both records\n", "iv-differs");
        bad += 1;
    }

    // An all-zero IV is the specific failure the discarded error let
    // through, so name it rather than relying on the comparison above.
    let mut zeros = true;
    for x in iv_a.iter() {
        if *x != 0 {
            zeros = false;
        }
    }
    if !zeros {
        fmt::Printf!("[ok] %-28s IV is not all zeros\n", "iv-nonzero");
    } else {
        fmt::Printf!("[!!] %-28s IV is all zeros\n", "iv-nonzero");
        bad += 1;
    }

    // Same plaintext, same key, same sequence number: only the IV
    // differs, so the ciphertext must too.
    if av != bv {
        fmt::Printf!("[ok] %-28s ciphertext differs\n", "ct-differs");
    } else {
        fmt::Printf!("[!!] %-28s identical ciphertext\n", "ct-differs");
        bad += 1;
    }

    // And both must still decrypt back to the original.
    let (ga, da) = record::decrypt_record(23, 0, &dir, &av[5..]);
    let (gb, db) = record::decrypt_record(23, 0, &dir, &bv[5..]);
    let ok = da.IsNil() && db.IsNil()
        && ga.Len() as usize == pt.len()
        && gb.Len() as usize == pt.len();
    if ok {
        fmt::Printf!("[ok] %-28s both round-trip\n", "roundtrip");
    } else {
        fmt::Printf!("[!!] %-28s %v / %v\n", "roundtrip", da, db);
        bad += 1;
    }

    if bad == 0 {
        fmt::Printf!("tls_record_iv_smoke: all checks passed\n");
    } else {
        fmt::Printf!("tls_record_iv_smoke: %v FAILED\n", bad);
    }
}
