// tls_padding_oracle_smoke — that a bad MAC and bad padding are
// indistinguishable.
//
// `record.rs` is the invented TLS 1.2 CBC record layer the client
// handshake still runs on (ROADMAP.md §1). Its decrypt path returned
// THREE different errors — "tls: bad padding length", "tls: bad
// padding bytes", "tls: MAC verification failed" — and left the padding
// loop on the first byte that did not match.
//
// That is a padding oracle in both halves: a distinguishable answer and
// a shorter one. Go's extractPadding says why in its own comment —
// "an attacker that could distinguish MAC failures from padding
// failures could mount an attack similar to POODLE in SSL 3.0" — and
// Go folds the two results together deliberately:
//
//     macAndPaddingGood := ConstantTimeCompare(localMAC, remoteMAC) &
//                          int(paddingGood)
//     if macAndPaddingGood != 1 { return nil, 0, alertBadRecordMAC }
//
// Measured against the commit before the fix, these same four
// corruptions returned "bad padding bytes" for the padding case and
// "MAC verification failed" for the other three. They now all return
// "tls: bad record MAC", which is what this file exists to keep true.
//
// The corruptions are chosen for WHERE CBC puts the damage: garbling
// the last ciphertext block garbles the padding, garbling a middle
// block garbles the MAC while leaving the padding intact, and a wrong
// sequence number fails the MAC with the ciphertext untouched.
//
// What this does NOT establish is constant TIME. `extract_padding` is
// Go's, examining a fixed 256 bytes rather than stopping at the claimed
// length, but the MAC is still computed over a variable-length payload,
// which is the other half of Lucky13. conn.rs is the anchored port that
// should replace this file.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::crypto::tls::record;
use goish::fmt;
use goish::gostring::string;
use goish::types::{byte, int};

const GO: [&str; 5] = [
    "intact                 n=18 err=<nil>",
    "corrupt-padding        n=0 err=tls: bad record MAC",
    "corrupt-mac            n=0 err=tls: bad record MAC",
    "corrupt-iv             n=0 err=tls: bad record MAC",
    "wrong-seq              n=0 err=tls: bad record MAC",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let dir = record::DirectionKeys { mac_key: [7u8; 20], enc_key: [9u8; 16], iv: [3u8; 16] };
    let pt: Vec<byte> = b"hello record layer".to_vec();
    let (ct, err) = record::encrypt_record(22, 0, &dir, &pt);
    if !err.IsNil() {
        fmt::Printf!("[!!] encrypt err=%v\n", err);
        return;
    }
    let base = ct.__into_vec();

    // Intact.
    let (got, e) = record::decrypt_record(22, 0, &dir, &base[5..]);
    chk(&mut ln, &fmt::Sprintf!("%-22s n=%d err=%v", "intact", got.Len() as int, e));

    // Corrupt the LAST ciphertext block — this is what garbles the
    // padding after CBC decryption.
    let mut v = base.clone();
    let n = v.len();
    v[n - 1] ^= 0xff;
    let (got, e) = record::decrypt_record(22, 0, &dir, &v[5..]);
    chk(&mut ln, &fmt::Sprintf!("%-22s n=%d err=%v", "corrupt-padding", got.Len() as int, e));

    // Corrupt a middle block — garbles the MAC, padding stays valid.
    let mut v = base.clone();
    let mid = 5 + 16 + 16;
    v[mid] ^= 0xff;
    let (got, e) = record::decrypt_record(22, 0, &dir, &v[5..]);
    chk(&mut ln, &fmt::Sprintf!("%-22s n=%d err=%v", "corrupt-mac", got.Len() as int, e));

    // Corrupt the IV — garbles the first plaintext block.
    let mut v = base.clone();
    v[5] ^= 0xff;
    let (got, e) = record::decrypt_record(22, 0, &dir, &v[5..]);
    chk(&mut ln, &fmt::Sprintf!("%-22s n=%d err=%v", "corrupt-iv", got.Len() as int, e));

    // Wrong sequence number — MAC fails, padding is fine.
    let (got, e) = record::decrypt_record(22, 99, &dir, &base[5..]);
    chk(&mut ln, &fmt::Sprintf!("%-22s n=%d err=%v", "wrong-seq", got.Len() as int, e));
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
