// tls_record_overflow_smoke — the record-length bound the invented
// record layer did not have.
//
// Go's readRecord (crypto/tls/conn.go:673) refuses a record longer than
// maxCiphertext (16384+2048) with alertRecordOverflow, and a tighter
// maxCiphertextTLS13 (16384+256) once the version is known to be TLS
// 1.3. goish's `record.rs` — the invented layer the client handshake
// still runs on, see ROADMAP.md §1 — read a u16 length and allocated
// that many bytes with NO bound. Every record from 18433 to 65535 was
// accepted and buffered where Go sends an alert and fails the
// connection.
//
// A u16 caps the damage at 64 KiB, so this is a conformance defect
// rather than a memory one: a peer decided how much a goish TLS client
// allocated and parsed on the handshake path, and nothing said so.
// Measured before the fix, all five lengths below returned the full
// payload and a nil error.
//
// The boundary is the assertion: 18432 is accepted and 18433 is not,
// which is Go's `n > maxCiphertext` and not an off-by-one either side.
//
// The second half pins the OTHER bound Go applies, on the DECRYPTED
// bytes (conn.go:82): the ciphertext cap leaves ~2 KiB of slack, so a
// record of 18432 ciphertext bytes decrypts to as much as 18395 of
// plaintext, and maxPlaintext is 16384. That gap was also unchecked:
// before the fix a 17000-byte plaintext round-tripped whole. The
// boundary is exact — 16384 back, 16385 refused.
//
// The TLS 1.3 bound is NOT enforced here. `read_record` is handed a
// bare io::Reader and has no connection state to know the version from;
// `conn.rs`'s readRecordOrCCS — the real port, which this file is meant
// to be replaced by — does the version-dependent check properly. That
// is a divergence this smoke deliberately does not hide.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::bytes;
use goish::crypto::tls::record;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::types::{byte, int};

const GO: [&str; 8] = [
    "len=16384  type=22 got=16384 err=<nil>",
    "len=18432  type=22 got=18432 err=<nil>",
    "len=18433  type=22 got=0 err=tls: oversized record received",
    "len=40000  type=22 got=0 err=tls: oversized record received",
    "len=65535  type=22 got=0 err=tls: oversized record received",
    "plaintext=16384  ct=16437 back=16384 err=<nil>",
    "plaintext=16385  ct=16437 back=0 err=tls: oversized record received",
    "plaintext=17000  ct=17045 back=0 err=tls: oversized record received",
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

// A record header claiming `n` payload bytes, followed by that many.
fn rec(n: usize) -> Vec<byte> {
    let mut v: Vec<byte> = alloc::vec![0x16, 0x03, 0x03];
    v.push(((n >> 8) & 0xff) as u8);
    v.push((n & 0xff) as u8);
    v.extend(alloc::vec![0x41u8; n]);
    return v;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    for n in [16384usize, 18432, 18433, 40000, 65535].iter() {
        let mut r = bytes::NewReader(slice::__from_vec(rec(*n)));
        let (ct, payload, err) = goish::crypto::tls::record::read_record(&mut r);
        chk(&mut ln, &fmt::Sprintf!("len=%-6d type=%d got=%d err=%v",
            *n as int, ct as int, payload.Len() as int, err));
    }

    let dir = record::DirectionKeys {
        mac_key: [7u8; 20],
        enc_key: [9u8; 16],
        iv: [3u8; 16],
    };
    for n in [16384usize, 16385, 17000].iter() {
        let pt: Vec<byte> = alloc::vec![0x41u8; *n];
        let (ct, err) = record::encrypt_record(22, 0, &dir, &pt);
        if !err.IsNil() {
            chk(&mut ln, &fmt::Sprintf!("plaintext=%-6d encrypt-err=%v", *n as int, err));
            continue;
        }
        let ctv = ct.__into_vec();
        let (got, derr) = record::decrypt_record(22, 0, &dir, &ctv[5..]);
        chk(&mut ln, &fmt::Sprintf!("plaintext=%-6d ct=%d back=%d err=%v",
            *n as int, ctv.len() as int, got.Len() as int, derr));
    }

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
