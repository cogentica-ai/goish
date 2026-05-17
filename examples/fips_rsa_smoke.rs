// fips_rsa_smoke — exercise crypto/internal/fips140/rsa: the FIPS-
// internal RSA key types, key generation, and the raw constant-time
// encrypt/decrypt built on the constant-time bigmod.
//
// The bulk of testing uses a HARDCODED, openssl-generated 512-bit key
// (debug-build RSA keygen is slow), with exactly one GenerateKey at a
// small size to prove key generation works end-to-end.
//
// Coverage:
//   1. NewPrivateKey from known (N, e, d, P, Q) — computes + validates
//      the CRT values; resulting PublicKey.Size() == 64 (512-bit N).
//   2. NewPrivateKeyWithPrecomputation from full known components
//      (N, e, d, P, Q, dP, dQ, qInv) — validates the precomputed CRT.
//   3. encrypt -> decrypt (CRT path) round-trips a plaintext block.
//   4. encrypt cross-checked against math/big modexp (m^e mod N).
//   5. decrypt with the m^e check (DecryptWithCheck) round-trips.
//   6. DecryptWithoutCheck round-trips and equals DecryptWithCheck.
//   7. decrypt rejects an out-of-range ciphertext (c >= N).
//   8. NewPrivateKey rejects a bad modulus (even N).
//   9. NewPrivateKeyWithoutCRT builds a usable CRT-less key; its
//      decrypt (legacy Exp path) round-trips.
//  10. GenerateKey at a small bit size produces a valid key whose
//      encrypt/decrypt round-trips.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::internal::fips140::rsa;
use goish::crypto::rand::RandReader;
use goish::math::big;
use goish::types::byte;
use goish::{slice, syscall, Println};

const KB: usize = 1024;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

// ─── known 512-bit RSA key (openssl genrsa 512) ───────────────────────

const N: &[u8] = &[
    0xbf, 0x97, 0x52, 0xdb, 0x54, 0x93, 0x8b, 0xd8, 0x6a, 0x57, 0x4f, 0xd5, 0xdf, 0x6e, 0xf9,
    0x96, 0xcc, 0xdd, 0x08, 0x8d, 0x90, 0x50, 0xfd, 0x4f, 0x18, 0x7a, 0xcf, 0xb0, 0x4a, 0x91,
    0x6d, 0xba, 0x82, 0xad, 0xa0, 0x44, 0xa4, 0x2c, 0xa4, 0xd5, 0x9d, 0xd1, 0xdb, 0xbd, 0x03,
    0x01, 0x29, 0x83, 0x0e, 0x90, 0x49, 0xee, 0x45, 0x61, 0x3a, 0x01, 0xc7, 0xa3, 0x46, 0x24,
    0x70, 0xc1, 0x17, 0x59,
];
const D: &[u8] = &[
    0x83, 0x1d, 0x5a, 0x14, 0xc3, 0x92, 0x9d, 0xd7, 0xa3, 0x1e, 0xd1, 0x81, 0xfa, 0x00, 0x86,
    0x4a, 0x4f, 0x34, 0xcc, 0xcf, 0xa4, 0x7d, 0xe8, 0x7c, 0xa2, 0xb2, 0x19, 0x43, 0xfa, 0x24,
    0x00, 0x44, 0xbe, 0x5d, 0x26, 0x6c, 0x29, 0x36, 0x81, 0xe4, 0xa7, 0x9c, 0x17, 0x05, 0x6b,
    0xf0, 0x44, 0x3e, 0x0d, 0xfd, 0x28, 0xca, 0x3a, 0xf5, 0x76, 0xbb, 0x2a, 0xa2, 0xff, 0x44,
    0x0e, 0x34, 0x90, 0x01,
];
const P: &[u8] = &[
    0xde, 0x57, 0x3b, 0x62, 0xb3, 0x57, 0x5a, 0xf9, 0x98, 0x2d, 0xc8, 0x58, 0x60, 0xc3, 0xd8,
    0xf3, 0x23, 0x93, 0x98, 0x07, 0x14, 0x7b, 0xd3, 0xe7, 0x56, 0xf5, 0x90, 0x9f, 0x99, 0xab,
    0xac, 0x59,
];
const Q: &[u8] = &[
    0xdc, 0x98, 0x65, 0x5a, 0xc4, 0x9a, 0xba, 0xfb, 0xd4, 0x51, 0xfe, 0x09, 0x70, 0x49, 0x1e,
    0x1d, 0x21, 0x63, 0x54, 0x89, 0x57, 0xc7, 0xb8, 0x2d, 0xf4, 0x12, 0xe6, 0x48, 0x05, 0x07,
    0x63, 0x01,
];
const DP: &[u8] = &[
    0x9e, 0xb3, 0xcf, 0x3c, 0xbd, 0x5c, 0x5e, 0x20, 0x88, 0x62, 0x2d, 0x7d, 0xff, 0xdb, 0xeb,
    0x70, 0x69, 0x75, 0x81, 0x6f, 0x94, 0x4c, 0x6a, 0xcd, 0xd7, 0x01, 0x43, 0x30, 0xd8, 0xa4,
    0x74, 0x49,
];
const DQ: &[u8] = &[
    0x15, 0xab, 0x8a, 0xd9, 0x5d, 0xd2, 0xed, 0x67, 0x6b, 0xb6, 0x1a, 0x44, 0x87, 0x19, 0x47,
    0xb2, 0x08, 0xe3, 0x9f, 0x1c, 0x56, 0xd9, 0x31, 0xc8, 0xa1, 0xdf, 0x71, 0x6b, 0xc5, 0xc2,
    0xb2, 0x01,
];
const QINV: &[u8] = &[
    0x73, 0xb8, 0x2d, 0xc5, 0xc9, 0xb5, 0xc3, 0xe0, 0x99, 0x57, 0x69, 0x4a, 0xac, 0x66, 0xe3,
    0x43, 0x02, 0x7a, 0xb3, 0xb5, 0x2c, 0x45, 0x37, 0x96, 0x1f, 0x11, 0x10, 0x85, 0x1d, 0x8b,
    0x66, 0x32,
];
const E: i64 = 65537;

// A 512-bit-minus-a-bit plaintext block (< N), used for round-trips.
const MSG: &[u8] = &[
    0x42, 0x13, 0x37, 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
    0x1b, 0x1c,
];

fn from_bytes(b: &[u8]) -> goish::slice<byte> {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(b.len());
    for &x in b {
        v.push(x);
    }
    slice::__from_vec(v)
}

// Compare two goish slice<byte> for equality, ignoring leading zeroes.
fn slice_eq_trim(a: &goish::slice<byte>, b: &goish::slice<byte>) -> bool {
    let av = trim_leading(a);
    let bv = trim_leading(b);
    if av.len() != bv.len() {
        return false;
    }
    for i in 0..av.len() {
        if av[i] != bv[i] {
            return false;
        }
    }
    true
}

fn trim_leading(s: &goish::slice<byte>) -> alloc::vec::Vec<u8> {
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let n = s.Len();
    let mut started = false;
    let mut i: goish::int = 0;
    while i < n {
        let x = s[i];
        if x != 0 {
            started = true;
        }
        if started {
            v.push(x);
        }
        i += 1;
    }
    v
}

fn write_result(idx: u8, label: &[u8], pass: bool) {
    syscall::Write(syscall::STDOUT, b"[".as_ptr(), 1);
    let d2 = b'0' + (idx % 10);
    if idx >= 10 {
        let d1 = b'0' + (idx / 10);
        let buf = [d1, d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    } else {
        let buf = [b' ', d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    }
    syscall::Write(syscall::STDOUT, b"] ".as_ptr(), 2);
    syscall::Write(syscall::STDOUT, label.as_ptr(), label.len());
    if pass {
        syscall::Write(syscall::STDOUT, b" PASS\n".as_ptr(), 6);
    } else {
        syscall::Write(syscall::STDOUT, b" FAIL\n".as_ptr(), 6);
    }
}

// big::Int from raw big-endian bytes.
fn big_from(b: &[u8]) -> big::Int {
    let mut x = big::Int::new();
    x.SetBytes(from_bytes(b));
    x
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * KB), || {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run_tests() {
    test_1_new_private_key();
    test_2_new_with_precomputation();
    test_3_encrypt_decrypt_roundtrip();
    test_4_encrypt_vs_big();
    test_5_decrypt_with_check();
    test_6_decrypt_without_check();
    test_7_decrypt_out_of_range();
    test_8_new_private_key_bad_modulus();
    test_9_without_crt();
    test_10_generate_key();
}

// Build the hardcoded CRT key via NewPrivateKey (re-derives dP/dQ/qInv).
fn mk_key() -> rsa::PrivateKey {
    let (k, e) = rsa::NewPrivateKey(
        from_bytes(N),
        E,
        from_bytes(D),
        from_bytes(P),
        from_bytes(Q),
    );
    if !e.IsNil() {
        panic!("NewPrivateKey failed");
    }
    k
}

fn test_1_new_private_key() {
    let (k, e) = rsa::NewPrivateKey(
        from_bytes(N),
        E,
        from_bytes(D),
        from_bytes(P),
        from_bytes(Q),
    );
    let ok = e.IsNil() && k.PublicKey().Size() == 64 && k.pub_.E == E && k.has_crt;
    write_result(1, b"NewPrivateKey + Size         ", ok);
    if !ok {
        fail();
    }
}

fn test_2_new_with_precomputation() {
    let (k, e) = rsa::NewPrivateKeyWithPrecomputation(
        from_bytes(N),
        E,
        from_bytes(D),
        from_bytes(P),
        from_bytes(Q),
        from_bytes(DP),
        from_bytes(DQ),
        from_bytes(QINV),
    );
    let ok = e.IsNil() && k.PublicKey().Size() == 64 && k.has_crt;
    write_result(2, b"NewPrivateKeyWithPrecomp     ", ok);
    if !ok {
        fail();
    }
}

fn test_3_encrypt_decrypt_roundtrip() {
    let k = mk_key();
    let pubk = k.PublicKey();
    let (ct, e1) = rsa::encrypt(&pubk, from_bytes(MSG));
    let (pt, e2) = rsa::decrypt(&k, ct, false);
    let ok = e1.IsNil() && e2.IsNil() && slice_eq_trim(&pt, &from_bytes(MSG));
    write_result(3, b"encrypt -> decrypt (CRT)     ", ok);
    if !ok {
        fail();
    }
}

fn test_4_encrypt_vs_big() {
    let k = mk_key();
    let pubk = k.PublicKey();
    let (ct, e1) = rsa::encrypt(&pubk, from_bytes(MSG));
    // big::Int reference: m^e mod N.
    let ibase = big_from(MSG);
    let mut iexp = big::Int::new();
    iexp.SetUint64(E as u64);
    let imod = big_from(N);
    let mut want = big::Int::new();
    want.Exp(&ibase, &iexp, &imod);
    let ok = e1.IsNil() && slice_eq_trim(&ct, &want.Bytes());
    write_result(4, b"encrypt vs big::Int modexp   ", ok);
    if !ok {
        fail();
    }
}

fn test_5_decrypt_with_check() {
    let k = mk_key();
    let pubk = k.PublicKey();
    let (ct, _) = rsa::encrypt(&pubk, from_bytes(MSG));
    let (pt, e) = rsa::DecryptWithCheck(&k, ct);
    let ok = e.IsNil() && slice_eq_trim(&pt, &from_bytes(MSG));
    write_result(5, b"DecryptWithCheck             ", ok);
    if !ok {
        fail();
    }
}

fn test_6_decrypt_without_check() {
    let k = mk_key();
    let pubk = k.PublicKey();
    let (ct, _) = rsa::encrypt(&pubk, from_bytes(MSG));
    let (pt1, e1) = rsa::DecryptWithoutCheck(&k, ct.clone());
    let (pt2, e2) = rsa::DecryptWithCheck(&k, ct);
    let ok = e1.IsNil() && e2.IsNil() && slice_eq_trim(&pt1, &from_bytes(MSG))
        && slice_eq_trim(&pt1, &pt2);
    write_result(6, b"DecryptWithoutCheck          ", ok);
    if !ok {
        fail();
    }
}

fn test_7_decrypt_out_of_range() {
    let k = mk_key();
    // A ciphertext equal to N is out of range (c >= N must be rejected).
    let (pt, e) = rsa::decrypt(&k, from_bytes(N), false);
    let ok = !e.IsNil() && pt.Len() == 0;
    write_result(7, b"decrypt rejects c >= N       ", ok);
    if !ok {
        fail();
    }
}

fn test_8_new_private_key_bad_modulus() {
    // An even modulus must be rejected by checkPublicKey.
    let even_n: &[u8] = &[
        0xbf, 0x97, 0x52, 0xdb, 0x54, 0x93, 0x8b, 0xd8, 0x6a, 0x57, 0x4f, 0xd5, 0xdf, 0x6e,
        0xf9, 0x96, 0xcc, 0xdd, 0x08, 0x8d, 0x90, 0x50, 0xfd, 0x4f, 0x18, 0x7a, 0xcf, 0xb0,
        0x4a, 0x91, 0x6d, 0xba, 0x82, 0xad, 0xa0, 0x44, 0xa4, 0x2c, 0xa4, 0xd5, 0x9d, 0xd1,
        0xdb, 0xbd, 0x03, 0x01, 0x29, 0x83, 0x0e, 0x90, 0x49, 0xee, 0x45, 0x61, 0x3a, 0x01,
        0xc7, 0xa3, 0x46, 0x24, 0x70, 0xc1, 0x17, 0x58,
    ];
    let (_, e) = rsa::NewPrivateKey(
        from_bytes(even_n),
        E,
        from_bytes(D),
        from_bytes(P),
        from_bytes(Q),
    );
    let ok = !e.IsNil();
    write_result(8, b"NewPrivateKey rejects even N ", ok);
    if !ok {
        fail();
    }
}

fn test_9_without_crt() {
    // A CRT-less key (legacy multi-prime path). decrypt uses the plain
    // Exp codepath; encrypt -> decrypt must still round-trip.
    let (k, e) = rsa::NewPrivateKeyWithoutCRT(from_bytes(N), E, from_bytes(D));
    if !e.IsNil() {
        write_result(9, b"NewPrivateKeyWithoutCRT      ", false);
        fail();
        return;
    }
    let pubk = k.PublicKey();
    let (ct, e1) = rsa::encrypt(&pubk, from_bytes(MSG));
    let (pt, e2) = rsa::decrypt(&k, ct, false);
    let ok = e1.IsNil() && e2.IsNil() && !k.has_crt
        && slice_eq_trim(&pt, &from_bytes(MSG));
    write_result(9, b"NewPrivateKeyWithoutCRT      ", ok);
    if !ok {
        fail();
    }
}

fn test_10_generate_key() {
    // GenerateKey at a small bit size. Debug-build keygen is slow, so
    // keep it modest (256 bits) to stay well inside the e2e timeout.
    let mut rng = RandReader;
    let (k, e) = rsa::GenerateKey(&mut rng, 256);
    if !e.IsNil() {
        write_result(10, b"GenerateKey(256) round-trip  ", false);
        fail();
        return;
    }
    let ok_size = k.PublicKey().Size() == 32 && k.has_crt;
    // The generated key must encrypt/decrypt round-trip.
    let pubk = k.PublicKey();
    // A small plaintext block, comfortably < the 256-bit modulus.
    let small: &[u8] = &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let (ct, e1) = rsa::encrypt(&pubk, from_bytes(small));
    let (pt, e2) = rsa::decrypt(&k, ct, true);
    let ok = ok_size && e1.IsNil() && e2.IsNil()
        && slice_eq_trim(&pt, &from_bytes(small));
    write_result(10, b"GenerateKey(256) round-trip  ", ok);
    if !ok {
        fail();
    }
}
