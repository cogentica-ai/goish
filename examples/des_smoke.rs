// des_smoke — exercise crypto/des::NewCipher + NewTripleDESCipher.
//
// Test vectors lifted from /share/go/src/crypto/des/des_test.go
// (encryptDESTests + encryptTripleDESTests slices). All vectors are
// encrypted then decrypted; ciphertext / plaintext compared against
// the published expected values.
//
// Coverage:
//   1. DES — key=0, plain=0 → 8ca64de9c1b123a7 (round-trip).
//   2. DES — key=0, plain=ffff…ff → 355550b2150e2451 (round-trip).
//   3. DES — key=ffff…, plain=0 → caaaaf4deaf1dbae (round-trip).
//   4. DES — key=0123…ef, plain=fedc…10 → 12c626af058b433b (round-trip).
//   5. KeySizeError on length-0 DES key.
//   6. KeySizeError on length-7 DES key.
//   7. NewCipher succeeds on length-8 (no error) + BlockSize()==8.
//   8. 3DES — k1=0,k2=ffff,k3=0; plain=0 → 9295b59bb384736e (round-trip).
//   9. 3DES — k1=ffff,k2=0,k3=ffff; plain=ffff → 6d6a4a644c7b8c91 (round-trip).
//  10. 3DES — KeySizeError on length-23 + NewTripleDESCipher succeeds on 24.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::cipher::Block;
use goish::crypto::des;
use goish::types::byte;
use goish::{slice, syscall, Println};

const KB: usize = 1024;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

fn from_bytes(b: &[u8]) -> goish::slice<byte> {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(b.len());
    for &x in b {
        v.push(x);
    }
    slice::__from_vec(v)
}

fn check_bytes(got: &goish::slice<byte>, want: &[u8]) -> bool {
    if got.Len() as usize != want.len() {
        return false;
    }
    for i in 0..want.len() {
        if got[i as goish::int] != want[i] {
            return false;
        }
    }
    true
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

#[goish::main]
fn main() {
    goish::go!(stack(128 * KB), || {
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
    test_1_des_zero_zero();
    test_2_des_zero_ones();
    test_3_des_ones_zero();
    test_4_des_0123ef_fedc10();
    test_5_des_keysize_zero();
    test_6_des_keysize_7();
    test_7_des_keysize_8_block_size();
    test_8_3des_vector1();
    test_9_3des_vector4();
    test_10_3des_keysize();
}

fn run_des_vector(idx: u8, key: &[u8], plain: &[u8], cipher: &[u8], label: &[u8]) {
    let key_s = from_bytes(key);
    let (c_opt, err) = des::NewCipher(key_s);
    if !err.IsNil() || c_opt.is_none() {
        write_result(idx, label, false);
        fail();
        return;
    }
    let c = c_opt.unwrap();

    // Encrypt: plain → ct
    let mut ct = from_bytes(&[0u8; 8]);
    c.Encrypt(&mut ct, from_bytes(plain));
    if !check_bytes(&ct, cipher) {
        write_result(idx, label, false);
        fail();
        return;
    }

    // Decrypt: ct → pt
    let mut pt = from_bytes(&[0u8; 8]);
    c.Decrypt(&mut pt, from_bytes(cipher));
    if !check_bytes(&pt, plain) {
        write_result(idx, label, false);
        fail();
        return;
    }

    write_result(idx, label, true);
}

// DES vector — key=0…0, plain=0…0 → 8ca64de9c1b123a7.
fn test_1_des_zero_zero() {
    run_des_vector(
        1,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x8c, 0xa6, 0x4d, 0xe9, 0xc1, 0xb1, 0x23, 0xa7],
        b"DES key=0 plain=0          ",
    );
}

// DES vector — key=0…0, plain=ff…ff → 355550b2150e2451.
fn test_2_des_zero_ones() {
    run_des_vector(
        2,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0x35, 0x55, 0x50, 0xb2, 0x15, 0x0e, 0x24, 0x51],
        b"DES key=0 plain=1          ",
    );
}

// DES vector — key=ff…ff, plain=0…0 → caaaaf4deaf1dbae.
fn test_3_des_ones_zero() {
    run_des_vector(
        3,
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0xca, 0xaa, 0xaf, 0x4d, 0xea, 0xf1, 0xdb, 0xae],
        b"DES key=1 plain=0          ",
    );
}

// DES vector — key=0123456789abcdef, plain=fedcba9876543210
//              → 12c626af058b433b.
fn test_4_des_0123ef_fedc10() {
    run_des_vector(
        4,
        &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        &[0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
        &[0x12, 0xc6, 0x26, 0xaf, 0x05, 0x8b, 0x43, 0x3b],
        b"DES key=0123ef plain=fedc10",
    );
}

fn test_5_des_keysize_zero() {
    let (c_opt, err) = des::NewCipher(from_bytes(&[]));
    if c_opt.is_none() && !err.IsNil() {
        write_result(5, b"KeySizeError on len=0      ", true);
    } else {
        write_result(5, b"KeySizeError on len=0      ", false);
        fail();
    }
}

fn test_6_des_keysize_7() {
    let (c_opt, err) = des::NewCipher(from_bytes(&[0u8; 7]));
    if c_opt.is_none() && !err.IsNil() {
        write_result(6, b"KeySizeError on len=7      ", true);
    } else {
        write_result(6, b"KeySizeError on len=7      ", false);
        fail();
    }
}

fn test_7_des_keysize_8_block_size() {
    let (c_opt, err) = des::NewCipher(from_bytes(&[0u8; 8]));
    if c_opt.is_some() && err.IsNil() {
        let c = c_opt.unwrap();
        if c.BlockSize() == des::BlockSize && c.BlockSize() == 8 {
            write_result(7, b"NewCipher 8 + BlockSize    ", true);
            return;
        }
    }
    write_result(7, b"NewCipher 8 + BlockSize    ", false);
    fail();
}

fn run_3des_vector(idx: u8, key: &[u8], plain: &[u8], cipher: &[u8], label: &[u8]) {
    let key_s = from_bytes(key);
    let (c_opt, err) = des::NewTripleDESCipher(key_s);
    if !err.IsNil() || c_opt.is_none() {
        write_result(idx, label, false);
        fail();
        return;
    }
    let c = c_opt.unwrap();

    // Encrypt: plain → ct
    let mut ct = from_bytes(&[0u8; 8]);
    c.Encrypt(&mut ct, from_bytes(plain));
    if !check_bytes(&ct, cipher) {
        write_result(idx, label, false);
        fail();
        return;
    }

    // Decrypt: ct → pt
    let mut pt = from_bytes(&[0u8; 8]);
    c.Decrypt(&mut pt, from_bytes(cipher));
    if !check_bytes(&pt, plain) {
        write_result(idx, label, false);
        fail();
        return;
    }

    write_result(idx, label, true);
}

// 3DES vector 1 — k1=0,k2=ffff,k3=0; plain=0 → 9295b59bb384736e.
fn test_8_3des_vector1() {
    run_3des_vector(
        8,
        &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x92, 0x95, 0xb5, 0x9b, 0xb3, 0x84, 0x73, 0x6e],
        b"3DES k1=0,k2=1,k3=0 p=0    ",
    );
}

// 3DES vector 4 — k1=ffff,k2=0,k3=ffff; plain=ffff → 6d6a4a644c7b8c91.
fn test_9_3des_vector4() {
    run_3des_vector(
        9,
        &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0x6d, 0x6a, 0x4a, 0x64, 0x4c, 0x7b, 0x8c, 0x91],
        b"3DES k1=1,k2=0,k3=1 p=1    ",
    );
}

fn test_10_3des_keysize() {
    let (c_opt, err) = des::NewTripleDESCipher(from_bytes(&[0u8; 23]));
    let bad = c_opt.is_none() && !err.IsNil();
    let (c_opt, err) = des::NewTripleDESCipher(from_bytes(&[0u8; 24]));
    let good = c_opt.is_some() && err.IsNil();
    if bad && good {
        write_result(10, b"3DES keysize 23 vs 24      ", true);
    } else {
        write_result(10, b"3DES keysize 23 vs 24      ", false);
        fail();
    }
}
