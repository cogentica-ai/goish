// crypto_hash_smoke — exercise crypto.Hash registry + SignerOpts.
//
// Hash IDs / digestSizes / String() / RegisterHash / Available / New
// drawn from /share/go/src/crypto/crypto_test.go and crypto.go directly.
//
// Coverage:
//   1. SHA256.Size() == 32, SHA3_512.Size() == 64.
//   2. SHA256.String() == "SHA-256"; SHA3_256.String() == "SHA3-256".
//   3. Hash(99).String() prefix "unknown hash value ".
//   4. Available() before RegisterHash → false.
//   5. RegisterHash(SHA256, …) then SHA256.Available() → true.
//   6. SHA256.New() computes the right digest of "abc".
//   7. RegisterHash(SHA3_256, …) + SHA3_256.New() of "abc".
//   8. SHA256.HashFunc() == SHA256 (identity).
//   9. SHA1 satisfies SignerOpts directly — Go's `func (h Hash) HashFunc()`.
//  10. String() covers all 19 distinct identifiers.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::crypto::{self, RegisterHash, SignerOpts};
use goish::gostring::string;
use goish::io::Writer;
use goish::types::byte;
use goish::{slice, syscall};

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

fn check_str(got: &string, want: &str) -> bool {
    if got.Len() as usize != want.len() {
        return false;
    }
    let bytes = want.as_bytes();
    let mut i: goish::int = 0;
    while (i as usize) < want.len() {
        if got[i] != bytes[i as usize] {
            return false;
        }
        i += 1;
    }
    true
}

fn starts_with(got: &string, want: &str) -> bool {
    if (got.Len() as usize) < want.len() {
        return false;
    }
    let bytes = want.as_bytes();
    let mut i: goish::int = 0;
    while (i as usize) < want.len() {
        if got[i] != bytes[i as usize] {
            return false;
        }
        i += 1;
    }
    true
}

fn check_slice(got: &goish::slice<byte>, want: &[u8]) -> bool {
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
    goish::go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            fmt::Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run_tests() {
    test_1_size();
    test_2_name_known();
    test_3_name_unknown();
    test_4_available_pre_register();
    test_5_register_sha256_then_available();
    test_6_new_sha256_abc();
    test_7_register_and_new_sha3_256_abc();
    test_8_hashfunc_identity();
    test_9_hash_is_signer_opts();
    test_10_all_known_names();
}

fn test_1_size() {
    let s256 = crypto::SHA256.Size();
    let s3_512 = crypto::SHA3_512.Size();
    if s256 == 32 && s3_512 == 64 {
        write_result(1, b"Hash.Size(SHA256, SHA3_512)  ", true);
    } else {
        write_result(1, b"Hash.Size(SHA256, SHA3_512)  ", false);
        fail();
    }
}

fn test_2_name_known() {
    let s256 = crypto::SHA256.String();
    let s3_256 = crypto::SHA3_256.String();
    if check_str(&s256, "SHA-256") && check_str(&s3_256, "SHA3-256") {
        write_result(2, b"Hash.String known            ", true);
    } else {
        write_result(2, b"Hash.String known            ", false);
        fail();
    }
}

fn test_3_name_unknown() {
    let s = crypto::Hash(99).String();
    if starts_with(&s, "unknown hash value ") {
        write_result(3, b"Hash.String unknown          ", true);
    } else {
        write_result(3, b"Hash.String unknown          ", false);
        fail();
    }
}

fn test_4_available_pre_register() {
    // BLAKE2b_512 is never registered in this test → must be unavailable.
    if !crypto::BLAKE2b_512.Available() {
        write_result(4, b"Hash.Available pre-register  ", true);
    } else {
        write_result(4, b"Hash.Available pre-register  ", false);
        fail();
    }
}

fn test_5_register_sha256_then_available() {
    RegisterHash(crypto::SHA256, || goish::crypto::sha256::NewHash());
    if crypto::SHA256.Available() {
        write_result(5, b"RegisterHash + Available     ", true);
    } else {
        write_result(5, b"RegisterHash + Available     ", false);
        fail();
    }
}

fn test_6_new_sha256_abc() {
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let mut h = crypto::SHA256.New();
    let _ = h.Write(from_bytes(b"abc"));
    let empty: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    let got = h.Sum(slice::__from_vec(empty));
    let want = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    if check_slice(&got, &want) {
        write_result(6, b"Hash.New(SHA256) abc         ", true);
    } else {
        write_result(6, b"Hash.New(SHA256) abc         ", false);
        fail();
    }
}

fn test_7_register_and_new_sha3_256_abc() {
    RegisterHash(crypto::SHA3_256, || goish::crypto::sha3::NewHash256());
    let mut h = crypto::SHA3_256.New();
    let _ = h.Write(from_bytes(b"abc"));
    let empty: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    let got = h.Sum(slice::__from_vec(empty));
    // SHA3-256("abc")
    let want = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
        0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
        0x15, 0x32,
    ];
    if check_slice(&got, &want) {
        write_result(7, b"Hash.New(SHA3_256) abc       ", true);
    } else {
        write_result(7, b"Hash.New(SHA3_256) abc       ", false);
        fail();
    }
}

fn test_8_hashfunc_identity() {
    if crypto::SHA256.HashFunc() == crypto::SHA256 && crypto::SHA1.HashFunc() == crypto::SHA1 {
        write_result(8, b"Hash.HashFunc identity       ", true);
    } else {
        write_result(8, b"Hash.HashFunc identity       ", false);
        fail();
    }
}

fn test_9_hash_is_signer_opts() {
    // Go: `func (h Hash) HashFunc() Hash` is what makes a bare Hash usable
    // wherever a SignerOpts is wanted. Take it through the trait object to
    // prove the impl is the one being exercised, not the inherent method.
    let opts: &dyn SignerOpts = &crypto::SHA1;
    if opts.HashFunc() == crypto::SHA1 {
        write_result(9, b"Hash is SignerOpts           ", true);
    } else {
        write_result(9, b"Hash is SignerOpts           ", false);
        fail();
    }
}

fn test_10_all_known_names() {
    // 19 known hash IDs (MD4..BLAKE2b_512). All must produce a non-empty
    // name without the "unknown" prefix.
    let ids: [crypto::Hash; 19] = [
        crypto::MD4,
        crypto::MD5,
        crypto::SHA1,
        crypto::SHA224,
        crypto::SHA256,
        crypto::SHA384,
        crypto::SHA512,
        crypto::MD5SHA1,
        crypto::RIPEMD160,
        crypto::SHA3_224,
        crypto::SHA3_256,
        crypto::SHA3_384,
        crypto::SHA3_512,
        crypto::SHA512_224,
        crypto::SHA512_256,
        crypto::BLAKE2s_256,
        crypto::BLAKE2b_256,
        crypto::BLAKE2b_384,
        crypto::BLAKE2b_512,
    ];
    let mut ok = true;
    for &id in ids.iter() {
        let n = id.String();
        if starts_with(&n, "unknown") || n.Len() == 0 {
            ok = false;
            break;
        }
    }
    if ok {
        write_result(10, b"All 19 hash IDs named        ", true);
    } else {
        write_result(10, b"All 19 hash IDs named        ", false);
        fail();
    }
}
