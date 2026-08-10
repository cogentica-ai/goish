// fips140_gcm_smoke — crypto/internal/fips140/aes/gcm, against the NIST
// SP 800-38D worked test cases.
//
// GCM fails silently in the worst way: a wrong GHASH or a mis-derived
// counter still produces ciphertext of the right length with a tag that
// verifies against itself. So nothing here is compared to another goish
// call — every value is a published vector.
//
// Test case 6 matters most: its 60-byte nonce takes the slow path where
// the initial counter is derived by running the nonce through GHASH,
// rather than the 96-bit fast path everything else uses.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::internal::fips140::aes;
use goish::crypto::internal::fips140::aes::gcm;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::types::byte;

static mut FAILED: bool = false;

fn check(name: &str, got: goish::string, want: &str) {
    if got == goish::string::from(want) {
        fmt::Printf!("PASS: %s\n", goish::string::from(name));
    } else {
        fmt::Printf!(
            "FAIL: %s\n  got  %s\n  want %s\n",
            goish::string::from(name),
            got,
            goish::string::from(want)
        );
        unsafe { FAILED = true };
    }
}

fn unhex(s: &str) -> slice<byte> {
    let b = s.as_bytes();
    let mut out: Vec<byte> = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        let hi = match b[i] {
            x @ b'0'..=b'9' => x - b'0',
            x @ b'a'..=b'f' => x - b'a' + 10,
            _ => 0,
        };
        let lo = match b[i + 1] {
            x @ b'0'..=b'9' => x - b'0',
            x @ b'a'..=b'f' => x - b'a' + 10,
            _ => 0,
        };
        out.push((hi << 4) | lo);
        i += 2;
    }
    return slice::__from_vec(out);
}

fn hx(s: &slice<byte>) -> goish::string {
    let r: &[byte] = s;
    return hex::EncodeToString(r);
}

fn empty() -> slice<byte> {
    return slice::__from_vec(Vec::new());
}

const KEY: &str = "feffe9928665731c6d6a8f9467308308";
const PT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
const AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
// The full 64-byte plaintext of test case 3; PT is its first 60 bytes,
// which is what cases 4 and 6 use. Spelled out rather than concatenated:
// alloc::format! drags in alloc::fmt::format, which needs _Unwind_Resume
// and does not link in goish's panic=abort build.
const PT64: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";

#[goish::main]
fn main() {
    let (blk, err) = aes::New(unhex(KEY));
    if err != goish::nil {
        fmt::Printf!("FAIL: aes::New returned %v\n", err);
        goish::syscall::Exit(1);
    }
    let b = blk.unwrap();

    // ── SP 800-38D test case 3: 96-bit nonce, no AAD ──────────────────
    let (g, err) = gcm::New(&b, 12, 16);
    if err != goish::nil {
        fmt::Printf!("FAIL: gcm::New returned %v\n", err);
        goish::syscall::Exit(1);
    }
    let g = g.unwrap();
    check("NonceSize", fmt::Sprintf!("%d", g.NonceSize()), "12");
    check("Overhead", fmt::Sprintf!("%d", g.Overhead()), "16");

    let nonce = unhex("cafebabefacedbaddecaf888");
    let pt3 = unhex(PT64);
    let sealed = g.Seal(empty(), nonce.clone(), pt3.clone(), empty());
    check(
        "TC3 seal (96-bit nonce, no AAD)",
        hx(&sealed),
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
         4d5c2af327cd64a62cf35abd2ba6fab4",
    );

    let (opened, err) = g.Open(empty(), nonce.clone(), sealed.clone(), empty());
    if err != goish::nil {
        fmt::Printf!("FAIL: TC3 Open returned %v\n", err);
        unsafe { FAILED = true };
    }
    check("TC3 open round-trip", hx(&opened), PT64);

    // ── SP 800-38D test case 4: 96-bit nonce with AAD ─────────────────
    let sealed4 = g.Seal(empty(), nonce.clone(), unhex(PT), unhex(AAD));
    check(
        "TC4 seal (with AAD)",
        hx(&sealed4),
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
         5bc94fbc3221a5db94fae95ae7121a47",
    );

    let (opened4, err) = g.Open(empty(), nonce.clone(), sealed4.clone(), unhex(AAD));
    if err != goish::nil {
        fmt::Printf!("FAIL: TC4 Open returned %v\n", err);
        unsafe { FAILED = true };
    }
    check("TC4 open round-trip", hx(&opened4), PT);

    // Wrong AAD must fail authentication, not return garbage plaintext.
    let (bad, err) = g.Open(empty(), nonce.clone(), sealed4.clone(), unhex("00"));
    check(
        "TC4 open with wrong AAD errors",
        fmt::Sprintf!("%v", err != goish::nil),
        "true",
    );
    check(
        "and returns no plaintext",
        fmt::Sprintf!("%d", bad.Len()),
        "0",
    );

    // A flipped ciphertext bit must fail too.
    let mut tampered: Vec<byte> = {
        let r: &[byte] = &sealed4;
        r.to_vec()
    };
    tampered[0] ^= 0x01;
    let (_, err) = g.Open(empty(), nonce.clone(), slice::__from_vec(tampered), unhex(AAD));
    check(
        "tampered ciphertext errors",
        fmt::Sprintf!("%v", err != goish::nil),
        "true",
    );

    // ── SP 800-38D test case 6: 60-byte nonce (GHASH-derived counter) ─
    let (g6, err) = gcm::New(&b, 60, 16);
    if err != goish::nil {
        fmt::Printf!("FAIL: gcm::New(60) returned %v\n", err);
        goish::syscall::Exit(1);
    }
    let g6 = g6.unwrap();
    let nonce6 = unhex(
        "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728\
         c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
    );
    let sealed6 = g6.Seal(empty(), nonce6.clone(), unhex(PT), unhex(AAD));
    check(
        "TC6 seal (60-byte nonce, GHASH counter)",
        hx(&sealed6),
        "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7\
         01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5\
         619cc5aefffe0bfa462af43c1699d050",
    );

    let (opened6, err) = g6.Open(empty(), nonce6.clone(), sealed6.clone(), unhex(AAD));
    if err != goish::nil {
        fmt::Printf!("FAIL: TC6 Open returned %v\n", err);
        unsafe { FAILED = true };
    }
    check("TC6 open round-trip", hx(&opened6), PT);

    // ── dst append semantics ──────────────────────────────────────────
    //
    // Seal appends to dst rather than replacing it, so a non-empty dst
    // must be preserved ahead of the ciphertext.
    let prefix = unhex("aabbcc");
    let appended = g.Seal(prefix.clone(), nonce.clone(), unhex(PT), unhex(AAD));
    check(
        "Seal appends to dst",
        hx(&appended),
        "aabbcc42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329\
         aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
         5bc94fbc3221a5db94fae95ae7121a47",
    );

    // ── constructor validation ────────────────────────────────────────
    let (_, err) = gcm::New(&b, 12, 11);
    check(
        "tag size below 12 rejected",
        fmt::Sprintf!("%v", err != goish::nil),
        "true",
    );
    let (_, err) = gcm::New(&b, 0, 16);
    check(
        "zero nonce size rejected",
        fmt::Sprintf!("%v", err != goish::nil),
        "true",
    );

    // ── GHASH is exported for crypto/cipher's non-AES GCM modes ───────
    let mut hkey = [0u8; 16];
    let one = unhex("0388dace60b6a392f328c2b971b2fe78");
    let hr: &[byte] = &one;
    hkey.copy_from_slice(hr);
    let gh = gcm::GHASH(&hkey, &[unhex("00000000000000000000000000000000")]);
    check(
        "GHASH one zero block",
        fmt::Sprintf!("%d", gh.Len()),
        "16",
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_gcm_smoke OK\n");
}
