// fips140_aes_smoke — crypto/internal/fips140/aes: Block, CBCEncrypter,
// CBCDecrypter and CTR, against the NIST SP 800-38A worked examples.
//
// These paths are not reachable from crypto/cipher (which has its own
// CBC/CTR over the cipher.Block trait), so without this test the
// fips140-native modes would compile and never run. Every vector below is
// from SP 800-38A §F, cross-checked against openssl.
//
// XORKeyStreamAt gets its own checks: it is the seeking entry point CTR
// itself is built on, and an off-by-one in the counter arithmetic there
// produces plausible-looking garbage rather than a failure.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::internal::fips140::aes;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::types::byte;

static mut FAILED: bool = false;

fn check(name: &str, got: goish::string, want: goish::string) {
    if got == want {
        fmt::Printf!("PASS: %s\n", goish::string::from(name));
    } else {
        fmt::Printf!(
            "FAIL: %s\n  got  %s\n  want %s\n",
            goish::string::from(name),
            got,
            want
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

fn tohex(s: &slice<byte>) -> goish::string {
    let raw: &[byte] = s;
    return hex::EncodeToString(raw);
}

fn zeros(n: usize) -> slice<byte> {
    return slice::__from_vec(alloc::vec![0u8; n]);
}

fn iv16(s: &str) -> [byte; 16] {
    let v = unhex(s);
    let raw: &[byte] = &v;
    let mut a = [0u8; 16];
    a.copy_from_slice(&raw[..16]);
    return a;
}

// SP 800-38A §F — the shared key and plaintext for every AES-128 example.
const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const PT: &str = "6bc1bee22e409f96e93d7e117393172a\
                  ae2d8a571e03ac9c9eb76fac45af8e51\
                  30c81c46a35ce411e5fbc1191a0a52ef\
                  f69f2445df4f9b17ad2b417be66c3710";

#[goish::main]
fn main() {
    let (blk, err) = aes::New(unhex(KEY));
    if err != goish::nil {
        fmt::Printf!("FAIL: aes::New returned %v\n", err);
        goish::syscall::Exit(1);
    }
    let b = blk.unwrap();

    // ── ECB single block (SP 800-38A F.1.1, first block) ───────────────
    let mut ct = zeros(16);
    b.Encrypt(&mut ct, unhex("6bc1bee22e409f96e93d7e117393172a"));
    check(
        "Block.Encrypt",
        tohex(&ct),
        goish::string::from("3ad77bb40d7a3660a89ecaf32466ef97"),
    );

    let mut pt = zeros(16);
    b.Decrypt(&mut pt, ct.clone());
    check(
        "Block.Decrypt round-trips",
        tohex(&pt),
        goish::string::from("6bc1bee22e409f96e93d7e117393172a"),
    );

    // ── CBC (SP 800-38A F.2.1 / F.2.2) ────────────────────────────────
    let cbcIV = iv16("000102030405060708090a0b0c0d0e0f");
    let want_cbc = "7649abac8119b246cee98e9b12e9197d\
                    5086cb9b507219ee95db113a917678b2\
                    73bed6b8e3c1743b7116e69e22229516\
                    3ff1caa1681fac09120eca307586e1a7";

    let mut enc = aes::NewCBCEncrypter(&b, cbcIV);
    check(
        "CBCEncrypter.BlockSize",
        fmt::Sprintf!("%d", enc.BlockSize()),
        goish::string::from("16"),
    );
    let mut out = zeros(64);
    enc.CryptBlocks(&mut out, &unhex(PT));
    check(
        "CBC encrypt (F.2.1)",
        tohex(&out),
        goish::string::from(want_cbc),
    );

    let mut dec = aes::NewCBCDecrypter(&b, cbcIV);
    let mut back = zeros(64);
    dec.CryptBlocks(&mut back, &unhex(want_cbc));
    check("CBC decrypt (F.2.2)", tohex(&back), goish::string::from(PT));

    // Chaining across calls must match one call over the whole input:
    // the IV carried in the encrypter is the previous ciphertext block.
    let mut enc2 = aes::NewCBCEncrypter(&b, cbcIV);
    let mut half1 = zeros(32);
    let mut half2 = zeros(32);
    let ptv = unhex(PT);
    let ptr: &[byte] = &ptv;
    enc2.CryptBlocks(&mut half1, &slice::__from_vec(ptr[..32].to_vec()));
    enc2.CryptBlocks(&mut half2, &slice::__from_vec(ptr[32..].to_vec()));
    let mut joined: Vec<byte> = Vec::new();
    joined.extend_from_slice(&half1);
    joined.extend_from_slice(&half2);
    check(
        "CBC chains across CryptBlocks calls",
        tohex(&slice::__from_vec(joined)),
        goish::string::from(want_cbc),
    );

    // SetIV must reset the chain: re-encrypting from the original IV
    // reproduces the first call exactly.
    let mut enc3 = aes::NewCBCEncrypter(&b, iv16("ffffffffffffffffffffffffffffffff"));
    enc3.SetIV(&unhex("000102030405060708090a0b0c0d0e0f"));
    let mut out3 = zeros(64);
    enc3.CryptBlocks(&mut out3, &unhex(PT));
    check("CBC SetIV", tohex(&out3), goish::string::from(want_cbc));

    // ── CTR (SP 800-38A F.5.1) ────────────────────────────────────────
    let want_ctr = "874d6191b620e3261bef6864990db6ce\
                    9806f66b7970fdff8617187bb9fffdff\
                    5ae4df3edbd5d35e5b4f09020db03eab\
                    1e031dda2fbe03d1792170a0f3009cee";
    let ctrIV = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    let mut ctr = aes::NewCTR(&b, &ctrIV);
    let mut cout = zeros(64);
    ctr.XORKeyStream(&mut cout, &unhex(PT));
    check(
        "CTR encrypt (F.5.1)",
        tohex(&cout),
        goish::string::from(want_ctr),
    );

    // CTR is its own inverse.
    let mut ctr2 = aes::NewCTR(&b, &ctrIV);
    let mut cback = zeros(64);
    ctr2.XORKeyStream(&mut cback, &unhex(want_ctr));
    check(
        "CTR decrypt round-trip",
        tohex(&cback),
        goish::string::from(PT),
    );

    // Streaming in uneven pieces must equal one shot — this is what
    // exercises the partial-block path at both ends of XORKeyStreamAt.
    let mut ctr3 = aes::NewCTR(&b, &ctrIV);
    let mut acc: Vec<byte> = Vec::new();
    let cuts: [usize; 5] = [1, 14, 17, 0, 32];
    let mut pos: usize = 0;
    let mut ci = 0;
    while ci < cuts.len() {
        let n = cuts[ci];
        if n > 0 {
            let mut piece = zeros(n);
            ctr3.XORKeyStream(&mut piece, &slice::__from_vec(ptr[pos..pos + n].to_vec()));
            acc.extend_from_slice(&piece);
            pos += n;
        }
        ci += 1;
    }
    check(
        "CTR streams across uneven writes",
        tohex(&slice::__from_vec(acc)),
        goish::string::from(want_ctr),
    );

    // XORKeyStreamAt seeks without consuming state: reading block 1 at
    // offset 16 must equal bytes 16..32 of the one-shot ciphertext.
    let ctr4 = aes::NewCTR(&b, &ctrIV);
    let mut at = zeros(16);
    ctr4.XORKeyStreamAt(&mut at, &slice::__from_vec(ptr[16..32].to_vec()), 16);
    check(
        "CTR XORKeyStreamAt block boundary",
        tohex(&at),
        goish::string::from("9806f66b7970fdff8617187bb9fffdff"),
    );

    // A seek to a non-block-aligned offset takes the partial-block path.
    let mut at2 = zeros(8);
    ctr4.XORKeyStreamAt(&mut at2, &slice::__from_vec(ptr[20..28].to_vec()), 20);
    let full = unhex(want_ctr);
    let fr: &[byte] = &full;
    check(
        "CTR XORKeyStreamAt unaligned",
        tohex(&at2),
        tohex(&slice::__from_vec(fr[20..28].to_vec())),
    );

    // RoundToBlock advances a mid-block offset to the next boundary, so
    // the next XORKeyStream starts on block 1, not mid-block 0.
    let mut ctr5 = aes::NewCTR(&b, &ctrIV);
    let mut five = zeros(5);
    ctr5.XORKeyStream(&mut five, &slice::__from_vec(ptr[..5].to_vec()));
    aes::RoundToBlock(&mut ctr5);
    let mut after = zeros(16);
    ctr5.XORKeyStream(&mut after, &slice::__from_vec(ptr[16..32].to_vec()));
    check(
        "CTR RoundToBlock",
        tohex(&after),
        goish::string::from("9806f66b7970fdff8617187bb9fffdff"),
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_aes_smoke OK\n");
}
