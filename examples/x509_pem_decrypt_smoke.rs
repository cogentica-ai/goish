// x509_pem_decrypt_smoke — crypto/x509's RFC 1423 PEM encryption vs Go 1.25.5.
//
// Every expectation is `scripts/goref.sh crypto/x509` output. The IV comes
// from a deterministic reader (0,1,2,…) so the ciphertext is reproducible
// and can be compared byte-for-byte against Go rather than only
// round-tripped — a round-trip alone would pass even if the KDF, the
// padding and the CBC chaining were all wrong in compensating ways.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::x509::{
    DecryptPEMBlock, EncryptPEMBlock, IsEncryptedPEMBlock, PEMCipher, PEMCipher3DES,
    PEMCipherAES128, PEMCipherAES192, PEMCipherAES256, PEMCipherDES,
};
use goish::encoding::pem;
use goish::goslice::slice;
use goish::{fmt, io, string};

static RAN: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(ok: bool, label: &'static str) {
    RAN.fetch_add(1, Ordering::AcqRel);
    if ok {
        fmt::Printf!("PASS: %s\n", string(label));
    } else {
        FAILED.fetch_add(1, Ordering::AcqRel);
        fmt::Printf!("FAIL: %s\n", string(label));
    }
}

fn hex(b: &slice<u8>) -> alloc::vec::Vec<u8> {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for x in b.as_ref().iter() {
        out.push(D[(x >> 4) as usize]);
        out.push(D[(x & 0xf) as usize]);
    }
    return out;
}

/// Go's test reader: fills with 0,1,2,… so the IV is deterministic.
struct zeroRand {
    n: u8,
}

impl io::Reader for zeroRand {
    fn Read(&mut self, p: &mut slice<u8>) -> (i64, goish::error) {
        let d: &mut [u8] = p;
        for i in 0..d.len() {
            d[i] = self.n;
            self.n = self.n.wrapping_add(1);
        }
        return (d.len() as i64, goish::nil.into());
    }
}

fn bytes(s: &[u8]) -> slice<u8> {
    return slice::__from_vec(s.to_vec());
}

fn one(alg: PEMCipher, dek: &'static str, enc: &'static str, label: &'static str) {
    let pw = bytes(b"password");
    let data = bytes(b"the quick brown fox jumps over the lazy dog!!!!!");
    let mut r = zeroRand { n: 0 };
    let (b, err) = EncryptPEMBlock(&mut r, "TEST KEY", data.clone(), pw.clone(), alg);
    if err != goish::nil {
        check(false, label);
        return;
    }
    let b = b.unwrap();
    let (got_dek, _) = b.Headers.Get("DEK-Info");
    let ok_dek = got_dek.as_bytes() == dek.as_bytes();
    let ok_enc = hex(&b.Bytes) == enc.as_bytes();
    let ok_is = IsEncryptedPEMBlock(&b);
    let (dec, derr) = DecryptPEMBlock(&b, pw);
    let ok_rt = derr == goish::nil && dec.as_ref() == data.as_ref();
    let (_, werr) = DecryptPEMBlock(&b, bytes(b"wrong"));
    let ok_wrong = werr != goish::nil;
    check(ok_dek && ok_enc && ok_is && ok_rt && ok_wrong, label);
}

#[goish::main]
fn main() {
    one(
        PEMCipherDES,
        "DES-CBC,0001020304050607",
        "9a697c2037e1c4ec227188075d6978994ca83971fae7c907c1e8980091dedbe5afbcadd4d665863b09c2d5ebcc89a27fba184f33c0cedf02",
        "DES-CBC encrypt/decrypt byte-exact vs Go",
    );
    one(
        PEMCipher3DES,
        "DES-EDE3-CBC,0001020304050607",
        "7b7395818817c7ce7edcf6f56e2511dcbe6e0b8bb29c5a6fb5f3dde683bb49b7ccc5f6e561865439d3c27f2391f73124f838a36c31bf1b4c",
        "DES-EDE3-CBC encrypt/decrypt byte-exact vs Go",
    );
    one(
        PEMCipherAES128,
        "AES-128-CBC,000102030405060708090a0b0c0d0e0f",
        "00ad2e4b59fe4d476f158f0a0c9991c2bc52741d16eda6204eb85aa5b09e5c4b1d0c84f278e898891e41b74fef40c8bfa5fc66fc59d36141f60acf8b8e02ffe0",
        "AES-128-CBC encrypt/decrypt byte-exact vs Go",
    );
    one(
        PEMCipherAES192,
        "AES-192-CBC,000102030405060708090a0b0c0d0e0f",
        "c937487067e929fe655c5168a24ccc8707cc662380dfbdfff9be40b01d8cc62ebb9501922a1f449dbc1d22017fb856413db1c0bc221c4ef746f616be0bde02c5",
        "AES-192-CBC encrypt/decrypt byte-exact vs Go",
    );
    one(
        PEMCipherAES256,
        "AES-256-CBC,000102030405060708090a0b0c0d0e0f",
        "60b9d2da404c2160f3baad37c63ed37fa8bf3b37c03142b31b6d22f15dfdeddc9280b5869e010c13f82f6c5304110a370c41ddd385453da6ab0d7f379cd06cc8",
        "AES-256-CBC encrypt/decrypt byte-exact vs Go",
    );

    // The three error paths, each with Go's exact message.
    let pw = bytes(b"password");
    let plain = pem::Block {
        Type: string("TEST"),
        Headers: goish::gomap::map::<goish::string, goish::string>::new(),
        Bytes: bytes(&[1, 2, 3]),
    };
    check(!IsEncryptedPEMBlock(&plain), "IsEncryptedPEMBlock(plain)=false");
    let (_, e) = DecryptPEMBlock(&plain, pw.clone());
    check(
        e.Error().as_bytes() == b"x509: no DEK-Info header in block",
        "Decrypt(plain) reports no DEK-Info",
    );

    let mut unknown = pem::Block {
        Type: string("TEST"),
        Headers: goish::gomap::map::<goish::string, goish::string>::new(),
        Bytes: bytes(&[1, 2, 3]),
    };
    unknown.Headers.Set("DEK-Info", "NOPE-123,00");
    let (_, e2) = DecryptPEMBlock(&unknown, pw.clone());
    check(
        e2.Error().as_bytes() == b"x509: unknown encryption mode",
        "Decrypt(unknown cipher)",
    );

    let mut malformed = pem::Block {
        Type: string("TEST"),
        Headers: goish::gomap::map::<goish::string, goish::string>::new(),
        Bytes: bytes(&[1, 2, 3]),
    };
    malformed.Headers.Set("DEK-Info", "AES-128-CBC");
    let (_, e3) = DecryptPEMBlock(&malformed, pw);
    check(
        e3.Error().as_bytes() == b"x509: malformed DEK-Info header",
        "Decrypt(malformed DEK-Info)",
    );

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("x509_pem_decrypt_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!("x509_pem_decrypt_smoke FAILED %d of %d\n", failed as i64, ran as i64);
        goish::syscall::Exit(1);
    }
}
