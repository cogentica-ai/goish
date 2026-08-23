// crypto_kdf_smoke — exercise HKDF (RFC 5869) and PBKDF2 (RFC 8018).
// Test vectors: RFC 5869 Appendix A.1, A.2 + RFC 6070 PBKDF2 vectors.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::crypto::{hkdf, pbkdf2, sha1, sha256};
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::types::byte;
use goish::{string, syscall};

fn from_hex(s: &str) -> slice<byte> {
    let (v, _) = hex::DecodeString(s);
    v
}

fn to_hex(v: &slice<byte>) -> goish::gostring::string {
    let raw: &[byte] = v;
    hex::EncodeToString(raw)
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // ─── HKDF — RFC 5869 ────────────────────────────────────────────

    // A.1. Basic test case with SHA-256.
    //   IKM  = 0x0b * 22
    //   salt = 0x000102030405060708090a0b0c
    //   info = 0xf0f1f2f3f4f5f6f7f8f9
    //   L    = 42
    //   PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
    //   OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
    //          34007208d5b887185865
    {
        let ikm = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = from_hex("000102030405060708090a0b0c");
        let info = string("");

        let (prk, _) = hkdf::Extract(sha256::NewHash, ikm.clone(), salt.clone());
        let want_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
        if to_hex(&prk) == string(want_prk) {
            fmt::Println!("[ 1] HKDF-SHA256 Extract A.1  PASS");
        } else {
            fmt::Println!("[ 1] HKDF-SHA256 Extract A.1  FAIL got {}", to_hex(&prk));
            failed += 1;
        }

        let info2 = string("");
        let _ = info2;
        let info_real = from_hex("f0f1f2f3f4f5f6f7f8f9");
        let info_str = string::from_bytes(&info_real);
        let (okm, _) = hkdf::Expand(sha256::NewHash, prk.clone(), info_str.clone(), 42);
        let want_okm =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        if to_hex(&okm) == string(want_okm) {
            fmt::Println!("[ 2] HKDF-SHA256 Expand A.1   PASS");
        } else {
            fmt::Println!("[ 2] HKDF-SHA256 Expand A.1   FAIL got {}", to_hex(&okm));
            failed += 1;
        }

        // Key combines Extract+Expand in one call.
        let (okm_key, _) = hkdf::Key(sha256::NewHash, ikm, salt, info_str, 42);
        if to_hex(&okm_key) == string(want_okm) {
            fmt::Println!("[ 3] HKDF-SHA256 Key A.1      PASS");
        } else {
            fmt::Println!(
                "[ 3] HKDF-SHA256 Key A.1      FAIL got {}",
                to_hex(&okm_key)
            );
            failed += 1;
        }
        let _ = info;
    }

    // A.2. Test with SHA-256 and longer inputs/outputs (L=82).
    //   IKM  = 0x000102...4f (80 bytes)
    //   salt = 0x606162...af (80 bytes)
    //   info = 0xb0b1b2...ff (80 bytes)
    //   PRK  = 06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244
    //   OKM  = b11e398dc80327a1c8e7f78c596a4934 4f012eda2d4efad8a050cc4c19afa97c
    //          59045a99cac7827271cb41c65e590e09 da3275600c2f09b8367793a9aca3db71
    //          cc30c58179ec3e87c14c01d5c1f3434f 1d87
    {
        let ikm = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        let salt = from_hex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        let info_bytes = from_hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let info_str = string::from_bytes(&info_bytes);
        let want_okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87";

        let (okm, _) = hkdf::Key(sha256::NewHash, ikm, salt, info_str, 82);
        if to_hex(&okm) == string(want_okm) {
            fmt::Println!("[ 4] HKDF-SHA256 Key A.2      PASS");
        } else {
            fmt::Println!("[ 4] HKDF-SHA256 Key A.2      FAIL got {}", to_hex(&okm));
            failed += 1;
        }
    }

    // A.3. Test with SHA-256 and zero-length salt/info.
    //   IKM  = 0x0b * 22
    //   salt = (empty)  → defaults to zero-byte block of hash size
    //   info = (empty)
    //   L    = 42
    //   PRK  = 19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04
    //   OKM  = 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d
    //          9d201395faa4b61a96c8
    {
        let ikm = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt: slice<byte> = slice::__from_vec(alloc::vec::Vec::new()); // empty
        let info = string("");

        let (prk, _) = hkdf::Extract(sha256::NewHash, ikm.clone(), salt.clone());
        let want_prk = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";
        if to_hex(&prk) == string(want_prk) {
            fmt::Println!("[ 5] HKDF-SHA256 Extract A.3  PASS");
        } else {
            fmt::Println!("[ 5] HKDF-SHA256 Extract A.3  FAIL got {}", to_hex(&prk));
            failed += 1;
        }

        let (okm, _) = hkdf::Key(sha256::NewHash, ikm, salt, info, 42);
        let want_okm =
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";
        if to_hex(&okm) == string(want_okm) {
            fmt::Println!("[ 6] HKDF-SHA256 Key A.3      PASS");
        } else {
            fmt::Println!("[ 6] HKDF-SHA256 Key A.3      FAIL got {}", to_hex(&okm));
            failed += 1;
        }
    }

    // 7. HKDF length validation: keyLength > 255*hashSize must error.
    {
        let secret = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt: slice<byte> = slice::__from_vec(alloc::vec::Vec::new());
        let info = string("");
        // SHA-256 size=32, max output = 32*255 = 8160. Request 8161.
        let (out, err) = hkdf::Key(sha256::NewHash, secret, salt, info, 8161);
        let raw: &[byte] = &out;
        if !err.IsNil() && raw.is_empty() {
            fmt::Println!("[ 7] HKDF length cap error    PASS");
        } else {
            fmt::Println!("[ 7] HKDF length cap error    FAIL");
            failed += 1;
        }
    }

    // ─── PBKDF2 — RFC 6070 ──────────────────────────────────────────

    // 8. RFC 6070 vector 1: P="password", S="salt", c=1, dkLen=20, HMAC-SHA1
    //    DK = 0c60c80f961f0e71f3a9b524af6012062fe037a6
    {
        let pw = string("password");
        let salt = from_hex("73616c74"); // "salt"
        let (dk, _) = pbkdf2::Key(sha1::NewHash, pw, salt, 1, 20);
        let want = "0c60c80f961f0e71f3a9b524af6012062fe037a6";
        if to_hex(&dk) == string(want) {
            fmt::Println!("[ 8] PBKDF2-SHA1 c=1 dk=20    PASS");
        } else {
            fmt::Println!("[ 8] PBKDF2-SHA1 c=1 dk=20    FAIL got {}", to_hex(&dk));
            failed += 1;
        }
    }

    // 9. RFC 6070 vector 2: P="password", S="salt", c=2, dkLen=20, HMAC-SHA1
    //    DK = ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957
    {
        let pw = string("password");
        let salt = from_hex("73616c74");
        let (dk, _) = pbkdf2::Key(sha1::NewHash, pw, salt, 2, 20);
        let want = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";
        if to_hex(&dk) == string(want) {
            fmt::Println!("[ 9] PBKDF2-SHA1 c=2 dk=20    PASS");
        } else {
            fmt::Println!("[ 9] PBKDF2-SHA1 c=2 dk=20    FAIL got {}", to_hex(&dk));
            failed += 1;
        }
    }

    // 10. RFC 6070 vector 3: c=4096, dkLen=20, HMAC-SHA1
    //    DK = 4b007901b765489abead49d926f721d065a429c1
    {
        let pw = string("password");
        let salt = from_hex("73616c74");
        let (dk, _) = pbkdf2::Key(sha1::NewHash, pw, salt, 4096, 20);
        let want = "4b007901b765489abead49d926f721d065a429c1";
        if to_hex(&dk) == string(want) {
            fmt::Println!("[10] PBKDF2-SHA1 c=4096 dk=20 PASS");
        } else {
            fmt::Println!("[10] PBKDF2-SHA1 c=4096 dk=20 FAIL got {}", to_hex(&dk));
            failed += 1;
        }
    }

    // 11. RFC 6070 vector 5: longer P/S/dkLen
    //    P="passwordPASSWORDpassword" (24)
    //    S="saltSALTsaltSALTsaltSALTsaltSALTsalt" (36)
    //    c=4096, dkLen=25
    //    DK = 3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038
    {
        let pw = string("passwordPASSWORDpassword");
        let salt =
            from_hex("73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74");
        let (dk, _) = pbkdf2::Key(sha1::NewHash, pw, salt, 4096, 25);
        let want = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";
        if to_hex(&dk) == string(want) {
            fmt::Println!("[11] PBKDF2-SHA1 long inputs  PASS");
        } else {
            fmt::Println!("[11] PBKDF2-SHA1 long inputs  FAIL got {}", to_hex(&dk));
            failed += 1;
        }
    }

    // 12. PBKDF2 with SHA-256 (RFC 7914 vector — c=1, dkLen=64).
    //    P="passwd", S="salt", c=1, dkLen=64, HMAC-SHA256
    //    DK = 55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783
    {
        let pw = string("passwd");
        let salt = from_hex("73616c74");
        let (dk, _) = pbkdf2::Key(sha256::NewHash, pw, salt, 1, 64);
        let want = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783";
        if to_hex(&dk) == string(want) {
            fmt::Println!("[12] PBKDF2-SHA256 c=1        PASS");
        } else {
            fmt::Println!("[12] PBKDF2-SHA256 c=1        FAIL got {}", to_hex(&dk));
            failed += 1;
        }
    }

    // 13. PBKDF2 keyLength=0 returns error.
    {
        let pw = string("p");
        let salt = from_hex("73");
        let (out, err) = pbkdf2::Key(sha1::NewHash, pw, salt, 1, 0);
        let raw: &[byte] = &out;
        if !err.IsNil() && raw.is_empty() {
            fmt::Println!("[13] PBKDF2 keyLength<=0 err  PASS");
        } else {
            fmt::Println!("[13] PBKDF2 keyLength<=0 err  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 13/13");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 13");
        syscall::Exit(1);
    }
}
