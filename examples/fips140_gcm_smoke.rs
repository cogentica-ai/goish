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

// Panics on anything that is not lowercase hex, and on an odd length.
// An earlier version mapped stray characters to 0, which let a mangled
// literal (a lost `\` line-continuation, joining two halves with spaces)
// silently produce a wrong-but-plausible vector instead of failing.
fn unhex(s: &str) -> slice<byte> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        panic!("unhex: odd-length hex literal");
    }
    let mut out: Vec<byte> = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        let nib = |c: u8| -> byte {
            match c {
                x @ b'0'..=b'9' => x - b'0',
                x @ b'a'..=b'f' => x - b'a' + 10,
                _ => panic!("unhex: non-hex character in literal"),
            }
        };
        out.push((nib(b[i]) << 4) | nib(b[i + 1]));
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
    let (_, err) = g.Open(
        empty(),
        nonce.clone(),
        slice::__from_vec(tampered),
        unhex(AAD),
    );
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
    check("GHASH one zero block", fmt::Sprintf!("%d", gh.Len()), "16");

    // ── CMAC (NIST SP 800-38B) ────────────────────────────────────────
    //
    // The empty-message case is special-cased in Go as a single empty
    // partial final block, and the exactly-one-block case is the only
    // path that XORs k1 rather than k2 — both are pinned here.
    let ck = unhex("2b7e151628aed2a6abf7158809cf4f3c");
    let (cb, _) = aes::New(ck);
    let cb = cb.unwrap();
    let mac = gcm::NewCMAC(&cb);
    let msg = unhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    );
    let mr: &[byte] = &msg;

    check(
        "CMAC empty message",
        hx(&slice::__from_vec(mac.MAC(empty()).to_vec())),
        "bb1d6929e95937287fa37d129b756746",
    );
    check(
        "CMAC one full block",
        hx(&slice::__from_vec(
            mac.MAC(slice::__from_vec(mr[..16].to_vec())).to_vec(),
        )),
        "070a16b46b4d4144f79bdd9dd04a287c",
    );
    check(
        "CMAC partial final block (40 bytes)",
        hx(&slice::__from_vec(
            mac.MAC(slice::__from_vec(mr[..40].to_vec())).to_vec(),
        )),
        "dfa66747de9ae63030ca32611497c827",
    );
    check(
        "CMAC exact multiple (64 bytes)",
        hx(&slice::__from_vec(
            mac.MAC(slice::__from_vec(mr[..64].to_vec())).to_vec(),
        )),
        "51f0bebf7e3b9d92fc49741779363cfe",
    );

    // ── CounterKDF (SP 800-108r1 §4.1 over CMAC-AES) ──────────────────
    let kdf = gcm::NewCounterKDF(&cb);
    let mut ctx = [0u8; 12];
    check(
        "CounterKDF label=0 context=0",
        hx(&slice::__from_vec(kdf.DeriveKey(0, ctx).to_vec())),
        "5e3d7b0ba53f2c72717b90501a53b3ca72f37a8a2b53f7fc916e8ce50defb1c2",
    );
    let mut i: usize = 0;
    while i < 12 {
        ctx[i] = i as byte;
        i += 1;
    }
    check(
        "CounterKDF label=0x42 context=00..0b",
        hx(&slice::__from_vec(kdf.DeriveKey(0x42, ctx).to_vec())),
        "48ecf11c9dd1ac76fa316533c4dfa9f11e7c236e095d67f3ff2a17aa261e68d8",
    );

    // ── nonce disciplines ─────────────────────────────────────────────
    //
    // TLS 1.3 learns an XOR mask from the first Seal (where the record
    // counter is zero), so a nonce that looks like a large number is
    // really sequence 0. Sealing the same nonce twice must then be
    // rejected as a repeat, which is the whole point of the wrapper.
    let (t13, err) = gcm::NewGCMForTLS13(&b);
    if err != goish::nil {
        fmt::Printf!("FAIL: NewGCMForTLS13 returned %v\n", err);
        unsafe { FAILED = true };
    }
    let mut t13 = t13.unwrap();
    let n0 = unhex("cafebabefacedbaddecaf888");
    let sealedA = t13.Seal(empty(), n0.clone(), unhex(PT), unhex(AAD));
    check(
        "TLS1.3 wrapper seals identically to plain GCM",
        hx(&sealedA),
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
         5bc94fbc3221a5db94fae95ae7121a47",
    );

    // The next record's nonce is the mask XOR 1, which must be accepted.
    let mut n1v: Vec<byte> = {
        let r: &[byte] = &n0;
        r.to_vec()
    };
    n1v[11] ^= 1;
    let _ = t13.Seal(empty(), slice::__from_vec(n1v), unhex(PT), unhex(AAD));
    check(
        "TLS1.3 wrapper accepts the next counter",
        goish::string::from("ok"),
        "ok",
    );

    // TLS 1.2 has no mask: the counter is the raw trailing 64 bits.
    let (t12, err) = gcm::NewGCMForTLS12(&b);
    if err != goish::nil {
        fmt::Printf!("FAIL: NewGCMForTLS12 returned %v\n", err);
        unsafe { FAILED = true };
    }
    let mut t12 = t12.unwrap();
    let sealed12 = t12.Seal(empty(), n0.clone(), unhex(PT), unhex(AAD));
    check(
        "TLS1.2 wrapper seals identically to plain GCM",
        hx(&sealed12),
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
         5bc94fbc3221a5db94fae95ae7121a47",
    );

    // SealWithRandomNonce fills the nonce and the result must decrypt.
    let (gr, _) = gcm::New(&b, 12, 16);
    let gr = gr.unwrap();
    let mut rnonce = slice::__from_vec(alloc::vec![0u8; 12]);
    let ptv = unhex(PT);
    let mut rout = slice::__from_vec(alloc::vec![0u8; (ptv.Len() + 16) as usize]);
    gcm::SealWithRandomNonce(&gr, &mut rnonce, &mut rout, ptv.clone(), unhex(AAD));
    let (rback, err) = gr.Open(empty(), rnonce.clone(), rout.clone(), unhex(AAD));
    if err != goish::nil {
        fmt::Printf!("FAIL: SealWithRandomNonce round-trip: %v\n", err);
        unsafe { FAILED = true };
    }
    check("SealWithRandomNonce round-trips", hx(&rback), PT);

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_gcm_smoke OK\n");
}
