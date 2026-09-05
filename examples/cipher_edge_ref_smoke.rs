//! Pinned against Go 1.25.5: crypto/aes, crypto/cipher's modes, and
//! crypto/subtle — the EDGE paths, not the happy path.
//!
//! None of these had a reference smoke. The RFC test vectors that
//! normally cover a cipher say nothing about what happens when
//! authentication FAILS, and that is the part where a divergence is a
//! security bug rather than a wrong answer.
//!
//! It measures clean: 23/23 identical to Go, no defects. What is
//! pinned:
//!
//!   * `Open` with a corrupted tag, with the wrong additional data,
//!     and with a truncated ciphertext all return the SAME generic
//!     error — "cipher: message authentication failed" — and an EMPTY
//!     plaintext. Never a partial decrypt, and never a message that
//!     distinguishes which check failed, because distinguishing them
//!     is an oracle.
//!   * aes.NewCipher accepts exactly 16, 24 and 32 bytes and names
//!     the size it refused: "crypto/aes: invalid key size 15".
//!   * GCM's NonceSize is 12 and Overhead is 16.
//!   * CTR is a stream — running it twice returns the plaintext — and
//!     CBC round-trips on a block multiple. Both ciphertexts are
//!     pinned byte for byte, so a change in either mode's block
//!     chaining shows up here and not in a TLS handshake three
//!     packages away.
//!   * subtle.ConstantTimeCompare answers 0 for DIFFERENT LENGTHS and
//!     1 for two empty slices. The length case is the one a
//!     reimplementation gets wrong, and it is what stops the function
//!     leaking a length through an early return.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh crypto/cipher <cipher_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::crypto::aes;
use goish::crypto::cipher::{self, BlockMode, Stream, AEAD};
use goish::crypto::subtle;
use goish::encoding::hex;
use goish::types::byte;
use goish::{fmt, make, slice, string};
/// Go's output, verbatim.
const GO: [&str; 24] = [
    "aes-16                     err=\"<nil>\" blockSize=16",
    "aes-keysize                n=0   err=\"crypto/aes: invalid key size 0\"",
    "aes-keysize                n=15  err=\"crypto/aes: invalid key size 15\"",
    "aes-keysize                n=17  err=\"crypto/aes: invalid key size 17\"",
    "aes-keysize                n=24  err=\"<nil>\"",
    "aes-keysize                n=32  err=\"<nil>\"",
    "aes-keysize                n=33  err=\"crypto/aes: invalid key size 33\"",
    "gcm                        err=\"<nil>\" nonceSize=12 overhead=16",
    "gcm-seal                   ct=21b3eb3ff6bbd1e391e51e4941a091bc4cf779e8cb396b4891a44087423778b5",
    "gcm-open                   pt=\"hello world!!!!!\" err=\"<nil>\"",
    "gcm-open-badtag            pt=\"\" err=\"cipher: message authentication failed\"",
    "gcm-open-badaad            pt=\"\" err=\"cipher: message authentication failed\"",
    "gcm-open-short             pt=\"\" err=\"cipher: message authentication failed\"",
    "ctr-encrypt                ct=aec4575be8af2ced1d23e54380e9f958",
    "ctr-roundtrip              pt=\"hello world!!!!!\"",
    "cbc-encrypt                ct=e00de18f7048e7bb77a1a3b8e8f6fa65",
    "cbc-roundtrip              pt=\"hello world!!!!!\"",
    "subtle-eq                  eq=1",
    "subtle-ne                  ne=0",
    "subtle-difflen             len=0",
    "subtle-empty               empty=1",
    "subtle-select              sel=7 9",
    "subtle-byteeq              byteeq=1 0",
    "subtle-less                less=1 0",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

fn es(e: goish::error) -> string {
    if e.IsNil() {
        string("<nil>")
    } else {
        e.Error()
    }
}

/// Compare one rendered line against the Go reference, in order.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    let want = string::from_static(GO[i]);
    if got == want {
        return;
    }
    fmt::Printf!("DIFF go   : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    unsafe { FAILED += 1 };
}
#[goish::main]
fn main() {
    let mut key = make!([]byte, 16);
    for i in 0..16 {
        key[i] = i as u8;
    }
    let (blk, err) = aes::NewCipher(key.clone());
    let b = blk.unwrap();
    chk(fmt::Sprintf!(
        "%-26s err=%q blockSize=%d",
        string("aes-16"),
        es(err),
        b.BlockSize()
    ));

    for n in [0usize, 15, 17, 24, 32, 33] {
        let (_k, e) = aes::NewCipher(make!([]byte, n as goish::int));
        chk(fmt::Sprintf!(
            "%-26s n=%-3d err=%q",
            string("aes-keysize"),
            n as i64,
            es(e)
        ));
    }

    let nonce = make!([]byte, 12);
    let (g, ge) = cipher::NewGCM(b.clone());
    let g = g.unwrap();
    chk(fmt::Sprintf!(
        "%-26s err=%q nonceSize=%d overhead=%d",
        string("gcm"),
        es(ge),
        g.NonceSize(),
        g.Overhead()
    ));

    let pt = goish::convert::bytes(string("hello world!!!!!"));
    let ct = g.Seal(
        slice::<u8>::new(),
        nonce.clone(),
        pt.clone(),
        slice::<u8>::new(),
    );
    chk(fmt::Sprintf!(
        "%-26s ct=%s",
        string("gcm-seal"),
        hex::EncodeToString(&ct.to_vec())
    ));

    let (got, oe) = g.Open(
        slice::<u8>::new(),
        nonce.clone(),
        ct.clone(),
        slice::<u8>::new(),
    );
    chk(fmt::Sprintf!(
        "%-26s pt=%q err=%q",
        string("gcm-open"),
        string::from_bytes(&got.to_vec()),
        es(oe)
    ));

    let mut bad = ct.clone();
    let last = bad.Len() - 1;
    bad[last] ^= 1;
    let (g2, oe2) = g.Open(slice::<u8>::new(), nonce.clone(), bad, slice::<u8>::new());
    chk(fmt::Sprintf!(
        "%-26s pt=%q err=%q",
        string("gcm-open-badtag"),
        string::from_bytes(&g2.to_vec()),
        es(oe2)
    ));

    let (g3, oe3) = g.Open(
        slice::<u8>::new(),
        nonce.clone(),
        ct.clone(),
        goish::convert::bytes(string("aad")),
    );
    chk(fmt::Sprintf!(
        "%-26s pt=%q err=%q",
        string("gcm-open-badaad"),
        string::from_bytes(&g3.to_vec()),
        es(oe3)
    ));

    let short = ct.slice(0, 3);
    let (g4, oe4) = g.Open(slice::<u8>::new(), nonce.clone(), short, slice::<u8>::new());
    chk(fmt::Sprintf!(
        "%-26s pt=%q err=%q",
        string("gcm-open-short"),
        string::from_bytes(&g4.to_vec()),
        es(oe4)
    ));

    let iv = make!([]byte, 16);
    let mut s = cipher::NewCTR(b.clone(), iv.clone());
    let mut buf = make!([]byte, pt.Len());
    s.XORKeyStream(&mut buf, pt.clone());
    chk(fmt::Sprintf!(
        "%-26s ct=%s",
        string("ctr-encrypt"),
        hex::EncodeToString(&buf.to_vec())
    ));
    let mut s2 = cipher::NewCTR(b.clone(), iv.clone());
    let mut out = make!([]byte, buf.Len());
    s2.XORKeyStream(&mut out, buf.clone());
    chk(fmt::Sprintf!(
        "%-26s pt=%q",
        string("ctr-roundtrip"),
        string::from_bytes(&out.to_vec())
    ));

    let mut enc = cipher::NewCBCEncrypter(b.clone(), iv.clone());
    let mut cb = make!([]byte, pt.Len());
    enc.CryptBlocks(&mut cb, pt.clone());
    chk(fmt::Sprintf!(
        "%-26s ct=%s",
        string("cbc-encrypt"),
        hex::EncodeToString(&cb.to_vec())
    ));
    let mut dec = cipher::NewCBCDecrypter(b.clone(), iv.clone());
    let mut pb = make!([]byte, cb.Len());
    dec.CryptBlocks(&mut pb, cb.clone());
    chk(fmt::Sprintf!(
        "%-26s pt=%q",
        string("cbc-roundtrip"),
        string::from_bytes(&pb.to_vec())
    ));

    let abc = goish::convert::bytes(string("abc"));
    let abd = goish::convert::bytes(string("abd"));
    let ab = goish::convert::bytes(string("ab"));
    let empty = slice::<u8>::new();
    chk(fmt::Sprintf!(
        "%-26s eq=%d",
        string("subtle-eq"),
        subtle::ConstantTimeCompare(&abc, &abc) as i64
    ));
    chk(fmt::Sprintf!(
        "%-26s ne=%d",
        string("subtle-ne"),
        subtle::ConstantTimeCompare(&abc, &abd) as i64
    ));
    chk(fmt::Sprintf!(
        "%-26s len=%d",
        string("subtle-difflen"),
        subtle::ConstantTimeCompare(&abc, &ab) as i64
    ));
    chk(fmt::Sprintf!(
        "%-26s empty=%d",
        string("subtle-empty"),
        subtle::ConstantTimeCompare(&empty, &empty) as i64
    ));
    chk(fmt::Sprintf!(
        "%-26s sel=%d %d",
        string("subtle-select"),
        subtle::ConstantTimeSelect(1, 7, 9) as i64,
        subtle::ConstantTimeSelect(0, 7, 9) as i64
    ));
    chk(fmt::Sprintf!(
        "%-26s byteeq=%d %d",
        string("subtle-byteeq"),
        subtle::ConstantTimeByteEq(3, 3) as i64,
        subtle::ConstantTimeByteEq(3, 4) as i64
    ));
    chk(fmt::Sprintf!(
        "%-26s less=%d %d",
        string("subtle-less"),
        subtle::ConstantTimeLessOrEq(3, 4) as i64,
        subtle::ConstantTimeLessOrEq(5, 4) as i64
    ));
    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("crypto cipher/subtle: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}
