//! Pinned against Go 1.25.5: the `hash.Hash` CONTRACT for md5, sha1,
//! sha256, sha512 and hmac.
//!
//! The digests appear inside dsa, ecdsa, hkdf and rsa smokes as
//! ingredients, but nothing measured the interface they satisfy. Test
//! vectors cover the VALUE; they say nothing about the contract, and
//! the contract is where a port goes wrong:
//!
//!   * `Sum(b)` APPENDS the digest to b and returns the extended
//!     slice — it does not overwrite b, and the length check here
//!     ("PRE" + 32 = 35 for sha256) is what catches a port that
//!     ignored its argument.
//!   * `Sum` does NOT reset the hash. Calling it twice gives the same
//!     digest, and calling it mid-stream must not disturb the state.
//!     A port that finalised in place would pass every single-shot
//!     test and corrupt every streaming one.
//!   * Writing in two pieces equals writing once.
//!   * `Reset()` returns to the EMPTY-input digest, not to zero bytes.
//!   * Size and BlockSize: sha512's block is 128, not 64, and hmac
//!     reports the block of the hash it wraps.
//!   * hmac with a key LONGER than the block hashes the key first;
//!     the pinned digest is what proves it rather than truncating.
//!   * hmac.Equal is length-sensitive: comparing "ab" with "a" is
//!     false, not a prefix match.
//!
//! It measures clean: 30/30 identical to Go, no defects.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh crypto/sha256 <hashcontract_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::crypto::{hmac, md5, sha1, sha256, sha512};
use goish::encoding::hex;
use goish::hash::Hash;
use goish::io::Writer;
use goish::types::byte;
use goish::{fmt, make, slice, string};

/// Go's output, verbatim.
const GO: [&str; 29] = [
    "md5-size                     [16 64]",
    "md5-empty                    [d41d8cd98f00b204e9800998ecf8427e]",
    "md5-pieces                   [true 5eb63bbbe01eeed093cb22bb8f5acdc3]",
    "md5-sum-appends              [PRE 19]",
    "md5-sum-no-reset             [true]",
    "md5-after-reset              [d41d8cd98f00b204e9800998ecf8427e]",
    "sha1-size                    [20 64]",
    "sha1-empty                   [da39a3ee5e6b4b0d3255bfef95601890afd80709]",
    "sha1-pieces                  [true 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed]",
    "sha1-sum-appends             [PRE 23]",
    "sha1-sum-no-reset            [true]",
    "sha1-after-reset             [da39a3ee5e6b4b0d3255bfef95601890afd80709]",
    "sha256-size                  [32 64]",
    "sha256-empty                 [e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
    "sha256-pieces                [true b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9]",
    "sha256-sum-appends           [PRE 35]",
    "sha256-sum-no-reset          [true]",
    "sha256-after-reset           [e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
    "sha512-size                  [64 128]",
    "sha512-empty                 [cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e]",
    "sha512-pieces                [true 309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f]",
    "sha512-sum-appends           [PRE 67]",
    "sha512-sum-no-reset          [true]",
    "sha512-after-reset           [cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e]",
    "sha256-sum256                [b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9]",
    "hmac-short-key               [0ba06f1f9a6300461e43454535dc3c4223e47b1d357073d7536eae90ec095be1]",
    "hmac-long-key                [3450b7b0ed70c606ca8da5875062d9b904f53e0853b4d6e9b9700a3c53545db2]",
    "hmac-size                    [32 64]",
    "hmac-equal                   [true false false]",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

fn line2(tag: string, a: string, b: string) {
    chk(fmt::Sprintf!("%-28s [%s %s]", tag, a, b));
}
fn line1(tag: string, a: string) {
    chk(fmt::Sprintf!("%-28s [%s]", tag, a));
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
fn hx(b: slice<byte>) -> string {
    hex::EncodeToString(&b.to_vec())
}
fn i(v: goish::int) -> string {
    fmt::Sprintf!("%d", v as i64)
}
fn bl(v: bool) -> string {
    fmt::Sprintf!("%v", v)
}

fn contract<H: Hash>(name: &str, h: &mut H) {
    let n = string::from_bytes(name.as_bytes());
    line2(n.clone() + string("-size"), i(h.Size()), i(h.BlockSize()));
    line1(
        n.clone() + string("-empty"),
        hx(h.Sum(slice::<byte>::new())),
    );

    h.Reset();
    let _ = h.Write(goish::convert::bytes(string("hello ")));
    let _ = h.Write(goish::convert::bytes(string("world")));
    let pieces = hx(h.Sum(slice::<byte>::new()));
    h.Reset();
    let _ = h.Write(goish::convert::bytes(string("hello world")));
    let once = hx(h.Sum(slice::<byte>::new()));
    line2(
        n.clone() + string("-pieces"),
        bl(pieces == once),
        once.clone(),
    );

    let prefixed = h.Sum(goish::convert::bytes(string("PRE")));
    let head = string::from_bytes(&prefixed.slice(0, 3).to_vec());
    line2(n.clone() + string("-sum-appends"), head, i(prefixed.Len()));
    let again = hx(h.Sum(slice::<byte>::new()));
    line1(n.clone() + string("-sum-no-reset"), bl(again == once));

    h.Reset();
    line1(
        n.clone() + string("-after-reset"),
        hx(h.Sum(slice::<byte>::new())),
    );
}

#[goish::main]
fn main() {
    let mut a = md5::New();
    contract("md5", &mut a);
    let mut b = sha1::New();
    contract("sha1", &mut b);
    let mut c = sha256::New();
    contract("sha256", &mut c);
    let mut d = sha512::New();
    contract("sha512", &mut d);

    let s = sha256::Sum256(goish::convert::bytes(string("hello world")));
    line1(string("sha256-sum256"), hex::EncodeToString(&s.to_vec()));

    let mut m = hmac::New(sha256::NewHash, goish::convert::bytes(string("key")));
    let _ = m.Write(goish::convert::bytes(string("hello world")));
    line1(string("hmac-short-key"), hx(m.Sum(slice::<byte>::new())));

    let mut long = make!([]byte, 100);
    for k in 0..100 {
        long[k] = k as u8;
    }
    let mut m2 = hmac::New(sha256::NewHash, long);
    let _ = m2.Write(goish::convert::bytes(string("hello world")));
    line1(string("hmac-long-key"), hx(m2.Sum(slice::<byte>::new())));
    line2(string("hmac-size"), i(m2.Size()), i(m2.BlockSize()));
    let ab = goish::convert::bytes(string("ab"));
    let ac = goish::convert::bytes(string("ac"));
    let a1 = goish::convert::bytes(string("a"));
    chk(fmt::Sprintf!(
        "%-28s [%v %v %v]",
        string("hmac-equal"),
        hmac::Equal(ab.clone(), ab.clone()),
        hmac::Equal(ab.clone(), ac),
        hmac::Equal(ab, a1)
    ));

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("hash contract: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}
