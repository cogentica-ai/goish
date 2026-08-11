// fips140_fiat_smoke — the four NIST prime-field element types of
// crypto/internal/fips140/nistec/fiat.
//
// The arithmetic under these wrappers is 11k lines of Fiat Cryptography
// output translated by scripts/fiat64_to_rust.py. Nothing about that
// translation is reviewable by reading it, so it is checked the only way
// that means anything: every value here is what Go prints for the same
// input, via scripts/goref.sh (AGENTS.md §10).
//
// The checks are chosen for what a mistranslated carry chain would
// survive. `Mul` and `Square` compute a*a by different code paths and
// must agree. `-1 mod p` is the top canonical encoding and depends on
// every limb of the modulus being right. Round-tripping through
// SetBytes/Bytes exercises To/FromMontgomery and To/FromBytes together,
// including the endianness swap.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::internal::fips140::nistec::fiat;
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

fn hx(s: &slice<byte>) -> goish::string {
    let r: &[byte] = s;
    return hex::EncodeToString(r);
}

/// The same deterministic in-range input the Go reference used.
fn seed(n: usize) -> slice<byte> {
    let mut b: Vec<byte> = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        b.push(((i * 7 + 3) & 0xff) as byte);
        i += 1;
    }
    // P-521's top byte holds only 9 bits.
    b[0] &= if n == 66 { 0x01 } else { 0x7f };
    return slice::__from_vec(b);
}

macro_rules! curve_checks {
    ($C:ident, $len:expr, $tag:expr, $a:expr, $mul:expr, $add:expr, $neg1:expr) => {{
        let mut a = fiat::$C::New();
        let err = a.SetBytes(seed($len));
        check(
            concat!($tag, " SetBytes succeeds"),
            fmt::Sprintf!("%v", err == goish::nil),
            "true",
        );
        check(concat!($tag, " round-trips"), hx(&a.Bytes()), $a);

        let mut one = fiat::$C::New();
        one.One();

        // Mul and Square reach a*a by different code paths.
        let mut m = fiat::$C::New();
        m.Mul(a, a);
        check(concat!($tag, " a*a"), hx(&m.Bytes()), $mul);
        let mut s = fiat::$C::New();
        s.Square(a);
        check(concat!($tag, " a^2 == a*a"), hx(&s.Bytes()), $mul);

        let mut p = fiat::$C::New();
        p.Add(a, a);
        check(concat!($tag, " a+a"), hx(&p.Bytes()), $add);

        // -1 mod p is the highest canonical encoding: every limb of the
        // modulus has to be right for this one.
        let mut n = fiat::$C::New();
        n.Sub(fiat::$C::New(), one);
        check(concat!($tag, " -1 mod p"), hx(&n.Bytes()), $neg1);

        // Sub is Add's inverse.
        let mut back = fiat::$C::New();
        back.Sub(p, a);
        check(
            concat!($tag, " (a+a)-a == a"),
            hx(&back.Bytes()),
            hx(&a.Bytes()).as_ref(),
        );
    }};
}

const P256_A: &str = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc";
const P256_MUL: &str = "ca69565f8661aaf6a59eeef81cbf420771da829c259146e4064213e82b49afca";
const P256_ADD: &str = "061422303e4c5a68768492a0aebccad8e6f503111f2d3b49576573818f9dabb8";
const P256_NEG1: &str = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe";

const P224_A: &str = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0";
const P224_MUL: &str = "a9e8ea7d709bef6b0edaceeb2f9c30ed24262182b628457a32dbe1b2";
const P224_ADD: &str = "061422303e4c5a68768492a0aebccad8e6f503111f2d3b4957657380";
const P224_NEG1: &str = "ffffffffffffffffffffffffffffffff000000000000000000000000";

const P384_A: &str = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc\
                      e3eaf1f8ff060d141b222930373e454c";
const P384_MUL: &str = "c075b8baacc0260fae32ceb31119fef121cb3fe21445113d8ecdd7a2233ea7f1\
                      f010947b04b7dc40b40e3f47e8395367";
const P384_ADD: &str = "061422303e4c5a68768492a0aebccad8e6f503111f2d3b49576573818f9dabb9\
                      c7d5e3f1fe0c1a28364452606e7c8a98";
const P384_NEG1: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
                      ffffffff0000000000000000fffffffe";

const P521_A: &str = "010a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc\
                      e3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bc\
                      c3ca";
const P521_MUL: &str = "00ce2e4a8a55122a0304961f06b490006d3dd9a8107a4cefca43c3b1747417c6\
                      e8e5230a020afa372937ca4818a34f84aa2763c6b79de0e81ae0a0c2adc97d30\
                      4a32";
const P521_ADD: &str = "001422303e4c5a68768492a0aebccad8e6f503111f2d3b49576573818f9dabb9\
                      c7d5e3f1fe0c1a28364452606e7c8a98a6b4c2d0deecfb09172533414f5d6b79\
                      8795";
const P521_NEG1: &str = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                      ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                      fffe";

#[goish::main]
fn main() {
    curve_checks!(P224Element, 28, "P-224", P224_A, P224_MUL, P224_ADD, P224_NEG1);
    curve_checks!(P256Element, 32, "P-256", P256_A, P256_MUL, P256_ADD, P256_NEG1);
    curve_checks!(P384Element, 48, "P-384", P384_A, P384_MUL, P384_ADD, P384_NEG1);
    curve_checks!(P521Element, 66, "P-521", P521_A, P521_MUL, P521_ADD, P521_NEG1);

    // ── Select, Equal, IsZero, and the encoding checks (P-256) ────────
    let mut a = fiat::P256Element::New();
    let _ = a.SetBytes(seed(32));
    let mut one = fiat::P256Element::New();
    one.One();
    check(
        "one is 1",
        hx(&one.Bytes()),
        "0000000000000000000000000000000000000000000000000000000000000001",
    );

    let mut s = fiat::P256Element::New();
    s.Select(a, one, 1);
    check("Select(a, one, 1) == a", hx(&s.Bytes()), P256_A);
    let mut s = fiat::P256Element::New();
    s.Select(a, one, 0);
    check(
        "Select(a, one, 0) == one",
        hx(&s.Bytes()),
        "0000000000000000000000000000000000000000000000000000000000000001",
    );

    check("a.Equal(a)", fmt::Sprintf!("%d", a.Equal(a)), "1");
    check("a.Equal(one)", fmt::Sprintf!("%d", a.Equal(one)), "0");
    check("a.IsZero()", fmt::Sprintf!("%d", a.IsZero()), "0");
    check(
        "zero.IsZero()",
        fmt::Sprintf!("%d", fiat::P256Element::New().IsZero()),
        "1",
    );

    let mut e = fiat::P256Element::New();
    check(
        "short encoding rejected",
        fmt::Sprintf!("%v", e.SetBytes(slice::__from_vec(alloc::vec![0u8; 31])).Error()),
        "invalid P256Element encoding",
    );
    check(
        "non-canonical encoding rejected",
        fmt::Sprintf!(
            "%v",
            e.SetBytes(slice::__from_vec(alloc::vec![0xffu8; 32])) != goish::nil
        ),
        "true",
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_fiat_smoke OK\n");
}
