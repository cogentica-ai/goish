// edwards25519_field_smoke — exercise
// crypto/internal/fips140/edwards25519/field's constant-time GF(2^255-19)
// arithmetic (the `Element` type).
//
// Coverage:
//   1. SetBytes -> Bytes round-trip (32-byte little-endian).
//   2. SetBytes rejects a wrong-length input.
//   3. Add / Subtract are inverse:  (a + b) - b == a.
//   4. Multiply commutes:  a * b == b * a.
//   5. Square agrees with Multiply:  a * a == Square(a).
//   6. Invert:  a * a⁻¹ == 1 for several a (and 1⁻¹ == 1).
//   7. Negate then Add gives 0:  a + (-a) == 0.
//   8. Multiply by 1 / by 0 identities.
//   9. Select / Swap with mask 0 and 1 (constant-time select).
//  10. IsNegative / Absolute.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::crypto::internal::fips140::edwards25519::field::Element;
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

fn slice_eq(a: &goish::slice<byte>, b: &goish::slice<byte>) -> bool {
    if a.Len() != b.Len() {
        return false;
    }
    let mut i: goish::int = 0;
    while i < a.Len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

// Build an Element from a 32-byte little-endian array, panicking on error.
fn elem(b: &[u8; 32]) -> Element {
    let mut e = Element::new();
    let err = e.SetBytes(from_bytes(b));
    if !err.IsNil() {
        panic!("SetBytes failed");
    }
    e
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
    test_1_setbytes_roundtrip();
    test_2_setbytes_badlen();
    test_3_add_subtract_inverse();
    test_4_multiply_commutes();
    test_5_square_eq_multiply();
    test_6_invert();
    test_7_negate_add_zero();
    test_8_mul_by_one_zero();
    test_9_select_swap();
    test_10_isnegative_absolute();
}

// A handful of fixed 32-byte little-endian Element encodings. The high
// bit of the last byte is ignored by SetBytes, so all are canonical.
const A: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];
const B: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x07,
];

fn test_1_setbytes_roundtrip() {
    // SetBytes then Bytes should reproduce the (canonical) input. A and
    // B are below 2^255-19 so they are already canonical.
    let mut ok = true;
    let a = elem(&A);
    let out = a.Bytes();
    if !slice_eq(&out, &from_bytes(&A)) {
        ok = false;
    }
    let b = elem(&B);
    if !slice_eq(&b.Bytes(), &from_bytes(&B)) {
        ok = false;
    }
    write_result(1, b"SetBytes/Bytes round-trip    ", ok);
    if !ok {
        fail();
    }
}

fn test_2_setbytes_badlen() {
    // Wrong-length input must be rejected; the receiver is unchanged.
    let mut e = Element::new();
    let err31 = e.SetBytes(from_bytes(&[0u8; 31]));
    let mut e2 = Element::new();
    let err33 = e2.SetBytes(from_bytes(&[0u8; 33]));
    let mut e3 = Element::new();
    let err32 = e3.SetBytes(from_bytes(&[0u8; 32]));
    let ok = !err31.IsNil() && !err33.IsNil() && err32.IsNil();
    write_result(2, b"SetBytes bad-length guard    ", ok);
    if !ok {
        fail();
    }
}

fn test_3_add_subtract_inverse() {
    // (a + b) - b == a.
    let a = elem(&A);
    let b = elem(&B);
    let mut sum = Element::new();
    sum.Add(&a, &b);
    let mut diff = Element::new();
    diff.Subtract(&sum, &b);
    let ok = diff.Equal(&a) == 1;
    write_result(3, b"Add/Subtract inverse         ", ok);
    if !ok {
        fail();
    }
}

fn test_4_multiply_commutes() {
    // a * b == b * a.
    let a = elem(&A);
    let b = elem(&B);
    let mut ab = Element::new();
    ab.Multiply(&a, &b);
    let mut ba = Element::new();
    ba.Multiply(&b, &a);
    let ok = ab.Equal(&ba) == 1;
    write_result(4, b"Multiply commutes            ", ok);
    if !ok {
        fail();
    }
}

fn test_5_square_eq_multiply() {
    // a * a == Square(a). Also exercise the aliasing form v.Square(&v).
    let a = elem(&A);
    let mut sq = Element::new();
    sq.Square(&a);
    let mut prod = Element::new();
    prod.Multiply(&a, &a);
    let ok_basic = sq.Equal(&prod) == 1;
    // Aliasing: v.Square(&v.clone()) — receiver also the input.
    let mut v = elem(&B);
    let vc = v;
    v.Square(&vc);
    let mut bsq = Element::new();
    bsq.Multiply(&vc, &vc);
    let ok_alias = v.Equal(&bsq) == 1;
    let ok = ok_basic && ok_alias;
    write_result(5, b"Square == Multiply           ", ok);
    if !ok {
        fail();
    }
}

fn test_6_invert() {
    // a * a⁻¹ == 1 for several a; and 1⁻¹ == 1.
    let mut one = Element::new();
    one.One();
    let mut ok = true;
    let inputs: [[u8; 32]; 2] = [A, B];
    for inp in inputs.iter() {
        let a = elem(inp);
        let mut inv = Element::new();
        inv.Invert(&a);
        let mut prod = Element::new();
        prod.Multiply(&a, &inv);
        if prod.Equal(&one) != 1 {
            ok = false;
        }
    }
    // 1⁻¹ == 1.
    let mut invone = Element::new();
    invone.Invert(&one);
    if invone.Equal(&one) != 1 {
        ok = false;
    }
    write_result(6, b"Invert: a * a^-1 == 1        ", ok);
    if !ok {
        fail();
    }
}

fn test_7_negate_add_zero() {
    // a + (-a) == 0.
    let mut zero = Element::new();
    zero.Zero();
    let a = elem(&A);
    let mut neg = Element::new();
    neg.Negate(&a);
    let mut sum = Element::new();
    sum.Add(&a, &neg);
    let ok = sum.Equal(&zero) == 1;
    write_result(7, b"Negate then Add == 0         ", ok);
    if !ok {
        fail();
    }
}

fn test_8_mul_by_one_zero() {
    // a * 1 == a;  a * 0 == 0.
    let mut one = Element::new();
    one.One();
    let mut zero = Element::new();
    zero.Zero();
    let a = elem(&A);
    let mut by_one = Element::new();
    by_one.Multiply(&a, &one);
    let ok_one = by_one.Equal(&a) == 1;
    let mut by_zero = Element::new();
    by_zero.Multiply(&a, &zero);
    let ok_zero = by_zero.Equal(&zero) == 1;
    let ok = ok_one && ok_zero;
    write_result(8, b"Multiply by 1 / by 0         ", ok);
    if !ok {
        fail();
    }
}

fn test_9_select_swap() {
    // Select: cond 1 -> a, cond 0 -> b.
    let a = elem(&A);
    let b = elem(&B);
    let mut s1 = Element::new();
    s1.Select(&a, &b, 1);
    let mut s0 = Element::new();
    s0.Select(&a, &b, 0);
    let ok_sel = s1.Equal(&a) == 1 && s0.Equal(&b) == 1;
    // Swap with cond 0: unchanged. cond 1: swapped.
    let mut x0 = elem(&A);
    let mut y0 = elem(&B);
    x0.Swap(&mut y0, 0);
    let ok_swap0 = x0.Equal(&a) == 1 && y0.Equal(&b) == 1;
    let mut x1 = elem(&A);
    let mut y1 = elem(&B);
    x1.Swap(&mut y1, 1);
    let ok_swap1 = x1.Equal(&b) == 1 && y1.Equal(&a) == 1;
    let ok = ok_sel && ok_swap0 && ok_swap1;
    write_result(9, b"Select / Swap (mask 0,1)     ", ok);
    if !ok {
        fail();
    }
}

fn test_10_isnegative_absolute() {
    // IsNegative is the low bit of the canonical encoding. Absolute(u)
    // is non-negative, and equals u or -u.
    let mut ok = true;
    let inputs: [[u8; 32]; 2] = [A, B];
    for inp in inputs.iter() {
        let u = elem(inp);
        let mut neg = Element::new();
        neg.Negate(&u);
        // Exactly one of u, -u is negative (unless u == 0; A,B != 0).
        let un = u.IsNegative();
        let nn = neg.IsNegative();
        if un + nn != 1 {
            ok = false;
        }
        let mut absu = Element::new();
        absu.Absolute(&u);
        if absu.IsNegative() != 0 {
            ok = false;
        }
        // Absolute(u) is u or -u.
        if absu.Equal(&u) != 1 && absu.Equal(&neg) != 1 {
            ok = false;
        }
    }
    write_result(10, b"IsNegative / Absolute        ", ok);
    if !ok {
        fail();
    }
}
