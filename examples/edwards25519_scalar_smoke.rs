// edwards25519_scalar_smoke — exercise
// crypto/internal/fips140/edwards25519/scalar's constant-time mod-l
// arithmetic (the `Scalar` type).
//
// Coverage (ring laws modulo the group order l):
//   1. SetCanonicalBytes -> Bytes round-trip (32-byte little-endian).
//   2. SetCanonicalBytes rejects bad length / non-canonical (>= l).
//   3. Add / Subtract are inverse:  (a + b) - b == a.
//   4. Multiply commutes:  a * b == b * a.
//   5. Multiply is associative:  (a*b)*c == a*(b*c).
//   6. Negate then Add gives 0:  a + (-a) == 0.
//   7. Multiply by 1 / by 0 identities.
//   8. MultiplyAdd matches Multiply then Add.
//   9. SetUniformBytes reduces a 64-byte input mod l.
//  10. Aliasing: s.Multiply(s, t) and s.Add(s, t) behave correctly.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::internal::fips140::edwards25519::scalar::{NewScalar, Scalar};
use goish::types::byte;
use goish::{slice, syscall, Println};

const KB: usize = 1024;

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

// Build a Scalar from a 32-byte canonical little-endian array,
// panicking on error.
fn scalar(b: &[u8; 32]) -> Scalar {
    let mut s = Scalar::new();
    let err = s.SetCanonicalBytes(from_bytes(b));
    if !err.IsNil() {
        panic!("SetCanonicalBytes failed");
    }
    s
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
    goish::go!(stack(256 * KB), || {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run_tests() {
    test_1_canonical_roundtrip();
    test_2_setcanonical_reject();
    test_3_add_subtract_inverse();
    test_4_multiply_commutes();
    test_5_multiply_associative();
    test_6_negate_add_zero();
    test_7_mul_by_one_zero();
    test_8_multiplyadd();
    test_9_setuniformbytes();
    test_10_aliasing();
}

// Fixed canonical 32-byte little-endian scalar encodings. All are
// well below l (top byte <= 0x08, l ~ 2^252).
const A: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];
const B: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x07,
];
const C: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x06,
];

// zero (0) and one (1) as canonical 32-byte encodings.
const ZERO: [u8; 32] = [0u8; 32];
const ONE: [u8; 32] = {
    let mut a = [0u8; 32];
    a[0] = 1;
    a
};

fn test_1_canonical_roundtrip() {
    // SetCanonicalBytes then Bytes reproduces the canonical input.
    let mut ok = true;
    let a = scalar(&A);
    if !slice_eq(&a.Bytes(), &from_bytes(&A)) {
        ok = false;
    }
    let b = scalar(&B);
    if !slice_eq(&b.Bytes(), &from_bytes(&B)) {
        ok = false;
    }
    // zero round-trips.
    let z = scalar(&ZERO);
    if !slice_eq(&z.Bytes(), &from_bytes(&ZERO)) {
        ok = false;
    }
    write_result(1, b"SetCanonicalBytes round-trip ", ok);
    if !ok {
        fail();
    }
}

fn test_2_setcanonical_reject() {
    // Wrong length is rejected; a non-canonical (>= l) encoding is
    // rejected. l - 1 (the largest canonical value) is accepted.
    let mut s = Scalar::new();
    let err31 = s.SetCanonicalBytes(from_bytes(&[0u8; 31]));
    let mut s2 = Scalar::new();
    let err33 = s2.SetCanonicalBytes(from_bytes(&[0u8; 33]));

    // l in little-endian: 2^252 + 27742317777372353535851937790883648493.
    // Top byte 0x10, low 16 bytes are l mod 2^128.
    let l_le: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    // l - 1 (largest reduced value).
    let mut l_minus_one = l_le;
    l_minus_one[0] -= 1;

    let mut s3 = Scalar::new();
    let err_l = s3.SetCanonicalBytes(from_bytes(&l_le)); // == l: non-canonical
    let mut s4 = Scalar::new();
    let err_lm1 = s4.SetCanonicalBytes(from_bytes(&l_minus_one)); // canonical

    let ok = !err31.IsNil()
        && !err33.IsNil()
        && !err_l.IsNil()
        && err_lm1.IsNil();
    write_result(2, b"SetCanonicalBytes rejects    ", ok);
    if !ok {
        fail();
    }
}

fn test_3_add_subtract_inverse() {
    // (a + b) - b == a.
    let a = scalar(&A);
    let b = scalar(&B);
    let mut sum = Scalar::new();
    sum.Add(&a, &b);
    let mut diff = Scalar::new();
    diff.Subtract(&sum, &b);
    let ok = diff.Equal(&a) == 1;
    write_result(3, b"Add/Subtract inverse         ", ok);
    if !ok {
        fail();
    }
}

fn test_4_multiply_commutes() {
    // a * b == b * a.
    let a = scalar(&A);
    let b = scalar(&B);
    let mut ab = Scalar::new();
    ab.Multiply(&a, &b);
    let mut ba = Scalar::new();
    ba.Multiply(&b, &a);
    let ok = ab.Equal(&ba) == 1;
    write_result(4, b"Multiply commutes            ", ok);
    if !ok {
        fail();
    }
}

fn test_5_multiply_associative() {
    // (a * b) * c == a * (b * c).
    let a = scalar(&A);
    let b = scalar(&B);
    let c = scalar(&C);
    let mut ab = Scalar::new();
    ab.Multiply(&a, &b);
    let mut left = Scalar::new();
    left.Multiply(&ab, &c);
    let mut bc = Scalar::new();
    bc.Multiply(&b, &c);
    let mut right = Scalar::new();
    right.Multiply(&a, &bc);
    let ok = left.Equal(&right) == 1;
    write_result(5, b"Multiply associative         ", ok);
    if !ok {
        fail();
    }
}

fn test_6_negate_add_zero() {
    // a + (-a) == 0.
    let zero = scalar(&ZERO);
    let a = scalar(&A);
    let mut neg = Scalar::new();
    neg.Negate(&a);
    let mut sum = Scalar::new();
    sum.Add(&a, &neg);
    let ok = sum.Equal(&zero) == 1;
    write_result(6, b"Negate then Add == 0         ", ok);
    if !ok {
        fail();
    }
}

fn test_7_mul_by_one_zero() {
    // 1 * x == x;  0 * x == 0.
    let one = scalar(&ONE);
    let zero = scalar(&ZERO);
    let a = scalar(&A);
    let mut by_one = Scalar::new();
    by_one.Multiply(&a, &one);
    let ok_one = by_one.Equal(&a) == 1;
    let mut by_zero = Scalar::new();
    by_zero.Multiply(&a, &zero);
    let ok_zero = by_zero.Equal(&zero) == 1;
    // NewScalar() is a valid zero.
    let nz = NewScalar();
    let ok_new = nz.Equal(&zero) == 1;
    let ok = ok_one && ok_zero && ok_new;
    write_result(7, b"Multiply by 1 / by 0         ", ok);
    if !ok {
        fail();
    }
}

fn test_8_multiplyadd() {
    // MultiplyAdd(x,y,z) == Multiply(x,y) then Add(.,z).
    let x = scalar(&A);
    let y = scalar(&B);
    let z = scalar(&C);
    let mut ma = Scalar::new();
    ma.MultiplyAdd(&x, &y, &z);
    let mut expect = Scalar::new();
    expect.Multiply(&x, &y);
    let ex = expect;
    expect.Add(&ex, &z);
    let ok = ma.Equal(&expect) == 1;
    write_result(8, b"MultiplyAdd == Mul then Add  ", ok);
    if !ok {
        fail();
    }
}

fn test_9_setuniformbytes() {
    // SetUniformBytes on 64 bytes reduces mod l. A 64-byte value whose
    // low 32 bytes encode a known reduced scalar `a` and whose high 32
    // bytes are zero must reduce to exactly `a`.
    let mut wide = [0u8; 64];
    wide[0..32].copy_from_slice(&A);
    let mut s = Scalar::new();
    let err = s.SetUniformBytes(from_bytes(&wide));
    let ok_len = err.IsNil();
    let a = scalar(&A);
    let ok_reduce = s.Equal(&a) == 1;
    // Bad length rejected.
    let mut s2 = Scalar::new();
    let err_bad = s2.SetUniformBytes(from_bytes(&[0u8; 63]));
    // A full 64-byte value reduces to *something* canonical and stable.
    let mut full = [0xffu8; 64];
    full[0] = 0xfe;
    let mut sf = Scalar::new();
    let _ = sf.SetUniformBytes(from_bytes(&full));
    let mut sf2 = Scalar::new();
    let _ = sf2.SetUniformBytes(from_bytes(&full));
    let ok_stable = sf.Equal(&sf2) == 1;
    // Result is reduced: re-encoding then SetCanonicalBytes succeeds.
    let mut rt = Scalar::new();
    let err_rt = rt.SetCanonicalBytes(sf.Bytes());
    let ok = ok_len && ok_reduce && !err_bad.IsNil() && ok_stable && err_rt.IsNil();
    write_result(9, b"SetUniformBytes reduces      ", ok);
    if !ok {
        fail();
    }
}

fn test_10_aliasing() {
    // Aliasing receiver and input: s.Multiply(s, t), s.Add(s, t).
    let a = scalar(&A);
    let b = scalar(&B);

    // Reference products.
    let mut ref_mul = Scalar::new();
    ref_mul.Multiply(&a, &b);
    let mut ref_add = Scalar::new();
    ref_add.Add(&a, &b);

    // s.Multiply(s.clone, t): emulate Go's s.Multiply(s, t).
    let mut s = a;
    let s_in = s;
    s.Multiply(&s_in, &b);
    let ok_mul = s.Equal(&ref_mul) == 1;

    let mut s2 = a;
    let s2_in = s2;
    s2.Add(&s2_in, &b);
    let ok_add = s2.Equal(&ref_add) == 1;

    // s.Multiply(s, s) == a*a.
    let mut sq = a;
    let sq_in = sq;
    sq.Multiply(&sq_in, &sq_in);
    let mut ref_sq = Scalar::new();
    ref_sq.Multiply(&a, &a);
    let ok_sq = sq.Equal(&ref_sq) == 1;

    let ok = ok_mul && ok_add && ok_sq;
    write_result(10, b"Aliasing s.Op(s, t)          ", ok);
    if !ok {
        fail();
    }
}
