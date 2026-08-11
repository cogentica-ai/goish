// edwards25519_point_smoke — exercise
// crypto/internal/fips140/edwards25519's `Point` type: extended-
// coordinate group arithmetic and constant- / variable-time scalar
// multiplication.
//
// Coverage (group laws on the edwards25519 curve):
//   1. NewGeneratorPoint -> Bytes -> SetBytes round-trips; the
//      canonical basepoint encoding (RFC 8032) decodes correctly.
//   2. NewIdentityPoint is the additive identity:  P + I == P.
//   3. Add commutes:  P + Q == Q + P.
//   4. Negate is the additive inverse:  P + (-P) == I.
//   5. Subtract matches Add of the negation:  P - Q == P + (-Q).
//   6. ScalarBaseMult(s) == ScalarMult(s, generator) for several s.
//   7. ScalarBaseMult(0) == identity;  ScalarBaseMult(1) == generator.
//   8. ScalarBaseMult is a homomorphism:
//      ScalarBaseMult(a+b) == ScalarBaseMult(a) + ScalarBaseMult(b).
//   9. VarTimeDoubleScalarBaseMult(a, A, b) == a*A + b*B.
//  10. MultByCofactor(P) == 8*P;  aliasing P.Add(P, P) doubles.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::crypto::internal::fips140::edwards25519::Scalar;
use goish::crypto::internal::fips140::edwards25519::{
    NewGeneratorPoint, NewIdentityPoint, Point,
};
use goish::types::byte;
use goish::{slice, syscall};

static FAILED: AtomicUsize = AtomicUsize::new(0);
const TOTAL: u8 = 10;

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

// Build a Scalar from a 32-byte canonical little-endian array.
fn scalar(b: &[u8; 32]) -> Scalar {
    let mut s = Scalar::new();
    let err = s.SetCanonicalBytes(from_bytes(b));
    if !err.IsNil() {
        panic!("SetCanonicalBytes failed");
    }
    s
}

// Build a Scalar from a small u64 (little-endian canonical encoding).
fn scalar_u64(n: u64) -> Scalar {
    let mut b = [0u8; 32];
    let le = n.to_le_bytes();
    b[0..8].copy_from_slice(&le);
    scalar(&b)
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
    test_1_generator_roundtrip();
    test_2_identity();
    test_3_add_commutes();
    test_4_negate_inverse();
    test_5_subtract();
    test_6_basemult_vs_mult();
    test_7_basemult_known();
    test_8_basemult_homomorphism();
    test_9_double_scalar_basemult();
    test_10_cofactor_and_aliasing();
}

// The canonical Ed25519 basepoint encoding (RFC 8032, little-endian
// y-coordinate with x sign bit). 0x66 repeated; first byte 0x58.
const BASEPOINT: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

// The identity (point at infinity) encoding: y = 1, x = 0.
const IDENTITY: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

// A few small canonical scalars (well below the group order l).
const SA: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];
const SB: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x07,
];

fn test_1_generator_roundtrip() {
    // NewGeneratorPoint encodes to the canonical basepoint; that
    // encoding decodes back to an equivalent point.
    let mut ok = true;
    let g = NewGeneratorPoint();
    let enc = g.Bytes();
    if !slice_eq(&enc, &from_bytes(&BASEPOINT)) {
        ok = false;
    }
    let mut g2 = Point::new();
    let err = g2.SetBytes(from_bytes(&BASEPOINT));
    if !err.IsNil() {
        ok = false;
    }
    if g2.Equal(&g) != 1 {
        ok = false;
    }
    // Round-trip a derived point as well.
    let mut p = Point::new();
    p.ScalarBaseMult(&scalar(&SA));
    let mut p2 = Point::new();
    let err2 = p2.SetBytes(p.Bytes());
    if !err2.IsNil() || p2.Equal(&p) != 1 {
        ok = false;
    }
    write_result(1, b"Generator <-> Bytes round-trip ", ok);
    if !ok {
        fail();
    }
}

fn test_2_identity() {
    // P + I == P  and  I + P == P  for several points P.
    let mut ok = true;
    let id = NewIdentityPoint();
    // SetBytes of the identity encoding equals NewIdentityPoint.
    let mut id2 = Point::new();
    let err = id2.SetBytes(from_bytes(&IDENTITY));
    if !err.IsNil() || id2.Equal(&id) != 1 {
        ok = false;
    }
    let g = NewGeneratorPoint();
    let mut sum = Point::new();
    sum.Add(&g, &id);
    if sum.Equal(&g) != 1 {
        ok = false;
    }
    let mut sum2 = Point::new();
    sum2.Add(&id, &g);
    if sum2.Equal(&g) != 1 {
        ok = false;
    }
    // I + I == I.
    let mut ii = Point::new();
    ii.Add(&id, &id);
    if ii.Equal(&id) != 1 {
        ok = false;
    }
    write_result(2, b"Identity is additive identity  ", ok);
    if !ok {
        fail();
    }
}

fn test_3_add_commutes() {
    // P + Q == Q + P.
    let mut p = Point::new();
    p.ScalarBaseMult(&scalar(&SA));
    let mut q = Point::new();
    q.ScalarBaseMult(&scalar(&SB));
    let mut pq = Point::new();
    pq.Add(&p, &q);
    let mut qp = Point::new();
    qp.Add(&q, &p);
    let ok = pq.Equal(&qp) == 1;
    write_result(3, b"Add commutes                   ", ok);
    if !ok {
        fail();
    }
}

fn test_4_negate_inverse() {
    // P + (-P) == I.
    let mut ok = true;
    let id = NewIdentityPoint();
    let g = NewGeneratorPoint();
    let mut neg = Point::new();
    neg.Negate(&g);
    let mut sum = Point::new();
    sum.Add(&g, &neg);
    if sum.Equal(&id) != 1 {
        ok = false;
    }
    // -(-P) == P.
    let mut negneg = Point::new();
    negneg.Negate(&neg);
    if negneg.Equal(&g) != 1 {
        ok = false;
    }
    write_result(4, b"Negate is additive inverse     ", ok);
    if !ok {
        fail();
    }
}

fn test_5_subtract() {
    // P - Q == P + (-Q),  and  P - P == I.
    let mut ok = true;
    let id = NewIdentityPoint();
    let mut p = Point::new();
    p.ScalarBaseMult(&scalar(&SA));
    let mut q = Point::new();
    q.ScalarBaseMult(&scalar(&SB));
    let mut diff = Point::new();
    diff.Subtract(&p, &q);
    let mut negq = Point::new();
    negq.Negate(&q);
    let mut addneg = Point::new();
    addneg.Add(&p, &negq);
    if diff.Equal(&addneg) != 1 {
        ok = false;
    }
    let mut self_diff = Point::new();
    self_diff.Subtract(&p, &p);
    if self_diff.Equal(&id) != 1 {
        ok = false;
    }
    write_result(5, b"Subtract == Add of negation    ", ok);
    if !ok {
        fail();
    }
}

fn test_6_basemult_vs_mult() {
    // ScalarBaseMult(s) == ScalarMult(s, generator) for several s.
    let mut ok = true;
    let g = NewGeneratorPoint();
    let scalars = [scalar(&SA), scalar(&SB), scalar_u64(2), scalar_u64(255)];
    for s in scalars.iter() {
        let mut base = Point::new();
        base.ScalarBaseMult(s);
        let mut var = Point::new();
        var.ScalarMult(s, &g);
        if base.Equal(&var) != 1 {
            ok = false;
        }
    }
    write_result(6, b"ScalarBaseMult == ScalarMult   ", ok);
    if !ok {
        fail();
    }
}

fn test_7_basemult_known() {
    // ScalarBaseMult(0) == identity;  ScalarBaseMult(1) == generator.
    let mut ok = true;
    let id = NewIdentityPoint();
    let g = NewGeneratorPoint();
    let mut p0 = Point::new();
    p0.ScalarBaseMult(&scalar_u64(0));
    if p0.Equal(&id) != 1 {
        ok = false;
    }
    let mut p1 = Point::new();
    p1.ScalarBaseMult(&scalar_u64(1));
    if p1.Equal(&g) != 1 {
        ok = false;
    }
    // ScalarMult(0, G) == I  and  ScalarMult(1, G) == G.
    let mut m0 = Point::new();
    m0.ScalarMult(&scalar_u64(0), &g);
    if m0.Equal(&id) != 1 {
        ok = false;
    }
    let mut m1 = Point::new();
    m1.ScalarMult(&scalar_u64(1), &g);
    if m1.Equal(&g) != 1 {
        ok = false;
    }
    write_result(7, b"ScalarBaseMult 0/1 known       ", ok);
    if !ok {
        fail();
    }
}

fn test_8_basemult_homomorphism() {
    // ScalarBaseMult(a+b) == ScalarBaseMult(a) + ScalarBaseMult(b).
    let mut ok = true;
    let a = scalar(&SA);
    let b = scalar(&SB);
    let mut apb = Scalar::new();
    apb.Add(&a, &b);

    let mut lhs = Point::new();
    lhs.ScalarBaseMult(&apb);

    let mut pa = Point::new();
    pa.ScalarBaseMult(&a);
    let mut pb = Point::new();
    pb.ScalarBaseMult(&b);
    let mut rhs = Point::new();
    rhs.Add(&pa, &pb);

    if lhs.Equal(&rhs) != 1 {
        ok = false;
    }

    // 2*G == G + G  via small scalars.
    let mut two_g = Point::new();
    two_g.ScalarBaseMult(&scalar_u64(2));
    let g = NewGeneratorPoint();
    let mut g_plus_g = Point::new();
    g_plus_g.Add(&g, &g);
    if two_g.Equal(&g_plus_g) != 1 {
        ok = false;
    }
    write_result(8, b"ScalarBaseMult homomorphism    ", ok);
    if !ok {
        fail();
    }
}

fn test_9_double_scalar_basemult() {
    // VarTimeDoubleScalarBaseMult(a, A, b) == a*A + b*B.
    let mut ok = true;
    let a = scalar(&SA);
    let b = scalar(&SB);

    // A is an arbitrary curve point (b'*B for some scalar b').
    let mut A = Point::new();
    A.ScalarBaseMult(&scalar_u64(7));

    let mut got = Point::new();
    got.VarTimeDoubleScalarBaseMult(&a, &A, &b);

    let mut aA = Point::new();
    aA.ScalarMult(&a, &A);
    let mut bB = Point::new();
    bB.ScalarBaseMult(&b);
    let mut want = Point::new();
    want.Add(&aA, &bB);

    if got.Equal(&want) != 1 {
        ok = false;
    }

    // Edge: a=0, b=1 -> result is the generator.
    let g = NewGeneratorPoint();
    let mut edge = Point::new();
    edge.VarTimeDoubleScalarBaseMult(&scalar_u64(0), &A, &scalar_u64(1));
    if edge.Equal(&g) != 1 {
        ok = false;
    }
    // Edge: a=1, b=0 -> result is A.
    let mut edge2 = Point::new();
    edge2.VarTimeDoubleScalarBaseMult(&scalar_u64(1), &A, &scalar_u64(0));
    if edge2.Equal(&A) != 1 {
        ok = false;
    }
    write_result(9, b"VarTimeDoubleScalarBaseMult    ", ok);
    if !ok {
        fail();
    }
}

fn test_10_cofactor_and_aliasing() {
    // MultByCofactor(P) == 8*P  and aliasing P.Add(P, P) doubles P.
    let mut ok = true;
    let g = NewGeneratorPoint();

    let mut cof = Point::new();
    cof.MultByCofactor(&g);
    let mut eight_g = Point::new();
    eight_g.ScalarBaseMult(&scalar_u64(8));
    if cof.Equal(&eight_g) != 1 {
        ok = false;
    }

    // Aliasing: p.Add(p, p) must double p (snapshot inputs).
    let mut p = NewGeneratorPoint();
    let p_in = p;
    p.Add(&p_in, &p_in);
    let mut two_g = Point::new();
    two_g.ScalarBaseMult(&scalar_u64(2));
    if p.Equal(&two_g) != 1 {
        ok = false;
    }

    // Aliasing: q.ScalarMult(s, q).
    let mut q = NewGeneratorPoint();
    let q_in = q;
    q.ScalarMult(&scalar_u64(5), &q_in);
    let mut five_g = Point::new();
    five_g.ScalarBaseMult(&scalar_u64(5));
    if q.Equal(&five_g) != 1 {
        ok = false;
    }

    let _ = TOTAL;
    write_result(10, b"MultByCofactor + aliasing      ", ok);
    if !ok {
        fail();
    }
}
