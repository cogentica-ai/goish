// bigmod_smoke — exercise crypto/internal/fips140/bigmod's constant-time
// Nat / Modulus.
//
// Coverage:
//   1. NewModulus from a byte slice — bit length / size.
//   2. Nat::SetBytes -> Bytes round-trip (zero-extended to m's size).
//   3. SetBytes rejects an input >= m.
//   4. Add — modular addition (with and without wrap).
//   5. Sub — modular subtraction (with and without underflow).
//   6. Mul — modular multiplication, cross-checked against big::Int.
//   7. Exp — modular exponentiation cross-checked against big::Int::Exp
//      for several (base, exp, modulus) triples. KEY CORRECTNESS GATE.
//   8. ExpShortVarTime — small-exponent path, cross-checked.
//   9. InverseVarTime — a * a⁻¹ == 1 mod m.
//  10. DivShortVarTime / SubOne / IsOdd / IsZero — misc helpers.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::crypto::internal::fips140::bigmod::{Modulus, Nat};
use goish::math::big;
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

// Compare two goish slice<byte> for equality, ignoring leading zeroes.
fn slice_eq_trim(a: &goish::slice<byte>, b: &goish::slice<byte>) -> bool {
    let av = trim_leading(a);
    let bv = trim_leading(b);
    if av.len() != bv.len() {
        return false;
    }
    for i in 0..av.len() {
        if av[i] != bv[i] {
            return false;
        }
    }
    true
}

fn trim_leading(s: &goish::slice<byte>) -> alloc::vec::Vec<u8> {
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let n = s.Len();
    let mut started = false;
    let mut i: goish::int = 0;
    while i < n {
        let x = s[i];
        if x != 0 {
            started = true;
        }
        if started {
            v.push(x);
        }
        i += 1;
    }
    v
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
    test_1_new_modulus();
    test_2_setbytes_roundtrip();
    test_3_setbytes_overflow();
    test_4_add();
    test_5_sub();
    test_6_mul();
    test_7_exp();
    test_8_exp_short();
    test_9_inverse();
    test_10_misc();
}

// Helper: build a Modulus from raw bytes, panicking on error.
fn mk_modulus(b: &[u8]) -> Modulus {
    let (m, e) = Modulus::NewModulus(from_bytes(b));
    if !e.IsNil() {
        panic!("NewModulus failed");
    }
    m
}

// big::Int from raw big-endian bytes.
fn big_from(b: &[u8]) -> big::Int {
    let mut x = big::Int::new();
    x.SetBytes(from_bytes(b));
    x
}

fn test_1_new_modulus() {
    // 0x0101 = 257, an odd 9-bit modulus.
    let m = mk_modulus(&[0x01, 0x01]);
    let ok_size = m.Size() == 2 && m.BitLen() == 9;
    // Even modulus 0x0100 = 256.
    let m2 = mk_modulus(&[0x01, 0x00]);
    let ok_even = m2.Size() == 2 && m2.BitLen() == 9;
    // Modulus must be > 1.
    let (_, e_one) = Modulus::NewModulus(from_bytes(&[0x01]));
    let (_, e_zero) = Modulus::NewModulus(from_bytes(&[0x00]));
    let ok = ok_size && ok_even && !e_one.IsNil() && !e_zero.IsNil();
    write_result(1, b"NewModulus                   ", ok);
    if !ok {
        fail();
    }
}

fn test_2_setbytes_roundtrip() {
    // m is a 256-bit-ish modulus; round-trip a smaller value through it.
    let m = mk_modulus(&[
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
        0x22, 0x11, 0x01,
    ]);
    let val: [u8; 5] = [0xde, 0xad, 0xbe, 0xef, 0x42];
    let mut n = Nat::NewNat();
    let (_, e) = n.SetBytes(from_bytes(&val), &m);
    let ok_set = e.IsNil();
    let out = n.Bytes(&m);
    let ok_rt = slice_eq_trim(&out, &from_bytes(&val));
    let ok = ok_set && ok_rt;
    write_result(2, b"SetBytes/Bytes round-trip    ", ok);
    if !ok {
        fail();
    }
}

fn test_3_setbytes_overflow() {
    // m = 257; values >= m must be rejected.
    let m = mk_modulus(&[0x01, 0x01]);
    let mut n = Nat::NewNat();
    let (_, e_ok) = n.SetBytes(from_bytes(&[0x01, 0x00]), &m); // 256 < 257
    let mut n2 = Nat::NewNat();
    let (_, e_bad) = n2.SetBytes(from_bytes(&[0x01, 0x01]), &m); // 257 == m
    let mut n3 = Nat::NewNat();
    let (_, e_bad2) = n3.SetBytes(from_bytes(&[0x02, 0x00]), &m); // 512 > m
    let ok = e_ok.IsNil() && !e_bad.IsNil() && !e_bad2.IsNil();
    write_result(3, b"SetBytes overflow guard      ", ok);
    if !ok {
        fail();
    }
}

fn test_4_add() {
    // m = 0xfff1 (65521, a 16-bit prime). 0x8000 + 0x8000 = 0x10000;
    // 0x10000 mod 65521 = 15.
    let m = mk_modulus(&[0xff, 0xf1]);
    let mut a = Nat::NewNat();
    a.SetBytes(from_bytes(&[0x80, 0x00]), &m);
    let mut b = Nat::NewNat();
    b.SetBytes(from_bytes(&[0x80, 0x00]), &m);
    a.Add(&b, &m);
    let got = a.Bytes(&m);
    let ok_wrap = slice_eq_trim(&got, &from_bytes(&[0x0f]));
    // No-wrap: 0x10 + 0x20 = 0x30.
    let mut c = Nat::NewNat();
    c.SetBytes(from_bytes(&[0x10]), &m);
    let mut d = Nat::NewNat();
    d.SetBytes(from_bytes(&[0x20]), &m);
    c.Add(&d, &m);
    let ok_plain = slice_eq_trim(&c.Bytes(&m), &from_bytes(&[0x30]));
    let ok = ok_wrap && ok_plain;
    write_result(4, b"Add modular                  ", ok);
    if !ok {
        fail();
    }
}

fn test_5_sub() {
    // m = 65521. 0x10 - 0x30 underflows -> + m -> 65521 - 32 = 65489 = 0xffd1.
    let m = mk_modulus(&[0xff, 0xf1]);
    let mut a = Nat::NewNat();
    a.SetBytes(from_bytes(&[0x10]), &m);
    let mut b = Nat::NewNat();
    b.SetBytes(from_bytes(&[0x30]), &m);
    a.Sub(&b, &m);
    let ok_under = slice_eq_trim(&a.Bytes(&m), &from_bytes(&[0xff, 0xd1]));
    // No underflow: 0x50 - 0x30 = 0x20.
    let mut c = Nat::NewNat();
    c.SetBytes(from_bytes(&[0x50]), &m);
    let mut d = Nat::NewNat();
    d.SetBytes(from_bytes(&[0x30]), &m);
    c.Sub(&d, &m);
    let ok_plain = slice_eq_trim(&c.Bytes(&m), &from_bytes(&[0x20]));
    let ok = ok_under && ok_plain;
    write_result(5, b"Sub modular                  ", ok);
    if !ok {
        fail();
    }
}

fn test_6_mul() {
    // Cross-check Mul against big::Int for a few odd moduli.
    let mods: [&[u8]; 2] = [
        &[0xff, 0xf1],
        &[0xc0, 0xff, 0xee, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01],
    ];
    let mut ok = true;
    for mb in mods.iter() {
        let m = mk_modulus(mb);
        let base_a: &[u8] = &[0x12, 0x34, 0x56];
        let base_b: &[u8] = &[0x9a, 0xbc, 0xde];
        let mut na = Nat::NewNat();
        na.SetBytes(from_bytes(base_a), &m);
        let mut nb = Nat::NewNat();
        nb.SetBytes(from_bytes(base_b), &m);
        na.Mul(&nb, &m);
        let got = na.Bytes(&m);
        // big::Int reference: (a*b) mod m.
        let ia = big_from(base_a);
        let ib = big_from(base_b);
        let im = big_from(mb);
        let mut prod = big::Int::new();
        prod.Mul(&ia, &ib);
        let mut want = big::Int::new();
        want.Mod(&prod, &im);
        if !slice_eq_trim(&got, &want.Bytes()) {
            ok = false;
        }
    }
    write_result(6, b"Mul vs big::Int              ", ok);
    if !ok {
        fail();
    }
}

fn test_7_exp() {
    // KEY CROSS-CHECK: Exp vs big::Int::Exp for several triples.
    // Each modulus is odd (Exp requires it).
    let cases: [(&[u8], &[u8], &[u8]); 4] = [
        // (base, exp, modulus)
        (&[0x03], &[0x11], &[0xff, 0xf1]),
        (&[0x12, 0x34], &[0x05, 0x67], &[0xff, 0xf1]),
        (
            &[0xab, 0xcd, 0xef],
            &[0x01, 0x00, 0x01], // 65537, the RSA public exponent
            &[
                0xc0, 0xff, 0xee, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
            ],
        ),
        (
            &[0xde, 0xad, 0xbe, 0xef, 0x42, 0x11],
            &[0x7f, 0xed, 0xcb, 0xa9],
            &[
                0xf3, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b,
                0x5c, 0x6d, 0x7e, 0x8f, 0x91,
            ],
        ),
    ];
    let mut ok = true;
    for (i, (base, exp, modb)) in cases.iter().enumerate() {
        let m = mk_modulus(modb);
        let mut nb = Nat::NewNat();
        nb.SetBytes(from_bytes(base), &m);
        let mut out = Nat::NewNat();
        out.Exp(&nb, from_bytes(exp), &m);
        let got = out.Bytes(&m);
        // big::Int reference.
        let ibase = big_from(base);
        let iexp = big_from(exp);
        let imod = big_from(modb);
        let mut want = big::Int::new();
        want.Exp(&ibase, &iexp, &imod);
        if !slice_eq_trim(&got, &want.Bytes()) {
            ok = false;
            fmt::Println!("  Exp mismatch at case", i as i64);
        }
    }
    write_result(7, b"Exp vs big::Int::Exp         ", ok);
    if !ok {
        fail();
    }
}

fn test_8_exp_short() {
    // ExpShortVarTime: small uint exponent, cross-checked with big::Int.
    let m = mk_modulus(&[
        0xc0, 0xff, 0xee, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
    ]);
    let exps: [u64; 3] = [3, 65537, 0x7f_ed_cb_a9];
    let base: &[u8] = &[0x13, 0x57, 0x9b, 0xdf];
    let mut ok = true;
    for &e in exps.iter() {
        let mut nb = Nat::NewNat();
        nb.SetBytes(from_bytes(base), &m);
        let mut out = Nat::NewNat();
        out.ExpShortVarTime(&nb, e, &m);
        let got = out.Bytes(&m);
        // big::Int reference.
        let ibase = big_from(base);
        let mut iexp = big::Int::new();
        iexp.SetUint64(e);
        let imod = big_from(&[
            0xc0, 0xff, 0xee, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
        ]);
        let mut want = big::Int::new();
        want.Exp(&ibase, &iexp, &imod);
        if !slice_eq_trim(&got, &want.Bytes()) {
            ok = false;
        }
    }
    write_result(8, b"ExpShortVarTime vs big::Int  ", ok);
    if !ok {
        fail();
    }
}

fn test_9_inverse() {
    // InverseVarTime: a * a⁻¹ == 1 mod m, for m prime so every a is
    // invertible.
    let m = mk_modulus(&[0xff, 0xf1]); // 65521, prime
    let a_bytes: &[u8] = &[0x12, 0x34];
    let mut a = Nat::NewNat();
    a.SetBytes(from_bytes(a_bytes), &m);
    let mut inv = Nat::NewNat();
    let (_, ok_inv) = inv.InverseVarTime(&a, &m);
    // Verify a * inv == 1.
    let mut prod = Nat::NewNat();
    prod.SetBytes(from_bytes(a_bytes), &m);
    prod.Mul(&inv, &m);
    let ok_one = slice_eq_trim(&prod.Bytes(&m), &from_bytes(&[0x01]));
    let ok = ok_inv && ok_one;
    write_result(9, b"InverseVarTime               ", ok);
    if !ok {
        fail();
    }
}

fn test_10_misc() {
    // DivShortVarTime: 0x100 / 7 = 36 rem 4.
    let m = mk_modulus(&[0x01, 0x01]);
    let mut n = Nat::NewNat();
    n.SetBytes(from_bytes(&[0x01, 0x00]), &m); // 256
    let r = n.DivShortVarTime(7);
    let ok_div = r == 4 && slice_eq_trim(&n.Bytes(&m), &from_bytes(&[0x24])); // 36
    // SubOne on a known value: 0x10 - 1 = 0x0f.
    let mut s = Nat::NewNat();
    s.SetBytes(from_bytes(&[0x10]), &m);
    s.SubOne(&m);
    let ok_subone = slice_eq_trim(&s.Bytes(&m), &from_bytes(&[0x0f]));
    // IsOdd / IsZero.
    let mut odd = Nat::NewNat();
    odd.SetBytes(from_bytes(&[0x05]), &m);
    let mut zero = Nat::NewNat();
    zero.SetBytes(from_bytes(&[]), &m);
    let ok_flags = odd.IsOdd() == 1 && zero.IsZero() == 1 && odd.IsZero() == 0;
    let ok = ok_div && ok_subone && ok_flags;
    write_result(10, b"Div/SubOne/IsOdd/IsZero      ", ok);
    if !ok {
        fail();
    }
}
