// asn1_smoke — exercise encoding/asn1 primitive parsers.
//
// Test vectors drawn from /share/go/src/encoding/asn1/asn1_test.go
// (boolTestData, integerTestData, bitStringTestData, oidTestData,
// tagAndLengthData) plus DER-encoded fixtures from x509 test data.
//
// Coverage:
//   1. ParseBool — 0x00 → false, 0xff → true, 0x7f → error.
//   2. CheckInteger — empty rejected; minimal-encoding enforced.
//   3. ParseInt64 — sign extension and width bounds.
//   4. ParseInt32 — overflow rejection.
//   5. BitString.At — bit-level access at boundaries.
//   6. ParseBitString — padding-bits validation.
//   7. ParseObjectIdentifier — 1.2.840.113549.1.1.5 (SHA1WithRSA).
//   8. ParseBase128Int — minimal-encoding enforcement.
//   9. ParseTagAndLength — short-form length and class bits.
//  10. ParseUTF8String / ParseIA5String — character-set validation.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::x509;
use goish::encoding::asn1;
use goish::gostring::string;
use goish::math::big;
use goish::types::byte;
use goish::{slice, syscall, Println};


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

fn check_str(got: &string, want: &str) -> bool {
    if got.Len() as usize != want.len() {
        return false;
    }
    let bytes = want.as_bytes();
    let mut i: goish::int = 0;
    while (i as usize) < want.len() {
        if got[i] != bytes[i as usize] {
            return false;
        }
        i += 1;
    }
    true
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
            Println!("ok 13/13");
            syscall::Exit(0);
        } else {
            Println!("FAIL", f as i64, "of 13");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run_tests() {
    test_1_parse_bool();
    test_2_check_integer();
    test_3_parse_int64();
    test_4_parse_int32();
    test_5_bitstring_at();
    test_6_parse_bitstring();
    test_7_parse_object_identifier();
    test_8_parse_base128_int();
    test_9_parse_tag_and_length();
    test_10_parse_strings();
    test_11_parse_raw_sequence();
    test_12_parse_bigint_integer();
    test_13_parse_pkcs8_rsa_key();
}

fn test_1_parse_bool() {
    // From asn1_test.go boolTestData.
    let (v0, e0) = asn1::ParseBool(from_bytes(&[0x00]));
    let (v1, e1) = asn1::ParseBool(from_bytes(&[0xff]));
    let (_, e2) = asn1::ParseBool(from_bytes(&[0x7f]));
    let (_, e3) = asn1::ParseBool(from_bytes(&[]));
    let ok = !v0 && e0.IsNil()
        && v1 && e1.IsNil()
        && !e2.IsNil()
        && !e3.IsNil();
    write_result(1, b"ParseBool                    ", ok);
    if !ok {
        fail();
    }
}

fn test_2_check_integer() {
    // From asn1_test.go: empty -> err; minimal-encoding -> err.
    let e_empty = asn1::CheckInteger(from_bytes(&[]));
    let e_nm1 = asn1::CheckInteger(from_bytes(&[0x00, 0x01]));
    let e_nm2 = asn1::CheckInteger(from_bytes(&[0xff, 0xff]));
    let e_ok1 = asn1::CheckInteger(from_bytes(&[0x01]));
    let e_ok2 = asn1::CheckInteger(from_bytes(&[0x00, 0x80]));
    let ok = !e_empty.IsNil()
        && !e_nm1.IsNil()
        && !e_nm2.IsNil()
        && e_ok1.IsNil()
        && e_ok2.IsNil();
    write_result(2, b"CheckInteger                 ", ok);
    if !ok {
        fail();
    }
}

fn test_3_parse_int64() {
    // 0x80 -> -128 (sign-extended). 0x7f -> 127.
    // 0x00,0x80 -> 128. 0xff,0x7f -> -129.
    let (v_neg, e_neg) = asn1::ParseInt64(from_bytes(&[0x80]));
    let (v_pos, e_pos) = asn1::ParseInt64(from_bytes(&[0x7f]));
    let (v_128, e_128) = asn1::ParseInt64(from_bytes(&[0x00, 0x80]));
    let (v_n129, e_n129) = asn1::ParseInt64(from_bytes(&[0xff, 0x7f]));
    let ok = e_neg.IsNil() && v_neg == -128
        && e_pos.IsNil() && v_pos == 127
        && e_128.IsNil() && v_128 == 128
        && e_n129.IsNil() && v_n129 == -129;
    write_result(3, b"ParseInt64 sign-extension    ", ok);
    if !ok {
        fail();
    }
}

fn test_4_parse_int32() {
    // 0x7f,0xff,0xff,0xff -> 2^31-1.
    // 9 bytes -> overflow ("integer too large").
    let (v_max, e_max) = asn1::ParseInt32(from_bytes(&[0x7f, 0xff, 0xff, 0xff]));
    let (_, e_too) = asn1::ParseInt32(from_bytes(&[0x00, 0x80, 0x00, 0x00, 0x00]));
    let ok = e_max.IsNil() && v_max == 0x7fff_ffff && !e_too.IsNil();
    write_result(4, b"ParseInt32 overflow guard    ", ok);
    if !ok {
        fail();
    }
}

fn test_5_bitstring_at() {
    // BitString { Bytes: 0x82 = 10000010, BitLength: 7 }.
    // bits indexed left-to-right: bit0=1, bit1=0, ..., bit6=1.
    let bs = asn1::BitString {
        Bytes: from_bytes(&[0x82]),
        BitLength: 7,
    };
    let want: [goish::int; 7] = [1, 0, 0, 0, 0, 0, 1];
    let mut ok = true;
    let mut i: goish::int = 0;
    while i < 7 {
        if bs.At(i) != want[i as usize] {
            ok = false;
            break;
        }
        i += 1;
    }
    // Out-of-range -> 0.
    if bs.At(-1) != 0 || bs.At(7) != 0 || bs.At(100) != 0 {
        ok = false;
    }
    write_result(5, b"BitString.At                 ", ok);
    if !ok {
        fail();
    }
}

fn test_6_parse_bitstring() {
    // Valid: paddingBits=0x06, byte=0x6e (last 6 bits zeroed by mask).
    // 0x6e & ((1<<6)-1) = 0x6e & 0x3f = 0x2e (NOT zero) → must be invalid.
    // Pick a valid case: paddingBits=0x06, byte=0x40 (only top 2 bits).
    // 0x40 & 0x3f = 0 → valid. BitLength = (2-1)*8 - 6 = 2.
    let (bs, err) = asn1::ParseBitString(from_bytes(&[0x06, 0x40]));
    let ok_v = err.IsNil() && bs.BitLength == 2 && bs.Bytes.Len() == 1
        && bs.Bytes[0 as goish::int] == 0x40;
    // Invalid: paddingBits>7.
    let (_, err_p) = asn1::ParseBitString(from_bytes(&[0x09, 0xff]));
    let ok_p = !err_p.IsNil();
    // Invalid: paddingBits=2 but trailing bits not zero.
    let (_, err_t) = asn1::ParseBitString(from_bytes(&[0x02, 0xff]));
    let ok_t = !err_t.IsNil();
    // Invalid: zero length.
    let (_, err_z) = asn1::ParseBitString(from_bytes(&[]));
    let ok_z = !err_z.IsNil();
    let ok = ok_v && ok_p && ok_t && ok_z;
    write_result(6, b"ParseBitString               ", ok);
    if !ok {
        fail();
    }
}

fn test_7_parse_object_identifier() {
    // OID 1.2.840.113549.1.1.5 (sha1WithRSAEncryption) — well-known x509
    // signature algorithm.
    // DER: 06 09 2a 86 48 86 f7 0d 01 01 05
    //   tag=06 OID, len=09, body = 2a 86 48 86 f7 0d 01 01 05
    // First byte 0x2a = 42 → 1*40 + 2 → "1.2".
    // Then 0x86 0x48 → (0x06<<7)|0x48 = 0x348 = 840.
    // Then 0x86 0xf7 0x0d → (((0x06<<7)|0x77)<<7)|0x0d = 113549.
    // Then 0x01, 0x01, 0x05.
    let body = from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]);
    let (oid, err) = asn1::ParseObjectIdentifier(body);
    if !err.IsNil() || oid.Len() != 7 {
        write_result(7, b"ParseObjectIdentifier        ", false);
        fail();
        return;
    }
    let want: [goish::int; 7] = [1, 2, 840, 113549, 1, 1, 5];
    let mut ok = true;
    let mut i: goish::int = 0;
    while i < 7 {
        if oid[i] != want[i as usize] {
            ok = false;
            break;
        }
        i += 1;
    }
    // String() round-trip.
    let s = asn1::OIDString(&oid);
    if !check_str(&s, "1.2.840.113549.1.1.5") {
        ok = false;
    }
    // Equal()
    let oid2 = asn1::ParseObjectIdentifier(from_bytes(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05],
    )).0;
    if !asn1::OIDEqual(&oid, &oid2) {
        ok = false;
    }
    write_result(7, b"ParseObjectIdentifier        ", ok);
    if !ok {
        fail();
    }
}

fn test_8_parse_base128_int() {
    // Single byte: 0x05 -> (5, 1).
    let (v1, off1, e1) = asn1::ParseBase128Int(from_bytes(&[0x05]), 0);
    // Multi-byte: 0x86 0x48 -> 840.
    let (v2, off2, e2) = asn1::ParseBase128Int(from_bytes(&[0x86, 0x48]), 0);
    // Non-minimal encoding: 0x80 first byte — error.
    let (_, _, e3) = asn1::ParseBase128Int(from_bytes(&[0x80, 0x01]), 0);
    // Truncated: continuation bit but no more bytes.
    let (_, _, e4) = asn1::ParseBase128Int(from_bytes(&[0x86]), 0);
    let ok = e1.IsNil() && v1 == 5 && off1 == 1
        && e2.IsNil() && v2 == 840 && off2 == 2
        && !e3.IsNil()
        && !e4.IsNil();
    write_result(8, b"ParseBase128Int              ", ok);
    if !ok {
        fail();
    }
}

fn test_9_parse_tag_and_length() {
    // Universal SEQUENCE, length 5: 0x30 0x05.
    // 0x30 = 0b00110000 → class=0, isCompound=true, tag=0x10=16 (Sequence).
    let (tl1, off1, e1) = asn1::ParseTagAndLength(from_bytes(&[0x30, 0x05]), 0);
    // Context-specific [0] EXPLICIT, length 0: 0xA0 0x00.
    // 0xA0 = 0b10100000 → class=2, isCompound=true, tag=0.
    let (tl2, off2, e2) = asn1::ParseTagAndLength(from_bytes(&[0xa0, 0x00]), 0);
    // Long-form length: 0x04 0x82 0x01 0x00 → octet-string len 256.
    // 0x82 → bottom 7 bits=2 → next 2 bytes = 0x0100 = 256.
    let (tl3, off3, e3) = asn1::ParseTagAndLength(
        from_bytes(&[0x04, 0x82, 0x01, 0x00]), 0);
    let ok = e1.IsNil() && tl1.class == 0 && tl1.tag == 16 && tl1.length == 5
            && tl1.isCompound && off1 == 2
        && e2.IsNil() && tl2.class == 2 && tl2.tag == 0 && tl2.length == 0
            && tl2.isCompound && off2 == 2
        && e3.IsNil() && tl3.class == 0 && tl3.tag == 4 && tl3.length == 256
            && !tl3.isCompound && off3 == 4;
    write_result(9, b"ParseTagAndLength            ", ok);
    if !ok {
        fail();
    }
}

fn test_10_parse_strings() {
    // UTF-8 valid + invalid.
    let (s_ok, e_ok) = asn1::ParseUTF8String(from_bytes(b"hello"));
    let (_, e_bad) = asn1::ParseUTF8String(from_bytes(&[0xff, 0xfe]));
    // IA5: ASCII OK, non-ASCII rejected.
    let (s_ia5, e_ia5) = asn1::ParseIA5String(from_bytes(b"abc123"));
    let (_, e_ia5_bad) = asn1::ParseIA5String(from_bytes(&[0x80]));
    // Printable: alphanumeric+space+colon OK; '@' rejected.
    let (s_pr, e_pr) = asn1::ParsePrintableString(from_bytes(b"foo bar"));
    let (_, e_pr_bad) = asn1::ParsePrintableString(from_bytes(b"foo@bar"));
    let ok = e_ok.IsNil() && check_str(&s_ok, "hello")
        && !e_bad.IsNil()
        && e_ia5.IsNil() && check_str(&s_ia5, "abc123")
        && !e_ia5_bad.IsNil()
        && e_pr.IsNil() && check_str(&s_pr, "foo bar")
        && !e_pr_bad.IsNil();
    write_result(10, b"ParseUTF8/IA5/PrintableString", ok);
    if !ok {
        fail();
    }
}

fn test_11_parse_raw_sequence() {
    // Build: SEQUENCE { INTEGER 1, INTEGER 2 }
    //   30 06          -- SEQUENCE, length 6
    //     02 01 01     -- INTEGER, length 1, value 0x01
    //     02 01 02     -- INTEGER, length 1, value 0x02
    let der: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let (rv, rest, err) = asn1::ParseRaw(from_bytes(der));
    let ok = err.IsNil()
        && rv.Tag == asn1::TagSequence
        && rv.IsCompound
        && rv.Bytes.Len() == 6   // body = the 6 bytes inside the SEQUENCE
        && rest.Len() == 0;      // nothing left after parsing
    write_result(11, b"ParseRaw SEQUENCE            ", ok);
    if !ok {
        fail();
    }
}

fn test_12_parse_bigint_integer() {
    // DER INTEGER 0x42: tag=02, len=01, value=42
    // The value bytes passed to ParseBigInt are just the content (no tag/len).
    let value_bytes: &[u8] = &[0x42];
    let (z, err) = asn1::ParseBigInt(from_bytes(value_bytes));
    let ok = err.IsNil() && z.Int64() == 0x42;
    write_result(12, b"ParseBigInt INTEGER          ", ok);
    if !ok {
        fail();
    }
}

fn test_13_parse_pkcs8_rsa_key() {
    // Hand-crafted tiny PKCS#8 / PKCS#1 RSA key.
    //
    // Parameters chosen so all maths are exact:
    //   p = 11, q = 13, n = 143, e = 7, d = 103
    //   (e*d ≡ 1 mod lcm(10,12)=60 → 7*103=721=12*60+1 ✓)
    //   dp = d mod (p-1) = 103 mod 10 = 3
    //   dq = d mod (q-1) = 103 mod 12 = 7
    //   qinv = q^-1 mod p → 13^-1 mod 11 = 6  (13*6=78=7*11+1 ✓)
    //
    // DER encoding of the RSAPrivateKey SEQUENCE:
    //   30 17            -- SEQUENCE, length 23
    //     02 01 00       -- version = 0
    //     02 01 8f       -- n = 143  (0x8f, needs 0x00 prefix to be positive)
    //
    // Wait — 0x8f has bit 7 set, so DER requires a leading 0x00 byte.
    //
    // Let's instead use:
    //   n = 143 = 0x8f  → DER: 02 02 00 8f  (positive, 2 bytes)
    //   e = 7   = 0x07  → DER: 02 01 07
    //   d = 103 = 0x67  → DER: 02 01 67
    //   p = 11  = 0x0b  → DER: 02 01 0b
    //   q = 13  = 0x0d  → DER: 02 01 0d
    //   dp = 3  = 0x03  → DER: 02 01 03
    //   dq = 7  = 0x07  → DER: 02 01 07
    //   qinv=6  = 0x06  → DER: 02 01 06
    //   Total body = 3+2+2+2+2+2+2+2+2+2 = ... let me count precisely:
    //   02 01 00 = 3 bytes (version)
    //   02 02 00 8f = 4 bytes (n)
    //   02 01 07 = 3 bytes (e)
    //   02 01 67 = 3 bytes (d)
    //   02 01 0b = 3 bytes (p)
    //   02 01 0d = 3 bytes (q)
    //   02 01 03 = 3 bytes (dp)
    //   02 01 07 = 3 bytes (dq)
    //   02 01 06 = 3 bytes (qinv)
    //   Total body = 3+4+3+3+3+3+3+3+3 = 28 = 0x1c
    //
    // RSAPrivateKey DER = 30 1c  <28 bytes>
    // OCTET STRING wrapping = 04 1e  (length = 2 + 28 = 30 = 0x1e)
    // AlgorithmIdentifier = 30 0d
    //   OID rsaEncryption = 06 09 2a 86 48 86 f7 0d 01 01 01
    //   NULL = 05 00
    // version = 02 01 00
    // Outer body = 3 + (2+13) + (2+30) = 3 + 15 + 32 = 50 = 0x32
    // Outer SEQUENCE = 30 32  <50 bytes>

    // Build RSAPrivateKey body bytes:
    let rsa_body: &[u8] = &[
        // version = 0
        0x02, 0x01, 0x00,
        // n = 143 = 0x8f (needs leading 00 to be non-negative)
        0x02, 0x02, 0x00, 0x8f,
        // e = 7
        0x02, 0x01, 0x07,
        // d = 103 = 0x67
        0x02, 0x01, 0x67,
        // p = 11 = 0x0b
        0x02, 0x01, 0x0b,
        // q = 13 = 0x0d
        0x02, 0x01, 0x0d,
        // dp = 3
        0x02, 0x01, 0x03,
        // dq = 7
        0x02, 0x01, 0x07,
        // qinv = 6
        0x02, 0x01, 0x06,
    ];
    // rsa_body.len() = 3+4+3+3+3+3+3+3+3 = 28 = 0x1c
    // RSAPrivateKey SEQUENCE = 30 1c + rsa_body
    let rsa_seq_len: u8 = rsa_body.len() as u8; // goishlint:ignore GOISH005

    // AlgorithmIdentifier body = OID(11 bytes) + NULL(2 bytes) = 13 bytes
    let alg_body: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID
        0x05, 0x00, // NULL
    ];
    let alg_seq_len: u8 = alg_body.len() as u8; // goishlint:ignore GOISH005

    // OCTET STRING content = SEQUENCE tag(1) + length(1) + rsa_body
    let octet_content_len = 2 + rsa_body.len(); // 30 = 0x1e

    // Outer body = version(3) + alg(2+13) + octet(2+octet_content_len)
    let outer_body_len = 3 + (2 + alg_body.len()) + (2 + octet_content_len); // 3+15+32=50=0x32
    let outer_seq_len: u8 = outer_body_len as u8; // goishlint:ignore GOISH005

    // Build the full DER
    let mut der_vec: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    // outer SEQUENCE
    der_vec.push(0x30);
    der_vec.push(outer_seq_len);
    // version = 0
    der_vec.extend_from_slice(&[0x02, 0x01, 0x00]);
    // AlgorithmIdentifier SEQUENCE
    der_vec.push(0x30);
    der_vec.push(alg_seq_len);
    der_vec.extend_from_slice(alg_body);
    // OCTET STRING
    der_vec.push(0x04);
    der_vec.push(octet_content_len as u8); // goishlint:ignore GOISH005
    // inner RSAPrivateKey SEQUENCE
    der_vec.push(0x30);
    der_vec.push(rsa_seq_len);
    der_vec.extend_from_slice(rsa_body);

    let der = from_bytes(&der_vec);
    let (key, err) = x509::ParsePKCS8PrivateKey(der);
    if !err.IsNil() {
        write_result(13, b"ParsePKCS8PrivateKey         ", false);
        fail();
        return;
    }
    // Verify: n = 143, e = 7, p*q = 11*13 = 143 = n
    let n_ok = key.PublicKey.N.Int64() == 143;
    let e_ok = key.PublicKey.E == 7;
    // p * q should equal n
    let p = key.Primes[0 as goish::int].clone();
    let q = key.Primes[1 as goish::int].clone();
    let mut pq = big::Int::new();
    pq.Mul(&p, &q);
    let pq_ok = pq.Int64() == 143;
    let ok = n_ok && e_ok && pq_ok;
    write_result(13, b"ParsePKCS8PrivateKey         ", ok);
    if !ok {
        fail();
    }
}
