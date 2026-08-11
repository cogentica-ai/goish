// cryptobyte_string_smoke — golang.org/x/crypto/cryptobyte: the String
// parser and the Builder.
//
// cryptobyte is vendored inside GOROOT, and it is the single package
// standing between goish and crypto/ecdsa (43), crypto/x509 (150) and
// crypto/tls (259).
//
// The Builder cases matter more than they look. goish's addLengthPrefixed
// does not allocate a child Builder — the continuation runs against the
// same builder with the child's fields saved and restored around it — so
// the nested and 24/32-bit prefix cases are what prove that
// restore-and-patch produces the same bytes as Go's parent/child
// reconciliation.
//
// Parser code is the wrong place to guess, so every value below is what Go
// prints for the same input, via scripts/goref.sh (AGENTS.md §10) — run
// against the vendored package inside a writable GOROOT copy.
//
// The cases are chosen for the two ways a length-prefixed reader goes
// wrong: reading past the end (Skip(100), ReadUint16 on one byte) must
// fail without consuming, and a negative count (Skip(-1)) must be rejected
// rather than wrapping into a huge unsigned length.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::cryptobyte;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::types::{byte, uint16, uint32, uint64, uint8};

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

fn data() -> slice<byte> {
    return slice::__from_vec(alloc::vec![
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
        0x90, 0x03, 0x11, 0x22, 0x33, 0x00, 0x02, 0x44, 0x55
    ]);
}

fn tail(from: usize) -> slice<byte> {
    let d = data();
    let r: &[byte] = &d;
    return slice::__from_vec(r[from..].to_vec());
}

fn hx(s: &slice<byte>) -> goish::string {
    let r: &[byte] = s;
    return hex::EncodeToString(r);
}

#[goish::main]
fn main() {
    // Sequential fixed-width reads off one String.
    let mut s = cryptobyte::String::New(data());
    let mut u8v: uint8 = 0;
    let mut u16v: uint16 = 0;
    let mut u24v: uint32 = 0;
    let mut u32v: uint32 = 0;
    let mut u48v: uint64 = 0;
    check("ReadUint8 ok", fmt::Sprintf!("%v", s.ReadUint8(&mut u8v)), "true");
    check("ReadUint8", fmt::Sprintf!("%d", u8v), "161");
    check("ReadUint16 ok", fmt::Sprintf!("%v", s.ReadUint16(&mut u16v)), "true");
    check("ReadUint16", fmt::Sprintf!("%d", u16v), "45763");
    check("ReadUint24 ok", fmt::Sprintf!("%v", s.ReadUint24(&mut u24v)), "true");
    check("ReadUint24", fmt::Sprintf!("%d", u24v), "13952502");
    check("ReadUint32 ok", fmt::Sprintf!("%v", s.ReadUint32(&mut u32v)), "true");
    check("ReadUint32", fmt::Sprintf!("%d", u32v), "119023930");
    check("ReadUint48 ok", fmt::Sprintf!("%v", s.ReadUint48(&mut u48v)), "true");
    check("ReadUint48", fmt::Sprintf!("%d", u48v), "82860346085264");

    let mut s2 = cryptobyte::String::New(data());
    let mut u64v: uint64 = 0;
    check("ReadUint64 ok", fmt::Sprintf!("%v", s2.ReadUint64(&mut u64v)), "true");
    check("ReadUint64", fmt::Sprintf!("%d", u64v), "11651590505119483672");

    // Length-prefixed children: 0x03 then three bytes, then 0x0002 then two.
    let mut s3 = cryptobyte::String::New(tail(16));
    let mut child = cryptobyte::String::default();
    check(
        "ReadUint8LengthPrefixed ok",
        fmt::Sprintf!("%v", s3.ReadUint8LengthPrefixed(&mut child)),
        "true",
    );
    check("8-bit prefixed child", hx(&child.0), "112233");
    let mut child2 = cryptobyte::String::default();
    check(
        "ReadUint16LengthPrefixed ok",
        fmt::Sprintf!("%v", s3.ReadUint16LengthPrefixed(&mut child2)),
        "true",
    );
    check("16-bit prefixed child", hx(&child2.0), "4455");
    check("Empty after consuming all", fmt::Sprintf!("%v", s3.Empty()), "true");

    // Skip, and the two ways it must refuse.
    let mut s4 = cryptobyte::String::New(data());
    check("Skip(20)", fmt::Sprintf!("%v", s4.Skip(20)), "true");
    check("Skip past the end refuses", fmt::Sprintf!("%v", s4.Skip(100)), "false");
    let mut out = slice::__from_vec(Vec::<byte>::new());
    check("ReadBytes ok", fmt::Sprintf!("%v", s4.ReadBytes(&mut out, 4)), "true");
    check("ReadBytes value", hx(&out), "00024455");

    let mut s5 = cryptobyte::String::New(data());
    let mut buf = slice::__from_vec(alloc::vec![0u8; 5]);
    check("CopyBytes ok", fmt::Sprintf!("%v", s5.CopyBytes(&mut buf)), "true");
    check("CopyBytes value", hx(&buf), "a1b2c3d4e5");

    let mut s6 = cryptobyte::String::New(slice::__from_vec(alloc::vec![1u8]));
    check(
        "short read refuses",
        fmt::Sprintf!("%v", s6.ReadUint16(&mut u16v)),
        "false",
    );
    let mut s7 = cryptobyte::String::New(data());
    check(
        "negative skip refuses",
        fmt::Sprintf!("%v", s7.Skip(-1)),
        "false",
    );

    // ---- Builder
    {
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::<byte>::new()));
        b.AddUint8(0x01);
        b.AddUint16(0x0203);
        b.AddUint24(0x040506);
        b.AddUint32(0x0708090a);
        b.AddUint48(0x0b0c0d0e0f10);
        b.AddUint64(0x1112131415161718);
        b.AddBytes(&slice::__from_vec(alloc::vec![0xaau8, 0xbb]));
        let (out, err) = b.Bytes();
        check("Builder fixed-width appends", hx(&out), FLAT);
        check("Builder no error", fmt::Sprintf!("%v", err != goish::nil), "false");
    }
    {
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::<byte>::new()));
        b.AddUint8LengthPrefixed(|c| {
            c.AddBytes(&slice::__from_vec(alloc::vec![1u8, 2, 3]));
        });
        let (out, _) = b.Bytes();
        check("8-bit length prefix", hx(&out), "03010203");
    }
    {
        // Nested prefixes — the case the no-child design has to get right.
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::<byte>::new()));
        b.AddUint16LengthPrefixed(|c| {
            c.AddUint8(0x99);
            c.AddUint8LengthPrefixed(|g| {
                g.AddBytes(&slice::__from_vec(alloc::vec![7u8, 7, 7, 7]));
            });
            c.AddUint8(0x88);
        });
        let (out, _) = b.Bytes();
        check("nested length prefixes", hx(&out), "000799040707070788");
    }
    {
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::<byte>::new()));
        b.AddUint24LengthPrefixed(|c| c.AddBytes(&slice::__from_vec(alloc::vec![5u8, 5])));
        b.AddUint32LengthPrefixed(|c| c.AddBytes(&slice::__from_vec(alloc::vec![6u8])));
        let (out, _) = b.Bytes();
        check("24- and 32-bit prefixes", hx(&out), "00000205050000000106");
    }
    {
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::<byte>::new()));
        b.AddBytes(&slice::__from_vec(alloc::vec![1u8, 2, 3, 4, 5]));
        b.Unwrite(2);
        let (out, _) = b.Bytes();
        check("Unwrite rolls back", hx(&out), "010203");
    }
    {
        // A body too long for its prefix is an error, not a panic.
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::<byte>::new()));
        b.AddUint8LengthPrefixed(|c| {
            c.AddBytes(&slice::__from_vec(alloc::vec![0u8; 300]));
        });
        let (_, err) = b.Bytes();
        check(
            "over-long child is an error",
            fmt::Sprintf!("%v", err != goish::nil),
            "true",
        );
    }
    {
        // SetError short-circuits every later write.
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::<byte>::new()));
        b.AddUint8(1);
        b.SetError(goish::errors::New("test"));
        b.AddUint8(2);
        let (out, err) = b.Bytes();
        check("SetError reported", fmt::Sprintf!("%v", err != goish::nil), "true");
        check("SetError yields no bytes", fmt::Sprintf!("%d", out.Len()), "0");
    }

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("cryptobyte_string_smoke OK\n");
}

const FLAT: &str = "0102030405060708090a0b0c0d0e0f101112131415161718aabb";
