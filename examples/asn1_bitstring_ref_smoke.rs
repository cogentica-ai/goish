// asn1_bitstring_ref_smoke — DER BIT STRING padding-bit validation,
// against Go 1.25.5.
//
// The contents of a BIT STRING begin with a count of unused bits in
// the final octet. Go validates it with one short-circuiting condition
// (asn1.go:203-207):
//
//     if paddingBits > 7 ||
//        len(bytes) == 1 && paddingBits > 0 ||
//        bytes[len(bytes)-1]&((1<<bytes[0])-1) != 0 {
//
// The third clause is never evaluated once the first is true, so
// `1<<bytes[0]` only ever runs with a shift of 7 or less.
//
// goish computed that mask BEFORE the condition, which is not the same
// program. For any BIT STRING whose first byte is 32 or more, that is
// a u32 shifted by 32 or more — "attempt to shift left with overflow",
// which panics in a debug build and silently yields 255 in a release
// one. `make e2e` builds debug. So a certificate carrying such a BIT
// STRING aborted the process where Go returns a SyntaxError, and the
// two profiles disagreed about it, which is the worse half: a release
// build could not reproduce what CI saw.
//
// BIT STRING is how X.509 carries signature values and public keys, so
// the byte comes straight off the wire.
//
// The rows walk the boundary (7/8), the shift boundary (31/32) and
// past it (33, 64, 255), plus the length-1 and zero-length cases that
// the first two clauses own.
//
// Reference: tools/gen_asn1_bitstring_ref.go via scripts/goref.sh. It
// drives the unexported parseBitString through asn1.Unmarshal; goish
// exports it directly, so the smoke passes the same contents bytes.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::encoding::asn1;
use goish::fmt;
use goish::gostring::string;

const GO: [&str; 14] = [
    "empty-contents       err=asn1: syntax error: zero length BIT STRING",
    "pad0-one-byte        ok bitlen=8 bytes=ff",
    "pad1-clear           ok bitlen=7 bytes=fe",
    "pad1-set             err=asn1: syntax error: invalid padding bits in BIT STRING",
    "pad7-clear           ok bitlen=1 bytes=80",
    "pad7-set             err=asn1: syntax error: invalid padding bits in BIT STRING",
    "pad8                 err=asn1: syntax error: invalid padding bits in BIT STRING",
    "pad31                err=asn1: syntax error: invalid padding bits in BIT STRING",
    "pad32                err=asn1: syntax error: invalid padding bits in BIT STRING",
    "pad33                err=asn1: syntax error: invalid padding bits in BIT STRING",
    "pad64                err=asn1: syntax error: invalid padding bits in BIT STRING",
    "pad255               err=asn1: syntax error: invalid padding bits in BIT STRING",
    "pad-only-nonzero     err=asn1: syntax error: invalid padding bits in BIT STRING",
    "pad-only-zero        ok bitlen=0 bytes=",
];

static mut BAD: usize = 0;

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        unsafe { BAD += 1 };
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
        unsafe { BAD += 1 };
    }
    *ln += 1;
}

fn hex(b: &goish::slice<goish::byte>) -> string {
    let mut out = string::from_static("");
    let mut i: goish::int = 0;
    while i < b.Len() {
        out = out + fmt::Sprintf!("%02x", b[i]);
        i += 1;
    }
    return out;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let cases: [(&str, &[u8]); 14] = [
        ("empty-contents", b""),
        ("pad0-one-byte", b"\x00\xff"),
        ("pad1-clear", b"\x01\xfe"),
        ("pad1-set", b"\x01\xff"),
        ("pad7-clear", b"\x07\x80"),
        ("pad7-set", b"\x07\xff"),
        ("pad8", b"\x08\xff"),
        ("pad31", b"\x1f\xff"),
        ("pad32", b"\x20\xff"),
        ("pad33", b"\x21\xff"),
        ("pad64", b"\x40\xff"),
        ("pad255", b"\xff\xff"),
        ("pad-only-nonzero", b"\x01"),
        ("pad-only-zero", b"\x00"),
    ];
    for (name, raw) in cases.iter() {
        let contents = goish::slice::<goish::byte>::__from_vec(raw.to_vec());
        let (bs, err) = asn1::ParseBitString(contents);
        let line = if !err.IsNil() {
            fmt::Sprintf!("%-20s err=%s", string::from(*name), err.Error())
        } else {
            fmt::Sprintf!(
                "%-20s ok bitlen=%d bytes=%s",
                string::from(*name),
                bs.BitLength,
                hex(&bs.Bytes)
            )
        };
        chk(&mut ln, &line);
    }
    if ln != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
        unsafe { BAD += 1 };
    }
    // Exit nonzero on divergence. e2e_runner.sh line 192 is explicit
    // that "rc=0 wins regardless of stdout content", so a smoke that
    // only PRINTS its mismatches is not a gate — CI passes it.
    //
    // This covers the value rows. It cannot cover the shift-overflow
    // regression itself: that panics inside main, the scheduler
    // recovers, main never reaches this line, and the process still
    // exits 0. A regression there shows up as OUTPUT THAT STOPS at
    // pad31 — the last row below the u32 shift boundary — rather than
    // as a `[!!]` line or a nonzero status.
    let bad = unsafe { BAD };
    if bad != 0 {
        fmt::Printf!("[!!] %d row(s) diverge from Go\n", bad as goish::int);
        goish::os::Exit(1);
    }
    goish::os::Exit(0);
}
