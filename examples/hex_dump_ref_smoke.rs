// hex_dump_ref_smoke — hex.Dump layout and DecodeString errors.
//
// Reference: Go 1.25.5 encoding/hex, measured by
// tools/gen_hexascii_ref.go. Every GO[] line is Go's verbatim output.
//
// The generator existed and had been run; the smoke that makes it a
// regression guard had not been written. goish matches Go on all 17.
//
// Dump's output is a fixed-column layout, and the sizes chosen are the
// ones that break a hand-rolled version: 0 (empty output, NOT a blank
// line), 1, then 15/16/17 and 31/32/33 either side of each 16-byte row
// boundary. A short final row still pads its hex columns to full width
// so the ASCII gutter stays aligned, and there is an EXTRA space in
// the middle of each row after the 8th byte. Both are easy to drop and
// invisible until someone diffs two dumps.
//
// The ASCII gutter renders every non-printable byte as ".", including
// 0x7F, which is not a control character in the C0 sense but is not
// printable either.
//
// DecodeString pins what comes back ALONGSIDE an error, which is the
// part a caller gets wrong: "001" returns the successfully decoded
// 0x00 AND the odd-length error, so a caller that checks the error
// last, or not at all, still has one valid byte in hand. An empty
// string is not an error.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::encoding::hex;
use goish::fmt;
use goish::string;

// Go's verbatim output.
const GO: [&str; 17] = [
    "dump 0   \"\"",
    "dump 1   \"00000000  03                                                |.|\\n\"",
    "dump 7   \"00000000  03 0a 11 18 1f 26 2d                              |.....&-|\\n\"",
    "dump 15  \"00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65     |.....&-4;BIPW^e|\\n\"",
    "dump 16  \"00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65 6c  |.....&-4;BIPW^el|\\n\"",
    "dump 17  \"00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65 6c  |.....&-4;BIPW^el|\\n00000010  73                                                |s|\\n\"",
    "dump 31  \"00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65 6c  |.....&-4;BIPW^el|\\n00000010  73 7a 81 88 8f 96 9d a4  ab b2 b9 c0 c7 ce d5     |sz.............|\\n\"",
    "dump 32  \"00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65 6c  |.....&-4;BIPW^el|\\n00000010  73 7a 81 88 8f 96 9d a4  ab b2 b9 c0 c7 ce d5 dc  |sz..............|\\n\"",
    "dump 33  \"00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65 6c  |.....&-4;BIPW^el|\\n00000010  73 7a 81 88 8f 96 9d a4  ab b2 b9 c0 c7 ce d5 dc  |sz..............|\\n00000020  e3                                                |.|\\n\"",
    "printable \"00000000  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 20 7e 7f  |Hello, world! ~.|\\n00000010  00 1f                                             |..|\\n\"",
    "dec \"\"      err=<nil>",
    "dec \"0\"     err=encoding/hex: odd length hex string",
    "dec \"00\"   00 err=<nil>",
    "dec \"0g\"    err=encoding/hex: invalid byte: U+0067 'g'",
    "dec \"g0\"    err=encoding/hex: invalid byte: U+0067 'g'",
    "dec \"0011\" 0011 err=<nil>",
    "dec \"001\"  00 err=encoding/hex: odd length hex string",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            goish::string(GO[i])
        );
    }
}

fn mk(n: usize) -> goish::slice<goish::byte> {
    let mut v: Vec<u8> = Vec::with_capacity(n);
    for i in 0..n {
        v.push(((i * 7 + 3) % 256) as u8);
    }
    goish::slice::<goish::byte>::__from_vec(v)
}

#[goish::main]
fn main() {
    let sizes: [usize; 9] = [0, 1, 7, 15, 16, 17, 31, 32, 33];
    for n in sizes.iter() {
        chk(fmt::Sprintf!("dump %-3d %q", *n as i64, hex::Dump(mk(*n))));
    }
    let p = goish::slice::<goish::byte>::__from_vec(b"Hello, world! ~\x7f\x00\x1f".to_vec());
    chk(fmt::Sprintf!("printable %q", hex::Dump(p)));

    let cases: [&str; 7] = ["", "0", "00", "0g", "g0", "0011", "001"];
    for s in cases.iter() {
        let (b, err) = hex::DecodeString(s);
        chk(fmt::Sprintf!(
            "dec %-6q %x err=%v",
            goish::string::from_bytes(s.as_bytes()),
            b,
            err
        ));
    }
    let _ = string("");
    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
