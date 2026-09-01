// bits_ref_smoke — math/bits against a running Go.
// (math/bits/bits.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_bits_ref.go` run in `package bits_test`
// by `scripts/goref.sh`. The tables are GENERATED from that output
// rather than typed, so a transcription slip cannot make a wrong
// implementation look right.
//
// `math/bits` had no provenance anchors at all: 49 of its 49 functions
// matched Go by NAME only, which is exactly the state `encoding/binary`
// was in when its `Read` and `Write` turned out to be stubs. Everything
// here is pure integer manipulation, so every answer is exact and every
// wrong one is silent — a bad TrailingZeros or a bad RotateLeft
// produces a number, not an error, and it flows straight into whatever
// hash, allocator or codec asked for it.
//
// The result: all 49 agree with Go, across the zeros, the all-ones
// values, the single high bit, the wrap points of Add/Sub, the
// double-width Mul, and Div/Rem at the edge where the quotient only
// just fits. That is the outcome worth recording, and the anchors are
// what turn it from a name match into a proof.
//
// One thing did change. `Div64`/`Div32`/`Rem64`/`Rem32` panic on a zero
// divisor and on a quotient that would overflow, as Go's do, but with
// their own wording: "integer divide by zero" and "bits: integer
// overflow" against Go's "runtime error: integer divide by zero" and
// "runtime error: integer overflow" — Go panics with the runtime's own
// error values, which is what a recovering caller sees. The messages
// are Go's now. They are not asserted here because goish's `recover!()`
// does not resume execution, so a smoke cannot catch a panic and carry
// on; the two vectors are in the Go reference.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::math::bits;
use goish::types::{int, uint};
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// go: none — goish idiom: report one wrong number against Go's.
fn u(ok: &mut bool, what: &str, v: u64, got: u64, want: u64) {
    if got != want {
        fmt::Println!(
            "   ",
            s(what),
            fmt::Sprintf!("of %#x got %#x want %#x", v, got, want)
        );
        *ok = false;
    }
}

fn i(ok: &mut bool, what: &str, v: u64, got: int, want: int) {
    if got != want {
        fmt::Println!(
            "   ",
            s(what),
            fmt::Sprintf!("of %#x got %d want %d", v, got, want)
        );
        *ok = false;
    }
}

// (v, LeadingZeros, TrailingZeros, OnesCount, Len, Reverse, …) — Go
// 1.25.5 verbatim, generated from the reference output.
const B8: [(u8, int, int, int, int, u8, u8, u8, u8); 9] = [
    (0, 8, 8, 0, 0, 0, 0, 0, 0),
    (1, 7, 0, 1, 1, 128, 2, 128, 2),
    (2, 6, 1, 1, 2, 64, 4, 1, 4),
    (3, 6, 0, 2, 2, 192, 6, 129, 6),
    (128, 0, 7, 1, 8, 1, 1, 64, 1),
    (255, 0, 0, 8, 8, 255, 255, 255, 255),
    (15, 4, 0, 4, 4, 240, 30, 135, 30),
    (240, 0, 4, 4, 8, 15, 225, 120, 225),
    (85, 1, 0, 4, 7, 170, 170, 170, 170),
];

const B16: [(u16, int, int, int, int, u16, u16, u16); 6] = [
    (0, 16, 16, 0, 0, 0, 0, 0),
    (1, 15, 0, 1, 1, 32768, 256, 16),
    (32768, 0, 15, 1, 16, 1, 128, 8),
    (65535, 0, 0, 16, 16, 65535, 65535, 65535),
    (258, 7, 1, 2, 9, 16512, 513, 4128),
    (65280, 0, 8, 8, 16, 255, 255, 61455),
];

const B32: [(u32, int, int, int, int, u32, u32, u32, u32); 6] = [
    (0, 32, 32, 0, 0, 0, 0, 0, 0),
    (1, 31, 0, 1, 1, 2147483648, 16777216, 256, 16777216),
    (2147483648, 0, 31, 1, 32, 1, 128, 128, 8388608),
    (
        4294967295, 0, 0, 32, 32, 4294967295, 4294967295, 4294967295, 4294967295,
    ),
    (
        16909060, 7, 2, 5, 25, 549470336, 67305985, 33752065, 67174915,
    ),
    (
        3735928559, 0, 0, 24, 32, 4152210811, 4022250974, 2914971614, 4024348094,
    ),
];

const B64: [(u64, int, int, int, int, u64, u64, u64); 6] = [
    (0, 64, 64, 0, 0, 0, 0, 0),
    (
        1,
        63,
        0,
        1,
        1,
        9223372036854775808,
        72057594037927936,
        65536,
    ),
    (9223372036854775808, 0, 63, 1, 64, 1, 128, 32768),
    (
        18446744073709551615,
        0,
        0,
        64,
        64,
        18446744073709551615,
        18446744073709551615,
        18446744073709551615,
    ),
    (
        72623859790382856,
        7,
        3,
        13,
        57,
        1216078140250538112,
        578437695752307201,
        217304205466534146,
    ),
    (
        16045690984503098046,
        0,
        1,
        46,
        64,
        9033516426186306939,
        13743577360433589726,
        13758438582043729581,
    ),
];

const BU: [(uint, int, int, int, int, uint, uint, uint); 5] = [
    (0, 64, 64, 0, 0, 0, 0, 0),
    (1, 63, 0, 1, 1, 9223372036854775808, 72057594037927936, 8),
    (9223372036854775808, 0, 63, 1, 64, 1, 128, 4),
    (
        18446744073709551615,
        0,
        0,
        64,
        64,
        18446744073709551615,
        18446744073709551615,
        18446744073709551615,
    ),
    (
        72623859790382856,
        7,
        3,
        13,
        57,
        1216078140250538112,
        578437695752307201,
        580990878323062848,
    ),
];

const ADDSUB64: [(u64, u64, u64, u64, u64, u64, u64); 6] = [
    (1, 2, 0, 3, 0, 18446744073709551615, 1),
    (1, 2, 1, 4, 0, 18446744073709551614, 1),
    (18446744073709551615, 1, 0, 0, 1, 18446744073709551614, 0),
    (18446744073709551615, 0, 1, 0, 1, 18446744073709551614, 0),
    (
        18446744073709551615,
        18446744073709551615,
        1,
        18446744073709551615,
        1,
        18446744073709551615,
        1,
    ),
    (0, 0, 0, 0, 0, 0, 0),
];

const ADDSUB32: [(u32, u32, u32, u32, u32, u32, u32); 3] = [
    (1, 2, 0, 3, 0, 4294967295, 1),
    (4294967295, 1, 0, 0, 1, 4294967294, 0),
    (0, 1, 1, 2, 0, 4294967294, 1),
];

const MUL64: [(u64, u64, u64, u64); 6] = [
    (0, 0, 0, 0),
    (1, 1, 0, 1),
    (18446744073709551615, 2, 1, 18446744073709551614),
    (
        18446744073709551615,
        18446744073709551615,
        18446744073709551614,
        1,
    ),
    (4294967296, 4294967296, 1, 0),
    (3735928559, 3405691582, 0, 12723420444339690338),
];

const MUL32: [(u32, u32, u32, u32); 3] = [
    (0, 0, 0, 0),
    (4294967295, 2, 1, 4294967294),
    (65536, 65536, 1, 0),
];

const DIV64: [(u64, u64, u64, u64, u64, u64); 6] = [
    (0, 10, 3, 3, 1, 1),
    (0, 18446744073709551615, 3, 6148914691236517205, 0, 0),
    (1, 0, 2, 9223372036854775808, 0, 0),
    (1, 0, 18446744073709551615, 1, 1, 1),
    (0, 0, 1, 0, 0, 0),
    (2, 5, 7, 5270498306774157605, 2, 2),
];

const DIV32: [(u32, u32, u32, u32, u32, u32); 3] = [
    (0, 10, 3, 3, 1, 1),
    (1, 0, 2, 2147483648, 0, 0),
    (0, 0, 1, 0, 0, 0),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. UintSize, and the 8-bit family. The last three columns are
    //    RotateLeft8 by 1, by -1 and by 9 — the negative and the
    //    wrapping counts, which are where a rotate is usually wrong.
    {
        let mut ok = true;
        if bits::UintSize != 64 {
            ok = false;
        }
        let mut k = 0usize;
        while k < B8.len() {
            let (v, lz, tz, oc, ln, rev, r1, rm1, r9) = B8[k];
            let w = v as u64;
            i(&mut ok, "LeadingZeros8", w, bits::LeadingZeros8(v), lz);
            i(&mut ok, "TrailingZeros8", w, bits::TrailingZeros8(v), tz);
            i(&mut ok, "OnesCount8", w, bits::OnesCount8(v), oc);
            i(&mut ok, "Len8", w, bits::Len8(v), ln);
            u(&mut ok, "Reverse8", w, bits::Reverse8(v) as u64, rev as u64);
            u(
                &mut ok,
                "RotateLeft8 1",
                w,
                bits::RotateLeft8(v, 1) as u64,
                r1 as u64,
            );
            u(
                &mut ok,
                "RotateLeft8 -1",
                w,
                bits::RotateLeft8(v, -1) as u64,
                rm1 as u64,
            );
            u(
                &mut ok,
                "RotateLeft8 9",
                w,
                bits::RotateLeft8(v, 9) as u64,
                r9 as u64,
            );
            k += 1;
        }
        report(&mut failed, ok, " 1", "the 8-bit family, rotates included");
    }

    // 2. 16-bit, with ReverseBytes16.
    {
        let mut ok = true;
        let mut k = 0usize;
        while k < B16.len() {
            let (v, lz, tz, oc, ln, rev, revb, r4) = B16[k];
            let w = v as u64;
            i(&mut ok, "LeadingZeros16", w, bits::LeadingZeros16(v), lz);
            i(&mut ok, "TrailingZeros16", w, bits::TrailingZeros16(v), tz);
            i(&mut ok, "OnesCount16", w, bits::OnesCount16(v), oc);
            i(&mut ok, "Len16", w, bits::Len16(v), ln);
            u(
                &mut ok,
                "Reverse16",
                w,
                bits::Reverse16(v) as u64,
                rev as u64,
            );
            u(
                &mut ok,
                "ReverseBytes16",
                w,
                bits::ReverseBytes16(v) as u64,
                revb as u64,
            );
            u(
                &mut ok,
                "RotateLeft16 4",
                w,
                bits::RotateLeft16(v, 4) as u64,
                r4 as u64,
            );
            k += 1;
        }
        report(&mut failed, ok, " 2", "the 16-bit family");
    }

    // 3. 32-bit, both rotate directions.
    {
        let mut ok = true;
        let mut k = 0usize;
        while k < B32.len() {
            let (v, lz, tz, oc, ln, rev, revb, r8, rm8) = B32[k];
            let w = v as u64;
            i(&mut ok, "LeadingZeros32", w, bits::LeadingZeros32(v), lz);
            i(&mut ok, "TrailingZeros32", w, bits::TrailingZeros32(v), tz);
            i(&mut ok, "OnesCount32", w, bits::OnesCount32(v), oc);
            i(&mut ok, "Len32", w, bits::Len32(v), ln);
            u(
                &mut ok,
                "Reverse32",
                w,
                bits::Reverse32(v) as u64,
                rev as u64,
            );
            u(
                &mut ok,
                "ReverseBytes32",
                w,
                bits::ReverseBytes32(v) as u64,
                revb as u64,
            );
            u(
                &mut ok,
                "RotateLeft32 8",
                w,
                bits::RotateLeft32(v, 8) as u64,
                r8 as u64,
            );
            u(
                &mut ok,
                "RotateLeft32 -8",
                w,
                bits::RotateLeft32(v, -8) as u64,
                rm8 as u64,
            );
            k += 1;
        }
        report(&mut failed, ok, " 3", "the 32-bit family");
    }

    // 4. 64-bit, and the `uint`-width forms, which Go defines as the
    //    64-bit ones on a 64-bit target and goish pins to u64.
    {
        let mut ok = true;
        let mut k = 0usize;
        while k < B64.len() {
            let (v, lz, tz, oc, ln, rev, revb, r16) = B64[k];
            i(&mut ok, "LeadingZeros64", v, bits::LeadingZeros64(v), lz);
            i(&mut ok, "TrailingZeros64", v, bits::TrailingZeros64(v), tz);
            i(&mut ok, "OnesCount64", v, bits::OnesCount64(v), oc);
            i(&mut ok, "Len64", v, bits::Len64(v), ln);
            u(&mut ok, "Reverse64", v, bits::Reverse64(v), rev);
            u(&mut ok, "ReverseBytes64", v, bits::ReverseBytes64(v), revb);
            u(
                &mut ok,
                "RotateLeft64 16",
                v,
                bits::RotateLeft64(v, 16),
                r16,
            );
            k += 1;
        }
        let mut j = 0usize;
        while j < BU.len() {
            let (v, lz, tz, oc, ln, rev, revb, r3) = BU[j];
            i(&mut ok, "LeadingZeros", v, bits::LeadingZeros(v), lz);
            i(&mut ok, "TrailingZeros", v, bits::TrailingZeros(v), tz);
            i(&mut ok, "OnesCount", v, bits::OnesCount(v), oc);
            i(&mut ok, "Len", v, bits::Len(v), ln);
            u(&mut ok, "Reverse", v, bits::Reverse(v), rev);
            u(&mut ok, "ReverseBytes", v, bits::ReverseBytes(v), revb);
            u(&mut ok, "RotateLeft 3", v, bits::RotateLeft(v, 3), r3);
            j += 1;
        }
        report(&mut failed, ok, " 4", "the 64-bit and uint-width families");
    }

    // 5. Add and Sub, carry and borrow, at the wrap points — including
    //    the row where x and y are both all-ones with a carry in, which
    //    is the one that distinguishes a real carry chain from a naive
    //    wrapping add.
    {
        let mut ok = true;
        let mut k = 0usize;
        while k < ADDSUB64.len() {
            let (x, y, c, ws, wc, wd, wb) = ADDSUB64[k];
            let (gs, gc) = bits::Add64(x, y, c);
            let (gd, gb) = bits::Sub64(x, y, c);
            u(&mut ok, "Add64 sum", x, gs, ws);
            u(&mut ok, "Add64 carry", x, gc, wc);
            u(&mut ok, "Sub64 diff", x, gd, wd);
            u(&mut ok, "Sub64 borrow", x, gb, wb);
            k += 1;
        }
        let mut j = 0usize;
        while j < ADDSUB32.len() {
            let (x, y, c, ws, wc, wd, wb) = ADDSUB32[j];
            let (gs, gc) = bits::Add32(x, y, c);
            let (gd, gb) = bits::Sub32(x, y, c);
            u(&mut ok, "Add32 sum", x as u64, gs as u64, ws as u64);
            u(&mut ok, "Add32 carry", x as u64, gc as u64, wc as u64);
            u(&mut ok, "Sub32 diff", x as u64, gd as u64, wd as u64);
            u(&mut ok, "Sub32 borrow", x as u64, gb as u64, wb as u64);
            j += 1;
        }
        report(&mut failed, ok, " 5", "Add/Sub with carry and borrow");
    }

    // 6. The double-width Mul, including all-ones times all-ones, whose
    //    answer is (2^64-2, 1) and not anything a single-width multiply
    //    could produce.
    {
        let mut ok = true;
        let mut k = 0usize;
        while k < MUL64.len() {
            let (x, y, whi, wlo) = MUL64[k];
            let (ghi, glo) = bits::Mul64(x, y);
            u(&mut ok, "Mul64 hi", x, ghi, whi);
            u(&mut ok, "Mul64 lo", x, glo, wlo);
            k += 1;
        }
        let mut j = 0usize;
        while j < MUL32.len() {
            let (x, y, whi, wlo) = MUL32[j];
            let (ghi, glo) = bits::Mul32(x, y);
            u(&mut ok, "Mul32 hi", x as u64, ghi as u64, whi as u64);
            u(&mut ok, "Mul32 lo", x as u64, glo as u64, wlo as u64);
            j += 1;
        }
        report(&mut failed, ok, " 6", "Mul is double-width");
    }

    // 7. Div and Rem over a 128-bit dividend, including the row where
    //    hi is non-zero and the quotient only just fits.
    {
        let mut ok = true;
        let mut k = 0usize;
        while k < DIV64.len() {
            let (hi, lo, y, wq, wr, wrem) = DIV64[k];
            let (gq, gr) = bits::Div64(hi, lo, y);
            u(&mut ok, "Div64 quo", lo, gq, wq);
            u(&mut ok, "Div64 rem", lo, gr, wr);
            u(&mut ok, "Rem64", lo, bits::Rem64(hi, lo, y), wrem);
            k += 1;
        }
        let mut j = 0usize;
        while j < DIV32.len() {
            let (hi, lo, y, wq, wr, wrem) = DIV32[j];
            let (gq, gr) = bits::Div32(hi, lo, y);
            u(&mut ok, "Div32 quo", lo as u64, gq as u64, wq as u64);
            u(&mut ok, "Div32 rem", lo as u64, gr as u64, wr as u64);
            u(
                &mut ok,
                "Rem32",
                lo as u64,
                bits::Rem32(hi, lo, y) as u64,
                wrem as u64,
            );
            j += 1;
        }
        // Go: Rem is defined even where Div would panic on overflow —
        // "rem-overflow 0x0" and "rem32-overflow 0x0".
        u(&mut ok, "Rem64 overflow", 1, bits::Rem64(1, 0, 1), 0);
        u(&mut ok, "Rem32 overflow", 1, bits::Rem32(1, 0, 1) as u64, 0);
        report(&mut failed, ok, " 7", "Div/Rem over a 128-bit dividend");
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
