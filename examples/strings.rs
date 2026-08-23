// Milestone 3 smoke test: string, slice, range!, unicode/utf8, conversions.
//
// Exercises every public surface introduced in M3 and writes "strings:
// ok\n" if every check passes. On any failure, prints a marker to
// stderr and exits non-zero.
//
// Test material: "héllo, 世界" — 9 runes, 14 bytes, mix of ASCII /
// 2-byte / 3-byte UTF-8 sequences.

#![no_std]
#![no_main]

use goish::unicode::utf8;
use goish::{byte, bytes, len, range, rune, runes, slice, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    // (1) Construction + byte-level len matches Go.
    let s: string = string("héllo, 世界");
    check(len(&s) == 14, b"strings: len(s) wrong\n");

    // (2) Indexing returns a byte (Go-faithful), not a rune.
    let b0: byte = s[0];
    check(b0 == b'h', b"strings: s[0] not 'h'\n");

    // (3) utf8: rune count != byte count for non-ASCII strings.
    let rc = utf8::RuneCountInString(&s);
    check(rc == 9, b"strings: RuneCountInString != 9\n");
    check(utf8::ValidString(&s), b"strings: ValidString false\n");

    // (4) range!(s) decodes UTF-8: byte offset + rune.
    //     For "héllo, 世界": offsets are 0,1,3,4,5,6,7,8,11.
    let expected: [(goish::int, rune); 9] = [
        (0, 'h' as rune),
        (1, 'é' as rune),
        (3, 'l' as rune),
        (4, 'l' as rune),
        (5, 'o' as rune),
        (6, ',' as rune),
        (7, ' ' as rune),
        (8, '世' as rune),
        (11, '界' as rune),
    ];
    let mut idx: usize = 0;
    for (i, r) in range!(s) {
        check(idx < 9, b"strings: range!(s) too many iters\n");
        check(
            i == expected[idx].0,
            b"strings: range!(s) wrong byte offset\n",
        );
        check(r == expected[idx].1, b"strings: range!(s) wrong rune\n");
        idx += 1;
    }
    check(idx == 9, b"strings: range!(s) too few iters\n");

    // (5) Concat — `s + t` returns a fresh `string`.
    let greeting: string = s.clone() + "!";
    check(len(&greeting) == 15, b"strings: concat length wrong\n");
    check(greeting[14] == b'!', b"strings: concat last byte wrong\n");

    // (6) Equality — byte-wise; Arc fast path for clones is transparent.
    let s2 = s.clone();
    check(s == s2, b"strings: == clone failed\n");
    check(s == "héllo, 世界", b"strings: == &str failed\n");

    // (7) bytes(s) — copies into independent slice<byte>.
    let b: slice<byte> = bytes(s.clone());
    check(b.Len() == 14, b"strings: bytes(s).Len wrong\n");
    check(
        b[0] == b'h' && b[8] == 0xE4,
        b"strings: bytes(s) content wrong\n",
    );

    // (8) runes(s) — UTF-8 decode into slice<rune>.
    let rs: slice<rune> = runes(s.clone());
    check(rs.Len() == 9, b"strings: runes(s).Len wrong\n");
    check(rs[1] == 'é' as rune, b"strings: runes(s)[1] mismatch\n");
    check(rs[8] == '界' as rune, b"strings: runes(s)[8] mismatch\n");

    // (9) string(rune) — single-rune encode (the Go gotcha).
    let one_char = string(0x4E16 as rune); // '世'
    check(len(&one_char) == 3, b"strings: string(rune) length wrong\n");
    check(one_char == "世", b"strings: string(rune) bytes wrong\n");

    // (10) string(slice<rune>) — round-trip.
    let s3 = string(rs);
    check(s3 == s, b"strings: string(runes(s)) round-trip failed\n");

    // (11) utf8::DecodeRune on raw bytes (low-level path).
    let raw = b"\xE4\xB8\x96"; // '世' as bytes
    let (r, sz) = utf8::DecodeRune(raw);
    check(r == 0x4E16 && sz == 3, b"strings: DecodeRune wrong\n");

    // (12) utf8::EncodeRune writes 1..4 bytes back.
    let mut buf = [0u8; 4];
    let n = utf8::EncodeRune(&mut buf, 'A' as rune);
    check(
        n == 1 && buf[0] == b'A',
        b"strings: EncodeRune ASCII wrong\n",
    );
    let n = utf8::EncodeRune(&mut buf, '界' as rune);
    check(
        n == 3 && buf[0] == 0xE7,
        b"strings: EncodeRune 3-byte wrong\n",
    );

    // (13) RuneLen / ValidRune.
    check(utf8::RuneLen('A' as rune) == 1, b"strings: RuneLen ASCII\n");
    check(
        utf8::RuneLen('界' as rune) == 3,
        b"strings: RuneLen 3-byte\n",
    );
    check(
        utf8::RuneLen(0x110000) == -1,
        b"strings: RuneLen out-of-range\n",
    );
    check(utf8::ValidRune(0x4E16), b"strings: ValidRune valid\n");
    check(!utf8::ValidRune(0xD800), b"strings: ValidRune surrogate\n");

    const OK: &[u8] = b"strings: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
