// runeconv_ref_smoke — `[]rune(s)` and `string(rs)` across the whole
// invalid range, against a running Go 1.25.5 via scripts/goref.sh.
//
// Both conversions are total in Go: neither can fail, and neither
// drops an element. A byte that cannot begin or continue a UTF-8
// sequence decodes to U+FFFD and advances exactly ONE byte, so
// "\xed\xa0\x80" is three replacement runes rather than one; and a
// rune that is not a valid code point — negative, a surrogate half, or
// above MaxRune — encodes as U+FFFD's three bytes rather than being
// skipped.
//
// `string(rs)` did not exist until this smoke was written. goish had
// `[]rune(s)` and no way back, so the common Go shape — convert to
// runes, edit, convert back — could not be written at all. It walks
// `utf8::AppendRune`, which is Go's own function and already carries
// the substitution rule, rather than repeating the validity test.
//
// The `[]rune(s)` direction was already correct, including the case
// most likely to be wrong: a 5-byte lead (0xF8) is not a legal UTF-8
// prefix at any length, and yields five replacements, not one.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::types::{int, rune};

const GO: [&str; 19] = [
    "ascii                    n=3 [97 98 99]",
    "multibyte                n=5 [104 233 108 108 111]",
    "lone-ff                  n=1 [65533]",
    "bad-middle               n=3 [97 65533 98]",
    "truncated-3byte          n=2 [65533 65533]",
    "overlong                 n=2 [65533 65533]",
    "surrogate                n=3 [65533 65533 65533]",
    "trunc-4byte              n=2 [65533 65533]",
    "rune-cut                 n=2 [104 65533]",
    "valid-then-bad           n=2 [233 65533]",
    "bad-then-valid           n=2 [65533 233]",
    "5byte-lead               n=5 [65533 65533 65533 65533 65533]",
    "max-rune                 n=1 [1114111]",
    "empty                    n=0 []",
    "back-surrogate           efbfbd",
    "back-negative            efbfbd",
    "back-too-big             efbfbd",
    "back-maxrune             f48fbfbf",
    "back-mixed               61efbfbd62",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

// `[]rune(s)` — printed as Go prints a []rune with %v.
fn show(ln: &mut usize, tag: &str, s: &string) {
    let r = <slice<rune>>::from(s);
    let mut parts = string::from("[");
    for (i, v) in r.iter().enumerate() {
        if i > 0 {
            parts = parts + " ";
        }
        parts = parts + fmt::Sprintf!("%v", *v);
    }
    parts = parts + "]";
    chk(ln, &fmt::Sprintf!("%-24s n=%v %v", tag, r.Len() as int, parts));
}

// `string(rs)` — printed as the hex of the resulting bytes.
fn back(ln: &mut usize, tag: &str, rs: &[rune]) {
    let sl = <slice<rune>>::__from_vec(rs.to_vec());
    let out: string = string::from(&sl);
    chk(ln, &fmt::Sprintf!("%-24s %x", tag, out));
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    show(&mut ln, "ascii", &string::from("abc"));
    show(&mut ln, "multibyte", &string::from("héllo"));
    show(&mut ln, "lone-ff", &string::from_bytes(&[0xff]));
    show(&mut ln, "bad-middle", &string::from_bytes(&[0x61, 0xff, 0x62]));
    show(&mut ln, "truncated-3byte", &string::from_bytes(&[0xe4, 0xb8]));
    show(&mut ln, "overlong", &string::from_bytes(&[0xc0, 0xaf]));
    show(&mut ln, "surrogate", &string::from_bytes(&[0xed, 0xa0, 0x80]));
    show(&mut ln, "trunc-4byte", &string::from_bytes(&[0xf0, 0x9f]));
    show(&mut ln, "rune-cut", &string::from("héllo").slice(0, 2));
    show(&mut ln, "valid-then-bad", &string::from_bytes(&[0xc3, 0xa9, 0xff]));
    show(&mut ln, "bad-then-valid", &string::from_bytes(&[0xff, 0xc3, 0xa9]));
    show(&mut ln, "5byte-lead", &string::from_bytes(&[0xf8, 0x88, 0x80, 0x80, 0x80]));
    show(&mut ln, "max-rune", &string::from("\u{10FFFF}"));
    show(&mut ln, "empty", &string::from(""));

    // string([]rune) — the other direction.
    back(&mut ln, "back-surrogate", &[0xD800]);
    back(&mut ln, "back-negative", &[-1]);
    back(&mut ln, "back-too-big", &[0x110000]);
    back(&mut ln, "back-maxrune", &[0x10FFFF]);
    back(&mut ln, "back-mixed", &[0x61, 0xD800, 0x62]);

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
