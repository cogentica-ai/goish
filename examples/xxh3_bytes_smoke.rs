// xxh3_bytes_smoke — a string hash must hash the string's BYTES.
//
// goish's `string` is byte-backed and, like Go's, is not guaranteed
// UTF-8: `string(b)` for any []byte is legal, and a byte-offset slice
// can cut a multi-byte rune in half. `HashString` used to take
// `AsRef<str>` and go through `&str`, whose type invariant those
// values violate.
//
// While that conversion was `from_utf8_unchecked` the hash happened to
// come out right — undefined behaviour that behaved. Making the
// conversion checked (the correct thing to do) turned it into a
// visible defect: truncating to the longest valid prefix meant every
// string with a leading invalid byte hashed as "", so
// `HashString(string([]byte{0xff}))` collided with `HashString("")`
// and `HashString("a\xffb")` with `HashString("a")`.
//
// There is no Go reference here — xxh3 is not stdlib. The property is
// self-checking and stronger than a pinned digest would be: for every
// string, hashing it must equal hashing its bytes. Only a `HashString`
// that sees all the bytes can satisfy it.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string;
use goish::types::int;
use goish::xxh3;

fn check(name: &str, s: &string, bad: &mut int) {
    let a = xxh3::HashString(s);
    let b = xxh3::Hash(s.as_bytes());
    if a == b {
        fmt::Printf!("[ok] %-18s HashString == Hash(bytes)\n", name);
    } else {
        fmt::Printf!("[!!] %-18s HashString=%v Hash=%v\n", name, a, b);
        *bad += 1;
    }
}

fn distinct(name: &str, x: &string, y: &string, bad: &mut int) {
    if xxh3::HashString(x) != xxh3::HashString(y) {
        fmt::Printf!("[ok] %-18s distinct\n", name);
    } else {
        fmt::Printf!("[!!] %-18s COLLIDES\n", name);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad: int = 0;

    // Valid UTF-8 — the case that always worked.
    check("ascii", &string::from("hello"), &mut bad);
    check("multibyte", &string::from("héllo"), &mut bad);
    check("empty", &string::from(""), &mut bad);

    // Not valid UTF-8, all legal Go strings.
    let lone = string::from_bytes(&[0xff]);
    let bad_mid = string::from_bytes(&[0x61, 0xff, 0x62]);
    let trunc = string::from_bytes(&[0xe4, 0xb8]);
    let over = string::from_bytes(&[0xc0, 0xaf]);
    check("lone-ff", &lone, &mut bad);
    check("bad-middle", &bad_mid, &mut bad);
    check("truncated-rune", &trunc, &mut bad);
    check("overlong", &over, &mut bad);

    // A valid string sliced through a rune — invalid, from valid input.
    let cut = string::from("héllo").slice(0, 2);
    check("rune-cut-slice", &cut, &mut bad);

    // The collisions the &str round trip produced.
    distinct("ff vs empty", &lone, &string::from(""), &mut bad);
    distinct("a-ff-b vs a", &bad_mid, &string::from("a"), &mut bad);
    distinct("cut vs h", &cut, &string::from("h"), &mut bad);

    // The Hasher's streaming WriteString must agree with the one-shot.
    let mut h = xxh3::New();
    h.WriteString(&bad_mid);
    if h.Sum64() == xxh3::Hash(bad_mid.as_bytes()) {
        fmt::Printf!("[ok] %-18s streaming == one-shot\n", "WriteString");
    } else {
        fmt::Printf!("[!!] %-18s streaming != one-shot\n", "WriteString");
        bad += 1;
    }

    if bad == 0 {
        fmt::Printf!("xxh3_bytes_smoke: all checks passed\n");
    } else {
        fmt::Printf!("xxh3_bytes_smoke: %v FAILED\n", bad);
    }
}
