// unicode_case_smoke — full Unicode case mapping (ToUpper/ToLower/
// ToTitle/SimpleFold + strings ToUpper/ToLower/EqualFold), upgraded
// from the ASCII shims for the typescript-goish port (stringutil
// comparators use unicode.ToLower / strings.EqualFold).
//
// Test 1 recomputes an FNV-1a aggregate of all four mappings over
// every valid code point; the expected value is REAL GO 1.25.5's
// output for the identical computation (scratch case_ref/hash.go).
// Tests 2-3 assert EqualFold / string-case vectors dumped from Go.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::strings;
use goish::unicode;
use goish::{syscall, Println};

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
    // ─── 1. exhaustive sweep hash vs real Go ───────────────────────
    let mut h: u64 = 0xcbf29ce484222325;
    let mut mix = |hh: &mut u64, v: u64| {
        let mut i = 0;
        while i < 8 {
            *hh ^= (v >> (8 * i)) & 0xff;
            *hh = hh.wrapping_mul(0x100000001b3);
            i += 1;
        }
    };
    let mut r: i32 = 0;
    while r <= 0x10FFFF {
        if !(0xD800..=0xDFFF).contains(&r) {
            mix(&mut h, unicode::ToUpper(r) as u64);
            mix(&mut h, unicode::ToLower(r) as u64);
            mix(&mut h, unicode::ToTitle(r) as u64);
            mix(&mut h, unicode::SimpleFold(r) as u64);
        }
        r += 1;
    }
    if h != 0x104475aebf1f2c86 {
        die(b"t1: sweep hash mismatch vs Go\n");
    }

    // ─── 2. strings.EqualFold vectors (from real Go) ───────────────
    let vecs: &[(&str, &str, bool)] = &[
        ("Go", "GO", true),
        ("\u{130}stanbul", "istanbul", false),
        ("\u{132}SSELMEER", "\u{133}sselmeer", true),
        ("\u{3a3}\u{38a}\u{3a3}\u{3a5}\u{3a6}\u{39f}\u{3a3}", "\u{3c3}\u{3af}\u{3c3}\u{3c5}\u{3c6}\u{3bf}\u{3c2}", true),
        ("kelvin \u{212a}", "KELVIN k", true),
        ("\u{1c5}ungla", "\u{1c6}UNGLA", true),
        ("stra\u{df}e", "STRASSE", false),
        ("ABC", "abd", false),
        ("\u{1e9e}", "\u{df}", true),
    ];
    for (a, b, want) in vecs {
        if strings::EqualFold(*a, *b) != *want {
            Println!("EqualFold mismatch:", *a, *b);
            die(b"t2: EqualFold vector\n");
        }
    }

    // ─── 3. strings ToUpper/ToLower on mixed scripts (from Go) ─────
    let up = strings::ToUpper("\u{1c5}ungla-\u{43c}\u{430}\u{440}\u{43a}\u{430}-\u{133}s");
    check(
        up.as_bytes() == "\u{1c4}UNGLA-\u{41c}\u{410}\u{420}\u{41a}\u{410}-\u{132}S".as_bytes(),
        b"t3: ToUpper mixed\n",
    );
    let lo = strings::ToLower("\u{1c5}UNGLA-\u{41c}\u{410}\u{420}\u{41a}\u{410}-\u{132}S");
    check(
        lo.as_bytes() == "\u{1c6}ungla-\u{43c}\u{430}\u{440}\u{43a}\u{430}-\u{133}s".as_bytes(),
        b"t3: ToLower mixed\n",
    );
    // ASCII fast paths still exact.
    check(strings::ToUpper("hello Web").as_bytes() == b"HELLO WEB", b"t3: ascii upper\n");
    check(strings::ToLower("Hello WEB").as_bytes() == b"hello web", b"t3: ascii lower\n");

    let msg = b"UNICODE_CASE_OK sweep hash + fold vectors vs real Go\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
