// unicode_norm_smoke — unicode/norm NFD, ported from
// golang.org/x/text@v0.38.0.
//
// Covers:
//   1. Exact NFD vectors (dumped from real x/text): precomposed Latin,
//      double-accented, Greek, ordering of combining marks by CCC,
//      Hangul algorithmic decomposition, singleton replacements,
//      recursive decompositions, ASCII/identity passthrough.
//   2. The typescript-go organizeimports removeDiacritics pattern:
//      NFD then strip unicode.Mn.
//   3. Form.Bytes mirrors Form.String.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::unicode;
use goish::unicode::norm;
use goish::{string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

// (input, NFD) — expected outputs from real x/text v0.38.0 NFD.String.
static NFD_VECS: &[(&str, &str)] = &[
    // identity
    ("", ""),
    ("hello, world", "hello, world"),
    // precomposed Latin -> base + combining mark
    ("caf\u{e9}", "cafe\u{301}"),
    ("\u{c5}", "A\u{30a}"),
    ("\u{fc}ber", "u\u{308}ber"),
    // double-accented (recursive decomposition)
    ("\u{1e09}", "c\u{327}\u{301}"),
    ("\u{1fa7}", "\u{3c9}\u{314}\u{342}\u{345}"),
    // singleton replacements
    ("\u{212b}", "A\u{30a}"),
    ("\u{2126}", "\u{3a9}"),
    // canonical reordering: dot-below (CCC 220) sorts before acute (230)
    ("q\u{301}\u{323}", "q\u{323}\u{301}"),
    // already-decomposed stays put
    ("e\u{301}", "e\u{301}"),
    // Hangul: algorithmic LV / LVT decomposition
    ("\u{ac00}", "\u{1100}\u{1161}"),
    ("\u{ac01}", "\u{1100}\u{1161}\u{11a8}"),
    ("\u{d7a3}", "\u{1112}\u{1175}\u{11c2}"),
    ("\u{d55c}\u{ae00}", "\u{1112}\u{1161}\u{11ab}\u{1100}\u{1173}\u{11af}"),
    // CJK compatibility ideograph (singleton)
    ("\u{f900}", "\u{8c48}"),
    // mixed real-world text
    ("Ti\u{1ebf}ng Vi\u{1ec7}t", "Tie\u{302}\u{301}ng Vie\u{323}\u{302}t"),
    ("\u{110b}\u{1161}", "\u{110b}\u{1161}"),
];

// removeDiacritics — the typescript-go organizeimports pattern:
// strings.Map(drop unicode.Is(Mn), norm.NFD.String(s)).
fn remove_diacritics<S: Into<string>>(s: S) -> string {
    let n = norm::NFD.String(s);
    let mut out = alloc::string::String::new();
    for c in <goish::string as AsRef<str>>::as_ref(&n).chars() {
        if unicode::Is(unicode::Mn, c as goish::rune) {
            continue;
        }
        out.push(c);
    }
    out.as_str().into()
}

#[goish::main]
fn main() {
    // ─── 1. exact NFD vectors ──────────────────────────────────────
    for (input, want) in NFD_VECS {
        let got = norm::NFD.String(*input);
        if got.as_bytes() != want.as_bytes() {
            fmt::Println!("NFD mismatch on input:", *input);
            die(b"t1: NFD vector mismatch\n");
        }
    }

    // ─── 2. removeDiacritics (organizeimports shape) ───────────────
    let cases: &[(&str, &str)] = &[
        ("caf\u{e9}", "cafe"),
        ("\u{c5}ngstr\u{f6}m", "Angstrom"),
        ("Ti\u{1ebf}ng Vi\u{1ec7}t", "Tieng Viet"),
        ("na\u{ef}ve", "naive"),
        ("plain", "plain"),
    ];
    for (input, want) in cases {
        let got = remove_diacritics(*input);
        if got.as_bytes() != want.as_bytes() {
            fmt::Println!("removeDiacritics mismatch:", *input, "got", got);
            die(b"t2: removeDiacritics mismatch\n");
        }
    }

    // ─── 3. Bytes mirrors String ───────────────────────────────────
    let b = norm::NFD.Bytes("caf\u{e9}".as_bytes());
    if b.as_ref() != "cafe\u{301}".as_bytes() {
        die(b"t3: Bytes/String mismatch\n");
    }

    let msg = b"UNICODE_NORM_OK 18 NFD vectors + removeDiacritics\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
