// utf8bad_ref_smoke — unicode/utf8 on strings that are NOT valid UTF-8.
// (unicode/utf8/utf8.go)
//
// A Go string is a byte sequence, not guaranteed UTF-8. `string(b)` for
// any []byte is legal Go, and so is a byte-offset slice that cuts a
// multi-byte rune in half. utf8's whole invalid-input contract —
// (RuneError, 1) per bad byte, so a caller cannot loop forever — is
// about exactly these values.
//
// `utf8_ref_smoke` already covers that contract thoroughly, but every
// call it makes is to a BYTE-SLICE entry point (DecodeRune, Valid,
// RuneCount); it contains zero `*InString` calls. That is what let a
// defect sit here: the five `*InString` functions took `AsRef<str>` and
// went `s.as_ref().as_bytes()` — a round trip through a Rust `&str`,
// which by its own type invariant cannot hold these bytes. The
// signature made the interesting input unrepresentable, so no test
// could pass it, so nothing failed.
//
// Measured before the fix, the round trip happened to print all 13
// lines correctly on this toolchain: it was latent undefined
// behaviour, not a wrong answer. It is removed rather than tolerated
// because `from_utf8_unchecked` licenses the optimiser to assume
// something false about the buffer.
//
// Every expectation is what a real Go 1.25.5 prints, via
// `scripts/goref.sh`.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string;
use goish::types::int;
use goish::unicode::utf8;

const GO: [&str; 13] = [
    "ValidString                    [false false false false false]",
    "ValidString-good               [true true]",
    "DecodeRune-bad                 [97 1]",
    "DecodeRune-at-ff               [65533 1 true]",
    "DecodeRune-trunc               [65533 1]",
    "DecodeRune-surro               [65533 1]",
    "DecodeRune-over                [65533 1]",
    "DecodeRune-empty               [65533 0]",
    "DecodeLast-bad                 [98 1]",
    "DecodeLast-lone                [65533 1]",
    "RuneCountInString              [3 1 2 5]",
    "FullRuneInString               [false true true]",
    "len-bad                        [3 1 2]",
];

static mut BAD: usize = 0;

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        unsafe { BAD += 1 };
        *ln += 1;
        return;
    }
    let want = GO[*ln];
    if got == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        unsafe { BAD += 1 };
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, want);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let bad = string::from_bytes(&[0x61, 0xff, 0x62]);
    let lone = string::from_bytes(&[0xff]);
    let trunc = string::from_bytes(&[0xe4, 0xb8]);
    let surro = string::from_bytes(&[0xed, 0xa0, 0x80]);
    let over = string::from_bytes(&[0xc0, 0xaf]);

    chk(&mut ln, &fmt::Sprintf!("ValidString                    [%v %v %v %v %v]",
        utf8::ValidString(&bad), utf8::ValidString(&lone),
        utf8::ValidString(&trunc), utf8::ValidString(&surro),
        utf8::ValidString(&over)));
    chk(&mut ln, &fmt::Sprintf!("ValidString-good               [%v %v]",
        utf8::ValidString("héllo"), utf8::ValidString("")));

    let (r, n) = utf8::DecodeRuneInString(&bad);
    chk(&mut ln, &fmt::Sprintf!("DecodeRune-bad                 [%v %v]", r, n));
    let (r, n) = utf8::DecodeRuneInString(bad.slice(1, 3));
    chk(&mut ln, &fmt::Sprintf!("DecodeRune-at-ff               [%v %v %v]", r, n, r == utf8::RuneError));
    let (r, n) = utf8::DecodeRuneInString(&trunc);
    chk(&mut ln, &fmt::Sprintf!("DecodeRune-trunc               [%v %v]", r, n));
    let (r, n) = utf8::DecodeRuneInString(&surro);
    chk(&mut ln, &fmt::Sprintf!("DecodeRune-surro               [%v %v]", r, n));
    let (r, n) = utf8::DecodeRuneInString(&over);
    chk(&mut ln, &fmt::Sprintf!("DecodeRune-over                [%v %v]", r, n));
    let (r, n) = utf8::DecodeRuneInString("");
    chk(&mut ln, &fmt::Sprintf!("DecodeRune-empty               [%v %v]", r, n));

    let (r, n) = utf8::DecodeLastRuneInString(&bad);
    chk(&mut ln, &fmt::Sprintf!("DecodeLast-bad                 [%v %v]", r, n));
    let (r, n) = utf8::DecodeLastRuneInString(&lone);
    chk(&mut ln, &fmt::Sprintf!("DecodeLast-lone                [%v %v]", r, n));

    chk(&mut ln, &fmt::Sprintf!("RuneCountInString              [%v %v %v %v]",
        utf8::RuneCountInString(&bad), utf8::RuneCountInString(&lone),
        utf8::RuneCountInString(&trunc), utf8::RuneCountInString("héllo")));

    chk(&mut ln, &fmt::Sprintf!("FullRuneInString               [%v %v %v]",
        utf8::FullRuneInString(&trunc), utf8::FullRuneInString(&lone),
        utf8::FullRuneInString("é")));

    chk(&mut ln, &fmt::Sprintf!("len-bad                        [%v %v %v]",
        bad.Len(), lone.Len(), trunc.Len()));
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        unsafe { BAD += 1 };
    }
    let bad = unsafe { BAD };
    if bad != 0 {
        // e2e_runner.sh: "rc=0 wins regardless of stdout content",
        // so printing the mismatch is not enough to fail CI.
        fmt::Printf!("[!!] %d row(s) diverge from Go\n", bad as i64);
        goish::os::Exit(1);
    }
}
