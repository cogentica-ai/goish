// language_base_ref_smoke — every base-language subtag x/text accepts
// (#22).
//
// goish accepted 2930 base codes where golang.org/x/text v0.38.0 accepts
// 8984. The 6054 missing were all three-letter, and they included all
// 520 private-use codes `qaa`..`qtz` and x/text's whole non-indexed
// language set. Downstream that made `tsgo --locale not_a_locale` report
// TS6048 before compiling, because typescript-go delegates straight to
// `language.Parse`.
//
// ── the measurement that shaped the fix ──
//
// A bitmap of accepted codes is the obvious answer, and on its own it is
// WRONG. Dumping x/text over the whole aa..zz / aaa..zzz domain and
// diffing against goish's table:
//
//     accepted by x/text, absent from goish   6054  (all three-letter)
//     in goish, rejected by x/text               0
//     shared keys whose canonical form differs   0
//     of the missing, NON-identity canonical   241   <- eng -> en
//
// So 241 of the codes a bitmap would have admitted do not canonicalise
// to themselves. `eng` is `en`, `ell` is `el`, `fas` is `fa` — the ISO
// 639-2/B set. The tables are therefore split: VALID_LANGS keeps every
// code whose canonical form differs (and every two-letter code, of which
// there are only 190), and LANG3_ACCEPTED is a bit per `aaa`..`zzz`,
// which is x/text's own `langNoIndex` trick — 2197 bytes where the
// strings are a quarter of a megabyte. VALID_LANGS is consulted first so
// it always wins.
//
// ── the differential ──
//
// The last row walks the ENTIRE domain — 676 two-letter plus 17576
// three-letter inputs — and hashes every accepted `code\tcanonical\n`
// with FNV-1a 64 in x/text's own iteration order. The expected hash and
// count come from tools/gen_language_base_ref.go against x/text v0.38.0.
// A single wrong canonicalisation anywhere in 8984 entries moves the
// hash.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::text::language;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static ROWS: AtomicUsize = AtomicUsize::new(0);

/// x/text v0.38.0 over the whole domain.
const WANT_ACCEPTED: usize = 8984;
const WANT_TWO: usize = 190;
const WANT_THREE: usize = 8794;
const WANT_FNV: u64 = 0x6412_9d78_0cb3_ac1e;

fn check(name: &'static str, ok: bool, detail: string) {
    ROWS.fetch_add(1, Ordering::Relaxed);
    if ok {
        fmt::Printf!("[ok] %s\n", string::from_static(name));
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] %s — %s\n", string::from_static(name), detail);
    }
}

/// One parse, rendered the way the reference dump renders it.
fn parse_one(s: &str) -> (bool, string) {
    let (t, err) = language::Parse(string::from_bytes(s.as_bytes()));
    return (err.IsNil(), t.String());
}

fn expect_ok(input: &'static str, canon: &'static str) {
    let (ok, got) = parse_one(input);
    check(
        input,
        ok && (got.as_ref() as &str) == canon,
        fmt::Sprintf!(
            "got %q err=%v, want %q nil",
            got,
            !ok,
            string::from_static(canon)
        ),
    );
}

fn expect_err(input: &'static str) {
    let (ok, got) = parse_one(input);
    check(
        input,
        !ok && (got.as_ref() as &str) == "und",
        fmt::Sprintf!("got %q err=%v, want \"und\" + error", got, !ok),
    );
}

#[goish::main]
fn main() {
    // ── the four the issue reported ──
    expect_ok("not", "not");
    expect_ok("not_a_locale", "not-a-locale");
    expect_ok("qaa", "qaa");
    expect_ok("qtz", "qtz");

    // ── the rejection controls, so the fix is not "accept everything" ──
    expect_err("foo");
    expect_err("zzz");

    // ── the 241 a bitmap alone would have got wrong ──
    expect_ok("eng", "en");
    expect_ok("ell", "el");
    expect_ok("fas", "fa");

    // ── and the legacy merges that carry a script or region ──
    expect_ok("sh", "sr-Latn");
    expect_ok("mo", "ro-MD");
    expect_ok("en", "en");

    // ── the exhaustive differential ──
    let mut n: usize = 0;
    let mut two: usize = 0;
    let mut three: usize = 0;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut buf = [0u8; 3];
    let mut a = b'a';
    while a <= b'z' {
        let mut b = b'a';
        while b <= b'z' {
            // Two-letter first, then its three-letter block — the
            // generator's order, which the hash depends on.
            buf[0] = a;
            buf[1] = b;
            let two_s = core::str::from_utf8(&buf[..2]).unwrap_or("");
            let (ok2, canon2) = parse_one(two_s);
            if ok2 {
                n += 1;
                two += 1;
                h = fnv_line(h, two_s, &canon2);
            }
            let mut c = b'a';
            while c <= b'z' {
                buf[2] = c;
                let three_s = core::str::from_utf8(&buf[..3]).unwrap_or("");
                let (ok3, canon3) = parse_one(three_s);
                if ok3 {
                    n += 1;
                    three += 1;
                    h = fnv_line(h, three_s, &canon3);
                }
                c += 1;
            }
            b += 1;
        }
        a += 1;
    }

    check(
        "the accepted count matches x/text over the whole domain",
        n == WANT_ACCEPTED && two == WANT_TWO && three == WANT_THREE,
        fmt::Sprintf!(
            "accepted=%d (2:%d 3:%d), want %d (2:%d 3:%d)",
            n as i64,
            two as i64,
            three as i64,
            WANT_ACCEPTED as i64,
            WANT_TWO as i64,
            WANT_THREE as i64
        ),
    );
    check(
        "every canonicalisation matches x/text (FNV-1a 64 of all 8984)",
        h == WANT_FNV,
        fmt::Sprintf!("got 0x%x want 0x%x", h, WANT_FNV),
    );

    let ran = ROWS.load(Ordering::Relaxed);
    let bad = FAILED.load(Ordering::Relaxed);
    if ran != 14 {
        fmt::Printf!("\nFAILED: %d rows ran, expected 14\n", ran as i64);
        goish::os::Exit(1);
    }
    if bad != 0 {
        fmt::Printf!("\nFAILED %d of %d row(s)\n", bad as i64, ran as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ran as i64, ran as i64);
}

/// FNV-1a 64 over `code\tcanonical\n`, matching the Python that produced
/// WANT_FNV from x/text's dump.
fn fnv_line(mut h: u64, code: &str, canon: &string) -> u64 {
    for ch in code.as_bytes() {
        h ^= *ch as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h ^= b'\t' as u64;
    h = h.wrapping_mul(0x100_0000_01b3);
    for ch in canon.as_bytes() {
        h ^= *ch as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h ^= b'\n' as u64;
    h = h.wrapping_mul(0x100_0000_01b3);
    return h;
}
