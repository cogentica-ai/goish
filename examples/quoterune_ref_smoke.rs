// quoterune_ref_smoke — rune quoting and the titlecase category.
//
// Reference: Go 1.25.5, measured by tools/gen_quoterune_ref.go.
// Every GO[] line is Go's verbatim output.
//
// The generator for this has existed and been run; the smoke that
// turns it into a regression guard had not been written, so nothing
// in CI held the result. goish matches Go on all 11 lines, which is
// why it stayed unwritten — a measurement that finds nothing feels
// finished when the diff comes back clean.
//
// Two things are worth holding:
//
//   QuoteRune vs QuoteRuneToASCII on a rune that needs each escape
//   width: a plain ASCII letter, a control (\n), Latin-1 (U+00E9 ->
//   \u00e9), astral (U+1F600 -> \U0001f600, the 8-digit form), DEL
//   (U+007F -> \x7f, the 2-digit form), and a zero-width space
//   (U+200B), which IsPrint answers false for even though it is not a
//   control character. Picking \x, \u or \U by code point is easy to
//   get subtly wrong at each boundary.
//
//   unicode.IsTitle, which NOTHING else in this tree pins. The three
//   true cases are the ones a naive "is it uppercase" test gets
//   wrong: U+01C5 and U+01C8 are the Dz and Lj DIGRAPH titlecase
//   forms, which are a category of their own (Lt) and neither upper
//   nor lower, and U+1F88 is Greek capital alpha with prosgegrammeni,
//   titlecase by virtue of the iota subscript. A port that answered
//   IsTitle from an uppercase table would return true for U+0041 and
//   false for all three.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::strconv;
use goish::unicode;

// Go's verbatim output.
const GO: [&str; 11] = [
    "rune U+0061 quote=\"'a'\"        toascii=\"'a'\"          printable=true",
    "rune U+000A quote=\"'\\\\n'\"      toascii=\"'\\\\n'\"        printable=false",
    "rune U+00E9 quote=\"'é'\"        toascii=\"'\\\\u00e9'\"    printable=true",
    "rune U+1F600 quote=\"'😀'\"        toascii=\"'\\\\U0001f600'\" printable=true",
    "rune U+007F quote=\"'\\\\x7f'\"    toascii=\"'\\\\x7f'\"      printable=false",
    "rune U+200B quote=\"'\\\\u200b'\"  toascii=\"'\\\\u200b'\"    printable=false",
    "istitle U+0041 false",
    "istitle U+0061 false",
    "istitle U+01C5 true",
    "istitle U+01C8 true",
    "istitle U+1F88 true",
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

#[goish::main]
fn main() {
    let runes: [i32; 6] = [0x61, 0x0A, 0xE9, 0x1F600, 0x7F, 0x200B];
    for r in runes.iter() {
        let rr = *r as goish::rune;
        chk(fmt::Sprintf!(
            "rune U+%04X quote=%-12q toascii=%-14q printable=%v",
            *r as i64,
            strconv::QuoteRune(rr),
            strconv::QuoteRuneToASCII(rr),
            strconv::IsPrint(rr)
        ));
    }
    let titles: [i32; 5] = [0x41, 0x61, 0x01C5, 0x01C8, 0x1F88];
    for r in titles.iter() {
        chk(fmt::Sprintf!(
            "istitle U+%04X %v",
            *r as i64,
            unicode::IsTitle(*r as goish::rune)
        ));
    }
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
