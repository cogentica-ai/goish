// json_surrogate_ref_smoke — lone surrogates in a JSON string.
//
// Reference: Go 1.25.5 encoding/json, measured by
// tools/gen_jsonsurr_ref.go. Every GO[] line is Go's verbatim output.
//
// The generator existed and had been run; the smoke that makes it a
// regression guard had not been written. goish matches Go on all 10.
//
// A \uD800 escape names half of a surrogate pair. UTF-16 needs both
// halves; UTF-8 has no encoding for either half alone, so a decoder
// has to decide what a lone one becomes. Go NEVER errors here — it
// substitutes U+FFFD (EF BF BD) for each unpaired half and carries on.
//
// The choice matters more than it looks. Erroring and substituting are
// both defensible, but a decoder that passed the raw surrogate through
// would produce a Go string holding invalid UTF-8, and everything
// downstream — re-encoding to JSON, writing to a response, indexing by
// rune — would then be operating on bytes that cannot be valid. Two
// implementations that disagree about which of the three happens will
// disagree about the CONTENT of a decoded string, silently.
//
// The ten inputs cover each position an unpaired half can occupy: high
// alone, low alone, two highs, low-then-high (which pairs in neither
// direction), a lone half with text on both sides, before a plain
// character, and before an escape. A valid pair (U+1F600) and two
// plain BMP characters are there to show the substitution is not
// simply applied to everything.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::string::String;
use alloc::vec::Vec;
use goish::encoding::json;
use goish::fmt;
use goish::string;

// Go's verbatim output.
const GO: [&str; 10] = [
    "\"\\uD800\"             ok bytes=[239 191 189]",
    "\"\\uDC00\"             ok bytes=[239 191 189]",
    "\"\\uD800\\uD800\"       ok bytes=[239 191 189 239 191 189]",
    "\"😀\"                  ok bytes=[240 159 152 128]",
    "\"a\\uD800b\"           ok bytes=[97 239 191 189 98]",
    "\"\\uD800x\"            ok bytes=[239 191 189 120]",
    "\"A\"                  ok bytes=[65]",
    "\"é\"                  ok bytes=[195 169]",
    "\"\\uDC00\\uD800\"       ok bytes=[239 191 189 239 191 189]",
    "\"\\uD800A\"            ok bytes=[239 191 189 65]",
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

fn bytes_list(s: &goish::string) -> goish::string {
    let b = s.as_bytes();
    let mut out = String::from("[");
    for (i, c) in b.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let mut n = *c as u32;
        if n == 0 {
            out.push('0');
        } else {
            let mut d: Vec<u8> = Vec::new();
            while n > 0 {
                d.push(b'0' + (n % 10) as u8);
                n /= 10;
            }
            d.reverse();
            for ch in d.iter() {
                out.push(*ch as char);
            }
        }
    }
    out.push(']');
    goish::string::from_bytes(out.as_bytes())
}

#[goish::main]
fn main() {
    let inputs: [&str; 10] = [
        "\"\\uD800\"",
        "\"\\uDC00\"",
        "\"\\uD800\\uD800\"",
        "\"\u{1F600}\"",
        "\"a\\uD800b\"",
        "\"\\uD800x\"",
        "\"A\"",
        "\"\u{E9}\"",
        "\"\\uDC00\\uD800\"",
        "\"\\uD800A\"",
    ];
    for inp in inputs.iter() {
        let data = inp.as_bytes();
        let mut v: goish::string = string("");
        let err = json::Unmarshal(
            &goish::slice::<goish::byte>::__from_vec(data.to_vec()),
            &mut v,
        );
        let shown = goish::string::from_bytes(inp.as_bytes());
        if !err.IsNil() {
            chk(fmt::Sprintf!("%-20s err=%v", shown, err));
            continue;
        }
        chk(fmt::Sprintf!("%-20s ok bytes=%s", shown, bytes_list(&v)));
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
