// time_layouts_ref_smoke — every named layout constant, rendered.
//
// Reference: Go 1.25.5 time, measured by tools/gen_time_layouts_ref.go.
// Every GO[] line is Go's verbatim output for the same instant.
//
// The generator existed and had been run; the smoke that turns it into
// a regression guard had not been written, so nothing in CI held the
// result. goish matches Go on all 15 lines.
//
// These constants are not interchangeable strings — each is a
// reference-time pattern, and one wrong digit in one silently changes
// what every caller of that constant emits AND accepts. The set is
// chosen to separate the ways that goes wrong:
//
//   Padding. ANSIC and Stamp use "Jan _2", space-padded, so the 2nd
//   renders "Jan  2" with two spaces; RubyDate uses "Jan 02",
//   zero-padded. A layout confusing _2 with 02 differs only on
//   single-digit days — three weeks in ten.
//
//   Zone rendering. RFC1123 prints the zone NAME ("UTC") where
//   RFC1123Z prints the OFFSET ("+0000"), and the same split runs
//   through RFC822/RFC822Z. Both spellings are on the wire in real
//   traffic.
//
//   Two-digit years. RFC850 and RFC822 render 2024 as "24".
//
//   AM/PM. Kitchen is measured twice, at 03:04 and 15:04, because a
//   layout that dropped the PM half still looks right all morning.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::time;

// Go's verbatim output.
const GO: [&str; 15] = [
    "RFC3339    \"2024-01-02T03:04:05Z\"",
    "DateTime   \"2024-01-02 03:04:05\"",
    "DateOnly   \"2024-01-02\"",
    "TimeOnly   \"03:04:05\"",
    "RFC1123    \"Tue, 02 Jan 2024 03:04:05 UTC\"",
    "RFC1123Z   \"Tue, 02 Jan 2024 03:04:05 +0000\"",
    "Kitchen    \"3:04AM\"",
    "ANSIC      \"Tue Jan  2 03:04:05 2024\"",
    "RFC850     \"Tuesday, 02-Jan-24 03:04:05 UTC\"",
    "RFC822     \"02 Jan 24 03:04 UTC\"",
    "RFC822Z    \"02 Jan 24 03:04 +0000\"",
    "UnixDate   \"Tue Jan  2 03:04:05 UTC 2024\"",
    "RubyDate   \"Tue Jan 02 03:04:05 +0000 2024\"",
    "Stamp      \"Jan  2 03:04:05\"",
    "KitchenPM  \"3:04PM\"",
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
    let tm = time::Date(2024, time::January, 2, 3, 4, 5, 0, time::UTC);
    let cases: [(&str, &str); 14] = [
        ("RFC3339", time::RFC3339),
        ("DateTime", time::DateTime),
        ("DateOnly", time::DateOnly),
        ("TimeOnly", time::TimeOnly),
        ("RFC1123", time::RFC1123),
        ("RFC1123Z", time::RFC1123Z),
        ("Kitchen", time::Kitchen),
        ("ANSIC", time::ANSIC),
        ("RFC850", time::RFC850),
        ("RFC822", time::RFC822),
        ("RFC822Z", time::RFC822Z),
        ("UnixDate", time::UnixDate),
        ("RubyDate", time::RubyDate),
        ("Stamp", time::Stamp),
    ];
    for (name, layout) in cases.iter() {
        chk(fmt::Sprintf!(
            "%-10s %q",
            goish::string::from_bytes(name.as_bytes()),
            tm.Format(goish::string::from_bytes(layout.as_bytes()))
        ));
    }
    let pm = time::Date(2024, time::January, 2, 15, 4, 5, 0, time::UTC);
    chk(fmt::Sprintf!(
        "%-10s %q",
        goish::string("KitchenPM"),
        pm.Format(goish::string::from_bytes(time::Kitchen.as_bytes()))
    ));
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
