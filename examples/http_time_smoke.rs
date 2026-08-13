// http_time_smoke — http.ParseTime and the http.TimeFormat round-trip.
//
// ParseTime accepts the three formats HTTP/1.1 allows: IMF-fixdate,
// RFC 850 and ANSI C asctime. Every expected value below is Go 1.25.5
// output, produced by calling ParseTime inside a writable GOROOT
// (scripts/goref.sh net/http) — none of it is read off the layout
// strings, because the layout strings do not tell you the strictness
// rules and I got several of them wrong by guessing:
//
//   * The weekday must be well-formed but need NOT agree with the
//     date: "Mon, 06 Nov 1994" parses though that day was a Sunday.
//   * IMF-fixdate wants the 3-letter abbreviation and REJECTS the full
//     name; RFC 850 wants the full name and REJECTS the abbreviation.
//   * Weekday and month names fold case ("sunday", "SUN", "nov" all
//     parse); the zone does NOT ("gmt" is an error).
//   * IMF-fixdate demands the literal zone "GMT" — "UTC", "XYZ",
//     "+0000" and a missing zone are all errors.
//   * RFC 850 takes ANY 3-letter uppercase zone and treats it as UTC,
//     so "EST" and "XYZ" land on the same instant as "GMT", but a
//     missing or 2-letter zone is an error.
//   * RFC 850 years are 2 digits and pivot at 69: 69 is 1969, 68 is
//     2068, 00 is 2000, 99 is 1999.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http;
use goish::time;
use goish::{string, syscall};

// Sun, 06 Nov 1994 08:49:37 UTC
const REF: i64 = 784111777;

#[goish::main]
fn main() {
    let mut failed = 0;

    // (input, expected unix seconds, or 0 meaning "must error")
    let cases: &[(&str, i64)] = &[
        // ── IMF-fixdate ────────────────────────────────────────────
        ("Sun, 06 Nov 1994 08:49:37 GMT", REF),
        ("Mon, 06 Nov 1994 08:49:37 GMT", REF), // weekday not cross-checked
        ("SUN, 06 Nov 1994 08:49:37 GMT", REF), // weekday folds case
        ("Sun, 06 nov 1994 08:49:37 GMT", REF), // month folds case
        ("Xyz, 06 Nov 1994 08:49:37 GMT", 0),   // bogus weekday
        ("Sunday, 06 Nov 1994 08:49:37 GMT", 0), // full name not allowed here
        ("Sun, 06 Nov 1994 08:49:37 UTC", 0),   // zone must be GMT
        ("Sun, 06 Nov 1994 08:49:37 XYZ", 0),
        ("Sun, 06 Nov 1994 08:49:37 +0000", 0),
        ("Sun, 06 Nov 1994 08:49:37 gmt", 0), // zone does not fold case
        ("Sun, 06 Nov 1994 08:49:37", 0),     // zone required
        ("Sun, 6 Nov 1994 08:49:37 GMT", 0),  // day must be 2 digits
        // ── RFC 850 ────────────────────────────────────────────────
        ("Sunday, 06-Nov-94 08:49:37 GMT", REF),
        ("Monday, 06-Nov-94 08:49:37 GMT", REF), // not cross-checked
        ("sunday, 06-Nov-94 08:49:37 GMT", REF), // folds case
        ("Sunday, 06-Nov-94 08:49:37 UTC", REF),
        ("Sunday, 06-Nov-94 08:49:37 EST", REF), // any 3-letter zone is UTC
        ("Sunday, 06-Nov-94 08:49:37 XYZ", REF),
        ("Sun, 06-Nov-94 08:49:37 GMT", 0),      // abbreviation not allowed
        ("Xyzzy, 06-Nov-94 08:49:37 GMT", 0),    // bogus full weekday
        ("Sunday, 06-Nov-1994 08:49:37 GMT", 0), // 4-digit year rejected
        ("Sunday, 06-Nov-94 08:49:37 gmt", 0),   // zone case-sensitive
        ("Sunday, 06-Nov-94 08:49:37 UT", 0),    // 2-letter zone
        ("Sunday, 06-Nov-94 08:49:37", 0),       // zone required
        // The form goish used to accept and Go never did.
        ("Mon, 02-Jan-2006 15:04:05 MST", 0),
        // ── ANSI C asctime ─────────────────────────────────────────
        ("Sun Nov  6 08:49:37 1994", REF),
        ("Sun Nov 6 08:49:37 1994", REF),
        ("Sun Nov 06 08:49:37 1994", REF),
        // ── junk ───────────────────────────────────────────────────
        ("not a date", 0),
        ("", 0),
    ];

    let mut bad = 0;
    for (input, want) in cases {
        let (t, err) = http::ParseTime(string(*input));
        if *want == 0 {
            if err.IsNil() {
                fmt::Println!("     want ERROR, parsed: ", *input, " unix=", t.Unix());
                bad += 1;
            }
        } else if !err.IsNil() {
            fmt::Println!("     want parse, got error: ", *input);
            bad += 1;
        } else if t.Unix() != *want {
            fmt::Println!("     wrong instant: ", *input, " unix=", t.Unix());
            bad += 1;
        }
    }
    if bad == 0 {
        fmt::Println!("[1] ParseTime, 30 cases vs Go 1.25.5  PASS");
    } else {
        fmt::Println!("[1] ParseTime  FAIL ", bad, " of 30");
        failed += 1;
    }

    // 2. RFC 850's two-digit year pivots at 69.
    {
        let years: &[(&str, i64)] = &[
            ("Tuesday, 01-Jan-69 00:00:00 GMT", -31536000),  // 1969
            ("Wednesday, 01-Jan-68 00:00:00 GMT", 3092601600), // 2068
            ("Thursday, 01-Jan-00 00:00:00 GMT", 946684800),  // 2000
            ("Friday, 31-Dec-99 23:59:59 GMT", 946684799),    // 1999
        ];
        let mut yb = 0;
        for (input, want) in years {
            let (t, err) = http::ParseTime(string(*input));
            if !err.IsNil() || t.Unix() != *want {
                fmt::Println!("     pivot: ", *input, " unix=", t.Unix());
                yb += 1;
            }
        }
        if yb == 0 {
            fmt::Println!("[2] RFC 850 year pivot at 69  PASS");
        } else {
            fmt::Println!("[2] RFC 850 year pivot  FAIL");
            failed += 1;
        }
    }

    // 3. TimeFormat constant matches the reference layout.
    if http::TimeFormat == "Mon, 02 Jan 2006 15:04:05 GMT" {
        fmt::Println!("[3] TimeFormat constant  PASS");
    } else {
        fmt::Println!("[3] TimeFormat constant  FAIL");
        failed += 1;
    }

    // 4. Format/ParseTime round-trip.
    {
        let now = time::Now();
        let s = now.UTC().Format(string(http::TimeFormat));
        let (back, err) = http::ParseTime(s.clone());
        if err.IsNil() && back.Unix() == now.Unix() {
            fmt::Println!("[4] TimeFormat round-trip  PASS");
        } else {
            fmt::Println!("[4] TimeFormat round-trip  FAIL ", s);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 4");
        syscall::Exit(1);
    }
}
