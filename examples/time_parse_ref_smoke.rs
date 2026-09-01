// time_parse_ref_smoke — time.Parse against a running Go.
// (time/format.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_time_parse_ref.go` run in
// `package time_test` by `scripts/goref.sh`.
//
// Go's Parse is layout-driven: `nextStdChunk` walks the layout and each
// chunk consumes its part of the value. goish's was a switch over TEN
// hard-coded layout strings that returned `time: unsupported layout`
// for anything else — including `RFC3339Nano`, `RFC1123Z`, `RFC822`,
// `RFC850`, `RubyDate`, `Kitchen`, `Stamp`, `StampMilli`, `Layout` and
// `UnixDate`, every one of which the same file declares as a constant.
// Ten of the cases below use exactly those.
//
// The error text is checked too, because Go's is structured — a
// ParseError carrying the layout, the value, and which element failed —
// and goish returned one flat `errors.New` for every failure. A caller
// that reads the message to say WHICH field was wrong got nothing.
//
// The interesting rows are the ones where a plausible implementation
// and Go's part company: "2023-02-29" is a day-out-of-range but
// "2024-02-29" is fine; a two-digit year pivots at 69; "24:00:00" is
// out of range but a zone offset of 24 hours is not; `.999` accepts a
// missing fraction and `.000` does not; a fractional second in the
// input with none in the layout is consumed anyway; and "GMT+3" is a
// zone with an offset while "CEST" is a zone without one.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::time;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// (layout, value, want_unix, want_nsec, want_err) — Go 1.25.5 verbatim.
// A want_err of "" means Go returned a nil error.
const CASES: [(&str, &str, int, int, &str); 91] = [
    (
        "2006-01-02T15:04:05Z07:00",
        "2023-11-14T22:13:20Z",
        1700000000,
        0,
        "",
    ),
    (
        "2006-01-02T15:04:05Z07:00",
        "2023-11-14T22:13:20+00:00",
        1700000000,
        0,
        "",
    ),
    (
        "2006-01-02T15:04:05Z07:00",
        "2023-11-14T22:13:20-05:00",
        1700018000,
        0,
        "",
    ),
    (
        "2006-01-02T15:04:05Z07:00",
        "2023-11-14T22:13:20+05:30",
        1699980200,
        0,
        "",
    ),
    (
        "2006-01-02T15:04:05.999999999Z07:00",
        "2023-11-14T22:13:20.123456789Z",
        1700000000,
        123456789,
        "",
    ),
    (
        "2006-01-02T15:04:05.999999999Z07:00",
        "2023-11-14T22:13:20.1Z",
        1700000000,
        100000000,
        "",
    ),
    (
        "2006-01-02T15:04:05.999999999Z07:00",
        "2023-11-14T22:13:20Z",
        1700000000,
        0,
        "",
    ),
    (
        "Mon, 02 Jan 2006 15:04:05 MST",
        "Tue, 14 Nov 2023 22:13:20 UTC",
        1700000000,
        0,
        "",
    ),
    (
        "Mon, 02 Jan 2006 15:04:05 MST",
        "Tue, 14 Nov 2023 22:13:20 GMT",
        1700000000,
        0,
        "",
    ),
    (
        "Mon, 02 Jan 2006 15:04:05 -0700",
        "Tue, 14 Nov 2023 22:13:20 +0000",
        1700000000,
        0,
        "",
    ),
    (
        "Mon, 02 Jan 2006 15:04:05 -0700",
        "Tue, 14 Nov 2023 22:13:20 -0800",
        1700028800,
        0,
        "",
    ),
    (
        "02 Jan 06 15:04 MST",
        "14 Nov 23 22:13 UTC",
        1699999980,
        0,
        "",
    ),
    (
        "02 Jan 06 15:04 -0700",
        "14 Nov 23 22:13 +0000",
        1699999980,
        0,
        "",
    ),
    (
        "Monday, 02-Jan-06 15:04:05 MST",
        "Tuesday, 14-Nov-23 22:13:20 UTC",
        1700000000,
        0,
        "",
    ),
    (
        "Mon Jan _2 15:04:05 2006",
        "Tue Nov 14 22:13:20 2023",
        1700000000,
        0,
        "",
    ),
    (
        "Mon Jan _2 15:04:05 2006",
        "Tue Nov  4 22:13:20 2023",
        1699136000,
        0,
        "",
    ),
    (
        "Mon Jan _2 15:04:05 MST 2006",
        "Tue Nov 14 22:13:20 UTC 2023",
        1700000000,
        0,
        "",
    ),
    (
        "Mon Jan 02 15:04:05 -0700 2006",
        "Tue Nov 14 22:13:20 +0000 2023",
        1700000000,
        0,
        "",
    ),
    ("3:04PM", "10:13PM", -62167139220, 0, ""),
    ("3:04PM", "10:13AM", -62167182420, 0, ""),
    ("3:04PM", "12:00AM", -62167219200, 0, ""),
    ("3:04PM", "12:00PM", -62167176000, 0, ""),
    ("Jan _2 15:04:05", "Nov 14 22:13:20", -62139664000, 0, ""),
    (
        "Jan _2 15:04:05.000",
        "Nov 14 22:13:20.123",
        -62139664000,
        123000000,
        "",
    ),
    (
        "Jan _2 15:04:05.000000",
        "Nov 14 22:13:20.123456",
        -62139664000,
        123456000,
        "",
    ),
    (
        "Jan _2 15:04:05.000000000",
        "Nov 14 22:13:20.123456789",
        -62139664000,
        123456789,
        "",
    ),
    (
        "2006-01-02 15:04:05",
        "2023-11-14 22:13:20",
        1700000000,
        0,
        "",
    ),
    ("2006-01-02", "2023-11-14", 1699920000, 0, ""),
    ("15:04:05", "22:13:20", -62167139200, 0, ""),
    (
        "01/02 03:04:05PM '06 -0700",
        "11/14 10:13:20PM '23 +0000",
        1700000000,
        0,
        "",
    ),
    (
        "2006-01-02",
        "2023-02-29",
        -62135596800,
        0,
        "parsing time \"2023-02-29\": day out of range",
    ),
    ("2006-01-02", "2024-02-29", 1709164800, 0, ""),
    (
        "2006-01-02",
        "2023-13-01",
        -62135596800,
        0,
        "parsing time \"2023-13-01\": month out of range",
    ),
    (
        "2006-01-02",
        "2023-00-01",
        -62135596800,
        0,
        "parsing time \"2023-00-01\": month out of range",
    ),
    (
        "2006-01-02",
        "2023-01-32",
        -62135596800,
        0,
        "parsing time \"2023-01-32\": day out of range",
    ),
    (
        "2006-01-02",
        "2023-1-1",
        -62135596800,
        0,
        "parsing time \"2023-1-1\" as \"2006-01-02\": cannot parse \"1-1\" as \"01\"",
    ),
    ("2006-1-2", "2023-1-1", 1672531200, 0, ""),
    ("2006-1-2", "2023-11-14", 1699920000, 0, ""),
    ("2006-002", "2023-001", 1672531200, 0, ""),
    ("2006-002", "2023-365", 1703980800, 0, ""),
    ("2006-002", "2024-060", 1709164800, 0, ""),
    (
        "2006-002",
        "2023-366",
        -62135596800,
        0,
        "parsing time \"2023-366\": day-of-year out of range",
    ),
    ("2006 __2", "2023  60", 1677628800, 0, ""),
    ("06", "69", -31536000, 0, ""),
    ("06", "68", 3092601600, 0, ""),
    ("06", "00", 946684800, 0, ""),
    ("06", "99", 915148800, 0, ""),
    ("15:04:05", "22:13:20", -62167139200, 0, ""),
    (
        "15:04:05",
        "24:00:00",
        -62135596800,
        0,
        "parsing time \"24:00:00\": hour out of range",
    ),
    (
        "15:04:05",
        "23:60:00",
        -62135596800,
        0,
        "parsing time \"23:60:00\": minute out of range",
    ),
    (
        "15:04:05",
        "23:59:60",
        -62135596800,
        0,
        "parsing time \"23:59:60\": second out of range",
    ),
    ("15:04:05", "23:59:59.5", -62167132801, 500000000, ""),
    (
        "15:04:05.000",
        "23:59:59.5",
        -62135596800,
        0,
        "parsing time \"23:59:59.5\" as \"15:04:05.000\": cannot parse \".5\" as \".000\"",
    ),
    ("15:04:05.000", "23:59:59.500", -62167132801, 500000000, ""),
    ("15:04:05.999", "23:59:59", -62167132801, 0, ""),
    ("15:04:05.999", "23:59:59.5", -62167132801, 500000000, ""),
    ("15:04:05,000", "23:59:59,500", -62167132801, 500000000, ""),
    ("3:04PM", "9:05AM", -62167186500, 0, ""),
    ("3:04pm", "9:05am", -62167186500, 0, ""),
    ("Jan 2 2006", "Nov 14 2023", 1699920000, 0, ""),
    ("January 2, 2006", "November 14, 2023", 1699920000, 0, ""),
    ("Monday", "Tuesday", -62167219200, 0, ""),
    ("Mon", "Tue", -62167219200, 0, ""),
    (
        "Mon",
        "Xyz",
        -62135596800,
        0,
        "parsing time \"Xyz\" as \"Mon\": cannot parse \"Xyz\" as \"Mon\"",
    ),
    (
        "2006-01-02T15:04:05Z0700",
        "2023-11-14T22:13:20Z",
        1700000000,
        0,
        "",
    ),
    (
        "2006-01-02T15:04:05Z0700",
        "2023-11-14T22:13:20-0500",
        1700018000,
        0,
        "",
    ),
    (
        "2006-01-02T15:04:05Z07",
        "2023-11-14T22:13:20-05",
        1700018000,
        0,
        "",
    ),
    (
        "2006-01-02T15:04:05Z070000",
        "2023-11-14T22:13:20-050000",
        1700018000,
        0,
        "",
    ),
    (
        "2006-01-02T15:04:05Z07:00:00",
        "2023-11-14T22:13:20-05:00:00",
        1700018000,
        0,
        "",
    ),
    (
        "2006-01-02T15:04:05-0700",
        "2023-11-14T22:13:20-0500",
        1700018000,
        0,
        "",
    ),
    (
        "2006-01-02T15:04:05-07:00",
        "2023-11-14T22:13:20-05:00",
        1700018000,
        0,
        "",
    ),
    (
        "2006-01-02T15:04:05-07",
        "2023-11-14T22:13:20-05",
        1700018000,
        0,
        "",
    ),
    ("060102150405Z0700", "231114221320Z", 1700000000, 0, ""),
    ("20060102150405Z0700", "20231114221320Z", 1700000000, 0, ""),
    (
        "20060102150405.999999999Z0700",
        "20231114221320.5Z",
        1700000000,
        500000000,
        "",
    ),
    ("0601021504Z0700", "2311142213Z", 1699999980, 0, ""),
    (
        "2006-01-02",
        "2023-11-14 extra",
        -62135596800,
        0,
        "parsing time \"2023-11-14 extra\": extra text: \" extra\"",
    ),
    (
        "2006-01-02",
        "junk",
        -62135596800,
        0,
        "parsing time \"junk\" as \"2006-01-02\": cannot parse \"junk\" as \"2006\"",
    ),
    (
        "2006-01-02",
        "",
        -62135596800,
        0,
        "parsing time \"\" as \"2006-01-02\": cannot parse \"\" as \"2006\"",
    ),
    (
        "2006-01-02",
        "2023-11",
        -62135596800,
        0,
        "parsing time \"2023-11\" as \"2006-01-02\": cannot parse \"\" as \"-\"",
    ),
    ("", "", -62167219200, 0, ""),
    (
        "",
        "x",
        -62135596800,
        0,
        "parsing time \"x\": extra text: \"x\"",
    ),
    ("MST", "UTC", -62167219200, 0, ""),
    ("MST", "GMT", -62167219200, 0, ""),
    ("MST", "GMT+3", -62167219200, 0, ""),
    ("MST", "GMT-7", -62167219200, 0, ""),
    ("MST", "CEST", -62167219200, 0, ""),
    ("MST", "ChST", -62167219200, 0, ""),
    ("MST", "WITA", -62167219200, 0, ""),
    (
        "MST",
        "AB",
        -62135596800,
        0,
        "parsing time \"AB\" as \"MST\": cannot parse \"AB\" as \"MST\"",
    ),
    (
        "2006-01-02 15:04:05 -0700 MST",
        "2023-11-14 22:13:20 +0000 UTC",
        1700000000,
        0,
        "",
    ),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The instant Parse returns, compared on Unix seconds and
    //    nanoseconds. A zone offset has to move the instant, and a
    //    fractional second has to land in the right decimal place.
    {
        let mut ok = true;
        let mut bad = 0;
        let mut i = 0;
        while i < CASES.len() {
            let (lay, val, want_unix, want_nsec, want_err) = CASES[i];
            let (t, err) = time::Parse(lay, val);
            if want_err == "" {
                if !err.IsNil() {
                    if bad < 8 {
                        fmt::Println!("   ", s(lay), s(val), "unexpected err", err.Error());
                    }
                    bad += 1;
                    ok = false;
                } else if t.Unix() != want_unix || t.Nanosecond() != want_nsec {
                    if bad < 8 {
                        fmt::Println!(
                            "   ",
                            s(lay),
                            s(val),
                            "want",
                            want_unix,
                            want_nsec,
                            "got",
                            t.Unix(),
                            t.Nanosecond()
                        );
                    }
                    bad += 1;
                    ok = false;
                }
            }
            i += 1;
        }
        if bad > 0 {
            fmt::Println!("   ", bad, "mismatches");
        }
        report(&mut failed, ok, " 1", "Parse over 91 layout/value pairs");
    }

    // 2. The failures fail, with Go's exact message. This is where the
    //    ParseError structure shows: "cannot parse X as Y" names the
    //    element, and the range errors name the field.
    {
        let mut ok = true;
        let mut bad = 0;
        let mut i = 0;
        while i < CASES.len() {
            let (lay, val, _, _, want_err) = CASES[i];
            if want_err != "" {
                let (_, err) = time::Parse(lay, val);
                if err.IsNil() || err.Error() != s(want_err) {
                    if bad < 8 {
                        let got = if err.IsNil() { s("<nil>") } else { err.Error() };
                        fmt::Println!("   ", s(lay), s(val), "want", s(want_err), "got", got);
                    }
                    bad += 1;
                    ok = false;
                }
            }
            i += 1;
        }
        if bad > 0 {
            fmt::Println!("   ", bad, "mismatches");
        }
        report(&mut failed, ok, " 2", "the error text, element by element");
    }

    // 3. Format and Parse are inverses over every layout that carries a
    //    full date and time. This is the property callers actually rely
    //    on, and neither half can fake it alone.
    {
        let mut ok = true;
        let layouts: [&str; 10] = [
            time::RFC3339,
            time::RFC3339Nano,
            time::RFC1123,
            time::RFC1123Z,
            time::RFC850,
            time::ANSIC,
            time::UnixDate,
            time::RubyDate,
            time::DateTime,
            "2006-01-02T15:04:05.999999999-07:00",
        ];
        let instants: [(int, int); 4] = [
            (1_700_000_000, 0),
            (0, 0),
            (1_704_067_199, 0),
            (951_782_400, 0),
        ];
        let mut li = 0;
        while li < layouts.len() {
            let mut ii = 0;
            while ii < instants.len() {
                let (sec, nsec) = instants[ii];
                let t = time::Unix(sec, nsec);
                let text = t.Format(layouts[li]);
                let (back, err) = time::Parse(layouts[li], text.clone());
                if !err.IsNil() || back.Unix() != sec {
                    fmt::Println!("   ", s(layouts[li]), text, "->", back.Unix(), "want", sec);
                    ok = false;
                }
                ii += 1;
            }
            li += 1;
        }
        report(&mut failed, ok, " 3", "Format and Parse are inverses");
    }

    // 4. ParseInLocation exists and, with goish's UTC-only Location,
    //    agrees with Parse.
    {
        let (a, ea) = time::Parse(time::RFC3339, "2023-11-14T22:13:20Z");
        let (b, eb) = time::ParseInLocation(time::RFC3339, "2023-11-14T22:13:20Z", time::UTC);
        let ok = ea.IsNil() && eb.IsNil() && a.Unix() == b.Unix();
        report(&mut failed, ok, " 4", "ParseInLocation");
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
