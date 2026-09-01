// time_zone_ref_smoke — Time carries a Location, against a running Go.
// (time/zoneinfo.go, time/time.go, time/format.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_time_zone_ref.go` run in `package
// time_test` by `scripts/goref.sh`.
//
// A `Time` is an instant AND a location, and every wall-clock reader —
// `Format`, `Date`, `Clock`, `Hour`, `Weekday`, `YearDay` — reports the
// second one. goish's `Location` was an empty struct: it had no name
// and no offset, `Zone()` was hard-wired to ("UTC", 0), and `In` did
// not exist. So the port stopped at the instant.
//
// That is not a cosmetic gap. `Parse` of "2024-01-02T03:04:05+02:00"
// computed the correct instant and then discarded the offset, so
// `Format` gave back "2024-01-02T01:04:05Z" — the right moment rendered
// as the wrong wall clock, which is the difference every RFC 3339 round
// trip through a JSON API would show, in the direction that looks like
// a working timestamp. `Date(..., FixedZone(...))` ignored the zone and
// built the instant as if the fields were UTC, an offset-sized error in
// the other direction. `ParseInLocation` was `Parse`.
//
// It also reached past `time`: encoding/asn1's `parseUTCTime` and
// `parseGeneralizedTime` run Go's re-`Format`-and-compare guard, which
// could never pass for a numeric zone offset, so both REJECTED strings
// Go accepts. That divergence was pinned in x509_keys_smoke; it is
// closed here, and those assertions now read the Go way.
//
// `Location` here holds a name and a fixed offset, which covers UTC,
// `FixedZone` and every parsed offset. The tzdata machinery
// (`LoadLocation`, DST transitions) is still absent, so `Local` is UTC
// with the name "Local" — stated rather than implied.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

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

// go: none — goish idiom: the Go reference's `base`, hoisted so every
//     check below reads against one instant.
const BASE: int = 1_704_164_645;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Parse keeps the offset it read, and Format hands it back.
    //    Every `want` below is the INPUT string: an RFC 3339 round trip
    //    is the identity, which is exactly what it stopped being.
    {
        let mut ok = true;
        // (input, want_unix, want_offset, want_hour)
        let cases: [(&str, int, int, int); 4] = [
            ("2024-01-02T03:04:05Z", 1_704_164_645, 0, 3),
            ("2024-01-02T03:04:05+02:00", 1_704_157_445, 7200, 3),
            ("2024-01-02T03:04:05-05:30", 1_704_184_445, -19800, 3),
            (
                "2024-01-02T03:04:05.123456789+02:00",
                1_704_157_445,
                7200,
                3,
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, want_unix, want_off, want_hour) = cases[i];
            let (t, err) = time::Parse(time::RFC3339Nano, inp);
            if !err.IsNil() {
                ok = false;
            } else {
                if t.Format(time::RFC3339Nano) != s(inp) {
                    ok = false;
                }
                if t.Unix() != want_unix || t.Hour() != want_hour {
                    ok = false;
                }
                let (_, off) = t.Zone();
                if off != want_off {
                    ok = false;
                }
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "RFC 3339 round trip is the identity");
    }

    // 2. A parsed numeric offset is an ANONYMOUS zone: Go names it "",
    //    not "UTC" and not the offset. Go: zone=("",7200) loc="".
    //    Only the `Z` form is the named UTC.
    {
        let mut ok = true;
        let (t, _) = time::Parse(time::RFC3339, "2024-01-02T03:04:05+02:00");
        let (name, off) = t.Zone();
        if name != s("") || off != 7200 || t.Location().String() != s("") {
            ok = false;
        }
        let (u, _) = time::Parse(time::RFC3339, "2024-01-02T03:04:05Z");
        let (uname, uoff) = u.Zone();
        if uname != s("UTC") || uoff != 0 || u.Location().String() != s("UTC") {
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 2",
            "a parsed offset is an anonymous zone",
        );
    }

    // 3. `In` moves the wall clock without moving the instant. Go:
    //    fixed utc="2024-01-02T03:04:05Z" in="2024-01-02T05:04:05+02:00"
    //    zone=("CEST",7200) hour=3,5 date=2,2.
    {
        let mut ok = true;
        let z = time::FixedZone("CEST", 2 * 3600);
        let base = time::Unix(BASE, 0);
        let inz = base.In(z);
        if base.UTC().Format(time::RFC3339) != s("2024-01-02T03:04:05Z") {
            ok = false;
        }
        if inz.Format(time::RFC3339) != s("2024-01-02T05:04:05+02:00") {
            ok = false;
        }
        let (zn, zo) = inz.Zone();
        if zn != s("CEST") || zo != 7200 {
            ok = false;
        }
        // The instant is untouched — only the reading of it changed.
        if inz.Unix() != base.Unix() || !inz.Equal(base) {
            ok = false;
        }
        if base.UTC().Hour() != 3 || inz.Hour() != 5 {
            ok = false;
        }
        if base.UTC().Day() != 2 || inz.Day() != 2 {
            ok = false;
        }
        report(&mut failed, ok, " 3", "In moves the clock, not the instant");
    }

    // 4. A negative offset with a half-hour part, which also rolls the
    //    DATE back a day. Go: neg in="2024-01-01T23:34:05-03:30"
    //    hour=23 day=1 zonename="NST".
    {
        let mut ok = true;
        let neg = time::FixedZone("NST", -(3 * 3600 + 30 * 60));
        let inn = time::Unix(BASE, 0).In(neg);
        if inn.Format(time::RFC3339) != s("2024-01-01T23:34:05-03:30") {
            ok = false;
        }
        if inn.Hour() != 23 || inn.Day() != 1 {
            ok = false;
        }
        if inn.Location().String() != s("NST") {
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 4",
            "a negative offset rolls the date back",
        );
    }

    // 5. `Date` reads its fields IN the location it is given, so the
    //    instant it builds is offset from the same fields in UTC. Go:
    //    date "2024-01-02T03:04:05+02:00" unix=1704157445
    //    utc="2024-01-02T01:04:05Z". A port that ignores the zone here
    //    is wrong by the offset, silently.
    {
        let mut ok = true;
        let z = time::FixedZone("CEST", 2 * 3600);
        let d = time::Date(2024, 1, 2, 3, 4, 5, 0, z);
        if d.Format(time::RFC3339) != s("2024-01-02T03:04:05+02:00") {
            ok = false;
        }
        if d.Unix() != 1_704_157_445 {
            ok = false;
        }
        if d.UTC().Format(time::RFC3339) != s("2024-01-02T01:04:05Z") {
            ok = false;
        }
        // ParseInLocation reads a zoneless layout the same way, where
        // Parse would have read it as UTC.
        let (pl, err) = time::ParseInLocation("2006-01-02 15:04:05", "2024-01-02 03:04:05", z);
        if !err.IsNil() || pl.Unix() != 1_704_157_445 {
            ok = false;
        }
        if pl.Format(time::RFC3339) != s("2024-01-02T03:04:05+02:00") {
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 5",
            "Date and ParseInLocation use the zone",
        );
    }

    // 6. A zero-offset zone is NOT UTC: it keeps its own name, so
    //    RFC3339 prints "Z" while RFC1123 prints "GMT". Go:
    //    gmt "2024-01-02T03:04:05Z" rfc1123="Tue, 02 Jan 2024 03:04:05 GMT".
    {
        let mut ok = true;
        let gmt = time::FixedZone("GMT", 0);
        let g = time::Unix(BASE, 0).In(gmt);
        if g.Format(time::RFC3339) != s("2024-01-02T03:04:05Z") {
            ok = false;
        }
        if g.Format(time::RFC1123) != s("Tue, 02 Jan 2024 03:04:05 GMT") {
            ok = false;
        }
        // Go: names utc="UTC" fixed="CEST"
        if time::UTC.String() != s("UTC") {
            ok = false;
        }
        if time::FixedZone("CEST", 7200).String() != s("CEST") {
            ok = false;
        }
        report(&mut failed, ok, " 6", "a zero-offset zone keeps its name");
    }

    // 7. The six zone layouts, each against UTC and against CEST. `MST`
    //    prints the NAME; the `-07` family always prints a sign; the
    //    `Z07` family prints a bare "Z" at zero and the offset
    //    otherwise. Confusing the two families is how a port emits
    //    "+0000" where a certificate wants "Z".
    {
        let mut ok = true;
        // (layout, want_utc, want_cest)
        let cases: [(&str, &str, &str); 6] = [
            ("MST", "UTC", "CEST"),
            ("-0700", "+0000", "+0200"),
            ("-07:00", "+00:00", "+02:00"),
            ("Z0700", "Z", "+0200"),
            ("Z07:00", "Z", "+02:00"),
            ("-07", "+00", "+02"),
        ];
        let base = time::Unix(BASE, 0);
        let inz = base.In(time::FixedZone("CEST", 2 * 3600));
        let mut i = 0;
        while i < cases.len() {
            let (layout, want_utc, want_cest) = cases[i];
            if base.UTC().Format(layout) != s(want_utc) {
                ok = false;
            }
            if inz.Format(layout) != s(want_cest) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 7", "the six zone layouts");
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
