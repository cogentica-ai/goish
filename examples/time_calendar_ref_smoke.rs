//! Pinned against Go 1.25.5: time's CALENDAR arithmetic.
//!
//! `AddDate`, `ISOWeek`, `YearDay`, `Time.Round`, `Before` and
//! `Since`/`Until` are ported and appear in ZERO of the six existing
//! time reference smokes, which cover formatting, parsing, layouts,
//! zones and timers. Calendar arithmetic is where a date library is
//! actually wrong, and it had never been diffed.
//!
//! It measures clean: 37/37 identical to Go. What is pinned:
//!
//!   * **AddDate NORMALISES, it does not clamp.** Jan 31 plus one
//!     month is MARCH 3, not February 28 — Go builds
//!     Date(y, m+1, 31) and lets the normalisation carry. In a leap
//!     year the same call gives March 2. Clamping is the intuitive
//!     implementation and it is wrong; this is the single most
//!     valuable line in the file.
//!   * March 31 minus one month is also March 3, for the same reason.
//!   * ISOWeek disagrees with the calendar year at the boundaries:
//!     2021-01-01 is ISO week 2020-53, and 2016-01-01 is 2015-53.
//!     A port that returned the Gregorian year would be right for
//!     ~360 days a year.
//!   * Duration.Round is half-AWAY-from-zero: 1.5s rounds to 2s and
//!     -1.5s to -2s, where banker's rounding would give 2s and -2s
//!     but 2.5s would give 2s instead of Go's 3s.
//!   * Truncate and Round with a ZERO or NEGATIVE unit return the
//!     value unchanged rather than dividing by zero.
//!   * YearDay counts 366 in a leap year, and Compare returns
//!     -1/0/+1.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh time <timecal_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::time::{self, Duration, Time};
use goish::{fmt, int, string};

/// Go's output, verbatim.
const GO: [&str; 37] = [
    "AddDate                    [2021-01-31 0 1 0 -> 2021-03-03]",
    "AddDate                    [2020-01-31 0 1 0 -> 2020-03-02]",
    "AddDate                    [2021-03-31 0 -1 0 -> 2021-03-03]",
    "AddDate                    [2020-02-29 1 0 0 -> 2021-03-01]",
    "AddDate                    [2021-12-31 0 0 1 -> 2022-01-01]",
    "AddDate                    [2021-01-01 0 0 -1 -> 2020-12-31]",
    "AddDate                    [2021-05-15 -1 -2 -20 -> 2020-02-24]",
    "cal                        [2021-01-01 yd= 1 iso= 2020 53 Friday]",
    "cal                        [2020-12-31 yd= 366 iso= 2020 53 Thursday]",
    "cal                        [2021-12-31 yd= 365 iso= 2021 52 Friday]",
    "cal                        [2020-02-29 yd= 60 iso= 2020 9 Saturday]",
    "cal                        [2016-01-01 yd= 1 iso= 2015 53 Friday]",
    "cal                        [2015-12-31 yd= 365 iso= 2015 53 Thursday]",
    "cal                        [2026-01-01 yd= 1 iso= 2026 1 Thursday]",
    "Time.Truncate              [1s 13:47:33.000]",
    "Time.Round                 [1s 13:47:34.000]",
    "Time.Truncate              [1m0s 13:47:00.000]",
    "Time.Round                 [1m0s 13:48:00.000]",
    "Time.Truncate              [1h0m0s 13:00:00.000]",
    "Time.Round                 [1h0m0s 14:00:00.000]",
    "Time.Truncate              [15m0s 13:45:00.000]",
    "Time.Round                 [15m0s 13:45:00.000]",
    "Time.Truncate              [0s 13:47:33.500]",
    "Time.Round                 [0s 13:47:33.500]",
    "Time.Truncate              [-1s 13:47:33.500]",
    "Time.Round                 [-1s 13:47:33.500]",
    "Duration.Round             [1.5s 1s 2s]",
    "Duration.Truncate          [1.5s 1s 1s]",
    "Duration.Round             [2.5s 1s 3s]",
    "Duration.Truncate          [2.5s 1s 2s]",
    "Duration.Round             [-1.5s 1s -2s]",
    "Duration.Truncate          [-1.5s 1s -1s]",
    "Duration.Round             [1.499s 1s 1s]",
    "Duration.Truncate          [1.499s 1s 1s]",
    "Duration.Round             [1s 0s 1s]",
    "Duration.Truncate          [1s 0s 1s]",
    "order                      [true false -1 1 0 true]",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;
fn d(y: i64, m: i64, day: i64, h: i64, mi: i64, s: i64) -> Time {
    time::Date(
        y as int,
        m as int,
        day as int,
        h as int,
        mi as int,
        s as int,
        0,
        time::UTC,
    )
}
#[goish::main]
fn main() {
    let cases: [(i64, i64, i64, i64, i64, i64); 7] = [
        (2021, 1, 31, 0, 1, 0),
        (2020, 1, 31, 0, 1, 0),
        (2021, 3, 31, 0, -1, 0),
        (2020, 2, 29, 1, 0, 0),
        (2021, 12, 31, 0, 0, 1),
        (2021, 1, 1, 0, 0, -1),
        (2021, 5, 15, -1, -2, -20),
    ];
    for (y, m, day, ay, am, ad) in cases.iter() {
        let t = d(*y, *m, *day, 0, 0, 0);
        let r = t.AddDate(*ay as int, *am as int, *ad as int);
        chk(fmt::Sprintf!(
            "%-26s [%s %d %d %d -> %s]",
            string("AddDate"),
            t.Format(string("2006-01-02")),
            *ay,
            *am,
            *ad,
            r.Format(string("2006-01-02"))
        ));
    }
    let cal: [(i64, i64, i64); 7] = [
        (2021, 1, 1),
        (2020, 12, 31),
        (2021, 12, 31),
        (2020, 2, 29),
        (2016, 1, 1),
        (2015, 12, 31),
        (2026, 1, 1),
    ];
    for (y, m, day) in cal.iter() {
        let t = d(*y, *m, *day, 0, 0, 0);
        let (iy, iw) = t.ISOWeek();
        chk(fmt::Sprintf!(
            "%-26s [%s yd= %d iso= %d %d %s]",
            string("cal"),
            t.Format(string("2006-01-02")),
            t.YearDay() as i64,
            iy as i64,
            iw as i64,
            t.Weekday().String()
        ));
    }
    let base = time::Date(
        2021 as int,
        3 as int,
        15 as int,
        13 as int,
        47 as int,
        33 as int,
        500000000 as int,
        time::UTC,
    );
    let units: [i64; 6] = [
        1_000_000_000,
        60_000_000_000,
        3_600_000_000_000,
        900_000_000_000,
        0,
        -1_000_000_000,
    ];
    for u in units.iter() {
        let du = Duration(*u);
        chk(fmt::Sprintf!(
            "%-26s [%s %s]",
            string("Time.Truncate"),
            du.String(),
            base.Truncate(du).Format(string("15:04:05.000"))
        ));
        chk(fmt::Sprintf!(
            "%-26s [%s %s]",
            string("Time.Round"),
            du.String(),
            base.Round(du).Format(string("15:04:05.000"))
        ));
    }
    let dcases: [(i64, i64); 5] = [
        (1_500_000_000, 1_000_000_000),
        (2_500_000_000, 1_000_000_000),
        (-1_500_000_000, 1_000_000_000),
        (1_499_000_000, 1_000_000_000),
        (1_000_000_000, 0),
    ];
    for (dv, mv) in dcases.iter() {
        let dd = Duration(*dv);
        let mm = Duration(*mv);
        chk(fmt::Sprintf!(
            "%-26s [%s %s %s]",
            string("Duration.Round"),
            dd.String(),
            mm.String(),
            dd.Round(mm).String()
        ));
        chk(fmt::Sprintf!(
            "%-26s [%s %s %s]",
            string("Duration.Truncate"),
            dd.String(),
            mm.String(),
            dd.Truncate(mm).String()
        ));
    }
    let a = d(2021, 1, 1, 0, 0, 0);
    let b = d(2021, 1, 2, 0, 0, 0);
    chk(fmt::Sprintf!(
        "%-26s [%v %v %d %d %d %v]",
        string("order"),
        a.Before(b),
        a.After(b),
        a.Compare(b) as i64,
        b.Compare(a) as i64,
        a.Compare(a) as i64,
        a.Equal(a)
    ));
    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("time calendar: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}

/// Compare one rendered line against the Go reference, in order.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    let want = string::from_static(GO[i]);
    if got == want {
        return;
    }
    fmt::Printf!("DIFF go   : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    unsafe { FAILED += 1 };
}
