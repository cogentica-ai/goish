// time_zero_smoke — Go's zero Time against a running Go.
// (time/time.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_time_zero_ref.go` run in
// `package time_test` by `scripts/goref.sh`.
//
// Go's zero `Time` is January 1 of YEAR 1, not the Unix epoch, because
// `Time.sec` counts from the absolute zero year. goish's counted Unix
// seconds, so:
//
//   * `Time{}` read as 1970-01-01. This tree had already recorded that
//     twice — in io/fs's FormatFileInfo and in archive/tar's FileInfo
//     rendering, both of which state the divergence in their smoke.
//     Both notes are now stale in the good direction.
//   * `IsZero()` was true for `Unix(0, 0)` and false for the actual
//     zero. IsZero is what every "was this ever set?" check asks, and
//     it was answering about the wrong instant.
//   * The binary encoding writes `t.sec()`, the internal count. goish
//     wrote Unix seconds, so a MarshalBinary here and an
//     UnmarshalBinary in Go disagreed by 62135596800 seconds — over
//     nineteen centuries — with no error on either side.
//
// The vectors below pin all three, plus the round-trip that has to stay
// exact for every timestamp anyone actually sets.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::time::{self, Duration};
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

/// Seconds from year 1 to the Unix epoch — Go's `unixToInternal`.
const UNIX_TO_INTERNAL: int = 62_135_596_800;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The zero Time. Go: iszero=true unix=-62135596800 year=1
    //    date=0001-01-01 00:00:00.
    {
        let mut ok = true;
        let zero = time::Time::default();
        if !zero.IsZero() {
            ok = false;
        }
        if zero.Unix() != -UNIX_TO_INTERNAL {
            ok = false;
        }
        if zero.Year() != 1 {
            ok = false;
        }
        if zero.Format(s("2006-01-02 15:04:05")) != s("0001-01-01 00:00:00") {
            ok = false;
        }
        report(&mut failed, ok, " 1", "Time{} is year 1, not 1970");
    }

    // 2. The Unix epoch is NOT the zero Time. Go: epoch iszero=false
    //    unix=0 year=1970. This is the assertion that was inverted.
    {
        let mut ok = true;
        let epoch = time::Unix(0, 0);
        if epoch.IsZero() {
            ok = false;
        }
        if epoch.Unix() != 0 || epoch.Year() != 1970 {
            ok = false;
        }
        if epoch.Format(s("2006-01-02 15:04:05")) != s("1970-01-01 00:00:00") {
            ok = false;
        }
        // Go: zero-before-epoch=true epoch-after-zero=true equal=false
        let zero = time::Time::default();
        if !zero.Before(epoch) || !epoch.After(zero) || zero.Equal(epoch) {
            ok = false;
        }
        report(&mut failed, ok, " 2", "the epoch is not the zero Time");
    }

    // 3. Round-tripping a Unix second stays exact in both directions,
    //    including the one that lands exactly on the zero Time.
    {
        let mut ok = true;
        // (sec, want_year, want_iszero)
        let cases: [(int, int, bool); 6] = [
            (0, 1970, false),
            (1, 1970, false),
            (-1, 1969, false),
            (1_700_000_000, 2023, false),
            (-62_135_596_800, 1, true),
            (253_402_300_799, 9999, false),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (sec, want_year, want_zero) = cases[i];
            let u = time::Unix(sec, 0);
            if u.Unix() != sec || u.Year() != want_year || u.IsZero() != want_zero {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 3", "Unix round-trips exactly");
    }

    // 4. The binary encoding stores the INTERNAL count. Go's bytes for
    //    the epoch are [1, 0,0,0,14,119,145,247,0, 0,0,0,0, 255,255] —
    //    those eight middle bytes are 62135596800, not 0.
    {
        let mut ok = true;
        let epoch = time::Unix(0, 0);
        let (b, err) = epoch.MarshalBinary();
        if !err.IsNil() || b.Len() != 15 {
            ok = false;
        } else {
            let want: [u8; 15] = [1, 0, 0, 0, 14, 119, 145, 247, 0, 0, 0, 0, 0, 255, 255];
            let mut j = 0usize;
            while j < want.len() {
                if b[j] != want[j] {
                    ok = false;
                }
                j += 1;
            }
        }
        // Go: marshal zero bytes=[1 0 0 0 0 0 0 0 0 0 0 0 0 255 255] —
        // the zero Time is eight zero bytes, which is what makes the
        // encoding self-consistent.
        let zero = time::Time::default();
        let (bz, errz) = zero.MarshalBinary();
        if !errz.IsNil() || bz.Len() != 15 {
            ok = false;
        } else {
            let mut j = 1usize;
            while j < 9 {
                if bz[j] != 0 {
                    ok = false;
                }
                j += 1;
            }
        }
        report(&mut failed, ok, " 4", "MarshalBinary stores internal secs");
    }

    // 5. Round-tripping through the binary form preserves the instant,
    //    the nanoseconds and IsZero.
    {
        let mut ok = true;
        let cases: [(time::Time, int, bool); 3] = [
            (time::Time::default(), -UNIX_TO_INTERNAL, true),
            (time::Unix(0, 0), 0, false),
            (time::Unix(99_999, 12_345), 99_999, false),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (t, want_unix, want_zero) = cases[i];
            let (b, _) = t.MarshalBinary();
            let mut back = time::Unix(0, 0);
            let err = back.UnmarshalBinary(b);
            if !err.IsNil() || back.Unix() != want_unix || back.IsZero() != want_zero {
                ok = false;
            }
            i += 1;
        }
        // Go: unmarshal n99999 nano=99999000012345
        let (b, _) = time::Unix(99_999, 12_345).MarshalBinary();
        let mut back = time::Unix(0, 0);
        let _ = back.UnmarshalBinary(b);
        if back.UnixNano() != 99_999_000_012_345 {
            ok = false;
        }
        report(&mut failed, ok, " 5", "binary round-trip preserves it");
    }

    // 6. Date, Clock, Weekday and YearDay at both epochs. January 1 of
    //    year 1 was a MONDAY — an easy thing to get wrong when the
    //    weekday is derived from a Unix day count.
    {
        let mut ok = true;
        let zero = time::Time::default();
        let (y, m, d) = zero.Date();
        let (hh, mm, ss) = zero.Clock();
        if y != 1 || m != 1 || d != 1 || hh != 0 || mm != 0 || ss != 0 {
            ok = false;
        }
        // Go: parts zero weekday=Monday yearday=1
        if zero.Weekday().String() != s("Monday") || zero.YearDay() != 1 {
            ok = false;
        }
        let epoch = time::Unix(0, 0);
        let (y2, m2, d2) = epoch.Date();
        if y2 != 1970 || m2 != 1 || d2 != 1 {
            ok = false;
        }
        // Go: parts epoch weekday=Thursday yearday=1
        if epoch.Weekday().String() != s("Thursday") || epoch.YearDay() != 1 {
            ok = false;
        }
        report(&mut failed, ok, " 6", "year 1 January 1 was a Monday");
    }

    // 7. Sub SATURATES across the two epochs: a Duration is an int64 of
    //    nanoseconds, and nineteen centuries does not fit. Go returns
    //    the maximum rather than wrapping, and a port that wraps would
    //    report a negative gap between two ordered instants.
    {
        let mut ok = true;
        let zero = time::Time::default();
        let epoch = time::Unix(0, 0);
        // Go: sub epoch-zero=2562047h47m16.854775807s saturated=true
        if epoch.Sub(zero) != Duration(i64::MAX) {
            ok = false;
        }
        // The reverse saturates the other way.
        if zero.Sub(epoch) != Duration(i64::MIN) {
            ok = false;
        }
        // And an ordinary gap is exact.
        if time::Unix(2000, 0).Sub(time::Unix(1000, 0)) != Duration(1_000_000_000_000) {
            ok = false;
        }
        report(&mut failed, ok, " 7", "Sub saturates, never wraps");
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
