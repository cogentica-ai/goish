// time_format_smoke — exercise Time.Format with the canonical layout
// constants (slim port of format.go:639).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::time;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 2024-01-02 03:04:05 UTC.
    let t = time::Date(2024, 1, 2, 3, 4, 5, 0, goish::time::UTC);

    // 0. Sanity check: Year/Month/Day round-trip.
    {
        let y = t.Year();
        let m = t.Month();
        let d = t.Day();
        if y == 2024 && m == 1 && d == 2 {
            fmt::Println!("[ 0] Date round-trip           PASS");
        } else {
            fmt::Printf!(
                "[ 0] Date round-trip           FAIL y=%d m=%d d=%d\n",
                y,
                m,
                d
            );
            failed += 1;
        }
    }

    // 1. RFC3339
    {
        let s = t.Format(string(time::RFC3339));
        if s == "2024-01-02T03:04:05Z" {
            fmt::Println!("[ 1] RFC3339                   PASS");
        } else {
            fmt::Printf!("[ 1] RFC3339                   FAIL got=%q\n", s);
            failed += 1;
        }
    }

    // 2. DateTime
    {
        let s = t.Format(string(time::DateTime));
        if s == "2024-01-02 03:04:05" {
            fmt::Println!("[ 2] DateTime                  PASS");
        } else {
            fmt::Printf!("[ 2] DateTime                  FAIL got=%q\n", s);
            failed += 1;
        }
    }

    // 3. DateOnly
    {
        let s = t.Format(string(time::DateOnly));
        if s == "2024-01-02" {
            fmt::Println!("[ 3] DateOnly                  PASS");
        } else {
            fmt::Printf!("[ 3] DateOnly                  FAIL got=%q\n", s);
            failed += 1;
        }
    }

    // 4. TimeOnly
    {
        let s = t.Format(string(time::TimeOnly));
        if s == "03:04:05" {
            fmt::Println!("[ 4] TimeOnly                  PASS");
        } else {
            fmt::Printf!("[ 4] TimeOnly                  FAIL got=%q\n", s);
            failed += 1;
        }
    }

    // 5. RFC1123 — Tuesday in Jan 2024.
    {
        let s = t.Format(string(time::RFC1123));
        // Go: RFC1123's `MST` element prints the zone ABBREVIATION, and
        // for time.UTC that is "UTC". This line expected "GMT" — which
        // is what a FixedZone NAMED "GMT" would give, not UTC — and was
        // wrong from the day it was written. Nobody found out because
        // this example is not declared in Cargo.toml, so the e2e suite
        // never ran it.
        if s == "Tue, 02 Jan 2024 03:04:05 UTC" {
            fmt::Println!("[ 5] RFC1123                   PASS");
        } else {
            fmt::Printf!("[ 5] RFC1123                   FAIL got=%q\n", s);
            failed += 1;
        }
    }

    // 6. Kitchen 03:04 → "3:04AM"
    {
        let s = t.Format(string(time::Kitchen));
        if s == "3:04AM" {
            fmt::Println!("[ 6] Kitchen AM                PASS");
        } else {
            fmt::Printf!("[ 6] Kitchen AM                FAIL got=%q\n", s);
            failed += 1;
        }
    }

    // 7. Kitchen with PM time
    {
        let pm = time::Date(2024, 1, 2, 13, 0, 0, 0, goish::time::UTC);
        let s = pm.Format(string(time::Kitchen));
        if s == "1:00PM" {
            fmt::Println!("[ 7] Kitchen PM                PASS");
        } else {
            fmt::Printf!("[ 7] Kitchen PM                FAIL got=%q\n", s);
            failed += 1;
        }
    }

    // 8. ANSIC
    {
        let s = t.Format(string(time::ANSIC));
        if s == "Tue Jan  2 03:04:05 2024" {
            fmt::Println!("[ 8] ANSIC                     PASS");
        } else {
            fmt::Printf!("[ 8] ANSIC                     FAIL got=%q\n", s);
            failed += 1;
        }
    }

    // 9. RFC850
    {
        let s = t.Format(string(time::RFC850));
        // Go: same as RFC1123 above — the zone abbreviation is "UTC".
        if s == "Tuesday, 02-Jan-24 03:04:05 UTC" {
            fmt::Println!("[ 9] RFC850                    PASS");
        } else {
            fmt::Printf!("[ 9] RFC850                    FAIL got=%q\n", s);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Printf!("FAIL %d of 10\n", failed);
        syscall::Exit(1);
    }
}
