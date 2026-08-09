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
            fmt::Println!("[ 0] Date round-trip           FAIL y={} m={} d={}", y, m, d);
            failed += 1;
        }
    }

    // 1. RFC3339
    {
        let s = t.Format(string(time::RFC3339));
        if s == "2024-01-02T03:04:05Z" {
            fmt::Println!("[ 1] RFC3339                   PASS");
        } else {
            fmt::Println!("[ 1] RFC3339                   FAIL got={}", s);
            failed += 1;
        }
    }

    // 2. DateTime
    {
        let s = t.Format(string(time::DateTime));
        if s == "2024-01-02 03:04:05" {
            fmt::Println!("[ 2] DateTime                  PASS");
        } else {
            fmt::Println!("[ 2] DateTime                  FAIL got={}", s);
            failed += 1;
        }
    }

    // 3. DateOnly
    {
        let s = t.Format(string(time::DateOnly));
        if s == "2024-01-02" {
            fmt::Println!("[ 3] DateOnly                  PASS");
        } else {
            fmt::Println!("[ 3] DateOnly                  FAIL got={}", s);
            failed += 1;
        }
    }

    // 4. TimeOnly
    {
        let s = t.Format(string(time::TimeOnly));
        if s == "03:04:05" {
            fmt::Println!("[ 4] TimeOnly                  PASS");
        } else {
            fmt::Println!("[ 4] TimeOnly                  FAIL got={}", s);
            failed += 1;
        }
    }

    // 5. RFC1123 — Tuesday in Jan 2024.
    {
        let s = t.Format(string(time::RFC1123));
        if s == "Tue, 02 Jan 2024 03:04:05 GMT" {
            fmt::Println!("[ 5] RFC1123                   PASS");
        } else {
            fmt::Println!("[ 5] RFC1123                   FAIL got={}", s);
            failed += 1;
        }
    }

    // 6. Kitchen 03:04 → "3:04AM"
    {
        let s = t.Format(string(time::Kitchen));
        if s == "3:04AM" {
            fmt::Println!("[ 6] Kitchen AM                PASS");
        } else {
            fmt::Println!("[ 6] Kitchen AM                FAIL got={}", s);
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
            fmt::Println!("[ 7] Kitchen PM                FAIL got={}", s);
            failed += 1;
        }
    }

    // 8. ANSIC
    {
        let s = t.Format(string(time::ANSIC));
        if s == "Tue Jan  2 03:04:05 2024" {
            fmt::Println!("[ 8] ANSIC                     PASS");
        } else {
            fmt::Println!("[ 8] ANSIC                     FAIL got={}", s);
            failed += 1;
        }
    }

    // 9. RFC850
    {
        let s = t.Format(string(time::RFC850));
        if s == "Tuesday, 02-Jan-24 03:04:05 GMT" {
            fmt::Println!("[ 9] RFC850                    PASS");
        } else {
            fmt::Println!("[ 9] RFC850                    FAIL got={}", s);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 10", failed);
        syscall::Exit(1);
    }
}
