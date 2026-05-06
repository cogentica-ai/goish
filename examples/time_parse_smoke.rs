// time_parse_smoke — exercise time::Parse round-tripping with Format.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::time;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. RFC3339 round-trip.
    {
        let want = time::Date(2024, 1, 2, 3, 4, 5, 0);
        let s = want.Format(string(time::RFC3339));
        let (got, err) = time::Parse(string(time::RFC3339), s);
        if err.IsNil()
            && got.Year() == 2024
            && got.Month() == 1
            && got.Day() == 2
            && got.Hour() == 3
        {
            Println!("[ 1] RFC3339 round-trip        PASS");
        } else {
            Println!("[ 1] RFC3339 round-trip        FAIL");
            failed += 1;
        }
    }

    // 2. DateTime round-trip.
    {
        let want = time::Date(2025, 12, 31, 23, 59, 58, 0);
        let s = want.Format(string(time::DateTime));
        let (got, err) = time::Parse(string(time::DateTime), s);
        if err.IsNil() && got.Year() == 2025 && got.Day() == 31 {
            Println!("[ 2] DateTime round-trip       PASS");
        } else {
            Println!("[ 2] DateTime round-trip       FAIL");
            failed += 1;
        }
    }

    // 3. DateOnly.
    {
        let (got, err) = time::Parse(string(time::DateOnly), string("2024-07-04"));
        if err.IsNil() && got.Year() == 2024 && got.Month() == 7 && got.Day() == 4 {
            Println!("[ 3] DateOnly                  PASS");
        } else {
            Println!("[ 3] DateOnly                  FAIL");
            failed += 1;
        }
    }

    // 4. RFC1123 ("Tue, 02 Jan 2024 03:04:05 GMT").
    {
        let (got, err) = time::Parse(
            string(time::RFC1123),
            string("Tue, 02 Jan 2024 03:04:05 GMT"),
        );
        if err.IsNil()
            && got.Year() == 2024
            && got.Month() == 1
            && got.Day() == 2
            && got.Hour() == 3
            && got.Minute() == 4
            && got.Second() == 5
        {
            Println!("[ 4] RFC1123                   PASS");
        } else {
            Println!("[ 4] RFC1123                   FAIL");
            failed += 1;
        }
    }

    // 5. ANSIC.
    {
        let (got, err) = time::Parse(
            string(time::ANSIC),
            string("Mon Jul  4 12:00:00 2024"),
        );
        if err.IsNil() && got.Year() == 2024 && got.Month() == 7 && got.Day() == 4 {
            Println!("[ 5] ANSIC                     PASS");
        } else {
            Println!("[ 5] ANSIC                     FAIL");
            failed += 1;
        }
    }

    // 6. Malformed → error.
    {
        let (_t, err) = time::Parse(string(time::RFC3339), string("nope"));
        if !err.IsNil() {
            Println!("[ 6] malformed → err           PASS");
        } else {
            Println!("[ 6] malformed → err           FAIL");
            failed += 1;
        }
    }

    // 7. Unsupported layout → error.
    {
        let (_t, err) = time::Parse(string("01/02 03:04:05PM '06 -0700"), string("anything"));
        if !err.IsNil() {
            Println!("[ 7] unsupported layout → err  PASS");
        } else {
            Println!("[ 7] unsupported layout → err  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 7", failed);
        syscall::Exit(1);
    }
}
