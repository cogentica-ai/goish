// http_time_smoke — exercise http.ParseTime + http.TimeFormat round-trip.
//
// Cases 5 and 6 are pinned to Go 1.25.5 via scripts/goref.sh net/http.
// Go's ParseTime accepts three formats: IMF-fixdate, RFC 850 and ANSI
// C asctime. goish now accepts asctime too (case 5) — it previously
// did not, so an If-Modified-Since in asctime form was silently
// unparseable. RFC 850 proper is still NOT accepted (case 6): Go reads
// a full weekday name and a two-digit year, goish's scanner reads a
// three-letter day and a four-digit year. Case 6 pins the gap so it
// cannot be closed silently or regress further.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http;
use goish::time;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. IMF-fixdate parse.
    {
        let (t, err) = http::ParseTime(string("Mon, 02 Jan 2006 15:04:05 GMT"));
        if !err.IsNil() {
            fmt::Println!("[ 1] IMF-fixdate parse         FAIL err");
            failed += 1;
        } else if t.Year() == 2006 && t.Month() == 1 && t.Day() == 2 {
            let (h, m, s) = t.Clock();
            if h == 15 && m == 4 && s == 5 {
                fmt::Println!("[ 1] IMF-fixdate parse         PASS");
            } else {
                fmt::Println!("[ 1] IMF-fixdate parse         FAIL clock {}:{}:{}", h, m, s);
                failed += 1;
            }
        } else {
            fmt::Println!("[ 1] IMF-fixdate parse         FAIL date");
            failed += 1;
        }
    }

    // 2. Legacy dash form.
    {
        let (t, err) = http::ParseTime(string("Mon, 02-Jan-2006 15:04:05 MST"));
        if err.IsNil() && t.Year() == 2006 && t.Month() == 1 && t.Day() == 2 {
            fmt::Println!("[ 2] legacy dash parse         PASS");
        } else {
            fmt::Println!("[ 2] legacy dash parse         FAIL");
            failed += 1;
        }
    }

    // 3. Bogus input → error.
    {
        let (_t, err) = http::ParseTime(string("not a date"));
        if !err.IsNil() {
            fmt::Println!("[ 3] bogus → error             PASS");
        } else {
            fmt::Println!("[ 3] bogus → error             FAIL");
            failed += 1;
        }
    }

    // 5. ANSI C asctime — Go accepts it; goish now does too.
    {
        let (t, err) = http::ParseTime(string("Sun Nov  6 08:49:37 1994"));
        if err.IsNil() && t.Unix() == 784111777 {
            fmt::Println!("[ 5] asctime parse             PASS");
        } else {
            fmt::Println!("[ 5] asctime parse             FAIL unix=", t.Unix());
            failed += 1;
        }
    }

    // 6. RFC 850 proper — Go accepts, goish does NOT. Pinning the
    //    known gap: if this ever starts parsing, the assertion below
    //    must be flipped rather than the behaviour going unnoticed.
    {
        let (_t, err) = http::ParseTime(string("Sunday, 06-Nov-94 08:49:37 GMT"));
        if !err.IsNil() {
            fmt::Println!("[ 6] RFC 850 still unsupported PASS (known gap vs Go)");
        } else {
            fmt::Println!("[ 6] RFC 850 now parses — update this test  FAIL");
            failed += 1;
        }
    }

    // 4. TimeFormat constant matches the reference layout.
    if http::TimeFormat == "Mon, 02 Jan 2006 15:04:05 GMT" {
        fmt::Println!("[ 4] TimeFormat constant       PASS");
    } else {
        fmt::Println!("[ 4] TimeFormat constant       FAIL");
        failed += 1;
    }

    let _ = time::Now();

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 6");
        syscall::Exit(1);
    }
}
