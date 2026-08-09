// http_time_smoke — exercise http.ParseTime + http.TimeFormat round-trip.

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

    // 4. TimeFormat constant matches the reference layout.
    if http::TimeFormat == "Mon, 02 Jan 2006 15:04:05 GMT" {
        fmt::Println!("[ 4] TimeFormat constant       PASS");
    } else {
        fmt::Println!("[ 4] TimeFormat constant       FAIL");
        failed += 1;
    }

    let _ = time::Now();

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 4", failed);
        syscall::Exit(1);
    }
}
