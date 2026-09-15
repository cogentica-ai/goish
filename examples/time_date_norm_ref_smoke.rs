// time.Date's argument normalisation, pinned against Go 1.25.5.
//
// Go's Date normalises EVERY argument: "The month, day, hour, min, sec,
// and nsec values may be outside their usual ranges and will be
// normalized during the conversion. For example, October 32 converts to
// November 1."
//
// goish's did not normalise the MONTH. It handed the raw value to
// `days_from_civil`, which is Howard Hinnant's civil-from-days
// algorithm and is defined only for 1..12. That algorithm's year starts
// in MARCH, so months 13 and 14 — January and February of the next year
// — came out right by accident and 15 did not:
//
//     Date(1980, 15, 1)   goish 1981-03-03   Go 1981-03-01
//     Date(1980, 27, 1)   goish 1982-03-05   Go 1982-03-01
//
// The error was two days per year rolled past February, and it was
// silent. It surfaced porting archive/zip, whose `msDosTimeToTime`
// decodes a 4-bit month field and hands it straight to Date — so a ZIP
// entry with a zero or out-of-range date field, which is what a zero
// header or a hostile archive produces, decoded to the wrong day.
//
// The rows below are the ones that distinguish the two: 13 and 14
// (which always passed), 15 and 25 and 27 (one and two years rolled,
// before and after February), 0 (rolling BACKWARDS, which is what a
// zeroed MS-DOS date does), a day of 0, and leap and non-leap targets.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::fmt;
use goish::gostring::string;
use goish::time;
use goish::types::int;

static mut PASS: int = 0;
static mut FAIL: int = 0;

// go: none
fn drow(idx: int, y: int, m: int, d: int, want: &'static str) {
    let got = time::Date(y, m, d, 0, 0, 0, 0, time::UTC).Format("2006-01-02");
    unsafe {
        if got == string::from_bytes(want.as_bytes()) {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %v Date(%v,%v,%v)\n     got  %s\n     want %s\n",
                idx,
                y,
                m,
                d,
                got.clone(),
                want
            );
        }
    }
}

#[goish::main]
fn main() {
    drow(0, 1980, 15, 1, "1981-03-01");
    drow(1, 2043, 15, 31, "2044-03-31");
    drow(2, 2107, 15, 31, "2108-03-31");
    drow(3, 1980, 1, 1, "1980-01-01");
    drow(4, 1980, 0, 0, "1979-11-30");
    drow(5, 1980, 13, 1, "1981-01-01");
    drow(6, 1980, 14, 1, "1981-02-01");
    drow(7, 1980, 15, 0, "1981-02-28");
    drow(8, 1981, 3, 1, "1981-03-01");
    drow(9, 1980, 12, 1, "1980-12-01");
    drow(10, 1981, 1, 1, "1981-01-01");
    drow(11, 2043, 12, 31, "2043-12-31");
    drow(12, 2044, 3, 31, "2044-03-31");
    drow(13, 1980, 25, 1, "1982-01-01");
    drow(14, 1980, 27, 1, "1982-03-01");
    drow(15, 1979, 15, 1, "1980-03-01");
    drow(16, 2000, 15, 1, "2001-03-01");
    drow(17, 2001, 15, 1, "2002-03-01");

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 18 {
            fmt::Printf!("FAIL ran %v rows, expected 18\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("time_date_norm_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
