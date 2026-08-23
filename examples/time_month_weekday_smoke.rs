// time_month_weekday_smoke — exercise time::Month + time::Weekday.
//
// Coverage:
//   1. January..December constants have correct Int() values.
//   2. Sunday..Saturday constants have correct Int() values.
//   3. Month::String() returns English name.
//   4. Weekday::String() returns English name.
//   5. Month::String() out-of-range renders "%!Month(N)".
//   6. Weekday::String() out-of-range renders "%!Weekday(N)".
//   7. Time::Month() returns typed Month equal to a constant.
//   8. Time::Weekday() returns typed Weekday equal to a constant.
//   9. Cross-type equality: Month == int and Weekday == int.
//  10. fmt::Sprintf "%s" prints the name; "%d" prints the number.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::gostring::string;
use goish::runtime::sched::schedule;
use goish::time::{self, Month, Weekday};
use goish::{go, syscall};

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn ok_line(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

#[goish::main]
fn main() {
    go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            fmt::Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    schedule();
}

fn run_tests() {
    test_1_month_constants();
    test_2_weekday_constants();
    test_3_month_string();
    test_4_weekday_string();
    test_5_month_string_out_of_range();
    test_6_weekday_string_out_of_range();
    test_7_time_month_typed();
    test_8_time_weekday_typed();
    test_9_cross_type_equality();
    test_10_format_dispatch();
}

fn s(x: &'static str) -> string {
    string::from_static(x)
}

fn test_1_month_constants() {
    let ok = time::January.Int() == 1
        && time::February.Int() == 2
        && time::March.Int() == 3
        && time::April.Int() == 4
        && time::May.Int() == 5
        && time::June.Int() == 6
        && time::July.Int() == 7
        && time::August.Int() == 8
        && time::September.Int() == 9
        && time::October.Int() == 10
        && time::November.Int() == 11
        && time::December.Int() == 12;
    if ok {
        ok_line(b"[ 1] Month constants 1..12       PASS\n");
    } else {
        ok_line(b"[ 1] Month constants 1..12       FAIL\n");
        fail();
    }
}

fn test_2_weekday_constants() {
    let ok = time::Sunday.Int() == 0
        && time::Monday.Int() == 1
        && time::Tuesday.Int() == 2
        && time::Wednesday.Int() == 3
        && time::Thursday.Int() == 4
        && time::Friday.Int() == 5
        && time::Saturday.Int() == 6;
    if ok {
        ok_line(b"[ 2] Weekday constants 0..6      PASS\n");
    } else {
        ok_line(b"[ 2] Weekday constants 0..6      FAIL\n");
        fail();
    }
}

fn test_3_month_string() {
    let ok = time::January.String() == s("January")
        && time::April.String() == s("April")
        && time::December.String() == s("December");
    if ok {
        ok_line(b"[ 3] Month::String English names PASS\n");
    } else {
        ok_line(b"[ 3] Month::String English names FAIL\n");
        fail();
    }
}

fn test_4_weekday_string() {
    let ok = time::Sunday.String() == s("Sunday")
        && time::Wednesday.String() == s("Wednesday")
        && time::Saturday.String() == s("Saturday");
    if ok {
        ok_line(b"[ 4] Weekday::String English     PASS\n");
    } else {
        ok_line(b"[ 4] Weekday::String English     FAIL\n");
        fail();
    }
}

fn test_5_month_string_out_of_range() {
    let m = Month::new(0);
    let m13 = Month::new(13);
    if m.String() == s("%!Month(0)") && m13.String() == s("%!Month(13)") {
        ok_line(b"[ 5] Month OOR renders %!Month   PASS\n");
    } else {
        ok_line(b"[ 5] Month OOR renders %!Month   FAIL\n");
        fail();
    }
}

fn test_6_weekday_string_out_of_range() {
    let w = Weekday::new(7);
    let wn = Weekday::new(-1);
    if w.String() == s("%!Weekday(7)") && wn.String() == s("%!Weekday(-1)") {
        ok_line(b"[ 6] Weekday OOR %!Weekday       PASS\n");
    } else {
        ok_line(b"[ 6] Weekday OOR %!Weekday       FAIL\n");
        fail();
    }
}

fn test_7_time_month_typed() {
    // 2024-07-04 — well-known Independence Day.
    let t = time::Date(2024, 7, 4, 12, 0, 0, 0, goish::time::UTC);
    let m = t.Month();
    if m == time::July && m.Int() == 7 {
        ok_line(b"[ 7] Time::Month -> typed Month  PASS\n");
    } else {
        ok_line(b"[ 7] Time::Month -> typed Month  FAIL\n");
        fail();
    }
}

fn test_8_time_weekday_typed() {
    // 2024-07-04 was a Thursday.
    let t = time::Date(2024, 7, 4, 12, 0, 0, 0, goish::time::UTC);
    let wd = t.Weekday();
    if wd == time::Thursday && wd.Int() == 4 {
        ok_line(b"[ 8] Time::Weekday -> typed      PASS\n");
    } else {
        ok_line(b"[ 8] Time::Weekday -> typed      FAIL\n");
        fail();
    }
}

fn test_9_cross_type_equality() {
    // Month == int and int == Month both compile + work.
    let m: Month = time::March;
    let mi: i64 = 3;
    let w: Weekday = time::Friday;
    let wi: i64 = 5;
    if m == mi && mi == m && w == wi && wi == w {
        ok_line(b"[ 9] Month/Weekday == int        PASS\n");
    } else {
        ok_line(b"[ 9] Month/Weekday == int        FAIL\n");
        fail();
    }
}

fn test_10_format_dispatch() {
    // %s / %v → name; %d → number.
    let m = time::October;
    let w = time::Tuesday;
    let s_name = fmt::Sprintf!("%s", m);
    let v_name = fmt::Sprintf!("%v", w);
    let d_num = fmt::Sprintf!("%d", m);
    let d_num_w = fmt::Sprintf!("%d", w);
    if s_name == s("October") && v_name == s("Tuesday") && d_num == s("10") && d_num_w == s("2") {
        ok_line(b"[10] Sprintf %s/%v/%d dispatch   PASS\n");
    } else {
        ok_line(b"[10] Sprintf %s/%v/%d dispatch   FAIL\n");
        fail();
    }
}
