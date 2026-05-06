// time_adddate_yearday_smoke — exercise time.Time.AddDate (time.go:1258)
// and time.Time.YearDay (time.go:903).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::time;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. YearDay Jan 1 → 1.
    {
        let t = time::Date(2024, 1, 1, 0, 0, 0, 0);
        let d = t.YearDay();
        if d == 1 {
            Println!("[ 1] YearDay Jan 1             PASS");
        } else {
            Println!("[ 1] YearDay Jan 1             FAIL got=", d);
            failed += 1;
        }
    }

    // 2. YearDay Dec 31 leap year (2024) → 366.
    {
        let t = time::Date(2024, 12, 31, 12, 0, 0, 0);
        let d = t.YearDay();
        if d == 366 {
            Println!("[ 2] YearDay Dec 31 leap       PASS");
        } else {
            Println!("[ 2] YearDay Dec 31 leap       FAIL got=", d);
            failed += 1;
        }
    }

    // 3. YearDay Dec 31 non-leap (2023) → 365.
    {
        let t = time::Date(2023, 12, 31, 23, 59, 59, 0);
        let d = t.YearDay();
        if d == 365 {
            Println!("[ 3] YearDay Dec 31 non-leap   PASS");
        } else {
            Println!("[ 3] YearDay Dec 31 non-leap   FAIL got=", d);
            failed += 1;
        }
    }

    // 4. YearDay Mar 1 leap year — 31 (Jan) + 29 (Feb) + 1 = 61.
    {
        let t = time::Date(2024, 3, 1, 0, 0, 0, 0);
        let d = t.YearDay();
        if d == 61 {
            Println!("[ 4] YearDay Mar 1 leap        PASS");
        } else {
            Println!("[ 4] YearDay Mar 1 leap        FAIL got=", d);
            failed += 1;
        }
    }

    // 5. YearDay Mar 1 non-leap — 31 + 28 + 1 = 60.
    {
        let t = time::Date(2023, 3, 1, 0, 0, 0, 0);
        let d = t.YearDay();
        if d == 60 {
            Println!("[ 5] YearDay Mar 1 non-leap    PASS");
        } else {
            Println!("[ 5] YearDay Mar 1 non-leap    FAIL got=", d);
            failed += 1;
        }
    }

    // 6. AddDate adds years (zero-month, zero-day).
    {
        let t = time::Date(2024, 6, 15, 12, 30, 0, 0);
        let u = t.AddDate(2, 0, 0);
        let (y, m, d) = u.Date();
        if y == 2026 && m == 6 && d == 15 {
            Println!("[ 6] AddDate years             PASS");
        } else {
            Println!("[ 6] AddDate years             FAIL");
            failed += 1;
        }
    }

    // 7. AddDate adds months and overflows year.
    {
        let t = time::Date(2024, 11, 1, 0, 0, 0, 0);
        let u = t.AddDate(0, 3, 0);
        let (y, m, d) = u.Date();
        if y == 2025 && m == 2 && d == 1 {
            Println!("[ 7] AddDate months overflow   PASS");
        } else {
            Println!("[ 7] AddDate months overflow   FAIL");
            failed += 1;
        }
    }

    // 8. AddDate normalizes Oct 31 + 1 month = Dec 1 (per Go doc).
    {
        let t = time::Date(2024, 10, 31, 0, 0, 0, 0);
        let u = t.AddDate(0, 1, 0);
        let (y, m, d) = u.Date();
        if y == 2024 && m == 12 && d == 1 {
            Println!("[ 8] AddDate Oct31+1m → Dec 1  PASS");
        } else {
            Println!("[ 8] AddDate Oct31+1m → Dec 1  FAIL");
            failed += 1;
        }
    }

    // 9. AddDate adds days, crossing month boundary.
    {
        let t = time::Date(2024, 1, 30, 0, 0, 0, 0);
        let u = t.AddDate(0, 0, 5);
        let (y, m, d) = u.Date();
        if y == 2024 && m == 2 && d == 4 {
            Println!("[ 9] AddDate days cross month  PASS");
        } else {
            Println!("[ 9] AddDate days cross month  FAIL");
            failed += 1;
        }
    }

    // 10. AddDate negative deltas (subtract).
    {
        let t = time::Date(2024, 3, 1, 0, 0, 0, 0);
        let u = t.AddDate(-1, -2, -1);  // 2023 + (3-2)=Jan + (1-1)=0 → 2022-12-31
        let (y, m, d) = u.Date();
        if y == 2022 && m == 12 && d == 31 {
            Println!("[10] AddDate negative          PASS");
        } else {
            Println!("[10] AddDate negative          FAIL");
            failed += 1;
        }
    }

    // 11. AddDate preserves clock (hour/min/sec/nsec).
    {
        let t = time::Date(2024, 1, 1, 13, 45, 7, 123_456_789);
        let u = t.AddDate(0, 0, 1);
        let (h, mi, s) = u.Clock();
        if h == 13 && mi == 45 && s == 7 && u.Nanosecond() == 123_456_789 {
            Println!("[11] AddDate preserves clock   PASS");
        } else {
            Println!("[11] AddDate preserves clock   FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 11/11");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 11");
        syscall::Exit(1);
    }
}
