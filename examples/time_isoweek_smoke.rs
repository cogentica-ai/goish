// time_isoweek_smoke — exercise time.Time.ISOWeek (time.go:848).
//
// Test cases verified against:
//   $ date -u -d '2024-01-01' +'%G %V'
//   $ python3 -c 'import datetime; print(datetime.date(Y,M,D).isocalendar())'

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::time;
use goish::{syscall, Println};

fn check(label: &'static str, t: time::Time, want_y: i64, want_w: i64, failed: &mut i64) {
    let (y, w) = t.ISOWeek();
    if y == want_y as i64 && w == want_w as i64 {
        Println!("[", label, "]   PASS");
    } else {
        Println!("[", label, "]   FAIL  got year=", y, " week=", w);
        *failed += 1;
    }
}

#[goish::main]
fn main() {
    let mut failed: i64 = 0;

    // 1. 2024-01-01 (Mon) → ISO 2024-W01.
    check("1", time::Date(2024, 1, 1, 0, 0, 0, 0, goish::time::UTC), 2024, 1, &mut failed);

    // 2. 2024-12-31 (Tue) → ISO 2025-W01 (rolls into next ISO year).
    check("2", time::Date(2024, 12, 31, 12, 0, 0, 0, goish::time::UTC), 2025, 1, &mut failed);

    // 3. 2023-01-01 (Sun) → ISO 2022-W52 (early-year roll-back case).
    check("3", time::Date(2023, 1, 1, 0, 0, 0, 0, goish::time::UTC), 2022, 52, &mut failed);

    // 4. 2020-12-31 (Thu) → ISO 2020-W53 (53-week ISO year).
    check("4", time::Date(2020, 12, 31, 23, 0, 0, 0, goish::time::UTC), 2020, 53, &mut failed);

    // 5. 2021-01-01 (Fri) → ISO 2020-W53 (continuation of W53 year).
    check("5", time::Date(2021, 1, 1, 0, 0, 0, 0, goish::time::UTC), 2020, 53, &mut failed);

    // 6. 2024-06-15 (Sat) → ISO 2024-W24.
    check("6", time::Date(2024, 6, 15, 0, 0, 0, 0, goish::time::UTC), 2024, 24, &mut failed);

    // 7. 1970-01-01 (Thu) → ISO 1970-W01.
    check("7", time::Date(1970, 1, 1, 0, 0, 0, 0, goish::time::UTC), 1970, 1, &mut failed);

    // 8. 1969-12-29 (Mon) → ISO 1970-W01 (Monday before Thursday Jan 1).
    check("8", time::Date(1969, 12, 29, 0, 0, 0, 0, goish::time::UTC), 1970, 1, &mut failed);

    // 9. 2026-12-28 (Mon) → ISO 2026-W53 (53-week ISO year).
    //    2026 starts Thu, so it has 53 ISO weeks; W53 runs Dec 28 – Jan 3.
    check("9", time::Date(2026, 12, 28, 0, 0, 0, 0, goish::time::UTC), 2026, 53, &mut failed);

    // 10. 2027-01-03 (Sun) → ISO 2026-W53 (last day of W53).
    check("10", time::Date(2027, 1, 3, 0, 0, 0, 0, goish::time::UTC), 2026, 53, &mut failed);

    if failed == 0 {
        Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
