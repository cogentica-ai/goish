// time_duration_methods_smoke — exercise Duration.Truncate / Round /
// Abs / Seconds / Minutes / Hours.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::time;
use goish::{syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Truncate(Second) drops sub-second.
    {
        let d = time::Second * 5 + time::Millisecond * 789;
        let r = d.Truncate(time::Second);
        if r.Nanoseconds() == 5 * 1_000_000_000 {
            fmt::Println!("[ 1] Truncate(Second)          PASS");
        } else {
            fmt::Println!("[ 1] Truncate(Second)          FAIL ns={}", r.Nanoseconds());
            failed += 1;
        }
    }

    // 2. Truncate(0) is identity.
    {
        let d = time::Second * 7;
        let r = d.Truncate(time::Duration(0));
        if r.Nanoseconds() == 7 * 1_000_000_000 {
            fmt::Println!("[ 2] Truncate(0) identity      PASS");
        } else {
            fmt::Println!("[ 2] Truncate(0) identity      FAIL");
            failed += 1;
        }
    }

    // 3. Round up at .789s.
    {
        let d = time::Second * 5 + time::Millisecond * 789;
        let r = d.Round(time::Second);
        if r.Nanoseconds() == 6 * 1_000_000_000 {
            fmt::Println!("[ 3] Round up .789s            PASS");
        } else {
            fmt::Println!("[ 3] Round up .789s            FAIL ns={}", r.Nanoseconds());
            failed += 1;
        }
    }

    // 4. Round down at .200s.
    {
        let d = time::Second * 5 + time::Millisecond * 200;
        let r = d.Round(time::Second);
        if r.Nanoseconds() == 5 * 1_000_000_000 {
            fmt::Println!("[ 4] Round down .200s          PASS");
        } else {
            fmt::Println!("[ 4] Round down .200s          FAIL ns={}", r.Nanoseconds());
            failed += 1;
        }
    }

    // 5. Halfway rounds away from zero (.500s rounds up).
    {
        let d = time::Second * 5 + time::Millisecond * 500;
        let r = d.Round(time::Second);
        if r.Nanoseconds() == 6 * 1_000_000_000 {
            fmt::Println!("[ 5] Round halfway up          PASS");
        } else {
            fmt::Println!("[ 5] Round halfway up          FAIL ns={}", r.Nanoseconds());
            failed += 1;
        }
    }

    // 6. Round(<= 0) is identity.
    {
        let d = time::Second * 5;
        let r = d.Round(time::Duration(-1));
        if r.Nanoseconds() == 5 * 1_000_000_000 {
            fmt::Println!("[ 6] Round(<=0) identity       PASS");
        } else {
            fmt::Println!("[ 6] Round(<=0) identity       FAIL");
            failed += 1;
        }
    }

    // 7. Abs of negative duration.
    {
        let d = time::Duration(-3_000_000_000);
        let r = d.Abs();
        if r.Nanoseconds() == 3_000_000_000 {
            fmt::Println!("[ 7] Abs(-3s)=3s               PASS");
        } else {
            fmt::Println!("[ 7] Abs(-3s)=3s               FAIL");
            failed += 1;
        }
    }

    // 8. Abs of MinInt64 saturates to MaxInt64.
    {
        let d = time::Duration(i64::MIN);
        let r = d.Abs();
        if r.Nanoseconds() == i64::MAX {
            fmt::Println!("[ 8] Abs(MinInt64)=MaxInt64    PASS");
        } else {
            fmt::Println!("[ 8] Abs(MinInt64)=MaxInt64    FAIL");
            failed += 1;
        }
    }

    // 9. Seconds() float for "1.5s".
    {
        let d = time::Millisecond * 1500;
        let s = d.Seconds();
        // Compare with tolerance via integer ratio (avoid float == in no_std).
        let n = (s * 1000.0) as i64;
        if n == 1500 {
            fmt::Println!("[ 9] Seconds()=1.5             PASS");
        } else {
            fmt::Println!("[ 9] Seconds()=1.5             FAIL n={}", n);
            failed += 1;
        }
    }

    // 10. Minutes() float for "150s" -> 2.5.
    {
        let d = time::Second * 150;
        let m = d.Minutes();
        let n = (m * 1000.0) as i64;
        if n == 2500 {
            fmt::Println!("[10] Minutes()=2.5             PASS");
        } else {
            fmt::Println!("[10] Minutes()=2.5             FAIL n={}", n);
            failed += 1;
        }
    }

    // 11. Hours() for "2h30m" -> 2.5.
    {
        let d = time::Hour * 2 + time::Minute * 30;
        let h = d.Hours();
        let n = (h * 1000.0) as i64;
        if n == 2500 {
            fmt::Println!("[11] Hours()=2.5               PASS");
        } else {
            fmt::Println!("[11] Hours()=2.5               FAIL n={}", n);
            failed += 1;
        }
    }

    // 12. Round on a negative duration.
    {
        let d = time::Duration(-5_500_000_000);
        let r = d.Round(time::Second);
        if r.Nanoseconds() == -6_000_000_000 {
            fmt::Println!("[12] Round(-5.5s)=-6s          PASS");
        } else {
            fmt::Println!("[12] Round(-5.5s)=-6s          FAIL ns={}", r.Nanoseconds());
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 12", failed);
        syscall::Exit(1);
    }
}
