// time_parse_duration_smoke — exercise time.ParseDuration line-by-line
// port (Go format.go:1621).

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

    // 1. "0" -> 0.
    {
        let (d, err) = time::ParseDuration(string("0"));
        if err.IsNil() && d.Nanoseconds() == 0 {
            Println!("[ 1] zero string               PASS");
        } else {
            Println!("[ 1] zero string               FAIL ns={}", d.Nanoseconds());
            failed += 1;
        }
    }

    // 2. "5s" -> 5 * Second.
    {
        let (d, err) = time::ParseDuration(string("5s"));
        if err.IsNil() && d.Nanoseconds() == 5 * 1_000_000_000 {
            Println!("[ 2] 5s                        PASS");
        } else {
            Println!("[ 2] 5s                        FAIL ns={}", d.Nanoseconds());
            failed += 1;
        }
    }

    // 3. "300ms" -> 300 * Millisecond.
    {
        let (d, err) = time::ParseDuration(string("300ms"));
        if err.IsNil() && d.Nanoseconds() == 300 * 1_000_000 {
            Println!("[ 3] 300ms                     PASS");
        } else {
            Println!("[ 3] 300ms                     FAIL ns={}", d.Nanoseconds());
            failed += 1;
        }
    }

    // 4. "-1.5h" -> -90 * Minute.
    {
        let (d, err) = time::ParseDuration(string("-1.5h"));
        if err.IsNil() && d.Nanoseconds() == -90i64 * 60 * 1_000_000_000 {
            Println!("[ 4] -1.5h                     PASS");
        } else {
            Println!("[ 4] -1.5h                     FAIL ns={}", d.Nanoseconds());
            failed += 1;
        }
    }

    // 5. "2h45m" -> 2*Hour + 45*Minute.
    {
        let (d, err) = time::ParseDuration(string("2h45m"));
        let want = 2i64 * 60 * 60 * 1_000_000_000 + 45i64 * 60 * 1_000_000_000;
        if err.IsNil() && d.Nanoseconds() == want {
            Println!("[ 5] 2h45m                     PASS");
        } else {
            Println!("[ 5] 2h45m                     FAIL ns={}", d.Nanoseconds());
            failed += 1;
        }
    }

    // 6. "1h2m3.456s" combined integer + fractional.
    {
        let (d, err) = time::ParseDuration(string("1h2m3.456s"));
        let want = 1i64 * 60 * 60 * 1_000_000_000
            + 2i64 * 60 * 1_000_000_000
            + 3i64 * 1_000_000_000
            + 456i64 * 1_000_000;
        if err.IsNil() && d.Nanoseconds() == want {
            Println!("[ 6] 1h2m3.456s                PASS");
        } else {
            Println!("[ 6] 1h2m3.456s                FAIL ns={} want={}", d.Nanoseconds(), want);
            failed += 1;
        }
    }

    // 7. "100ns" -> 100.
    {
        let (d, err) = time::ParseDuration(string("100ns"));
        if err.IsNil() && d.Nanoseconds() == 100 {
            Println!("[ 7] 100ns                     PASS");
        } else {
            Println!("[ 7] 100ns                     FAIL");
            failed += 1;
        }
    }

    // 8. "1us" and "1µs" must give same result.
    {
        let (a, ea) = time::ParseDuration(string("1us"));
        let (b, eb) = time::ParseDuration(string("1µs"));
        if ea.IsNil() && eb.IsNil() && a.Nanoseconds() == 1_000 && b.Nanoseconds() == 1_000 {
            Println!("[ 8] us == µs                  PASS");
        } else {
            Println!("[ 8] us == µs                  FAIL a={} b={}", a.Nanoseconds(), b.Nanoseconds());
            failed += 1;
        }
    }

    // 9. Empty string is an error.
    {
        let (_d, err) = time::ParseDuration(string(""));
        if !err.IsNil() {
            Println!("[ 9] empty errors              PASS");
        } else {
            Println!("[ 9] empty errors              FAIL");
            failed += 1;
        }
    }

    // 10. "abc" — missing unit / not [0-9.] — error.
    {
        let (_d, err) = time::ParseDuration(string("abc"));
        if !err.IsNil() {
            Println!("[10] abc errors                PASS");
        } else {
            Println!("[10] abc errors                FAIL");
            failed += 1;
        }
    }

    // 11. "5" — digits without unit is "missing unit" error.
    {
        let (_d, err) = time::ParseDuration(string("5"));
        if !err.IsNil() {
            Println!("[11] missing unit              PASS");
        } else {
            Println!("[11] missing unit              FAIL");
            failed += 1;
        }
    }

    // 12. "+1m" — leading + sign is allowed.
    {
        let (d, err) = time::ParseDuration(string("+1m"));
        if err.IsNil() && d.Nanoseconds() == 60 * 1_000_000_000 {
            Println!("[12] leading + sign            PASS");
        } else {
            Println!("[12] leading + sign            FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 12", failed);
        syscall::Exit(1);
    }
}
