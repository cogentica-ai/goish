// time_rfc3339_nano_smoke — exercise time.Format with RFC3339Nano layout.
//
// Validates: trailing-zero trimming, all-zero omits '.', max digits.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::time::{Date, RFC3339, RFC3339Nano};
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. nsec=0 → no fractional part (no '.', no digits).
    {
        let t = Date(2026, 5, 1, 12, 0, 0, 0, goish::time::UTC);
        let got = t.Format(string(RFC3339Nano));
        if got == "2026-05-01T12:00:00Z" {
            Println!("[ 1] nsec=0 omits '.'           PASS");
        } else {
            Println!("[ 1] nsec=0 omits '.'           FAIL got=", got);
            failed += 1;
        }
    }

    // 2. nsec=500_000_000 → ".5".
    {
        let t = Date(2026, 5, 1, 12, 0, 0, 500_000_000, goish::time::UTC);
        let got = t.Format(string(RFC3339Nano));
        if got == "2026-05-01T12:00:00.5Z" {
            Println!("[ 2] nsec=5e8 → .5             PASS");
        } else {
            Println!("[ 2] nsec=5e8 → .5             FAIL got=", got);
            failed += 1;
        }
    }

    // 3. nsec=123_456_789 → ".123456789" (full 9 digits, no trim).
    {
        let t = Date(2026, 5, 1, 12, 0, 0, 123_456_789, goish::time::UTC);
        let got = t.Format(string(RFC3339Nano));
        if got == "2026-05-01T12:00:00.123456789Z" {
            Println!("[ 3] full 9 digits             PASS");
        } else {
            Println!("[ 3] full 9 digits             FAIL got=", got);
            failed += 1;
        }
    }

    // 4. nsec=1 → ".000000001" (no trailing-zero trimming because last
    //    digit is non-zero; the leading zeros stay).
    {
        let t = Date(2026, 5, 1, 12, 0, 0, 1, goish::time::UTC);
        let got = t.Format(string(RFC3339Nano));
        if got == "2026-05-01T12:00:00.000000001Z" {
            Println!("[ 4] nsec=1 leading zeros      PASS");
        } else {
            Println!("[ 4] nsec=1 leading zeros      FAIL got=", got);
            failed += 1;
        }
    }

    // 5. nsec=100_000_000 → ".1".
    {
        let t = Date(2026, 5, 1, 12, 0, 0, 100_000_000, goish::time::UTC);
        let got = t.Format(string(RFC3339Nano));
        if got == "2026-05-01T12:00:00.1Z" {
            Println!("[ 5] nsec=1e8 → .1             PASS");
        } else {
            Println!("[ 5] nsec=1e8 → .1             FAIL got=", got);
            failed += 1;
        }
    }

    // 6. RFC3339 (no Nano) still produces no fractional part.
    {
        let t = Date(2026, 5, 1, 12, 0, 0, 123_456_789, goish::time::UTC);
        let got = t.Format(string(RFC3339));
        if got == "2026-05-01T12:00:00Z" {
            Println!("[ 6] RFC3339 strips fractional PASS");
        } else {
            Println!("[ 6] RFC3339 strips fractional FAIL got=", got);
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
