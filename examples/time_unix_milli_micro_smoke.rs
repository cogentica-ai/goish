// time_unix_milli_micro_smoke — exercise time.UnixMilli + time.UnixMicro
// (time.go:1666 + 1672).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::syscall;
use goish::time::{Unix, UnixMicro, UnixMilli};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. UnixMilli(0) == Unix(0, 0).
    {
        let a = UnixMilli(0);
        let b = Unix(0, 0);
        if a.Equal(b) {
            fmt::Println!("[ 1] UnixMilli(0) == Unix(0,0)  PASS");
        } else {
            fmt::Println!("[ 1] UnixMilli(0) == Unix(0,0)  FAIL");
            failed += 1;
        }
    }

    // 2. UnixMilli(1234) → sec=1, nsec=234_000_000.
    {
        let t = UnixMilli(1234);
        if t.Unix() == 1 && t.UnixMilli() == 1234 {
            fmt::Println!("[ 2] UnixMilli(1234) round-trip PASS");
        } else {
            fmt::Println!(
                "[ 2] UnixMilli(1234) round-trip FAIL sec=",
                t.Unix(),
                "ms=",
                t.UnixMilli()
            );
            failed += 1;
        }
    }

    // 3. UnixMilli(-1) → 1ms before epoch (sec=-1, nsec=999_000_000).
    //    Go's div/mod for negatives: -1/1000 = 0, -1%1000 = -1, then
    //    Unix(0, -1_000_000) → sec=-1, nsec=999_000_000.
    {
        let t = UnixMilli(-1);
        if t.UnixMilli() == -1 {
            fmt::Println!("[ 3] UnixMilli(-1) round-trip   PASS");
        } else {
            fmt::Println!("[ 3] UnixMilli(-1) round-trip   FAIL ms=", t.UnixMilli());
            failed += 1;
        }
    }

    // 4. UnixMicro(0) == Unix(0, 0).
    {
        let a = UnixMicro(0);
        let b = Unix(0, 0);
        if a.Equal(b) {
            fmt::Println!("[ 4] UnixMicro(0) == Unix(0,0)  PASS");
        } else {
            fmt::Println!("[ 4] UnixMicro(0) == Unix(0,0)  FAIL");
            failed += 1;
        }
    }

    // 5. UnixMicro(1_500_000) → sec=1, nsec=500_000_000; UnixMicro round-trip.
    {
        let t = UnixMicro(1_500_000);
        if t.Unix() == 1 && t.UnixMicro() == 1_500_000 {
            fmt::Println!("[ 5] UnixMicro(1.5e6) round     PASS");
        } else {
            fmt::Println!(
                "[ 5] UnixMicro(1.5e6) round     FAIL sec=",
                t.Unix(),
                "us=",
                t.UnixMicro()
            );
            failed += 1;
        }
    }

    // 6. UnixMicro(2026 epoch ≈ 1.78e15) round-trip.
    {
        // 2026-01-01 ≈ 56*365.25 * 86400 * 1e6 us ≈ 1_767_225_600_000_000
        let usec: i64 = 1_767_225_600_000_000;
        let t = UnixMicro(usec);
        if t.UnixMicro() == usec {
            fmt::Println!("[ 6] UnixMicro(future) round    PASS");
        } else {
            fmt::Println!("[ 6] UnixMicro(future) round    FAIL got=", t.UnixMicro());
            failed += 1;
        }
    }

    // 7. UnixMilli + UnixMicro consistent: same instant.
    {
        let ms: i64 = 1_500;
        let us: i64 = ms * 1_000;
        let t1 = UnixMilli(ms);
        let t2 = UnixMicro(us);
        if t1.Equal(t2) {
            fmt::Println!("[ 7] UnixMilli ≈ UnixMicro     PASS");
        } else {
            fmt::Println!("[ 7] UnixMilli ≈ UnixMicro     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
