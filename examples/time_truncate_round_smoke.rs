// time_truncate_round_smoke — exercise Time.Truncate / Round / UTC / Local.

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

    // Anchor: pick a real-ish 2024-era epoch; what matters is that
    // Truncate/Round operate on UnixNano modulo d. Stay well below
    // i64::MAX/1e9 to keep nanoseconds in range.
    let sec_in: i64 = 1_700_000_056;
    let nsec_in: i64 = 789_000_000;
    let t = time::Unix(sec_in, nsec_in);

    // 1. Truncate(Second) zeroes the sub-second component.
    {
        let r = t.Truncate(time::Second);
        if r.UnixNano() == sec_in.wrapping_mul(1_000_000_000) {
            Println!("[ 1] Truncate(Second)            PASS");
        } else {
            Println!("[ 1] Truncate(Second)            FAIL got={}", r.UnixNano());
            failed += 1;
        }
    }

    // 2. Truncate(Minute) — total ns must be a multiple of 60s.
    {
        let r = t.Truncate(time::Minute);
        let ns = r.UnixNano();
        if ns % (60 * 1_000_000_000) == 0 && ns <= t.UnixNano() {
            Println!("[ 2] Truncate(Minute)            PASS");
        } else {
            Println!("[ 2] Truncate(Minute)            FAIL");
            failed += 1;
        }
    }

    // 3. Round(Second) on .789s rounds UP to next second.
    {
        let r = t.Round(time::Second);
        if r.UnixNano() == (sec_in + 1).wrapping_mul(1_000_000_000) {
            Println!("[ 3] Round up                    PASS");
        } else {
            Println!("[ 3] Round up                    FAIL got={}", r.UnixNano());
            failed += 1;
        }
    }

    // 4. Round(Second) on .200s rounds DOWN.
    {
        let t2 = time::Unix(sec_in, 200_000_000);
        let r = t2.Round(time::Second);
        if r.UnixNano() == sec_in.wrapping_mul(1_000_000_000) {
            Println!("[ 4] Round down                  PASS");
        } else {
            Println!("[ 4] Round down                  FAIL got={}", r.UnixNano());
            failed += 1;
        }
    }

    // 5. Halfway-value rounds UP (Go semantics).
    {
        let t3 = time::Unix(sec_in, 500_000_000);
        let r = t3.Round(time::Second);
        if r.UnixNano() == (sec_in + 1).wrapping_mul(1_000_000_000) {
            Println!("[ 5] Halfway rounds up           PASS");
        } else {
            Println!("[ 5] Halfway rounds up           FAIL got={}", r.UnixNano());
            failed += 1;
        }
    }

    // 6. Truncate(d=0) returns t unchanged.
    {
        let r = t.Truncate(time::Duration(0));
        if r.UnixNano() == t.UnixNano() {
            Println!("[ 6] Truncate(0) is noop         PASS");
        } else {
            Println!("[ 6] Truncate(0) is noop         FAIL");
            failed += 1;
        }
    }

    // 7. Round(d<0) returns t unchanged.
    {
        let r = t.Round(time::Duration(-1));
        if r.UnixNano() == t.UnixNano() {
            Println!("[ 7] Round(-1) is noop           PASS");
        } else {
            Println!("[ 7] Round(-1) is noop           FAIL");
            failed += 1;
        }
    }

    // 8. UTC() / Local() are identity in slim time.
    {
        let u = t.UTC();
        let l = t.Local();
        if u.UnixNano() == t.UnixNano() && l.UnixNano() == t.UnixNano() {
            Println!("[ 8] UTC/Local identity          PASS");
        } else {
            Println!("[ 8] UTC/Local identity          FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 8", failed);
        syscall::Exit(1);
    }
}
