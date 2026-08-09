// time_truncate_round_smoke — exercise Time.Truncate / Round / UTC / Local.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::time;
use goish::{string, syscall};

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
            fmt::Println!("[ 1] Truncate(Second)            PASS");
        } else {
            fmt::Println!("[ 1] Truncate(Second)            FAIL got={}", r.UnixNano());
            failed += 1;
        }
    }

    // 2. Truncate(Minute) — total ns must be a multiple of 60s.
    {
        let r = t.Truncate(time::Minute);
        let ns = r.UnixNano();
        if ns % (60 * 1_000_000_000) == 0 && ns <= t.UnixNano() {
            fmt::Println!("[ 2] Truncate(Minute)            PASS");
        } else {
            fmt::Println!("[ 2] Truncate(Minute)            FAIL");
            failed += 1;
        }
    }

    // 3. Round(Second) on .789s rounds UP to next second.
    {
        let r = t.Round(time::Second);
        if r.UnixNano() == (sec_in + 1).wrapping_mul(1_000_000_000) {
            fmt::Println!("[ 3] Round up                    PASS");
        } else {
            fmt::Println!("[ 3] Round up                    FAIL got={}", r.UnixNano());
            failed += 1;
        }
    }

    // 4. Round(Second) on .200s rounds DOWN.
    {
        let t2 = time::Unix(sec_in, 200_000_000);
        let r = t2.Round(time::Second);
        if r.UnixNano() == sec_in.wrapping_mul(1_000_000_000) {
            fmt::Println!("[ 4] Round down                  PASS");
        } else {
            fmt::Println!("[ 4] Round down                  FAIL got={}", r.UnixNano());
            failed += 1;
        }
    }

    // 5. Halfway-value rounds UP (Go semantics).
    {
        let t3 = time::Unix(sec_in, 500_000_000);
        let r = t3.Round(time::Second);
        if r.UnixNano() == (sec_in + 1).wrapping_mul(1_000_000_000) {
            fmt::Println!("[ 5] Halfway rounds up           PASS");
        } else {
            fmt::Println!("[ 5] Halfway rounds up           FAIL got={}", r.UnixNano());
            failed += 1;
        }
    }

    // 6. Truncate(d=0) returns t unchanged.
    {
        let r = t.Truncate(time::Duration(0));
        if r.UnixNano() == t.UnixNano() {
            fmt::Println!("[ 6] Truncate(0) is noop         PASS");
        } else {
            fmt::Println!("[ 6] Truncate(0) is noop         FAIL");
            failed += 1;
        }
    }

    // 7. Round(d<0) returns t unchanged.
    {
        let r = t.Round(time::Duration(-1));
        if r.UnixNano() == t.UnixNano() {
            fmt::Println!("[ 7] Round(-1) is noop           PASS");
        } else {
            fmt::Println!("[ 7] Round(-1) is noop           FAIL");
            failed += 1;
        }
    }

    // 8. UTC() / Local() are identity in slim time.
    {
        let u = t.UTC();
        let l = t.Local();
        if u.UnixNano() == t.UnixNano() && l.UnixNano() == t.UnixNano() {
            fmt::Println!("[ 8] UTC/Local identity          PASS");
        } else {
            fmt::Println!("[ 8] UTC/Local identity          FAIL");
            failed += 1;
        }
    }

    // 9. AppendFormat appends formatted bytes to existing buffer.
    {
        let prefix = goish::convert::bytes("ts=");
        let appended = t.AppendFormat(prefix, string(time::RFC3339));
        let s = goish::string::from_bytes(&appended);
        // RFC3339 layout produces the date-time including 'Z'.
        if goish::strings::HasPrefix(s.clone(), string("ts=")) && s.Len() > 3 {
            fmt::Println!("[ 9] AppendFormat prefix       PASS");
        } else {
            fmt::Println!("[ 9] AppendFormat prefix       FAIL got={}", s);
            failed += 1;
        }
    }

    // 10. Zone() returns ("UTC", 0) — slim time has no Location.
    {
        let (name, off) = t.Zone();
        if name == "UTC" && off == 0 {
            fmt::Println!("[10] Zone UTC                  PASS");
        } else {
            fmt::Println!("[10] Zone UTC                  FAIL");
            failed += 1;
        }
    }

    // 11. IsDST() always returns false.
    {
        if !t.IsDST() {
            fmt::Println!("[11] IsDST=false               PASS");
        } else {
            fmt::Println!("[11] IsDST=false               FAIL");
            failed += 1;
        }
    }

    // 12. MarshalText/UnmarshalText round-trip via RFC3339 (no nanos).
    {
        let t_anchor = time::Unix(1_700_000_000, 0);
        let (data, err) = t_anchor.MarshalText();
        if !err.IsNil() {
            fmt::Println!("[12] MarshalText/Unmarshal     FAIL marshal");
            failed += 1;
        } else {
            let mut got = time::Unix(0, 0);
            let uerr = got.UnmarshalText(data);
            if uerr.IsNil() && got.Unix() == 1_700_000_000 {
                fmt::Println!("[12] MarshalText/Unmarshal     PASS");
            } else {
                fmt::Println!("[12] MarshalText/Unmarshal     FAIL unix={}", got.Unix());
                failed += 1;
            }
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
