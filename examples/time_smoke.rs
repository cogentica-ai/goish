// M13 smoke test: time package.
//
// Covers: Now/Sleep/Since semantics, Time arithmetic (Sub/Add/After/
// Before/Equal/IsZero), Unix*/UnixNano round-trip, Duration arithmetic,
// Duration constructors, and Duration.String() across magnitudes.

#![no_std]
#![no_main]

use goish::{syscall, time, Sprintf};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    // ─── Duration constants & arithmetic ──────────────────────────────

    check(time::Nanosecond.Nanoseconds() == 1, b"time: Nanosecond const wrong\n");
    check(
        time::Microsecond.Nanoseconds() == 1_000,
        b"time: Microsecond const wrong\n",
    );
    check(
        time::Millisecond.Nanoseconds() == 1_000_000,
        b"time: Millisecond const wrong\n",
    );
    check(
        time::Second.Nanoseconds() == 1_000_000_000,
        b"time: Second const wrong\n",
    );
    check(
        time::Minute.Nanoseconds() == 60 * 1_000_000_000,
        b"time: Minute const wrong\n",
    );

    // Mul<int>: Duration * int
    let d = time::Millisecond * 100;
    check(d.Milliseconds() == 100, b"time: Millisecond*100 wrong\n");

    // Add / Sub
    let d = time::Second + time::Millisecond * 500;
    check(d.Milliseconds() == 1500, b"time: Second + 500ms wrong\n");
    let d = time::Second - time::Millisecond * 250;
    check(d.Milliseconds() == 750, b"time: Second - 250ms wrong\n");

    // Constructors
    check(time::Milliseconds(42).Milliseconds() == 42, b"time: Milliseconds(42) wrong\n");
    check(time::Microseconds(7).Microseconds() == 7, b"time: Microseconds(7) wrong\n");
    check(time::Seconds(3).Nanoseconds() == 3_000_000_000, b"time: Seconds(3) wrong\n");

    // ─── Duration.String() across magnitudes ──────────────────────────

    check(time::Duration(0).String() == "0s", b"time: Duration(0).String wrong\n");
    check(time::Nanoseconds(5).String() == "5ns", b"time: 5ns String wrong\n");
    check(
        time::Microseconds(123).String() == "123us",
        b"time: 123us String wrong\n",
    );
    check(
        time::Milliseconds(250).String() == "250ms",
        b"time: 250ms String wrong\n",
    );
    check(time::Seconds(5).String() == "5s", b"time: 5s String wrong\n");
    check(
        (time::Minute + time::Second * 30).String() == "1m30s",
        b"time: 1m30s String wrong\n",
    );
    check(
        (time::Hour + time::Minute * 2 + time::Second * 3).String() == "1h2m3s",
        b"time: 1h2m3s String wrong\n",
    );
    // Negative.
    check(
        (time::Millisecond * -250).String() == "-250ms",
        b"time: -250ms String wrong\n",
    );

    // %v via Sprintf — confirms fmt::Format impl works.
    let s = Sprintf!("took %v", time::Milliseconds(250));
    check(s == "took 250ms", b"time: %v on Duration wrong\n");

    // ─── Time::Unix round-trip ────────────────────────────────────────

    let t = time::Unix(1_700_000_000, 500_000_000); // 1.7e9 sec + 0.5s
    check(t.Unix() == 1_700_000_000, b"time: Unix() wrong\n");
    check(t.UnixMilli() == 1_700_000_000_500, b"time: UnixMilli wrong\n");
    check(
        t.UnixNano() == 1_700_000_000_500_000_000,
        b"time: UnixNano wrong\n",
    );

    // ─── IsZero ───────────────────────────────────────────────────────

    let zero = time::Unix(0, 0);
    check(zero.IsZero(), b"time: IsZero(zero) wrong\n");
    check(!t.IsZero(), b"time: IsZero(non-zero) wrong\n");

    // ─── Before / After / Equal ───────────────────────────────────────

    let earlier = time::Unix(1000, 0);
    let later = time::Unix(2000, 0);
    let same = time::Unix(1000, 0);
    check(earlier.Before(later), b"time: Before wrong\n");
    check(later.After(earlier), b"time: After wrong\n");
    check(earlier.Equal(same), b"time: Equal wrong\n");
    check(!earlier.Equal(later), b"time: Equal negative wrong\n");

    // ─── Sub / Add ────────────────────────────────────────────────────

    let diff = later.Sub(earlier);
    check(diff == time::Second * 1000, b"time: Sub diff wrong\n");

    let plus_5s = earlier.Add(time::Second * 5);
    check(plus_5s.Unix() == 1005, b"time: Add wrong\n");

    // Sub of a future from past is negative.
    let neg = earlier.Sub(later);
    check(neg.Nanoseconds() < 0, b"time: Sub negative wrong\n");

    // ─── Now + Sleep + Since ──────────────────────────────────────────
    //
    // Sleep ~10ms, assert Since reports between 8ms and 100ms.

    let start = time::Now();
    time::Sleep(time::Milliseconds(10));
    let elapsed = time::Since(start);
    check(
        elapsed >= time::Milliseconds(8),
        b"time: Sleep elapsed too short\n",
    );
    check(
        elapsed < time::Milliseconds(100),
        b"time: Sleep elapsed unreasonably long\n",
    );

    // Now() advances under successive calls.
    let a = time::Now();
    let b = time::Now();
    check(!b.Before(a), b"time: Now() must not regress\n");

    const OK: &[u8] = b"time: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
