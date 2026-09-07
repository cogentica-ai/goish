// duration_string_ref_smoke — Duration.String against Go 1.25.5.
//
// Go's Duration.format writes backwards into a 32-byte buffer with its
// own fraction logic, and the edges are where a reimplementation
// drifts: the unit boundaries, the carry between units, and the two
// extremes (MaxInt64 and MinInt64, whose negation is its own value).
//
// The microsecond row is why this exists. goish wrote ASCII "us" where
// Go writes "µs" — U+00B5, two bytes in UTF-8 — as a DELIBERATE
// divergence, justified "because the rest of the formatter is
// ASCII-clean". That was a reason about the function rather than about
// the output, which gets logged, compared and diffed against Go's; the
// parser beside it had always accepted the UTF-8 form. What kept it
// alive was time_smoke, which asserted "123us": a smoke pinning goish
// to goish rather than to Go.
//
// GO[] is the verbatim output of tools/gen_duration_string_ref.go
// under scripts/goref.sh.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::string;
use goish::time;

static FAILED: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 21] = [
    "0 -> \"0s\"",
    "1 -> \"1ns\"",
    "999 -> \"999ns\"",
    "1000 -> \"1µs\"",
    "1001 -> \"1.001µs\"",
    "999999 -> \"999.999µs\"",
    "1000000 -> \"1ms\"",
    "1500000 -> \"1.5ms\"",
    "1000000000 -> \"1s\"",
    "1500000000 -> \"1.5s\"",
    "59000000000 -> \"59s\"",
    "60000000000 -> \"1m0s\"",
    "61000000000 -> \"1m1s\"",
    "3600000000000 -> \"1h0m0s\"",
    "3661000000000 -> \"1h1m1s\"",
    "90000000000000 -> \"25h0m0s\"",
    "-1 -> \"-1ns\"",
    "-1000000000 -> \"-1s\"",
    "-5400000000000 -> \"-1h30m0s\"",
    "9223372036854775807 -> \"2562047h47m16.854775807s\"",
    "-9223372036854775808 -> \"-2562047h47m16.854775808s\"",
];

static NS: [i64; 21] = [
    0, 1, 999, 1000, 1001, 999999, 1000000, 1500000,
    1_000_000_000, 1_500_000_000, 59_000_000_000, 60_000_000_000, 61_000_000_000,
    3_600_000_000_000, 3_661_000_000_000, 90_000_000_000_000,
    -1, -1_000_000_000, -5_400_000_000_000,
    9223372036854775807, -9223372036854775808,
];

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let mut i = 0usize;
    while i < NS.len() {
        let got = fmt::Sprintf!("%d -> %q", NS[i], time::Duration(NS[i]).String());
        if got == string(GO[i]) {
            fmt::Printf!("ok   %s
", got);
        } else {
            FAILED.fetch_add(1, Ordering::Relaxed);
            fmt::Printf!("[!!]
  got:  %s
  want: %s
", got, string(GO[i]));
        }
        i += 1;
    }
    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("
ok 21/21
");
        goish::os::Exit(0);
    }
    fmt::Printf!("
FAILED %d of 21
", f as i64);
    goish::os::Exit(1);
}
