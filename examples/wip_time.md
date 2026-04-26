# WIP example — M13 `time` package

A "stopwatch" CLI: parses a millisecond count from `os.Args[1]`, sleeps
for that long, prints the requested vs actual elapsed duration. Picked
because it's the smallest program that exercises:

- `time.Now()` (twice, via `time.Since`)
- `time.Sleep(d Duration)`
- `time.Since(t Time) Duration`
- `time.Millisecond` constant + `Duration * int` arithmetic
- `Duration.String()` (printed via `%v`)

This file is **not compiled**. It's the design target for M13.

---

## Go original

```go
package main

import (
    "fmt"
    "os"
    "strconv"
    "time"
)

func main() {
    if len(os.Args) != 2 {
        fmt.Fprintln(os.Stderr, "usage: stopwatch MILLIS")
        os.Exit(1)
    }
    ms, err := strconv.Atoi(os.Args[1])
    if err != nil {
        fmt.Fprintln(os.Stderr, "parse:", err)
        os.Exit(1)
    }
    start := time.Now()
    time.Sleep(time.Duration(ms) * time.Millisecond)
    elapsed := time.Since(start)
    fmt.Println("requested:", ms, "ms")
    fmt.Println("elapsed:", elapsed)
}
```

## Proposed goish v1 (target shape)

```rust
#![no_std]
#![no_main]

use goish::{int, len, nil, os, strconv, time, Fprintln, Println};

#[goish::main]
fn main() {
    let all = os::Args();
    if len(&all) != 2 {
        let mut e = os::Stderr();
        Fprintln!(e, "usage: stopwatch MILLIS");
        os::Exit(1);
    }
    let (ms, err) = strconv::Atoi(all[1].clone());
    if err != nil {
        let mut e = os::Stderr();
        Fprintln!(e, "parse:", err);
        os::Exit(1);
    }
    let start = time::Now();
    time::Sleep(time::Millisecond * ms);
    let elapsed = time::Since(start);
    Println!("requested:", ms, "ms");
    Println!("elapsed:", elapsed);
}
```

Run shape:
```
$ stopwatch 250
requested: 250 ms
elapsed: 250.123ms
```

---

## What this needs from M13

### Public types

```rust
/// Newtype around `int` (i64 nanoseconds). Mul<int> + Add/Sub/PartialOrd
/// derived. `Duration::String()` formats like Go: "5s", "100ms",
/// "1h2m3.456s", etc.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(pub int);

/// Wall-clock + optional monotonic time. Internally stores seconds since
/// the Unix epoch + nanosecond fraction + (optional) monotonic
/// nanoseconds. Comparisons (`After`, `Before`, `Equal`) use wall time.
/// `Sub` prefers monotonic when both operands have it.
#[derive(Clone, Copy)]
pub struct Time { /* opaque */ }
```

### Constants

```rust
pub const Nanosecond:  Duration = Duration(1);
pub const Microsecond: Duration = Duration(1_000);
pub const Millisecond: Duration = Duration(1_000_000);
pub const Second:      Duration = Duration(1_000_000_000);
pub const Minute:      Duration = Duration(60 * Second.0);
pub const Hour:        Duration = Duration(60 * Minute.0);
```

### Free functions

| Go | goish |
|---|---|
| `Now() Time` | identical |
| `Sleep(d Duration)` | identical |
| `Since(t Time) Duration` | identical (`Now().Sub(t)`) |
| `Until(t Time) Duration` | identical (`t.Sub(Now())`) |
| `Unix(sec int64, nsec int64) Time` | `pub fn Unix(sec: int, nsec: int) -> Time` |
| `Nanoseconds/Microseconds/Milliseconds/Seconds(n int) Duration` | clean Go-style constructors so users avoid `Duration * Duration` ambiguity |

### Methods

```rust
impl Duration {
    pub fn Nanoseconds(self) -> int;
    pub fn Microseconds(self) -> int;
    pub fn Milliseconds(self) -> int;
    pub fn String(self) -> string;
}
impl Mul<int> for Duration {
    type Output = Duration;          // 100 * Millisecond  (using Millisecond * 100)
}
impl Add<Duration> for Duration { ... }
impl Sub<Duration> for Duration { ... }
impl fmt::Format for Duration { ... }   // for Println! %v

impl Time {
    pub fn Unix(self) -> int;        // seconds since epoch
    pub fn UnixMilli(self) -> int;
    pub fn UnixMicro(self) -> int;
    pub fn UnixNano(self) -> int;
    pub fn IsZero(self) -> bool;
    pub fn After(self, u: Time) -> bool;
    pub fn Before(self, u: Time) -> bool;
    pub fn Equal(self, u: Time) -> bool;
    pub fn Sub(self, u: Time) -> Duration;
    pub fn Add(self, d: Duration) -> Time;
}
```

### v1 deviations from Go

- **No `Year`/`Month`/`Day`/`Hour`/`Minute`/`Second` accessors.** Gregorian
  calendar conversion is ~150 LOC of port (Go's `absSec().days().date()`
  chain). Defer to a follow-up; covers ~100% of timing-critical use
  without it.
- **No formatting / parsing** (`Format`, `Parse`, `ParseDuration`).
  Go's reference time `"Mon Jan 2 15:04:05 MST 2006"` machinery is
  ~1700 LOC. Defer.
- **No timezones.** Everything is UTC. `Time.Location()` and the
  ~7000 LOC of timezone DB are deferred indefinitely (out-of-scope for
  v1 per ROADMAP).
- **`Duration.Seconds()/Minutes()/Hours()` deferred** — Go returns
  `float64`, we don't expose floats yet (M11b). Use
  `d.Milliseconds() / 1000` etc. as the workaround until float lands.
- **No `Tickers`/`Timers`** — depends on goroutines (M15).
- **No `AddDate`** — needs Y/M/D arithmetic.
- **No `Truncate`/`Round`** — small additions, defer until requested.

### Syscalls to add

```
clock_gettime(clockid: int, tp: *mut Timespec)   // syscall 228
nanosleep(req: *const Timespec, rem: *mut Timespec)  // syscall 35

CLOCK_REALTIME  = 0
CLOCK_MONOTONIC = 1

#[repr(C)] struct Timespec { tv_sec: i64, tv_nsec: i64 }
```

`Now()` uses `clock_gettime(CLOCK_REALTIME)` for wall time and
`clock_gettime(CLOCK_MONOTONIC)` for the monotonic component, matching
Go's behaviour. `Sleep()` uses `nanosleep` and does **not** retry on
EINTR for v1 simplicity (most use cases don't care; document).

### Duration `.String()` format

Mirror Go faithfully (~80 LOC port from `time.go:format`):
- 0 → `"0s"`
- < 1µs → `"123ns"`
- < 1ms → `"123.45us"` (ASCII `us` vs Go's `µs` — see below)
- < 1s  → `"123.45ms"`
- ≥ 1s  → `"1h2m3.456s"` (omits leading zero units)

ASCII `us` instead of `µs` to keep the byte-string literal in the
formatter ASCII-clean. Document this as the only print-shape divergence.

---

## Output & verification

```
$ cargo run --example stopwatch -- 250
requested: 250 ms
elapsed: 250.123ms

$ cargo run --example stopwatch -- 0
requested: 0 ms
elapsed: 1us       (or similar tiny non-zero)

$ cargo run --example stopwatch -- abc
parse: strconv.Atoi: parsing "abc": invalid syntax
(exit 1)
```

`examples/time_smoke.rs` covers: `Now()` advances under `Sleep`,
`Since` ≈ slept duration (with slack), `Time.Sub` returns negative for
past, `IsZero`, `Equal`/`After`/`Before`, `Duration.String` for several
magnitudes, `Mul<int>` arithmetic, and `Unix` round-trip.
