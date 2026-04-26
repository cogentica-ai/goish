# WIP example — M11b-A `strconv` floats (slow path port)

A "stats" CLI: reads numbers (one per line) from stdin, prints
count / sum / mean / min / max with float-aware output.

This file is **not compiled**. It's the design target for M11b-A.

---

## Go original

```go
package main

import (
    "bufio"
    "fmt"
    "math"
    "os"
    "strconv"
)

func main() {
    sc := bufio.NewScanner(os.Stdin)
    n := 0
    sum := 0.0
    minV := math.Inf(1)
    maxV := math.Inf(-1)
    for sc.Scan() {
        v, err := strconv.ParseFloat(sc.Text(), 64)
        if err != nil { continue }
        n++; sum += v
        if v < minV { minV = v }
        if v > maxV { maxV = v }
    }
    if n == 0 { fmt.Println("(no numbers)"); return }
    fmt.Printf("count: %d\n", n)
    fmt.Printf("sum:   %g\n", sum)
    fmt.Printf("mean:  %g\n", sum/float64(n))
    fmt.Printf("min:   %g\n", minV)
    fmt.Printf("max:   %g\n", maxV)
}
```

## Proposed goish v1 (target shape)

```rust
#![no_std]
#![no_main]

use goish::{bufio, float64, int, nil, os, strconv, Println, Printf};

#[goish::main]
fn main() {
    let mut sc = bufio::NewScanner(os::Stdin());
    let mut n: int = 0;
    let mut sum: float64 = 0.0;
    let mut min_v: float64 = float64::INFINITY;
    let mut max_v: float64 = float64::NEG_INFINITY;
    while sc.Scan() {
        let (v, err) = strconv::ParseFloat(sc.Text(), 64);
        if err != nil { continue; }
        n += 1; sum += v;
        if v < min_v { min_v = v; }
        if v > max_v { max_v = v; }
    }
    if n == 0 { Println!("(no numbers)"); return; }
    Printf!("count: %d\n", n);
    Printf!("sum:   %g\n", sum);
    Printf!("mean:  %g\n", sum / (n as float64));
    Printf!("min:   %g\n", min_v);
    Printf!("max:   %g\n", max_v);
}
```

Run:
```
$ printf '1.5\n2.5\n10\n0.001\n' | stats
count: 4
sum:   14.001
mean:  3.50025
min:   0.001
max:   10
```

---

## Scope (this milestone, M11b-A)

**Ports verbatim from Go 1.25:**

- `src/strconv/decimal.rs` ← `decimal.go` (415 LOC). Multiprecision
  decimal type, `Shift`, `Round*`, `RoundedInteger`, `Assign`, `set`,
  `String`. Used by both ParseFloat (slow path) and FormatFloat
  (`bigFtoa`).
- `src/strconv/atof.rs` ← `atof.go` slow path (~400 LOC of relevant
  parts). Contains `special`, `readFloat`, `atof32exact`, `atof64exact`,
  `atofHex`, `atof64`, `atof32`, `floatBits` (on `decimal`). Skips the
  Eisel-Lemire optimization — slow path produces identical output.
- `src/strconv/ftoa.rs` ← `ftoa.go` slow path (~500 LOC). Contains
  `genericFtoa`, `bigFtoa`, `formatDigits`, `roundShortest`, `fmtE`,
  `fmtF`, `fmtB`, `fmtX`. Skips `ryuFtoaShortest`/`ryuFtoaFixed*`
  optimizations — `bigFtoa` (the slow path through `decimal.Shift` +
  `roundShortest`) produces identical output.
- `src/types.rs` adds `pub type float32 = f32; pub type float64 = f64;`.
- `src/strconv/mod.rs` exposes `ParseFloat`, `FormatFloat`, `AppendFloat`.
- `src/fmt/mod.rs` adds `%f`, `%g`, `%G`, `%e`, `%E` verbs (calls
  `FormatFloat`).

**Verbs supported**: `'b'`, `'e'`, `'E'`, `'f'`, `'g'`, `'G'`, `'x'`, `'X'`.
Same set Go ships.

**Public API verbatim from Go:**

```rust
pub fn ParseFloat<S: Into<string>>(s: S, bit_size: int) -> (float64, error);
pub fn FormatFloat(f: float64, fmt: byte, prec: int, bit_size: int) -> string;
pub fn AppendFloat(dst: slice<byte>, f: float64, fmt: byte, prec: int, bit_size: int) -> slice<byte>;
```

`fmt::Format` for `f64`/`f32` so `Println!`/`Sprintf!`/`Printf!` work
with `%v`/`%f`/`%g`/`%e`. `%v` uses `'g'` with `prec=-1` (shortest).

## Deferred to later milestones

- **M11b-B** — Port `ftoaryu.go` for fast shortest-round-trip. Replaces
  `bigFtoa` for the prec=-1 path. ~570 LOC.
- **M11b-C** — Port `eisel_lemire.go` for fast ParseFloat path. ~880 LOC.

Each later phase is a transparent perf upgrade — public API stays
identical, smoke tests stay green.

## v1 deviations from Go

**None at the algorithm level.** This is a verbatim port of the slow
paths. The only intentional differences:

- Code is in Rust syntax (struct fields, impl blocks, `&[u8]` instead
  of `[]byte`).
- `int` is `i64`-pinned (amd64-only); Go's `int` matches platform width.
  Doesn't affect float behavior.
- `f32` ParseFloat path internally widens to `f64` and narrows at the
  end — this is what Go does in `parseFloatPrefix` too (`float64(f)`).

Output for inputs in the test corpus should match `go run` byte-for-byte.

---

## Confirmation

Writing this out post-confirmation, since you said "ok". Implementation
follows immediately.
