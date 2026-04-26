# WIP example — M11a `strconv` package

A "sumargs" CLI: reads command-line args, parses each as int with
`strconv.Atoi`, prints the sum via `strconv.Itoa`. Failures print the
`NumError` to stderr with `Fprintf` and exit 1. Picked because it's the
shortest possible program that exercises the canonical Go shape:

- `strconv.Atoi(s) (int, error)` — happy + failure paths
- `strconv.Itoa(i) string`
- `NumError` — concrete public type, formatted via `%v`, walkable via
  `errors::Is(err, ErrSyntax())`

This file is **not compiled**. It's the design target for M11a.

---

## Go original

```go
package main

import (
    "fmt"
    "os"
    "strconv"
)

func main() {
    sum := 0
    for i, arg := range os.Args[1:] {
        n, err := strconv.Atoi(arg)
        if err != nil {
            fmt.Fprintf(os.Stderr, "arg %d: %v\n", i, err)
            os.Exit(1)
        }
        sum += n
    }
    fmt.Println("sum =", strconv.Itoa(sum))
}
```

## Proposed goish v1 (target shape)

```rust
#![no_std]
#![no_main]

use goish::{len, nil, os, range, strconv, string, Fprintf, Println};

#[goish::main]
fn main() {
    let all = os::Args();
    let args = all.slice(1, len(&all));

    let mut sum: int = 0;
    let mut errf = os::Stderr();
    for (i, arg) in range!(args) {
        let (n, err) = strconv::Atoi(arg.clone());
        if err != nil {
            Fprintf!(errf, "arg %d: %v\n", i, err);
            os::Exit(1);
        }
        sum += n;
    }
    Println!("sum =", strconv::Itoa(sum));
}
```

Run shape:
```
$ sumargs 1 2 3
sum = 6

$ sumargs 1 abc
arg 1: strconv.Atoi: parsing "abc": invalid syntax
(exit 1)
```

The `if err != nil { return / continue / Exit }` block is fully visible
at the call site — exactly the canonical pattern locked in earlier.

---

## What this needs from M11a

### Public functions (Go signatures)

| Go signature | goish proposed |
|--------------|----------------|
| `Atoi(s string) (int, error)` | `pub fn Atoi<S: Into<string>>(s: S) -> (int, error)` |
| `Itoa(i int) string` | `pub fn Itoa(i: int) -> string` |
| `ParseInt(s string, base int, bitSize int) (int64, error)` | `pub fn ParseInt<S: Into<string>>(s: S, base: int, bit_size: int) -> (int, error)` |
| `ParseUint(s string, base int, bitSize int) (uint64, error)` | `pub fn ParseUint<S: Into<string>>(s: S, base: int, bit_size: int) -> (uint, error)` |
| `FormatInt(i int64, base int) string` | `pub fn FormatInt(i: int, base: int) -> string` |
| `FormatUint(i uint64, base int) string` | `pub fn FormatUint(i: uint, base: int) -> string` |
| `AppendInt(dst []byte, i int64, base int) []byte` | `pub fn AppendInt(dst: slice<byte>, i: int, base: int) -> slice<byte>` |
| `AppendUint(dst []byte, i uint64, base int) []byte` | `pub fn AppendUint(dst: slice<byte>, i: uint, base: int) -> slice<byte>` |
| `ParseBool(str string) (bool, error)` | `pub fn ParseBool<S: Into<string>>(s: S) -> (bool, error)` |
| `FormatBool(b bool) string` | `pub fn FormatBool(b: bool) -> string` |
| `AppendBool(dst []byte, b bool) []byte` | `pub fn AppendBool(dst: slice<byte>, b: bool) -> slice<byte>` |

`int` is `int64`-pinned in v1 (amd64), so `ParseInt`'s return slot is
`int` directly. `IntSize = 64`.

### Concrete error type

```rust
pub struct NumError {
    pub Func: string,    // "Atoi", "ParseInt", ...
    pub Num: string,     // the offending input
    pub Err: error,      // ErrSyntax / ErrRange / "invalid base N"
}

impl errors::ErrorTrait for NumError {
    fn Error(&self) -> string { /* "strconv.Atoi: parsing \"abc\": invalid syntax" */ }
    fn Unwrap(&self) -> error { self.Err.clone() }
}
```

### Sentinels

```rust
pub fn ErrSyntax() -> error;   // "invalid syntax"
pub fn ErrRange() -> error;    // "value out of range"
```

Cached via `SpinLock<Option<error>>` (same pattern as `io::EOF`) — every
caller gets a clone of the same `Arc`, so `errors::Is(err, ErrSyntax())`
walks the chain via `NumError::Unwrap` and matches on Arc identity.

### Implementation notes

- **Base detection** (`base == 0`): handle `0b` / `0o` / `0x` prefixes
  and bare leading `0` for octal. Plus underscore separator (`1_000`)
  for `base == 0` only — port Go's `underscoreOK`.
- **Range clamping**: matches Go's "return the maximum magnitude
  integer of the appropriate bitSize and sign on overflow".
- **`bit_size` 0 == 64** for v1 (since `int = int64`). 8/16/32/64 honored
  via the same range-clamp logic.
- **`NumError.Error()` text** uses plain double-quotes around `Num`
  rather than `strconv.Quote(Num)`. Identical for ASCII inputs without
  escape characters; will upgrade once M11c (Quote) lands.
- **Use `wrapping_neg`** in the int↔uint sign flip to handle `i64::MIN`
  cleanly (Go's `-n` is two's-complement wrap; Rust panics in debug
  without `wrapping_*`).

### Defer to later milestones

- **Floats** (`ParseFloat`, `FormatFloat`, `AppendFloat`) — M11b. Ryu +
  Eisel-Lemire are ~3100 LOC of subtle algorithmic code; deserves its
  own session.
- **Quote / Unquote / IsPrint / IsGraphic** — M11c. Need unicode print
  tables (`isprint.go`, ~750 LOC).
- **Complex** (`ParseComplex`, `FormatComplex`) — no `complex` type yet.

---

## Output & verification

Once M11a ships, the example runs as:

```
$ cargo run --example sumargs -- 10 20 30
sum = 60

$ cargo run --example sumargs -- 1 abc
arg 1: strconv.Atoi: parsing "abc": invalid syntax
(exit 1)
```

Plus `examples/strconv_smoke.rs` covers: base 2/8/16/36, signed/unsigned
ranges, overflow clamping, bool round-trip, `errors::Is` chain walk to
the sentinels, and `Append*` building into a byte slice.

---

## Confirmed defaults (from earlier discussion)

- **Q1** `bit_size` parameter: **A** — keep verbatim Go signature.
- **Q2** `NumError`: **A** — public struct with `Func`/`Num`/`Err`.
- **Q3** `&str` literals as input: **A** — generic `S: Into<string>`.

Implementation lands directly on this design.
