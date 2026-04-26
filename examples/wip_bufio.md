# WIP example — M12.5 `bufio` Scanner

A line-by-line uppercaser: reads lines from stdin, ASCII-uppercases each
with `strings.ToUpper`, prints to stdout. Picked because it's the
shortest program that exercises the canonical Scanner shape:

- `bufio.NewScanner(io.Reader)`
- `scanner.Scan()` loop with `scanner.Text()` / `scanner.Err()`
- `ScanLines` (default split) — the most-used split function

This file is **not compiled**. It's the design target for M12.5.

---

## Go original

```go
package main

import (
    "bufio"
    "fmt"
    "os"
    "strings"
)

func main() {
    sc := bufio.NewScanner(os.Stdin)
    for sc.Scan() {
        fmt.Println(strings.ToUpper(sc.Text()))
    }
    if err := sc.Err(); err != nil {
        fmt.Fprintln(os.Stderr, "scan:", err)
        os.Exit(1)
    }
}
```

## Proposed goish v1 (target shape)

```rust
#![no_std]
#![no_main]

use goish::{bufio, nil, os, strings, Fprintln, Println};

#[goish::main]
fn main() {
    let mut sc = bufio::NewScanner(os::Stdin());
    while sc.Scan() {
        Println!(strings::ToUpper(sc.Text()));
    }
    let err = sc.Err();
    if err != nil {
        let mut e = os::Stderr();
        Fprintln!(e, "scan:", err);
        os::Exit(1);
    }
}
```

Run shape:
```
$ printf 'hello\nworld\n' | uppercase
HELLO
WORLD
```

---

## What this needs from M12.5

### Public types

```rust
pub struct Scanner<R: io::Reader> { /* opaque */ }

// Split function type — Option<slice<byte>> for the "nil vs empty" token
// distinction Go makes with []byte's nilability.
pub type SplitFunc =
    Box<dyn FnMut(&[byte], bool) -> (int, Option<slice<byte>>, error)>;
```

### Methods on `Scanner`

| Go signature | goish |
|---|---|
| `NewScanner(r io.Reader) *Scanner` | `pub fn NewScanner<R: io::Reader>(r: R) -> Scanner<R>` |
| `(s) Scan() bool` | `pub fn Scan(&mut self) -> bool` |
| `(s) Text() string` | `pub fn Text(&self) -> string` |
| `(s) Bytes() []byte` | `pub fn Bytes(&self) -> slice<byte>` (cloned — safe across Scan calls) |
| `(s) Err() error` | `pub fn Err(&self) -> error` (returns `nil` for `io.EOF`) |
| `(s) Buffer(buf []byte, max int)` | `pub fn Buffer(&mut self, buf: slice<byte>, max: int)` |
| `(s) Split(split SplitFunc)` | `pub fn Split<F>(&mut self, split: F)` where F: FnMut(...)+'static |

### Split functions (free functions)

```rust
pub fn ScanLines(data: &[byte], at_eof: bool) -> (int, Option<slice<byte>>, error);
pub fn ScanBytes(data: &[byte], at_eof: bool) -> (int, Option<slice<byte>>, error);
pub fn ScanRunes(data: &[byte], at_eof: bool) -> (int, Option<slice<byte>>, error);
pub fn ScanWords(data: &[byte], at_eof: bool) -> (int, Option<slice<byte>>, error);
```

### Sentinels

```rust
pub fn ErrTooLong() -> error;          // "bufio.Scanner: token too long"
pub fn ErrNegativeAdvance() -> error;
pub fn ErrAdvanceTooFar() -> error;
pub fn ErrBadReadCount() -> error;
```

Cached via `SpinLock<Option<error>>` (same pattern as `io::EOF`,
`strconv::ErrSyntax`).

### Constants

```rust
pub const MaxScanTokenSize: int = 64 * 1024;
```

### v1 deviations from Go

- **`Bytes()` clones.** Go returns the underlying buffer's slice (zero-copy
  but invalidated by next `Scan`). Goish slices have copy-on-subslice
  semantics, so we clone the token. Slightly more allocation, never
  invalidated. Document.
- **`Option<slice<byte>>` for the token return.** Go uses `[]byte` which
  can be `nil`. Goish slice<byte> has no nil. Option carries the
  distinction explicitly.
- **`ErrFinalToken` deferred.** Edge-case sentinel for early-stop with a
  trailing token. Most code doesn't use it. Add when there's demand.
- **No buffer-shrinking heuristic deviation.** Match Go: shift to start
  when buffer is half-empty; double until `MaxScanTokenSize`.

### Defer

- `bufio.Reader` / `bufio.Writer` (the buffered I/O wrappers in
  `bufio.go`, ~845 LOC) — separate milestone. Scanner alone covers the
  common line-reading need; the rest can wait.

---

## Output & verification

Once M12.5 ships, the example runs as:

```
$ printf 'hello\nworld\n' | cargo run --example uppercase
HELLO
WORLD
```

Plus `examples/bufio_smoke.rs` covers: ScanLines on empty input,
single-line, multi-line, trailing newline missing, CRLF stripping,
ScanWords splitting on whitespace, ScanBytes one-at-a-time, custom
split function via `s.Split(...)`, and `Err()` returning nil on EOF.
