# WIP example — M13 `bytes` package

Mirror of M10 `strings` over byte slices. Same shape, same call sites,
just `slice<byte>` in/out instead of `string`.

A "bytestack" CLI: reads lines from stdin, splits each by a separator
from `os.Args[1]`, trims and uppercases each field, prints them as a
bullet list. Picked because it demos the parallel-with-strings shape
*and* composes with M12.5 bufio Scanner.

This file is **not compiled**. It's the design target for M13.

---

## Go original

```go
package main

import (
    "bufio"
    "bytes"
    "fmt"
    "os"
)

func main() {
    if len(os.Args) != 2 {
        fmt.Fprintln(os.Stderr, "usage: bytestack SEP")
        os.Exit(1)
    }
    sep := []byte(os.Args[1])

    sc := bufio.NewScanner(os.Stdin)
    for sc.Scan() {
        for _, field := range bytes.Split(sc.Bytes(), sep) {
            field = bytes.TrimSpace(field)
            if len(field) == 0 {
                continue
            }
            field = bytes.ToUpper(field)
            fmt.Printf("  - %s\n", field)
        }
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

use goish::{bufio, bytes, len, nil, os, range, Fprintln, Printf};

#[goish::main]
fn main() {
    let all = os::Args();
    if len(&all) != 2 {
        let mut e = os::Stderr();
        Fprintln!(e, "usage: bytestack SEP");
        os::Exit(1);
    }
    let sep = goish::bytes(all[1].clone());     // string → slice<byte>

    let mut sc = bufio::NewScanner(os::Stdin());
    while sc.Scan() {
        let line = sc.Bytes();
        for (_, field) in range!(bytes::Split(line, sep.clone())) {
            let field = bytes::TrimSpace(field.clone());
            if len(&field) == 0 {
                continue;
            }
            let field = bytes::ToUpper(field);
            Printf!("  - %s\n", goish::string(field));
        }
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
$ printf 'apple,banana, cherry\n  date,fig\n' | bytestack ,
  - APPLE
  - BANANA
  - CHERRY
  - DATE
  - FIG
```

---

## What this needs from M13

### Public functions (Go signatures, mirrored)

| Go | goish |
|---|---|
| `Equal(a, b []byte) bool` | `pub fn Equal<S1, S2>(a: S1, b: S2) -> bool` |
| `Compare(a, b []byte) int` | identical |
| `Count(s, sep []byte) int` | identical |
| `Contains(b, sub []byte) bool` | identical |
| `ContainsRune(b []byte, r rune) bool` | identical |
| `HasPrefix(s, prefix []byte) bool` | identical |
| `HasSuffix(s, suffix []byte) bool` | identical |
| `Index(s, sep []byte) int` | identical |
| `IndexByte(s []byte, c byte) int` | identical |
| `IndexRune(s []byte, r rune) int` | identical |
| `LastIndex(s, sep []byte) int` | identical |
| `LastIndexByte(s []byte, c byte) int` | identical |
| `TrimSpace(s []byte) []byte` | `pub fn TrimSpace<S>(s: S) -> slice<byte>` |
| `Trim/TrimLeft/TrimRight(s []byte, cutset string) []byte` | byte-set semantics like strings |
| `TrimPrefix/TrimSuffix(s, p []byte) []byte` | mirror |
| `ToUpper(s []byte) []byte` | ASCII-only for v1, mirroring strings |
| `ToLower(s []byte) []byte` | ASCII-only for v1 |
| `Replace(s, old, new []byte, n int) []byte` | mirror |
| `ReplaceAll(s, old, new []byte) []byte` | mirror |
| `Repeat(b []byte, count int) []byte` | mirror |
| `Split(s, sep []byte) [][]byte` | `pub fn Split<S1, S2>(s: S1, sep: S2) -> slice<slice<byte>>` |
| `SplitN(s, sep []byte, n int) [][]byte` | mirror |
| `Join(s [][]byte, sep []byte) []byte` | mirror |
| `EqualFold(s, t []byte) bool` | ASCII-only, mirror |
| `Clone(b []byte) []byte` | identical |

All input-byte-slice arguments take `S: Into<slice<byte>>` so byte
literals (`b","`) flow via two new `From` impls (see below).

### Concrete types

```rust
pub struct Buffer { /* opaque: Vec<byte> + read offset */ }
pub fn NewBuffer(buf: slice<byte>) -> Buffer;
pub fn NewBufferString<S: Into<string>>(s: S) -> Buffer;

impl Buffer {
    pub fn Bytes(&self) -> slice<byte>;
    pub fn String(&self) -> string;
    pub fn Len(&self) -> int;
    pub fn Cap(&self) -> int;
    pub fn Reset(&mut self);
    pub fn Grow(&mut self, n: int);
    pub fn Write(&mut self, p: slice<byte>) -> (int, error);
    pub fn WriteString<S: Into<string>>(&mut self, s: S) -> (int, error);
    pub fn WriteByte(&mut self, c: byte) -> error;
    pub fn WriteRune(&mut self, r: rune) -> (int, error);
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error);
}
impl io::Reader for Buffer { ... }
impl io::Writer for Buffer { ... }

pub struct Reader { /* opaque: slice<byte> + read offset */ }
pub fn NewReader(b: slice<byte>) -> Reader;

impl Reader {
    pub fn Len(&self) -> int;
    pub fn Size(&self) -> int;          // i64 in Go; int=i64 here
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error);
    pub fn Reset(&mut self, b: slice<byte>);
}
impl io::Reader for Reader { ... }
```

### v1 deviations from Go

- **`Buffer.Bytes()` / `Buffer.String()` clone.** Go returns a view into
  the unread portion of the internal buffer (invalidated by next
  Write/Read/Reset). Goish slices/strings are owning, so we clone.
  Slightly more allocation, never invalidated.
- **`ToUpper` / `ToLower` / `EqualFold` ASCII-only**, matching M10
  strings. Bytes ≥ 0x80 pass through unchanged.
- **No `Map`, `IndexFunc`, `FieldsFunc`, `TrimFunc`, `Fields`** — mirror
  the strings deferral list.
- **No `IndexAny`, `LastIndexAny`, `ContainsAny`** — Go takes a `string`
  charset there; defer to keep the surface byte-only.
- **No `Title`, `ToTitle`, `*Special`, `ToValidUTF8`** — need full
  unicode tables.
- **No `Cut/CutPrefix/CutSuffix`** — mirror the strings deferral.
- **`bytes.Reader` skips `Seek`/`ReadAt`/`ReadByte`/`ReadRune`** — only
  the `io.Reader` interface and `Len`/`Size`/`Reset`. Specialized
  scanner methods can come back when `Seeker` lands.

### New `From` impls on `slice<byte>` (in `src/goslice.rs`)

To let `b","` and `&[u8]` literals flow into bytes-package args
without `bytes(b",")` wrapping:

```rust
impl From<&'static [u8]> for slice<byte> { ... }
impl<const N: usize> From<&'static [u8; N]> for slice<byte> { ... }
```

So `bytes::Index(input, b",")` works the same way `strings::Index(s, ",")`
does today.

---

## Output & verification

Once M13 ships, the example runs as:

```
$ printf 'apple,banana, cherry\n  date,fig\n' | cargo run --example bytestack -- ,
  - APPLE
  - BANANA
  - CHERRY
  - DATE
  - FIG
```

`examples/bytes_lib_smoke.rs` will assert on every public function
across happy + edge cases (empty input, missing separator, CRLF
preservation, ASCII case, EqualFold), plus Buffer write→read round-trip
and Reader integration with bufio Scanner.
