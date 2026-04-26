# WIP example — M10 `strings` package

A "tag normalizer" CLI: splits a comma-separated input, trims each
field, lowercases, strips a leading `#`, drops empties, and joins the
result. Picked because it exercises the most-used `strings` functions
in one tight loop:

- `strings.Split(s, sep)` → `[]string`
- `strings.TrimSpace(s)` → `string`
- `strings.ToLower(s)` → `string`
- `strings.TrimPrefix(s, prefix)` → `string`
- `strings.Builder` (`WriteString`, `Len`, `String`)
- `strings.Join(elems, sep)` → `string` *(alternative path)*

This file is **not compiled**. It's the design target for M10.

---

## Go original

```go
package main

import (
    "fmt"
    "strings"
)

func normalize(input string) string {
    parts := strings.Split(input, ",")

    var out strings.Builder
    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p == "" {
            continue
        }
        p = strings.ToLower(p)
        p = strings.TrimPrefix(p, "#")

        if out.Len() > 0 {
            out.WriteString(", ")
        }
        out.WriteString(p)
    }
    return out.String()
}

func main() {
    input := "Hello,  WORLD , #goish, , Rust"
    fmt.Println(normalize(input))
    // Output: hello, world, goish, rust
}
```

## Proposed goish v1 (target shape)

```rust
#![no_std]
#![no_main]

use goish::{range, string, Println};
use goish::strings;

fn normalize(input: string) -> string {
    let parts = strings::Split(input, string(","));

    let mut out = strings::Builder::new();
    for (_, p) in range!(parts) {
        let p = strings::TrimSpace(p.clone());
        if p == "" {
            continue;
        }
        let p = strings::ToLower(p);
        let p = strings::TrimPrefix(p, string("#"));

        if out.Len() > 0 {
            out.WriteString(string(", "));
        }
        out.WriteString(p);
    }
    out.String()
}

#[goish::main]
fn main() {
    let input = string("Hello,  WORLD , #goish, , Rust");
    Println!(normalize(input));
}
```

---

## What this needs from M10

### Core public functions

| Go signature | goish proposed |
|--------------|----------------|
| `Split(s, sep string) []string` | `pub fn Split(s: string, sep: string) -> slice<string>` |
| `Join(elems []string, sep string) string` | `pub fn Join(elems: slice<string>, sep: string) -> string` |
| `Contains(s, substr string) bool` | `pub fn Contains(s: string, substr: string) -> bool` |
| `HasPrefix(s, prefix string) bool` | identical |
| `HasSuffix(s, suffix string) bool` | identical |
| `Index(s, substr string) int` | `pub fn Index(s: string, substr: string) -> int` |
| `IndexByte(s string, c byte) int` | identical |
| `IndexRune(s string, r rune) int` | identical |
| `LastIndex(s, substr string) int` | identical |
| `TrimSpace(s string) string` | identical |
| `Trim(s, cutset string) string` | identical |
| `TrimLeft / TrimRight` | identical |
| `TrimPrefix(s, prefix string) string` | identical |
| `TrimSuffix(s, suffix string) string` | identical |
| `ToUpper(s string) string` | identical |
| `ToLower(s string) string` | identical |
| `Replace(s, old, new string, n int) string` | identical |
| `ReplaceAll(s, old, new string) string` | identical |
| `Repeat(s string, count int) string` | identical |
| `Count(s, substr string) int` | identical |
| `EqualFold(s, t string) bool` | identical |

Skip for M10 launch (defer):
- `Map`, `IndexFunc`, `FieldsFunc`, `TrimFunc` — need first-class function values; user closures are M14+ territory once we have `Box<dyn Fn>` story.
- `ToUpperSpecial / ToLowerSpecial / Title` — need full `unicode` package (we only have `unicode/utf8`).
- `Cut`, `CutPrefix`, `CutSuffix` (Go 1.18+) — small, can add easily; flag for inclusion.

### Builder type

```rust
pub struct Builder {
    buf: slice<byte>,
}

impl Builder {
    pub fn new() -> Self;
    pub fn Len(&self) -> int;
    pub fn Cap(&self) -> int;
    pub fn Grow(&mut self, n: int);
    pub fn Reset(&mut self);
    pub fn String(self) -> string;             // consumes — see Q1
    pub fn WriteString(&mut self, s: string) -> (int, error);
    pub fn WriteByte(&mut self, b: byte) -> error;
    pub fn WriteRune(&mut self, r: rune) -> (int, error);
}
impl io::Writer for Builder { ... }
```

### Implementation notes

- **ToUpper / ToLower**: ASCII-only for M10. Full Unicode case mapping
  needs `unicode.ToUpper(rune) rune` + tables; defer to a later
  unicode-package milestone. Document this in goish docs as a v1 limit.
- **Builder.String()**: consume vs. clone? Go's Builder.String is a
  read-without-consume that exposes the internal buffer (because Go
  strings + slices share backing). We don't share backing — see Q1.
- **All splits/trims are byte-based** by default, matching Go (which
  treats UTF-8 as bytes for cutsets etc.).
- **Performance**: naive O(n*m) for Index/Contains. Boyer-Moore is
  Go's later optimization (≥ 13 bytes); skip for M10.

---

## Design questions

### Q1. `Builder.String()` — consume or clone?

Go's `Builder.String()` doesn't copy: it returns the internal buffer
*as* a string (allowed because Go's `string` and `[]byte` share backing
when constructed this way via `unsafe.String`). Subsequent `Write` calls
to a Builder after a call to `String()` would race; Go's docs say "do
not copy a non-zero Builder" but there's no compile-time enforcement.

**Options for goish:**

**A. `Builder::String(self) -> string` — consume.** Take ownership of
the buffer, hand it to a `string`. Subsequent uses of the Builder are
compile-errored. Most Rust-correct. Idiomatic call:
```rust
let s = out.String();   // out is consumed
```

**B. `Builder::String(&self) -> string` — clone.** Each call allocates
a fresh string by copying the buffer. Matches Go's "you can call
String() multiple times" semantic. Cost: O(n) per call.
```rust
let s1 = out.String();
let s2 = out.String();   // works, allocates again
```

**C. `Builder::Build(self) -> string`** plus **`String(&self) -> string`** —
both. `Build` consumes (zero-copy via `Arc::from(Vec)`); `String` clones.

**Lean: A.** Consume is the cleaner Rust shape and the idiomatic Go
pattern for Builder is "build then call String once at end". Trade-off:
small breakage from Go's free-call semantic. Doc note suffices.

### Q2. Subslicing inside strings.Split

`Split("a,b,c", ",")` walks the input, finding `,` separators, and
returns each segment as its own `string`. In Go, each segment shares
the original backing (`s[i:j]`); in goish, our string backing is
`Arc<[u8]>` so we *could* do something similar.

**Options:**

**A. Each segment is a fresh `string::from_bytes(&original[i..j])`** —
allocates per segment. Simple, matches our slice-on-copy semantic.

**B. Each segment shares the original `Arc<[u8]>` with an `(offset, len)`
window.** Faster for many splits, no extra allocs. Requires extending
`string` to carry an optional `(offset, len)` pair. Slight type-layout
churn.

**Lean: A.** Splits typically don't exceed ~10s of segments in idiomatic
code. Premature optimization to add windowing now. Revisit if profiling
shows allocator pressure.

### Q3. ASCII-only ToUpper/ToLower for M10

Go's `strings.ToUpper("café")` correctly upcases `é` → `É`. Goish v1
won't have unicode case tables until a later milestone.

**Options:**

A. **ASCII-only**, document the limit clearly. `ToUpper("café") = "CAFé"`.
B. **Defer ToUpper/ToLower to the unicode milestone.** Don't ship them in M10.

**Lean: A.** `greet.rs` already wants `ToUpper`. Shipping ASCII-only
unblocks 95% of practical use. Doc note explains when full Unicode lands.

### Q4. `&str` literals as second argument

Many calls have `string` literals as the separator/prefix/cutset:
```rust
strings::Split(input, ",")          // would be nice — `","` is &'static str
strings::Split(input, string(","))  // explicit conversion, currently required
```

Letting `&'static str` flow into these arguments would shorten the call
sites significantly. Two paths:

A. Generic over a trait: `pub fn Split<S: __StringConv>(s: string, sep: S) -> slice<string>`.
   Internally calls `sep.__to_string()`. Cost: a clone-coerce per call.

B. Accept only `string`. Force the user to wrap: `string(",")`. More
   verbose but uniform.

**Lean: A.** Almost every separator arg in real code is a literal.
Saving the typing is worth one trait dispatch.

---

## Output & verification

Once M10 ships, the example should run as:

```
$ cargo run --example tags
hello, world, goish, rust
```

(The example file would be `examples/tags.rs` plus any negative tests
in `examples/strings_lib.rs`.)

---

## Confirm before implementing

Three answers needed:

1. **Q1 `Builder.String`**: consume only (A), clone (B), or both (C)?
2. **Q3 ASCII-only ToUpper**: ship A (ASCII) or defer (B)?
3. **Q4 generic `&str` literals**: A (generic) or B (uniform)?

My defaults: A / A / A. Once confirmed I'll implement M10 + `examples/tags.rs`.
