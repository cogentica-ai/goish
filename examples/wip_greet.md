# WIP example — `greet` CLI

A small CLI that reads names from `os.Args[1:]`, validates each, prints
a greeting per name, sends errors to stderr. Picked because it's small
and exercises everything in milestones M6–M9 simultaneously.

This file is **not compiled**. It's a target shape for goish syntax once
the named milestones land.

---

## Go original

```go
package main

import (
    "errors"
    "fmt"
    "os"
    "strings"
)

func greet(name string) (string, error) {
    if name == "" {
        return "", errors.New("name cannot be empty")
    }
    return fmt.Sprintf("Hello, %s!", strings.ToUpper(name)), nil
}

func main() {
    args := os.Args[1:]
    if len(args) == 0 {
        fmt.Fprintln(os.Stderr, "usage: greet NAME...")
        os.Exit(1)
    }
    for i, name := range args {
        msg, err := greet(name)
        if err != nil {
            fmt.Fprintf(os.Stderr, "arg %d: %v\n", i, err)
            continue
        }
        fmt.Println(msg)
    }
}
```

## Proposed goish v1 (target shape)

```rust
#![no_std]
#![no_main]

use goish::{string, slice, range, len, range};
use goish::{errors, fmt, os, strings};

fn greet(name: string) -> (string, error) {
    if name == "" {
        return ("".into(), errors::New("name cannot be empty"));
    }
    (fmt::Sprintf!("Hello, %s!", strings::ToUpper(name)), nil)
}

#[goish::main]
fn main() {
    let args = os::Args().slice(1, len(&os::Args()));     // os.Args[1:]
    if len(&args) == 0 {
        fmt::Fprintln!(os::Stderr(), "usage: greet NAME...");
        os::Exit(1);
    }
    for (i, name) in range!(args) {
        let (msg, err) = greet(name.clone());
        if err != nil {
            fmt::Fprintf!(os::Stderr(), "arg %d: %v\n", i, err);
            continue;
        }
        fmt::Println!(msg);
    }
}
```

---

## What's missing — the milestone hit-list

| Symbol | Milestone | Notes |
|--------|-----------|-------|
| `error` (type) | M9 | Trait with `Error() -> string`. Boxed as a sentinel-able value type. |
| `nil` (for error) | M9 | The *single* `nil`-equivalent we need this milestone is for `error`. Slice/map/chan nil land later. |
| `errors::New` | M9 | Returns boxed `error` carrying a string. |
| `fmt::Sprintf!`, `fmt::Println!`, `fmt::Printf!`, `fmt::Fprintln!`, `fmt::Fprintf!` | M8 | Macro shape from earlier plan. Verbs `%s %d %v` minimum for this example. |
| `fmt::Errorf!` (wraps with `%w`) | M8 | Future use; not needed for `greet` itself. |
| `os::Stdin/Stdout/Stderr` | M7 | Returns a `File` (wraps fd). Implements `io::Writer`. |
| `os::Args` | M7 | Returns `slice<string>`. Source: argv stashed during `__goish_rt0`. |
| `os::Exit(code)` | M7 | Already exists at `syscall::Exit`; re-export under `os`. |
| `strings::ToUpper` | M10 | Acceptable to defer if we make the example skip it. |
| `io::Writer` trait | M6 | Backing for `fmt::Fprintf`. |

---

## Design questions raised

### 1. How does `error` work?

Go: `type error interface { Error() string }` — minimal interface, satisfied by anything with an `Error()` method. `nil` is the zero value; comparison is `if err != nil`.

**Options for goish:**

A. **Trait + nil sentinel via `Option`-like wrapper** (uses Rust's algebraic types). Public type: `pub type error = Option<Box<dyn ErrorTrait>>`. `nil` becomes `None`. Reads OK in code:
```rust
let err: error = errors::New("bad");
if err != nil { ... }
```
But `nil` is a goish-defined `pub const nil: error = None` or similar.

B. **Custom type** with internal `Option<Box<dyn>>` and explicit `is_nil()` / `nil()` constructor. Less Go-natural — `if err != nil` becomes `if !err.is_nil()` or similar.

C. **Wrap Rust's `Result`** — change function signatures to `Result<T, error>`. Definitely *not* Go-shaped; rejected.

**Lean:** A. The `if err != nil` pattern is iconic Go; preserving it is worth the small machinery.

### 2. Multi-return for errors

Go: `(string, error)`. We have tuples — already works:
```rust
fn greet(name: string) -> (string, error) { ... }
let (msg, err) = greet(name);
```
Already idiomatic Rust + reads as Go. **Decision: keep tuple form, no special syntax needed.**

### 3. fmt's `any` / `interface{}` boxing

Go's `fmt.Printf("%d %s", n, name)` works because `n` and `name` both implement the empty interface. Rust has no empty interface. Two paths:

A. **Trait-object slice via macro**: `Printf!("%d %s", n, name)` expands to a slice of `&dyn Format`. The `Format` trait is implemented for `int`, `byte`, `rune`, `string`, `slice<T>`, and `error`. User can `impl Format for MyType` to extend. (Mirrors v0.)

B. **Per-arg generic dispatch in macro**: each macro arg is wrapped in a `__fmt_arg!` autoref-spec helper that picks the right `Format` impl at compile time. Needed if we want `%v` to do something type-aware without a master trait.

**Lean:** A — simpler, matches Go's mental model. Closed set of types makes coverage explicit.

### 4. `os.Args[1:]` slicing

Go's `args[1:]` on a `[]string` is a *view* into the parent. Our `slice<T>::slice(low, high)` *copies* (the documented v1 deviation).

Cost: every `os.Args[1:]` allocates a new slice. For a CLI's argv this is trivial — N strings, where N is typically <100. Real cost only matters if someone subslices megabyte buffers; not the common path.

**Decision:** stay with copy semantics. Document on the `os.Args` doc that `os.Args.slice(1, len(os.Args))` is the idiom.

Also — do we want the macro `slice![ args, 1, : ]` for slicing? Or just `args.slice(low, high)` method? The user wrote `xs.slice(low, high)` in M3b; let's keep that. A `slice!` literal is for *constructing*; subslicing stays a method.

Could add a subslice macro later: `subslice!(xs, 1, len(&xs))` → `xs.slice(1, len(&xs))`. Or even Go-shaped: `xs[1:]` via `Index<Range>` impl — Rust `Range`s could be made to fit. But this is sugar; defer.

### 5. `strings::ToUpper`

Whole `strings` package is M10. For *this* example, two options:
- Inline: skip the ToUpper and just use the name as-is. Smaller scope.
- Keep: defer compilation until M10 also lands.

**Decision:** keep `strings::ToUpper` to surface the `strings` package as a needed milestone. The example as written compiles on M6+M7+M8+M9+M10.

### 6. Implicit string-literal `into()`

`return ("".into(), ...)` is Rust-y. Goish-faithful would let us write `""` and have it auto-coerce. Options:

A. Allow `&'static str` to *be* a `string` for return-position via a generic return type. Tricky in Rust.

B. Add a constructor sugar: write `s!("")` or `string!("")` — short macro. Or `s("")`. We already have `string("")` (the conversion function), so `return ("".into(), ...)` could be `return (string(""), ...)`. Slightly more typing, all-Go-shaped.

**Decision:** use `string("")` everywhere; drop the `.into()`.

### 7. `os::Args()` — function or static?

Go: `os.Args` is a `var` (read-only after init). In Rust, exposing it as a `static` is cleanest, but mutable static-init is a footgun. Two paths:

A. `os::Args() -> slice<string>` — function, computes from a `OnceCell` on first call. Clones each invocation (cheap — strings are Arc-backed). This is what the proposed code shows.

B. `os::Args` as a `OnceCell<slice<string>>`. User writes `&*os::Args` or similar — leaks Rust idiom.

**Lean:** A. Reads almost like Go's variable access; the parens are the only difference.

---

## What this implies for milestone ordering

Looking at this example: M6 → M7 → M8 → M9 → (M10) is the *experiential* unblock for "Go programs that look like Go". Every cell of v1 stdlib that lives in the example pulls in another milestone.

Suggested merge order:
1. **M9 errors** first (smallest; ~80 LOC for trait + New + Is + As + nil sentinel).
2. **M6 io** — Reader/Writer traits, Copy, EOF.
3. **M7 os** — depends on M6 for File implementing Writer.
4. **M8 fmt** — depends on M6 (Writer) and M9 (error for return values + %w).
5. **M10 strings** — small once M3 lands; could land in parallel with M8.

This is the order to flip the example from "WIP" to "compiles + runs".
