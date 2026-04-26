# WIP example — `encoding/json`

A "json-pretty" CLI: reads JSON from stdin, parses to a `Value` tree,
re-encodes with indentation. Round-trip demo.

This file is **not compiled**. It's the design target for M-json.

---

## Go original

```go
package main

import (
    "encoding/json"
    "io"
    "os"
)

func main() {
    raw, _ := io.ReadAll(os.Stdin)
    var v any
    if err := json.Unmarshal(raw, &v); err != nil {
        os.Stderr.Write([]byte("parse: " + err.Error() + "\n"))
        os.Exit(1)
    }
    out, _ := json.MarshalIndent(v, "", "  ")
    os.Stdout.Write(out)
    os.Stdout.Write([]byte("\n"))
}
```

## Proposed goish (target shape)

```rust
#![no_std]
#![no_main]

use goish::{
    encoding::json, io::Writer as _, nil, os, Fprintln,
};

#[goish::main]
fn main() {
    let raw = read_all(os::Stdin());
    let (v, err) = json::Unmarshal(&raw);
    if err != nil {
        let mut e = os::Stderr();
        Fprintln!(e, "parse:", err);
        os::Exit(1);
    }
    let (out, _) = json::MarshalIndent(&v, "", "  ");
    let mut o = os::Stdout();
    o.Write(out);
    o.Write(goish::bytes(goish::string("\n")));
}

fn read_all<R: goish::io::Reader>(mut r: R) -> goish::slice<goish::byte> {
    use goish::{append, make};
    let mut out = make!([]goish::byte, 0, 1024);
    let mut buf = make!([]goish::byte, 4096);
    loop {
        let (n, err) = r.Read(&mut buf);
        if n > 0 {
            for i in 0..n { out = append!(out, buf[i]); }
        }
        if err != nil { break; }
    }
    out
}
```

Run:
```
$ printf '{"name":"alice","count":3,"tags":["go","rs"]}' | json-pretty
{
  "count": 3,
  "name": "alice",
  "tags": [
    "go",
    "rs"
  ]
}
```

(Note: object keys come out sorted because `map<K, V>` is BTreeMap-backed
in v1 — same trade-off documented in the map milestone.)

---

## Scope (this milestone)

### Public types

```rust
pub enum Value {
    Null,
    Bool(bool),
    Number(float64),
    String(string),
    Array(slice<Value>),
    Object(map<string, Value>),
}

impl Value {
    pub fn IsNull(&self) -> bool;
    pub fn AsBool(&self) -> Option<bool>;
    pub fn AsNumber(&self) -> Option<float64>;
    pub fn AsString(&self) -> Option<&string>;
    pub fn AsArray(&self) -> Option<&slice<Value>>;
    pub fn AsObject(&self) -> Option<&map<string, Value>>;
}
```

### Top-level functions

```rust
pub fn Marshal(v: &Value) -> (slice<byte>, error);
pub fn MarshalIndent(v: &Value, prefix: &str, indent: &str) -> (slice<byte>, error);
pub fn Unmarshal<S: AsRef<[byte]>>(data: S) -> (Value, error);
```

### Streaming

```rust
pub struct Encoder<W: io::Writer> { /* opaque */ }
pub fn NewEncoder<W: io::Writer>(w: W) -> Encoder<W>;
impl Encoder<W> {
    pub fn Encode(&mut self, v: &Value) -> error;
    pub fn SetIndent(&mut self, prefix: &str, indent: &str);
}

pub struct Decoder<R: io::Reader> { /* opaque */ }
pub fn NewDecoder<R: io::Reader>(r: R) -> Decoder<R>;
impl Decoder<R> {
    pub fn Decode(&mut self) -> (Value, error);
}
```

### User-implementable traits (escape hatch for typed values)

```rust
pub trait Marshaler {
    fn MarshalJSON(&self) -> (slice<byte>, error);
}
pub trait Unmarshaler {
    fn UnmarshalJSON(&mut self, data: &[byte]) -> error;
}
```

### Sentinels

```rust
pub fn ErrSyntax() -> error;          // "json: invalid syntax"
pub fn ErrUnexpectedEnd() -> error;   // truncated input
```

## v1 deviations from Go

- **No reflection-based Marshal/Unmarshal of arbitrary user structs.**
  Go uses `reflect` to walk struct fields and apply `json:"..."` tags.
  We don't have reflection. User types serialize via the `Marshaler`
  trait (Go has this too — it's the type-defined hook). Use the
  `Value` enum for arbitrary JSON.
- **No `json.Number` type.** Numbers are always `float64`. Go offers
  `Number` (string-backed) for high-precision integers; we defer it.
- **Object iteration is sorted.** Inherited from `map<K, V>`'s BTreeMap
  backing. JSON spec doesn't require ordering, but Go's standard
  Marshal sorts keys for `map[string]any` anyway — output matches.
- **`[]byte` ↔ base64** — Go encodes `[]byte` as base64 strings.
  Without struct-field reflection we don't have a way to know "this is
  a []byte field" vs "this is a Number array". User explicit via
  `Marshaler` if needed.

## Output & verification

Convergence: `json-pretty` round-trips well-formed JSON with sorted
object keys and 2-space indent.

`examples/json_smoke.rs` covers:
- Unmarshal: null, bool, number, string with escapes, array, object,
  nested, whitespace tolerance, error on truncation/syntax.
- Marshal: each type, escape-correct strings, sorted-key objects.
- MarshalIndent: indentation correctness, prefix application.
- Round-trip: parse → emit → parse → equal.
- Marshaler trait: a custom type that emits its own JSON.
