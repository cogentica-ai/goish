# WIP: reflect mutation + fmt %v via reflect

## #1: reflect mutation — what's possible without unsafe

### Go reference

```go
type Person struct { Name string; Age int }
p := Person{}
v := reflect.ValueOf(&p).Elem()      // addressable Value
v.FieldByName("Age").SetInt(99)       // mutates p.Age
v.FieldByName("Name").SetString("a")  // mutates p.Name
fmt.Println(p)                        // {a 99}
```

### Goish: option A — chained Value (Go-faithful, requires unsafe)

```rust
let mut p = Person { Name: string::new(), Age: 0, secret: 0 };
let v = reflect::ValueOf(&mut p);   // ValueRef carrying *mut Person + Type
v.FieldByName("Age").SetInt(99);
v.FieldByName("Name").SetString(string("alice"));
```

Implementation cost: per-field `offset_of!()` baked into StructField,
unsafe pointer arithmetic in the SetXxx accessors. Requires Rust 1.77.

### Goish: option B — free functions (safe, less Go-shape)

```rust
let mut p = Person { Name: string::new(), Age: 0, secret: 0 };

reflect::SetField(&mut p, 1, reflect::Value::Int(99));
reflect::SetFieldByName(&mut p, "Name", reflect::Value::String(string("alice")));
// p == Person { Name: "alice", Age: 99, secret: 0 }
```

Implementation: macro emits a per-struct fn-pointer setter table; no
unsafe. Less Go-shape syntactically (no Value chain), but the
mutation primitive is the same and existing `Tag.Get("json")`-style
metadata still applies.

### My recommendation: option B for v1

- Honors the goish priority "no unsafe-by-default"
- Reuses the `#[goish::reflect]` macro that already exists
- The chain syntax can be layered on later when we're ready to bump
  rust-version and add bounded unsafe for offset_of
- Most user code that wants mutation lands at "set field by name" or
  "set field by index" anyway — the chain is mostly aesthetic

---

## #2: fmt.%v via reflect — auto-print Reflect types

### Go reference

```go
type Person struct { Name string; Age int }
p := Person{Name: "alice", Age: 30}
fmt.Printf("%v\n",  p)   // {alice 30}
fmt.Printf("%+v\n", p)   // {Name:alice Age:30}
```

### Goish target

```rust
#[goish::reflect]
pub struct Person {
    Name: string,
    Age:  int,
}

let p = Person { Name: string("alice"), Age: 30 };
Printf!("%v\n",  &p);    // {alice 30}
Printf!("%+v\n", &p);    // {Name:alice Age:30}
```

For built-in Reflect types:

```rust
let xs = goish::slice!([]int{1, 2, 3});
Printf!("%v\n", &xs);    // [1 2 3]

let mut m = make!(map[string]int);
m.Set(string("a"), 1);
m.Set(string("b"), 2);
Printf!("%v\n", &m);     // map[a:1 b:2]      (sorted keys, BTreeMap order)
```

### Implementation sketch

1. The `#[goish::reflect]` macro additionally emits
   `impl fmt::Format for Person { fn fmt(&self, verb, f) { reflect_fmt(self, verb, f) } }`.

2. `fmt::reflect_fmt<T: Reflect>(v: &T, verb: byte, f: &mut FmtBuf)`
   walks `reflect::ValueOf(v)` and emits per-Kind output.

3. Per-Kind defaults match Go's fmt.go:
   - `Bool`         → `true` / `false`
   - `Int*`/`Uint*` → decimal
   - `Float*`       → shortest round-trip
   - `String`       → unquoted (matches `%v`, not `%q`)
   - `Slice`        → `[v1 v2 v3]` (space-separated)
   - `Map`          → `map[k1:v1 k2:v2]` (sorted, space-separated)
   - `Struct`       → `{v1 v2 v3}`  (or `{F1:v1 F2:v2}` for `%+v`)
   - `Pointer`      → recurse into target
   - `Invalid`      → `<nil>`

4. `%+v` flag detection: extend the verb scanner to capture `+`. The
   reflect printer reads it and switches struct layout to
   `{Name:val ...}`.

### Coherence check

The existing `impl<T: Stringer> Format for T` blanket only applies to
types that impl `Stringer`. `#[goish::reflect]` structs typically don't
impl `Stringer`, so the macro can freely emit `impl Format` without
conflict. (If a user wants both — Stringer for `%s` AND reflect-based
`%v` — they'd write Stringer manually and `%v` would use Stringer's
output. We can revisit if it bites in practice.)

---

## Order of work

Do #2 first — smaller, self-contained, no design tension. Then #1
option B, which builds on the macro's existing field walk.
