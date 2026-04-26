# WIP: Reflect for nested #[goish::reflect] structs

## Goal

Today, a `#[goish::reflect]` struct can have primitive or slice fields,
but **not** another reflect struct as a field — `SetField` errors with
"reflect: type mismatch" when a value is `Value::Struct` because user
structs don't impl `FromReflectValue`. Marshal/Unmarshal already work
through `Reflect`/`FromValue` so the json path is fine, but mutation
and `%v` recursion through reflect needs the gap closed.

## Go reference

```go
type Address struct {
    Street string `json:"street"`
    Zip    int    `json:"zip"`
}

type User struct {
    Name string  `json:"name"`
    Home Address `json:"home"`
}

u := User{Name: "alice", Home: Address{Street: "Main", Zip: 123}}

// %v recursion
fmt.Printf("%+v\n", u)
// → {Name:alice Home:{Street:Main Zip:123}}

// reflect mutation through nested
v := reflect.ValueOf(&u).Elem()
v.FieldByName("Home").FieldByName("Zip").SetInt(456)

// json round-trip
b, _ := json.Marshal(u)
// → {"name":"alice","home":{"street":"Main","zip":123}}

var u2 User
json.Unmarshal(b, &u2)
// u2 == u
```

## Goish target

```rust
#[goish::reflect]
pub struct Address {
    #[tag(r#"json:"street""#)]  Street: string,
    #[tag(r#"json:"zip""#)]     Zip:    int,
}

#[goish::reflect]
pub struct User {
    #[tag(r#"json:"name""#)]    Name: string,
    #[tag(r#"json:"home""#)]    Home: Address,
}

let u = User {
    Name: string("alice"),
    Home: Address { Street: string("Main"), Zip: 123 },
};

// %v / %+v recursion
Sprintf!("%v",  &u);    // {alice {Main 123}}
Sprintf!("%+v", &u);    // {Name:alice Home:{Street:Main Zip:123}}

// SetField with a nested-struct payload
let new_home = Address { Street: string("Elm"), Zip: 999 };
reflect::SetFieldByName(&mut u, "Home", reflect::ValueOf(&new_home));
// u.Home == new_home

// SetField with a primitive Value into a nested field is NOT supported
// directly (would need the chain Value.Field(i).SetInt that requires
// addressable Value). Users either:
//   a) build a complete replacement struct and SetFieldByName the
//      whole field, OR
//   b) mutate u.Home directly via Rust, then read it back via reflect.
// The chain-based mutation lands when we add offset_of-based ValueRef.

// json round-trip through nested
let (b, _) = json::Marshal(&u);
// {"name":"alice","home":{"street":"Main","zip":123}}

let mut u2: User = User {
    Name: string::new(),
    Home: Address { Street: string::new(), Zip: 0 },
};
json::Unmarshal(&b.__into_vec(), &mut u2);
// reflect::DeepEqual(&u, &u2) == true
```

## What changes

The proc-macro already emits `Reflect` (so `__reflect_value` walks the
struct into `Value::Struct{ty, fields}`), `FromValue` (json
unmarshal), `Format` (fmt %v), and `Settable`. The remaining gap is
**`FromReflectValue`** — needed by `SetField` to accept a nested
struct payload.

The macro will additionally emit:

```rust
impl FromReflectValue for Address {
    fn from_reflect_value(v: Value) -> (Self, error) {
        match v {
            Value::Struct { fields, .. } => {
                if fields.len() != 2 {
                    return (zero(), errors::New("reflect: field count mismatch"));
                }
                // Extract each field by index.
                let (Street, err) = <string as FromReflectValue>::from_reflect_value(
                    fields[0].clone()
                );
                if err != nil { return (zero(), err); }
                let (Zip, err) = <int as FromReflectValue>::from_reflect_value(
                    fields[1].clone()
                );
                if err != nil { return (zero(), err); }
                (Address { Street, Zip }, nil)
            }
            _ => (zero(), errors::New("reflect: expected struct")),
        }
    }
}
```

`zero()` is a per-struct helper closure that builds a default-zero
Self via per-field `<FieldType as Default>::default()` — the same
pattern already used in the macro's `FromValue` impl. No `Self:
Default` bound needed.

## Smoke test

`examples/reflect_nested.rs`:

1. Define `Address` and `User` (User has Address field).
2. Construct `u` and Sprint `%v` / `%+v`, assert recursive output.
3. SetFieldByName "Home" with a fresh Address; assert mutation.
4. json Marshal → expected nested JSON.
5. json Unmarshal → DeepEqual round-trip with original.

Should be ~80 LOC, ~50 KiB release, 0 @GLIBC.
