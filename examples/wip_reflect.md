# WIP: goish::reflect — first slice

## Go reference

```go
type Person struct {
    Name string `json:"name" xml:"name,attr"`
    Age  int    `json:"age,omitempty"`
    secret int  // unexported, no tag
}

func main() {
    p := Person{"alice", 30, 0}
    t := reflect.TypeOf(p)

    fmt.Println(t.Name())        // "Person"
    fmt.Println(t.Kind())        // "struct"
    fmt.Println(t.NumField())    // 3

    f0 := t.Field(0)
    fmt.Println(f0.Name)              // "Name"
    fmt.Println(f0.Type.Kind())       // "string"
    fmt.Println(f0.Tag.Get("json"))   // "name"
    fmt.Println(f0.Tag.Get("xml"))    // "name,attr"

    f1 := t.Field(1)
    v, ok := f1.Tag.Lookup("json")
    fmt.Println(v, ok)                // "age,omitempty" true

    miss := f1.Tag.Get("missing")     // ""
}
```

## Goish target

```rust
#![no_std]
#![no_main]

use goish::{int, reflect, string};

#[goish::reflect]
pub struct Person {
    #[tag(r#"json:"name" xml:"name,attr""#)]
    Name: string,

    #[tag(r#"json:"age,omitempty""#)]
    Age: int,

    secret: int,
}

#[goish::main]
fn main() {
    let p = Person { Name: string("alice"), Age: 30, secret: 0 };
    let t = reflect::TypeOf(&p);

    assert!(t.Name() == "Person");
    assert!(t.Kind() == reflect::Kind::Struct);
    assert!(t.NumField() == 3);

    let f0 = t.Field(0);
    assert!(f0.Name == "Name");
    assert!((f0.Type)().Kind() == reflect::Kind::String);
    assert!(f0.Tag.Get("json") == "name");
    assert!(f0.Tag.Get("xml")  == "name,attr");

    let f1 = t.Field(1);
    let (v, ok) = f1.Tag.Lookup("json");
    assert!(v == "age,omitempty" && ok);
    assert!(f1.Tag.Get("missing") == "");
}
```

## API surface (first slice)

```rust
pub mod reflect {
    pub enum Kind {
        Invalid, Bool,
        Int, Int8, Int16, Int32,            // Int = i64 (= goish int)
        Uint, Uint8, Uint16, Uint32,        // Uint = u64 (= goish uint)
        Float32, Float64,
        String,
        Slice, Map, Struct, Pointer,        // composite kinds — slot only for now
    }

    pub trait Reflect {
        fn __reflect_type() -> Type;
    }

    pub struct StructTag(/* &'static str */);
    impl StructTag {
        pub fn Get(&self, key: &str) -> string;
        pub fn Lookup(&self, key: &str) -> (string, bool);
    }

    pub struct StructField {
        pub Name: &'static str,
        pub Tag:  StructTag,
        pub Type: fn() -> Type,             // late-bound to break recursion
    }

    pub struct Type { /* opaque */ }
    impl Type {
        pub fn Name(&self) -> &'static str;
        pub fn Kind(&self) -> Kind;
        pub fn NumField(&self) -> int;      // 0 for non-struct
        pub fn Field(&self, i: int) -> StructField;
        pub fn FieldByName(&self, name: &str) -> (StructField, bool);
    }

    pub fn TypeOf<T: Reflect + ?Sized>(_: &T) -> Type;
}
```

## Deferred (next iterations)

- `reflect::Value` — actual value introspection (Field, Index, MapIndex)
- Generic `Reflect` for `slice<T>`, `map<K,V>`, `*T`
- `Reflect` derived recursively from struct field types (currently we just record the field's `Type` as a fn pointer)
- json::Marshal integration via reflect (tag-driven encoding)
- DeepEqual

## v1 deviations from Go

- `int = i64` so `Kind::Int` covers i64; no separate `Kind::Int64`.
- Same for `uint = u64` → `Kind::Uint`. Document.
- `f0.Type` is a `fn() -> Type` (late binding via fn pointer), called as `(f0.Type)()`. Go's `f.Type` is a `reflect.Type` interface value — lazy via the call shape.
- `Reflect` is an opt-in trait. Convention: every goish-defined struct gets `#[goish::reflect]`. Built-in primitives have it baked in.
