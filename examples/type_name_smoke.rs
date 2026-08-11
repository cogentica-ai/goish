// type_name_smoke — `%T` prints the concrete type name of a `goish::Any`
// (Go's `fmt.Sprintf("%T", v)` when v is interface{}). Validates
// goany::Any::TypeName + the fmt `%T` wiring. Best-effort Rust path name.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::goany::Any;
use goish::gostring::string;
use goish::{syscall};

// `#[goish::reflect]` because `Any::new` requires `Reflect`: every value
// that goes into goish's `interface{}` must be able to come back out as
// a `reflect::Value` (see goany.rs, "Reflection through the wrap"). A
// type that genuinely has none goes in through `Any::new_opaque`, and
// `%T` still names it — `TypeName` reads the vtable, not the reflection.
#[derive(PartialEq)]
#[goish::reflect]
struct Widget {
    id: i64,
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    // interface{} holding a string — %T must name the type, NOT print "hi".
    let a: Any = Any::new(string::from_static("hi"));
    let got = fmt::Sprintf!("%T", a.clone());
    fmt::Println!(string::from_static("string Any  %T => "), got.clone());
    if got == string::from_static("hi") {
        bad += 1; // regression: printed the value, not the type
    }
    if !goish::strings::Contains(got.clone(), "string") {
        bad += 1;
    }

    // interface{} holding a custom struct — %T names the struct.
    let w: Any = Any::new(Widget { id: 7 });
    let got2 = fmt::Sprintf!("%T", w.clone());
    fmt::Println!(string::from_static("Widget Any  %T => "), got2.clone());
    if !goish::strings::Contains(got2.clone(), "Widget") {
        bad += 1;
    }

    // interface{} holding an int.
    let n: Any = Any::new(42i64);
    let got3 = fmt::Sprintf!("%T", n.clone());
    fmt::Println!(string::from_static("i64 Any     %T => "), got3.clone());
    if !goish::strings::Contains(got3.clone(), "i64") {
        bad += 1;
    }

    // Sanity: %v on the same Any still formats the VALUE, not the type.
    let v = fmt::Sprintf!("%v", n.clone());
    fmt::Println!(string::from_static("i64 Any     %v => "), v.clone());
    if v != string::from_static("42") {
        bad += 1;
    }

    if bad == 0 {
        fmt::Println!(string::from_static("PASS: %T type-name recovery works"));
        syscall::Exit(0);
    } else {
        fmt::Println!(string::from_static("FAIL"));
        syscall::Exit(1);
    }
}
