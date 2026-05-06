# Chapter 10: Interfaces and Reflection

One of the most powerful features of Go is its ability to inspect types at runtime. In **Goish**, we achieve this through a combination of procedural macros and a sophisticated `reflect` package.

## 10.1 Compile-time Reflection via Proc-Macros

Because Rust is a statically typed language, we cannot "discover" struct fields at runtime without help from the compiler. Goish uses the `#[goish::reflect]` macro to generate static type descriptors.

```rust
#[goish::reflect]
pub struct Person {
    pub Name: string,
    pub Age:  int,
}
```

When you add this attribute, the macro emits a `Reflect` trait implementation that contains a complete map of every field, its name, its type, and its **Struct Tags**.

## 10.2 The `reflect` Package

The `reflect` package (`src/reflect/mod.rs`) provides the user-facing API for introspection.

### `reflect.TypeOf` and `reflect.ValueOf`
Just like Go, you can get a descriptor of any variable:

```rust
let p = Person { Name: string("Alice"), Age: 30 };
let t = reflect::TypeOf(&p);
let v = reflect::ValueOf(&p);

fmt::Println!(t.Name()); // Prints "Person"
fmt::Println!(t.NumField()); // Prints 2
```

### Struct Tags
Goish supports Go-style struct tags, which are essential for JSON and XML serialization:

```rust
#[goish::reflect]
pub struct User {
    #[tag(json="user_name")]
    pub Name: string,
}

let t = reflect::TypeOf(&User::default());
let field = t.Field(0);
let json_name = field.Tag.Get("json"); // "user_name"
```

## 10.3 Dynamic Mutation: `SetField`

In standard Go, `reflect.Value.Set()` allows you to change a value dynamically. In Goish, we must do this safely while respecting Rust's borrow checker. 

Goish provides `reflect::SetField(&mut obj, index, value)`, which uses the macro-generated dispatch table to safely write to fields by index without using raw pointer arithmetic.

*   **Goish vs. Go**: Go's reflection is "built-in" and can bypass some safety checks. Goish's reflection is a pure-Rust library implementation that uses macros to "bake in" the type information at compile time, making it significantly faster and safer.
*   **Goish vs. Rust**: Rust's standard reflection (`Any`) is limited to simple type ID checks. Goish provides a full structural reflection system similar to `serde`, but with the familiar, dynamic API of the Go language.

---

# Chapter 11: The Standard Library

Goish aims to provide a "batteries-included" experience for systems programmers.

### 11.1 Raw Syscalls
Everything in Goish is built on the `syscall` package. It uses the `asm!` macro to talk directly to the Linux kernel. No C library is ever involved.

### 11.2 Buffered I/O
The `bufio` package provides efficient, buffered reading and writing, perfect for parsing protocols like HTTP. It implements the same `Scanner` and `Writer` idioms found in Go.

### 11.3 The `fmt` Package
The `fmt` package is the crown jewel of the Goish standard library. It uses the **Reflection** system we discussed in Chapter 10 to provide a powerful, type-safe `Println!` and `Printf!` implementation.

Unlike Rust's `println!`, which is a built-in compiler macro, Goish's `fmt::Println!` is a library-level macro that uses runtime reflection to format your structs, slices, and maps automatically.

---

## Conclusion: The Goish Journey

By building Goish from the ground up—starting with raw assembly, moving through the G-M-P scheduler, the epoll Netpoller, and finally the high-level reflection system—we have bridged the gap between the power of Rust and the simplicity of Go.

We hope this documentation has given you a deep understanding of how modern runtimes are designed and implemented. Happy Hacking!
