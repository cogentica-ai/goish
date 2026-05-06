# Chapter 2: Primitive Types and Ownership

While Goish provides a syntax and standard library experience that feels like Go, under the hood, every variable, allocation, and function call is strictly governed by Rust's memory safety rules. This chapter explores how Goish represents fundamental data types and how it handles ownership at the lowest levels.

## 2.1 Integers, Floats, and Stack Allocation

Go defines a set of predeclared numeric types (`int`, `uint`, `byte`, `rune`, `float32`, `float64`). Goish implements these directly as type aliases over Rust's native primitives.

In `src/types.rs`, you will find:
```rust
pub type byte = u8;
pub type rune = i32;
pub type int = i64;
pub type uint = u64;
pub type float32 = f32;
pub type float64 = f64;
```

These are value types. When you declare an `int` variable in a function, it is allocated on the stack of the current Goroutine. When passed to another function, it is copied by value.

*   **Goish vs. Go**: In Goish v1, `int` is strictly aliased to `i64`. 
*   **Goish vs. Rust**: Goish pushes developers toward the Go-idiomatic `int` to maintain compatibility.

### Lab Exercise 2.1: Numeric Widths
1. Create a Goish program that prints the `size_of` for `int`, `rune`, and `byte`.
2. Compare this to standard Rust's `i64`, `i32`, and `u8`. 
3. Try to assign a `float64` to an `int` without an explicit conversion. Does the Goish compiler (Rust) allow this?

---

## 2.2 Strings: Immutable Sharing via `Arc<[u8]>`

Goish bridges the gap with its custom `string` type (`src/gostring.rs`):

```rust
#[derive(Clone)]
pub struct string {
    bytes: Arc<[u8]>,
}
```

*   **Goish vs. Go**: Goish uses **RAII** via `Arc`. The moment the last reference to a string is dropped, the memory is freed instantly.
*   **Goish vs. Rust**: Goish's `string` behaves like a garbage-collected string—it can be passed anywhere without lifetime annotations.

### Lab Exercise 2.2: String Immutability
1. Create a Goish string: `let s = string("hello")`.
2. Try to change the first byte: `s[0] = b'H'`.
3. Why does this fail at compile time? (Check the `Index` vs `IndexMut` trait implementations for `string`).

---

## 2.3 Borrowing vs. Copying in Goish

One of the hardest adjustments for readers moving from Garbage Collected languages to Systems languages is understanding exactly when data is copied and when it is shared.

In Goish, we must respect Rust's strict ownership rules:
-   **Primitives** implement the `Copy` trait. They behave exactly like Go.
-   **Composite Goish Types** (`string`, `slice<T>`) implement the `Clone` trait but **do not** implement `Copy`. 

### Lab Exercise 2.3: The Move Semantic Trap
1. Write a function `func consume(s string) { fmt::Println(s); }`.
2. In `main`, create a string `s` and call `consume(s)` twice.
3. Observe the Rust compiler error. How do you fix this using `.clone()`?

---

## 2.4 The "Zero Value" Concept and `Default`

Goish relies heavily on Rust's `Default` trait to mirror Go's implicit initialization.

### Lab Exercise 2.4: Explicit Defaults
1. Declare a variable `let mut s: string;` without initializing it and try to print it.
2. Now initialize it using `string::default()`. 
3. How does this compare to Go's `var s string`?

---

## 2.5 Characters: Bytes vs. Runes

A common source of confusion in Go is the difference between a `byte` and a `rune`. 

### Lab Exercise 2.5: Multi-byte Decoding
1. Create a string containing an emoji: `let s = string("Hi 🌍")`.
2. Print `len(s)`. Why is it not 4?
3. Iterate over the string using `range!(s)` and print each rune. How many iterations occur?

---

## 2.7 The Polymorphic `nil`

Goish implements a **Polymorphic `nil`** (in `src/nilval.rs`) to bridge the gap between Go's universal constant and Rust's strict typing.

### Lab Exercise 2.7: Polymorphic Comparison
1. Create a `chan<int>` and assign it `nil.into()`.
2. Use an `if` statement to check if the channel is `== nil`.
3. Try to call `ch.Len()` on a nil channel. Does it crash? (Check `src/gochan.rs` for the `nil` check in `Len()`).
