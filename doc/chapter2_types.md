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

*   **Goish vs. Go**:
    *   In Go, `int` is a platform-dependent type (32-bit on x86, 64-bit on x86_64). In Goish v1 (which explicitly targets 64-bit Linux), `int` is strictly aliased to `i64`. This predictability helps macros evaluate type conversions at compile-time.
*   **Goish vs. Rust**:
    *   In Rust, developers are encouraged to use specific widths (`i32`, `u64`) or architecture-dependent widths (`isize`, `usize`). Goish pushes developers toward the Go-idiomatic `int` to maintain standard library compatibility, abstracting away the underlying `i64`.

---

## 2.2 Strings: Immutable Sharing via `Arc<[u8]>`

In Go, a `string` is a read-only slice of bytes. It is extremely cheap to pass around because copying a string in Go only copies a pointer and a length, not the underlying bytes.

In Rust, the standard `String` type is a heap-allocated, mutable buffer (`Vec<u8>`). If you want to share a `String` without copying its contents, you must borrow it as an `&str` (which introduces lifetime annotations) or wrap it in a reference counter like `Arc<str>`.

Goish bridges this gap with its custom `string` type (`src/gostring.rs`):

```rust
#[derive(Clone)]
pub struct string {
    bytes: Arc<[u8]>,
}
```

By backing the string with an `Arc<[u8]>` (Atomic Reference Counted slice):
1.  **Immutability is guaranteed**: The `Arc` provides read-only access to the shared bytes.
2.  **Cloning is cheap**: When you assign `a = b` or pass a string to a function, Goish simply increments an atomic counter. The actual string data is not duplicated.
3.  **Thread safety**: `Arc` ensures that strings can be safely sent across channels to other Goroutines running on different OS threads.

*   **Goish vs. Go**:
    *   In Go, the Garbage Collector tracks string references and frees the backing array when no pointers remain. In Goish, the `Arc` drops the backing array deterministically the moment the reference count hits zero.
*   **Goish vs. Rust**:
    *   A Rust `String` implies exclusive ownership and mutability, while `&str` requires lifetime management. Goish's `string` behaves like a garbage-collected string—it can be passed anywhere without lifetime annotations—at the cost of a small atomic reference counting overhead.

---

## 2.3 Borrowing vs. Copying in Goish

One of the hardest adjustments for students moving from Garbage Collected languages (like Go, Java, or Python) to Systems languages (like Rust or C) is understanding exactly when data is copied and when it is shared.

In Go, "everything is passed by value." However, because slices, maps, and channels are essentially pointers under the hood, passing them by value effectively *shares* the underlying data.

In Goish, we must respect Rust's strict ownership rules:
-   **Primitives** (like `int`, `bool`, `byte`) implement the `Copy` trait. They behave exactly like Go.
-   **Composite Goish Types** (like `string` and the upcoming `slice<T>`) implement the `Clone` trait but **do not** implement `Copy`. 

This creates a subtle but important difference in how you write Goish code compared to standard Go. 

If you want to pass a `string` to multiple functions in Goish, you must explicitly `.clone()` it if the function consumes it, or pass it by reference (`&string`).

*   **Goish vs. Go**:
    *   In Go, `func doSomething(s string)` is called as `doSomething(myString)`. The Go compiler cheaply copies the string header.
    *   In Goish, if `doSomething` consumes the string, calling `doSomething(myString)` *moves* the string. If you need it later, you must write `doSomething(myString.clone())`. The explicit `.clone()` makes the reference-count bump visible in the code.
*   **Goish vs. Rust**:
    *   Idiomatic Rust functions often take `&str` or `&[u8]` to avoid the overhead of `Arc` clones. Goish intentionally avoids forcing users to write lifetimes, preferring the slight `Arc::clone` overhead to maintain the Go-like experience of passing owned values without lifetime syntax.

---

## 2.4 The "Zero Value" Concept and `Default`

In Go, variables are automatically initialized to their "zero value" (`0` for `int`, `""` for `string`, `false` for `bool`). This guarantees that a variable is always in a valid, predictable state.

Rust, however, does not have implicit zero values; the compiler forces you to initialize every variable before use. 

To bridge this gap and make Goish code feel like Go, Goish relies heavily on Rust's `Default` trait. Every primitive type in Goish (`int`, `float64`, etc.) and every composite type (`string`, `slice<T>`) implements `Default`.

*   **Goish vs. Go**:
    *   In Go, `var s string` implicitly creates an empty string. In Goish, you must explicitly call `let mut s: string = string::default();` (or `string::new()`). However, Goish's macro system (like `#[goish::reflect]`) uses these `Default` implementations under the hood to auto-generate Go-like zero values for complex structs.
*   **Goish vs. Rust**:
    *   While idiomatic Rust uses `Option<T>` to represent the absence of a value (forcing you to handle the `None` case), Goish avoids `Option` for core types. Instead, it returns the concrete "zero value" (like an empty `string` or `0`) to perfectly match Go's map-lookup and error handling semantics.

---

## 2.5 Characters: Bytes vs. Runes

A common source of confusion in Go is the difference between a `byte` and a `rune`. 
- A `byte` is an alias for `uint8` and represents a single raw byte of data.
- A `rune` is an alias for `int32` and represents a single Unicode code point.

In Goish, these are mapped directly to `u8` and `i32`.

The distinction is most visible when interacting with a `string`:
1.  **Indexing (`s[i]`)**: Returns a raw `byte` (`u8`). This is a fast, O(1) operation, but it might return a partial character if the string contains multi-byte Unicode.
2.  **Iteration (`range!(s)`)**: Returns a `(byte_offset, rune)`. This requires decoding UTF-8 on the fly.

Because a single `rune` (like 'é' or '🌍') can take up to 4 bytes in UTF-8, iterating over a string using Goish's `range!` macro automatically steps by the correct number of bytes, exactly like Go's `for i, r := range s`.

*   **Goish vs. Go**:
    *   Goish perfectly mirrors Go's dual nature of strings. `s[0]` returns a byte, while the `range!` macro decodes runes, maintaining exact semantic compatibility.
*   **Goish vs. Rust**:
    *   Rust distinguishes strongly between a byte slice `&[u8]` and a guaranteed-valid UTF-8 string `&str`. Rust's `char` type is 4 bytes and is statically guaranteed to be a valid Unicode scalar value. Goish's `rune` (`i32`) is slightly looser to match Go's `int32`, meaning it can technically represent invalid code points if the underlying byte slice contains invalid UTF-8 (just like Go).

---

### Lab Exercise: Exploring String Behavior
1.  Write a Goish program that creates a `string`, assigns it to another variable, and prints both.
2.  What happens if you try to pass the same `string` variable to two different functions sequentially without using `.clone()`?
3.  Look at the compiler error. How does Rust's borrow checker explain the "move" of the `string` type?
