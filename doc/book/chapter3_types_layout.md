# Chapter 3: Composite Types and Layout

In this chapter, we explore how Goish handles complex data structures like Maps and Structs, and how they are laid out in memory to satisfy both Go's idioms and Rust's safety.

## 3.1 Slices: The "Copy-on-Subslice" Rule

As discussed in Chapter 2, Goish slices deviate from standard Go in one major way: **subslicing performs a copy**.

```rust
let s1 = slice!([1, 2, 3, 4, 5]);
let s2 = s1.slice(0, 2); // s2 is an independent COPY [1, 2]
```

This rule exists to ensure that multiple slice handles do not share mutable state, which would violate Rust's borrow checker. 

### Lab Exercise 3.1: Proving Independence
1. Create a slice `s1` with some initial values.
2. Create a subslice `s2 = s1.slice(0, 2)`.
3. Modify `s2[0]`. Print both `s1` and `s2`. 
4. Confirm that `s1` remains unchanged. Compare this behavior to standard Go.

---

## 3.2 Maps: Hash Tables and Shared Reference Logic

A Go `map` is a pointer to a hash table. In **Goish**, we implement this using a wrapper around Rust's `BTreeMap` (in `src/gomap.rs`).

### Lab Exercise 3.2: Map Concurrency
1.  Create a Goish map and share it between two goroutines using `go!`.
2.  Have both goroutines mutate the map simultaneously using `m.Set()`.
3.  Observe that the program does not panic or corrupt memory, thanks to the internal `SpinLock`.
4.  Now try the same with a standard Rust `BTreeMap` and a `static mut`. Why does Rust's compiler stop you?

---

## 3.3 Structs: Alignment, Tagging, and Reflection

Structs in Goish are standard Rust structs. However, to enable Go-style features like **Reflection**, they must be decorated with the `#[goish::reflect]` attribute.

### Lab Exercise 3.3: Parsing Struct Tags
1. Define a struct `User` with a field `ID` and a tag `#[tag(json="id")]`.
2. Use the `reflect` package to get the type of the struct: `let t = reflect::TypeOf(&User::default())`.
3. Access the tag: `t.Field(0).Tag.Get("json")`.
4. Print the tag. Change the tag value and run the program again to see it update.

---
