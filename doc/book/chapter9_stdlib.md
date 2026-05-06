# Chapter 9: The Standard Library

Goish aims to provide a "batteries-included" experience for systems programmers.

## 9.1 Raw Syscalls via `asm!`

Everything in Goish is built on the `syscall` package.

### Lab Exercise 9.1: Tracing Syscalls
1. Run a simple Goish program (e.g., `hello.rs`) under `strace`.
2. Can you find the `write` syscall? 
3. Look at the `src/syscall/` directory. Can you find the assembly code that generates this syscall? 

---

## 9.2 Buffered I/O and File Handling

The `bufio` and `io` packages provide efficient reading and writing patterns.

### Lab Exercise 9.2: Building a Utility
1. Use the `os` and `bufio` packages to write a simple version of the `cat` command.
2. The program should open a file, read it line-by-line, and print it to standard output.
3. Compare the performance of your `cat` utility with the standard Linux `cat`.

---

## 9.3 The `fmt` Package: Reflection-based Formatting

The `fmt` package uses the **Reflection** system (Chapter 8) to provide powerful, type-safe formatting.

### Lab Exercise 9.3: Custom Formatting
1. Create a complex struct with nested fields and slices.
2. Print the struct using `fmt::Println!`. 
3. Observe how the reflection system automatically formats the entire tree. Can you find where this logic is implemented in `src/fmt/mod.rs`?

---

## 9.4 The `crypto` Package: Modern Security in `no_std`

Goish includes a comprehensive `crypto` suite implemented in pure Rust.

### Lab Exercise 9.4: Hashing a File
1. Write a program that reads a file and computes its SHA-256 hash.
2. Use the `crypto/sha256` package. 
3. Verify the result using the standard `sha256sum` command on your terminal.

---
