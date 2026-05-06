# Chapter 10: Language Bridging: The Go-Rust Interface

Building a Go-style runtime in Rust requires more than just a scheduler; it requires a set of patterns and types that bridge the gap between Go's dynamic world and Rust's static world.

## 10.1 `Hook<T>`: Hot-Swappable Package Variables

Go developers often use package-level variables to allow users to register custom behavior. Goish provides the `Hook<T>` type to solve this.

### Lab Exercise 10.1: Registering a Hook
1. Define a trait `Logger` and a global `Hook<dyn Logger>`.
2. Implement a `StdoutLogger` and install it using `HOOK.set(Box::new(StdoutLogger))`.
3. Call the logger using `HOOK.call(|l| l.Log(...))`. 
4. What happens if you call it before calling `.set()`?

---

## 10.2 `Lazy<T>`: Safe Static Initialization

Goish provides `Lazy<T>` to allow complex initialization of package-level variables in a thread-safe way.

### Lab Exercise 10.2: Thread-Safe Init
1. Define a `static` map using `Lazy::new`.
2. In your initializer closure, print a message: `fmt::Println("Initializing...")`.
3. Access the map from multiple goroutines simultaneously. 
4. How many times do you see the "Initializing..." message?

---

## 10.3 The Goish ABI: Raw Syscalls and No Libc

Goish explicitly bypasses `libc`, talking directly to the Linux kernel using the `syscall` package and raw assembly.

### Lab Exercise 10.3: Inspecting Symbols
1. Run `nm target/debug/examples/hello`. 
2. Look for any symbols from `libc.so` (like `printf` or `malloc`). 
3. Why are they missing? (Hint: Does Goish link to any external shared libraries?)

---

### Conclusion: The Architecture of Choice

The journey from raw assembly in `_start` to the high-level `net/http` package illustrates a fundamental principle of systems engineering: **The Runtime is the Language.**

By choosing to build its own memory model, scheduler, and networking stack, Goish offers a unique environment where the safety of Rust and the productivity of Go coexist. Whether you are building an operating system, a high-performance proxy, or an embedded controller, the architecture of Goish provides the tools to build it reliably and efficiently.
