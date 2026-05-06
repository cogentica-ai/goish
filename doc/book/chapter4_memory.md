# Chapter 4: The Runtime Memory Model

Because Goish runs without the Rust standard library or a C library, it cannot use `malloc` or the default Rust allocator. Instead, it includes a custom, high-performance memory allocator modeled after the Go runtime.

## 4.1 The `mheap` Page Allocator

The lowest level of the Goish memory system is the `mheap` (`src/runtime/heap.rs`).

### Lab Exercise 4.1: Page Monitoring
1. Run any Goish example with the environment variable `GOISH_DEBUG=mheap`.
2. Look for logs showing `mheap_alloc_pages`. 
3. How many pages does the runtime request from the kernel during startup? (Hint: Check the initial `mcentral` setup in `__goish_rt0`).

---

## 4.2 Size Classes and `mcentral`

Allocating memory page-by-page is efficient for large objects, but very wasteful for small ones. Goish solves this using **Size Classes**.

### Lab Exercise 4.2: Size Class Distribution
1. Create a program that allocates 100 `int`s and 100 large structs (e.g., 512 bytes).
2. Use `GOISH_DEBUG=mcentral` to watch the allocations.
3. Observe how the runtime chooses different spans for different object sizes. What happens when a span for a specific size class is full?

---

## 4.3 Registering the Global Allocator

The most critical step in the bootstrap process is making this custom system the default for all of Rust using the `#[global_allocator]` attribute.

### Lab Exercise 4.3: Proving the Allocator
1. Open `src/runtime/mod.rs` and temporarily comment out the `#[global_allocator]` attribute.
2. Try to compile a Goish program.
3. What error does the Rust compiler give? (Hint: Does the `no_std` environment provide a default heap allocator?)

---

### Lab Exercise 4.4: Memory Fragmentation
1.  Write a program that allocates thousands of small objects and then drops them.
2.  Use the `runtime::MemStats` package to inspect the heap usage.
3.  Observe how the `mcentral` system recycles small blocks without needing to return pages to the kernel.
