# Goish v1: A Systems-Level Implementation of Go
## Table of Contents

### Part I: Foundations
*   **[Chapter 1: The Bootstrap — Booting from Zero](chapter1_bootstrap.md)**
    *   1.0 Getting Started (Environment & Cargo)
    *   1.1 Philosophy: Go Idioms on Rust Foundations
    *   1.1.1 Why Not Just Write Pure Rust?
    *   1.1.2 The Concurrency Trade-off: Stackless vs. Stackful
    *   1.2 Ownership at the Entry Point: `_start`
    *   1.3 The RT0 Pipeline (Initial Memory and TLS)
    *   1.4 From Rust to Runtime: The Macro Translation
    *   1.5 Handing off: From `no_main` to `main`
    *   1.6 The Comparative Landscape: Goish vs. Go vs. Rust

### Part II: Data Representation & Memory
*   **[Chapter 2: Primitive Types and Ownership](chapter2_types.md)**
    *   2.1 Integers, Floats, and Stack Allocation
    *   2.2 Strings: Immutable Sharing via `Arc<[u8]>`
    *   2.3 Borrowing vs. Copying in Goish
    *   2.4 The Zero Value and the `Default` Trait
    *   2.5 Bytes vs. Runes: The `range!` Decoder
    *   2.6 Polymorphic Nil
*   **[Chapter 3: Composite Types and Layout](chapter3_types_layout.md)**
    *   3.1 Slices: The "Copy-on-Subslice" Rule
    *   3.2 Maps: Hash Tables and Shared Reference Logic
    *   3.3 Structs: Alignment, Tagging, and Reflection
*   **[Chapter 4: Error Handling](chapter4_errors.md)**
    *   4.1 The `error` Interface and `nil` checks
    *   4.2 Creating and Wrapping Errors
    *   4.3 Error Chaining: `Is` and `As`
    *   4.4 Combining Errors with `Join`
    *   4.5 Panic and Recovery
*   **[Chapter 5: The Runtime Memory Model](chapter4_memory.md)**
    *   5.1 The `mheap` Page Allocator
    *   5.2 Size Classes and `mcentral`
    *   5.3 Registering the Global Allocator

### Part III: Execution & Concurrency
*   **[Chapter 6: The Scheduler](chapter5_scheduler.md)**
    *   6.1 The G-M-P Model
    *   6.2 Context Switching: Assembly and the Stack
    *   6.3 Asynchronous Preemption (SIGURG)
    *   6.4 Work Stealing
    *   6.5 Stack Management: 2 KB and On-Demand Growth
*   **[Chapter 7: Channels and Communication](chapter6_channels.md)**
    *   6.1 The Park/Ready Protocol
    *   6.2 Moving Ownership: The `Send` Trait in Channels
    *   6.3 Structured Concurrency: Scoped WaitGroups
    *   6.4 The `select!` Macro: Multi-way Dispatch

### Part IV: Networking & The Netpoller
*   **[Chapter 8: High-Performance Networking](chapter7_networking.md)**
    *   7.1 The Netpoller: Bridging Epoll and Goroutines
    *   7.2 Network Programming: Listen, Accept, and Dial
    *   7.3 Building an HTTP Server

### Part V: Advanced Features
*   **[Chapter 9: Reflection and Introspection](chapter8_reflection.md)**
    *   8.1 Compile-time Reflection via Proc-Macros
    *   8.2 The `reflect` Package: Type and Value Introspection
*   **[Chapter 10: The Standard Library](chapter9_stdlib.md)**
    *   10.1 Raw Syscalls via `asm!`
    *   10.2 Buffered I/O and File Handling
    *   10.3 The `fmt` Package: Reflection-based Formatting
    *   10.4 The `crypto` Package
*   **[Chapter 11: Language Bridging: The Go-Rust Interface](chapter10_bridging.md)**
    *   11.1 `Hook<T>`: Hot-Swappable Package Variables
    *   11.2 `Lazy<T>`: Safe Static Initialization
    *   11.3 The Goish ABI: Raw Syscalls and No Libc
