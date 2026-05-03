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
*   **[Chapter 3: Composite Types and Layout](chapter3_types_layout.md)**
    *   3.1 Slices: `Vec<T>` Backing and Independent Copies
    *   3.2 Maps: Hash Tables and Shared Reference Logic
    *   3.3 Structs: Alignment, Tagging, and Reflection
*   **[Chapter 4: The Runtime Memory Model](chapter4_memory.md)**
    *   4.1 The `mheap` Page Allocator
    *   4.2 Size Classes and `mcentral`
    *   4.3 Registering the Global Allocator

### Part III: Execution & Concurrency
*   **[Chapter 5: The Scheduler](chapter5_scheduler.md)**
    *   5.1 The G-M-P Model
    *   5.2 Context Switching: Assembly and the Stack
    *   5.3 Asynchronous Preemption (SIGURG)
*   **[Chapter 6: Channels and Communication](chapter6_channels.md)**
    *   6.1 The Park/Ready Protocol
    *   6.2 Moving Ownership: The `Send` Trait in Channels
    *   6.3 Structured Concurrency: Scoped WaitGroups
    *   6.4 The `select!` Macro: Multi-way Dispatch

### Part IV: Networking & The Netpoller
*   **[Chapter 7: High-Performance Networking](chapter7_networking.md)**
    *   7.1 The Netpoller: Bridging Epoll and Goroutines
    *   7.2 Network Programming: Listen, Accept, and Dial
    *   7.3 Building an HTTP Server

### Part V: Advanced Concepts
*   **[Chapter 8: Reflection and Introspection](chapter8_reflection.md)**
    *   8.1 Compile-time Reflection via Proc-Macros
    *   8.2 The `reflect` Package: Type and Value Introspection
*   **[Chapter 9: The Standard Library](chapter9_stdlib.md)**
    *   9.1 Raw Syscalls via `asm!`
    *   9.2 Buffered I/O and File Handling
    *   9.3 The `fmt` Package: Reflection-based Formatting
