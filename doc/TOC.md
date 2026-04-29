# Goish v1: A Systems-Level Implementation of Go
## Table of Contents

### Part I: Foundations
*   **Chapter 1: The Bootstrap — Booting from Zero**
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
*   **Chapter 2: Primitive Types and Ownership**
    *   2.1 Integers, Floats, and Stack Allocation
    *   2.2 Strings: Immutable Sharing via `Arc<[u8]>`
    *   2.3 Borrowing vs. Copying in Goish
*   **Chapter 3: Composite Types and Layout**
    *   3.1 Slices: `Vec<T>` Backing and Independent Copies
    *   3.2 Maps: Hash Tables and Shared Reference Logic
    *   3.3 Structs: Alignment, Tagging, and Reflection
*   **Chapter 4: The Runtime Memory Model**
    *   4.1 The `mheap` Page Allocator
    *   4.2 Size Classes and `mcentral`
    *   4.3 Registering the Global Allocator

### Part III: Execution & Concurrency
*   **Chapter 5: The Scheduler**
    *   5.1 The G-M-P Model
    *   5.2 Context Switching: Assembly and the Stack
    *   5.3 Asynchronous Preemption (SIGURG)
*   **Chapter 6: Channels and Communication**
    *   6.1 The Park/Ready Protocol
    *   6.2 Moving Ownership: The `Send` Trait in Channels
    *   6.3 The `select!` Macro: Multi-way Dispatch

### Part IV: Advanced Concepts
*   **Chapter 7: Interfaces and Reflection**
    *   7.1 Fat Pointers and Dynamic Dispatch
    *   7.2 Compile-time Reflection via Proc-Macros
*   **Chapter 8: System Packages**
    *   8.1 Raw Syscalls via `asm!`
    *   8.2 Buffered I/O and File Handling
    *   8.3 The `fmt` Package: Reflection-based Formatting
