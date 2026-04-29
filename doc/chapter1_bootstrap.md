# Chapter 1: The Bootstrap — Booting from Zero

Every program must start somewhere. In **Goish**, we build on `no_std`, which means we are responsible for the very first instruction the CPU executes after the kernel loads our binary.

## 1.0 Getting Started: Setting Up Your Environment

To use Goish, you need the Rust Nightly toolchain and a specific Cargo configuration to bypass the standard C startup code.

*   **Goish vs. Go**: In Go, the toolchain (`go build`) handles everything behind the scenes. In Goish, you have more control but must manually configure the linker (`-nostartfiles`) and the target.
*   **Goish vs. Rust**: A standard Rust project implicitly links to `std` and the C runtime (`crt0`). Goish explicitly opts out of both, requiring the user to define the entry point.

---

## 1.1 Philosophy: Go Idioms on Rust Foundations

Goish provides the "feeling" of Go with the "safety" of Rust.

*   **Goish vs. Go**: Goish replaces the Garbage Collector with Rust's **Ownership** system. You get Go-style channels, but the Rust compiler ensures that once you "send" a value, you no longer "own" it, preventing data races.
*   **Goish vs. Rust**: Rust's standard concurrency uses `async/await` (stackless). Goish uses **Goroutines** (stackful), which avoids "function coloring" and makes concurrent code look like sequential code.

### 1.1.1 Why Not Just Write Pure Rust?
If Rust is so safe and fast, why not just teach students to write pure Rust instead of building a Go-like runtime on top of it?

Writing high-level concurrent applications in standard Rust exposes developers to a steep learning curve:
1.  **Function Coloring (`async`/`await`)**: Rust's standard concurrency model is *stackless*. An `async` function returns a `Future` state machine, not a value. You cannot easily call an `async` function from a synchronous one without blocking the thread or introducing complex executor patterns. Goish uses *stackful* goroutines, meaning concurrent code looks exactly like sequential code—no `async` keywords required.
2.  **Shared State Complexity**: To share a channel receiver across multiple threads in pure Rust, you often have to wrap it in an `Arc<Mutex<Receiver<T>>>`. The developer is constantly wrestling with `LockGuard` scopes, deadlocks, and lifetimes. In Goish, a `chan<T>` is inherently shared and thread-safe; you simply `.clone()` the handle and pass it to a goroutine.
3.  **The `select` Problem**: Multiplexing channels in Rust (e.g., using `tokio::select!`) requires understanding "cancellation safety" and "pinning" futures to memory. Goish provides a `select!` macro that behaves exactly like Go's: it blocks on multiple channels simultaneously without the user ever needing to understand what a `Pin<Box<dyn Future>>` is.

Goish hides the exhausting boilerplate of asynchronous Rust while keeping the strict compile-time safety (Move Semantics) that makes Rust so reliable.

### 1.1.2 The Concurrency Trade-off: Stackless vs. Stackful
While Goish hides the complexity of Rust's standard concurrency, its approach (Stackful Goroutines) comes with its own set of engineering trade-offs when compared directly to pure Rust's `async`/`await` (Stackless Coroutines).

**The Case for Rust's Stackless (`async`/`await`) Approach**
*   **Memory Efficiency**: Rust's compiler generates state machines precisely sized to hold only the local variables needed across an `await` point. Millions of concurrent tasks can run on minimal RAM without the overhead of reserving a minimum stack size per task.
*   **Zero-Cost Context Switches**: "Awaiting" a future simply returns a `Poll::Pending` state from a function call. There is no need to save and restore hardware CPU registers (RSP, RBP, etc.), resulting in incredibly fast yields.
*   **No Hidden Allocations**: Future state machines can be allocated anywhere (stack, heap, or static memory), giving the programmer absolute control over memory layout.

**The Case for Goish's Stackful (Goroutine) Approach**
*   **Ergonomics and Simplicity**: Any function can block or yield. There is no "function coloring" problem. Synchronous and concurrent code look identical, making it far easier to read, write, and refactor.
*   **Preemption**: A runtime (like Goish's `sysmon`) can preempt long-running CPU-bound tasks using OS signals (e.g., `SIGURG`), preventing a single rogue loop from starving other goroutines. In standard Rust, a CPU-bound `async` function blocks the executor thread unless it cooperatively yields.
*   **Debugging and Profiling**: Because each goroutine has a real, contiguous call stack, panics and debuggers show the exact, nested sequence of function calls. Rust's `async` futures often result in fragmented and deeply nested executor backtraces that are notoriously difficult to decipher.

**The Honest Compromise**
Goish accepts the overhead of allocating a contiguous memory stack for every goroutine. But why does Goish use a massive **64KB** per goroutine while standard Go only needs **2KB**?

The answer lies in compiler integration:
*   **Go's `morestack` Magic**: The Go compiler injects a tiny hidden check at the start of *every single function*. If the function is about to overflow the current 2KB stack, the runtime pauses, allocates a larger stack, copies the old data over, updates all pointers, and resumes. This requires deep, proprietary integration between the compiler and the runtime.
*   **Goish's Fixed Stacks**: Because Goish is built on standard Rust (via LLVM), we do not have the compiler hooks to dynamically grow or move stacks. Once a goroutine's stack is allocated, its size is fixed. To prevent stack overflows during deep function calls, Goish must defensively allocate a much larger block upfront (64KB) to accommodate the "worst-case" depth of a normal program.

### How Does Rust Safety Prevent Stack Overflow Corruption?
If a goroutine in Goish has a fixed 64KB stack, what happens if it recurses too deeply and exceeds that limit? In C, this would silently corrupt the adjacent memory, likely destroying another thread's stack and causing catastrophic, unpredictable behavior. 

Rust's borrow checker cannot prevent stack overflows at compile time (since recursion depth is a runtime property). Instead, Goish leverages the operating system's memory protection hardware (the MMU).

When Goish allocates a goroutine's stack (`src/runtime/sched/stack.rs`), it doesn't just allocate memory from the global heap. It uses the raw `mmap` syscall to create an isolated region of memory. This allows the runtime to place a **Guard Page** at the very bottom of the stack.

A Guard Page is a page of memory (usually 4KB) mapped with `PROT_NONE` (no read, no write permissions). As the stack grows downward, if it exceeds its 64KB limit, the CPU will attempt to write into the Guard Page. The hardware MMU instantly intercepts this illegal write and throws a `SIGSEGV` (Segmentation Fault).

While a SegFault crashes the program, **a deterministic crash is a form of safety**. It guarantees that a stack overflow will immediately halt execution rather than silently corrupting the memory of other goroutines. 

Additionally, Goish incurs the performance cost of an assembly-level context switch (`swap_context`) that saves and restores hardware CPU registers. In exchange for this memory overhead and context-switching cost, it offers unparalleled developer ergonomics, simple C-interoperability without breaking executors, and true preemptive multitasking.

If you are building a system that must handle 10 million simultaneous idle connections on limited hardware, pure Rust's stackless `async` is the undisputed winner. But for standard systems programming, microservices, and general-purpose tooling, the Goish stackful approach optimizes for human developer time, code readability, and debugging sanity.

---

## 1.2 The Entry Point: `_start`

The kernel jumps to the address labeled `_start`. This is generated by the `#[goish::main]` macro.

*   **Goish vs. Go**: Go's entry point is hidden inside the runtime's assembly files (e.g., `rt0_linux_amd64.s`). Goish makes this visible and customizable via a procedural macro.
*   **Goish vs. Rust**: Standard Rust relies on the C library's `crt0` to handle the transition from the kernel to `fn main()`. Goish bypasses the C library entirely, talking directly to the kernel.

---

## 1.3 The RT0 Pipeline (Initial Memory and TLS)

The function `__goish_rt0` performs the "Mission Control" boot sequence.

*   **Goish vs. Go**: Go's initialization (`runtime.schedinit`) is monolithic and complex. Goish's pipeline is modular: it starts the allocator (`mheap`), then the scheduler, then the workers.
*   **Goish vs. Rust**: Rust's `std` initialization handles environment variables and thread safety for the C library. Goish initializes the **M-P-G** structures needed for stackful multitasking.

---

## 1.4 From Rust to Runtime: The Macro Translation

The `#[goish::main]` macro transforms your high-level code into low-level entry points.

*   **Goish vs. Go**: Go uses a custom compiler (`compile`) and linker (`link`) that have built-in knowledge of the `main` package. Goish uses standard Rust macros to achieve the same result without modifying the compiler.
*   **Goish vs. Rust**: Rust attributes like `#[tokio::main]` set up an async runtime. `#[goish::main]` sets up a stackful scheduler and an assembly entry point.

---

## 1.5 Handing off: From `no_main` to `main`

Once the runtime is ready, it calls `__goish_main()`.

*   **Goish vs. Go**: After `main.main` returns, the Go runtime exits. Goish also exits, but it first calls `sched::schedule()` to allow background goroutines a final chance to complete.
*   **Goish vs. Rust**: In `std` Rust, the return value of `main` determines the exit code. In Goish, the runtime explicitly calls `syscall::Exit(0)` to ensure the process terminates cleanly without the C library's help.

---

### Lab Exercise: The Comparison in Action
1.  Run `cargo build --example hello`.
2.  Use `ldd target/debug/examples/hello`. 
    *   **Goish Observation**: It should say "not a dynamic executable". 
    *   **Comparison**: Compare this to a standard Rust or Go binary, which usually links to `linux-vdso.so` or `libc.so`.
3.  Why is Goish's approach preferred for building an Operating System kernel or an embedded driver?
