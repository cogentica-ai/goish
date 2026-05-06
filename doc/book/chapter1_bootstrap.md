# Chapter 1: The Bootstrap — Booting from Zero

Every program must start somewhere. In **Goish**, we build on `no_std`, which means we are responsible for the very first instruction the CPU executes after the kernel loads our binary.

## 1.0 Getting Started: Setting Up Your Environment

To use Goish, you need the Rust Nightly toolchain and a specific Cargo configuration to bypass the standard C startup code.

*   **Goish vs. Go**: In Go, the toolchain (`go build`) handles everything behind the scenes. In Goish, you have more control but must manually configure the linker (`-nostartfiles`) and the target.
*   **Goish vs. Rust**: A standard Rust project implicitly links to `std` and the C runtime (`crt0`). Goish explicitly opts out of both, requiring the user to define the entry point.

### Lab Exercise 1.0: Binary Independence
1.  Run `cargo build --example hello`.
2.  Use `ldd target/debug/examples/hello`. 
    *   **Goish Observation**: It should say "not a dynamic executable". 
    *   **Comparison**: Compare this to a standard Rust or Go binary, which usually links to `linux-vdso.so` or `libc.so`.
3.  Why is Goish's approach preferred for building an Operating System kernel or an embedded driver?

---

## 1.1 Philosophy: Go Idioms on Rust Foundations

Goish provides the "feeling" of Go with the "safety" of Rust.

*   **Goish vs. Go**: Goish replaces the Garbage Collector with Rust's **Ownership** system. You get Go-style channels, but the Rust compiler ensures that once you "send" a value, you no longer "own" it, preventing data races.
*   **Goish vs. Rust**: Rust's standard concurrency uses `async/await` (stackless). Goish uses **Goroutines** (stackful), which avoids "function coloring" and makes concurrent code look like sequential code.

### 1.1.1 Why Not Just Write Pure Rust?
If Rust is so safe and fast, why not just encourage developers to write pure Rust instead of building a Go-like runtime on top of it?

Writing high-level concurrent applications in standard Rust exposes developers to a steep learning curve:
1.  **Function Coloring (`async`/`await`)**: Rust's standard concurrency model is *stackless*. An `async` function returns a `Future` state machine, not a value. You cannot easily call an `async` function from a synchronous one without blocking the thread or introducing complex executor patterns. Goish uses *stackful* goroutines, meaning concurrent code looks exactly like sequential code—no `async` keywords required.
2.  **Shared State Complexity**: To share a channel receiver across multiple threads in pure Rust, you often have to wrap it in an `Arc<Mutex<Receiver<T>>>`. The developer is constantly wrestling with `LockGuard` scopes, deadlocks, and lifetimes. In Goish, a `chan<T>` is inherently shared and thread-safe; you simply `.clone()` the handle and pass it to a goroutine.
3.  **The `select` Problem**: Multiplexing channels in Rust (e.g., using `tokio::select!`) requires understanding "cancellation safety" and "pinning" futures to memory. Goish provides a `select!` macro that behaves exactly like Go's: it blocks on multiple channels simultaneously without the user ever needing to understand what a `Pin<Box<dyn Future>>` is.

Goish hides the exhausting boilerplate of asynchronous Rust while keeping the strict compile-time safety (Move Semantics) that makes Rust so reliable.

### 1.1.2 The Concurrency Trade-off: Stackless vs. Stackful
Goish leverages **Stackful Goroutines**, providing a **2 KB minimum stack** today with `stacker`-style on-demand growth. This makes Goish significantly more memory-efficient than standard Go (which starts at 2 KB but has higher management overhead) and provides a path to "millions of goroutines" on standard hardware.

**The Case for Goish's Stackful Approach**
*   **Memory Efficiency**: By using a 2 KB starting tier and growing only when needed, Goish achieves a 5× improvement in baseline overhead compared to traditional green-thread implementations.
*   **Ergonomics**: No "function coloring." Synchronous and concurrent code look identical.
*   **Preemption**: Uses OS signals (`SIGURG`) to prevent CPU-bound tasks from starving the system.

### How Does Rust Safety Prevent Stack Overflow Corruption?
If a goroutine in Goish starts with a 2 KB stack, what happens if it recurses too deeply? 

Goish uses the operating system's memory protection hardware (the MMU) and the `stacker` library's logic to ensure safety. When Goish allocates a goroutine's stack, it uses the raw `mmap` syscall to create an isolated region of memory. This allows the runtime to place a **Guard Page** at the very bottom.

As the stack grows downward, if it reaches the boundary, the runtime triggers an on-demand allocation to grow the stack. If a true overflow occurs (exceeding the maximum allowed growth), the CPU will attempt to write into the Guard Page. The hardware MMU instantly intercepts this illegal write and throws a `SIGSEGV` (Segmentation Fault).

While a SegFault crashes the program, **a deterministic crash is a form of safety**. It guarantees that a stack overflow will immediately halt execution rather than silently corrupting the memory of other goroutines. 

### Lab Exercise 1.1: Visualizing Stack Growth
1. Run `cargo build --example bench_string_slice` (or any recursive example).
2. Set the environment variable `GOISH_DEBUG=grow`.
3. Observe the logs. Can you identify when a goroutine exceeds its 2 KB carve and triggers an on-demand stack pivot?

---

## 1.2 The Entry Point: `_start`

The kernel jumps to the address labeled `_start`. This is generated by the `#[goish::main]` macro.

*   **Goish vs. Go**: Go's entry point is hidden inside the runtime's assembly files (e.g., `rt0_linux_amd64.s`). Goish makes this visible and customizable via a procedural macro.
*   **Goish vs. Rust**: Standard Rust relies on the C library's `crt0` to handle the transition from the kernel to `fn main()`. Goish bypasses the C library entirely, talking directly to the kernel.

### Lab Exercise 1.2: Entry Point Disassembly
1. Run `objdump -d target/debug/examples/hello | grep -A 20 "<_start>:"`.
2. Find where the stack pointer (`rsp`) is aligned to 16 bytes.
3. Identify the `call` to `__goish_rt0`. What arguments are being passed in `rdi` and `rsi`?

---

## 1.3 The RT0 Pipeline (Initial Memory and TLS)

The function `__goish_rt0` performs the "Mission Control" boot sequence.

*   **Goish vs. Go**: Go's initialization (`runtime.schedinit`) is monolithic and complex. Goish's pipeline is modular: it starts the allocator (`mheap`), then the scheduler, then the workers.
*   **Goish vs. Rust**: Rust's `std` initialization handles environment variables and thread safety for the C library. Goish initializes the **M-P-G** structures needed for stackful multitasking.

### Lab Exercise 1.3: Analyzing the Bootstrap
1. Open `src/runtime/mod.rs` and find the `__goish_rt0` function.
2. Comment out the call to `heap::mheap_init()`.
3. Try to compile and run `hello.rs`. Why does the program fail even before reaching your `main` function? (Hint: Does the `#[goish::main]` macro need to allocate any memory?)

---

## 1.4 From Rust to Runtime: The Macro Translation

The `#[goish::main]` macro transforms your high-level code into low-level entry points.

*   **Goish vs. Go**: Go uses a custom compiler (`compile`) and linker (`link`) that have built-in knowledge of the `main` package. Goish uses standard Rust macros to achieve the same result without modifying the compiler.
*   **Goish vs. Rust**: Rust attributes like `#[tokio::main]` set up an async runtime. `#[goish::main]` sets up a stackful scheduler and an assembly entry point.

### Lab Exercise 1.4: Macro Expansion
1. Use `cargo expand --example hello` (requires `cargo-expand` tool).
2. Look at the code generated by `#[goish::main]`.
3. Can you find the `extern "C" fn __goish_main()` and the `global_asm!` block?

---

## 1.5 Handing off: From `no_main` to `main`

Once the runtime is ready, it calls `__goish_main()`.

*   **Goish vs. Go**: After `main.main` returns, the Go runtime exits. Goish also exits, but it first calls `sched::schedule()` to allow background goroutines a final chance to complete.
*   **Goish vs. Rust**: In `std` Rust, the return value of `main` determines the exit code. In Goish, the runtime explicitly calls `syscall::Exit(0)` to ensure the process terminates cleanly without the C library's help.

### Lab Exercise 1.5: The Final Exit
1. Modify `examples/hello.rs` to spawn a goroutine that sleeps for 1 second before printing.
2. Run the program.
3. Does the program exit immediately, or does it wait for the goroutine? Why? (Check `src/runtime/mod.rs` after the call to `__goish_main`).
