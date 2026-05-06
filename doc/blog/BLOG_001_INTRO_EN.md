# The World's AI Infrastructure is Driven by Go... So Why Do I Want to Build It in Rust?

A slightly confusing headline—what's the catch this time?

As we all know, the foundational infrastructure that powers AI providers globally—like Docker and Kubernetes—is predominantly written in Go. 

However, from the perspective of a deep systems engineer, I actually prefer **Rust**, even though deep down I have a couple of core issues with it that make this transition far from easy:
1. **Syntax extensions** (like Async/Await) still don't feel quite intuitive to me.
2. **A fragmented ecosystem** compared to Go. Go's standard library and ecosystem feel much more "professional" (perhaps due to early backing by tech giants and the sheer volume of CNCF projects born early on).

## Why is Porting Kubernetes to Rust (Almost) Impossible?

If Rust is so safe and fast, why isn't anyone writing AI infra in Rust? The short answer is: **"It's just not mature enough at the ecosystem level."**

Attempting to port Kubernetes directly to Rust is practically impossible. Even if someone managed to manually port the entire codebase (like the *Rusternetes* project), almost no one would dare run it in production. The **runtime semantics** of the two languages are fundamentally different.

There's a saying in the industry: *"If you have the audacity to think about porting Kubernetes to Rust... try porting ETCD (K8s' primary storage) and surviving first."*

Changing languages isn't just about getting it to compile. You have to answer:
*   When upstream Kubernetes releases a new version, how do we keep up?
*   How do hundreds of sub-components maintain conformance with the original?

## Goish: Porting at a Lower Layer to Lift the Entire Ecosystem

I believe the correct approach isn't translating Kubernetes code directly. It's **building a new Go Runtime and Standard Library entirely in Rust** first.

And that is the core idea behind **Goish**:
1. **Strip away Go's Garbage Collector (GC)**: But retain the memory safety mechanism using Rust's Ownership rules.
2. **Bypass the OS mechanisms**: We rely on zero `libc` and don't even use Rust's `std`. Writing it feels akin to developing an OS Kernel in Rust, strictly using the `core` library.
3. **Custom Global Allocator**: Even the memory allocator is custom-built and plugged in as the Rust Global Allocator. So, when code calls `Vec<u8>`, it routes directly through a specialized allocator I tailored specifically for this system.

## Deep Dive Architecture: Squeezing Low-Level Performance

What I genuinely want are **Goroutines** protected by the Rust Compiler's memory safety guarantees, running under absolute hardware-level control:

*   **Stack Management**: We manually control all stack size allocations for precise memory management. (Honestly, this is the joy of programming for me. As for Rust's native Async/Await... I *no care* about it.)
*   **Custom Scheduler**: Written seamlessly using a mix of Rust and Assembly (ASM) to mimic Go's execution semantics as closely as possible.
*   **Pure Static Linking**: An important byproduct is that we get a Rust SDK that compiles seamlessly without `libc`, yielding binaries that are clean, tiny, and truly static.

### The Heart of the System: Trampolines and the SysV ABI Bridge

The ultimate challenge in Goish is making Rust understand the context of low-level execution just like the Go runtime does. We had to strictly design a **Trampoline** system and adhere to the **SysV AMD64 ABI**:

*   **The Naked Trampoline**: We use `#[naked]` functions to write the "Assembly Trampoline" entirely by hand. When a Goroutine is interrupted by a `SIGURG` signal, we absolutely cannot let the Rust compiler inject Prologues/Epilogues (which would shift the RSP or clear registers). We must manually control every register and the stack to preserve the original state.
*   **Respecting the Red Zone**: According to the SysV AMD64 ABI standard, there is a 128-byte area below the Stack Pointer known as the "Red Zone," which small functions use to store data without moving the RSP. If our system blindly overwrites this area, the program will instantly crash! Goish avoids this lethal trap using a `lea rsp, [rsp - 128]` instruction to jump over the danger zone before saving any state.
*   **Clobber-Free via `SA_ONSTACK`**: A very expensive lesson we learned (δ.3 post-mortem) was that if the system doesn't isolate the Signal Handler's stack, the Kernel drops the `rt_sigframe` right on top of the Goroutine's stack, clobbering the data. Goish enables `sigaltstack` coupled with the `SA_ONSTACK` flag to force the handler onto a separate stack. This allows us to safely log the Program Counter (PC) directly onto the Goroutine stack with 100% safety, completely eliminating Context Switch race conditions between threads.
*   **Register Preservation Discipline**: Before switching contexts to call Rust code (`async_preempt2`), we must back up every single register, including **EFLAGS** and **XMM registers** (via `fxsave64`), while ensuring the stack is perfectly 16-byte Aligned according to ABI rules. This ensures execution can flow back and forth between Rust code and the Kernel flawlessly.

## The Experience: Writing Rust like Go

The Goish project is split into two main crates: `stdlib/runtime` and `macros`. This allows me to leverage the power of the Rust compiler to compile code that looks and feels exactly like Go:

```rust
#[goish::main]
fn main() {
    // String literals are automatically converted (Into) to the goish::string type
    // to maintain the balance between Syntactic Sugar and accurate Go Semantics.
    fmt::Printf!("Hello world %s\n", "Goish");
}
```

And of course... spinning up concurrent Goroutines remains just as effortless:

```rust
fn main() {
    go!(move || {
        // This code runs in the background
        // under the absolute protection of Rust
    });
}
```

**Final Thoughts:**
The **Goish** project might sound like a reckless engineering experiment, but our main goal is clear and simple: **retain the elegant simplicity of Go** while fully harnessing **the memory safety and low-level resource control of Rust**.
