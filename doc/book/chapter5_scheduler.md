# Chapter 5: The Scheduler

The Goish scheduler is the most complex and critical part of the runtime. It is responsible for multiplexing thousands of **Goroutines (G)** onto a few **OS Threads (M)** using the concept of **Processors (P)**.

## 5.1 The G-M-P Model

Goish uses the G-M-P model to manage concurrency. Each **P** owns a **Local Run Queue**.

### Lab Exercise 5.1: Monitoring CPUs
1. Run a Goish program and check the logs with `GOISH_DEBUG=sched`.
2. How many **Ps** are initialized? Does it match the number of CPU cores on your machine? 
3. Try setting the environment variable `GOMAXPROCS=1`. How does the scheduler behavior change?

---

## 5.2 Context Switching: Assembly and the Stack

The runtime "swaps" goroutines using raw assembly in `src/runtime/sched/gobuf.rs`. 

### Lab Exercise 5.2: Dissecting the Switch
1. Open `src/runtime/sched/gobuf.rs` and look at the `swap_context` assembly.
2. Identify the instruction that saves the current Stack Pointer (`rsp`). 
3. Identify the instruction that loads the new Stack Pointer. What register is used as the base address for the new `gobuf`?

---

## 5.3 Asynchronous Preemption (SIGURG)

Goish prevents "CPU hogging" using **Asynchronous Preemption** via the `sysmon` thread and **SIGURG** signals.

### Lab Exercise 5.3: Visualizing Preemption
1. Run a program with an infinite loop: `go!(|| { loop {} });`.
2. Spawn another goroutine that prints something every second.
3. Observe that the second goroutine still makes progress. 
4. Check the logs with `GOISH_DEBUG=preempt`. Can you see the `SIGURG` signals being sent?

---

## 5.4 Work Stealing

If an M runs out of work, it "steals" goroutines from other Ps.

### Lab Exercise 5.4: Work Distribution
1. Run a program that spawns a large number of short-lived goroutines.
2. Use `GOISH_DEBUG=sched` and look for "steal" entries. 
3. Can you find an instance where an **M** successfully steals a **G** from another **P**'s queue?

---

## 5.5 Stack Management: 2 KB and On-Demand Growth

Goish uses **Stack Pivoting** to handle deep recursion while maintaining a 2 KB baseline.

### Lab Exercise 5.5: Stressing the Stack
1. Write a deeply recursive function (e.g., computing a large Fibonacci number) without using `maybe_grow`. 
2. Observe the program crash with a `SIGSEGV`. 
3. Now wrap the recursive call in `maybe_grow`. Run the program again. 
4. Use `GOISH_DEBUG=grow` to confirm that the stack pivot is working correctly.

---

## 5.6 Diagnostic Stack Traces

Without a robust runtime, a goroutine that exhausts its stack simply dies with a silent "Segmentation fault" (core dumped). The developer is left with no context about *which* goroutine crashed or *where* it was spawned.

Goish v1 solves this using a custom `SIGSEGV` handler and a zero-dependency DWARF symbolizer (`src/runtime/symbolize`).

### 5.6.1 The Spawn Table
When you spawn a goroutine using `go!()`, the runtime records the file and line number of the spawn site in a fixed-size, lock-free **Spawn Table**. This ensures the runtime always knows where a goroutine originated, even if it crashes far away from its creation point.

### 5.6.2 The SIGSEGV Handler
If a goroutine overflows its stack and hits the Guard Page, the custom `SIGSEGV` handler (`src/runtime/segv.rs`) intercepts the fault.

1.  **Classification**: The handler checks if the fault address falls within the current goroutine's stack (or any of its grown stack regions).
2.  **Frame Walking**: It walks the RBP (Base Pointer) chain to extract the PC (Program Counter) for each active function frame.
3.  **Symbolization**: It uses a built-in DWARF parser to translate the raw PCs into human-readable function names, files, and line numbers.
4.  **Reporting**: It prints a Go-style stack trace, including the specific `go!()` spawn site, before cleanly exiting with code 2.

```text
goish: runtime error: stack overflow

goroutine 1 [running]:
fibonacci(...)
	examples/fib.rs:10 +0x42
main(...)
	examples/fib.rs:25 +0x14

created by examples/fib.rs:20 (go!())
	g.stack: 0x...-0x... (2048 bytes, home)
	fault: SIGSEGV at 0x... (PC=0x... SP=0x...)

remedy:
	bump the spawn-site stack:    go!(stack(64 * KB), || ...)
	or wrap recursion to grow:    runtime::sched::maybe_grow_step(|| ...)
```

This guarantees that a stack overflow will immediately halt execution and provide actionable diagnostics rather than silently corrupting memory.

### Lab Exercise 5.6: Triggering a Traceback
1. Write a deeply recursive function that intentionally exhausts its stack.
2. Run the program.
3. Observe the Go-style traceback printed to the console. Can you identify the exact file and line number where the overflow occurred, as well as where the goroutine was spawned?

---

