# Chapter 7: The Netpoller: Bridging Epoll and Goroutines

One of the greatest achievements of the Go runtime is making non-blocking I/O look like blocking I/O. In standard Go, when you call `conn.Read()`, your goroutine might pause, but you don't write any callbacks or state machines. The **Netpoller** handles this magic behind the scenes.

In **Goish**, we implement a slim port of Go's `netpoll_epoll.go` to achieve the same result in a `no_std` Rust environment.

## 7.1 The EAGAIN Problem

In a traditional systems program, if you set a socket to non-blocking mode and try to read from it before data has arrived, the kernel returns an error: `EAGAIN` (Resource temporarily unavailable).

A naive way to handle this is to loop:
```rust
loop {
    let n = syscall::Read(fd, buf, len);
    if n != -EAGAIN { break; }
}
```
This is a **busy-wait**, which wastes 100% of a CPU core doing nothing. 

In Goish, we solve this by **parking** the goroutine. When `net.Conn` hits `EAGAIN`, it calls `netpoll::block()`, which tells the scheduler: "This goroutine is done for now. Switch to someone else, and don't wake me up until this File Descriptor has data."

## 7.2 Edge-Triggered Epoll Integration

The heart of the Netpoller is the Linux `epoll` subsystem. Goish uses **Edge-Triggered (EPOLLET)** mode, which is the most efficient but also the most complex to implement.

### How it works:
1.  **Lazy Registration**: The first time a socket hits `EAGAIN`, Goish registers the FD with a global `epoll` instance using `EPOLL_CTL_ADD`.
2.  **The `PollDesc`**: Every registered FD has a `PollDesc` structure (`src/runtime/netpoll/mod.rs`). This structure holds an atomic pointer to the goroutine currently waiting on that FD.
3.  **The Park/Ready Cycle**:
    -   The user goroutine calls `gopark`. Its status becomes `Waiting`.
    -   A background thread (or any idle worker) calls `netpoll::poll()`.
    -   When the kernel signals that an FD is ready, `poll()` finds the `PollDesc` for that FD, extracts the parked goroutine, and calls `goready(gp)`.
    -   The goroutine is moved back to the **Run Queue** and eventually resumes exactly where it left off.

## 7.3 Deadlines and Timeouts

Goish supports Go-style deadlines (`SetReadDeadline`, `SetWriteDeadline`).

Unlike standard Rust `async` which requires a complex timer heap integrated into the executor, Goish implements deadlines using a global **Min-Heap** of nanosecond timestamps. 

1.  When you set a deadline, a `DeadlineEntry` is pushed onto the heap.
2.  The `sysmon` (System Monitor) thread scans this heap periodically.
3.  If a deadline has passed, `sysmon` calls `netpoll::unblock()`, which wakes the parked goroutine with a `Timedout` status.
4.  The goroutine resumes and returns the familiar `net: i/o timeout` error to the user.

*   **Goish vs. Go**: Go's Netpoller is tightly integrated with the runtime's "timer" subsystem. Goish uses a simpler, sysmon-driven heap that avoids the need for per-P timer lists in v1, making it easier for students to study.
*   **Goish vs. Rust**: Pure Rust often relies on `mio` or `tokio` to handle epoll. Goish shows how to build this from scratch using raw `syscall::EpollWait`, providing a transparent look at how an async runtime actually talks to the kernel.

---

### Lab Exercise: Monitoring the Poller
1.  Run a Goish HTTP server.
2.  Use `strace -p <pid> -e epoll_pwait` to watch the runtime interaction with the kernel.
3.  Observe how the runtime blocks in `epoll_pwait` when there is no work to do, and wakes up instantly when a packet arrives.
