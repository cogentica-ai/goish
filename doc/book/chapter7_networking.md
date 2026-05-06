# Chapter 7: High-Performance Networking

Goish makes non-blocking I/O look like simple synchronous code. This is achieved through the **Netpoller**, which bridges the Linux `epoll` system with the Goroutine scheduler.

## 7.1 The Netpoller: Bridging Epoll and Goroutines

### Lab Exercise 7.1: Monitoring the Poller
1.  Run a Goish network server (e.g., `examples/http_smoke`).
2.  Use `strace -e epoll_pwait` to observe the runtime's interaction with the kernel.
3.  Notice how the runtime blocks only when all goroutines are idle, and wakes up instantly when network data arrives.

---

## 7.2 Network Programming: Listen, Accept, and Dial

Goish provides a high-level `net` package that mirrors Go's API.

### Lab Exercise 7.2: TCP Echo Server
1. Write a program that listens on a port and echoes back any data it receives.
2. Use `go!(move || { ... })` to handle each connection.
3. Use a tool like `nc` (Netcat) to connect to your server and verify it works.

---

## 7.3 Building an HTTP Server

The `net/http` package provides a complete HTTP/1.1 implementation.

### Lab Exercise 7.3: Benchmarking Goish
1.  Run the `examples/http_smoke` test.
2.  Use a benchmarking tool like `wrk` or `ab` to hit your Goish server.
3.  Compare the throughput and latency to a standard Go or Node.js server. Note the memory usage!

---
