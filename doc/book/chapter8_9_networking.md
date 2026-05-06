# Chapter 8: Network Programming

With the Netpoller providing a solid foundation, Goish exposes a high-level `net` package that mirrors the Go 1.25 API. This allows developers to write network code that looks and feels like Go, but runs with the zero-dependency, `no_std` efficiency of Goish.

## 8.1 Listen, Accept, and Dial

Goish implements the core TCP primitives in `src/net/mod.rs`.

### The Listening Loop
Creating a server in Goish follows the exact same pattern as Go:

```rust
use goish::{net, string};

let (ln, err) = net::Listen(string("tcp"), string(":8080"));
if err != nil { panic!(err.Error()); }

loop {
    let (conn, err) = ln.Accept();
    if err != nil { continue; }
    
    go!(move || {
        handle_connection(conn);
    });
}
```

### Key Differences:
*   **Strings**: Because goish uses `Arc`-backed strings, we pass `string("tcp")` instead of a raw literal.
*   **Ownership**: Notice the `move` keyword in the `go!` macro. Goish conns are **moved** into the goroutine, ensuring that no other thread can accidentally close the connection while it's being used.

## 8.2 TCP Programming Idioms

Goish conns implement `io::Reader`, `io::Writer`, and `io::Closer`. This means you can use them with any other Goish package like `bufio` or `io`.

*   **Goish vs. Go**: Standard Go uses an interface for `net.Conn`. Goish v1 uses a concrete `struct Conn`, but provides the same method set. This simplifies the implementation for students before they learn about Goish interfaces.
*   **Goish vs. Rust**: In standard Rust, `TcpListener::accept` returns a blocking socket. To make it non-blocking, you must either use an async executor or manually call `set_nonblocking(true)`. In Goish, **every socket is non-blocking by default**, and the runtime automatically parks your goroutine if I/O isn't ready.

---

# Chapter 9: Building an HTTP Server

Goish includes a highly sophisticated `net/http` implementation that enables you to build high-performance web servers with zero external dependencies.

## 9.1 Request/Response Parsing

The `http` package handles the complexities of the HTTP/1.1 protocol.

1.  **Request Parsing (`src/net/http/request.rs`)**: Automatically parses the method (GET, POST), URL, headers, and body from the raw TCP stream.
2.  **Header Management**: Uses a Go-style `Header` map that supports multiple values per key.
3.  **Response Writer**: Provides a `ResponseWriter` interface (as a struct in v1) that buffers output and automatically generates the correct `Content-Length`.

## 9.2 The "Goroutine-per-Connection" Model

Goish HTTP servers use the classic Go concurrency model:
-   The main server loop accepts a TCP connection.
-   It spawns a new **Goroutine** for every single connection.
-   The goroutine parses the request, executes your handler, and sends the response.

Because Goish goroutines only cost **64KB** (and future versions will optimize this), you can handle thousands of concurrent requests without the complexity of a state-machine-based async handler.

### Example: A Simple Hello Server
```rust
use goish::{net, string, fmt};
use goish::net::http;

fn handler(w: &mut http::ResponseWriter, r: http::Request) {
    fmt::Fprintln!(w, "Hello from Goish HTTP!");
}

let server = http::Server {
    Addr: string(":8080"),
    Handler: handler,
};

server.ListenAndServe();
```

*   **Goish vs. Go**: The Goish HTTP server is a "clean room" implementation of the HTTP protocol. It shows students how to build a protocol parser from scratch using only byte-slices and the `io` primitives.
*   **Goish vs. Rust**: Building a `no_std` HTTP server in pure Rust usually requires many crates (`httparse`, `http`, etc.). Goish provides a single, cohesive library that "just works" out of the box.

---

### Lab Exercise: Benchmarking Goish
1.  Run the `examples/http_smoke` test.
2.  Use a benchmarking tool like `wrk` or `ab` to hit your Goish server.
3.  Compare the throughput and latency to a standard Go or Node.js server. Note the memory usage!
