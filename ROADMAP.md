# goish v1 — Roadmap

A `no_std`, no-libc, no-GC port of Go's stdlib idioms to Rust. Built
bottom-up, the way Go's stdlib layers itself.

## Phase 1 · Foundation

- **M1**  syscall + `_start` + `#[goish::main]` — hello world, no libc *(done)*
- **M2a** `runtime::alloc` via dlmalloc-rs over mmap *(done)*

## Phase 2 · Core types & I/O

- **M3**  `string` — `Arc<[u8]>` backing, immutable
- **M4**  `slice<T>` — `Vec<T>` backing, subslicing **copies** (see below)
- **M5**  `builtin` — `len`, `cap`, `make`, `append`, `copy`, `new` as Go-shaped free functions
- **M6**  `io` — `Reader`, `Writer` traits + `Copy`, `EOF`
- **M7**  `os` — `File`, `Stdin/Stdout/Stderr`, `Args`, `Exit`, `Open/Create`
- **M8**  `fmt` — `Println!`, `Printf!`, `Sprintf!`, `Fprintf!`, `Errorf!`
  - Verbs: `%s %d %v %t %x %q %%` for milestone, full set as follow-up

## Phase 3 · Practical stdlib

- **M9**  `errors` — `error` trait, `New`, `Is`, `As`, wrapping via `%w`
- **M10** `strings` / `bytes` — split, contains, builder
- **M11** `strconv` — int↔string, float↔string, atoi/itoa
- **M12** `sort` / `slices` / `maps` utilities
- **M13** `time` — `Now`, `Duration`, `Sleep`, `Time` (via `clock_gettime`, `nanosleep`)
- **M14** `sync` — `Mutex`, `RWMutex`, `WaitGroup`, `Once` (via futex)

## Phase 4 · Concurrency

- **M15** goroutines — G/M/P scheduler, `clone(2)` for OS threads
- **M2d** *(parallel)* `tcache` — once threads exist, per-M small-object cache
- **M16** `chan` — channels (rendezvous + buffered), `select`

## Phase 5 · Network & web

- **M17** `net` — TCP/UDP via `socket/bind/listen/accept/connect`
- **M2b/2c** *(parallel)* allocator chunks + arena tiers — needed for HTTP-grade load
- **M18** `net/http` — HTTP/1.1 server, then client
- **M19** `encoding/json` — encoder/decoder over `Reader`/`Writer`

## Phase 6 · Polish

- **M20** `testing` (harness), `log`, `flag`
- Profiling, perf benchmarks vs. Go and Rust+std

---

## Cross-cutting decisions

### No GC — firm
Memory is reclaimed by Rust's `Drop`. No mark-sweep, no write barriers,
no stop-the-world. What replaces each Go pattern:

| Go pattern | goish v1 |
|------------|----------|
| Owned heap value | `Vec` / `Box`, dropped automatically |
| Shared immutable string | `Arc<[u8]>` inside `string` |
| Closure captured by goroutine | Rust `move` + `Send` (compile-time) |
| `chan T` | `T: Send`, sender moves ownership |
| `interface{}` | `Box<dyn Trait>` / `Box<dyn Any + Send>` |
| Cycles | user breaks with `Weak<T>` |

### Slice subslicing semantics
Go's `t := s[1:3]` shares backing memory with `s`. goish-v1's
`slice::slice(low, high)` returns an **independent copy**. Most Go
idioms (read, append) work identically; mutation-propagation through
a subslice must be written explicitly. One-line semantic note in the
`slice<T>` docs, in exchange for keeping Rust's borrow-checker safety.

### `defer`
Rust's `Drop` already gives RAII. We add a `defer!{}` macro for
early-return cleanup that doesn't fit a type's lifetime — same call
site as Go, executed at scope exit via `Drop`-based shim.

### Goroutine stacks — reserve-big, commit-lazy (M29, landed)
Go grows stacks by copying (`morestack`); goish can't — relocating a
Rust stack would require fixing up raw pointers the runtime cannot
see, and stable Rust has no compiler hook for prologue checks. The
stacker-style pivot ladder (`runtime::sched::maybe_grow`) works but
only at annotated call sites. So goish grows the other way, using
what x86-64 Linux gives us for free — abundant virtual address space
with kernel-side lazy commit:

| Spawn form | Stack | For |
|------------|-------|-----|
| `go!(closure)` | 1 MiB `MAP_NORESERVE` reservation + `PROT_NONE` guard page; physical 4 KiB pages committed on touch; recycled via pool + `MADV_DONTNEED` | everyday code — never size a stack |
| `go!(stack(N), closure)`, N ≤ 32 KiB | sub-page carve from the chunked stackpool (no guard, no per-G VMA) | extreme density — 1M-goroutine workloads, where per-G mmaps would exhaust `vm.max_map_count` |
| `go!(stack(N), closure)`, N > 32 KiB | direct mmap + guard page | goroutines needing more than 1 MiB |
| `maybe_grow(red_zone, size, closure)` | scoped pivot region | >1 MiB excursions at a known recursion site |

Overflow past a reservation hits the guard page and the SIGSEGV
handler prints a spawn-site diagnostic (`created by file:line`). The
main goroutine gets an 8 MiB reservation via the same machinery.

### Request contexts — `net/http` × `context` (landed)
Go cancels an inbound request's context when the handler finishes or
the client's connection dies, and threads outbound cancellation
through the transport. goish mirrors all of it:

| Path | Mechanism |
|------|-----------|
| `r.Context()` (server) | per-request `context.WithCancel`; canceled when the response is finished (Go `finishRequest`) |
| client disconnect mid-handler | watcher goroutine probes with `recv(MSG_PEEK \| MSG_DONTWAIT)` — peeking never consumes a pipelined next request — and parks on the netpoller; EOF/reset cancels the ctx. Aborted after the handler via a past netpoll read deadline (Go's `aLongTimeAgo`) and joined before the conn is reused, so the fd's read side has one owner at all times |
| `Client.Timeout` | `Do` re-parents the request under `context.WithTimeout` (Go `setRequestCancel`) — one deadline spans every redirect hop, which also inherit the original ctx |
| outbound ctx cancel | `RoundTrip` fast-fails an already-done ctx, folds `ctx.Deadline()` into the conn deadlines, and a cancel watcher kicks blocked I/O out with past netpoll deadlines; wire errors surface as `context.Canceled` / `DeadlineExceeded` |

`http.TimeoutHandler` composes on top: the wrapped handler runs on
its own goroutine against a buffered writer and observes its budget
through `r.Context().Done()`. The TLS client path gets the same
mid-I/O cancel as plaintext: `RoundTrip` dials the raw conn, arms the
deadline + cancel watcher on the underlying socket, then runs the
handshake — so cancel aborts a stuck handshake or mid-body TLS read.
Not in v1: `Server.BaseContext` / `ConnContext` hooks (the base is
always `Background`).

### Allocator maturation
Phase 2a (today) is sufficient through M14. Higher tiers schedule
against their forcing milestones:

| Tier | Forcing milestone | Reason |
|------|-------------------|--------|
| 2b chunks | M17 / M18 | many large allocations under HTTP load |
| 2c arena  | M17 / M18 | small-object pressure under load |
| 2d tcache | M15 | per-thread requires threads |

---

## What's explicitly out of scope for v1

- `crypto/*`, `database/*`, `image/*`
- Reflection (`reflect`) beyond the minimum `fmt %v` needs
- Compile-time transpiler (separate project; Go→goish-Rust)
- Multi-arch — x86-64 Linux only for v1 (aarch64 in v1.x)

---

## Velocity

M3–M8 are each smaller than M2a; expect 1–3 sessions per. M15
(scheduler) and M18 (HTTP) are multi-session. v1 surface ≈ Go's
"tier 1" stdlib packages.
