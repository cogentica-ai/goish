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
