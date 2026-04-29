# goish

**A Go-style standard library and runtime, implemented in `no_std` Rust on top of raw Linux syscalls.**

No `glibc`, no `std`, no Tokio. Goish ships its own `_start`, page allocator, size-class heap, M:N scheduler, channels, `select!`, `sync` primitives, async preemption, and ~30 ports of Go's standard library packages — all in one statically-linked binary.

```rust
use goish::{go, KB};
use goish::sync::WaitGroup;

#[goish::main]
fn main() {
    let wg = &WaitGroup::new();
    wg.Add(1_000_000);

    for i in 0..1_000_000 {
        // 2 KiB stack, sub-page allocated from the chunked stackpool.
        go!(stack(2 * KB), move || {
            do_work(i);
            wg.Done();
        });
    }

    wg.Wait();
}
```

That's a million real goroutines on 13 OS threads, ~2 GiB virtual / ~2.4 GiB peak RSS. ([demo](#1-million-goroutines-demo))

---

## Status

Active development. `main` is green: 360/360 across 12 stress examples, 1500/1500 on `sched_park`, 1000/1000 on `sync_waitgroup` at the new 2 KiB default.

Goish is **single-target**: `x86_64-unknown-linux-gnu`. Other targets are deliberately out of scope.

## What's implemented

### Runtime
- **G/M/P scheduler** ported verbatim from Go 1.25's `runtime/proc.go`:
  - Per-P lock-free SPMC run queue (256 entries) + global overflow.
  - Coprime-permuted work stealing (`runqgrab`/`runqsteal`/`stealOrder`).
  - `gogo` / `mcall` asm trampoline (`runtime/asm_amd64.s:404,427` shape).
  - Idle-M parking via futex + per-M `Note`.
- **Async preemption** (M18b): SIGURG handler with per-M `sigaltstack`, handler-direct G-stack write at `[sp - 144]`, sysmon-driven force-preempt + cooperative-preempt safe points.
- **TLS-backed M discovery**: `arch_prctl(ARCH_SET_FS)` for the main thread, `CLONE_SETTLS` for workers. `current_m()` reads `%fs:0` with one mov.
- **GOMAXPROCS**: sized from `sched_getaffinity(2)`; one P per CPU.

### Memory
- **Page allocator** (`mheap`): radix-tree port of Go's `runtime/mpallocbits.go` — leaf summaries, four-level summary tree, demand-paged metadata via raw `mmap`.
- **Size-class heap** (`mcentral`): 67 size classes from Go's `internal/runtime/gc/sizeclasses.go`. Lock-free hot path via atomic `alloc_bits` + Go-style `allocCache` discipline (`runtime/mcache.go:14`).
- **Per-P mcache**: cached span per size-class; mcache hot path takes no central lock.
- **Chunked stack pool**: Go's `stackpoolalloc` (`runtime/stack.go:194`) port — sub-page 2 KiB / 4 KiB / 8 KiB / 16 KiB / 32 KiB stacks carved from 32 KiB spans. True 2 GiB virtual at 1M goroutines.

### Concurrency primitives
- **Channels** (`gochan.rs`): unbuffered, buffered, nil, close. Intrusive doubly-linked sudog wait queues — zero allocator round-trips on park/unpark.
- **`select!` macro** (M16f-β): multi-way send/recv with default, full multi-M lock order, CAS-claim for select winner/loser detection.
- **`sync.{Mutex, RWMutex, WaitGroup, Once}`** plus internal `Sema` — all built on an alloc-free intrusive G chain.
- **`time.{Sleep, NewTimer, NewTicker, After}`** + sysmon-driven timer heap.

### Standard library ports (Go 1.25-faithful)
`bufio`, `bytes`, `context`, `encoding/{binary, hex, base64, json}`, `errors`, `flag`, `fmt`, `io`, `log`, `maps`, `os`, `path`/`path/filepath`, `reflect` (3 tiers), `slices`, `strconv` (ints + bool + floats), `strings`, `sync`, `sync/atomic`, `testing`, `time`, `unicode/utf8`. Plus `make!` / `slice!` / `append!` / `range!` / `defer!` / `select!` / `go!` macros.

### Public API discipline
Public Go-API surfaces use lowercase types: `string` (gostring), `slice<T>` (goslice), `map<K, V>` (gomap), `chan<T>` (gochan), `byte`, `rune`, `int`. `Vec<u8>`, `String`, `&str`, `&[u8]` are explicitly absent from public signatures — converted at the boundary via zero-cost wrappers.

---

## Build & run

```bash
cargo build --target x86_64-unknown-linux-gnu              # library
cargo build --target x86_64-unknown-linux-gnu --release    # release
cargo build --target x86_64-unknown-linux-gnu --example sched_park
./target/x86_64-unknown-linux-gnu/debug/examples/sched_park
```

Binaries are statically linked, no `glibc`, no `ld.so` — `cat /proc/<pid>/maps` shows only the binary itself plus `mmap`'d arenas.

### Toolchain
- Rust 1.79+ (uses inline-const `[const { Span::new() }; N]` and naked asm).
- Linux x86_64 host. Tests run under the host's kernel.

### Notable build flags (in `.cargo/config.toml`)
```
-C link-arg=-nostartfiles
-C link-arg=-nodefaultlibs
-C link-arg=-static
-C relocation-model=static
panic = "abort"        # both dev and release
```

---

## 1-million-goroutines demo

```bash
cargo build --target x86_64-unknown-linux-gnu --release --example spawn_million
./examples/spawn_million.sh
```

Sample output (16-core x86_64, kernel 6.8):

```
ts  vmsize_kb  vmrss_kb  vmpeak_kb  vmhwm_kb  threads
  0s    1105148      44800    1108444      49024   13   ← baseline
  1s    2116924    1271680    2126588    1276288   13   ← spawning
  2s    3069660    2406528    3069660    2406528   13   ← 1M parked
 30s    3069660    2406528    3069660    2406528   13   ← steady-state
 32s    3015964    2348044    3069660    2406528   13   ← released
```

~2.4 KiB peak RSS per goroutine at sub-page density.

---

## Architecture, in brief

```
┌──────────────────────────────────────────────────┐
│  user code  (#[goish::main])                     │
│    go!() · chan! · select! · sync · time · …     │
├──────────────────────────────────────────────────┤
│  runtime::sched   G/M/P · runq · stealing        │
│  runtime::preempt SIGURG handler · trampoline    │
│  runtime::sysmon  timer heap · force-preempt     │
├──────────────────────────────────────────────────┤
│  runtime::sched::stackpool   2K..32K span pool   │
│  runtime::mcentral           67 size classes     │
│  runtime::mheap              page allocator       │
├──────────────────────────────────────────────────┤
│  syscall (mmap, futex, clone, rt_sigaction, …)   │
└──────────────────────────────────────────────────┘
                         ↓
              raw `int 0x80` / `syscall`
```

Single static binary. No dynamic linker. No libc runtime.

The book in `doc/` walks through the implementation chapter by chapter — bootstrap, types, memory, scheduler, channels, async preemption.

---

## Comparison

|                        | goish                  | Go                       | Pure Rust async       |
|------------------------|------------------------|--------------------------|-----------------------|
| Concurrency            | M:N, stackful Gs       | M:N, growable stacks     | stackless futures     |
| Stack/G                | 2 KiB sub-page         | 2 KiB growable           | one Future per task   |
| Preemption             | SIGURG (async)         | SIGURG (async)           | cooperative `.await`  |
| 1M goroutines          | ✅ (2 GiB virtual)     | ✅ (2 KiB-grow each)     | requires runtime tuning |
| Standalone binary      | ✅ no glibc, no ld.so  | ✅ static linkable       | needs `std`           |
| GC                     | none (manual mheap)    | concurrent mark+sweep    | none                  |

Goish is **not** a clone of Go — it ports the runtime *idioms* into a Rust ownership model. The trade-off is no growable stacks (no compiler hooks for `morestack`) and no GC. Per-G stack size is user-controlled via `go!(stack(N), …)` with a 2 KiB default.

## License

Dual-licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
