# goish

**Go's standard library and runtime, rebuilt in `no_std` Rust — with a receipt for every line.**

[goish.cogentica.ai](https://goish.cogentica.ai)

Write Go-shaped code — goroutines, channels, `select`, `net/http`, `crypto/tls` — and get a
single statically-linked binary with no `glibc`, no `ld.so`, no garbage collector, and no
language runtime to initialize. Goish ships its own `_start`, page allocator, M:N scheduler,
epoll netpoller and HTTP stack.

- **Traceable crypto.** Every one of the 1709 declarations in `crypto/` names the Go source
  file and line range it was translated from. CI re-opens the Go 1.25.5 tree on every push and
  checks that the citation still resolves. See [Provenance](#provenance).
- **No GC, no libc.** Go's allocator design (mheap / mcentral / per-P mcache, 67 size classes)
  driven by Rust ownership instead of a collector. `ldd` reports *not a dynamic executable*.
- **Stackful goroutines.** Async preemption via SIGURG, work stealing, and a demo that parks a
  million goroutines on 13 OS threads.

```rust
use goish::{go, KB};
use goish::sync::WaitGroup;

#[goish::main]
fn main() {
    let wg = &WaitGroup::new();
    wg.Add(1_000_000);

    for i in 0..1_000_000 {
        // Explicit 2 KiB stack, sub-page allocated from the chunked
        // stackpool - the opt-in for extreme spawn density. Everyday
        // code just writes go!(move || ...) and never sizes a stack.
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

## Provenance

Supply-chain tooling answers where an artifact came from. [SLSA provenance](https://slsa.dev/spec/v1.0/provenance)
is a signed statement about the build: builder identity, source repository, commit hash,
output digest.

That does not describe a reimplementation. When a component is a port, an SBOM records
`goish 0.1.0` and stops. It cannot show whether the AES-GCM in the binary is Go's reviewed
implementation or an approximation of it. Artifact-level provenance is silent about
source-level fidelity, which is the question a rewrite raises.

Goish records the answer per function:

```rust
// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm.go:31-46 newGCM
```

The comment sits directly above the port. `scripts/anchor_check.py` opens the Go 1.25.5 tree
and checks that the cited file and line range still resolve to the symbol named.

| marker | count | meaning |
|---|--:|---|
| `// go: sdk 1.25.5 <file>:<lines> <Symbol>` | 1,956 | translated from Go, citation checked |
| `// go: none — <reason>` | 1,118 | goish-only code, deliberately not a port |
| `// go: waived <decl> — <reason>` | 26 | in Go, left out here, with a reason |

Every ported function falls into one of those three categories, and goishlint fails on one
that carries no marker at all.

### Why this matters in 2026

Regulators are moving toward evidence that is machine-queryable and continuously verified
rather than [assembled for an audit](https://cloudsmith.com/blog/the-2026-guide-to-software-supply-chain-security-from-static-sboms-to-agentic-governance).
Four dates:

| date | what changes |
|---|---|
| **11 Sep 2026** | [EU CRA reporting obligations bind](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting): 24 h early warning and 72 h full notification on actively exploited vulnerabilities. Component-level inventory has to exist beforehand to meet a 24-hour window. Applies to non-EU manufacturers whose products reach the EU market. |
| **21 Sep 2026** | [FIPS 140-2 certificates move to the Historical List](https://www.safelogic.com/blog/what-happens-on-september-21-2026). Existing deployments keep running; a Historical certificate no longer justifies a new federal procurement. |
| **1 Jan 2027** | [CNSA 2.0 becomes the default for new NSS acquisitions](https://www.qusecure.com/cnsa-2-0-pqc-requirements-timelines-federal-impact/), with an exclusive-use requirement for software and firmware signing. |
| **11 Dec 2027** | CRA essential requirements, including the machine-readable SBOM mandate. |

All 35 `crypto/internal/fips140*` packages are ported at 100%, which is the code path Go's own
FIPS 140-3 validation covers, and each function carries the upstream file and line it came
from. Two limits on what that means: goish is not FIPS-validated, and a port of validated code
is not itself validated. It supplies the traceability argument, in a form an auditor can
re-run.

### Verifying the claims

Reproducible from a clean checkout:

```bash
# Every anchor's cited file and line range still resolves in the Go tree.
python3 scripts/anchor_check.py src

# Per-declaration coverage, receiver-qualified (crypto/ reports 1709/1709).
python3 scripts/port_coverage.py crypto --by-decl

# Generate ground truth by running the real Go code, then diff against it.
scripts/goref.sh crypto/tls /path/to/ref.go
```

The first two run in CI on every push ([`provenance.yml`](.github/workflows/provenance.yml)).

One gap: goishlint's `GOISH018` check, which diffs signature, arity and struct fields against
the Go source, lives in a separate binary that is not in this repository. It runs locally
through `make lint` as a ratchet against a per-file baseline, but it is not a CI gate, so that
tier is currently unverifiable from outside.

---

## Who this is for

**Regulated workloads facing the September 2026 deadlines.** FIPS 140-2 certificates go
Historical on the 21st; CRA reporting binds on the 11th. Both push verifiable provenance down
to every dependency, including the ones you did not choose. Goish ports Go's FIPS module and
emits, per function, the Go file and line range it was translated from, re-checked in CI on
every push. See [Provenance](#provenance) for what this does and does not amount to.

**Minimal-attack-surface deployments.** `scratch`/distroless containers, confidential VMs,
Nitro-style enclaves, appliance images. No libc, dynamic linker, interpreter or JIT: the
binary is the whole userspace, so there is less to inventory, patch and attest.

**Edge and embedded Linux.** One static binary, no runtime to install, no GC to tune, and
memory that tracks what you actually touch (a shallow goroutine costs about one page).

**High-density concurrent services.** A million parked goroutines, an epoll netpoller sharded
per-P, and an HTTP server with an allocation-free hot path.

### Not for you (yet)

- **Linux `x86_64` only.** Other targets are out of scope for now.
- **Not security-audited.** The TLS stack is a machine-checked port, but it has had no
  external review and no side-channel analysis. See [SECURITY.md](SECURITY.md).
- **Not all of Go.** `crypto/` is complete. `net`, `encoding` and `os` are partial, and
  outside `crypto/` most ports are name-level rather than anchor-verified; the
  [coverage table](#coverage-measured) marks which is which.
- **Not the Go compiler.** You write Rust that reads like Go, using goish's `string`,
  `slice<T>`, `map<K,V>` and macros. It does not compile `.go` files.

---

## Status

Active development. The e2e suite runs 278 declared examples at tiered loop counts (`make e2e`): deterministic examples once, memory-subsystem examples ×10, and the race-sensitive scheduler/chan/select/sync/timer/server families ×50. `spawn_million` still parks 1M goroutines.

Goish is single-target: `x86_64-unknown-linux-gnu`.

### Testing

Go's `testing` package is ported, so tests are written the Go way: `Test*` functions taking a
`*testing.T`, with subtests, cleanups and `go test`-shaped output.

```rust
use goish::{fmt, strings, syscall, testing};
use goish::gostring::string;
use goish::types::int;

fn TestAddition(t: &mut testing::T) {
    let got: int = 2 + 3;
    if got != 5 {
        t.Error(fmt::Sprintf!("2+3 = %d, want 5", got));
    }
}

fn TestSubtests(t: &mut testing::T) {
    t.Run(string::from_static("upper"), |t| {
        let got = strings::ToUpper(string::from_static("go"));
        if got != string::from_static("GO") {
            t.Error(fmt::Sprintf!("ToUpper(go) = %s, want GO", got));
        }
    });

    t.Run(string::from_static("cleanup"), |t| {
        // Cleanups run LIFO when the test function returns, as in Go.
        t.Cleanup(|| { fmt::Println!("second"); });
        t.Cleanup(|| { fmt::Println!("first"); });
    });
}

#[goish::main]
fn main() {
    let tests: &[(&str, testing::TestFn)] = &[
        ("TestAddition", TestAddition),
        ("TestSubtests", TestSubtests),
    ];
    syscall::Exit(testing::Main(tests) as i32);
}
```

```
=== RUN  TestAddition
--- PASS: TestAddition
=== RUN  TestSubtests
    === RUN  TestSubtests/upper
    --- PASS: TestSubtests/upper
    === RUN  TestSubtests/cleanup
first
second
    --- PASS: TestSubtests/cleanup
--- PASS: TestSubtests

ok	2 tests, 2 passed, 0 failed, 0 skipped
```

That snippet is [`examples/testing_readme.rs`](examples/testing_readme.rs), built and run by
the e2e suite so it cannot drift from the API. `testing.T` carries `Error`/`Errorf`,
`Fatal`/`Fatalf`, `Log`/`Logf`, `Fail`/`FailNow`, `Skip`/`Skipf`/`SkipNow`, `Failed`,
`Skipped`, `Helper`, `Cleanup`, `TempDir`, `Name` and `Run`. `testing/fstest` (47%) and
`testing/iotest` (55%) are partially ported alongside it.

Four things to know before relying on it. The port is name-level: the `testing` root package
sits at 22/149 declarations with **no provenance anchors**, so unlike `crypto/` it is not
diffed against Go — treat it as working code, not a verified port. There is no `testing.B`,
`testing.M`, `testing.F` or `t.Parallel()`, so benchmarks, fuzzing and parallel tests are
out. Tests are registered by hand in a slice rather than discovered, because goish has no
compile-time reflection over modules. And `t.Skip()` currently exits the process instead of
skipping only the current test, which makes it unusable mid-suite.

`cargo test` itself does not work and is not the harness: its test binary links `std`, whose
`panic_impl` lang item collides with goish's own. Tests build as examples and run through
`make e2e`.

### Coverage, measured

`scripts/port_coverage.py` counts, for each Go package, how many of its
declarations have a same-named counterpart here. Coverage is not
verification: an anchor (`// go: sdk 1.25.5 <file>:<lines> <Symbol>`)
lets goishlint open the Go file and diff signature, arity and struct
fields against the port; without one, a name match proves only that a
name matches.

#### `crypto/` — complete, and on the live path

`crypto/` is at **1709/1709 declarations (100%) across all 66 packages**,
counted by receiver-qualified declaration rather than collapsed names,
each carrying a provenance anchor checked against Go 1.25.5. 26
declarations are waived out of the denominator with in-tree
justifications. 24 of those are the QUIC transport surface (`QUICConn`
and the `c.quic` hooks), which is dead code without a QUIC stack; each
`c.quic != nil` arm in the ported handshake code is a documented
deviation at its site.

`crypto/tls` is ported verbatim and is what runs at runtime:
`makeClientHello` through both `clientHandshakeState{,TLS13}.handshake`
drivers, the TLS 1.2/1.3 server (`processClientHello` →
`sendSessionTicket`), Encrypted Client Hello on both ends, session
resumption, renegotiation policy, the post-handshake message
dispatcher, and the `Dialer` surface. `tls.Conn` owns that ported
connection; its `Handshake`, `Read`, `Write` and `Close` are the ported
record loops rather than a second implementation. Methods are pinned
against ground truth generated by running the real Go code
(`scripts/goref.sh`), and an in-memory loopback runs the ported client
and server against each other over TLS 1.3 and TLS 1.2.

| subtree | ported (by name) | `// go:` lines |
|---|--:|--:|
| `crypto` | **1431/1447 (98.9%)** — 100% by declaration | 3041 |
| `net` | 308/1794 (17.2%) | 9 |
| `math` | 307/661 (46.4%) | 5 |
| `encoding` | 210/1018 (20.6%) | 125 |
| `compress` | 122/151 (80.8%) | 0 |
| `os` | 112/366 (30.6%) | 2 |

The right-hand column counts *all* `// go:` lines, which is what
`port_coverage.py` reports. It mixes the 1,956 `sdk` anchors with the
1,118 `none` markers and 195 file-level manifests, so it runs larger than
the number of functions actually traced to Go.

Aggregate: **151 packages with a port, 77 at 100%, 1,956 source anchors.**
The default counter tallies unique names rather than declarations, so Go
methods sharing a name across types collapse; pass `--by-decl` for the
receiver-qualified count.

Two limits on those numbers. Outside `crypto/`, which holds 95% of all
anchors, coverage is name-level: `net` has 9 anchors across 308 ported
functions, and `sync`, `compress`, `archive` and `text` have none, so
treat non-crypto ports as working code rather than verified ports. And
998 anchors name a method without its receiver, so `anchor_check.py` can
confirm the file and line range but cannot bind the symbol uniquely.
`--strict` fails on those; tightening them is open work.

**[PROGRESS.md](PROGRESS.md)** — full coverage detail and what the three
verification tiers mean.

**[ROADMAP.md](ROADMAP.md)** — what is left and in what order. With
`crypto/` complete, the frontier moves to `net`, `encoding` and `os`.

**[CONTRIBUTING.md](CONTRIBUTING.md)** — the conventions a port must follow, and the pre-flight checks to run before starting one.

**[SECURITY.md](SECURITY.md)** — goish is not audited. The TLS stack is
machine-checked against Go but has had no security review and no
side-channel analysis. Read this before trusting goish with anything.

## What's implemented

### Runtime
- **G/M/P scheduler** ported verbatim from Go 1.25's `runtime/proc.go`:
  - Per-P lock-free SPMC run queue (256 entries) + global overflow.
  - Coprime-permuted work stealing (`runqgrab`/`runqsteal`/`stealOrder`).
  - `gogo` / `mcall` asm trampoline (`runtime/asm_amd64.s:404,427` shape).
  - Idle-M parking via futex + per-M `Note`.
- **Async preemption** (M18b): SIGURG handler with per-M `sigaltstack`, handler-direct G-stack write at `[sp - 144]`, sysmon-driven force-preempt + cooperative-preempt safe points. Hardened `m.locks` discipline: the allocator runs preempt-masked (`mallocgc` parity), mask epochs never straddle a park (a `gopark` can resume on a different M), and `acquirem`/`releasem` are single fs-relative asm RMWs so a mid-sequence migration can't charge the wrong M - with a debug-build underflow tripwire.
- **TLS-backed M discovery**: `arch_prctl(ARCH_SET_FS)` for the main thread, `CLONE_SETTLS` for workers. `current_m()` reads `%fs:0` with one mov.
- **GOMAXPROCS**: sized from `sched_getaffinity(2)`; one P per CPU.

### Memory
- **Page allocator** (`mheap`): radix-tree port of Go's `runtime/mpallocbits.go` - leaf summaries, four-level summary tree, demand-paged metadata via raw `mmap`. The arena is a `MAP_NORESERVE` reservation grown on demand, capped at 320 GiB.
- **Size-class heap** (`mcentral`): 67 size classes from Go's `internal/runtime/gc/sizeclasses.go`. Lock-free hot path via atomic `alloc_bits` + Go-style `allocCache` discipline (`runtime/mcache.go:14`).
- **Per-P mcache**: cached span per size-class; mcache hot path takes no central lock.
- **Reserved goroutine stacks** (M29): bare `go!()` gets a 1 MiB `MAP_NORESERVE` virtual reservation with a `PROT_NONE` guard page - the kernel commits physical 4 KiB pages as the goroutine touches them, so nobody sizes a stack and a shallow goroutine costs ~one page. Dead reservations recycle through a pool (`MADV_DONTNEED` drops their pages). Overflow past 1 MiB hits the guard and the SIGSEGV handler prints a spawn-site diagnostic.
- **Chunked stack pool**: Go's `stackpoolalloc` (`runtime/stack.go:194`) port - sub-page 2 KiB / 4 KiB / 8 KiB / 16 KiB / 32 KiB stacks carved from 32 KiB spans, opted into via `go!(stack(N), …)`. True 2 GiB virtual at 1M goroutines.

### Concurrency primitives
- **Channels** (`gochan.rs`): unbuffered, buffered, nil, close. Intrusive doubly-linked sudog wait queues - zero allocator round-trips on park/unpark.
- **`select!` macro** (M16f-β): multi-way send/recv with default, full multi-M lock order, CAS-claim for select winner/loser detection. Accepts expression channels in paren form - `let _ = (ctx.Done()).Recv() => …` is Go's `case <-ctx.Done():`.
- **`sync.{Mutex, RWMutex, WaitGroup, Once}`** plus internal `Sema` - all built on an alloc-free intrusive G chain.
- **`time.{Sleep, NewTimer, NewTicker, After}`** + sysmon-driven timer heap.
- **`context`**: `Background`, `WithCancel` / `WithTimeout` / `WithDeadline` / `WithValue`, `Cause`. `Done()` returns a real `chan<()>` that composes with `select!`; nil for non-cancellable contexts, exactly like Go.

### Networking & web
- **`net`** (M17): TCP/UDP over raw sockets, integrated with an **epoll netpoller** - a blocking `Read`/`Write` parks the goroutine instead of the thread. The poller is sharded **per-P epoll** (nginx-model), with a dedicated blocking-poller M woken via `netpollBreak`, and `SetDeadline` handled by a slab scan - no global heap on the request path. `ListenConfig.Control` + `syscall.RawConn` expose pre-bind socket options (`SO_REUSEPORT` per-CPU listeners work out of the box).
- **DNS resolver**: `LookupHost` / `LookupIP` / `LookupCNAME` / `LookupAddr` / `LookupTXT` / `LookupNS` / `LookupMX` / `LookupSRV` over a port of Go's `dnsclient_unix.go` - `/etc/resolv.conf` config, `dnsmessage` wire format, UDP round-trips through the netpoller.
- **`crypto/tls`**: a verbatim port of Go's, client and server, TLS 1.2 + 1.3, backed by goish's own `crypto/{aes, sha256, ecdh, ed25519, x509, …}` ports. `tls.Conn` owns the ported connection directly, so `Handshake`/`Read`/`Write` are the ported drivers and record loops — no interior locking (Go's `handshakeMutex`/`in`/`out`/`activeCall` become `&mut self`), so a shared conn is locked once, by the layer that shares it. See [SECURITY.md](SECURITY.md).
- **`net/http` server** (M18, production-hardened in M31): HTTP/1.1 with keep-alive, Go 1.22 `ServeMux` patterns (`"GET /users/{id}"` wildcards, GET-matches-HEAD, 405 + `Allow` on method mismatch), composable `Handler` middleware, `Flusher` chunked streaming, `TimeoutHandler`, `FileServer` + range requests, `httputil` reverse proxy, and an **allocation-free hot request path** through `bufio`. `ListenAndServeTLS` / `ServeTLS` serve HTTPS over the TLS 1.3 stack. Deployment-grade operations: `Shutdown(ctx)` draining every tracked listener and idle conn, `Close`, `RegisterOnShutdown`, live `IdleTimeout`, `BaseContext`/`ConnContext`, `ErrorLog`, `Expect: 100-continue`, HEAD body suppression, accept-failure backoff, `TCP_NODELAY` + keep-alive socket defaults, and `signal::NotifyContext` for SIGTERM-triggered graceful drain - see `examples/deploy_rest_api.rs` for the blessed pattern.
- **Live request contexts**: every inbound request carries a cancellable `r.Context()` - canceled when the response finishes, or the moment the client disconnects mid-handler. Disconnect detection is wired at the netpoller `PollDesc` level (probing with `recv(MSG_PEEK | MSG_DONTWAIT)` so a pipelined request is never eaten) - no per-request watcher goroutine.
- **`net/http` client**: `Get` / `Post` / `Do` with redirects, cookies, and a **streaming `Response.Body`** (`io.ReadCloser` shape). `Client.Timeout` re-parents the request under `context.WithTimeout` - one deadline covers every redirect hop - and a mid-flight `ctx` cancel interrupts blocked I/O through the netpoller, surfacing `context.Canceled` / `DeadlineExceeded` like Go's `url.Error` unwrapping.
- **`goginx`** (`examples/goginx.rs`): an nginx clone in Goish - `nginx.conf`-style config, virtual hosts, longest-prefix `location` matching, autoindex, upstream round-robin proxying with next-upstream retry, TLS termination, `listen … reuseport` per-CPU accept loops, access logs, graceful SIGTERM drain.

### Standard library ports (Go 1.25-faithful)
- **Core**: `bufio`, `bytes`, `cmp`, `context`, `errors`, `flag`, `fmt`, `io` + `io/fs`, `log` + `log/slog`, `maps`, `os` + `os/{exec, signal, user}`, `path` + `path/filepath`, `reflect` (3 tiers), `slices`, `sort`, `strconv`, `strings`, `sync` + `sync/atomic`, `syscall`, `testing` (+ `testing/fstest`), `time`, `unicode` (full case mapping) + `unicode/{utf8, utf16}`, `expvar`, `html`, `embed` (`//go:embed` as the `embed!` macro).
- **Encoding**: `encoding/{ascii85, asn1, base32, base64, binary, csv, hex, json, pem}` - including the `encoding/json/v2` + `jsontext` port with compile-time struct codecs.
- **Compression & archives**: `compress/{flate, gzip, lzw, zlib}`, `archive/tar`.
- **Crypto**: `crypto/{aes, cipher, chacha20, chacha20poly1305, des, ecdh, ecdsa, ed25519, hkdf, hmac, md5, pbkdf2, poly1305, rand, rc4, rsa, sha1, sha256, sha3, sha512, subtle, x509}`, plus `crypto/tls` (above) and a minimum-viable `crypto/ssh` SSH-2.0 client.
- **Math, hashing & text**: `math` + `math/{big, bits, rand}`, `hash/{adler32, crc32, crc64, fnv, maphash}`, `container/{heap, list, ring}`, `regexp`, `mime` + `mime/{multipart, quotedprintable}`, `net/{mail, textproto, url}`, `text/tabwriter`.
- **`golang.org/x` ports**: `x/term`, `x/sync/errgroup`, `x/text` (BCP 47 language tags + NFD normalization), plus `xxh3`.
- **Macros**: `make!` / `slice!` / `append!` / `range!` / `defer!` / `select!` / `go!` / `var!` / `cast!` / `embed!`, and `#[goish::interface]` for Go interfaces with comma-ok type assertions.

### Public API discipline
Public Go-API surfaces use lowercase types: `string` (gostring), `slice<T>` (goslice), `map<K, V>` (gomap), `chan<T>` (gochan), `byte`, `rune`, `int`. `Vec<u8>`, `String`, `&str`, `&[u8]` are explicitly absent from public signatures - converted at the boundary via zero-cost wrappers.

---

## Build & run

```bash
cargo build --target x86_64-unknown-linux-gnu              # library
cargo build --target x86_64-unknown-linux-gnu --release    # release
cargo build --target x86_64-unknown-linux-gnu --example sched_park
./target/x86_64-unknown-linux-gnu/debug/examples/sched_park
```

Binaries are statically linked, no `glibc`, no `ld.so` - `cat /proc/<pid>/maps` shows only the binary itself plus `mmap`'d arenas.

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

## goginx: an nginx clone, as the practical example

[`examples/goginx.rs`](examples/goginx.rs) is the showcase app: a single-binary web server / reverse proxy driven by an `nginx.conf`-style configuration file, exercising the whole goish net stack at once.

It speaks an `nginx.conf` subset (upstream pools, `reuseport`/`ssl` listeners, virtual hosts, locations), and the code reads like the Go you'd write for the same job. Three excerpts, verbatim. Multi-return tuples and `if err != nil`:

```rust
fn get(url: string) -> (int, string, string) {
    let (mut resp, err) = http::Get(url.clone());
    if err != nil {
        return (-1, fmt::Sprintf!("get %s: %v", url, err), string(""));
    }
    let (body, _) = io::ReadAll(&mut resp.Body);
    let _ = io::Closer::Close(&mut resp.Body);
    return (
        resp.StatusCode,
        string(body),
        resp.Header.Get("Content-Type"),
    );
}
```

`go!`, channels, `range!`, and `signal.NotifyContext` - the SIGTERM graceful drain:

```rust
/// On SIGTERM/SIGINT: drain every listener via Server::Shutdown.
fn installSignalDrain(servers: slice<Arc<http::Server>>, done: chan<bool>) {
    let (sig_ctx, _sig_stop) = signal::NotifyContext(
        context::Background(),
        &[syscall::SIGTERM, syscall::SIGINT],
    );
    go!(move || {
        let _ = sig_ctx.Done().Recv();
        fmt::Printf!("goginx: signal received, draining\n");
        for (_, s) in range!(&servers) {
            let _ = s.clone().Shutdown(time::Second * 10);
        }
        done.Send(true);
    });
}
```

And the self-test waits on that drain with `select!` - Go's `select` with a timeout arm:

```rust
select! {
    let _ = done.Recv() => {},
    let _ = (time::After(time::Second * 10)).Recv() => {
        fail("drain: timed out waiting for done");
    },
}
```

```bash
cargo build --target x86_64-unknown-linux-gnu --release --example goginx
GOGINX_CONF=goginx.conf ./target/x86_64-unknown-linux-gnu/release/examples/goginx
```

nginx behaviours reproduced: longest-prefix `location` matching, `root` + index files + 301 directory redirects + autoindex listings, MIME by extension, dot-dot traversal rejection, upstream round-robin with 502 when the whole pool is down, `X-Forwarded-*` injection with hop-by-hop header stripping, TLS termination (`listen 8443 ssl;`), access logging, and graceful SIGTERM drain. Run it with no config and it self-tests: builds a doc tree, two upstream backends, and a config in a temp dir, then asserts the lot.

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
│  runtime::netpoll per-P epoll shards · deadlines │
├──────────────────────────────────────────────────┤
│  runtime::sched::stack       1M lazy reservations│
│  runtime::sched::stackpool   2K..32K span pool   │
│  runtime::mcentral           67 size classes     │
│  runtime::mheap              page allocator      │
├──────────────────────────────────────────────────┤
│  syscall (mmap, futex, clone, rt_sigaction, …)   │
└──────────────────────────────────────────────────┘
                         ↓
              raw `int 0x80` / `syscall`
```

Single static binary. No dynamic linker. No libc runtime.

The book in `doc/` walks through the implementation chapter by chapter - bootstrap, types, memory, scheduler, channels, async preemption.

---

## Comparison

|                        | goish                     | Go                       | Pure Rust async       |
|------------------------|---------------------------|--------------------------|-----------------------|
| Concurrency            | M:N, stackful Gs          | M:N, growable stacks     | stackless futures     |
| Stack/G                | 1 MiB reserved, lazy-commit (2 KiB sub-page opt-in) | 2 KiB growable | one Future per task |
| Preemption             | SIGURG (async)            | SIGURG (async)           | cooperative `.await`  |
| 1M goroutines          | ✅ (2 GiB virtual, `stack(2*KB)`) | ✅ (2 KiB-grow each) | requires runtime tuning |
| Standalone binary      | ✅ no glibc, no ld.so     | ✅ static linkable       | needs `std`           |
| GC                     | none (manual mheap)       | concurrent mark+sweep    | none                  |
| Memory safety          | Rust ownership            | GC + runtime checks      | Rust ownership        |
| Per-function provenance to upstream source | ✅ CI-checked, 1,956 anchors | n/a (is upstream) | ✗ |
| Freestanding (`no_std`) | ✅                       | ✗ (needs the Go runtime) | ✅ with `no_std` crates |

Goish is **not** a clone of Go - it ports the runtime *idioms* into a Rust ownership model. Go's `morestack` (grow by copying the stack) is impossible here - relocating a Rust stack would require fixing up raw pointers the runtime cannot see - so goish grows the other way: bare `go!()` reserves 1 MiB of virtual address space per goroutine and lets the kernel commit physical pages on touch. Depth is transparent up to the reservation; physical cost tracks actual use; overflow faults into a guard page with a spawn-site diagnostic. `go!(stack(N), …)` remains the opt-in for sub-page density (the 1M-goroutine demo) or for goroutines needing more than 1 MiB. No GC either way.

## Commercial use & support

goish is permissively licensed (see [License](#license)), so you can ship it in a proprietary
product with no reciprocal obligation and no fee.

Paid work that goes beyond that:

- **Compliance evidence.** Provenance reports mapping a shipped binary back to upstream Go
  source, per function. The anchor data is already in the tree; packaging, attesting and
  signing it for a specific audit is the work.
- **Prioritised porting.** `net`, `encoding` and `os` are partial and anchor-light. Sponsoring
  a package gets it built to the same standard as `crypto/`: anchors, goref-generated ground
  truth, e2e coverage.
- **Support and SLA.** Guaranteed response, upgrade assistance, backports.
- **Integration.** Getting goish onto a specific target (confidential VM, appliance image,
  edge device) and keeping it there.

Commercial enquiries: **[hello@cogentica.ai](mailto:hello@cogentica.ai)** —
[goish.cogentica.ai](https://goish.cogentica.ai)

If you are inside one of the September 2026 windows, it helps to say which packages your
crypto path touches and which auditor or programme you are answering to.

---

## License

goish's own code (runtime, scheduler, allocator, macros, type system) is
**MIT** ([LICENSE](LICENSE)).

Substantial parts of `src/` are ports of the Go standard library and of
`golang.org/x/crypto` / `x/text`, translated function by function from
the Go 1.25 source. Those remain **BSD-3-Clause, © The Go Authors**
([LICENSE-GO](LICENSE-GO)). The 1,956 provenance anchors across 190 files
identify which code that is, so they also answer which files carry the Go
license. Both licenses must travel with any redistribution, source or
binary.

See [NOTICE.md](NOTICE.md) for the details.

goish is not affiliated with, endorsed by, or supported by Google or the
Go project. "Go" is a trademark of Google LLC.
