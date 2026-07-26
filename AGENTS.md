# goish agent reminders

This file captures the project conventions so that any coding agent
can discover them. **Scope: the goish runtime itself** (`goish-v1/`).

## Working directories (read first)

Repo layout (under `/home/chanwit/Dropbox/projects/goro-workspace/`):

```
goish-v1/                         ← this repo (the goish runtime)
├── src/                          runtime
├── examples/                     e2e examples
├── goish-macros/                 proc-macros (#[goish::main],
│                                  goish::interface, goish::var!, …)
├── doc/                          chapter drafts (untracked, in progress)
├── DISCUSSION_VAR.md             ← Doctrine 2 design record
├── AGENTS.md                     ← this file
└── CLAUDE.md                     `@AGENTS.md` redirect
```

### Important paths

| Path | Purpose |
|---|---|
| `/home/chanwit/Dropbox/projects/goro-workspace/goish-v1/` | goish runtime (this repo) |
| `/nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/` | Go 1.25 SDK source — consult before designing an API |

### Test commands

| Command | What it does |
|---|---|
| `cargo check --lib` | typecheck goish runtime |
| `cargo build --examples` | build all e2e examples |
| `make e2e` | **tiered**: each example at its own loop count |
| `make e2e-full` | everything x50 — required for runtime-core changes |
| `make e2e LOOPS=1` | force one run each (uniform; overrides tiers) |
| `make e2e LOOPS=10 FILTER='^chan_'` | stress one family |

#### e2e loop tiers — the loop count is a property of the TEST

`make e2e` runs each example at the tier its own subject matter needs
(classified in `scripts/e2e_runner.sh`'s `loops_for`):

| Tier | Loops | What belongs there |
|---|---|---|
| functional | 1 | deterministic: parsers, crypto, json, unicode, http parsing |
| memory | 10 | `alloc_*`, `mheap_*`, `mcentral`, `leak_proof`, introspection |
| races/stress | 50 | chan/select, preempt, sched, sync, timers, stacks, server lifecycle (shutdown/keepalive/goginx), TLS conns |

Two rules go with it:

- **Adding an example that touches goroutines, timers, sockets or
  server lifecycle? Add it to the tier-3 patterns.** Unmatched names
  default to tier 1, and a race test that runs once is not a test.
  Tier 3 stays at 50 deliberately: the historical lost-wakeup bug
  reproduced ~2% of the time, so 10 loops would hide it ~80% of the
  time.
- **Changing the scheduler, allocator, or anything in `runtime/`?
  `make e2e-full` (all x50), not `make e2e`.** Those bugs surface in
  tests that look unrelated to the change — per-test tiers are not
  enough there.

Tests that reach the real internet (`NETWORK_FLAKY` in the runner —
currently `https_real_smoke`) tolerate timeouts as long as at least one
iteration passes and nothing panics; anything else is a real failure.

### Conventions

- **goish-v1 is a git repo.** All runtime + example changes commit here.
- **Doc files in `goish-v1/doc/` are intentionally untracked.** Per
  recent commit conventions (e.g. `92d80b5`, `b702cb7`), goish source
  commits explicitly exclude `doc/*.md`.

## Reference docs at ../goishc/

Detailed Go↔Goish language-mapping + runtime-surface references live
at `/home/chanwit/Dropbox/projects/goro-workspace/goishc/` (sibling to
this repo; not a git repo). **Consult them before designing runtime
additions — the answer is often already documented.**

### Quick lookup

| If you're asking… | Read |
|---|---|
| "Where do I start? What docs exist?" | [INDEX.md](../goishc/INDEX.md) — 50 lines, links everything below |
| "How does Go construct X lower to Goish?" | [SYNTAX_MAPPING.md](../goishc/SYNTAX_MAPPING.md) — master phrasebook, 32 sections, ~250 row entries |
| "What public API does goish-v1 actually offer?" | [RUNTIME_SURFACE.md](../goishc/RUNTIME_SURFACE.md) — verified ground-truth from `src/` |
| "What's settled doctrine for runtime additions?" | [CONVERSION_RULES.md](../goishc/CONVERSION_RULES.md) — 29 sections, the rulebook |
| String / []byte / []rune patterns | [STRINGS_AND_BYTES.md](../goishc/STRINGS_AND_BYTES.md) |
| chan / select / send / recv / close | [CHANNELS_AND_SELECT.md](../goishc/CHANNELS_AND_SELECT.md) |
| Struct/slice/array/map literal forms | [COMPOSITE_LITERALS.md](../goishc/COMPOSITE_LITERALS.md) |
| Generics, type sets, `~T`, comparable | [GENERICS.md](../goishc/GENERICS.md) |
| goto / fallthrough / labels / named-return / if-init | [CONTROL_FLOW.md](../goishc/CONTROL_FLOW.md) |
| Defer + capture-by-move trap | [DEFER_DEEP.md](../goishc/DEFER_DEEP.md) |
| Wrapping arithmetic, int defaulting (i32 vs i64) | [NUMERIC_CONVERSIONS.md](../goishc/NUMERIC_CONVERSIONS.md) |
| Range over func (Go 1.23 iterators) | [RANGE_OVER_FUNC.md](../goishc/RANGE_OVER_FUNC.md) |
| Reflection through `Arc<dyn AnyReflect>` | [ANYREFLECT.md](../goishc/ANYREFLECT.md) |
| iota expansion + const blocks | [IOTA_SEQUENCES.md](../goishc/IOTA_SEQUENCES.md) |
| Package init ordering, eager-vs-lazy vars | [INIT_ORDERING.md](../goishc/INIT_ORDERING.md) |
| What gets rejected (cgo / complex / unsafe-ptr) | [FFI_BOUNDARIES.md](../goishc/FFI_BOUNDARIES.md) |
| Go 1.25 input language reference | [GO_LANGUAGE.md](../goishc/GO_LANGUAGE.md) |
| Rust Edition 2024 output reference | [RUST_LANGUAGE.md](../goishc/RUST_LANGUAGE.md) |
| Goish runtime surface overview | [GOISH_RUNTIME.md](../goishc/GOISH_RUNTIME.md) |

### Workflow hint

When you hit a runtime / language-mapping question:

1. **Search the table above** for the closest match.
2. **Read the linked doc** — they're 300–1500 lines each, scannable via
   headings, with a "What v1 must hold in mind" summary at the bottom.
3. **If the doc is wrong / outdated**, fix it (they're living docs).
4. **If the doc says "deferred" or "open"**, that's a known gap; either
   implement the listed plan or accept the documented limitation.

**Reading INDEX.md first tells you what exists.**

## 1. Consult Go 1.25 source when designing APIs

When designing any Go API, verify signatures, semantics, and edge
cases against the actual Go source at
`/nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/`
rather than reasoning from memory. Read the Go file before you write
the goish version.

→ For the *language-level* surface (statements, expressions, types) see [`../goishc/GO_LANGUAGE.md`](../goishc/GO_LANGUAGE.md). For the canonical Go↔Goish row-by-row mapping, [`../goishc/SYNTAX_MAPPING.md`](../goishc/SYNTAX_MAPPING.md) is the lookup table.

## 2. User-facing Go idioms + Rust safety are top priorities

Public API surface should read like Go:
- Lowercase types: `string`, `slice<T>`, `byte`, `rune`, `int`
- Free-function builtins: `len`, `cap`, `make`, `append`, `copy`, `string()`, `bytes()`, `runes()`
- `range!(x)` macro — **hard rule, see below**
- Multi-return tuples

Internal implementation must rely on Rust ownership / borrow-check, not unsafe-by-default. No shared mutable backing across slice handles, no leaking `&str` / `&[u8]` into public signatures except where unavoidable.

### 2a. No `as <type>` casts — use goish types

Never use Rust's `as` cast syntax (e.g., `x as usize`, `y as int`) in goish code. Goish defines its own type equivalents; use those instead. If a cast is needed, use the goish-provided conversion functions or types. This keeps the code looking like Go, not Rust.

### 2b. `range!()` is mandatory — if it doesn't work, fix the runtime

**Hard rule:** All iteration over goish collections (`slice<T>`, `map<K,V>`, `string`) **must** use `for (i, v) in range!(collection)`.

If `range!()` fails to compile for a given type or context (e.g., `range!(&node.childNodes)` produces `&&slice<T>` which lacks a `RangeIter` impl), **do not** work around it with raw Rust `for` loops, `.iter()`, or index-based `for i in 0..len`. Instead:

1. **Stop immediately.**
2. **Identify the missing `RangeIter` impl** or macro issue.
3. **Fix the goish runtime** (in `src/range.rs` or the relevant type module).
4. **Only continue once the runtime fix lands.**

This keeps all goish code uniform and benefits every future consumer of that type. Working around `range!()` fragments the codebase and defeats the purpose of a Go-like runtime.

→ For the full RangeIter trait + every yielded type per impl see [`../goishc/RUNTIME_SURFACE.md` §8](../goishc/RUNTIME_SURFACE.md). For Go 1.23 range-over-func iterators (a separate runtime addition), see [`../goishc/RANGE_OVER_FUNC.md`](../goishc/RANGE_OVER_FUNC.md).

## 3. NO Rust container types in public Go-API signatures

The following must not appear in return or parameter types of any public function mirroring a Go API:

| Go type     | goish public type      | NOT this                     |
|-------------|------------------------|------------------------------|
| `string`    | `string` (gostring)    | `String`, `&str`             |
| `[]byte`    | `slice<byte>`          | `Vec<u8>`, `&[u8]`, `&mut Vec<u8>` |
| `[]T`       | `slice<T>`             | `Vec<T>`, `&[T]`             |
| `map[K]V`   | `map<K, V>` (gomap)    | `BTreeMap`, `HashMap`        |

Conversion at the boundary is zero-cost:
- `slice::__from_vec(v)` wraps an existing `Vec<T>` without copying
- `string::from_bytes(&buf)` builds a goish string from any byte source

Internal scratch buffers should still be `Vec<T>`, but **convert at the return site** before handing back to user code.

Before declaring `pub fn` complete, grep the signature for `Vec<`, `String`, `&str`, `&[`. If any appear in a public goish API, that's a violation and must be fixed.

→ For the full reasoning + every banned/allowed Rust idiom in public API see [`../goishc/RUST_LANGUAGE.md` §9–18](../goishc/RUST_LANGUAGE.md). For string/[]byte conversion patterns specifically, see [`../goishc/STRINGS_AND_BYTES.md`](../goishc/STRINGS_AND_BYTES.md).

## 4. String parameters must be generic over `Into<string>`

Any user-facing `pub fn` that *accepts* a `string` must take `impl Into<string>` (or named generic `S: Into<string>`) instead of bare `string`. The `string` here is **goish's `string`** (`crate::string`), not Rust's `String`. This lets call sites pass `&'static str` literals directly.

```rust
pub fn Get<K: Into<string>>(&self, key: K) -> string {
    let k = key.into();
    // ...
}

pub fn Set<K: Into<string>, V: Into<string>>(&mut self, key: K, value: V) { }
```

**Return types stay `string`** — only parameters get the generic.

### Internal Rust helpers — relaxed rule

For **internal Rust helper functions** that are not part of the public Go API surface (e.g. private `fn`, `pub(crate)` helpers, builder internals), we relax the restriction. You may use `impl Into<String>` (Rust's `String`) when the parameter will be converted to `String` internally and the function is not meant to be called with goish `string` types. This avoids an extra `string → String` hop when the helper immediately needs a Rust `String`.

Two prerequisite impls in `gostring.rs` must stay:
- `impl From<&str> for string` — literal-coercion path
- `impl From<&string> for string` — borrow-friendly clone

**Struct-literal field assignment gap**: Rust does not auto-call `From` for field values, so `Cookie { Name: string("sid"), … }` still requires explicit wrap. Constructor methods or builder macros are the path forward.

**`json::Value` From impls**: `From<&str>`, `From<string>`, `From<bool>`, `From<f64>`, `From<int>` are wired so `obj.Set("k", "v")` and `obj.Set("count", 42_i64)` materialise as JSON nodes directly.

→ For the full `Into<string>` rule with method/generic-stack interactions and edge cases see [`../goishc/SYNTAX_MAPPING.md` §5](../goishc/SYNTAX_MAPPING.md). For struct-literal field-assignment patterns including the `string("sid")` wrap, see [`../goishc/COMPOSITE_LITERALS.md` §1.3–1.4](../goishc/COMPOSITE_LITERALS.md).

## 5. Go-shape structs — field layout must match Go exactly

When modelling a Go struct, **preserve the exact field layout** from the Go source. Do not redesign the struct to fit Rust patterns.

### What "Go-shape" means

| Go | goish | WRONG |
|---|---|---|
| `mu *sync.Mutex; logFile *os.File` | `mu: sync::Mutex, logFile: os::File` | `mu: sync::Mutex<os::File>` (bundles two fields into one) |
| `var Instance Writer` (global) | `pub static Instance: ...` or `pub` field | `GetInstance()` / `SetInstance()` accessor pair |
| `URL func(u *url.URL) string` | Use raw function type or fill the runtime gap | `pub URL: Option<Arc<dyn Fn(...)>>` (Rust trait object in public field) |
| `type foo struct{}` | `pub struct foo {}` | `pub struct Foo {}` (renames to Rust convention) |

### Rules

1. **No bundling.** Go has two fields → goish has two fields. Never combine them into a generic `Mutex<T>` or `Arc<RefCell<T>>`.
2. **No accessor ceremony.** Go exposes a field directly (`var Instance Writer`) → goish exposes it directly (`pub static Instance` or `pub Instance`). No `GetInstance()` / `SetInstance()` wrappers.
3. **No Rust trait objects in public struct fields.** `Arc<dyn Fn(...) -> T + Send + Sync>`, `Box<dyn Trait>`, `Rc<dyn ...>` are all banned from public struct definitions. They leak Rust's memory model and trait system into the Go API.
4. **If Go has a function-valued field** (`URL func(...)`) and goish has no equivalent, **fill the runtime gap** rather than exposing `dyn Fn`. In the interim, use the simplest possible representation (raw `fn(...)` pointer if no closure capture is needed, or a module-private wrapper) and document the limitation.
5. **Keep Go names.** `fileLogger` stays `fileLogger`, not `FileLogger`. `logFile` stays `logFile`, not `log_file`.

### Why this matters

The goal is that a Go programmer reading the Rust source can map it 1:1 to the Go original. When we redesign structs for Rust idioms, we lose that traceability and make maintenance harder.

→ For all 25 composite-literal forms (positional, keyed, partial, nested elision, sparse-keyed, embedded, address-of) see [`../goishc/COMPOSITE_LITERALS.md`](../goishc/COMPOSITE_LITERALS.md). For the function-valued-field "private box" pattern see [`../goishc/CONVERSION_RULES.md` §7.2](../goishc/CONVERSION_RULES.md). For generic structs (`type Set[E comparable]`) see [`../goishc/GENERICS.md` §3.2](../goishc/GENERICS.md).

## 6. Polymorphic `nil` — single sentinel, multiple types

Goish's `nil` is a `Nil` ZST (`pub const nil: Nil` at lib root) with per-type `From<Nil>` and `PartialEq<Nil>` impls in each nilable module.

**Where bare `nil` works (no `.into()`):**
- Function-arg slot when parameter is `impl Into<T>` or custom dispatch trait
- Equality both directions: `if err == nil { … }`, `if nil != s { … }`
- Generic over `From<Nil>` / `Into<T>` boundaries

**Where `.into()` is required** (Rust language constraint):
- Return position: `fn foo() -> error { nil.into() }`
- Let binding: `let e: error = nil.into();`
- Tuple-return slot: `(value, nil.into())`
- Struct-literal field: `Cookie { name: nil.into(), … }`
- Match-arm value: `match x { _ => nil.into() }`

**Crate-internal typed sentinel**: `errors::nil` is `pub const nil: error = error(None);` for the errors module's own use. External callers use the lib-root polymorphic `nil` plus `.into()`.

**Adding a new nilable type**: in the type's module, add three impls:
```rust
impl From<crate::nilval::Nil> for MyType { fn from(_) -> Self { ... } }
impl PartialEq<crate::nilval::Nil> for MyType { fn eq(&self, _) -> bool { self.is_nil_check() } }
impl PartialEq<MyType> for crate::nilval::Nil { fn eq(&self, other) -> bool { other.is_nil_check() } }
```

→ For per-type polymorphic-nil impls already wired (string, slice, map, chan, error, Arc<dyn Any>, Arc<dyn AnyReflect>, Arc<dyn Fn>) see [`../goishc/RUNTIME_SURFACE.md` §10](../goishc/RUNTIME_SURFACE.md). For nil-comparison rules at use sites see [`../goishc/SYNTAX_MAPPING.md` §27](../goishc/SYNTAX_MAPPING.md).

## 7. Debug and bug hunting using `rr` and `gdb`

Compile with debug symbols (cargo's `dev` profile is fine). Use `rr` to record and replay; use gdb breakpoints + reverse-execution to trace.

### rr setup on this host (i5-1335U, hybrid P+E cores)

Plain `rr record` aborts with `[FATAL ... PerfCounters.cc:488] Got 0 branch events ...` because `PERF_COUNT_HW_BRANCH_INSTRUCTIONS` only registers on the P-core PMU. Workaround: pin to P-cores with `taskset -c 0-3 rr record …` (logical CPUs 0–3 are the two P-cores' SMT threads; E-cores are 4–11).

One-time host setup: `cat /proc/sys/kernel/perf_event_paranoid` should be `≤ 1`.

### `--chaos` for race repro

Plain `rr record` is too serialised to reproduce timing-sensitive races. Use `rr record --chaos` to randomise scheduling. Capture a flake by looping:

```bash
for i in $(seq 1 30); do
  rm -rf ~/.local/share/rr/hang
  taskset -c 0-3 timeout 20 rr record --chaos -o ~/.local/share/rr/hang ./bin >/dev/null 2>&1
  [ $? -ne 0 ] && break
done
```

### Replay protocol (gotchas)

- **Heredoc, not `-batch -x`:** `gdb -batch -x file.gdb` fails with "program not running" because commands run before rr's remote target attaches. Pipe commands via stdin: `rr replay TRACE <<'EOF' ... EOF`.
- **Seek with `-g <event>`** (`rr replay -g 558500 TRACE`); `run 558500` passes argv instead.
- **Type-name pitfalls:** rr-gdb rejects `*(unsigned char*)X` and `*(int*)X`. Use `*(char*)X`, or skip the cast with `x/1bx X` / `x/1gx X`.
- **Hardware watchpoints in reverse: unreliable.** Prefer software BPs at raw instruction addresses (`break *0x21125d`) found via `objdump -d` + `addr2line -e bin -f -C 0x...`. Keep `commands` blocks simple — `silent`, `info registers`, `x/...`, `when`, `bt N`, `continue`. Complex Rust-typed expressions often error.
- **`break <symbol>` may skip the prologue** — gdb maps the symbol to the first source-line PC, not the literal entry. For exact entry, BP at the raw address.
- **Stale binaries fool bisects.** When a test source doesn't exist at a rev, cargo silently builds only the lib and the leftover binary from a prior bisect step gets timed. Always `rm -f target/.../examples/<test>` before each step AND guard with `[ -f examples/<test>.rs ]` before building.
- **Single-thread illusion in replay.** A thread can appear "stuck" in the same frame for hundreds of events because rr's deterministic-replay schedule has paused it; this isn't real-time spin.

See `memory/reference_rr_gdb_recipe.md` for the full playbook with worked examples.

## 8. Errors — `goish::var!` and Doctrine 2 (active doctrine)

The error type is `error` (canonical at `goish::error`, defined in
`src/errors/mod.rs`). Errors-package functions stay in their Go-shape
home: `errors::Is`, `errors::New`, `errors::Wrap`, `errors::As`,
`errors::Unwrap`, `errors::Join`, `errors::ErrUnsupported`.

### Defining sentinel errors

Use `goish::var!` (single-line or block form). Identity-stable markers
emitted by the macro support bare-symbol comparison; conversion needs
`.into()` (same discipline as polymorphic `nil`).

```rust
goish::var! {
    pub EOF: error              = "EOF";
    pub ErrShortWrite: error    = "short write";
    /// Unexported (no `pub`) — internal sentinel.
    errInvalidWrite: error      = "invalid write result";
}

// Typed-payload form (brace-grouped expression):
goish::var! {
    pub Canceled: error = { CanceledError };
}
```

For non-error vars, the same macro emits `pub const`:

```rust
goish::var! { pub MaxBufSize: int = 4096; }
```

### Use sites

```rust
// Comparison: bare symbol — no parens, no .into()
errors::Is(err, io::EOF)
if err == io::EOF { ... }
match err { e if e == io::EOF => ... }

// Conversion / storage: .into() needed (same as nil)
let e: error = io::EOF.into();
return (0, io::EOF.into());
Cause { err: io::EOF.into() }

// Public API accepting `impl Into<error>` lets callers pass bare:
fn handle<E: Into<error>>(e: E) { ... }
handle(io::EOF);                    // ✓
handle(errors::New("foo"));         // ✓ reflexive
```

### When adding a sentinel

- **Don't write hand-rolled `pub fn ErrFoo() -> error { ... lazy SpinLock ... }`.**
  Use `goish::var!` instead.
- **Don't use `errors::error` qualified.** The bare `error` type (or
  `goish::error`) is canonical; `errors::error` was removed from call
  sites in commit `8515436`.
- The macro doesn't allow same-name `pub fn` and `pub const` to coexist
  in the same module. Each module migrates as a unit (see
  `DISCUSSION_VAR.md` §13 if relevant).
- `syscall::Errno` (typed errors with custom semantic `Is()`) is a
  different shape — deferred.

Background: `DISCUSSION_VAR.md` at the repo root captures the full
design rationale (three doctrines, why Doctrine 2 won, the trait-
bound widening on `errors::Is`, the migration plan).

→ For the full error API surface (`ErrorTrait`, `New`, `Is`, `As`, `Unwrap`, `Wrap`, `Join`, sentinels), see [`../goishc/RUNTIME_SURFACE.md` §14](../goishc/RUNTIME_SURFACE.md).

## 9. Interfaces — `#[goish::interface]` and `goish::cast!`

Go interfaces are modelled with the `#[goish::interface]` attribute on
a `trait` declaration. It emits the nil sentinel, the `Send + Sync`
supertraits, the per-trait downcast registry, and the `&T` / `&mut T`
forwarding blankets.

- Interface-typed **borrow params** must spell the full
  `&(dyn Trait + Send + Sync + 'static)` — `dyn Trait` alone does not
  match the macro-emitted `impl … for dyn Trait + Send + Sync`.
- Interface methods must return **owned** types, not borrows — the
  macro's `Hook<dyn Trait>` forwarding impl can't return a value
  borrowed from inside its lock guard.
- `goish::cast!(carrier, Iface)` is Go's comma-ok type assertion
  `v, ok := x.(Iface)` — yields `(&dyn Iface, bool)`; on a miss the
  value is a nil-interface sentinel whose methods panic.

See `memory/project_http_responsewriter_interface.md` for the worked
example (`net/http` ResponseWriter).
