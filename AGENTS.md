# goish agent reminders

This file captures the project conventions from `.claude/goish-reminder.md` so that any coding agent can discover them.

## 1. Consult Go 1.25 source when porting APIs

When designing or porting any Go API, verify signatures, semantics, and edge cases against the actual Go source at `/nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/` rather than reasoning from memory. Read the file you're porting from before you write the goish version.

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
3. **Propose a fix to the goish runtime** (in `src/range.rs` or the relevant type module).
4. **Only continue once the runtime fix lands.**

This ensures all ports stay uniform and benefits every future consumer of that type. Working around `range!()` fragments the codebase and defeats the purpose of a Go-like runtime.

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

## 5. Go-shape struct ports — field layout must match Go exactly

When porting a Go struct, **preserve the exact field layout** from the Go source. Do not redesign the struct to fit Rust patterns.

### What "Go-shape" means

| Go | goish port | WRONG |
|---|---|---|
| `mu *sync.Mutex; logFile *os.File` | `mu: sync::Mutex, logFile: os::File` | `mu: sync::Mutex<os::File>` (bundles two fields into one) |
| `var Instance Writer` (global) | `pub static Instance: ...` or `pub` field | `GetInstance()` / `SetInstance()` accessor pair |
| `URL func(u *url.URL) string` | Use raw function type or propose runtime gap | `pub URL: Option<Arc<dyn Fn(...)>>` (Rust trait object in public field) |
| `type foo struct{}` | `pub struct foo {}` | `pub struct Foo {}` (renames to Rust convention) |

### Rules

1. **No bundling.** Go has two fields → goish has two fields. Never combine them into a generic `Mutex<T>` or `Arc<RefCell<T>>`.
2. **No accessor ceremony.** Go exposes a field directly (`var Instance Writer`) → the port exposes it directly (`pub static Instance` or `pub Instance`). No `GetInstance()` / `SetInstance()` wrappers.
3. **No Rust trait objects in public struct fields.** `Arc<dyn Fn(...) -> T + Send + Sync>`, `Box<dyn Trait>`, `Rc<dyn ...>` are all banned from public struct definitions. They leak Rust's memory model and trait system into the Go API.
4. **If Go has a function-valued field** (`URL func(...)`) and goish has no equivalent, **propose a runtime gap** rather than exposing `dyn Fn`. In the interim, use the simplest possible representation (raw `fn(...)` pointer if no closure capture is needed, or a module-private wrapper) and document the limitation.
5. **Keep Go names.** `fileLogger` stays `fileLogger`, not `FileLogger`. `logFile` stays `logFile`, not `log_file`.

### Why this matters

The goal of a port is that a Go programmer reading the Rust source can map it 1:1 to the Go original. When we redesign structs for Rust idioms, we lose that traceability and make maintenance harder.

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

## 7. Picking the next leaf to port — use `goishc deps`

Don't browse `~/go/pkg/mod` by hand. The `goishc deps` subcommand walks a Go module's full transitive dep graph, cross-references against the ports workspace `Cargo.toml`, and ranks candidates.

```bash
cd /home/chanwit/Dropbox/projects/goro-workspace/ports
goishc deps -ready -unported -by-loc /tmp/source-controller
```

Flags:
- `-ready` — modules whose every dep is already ported
- `-unported` — exclude modules already in the workspace
- `-by-loc` — sort ascending by recursive Go LOC (smallest first)
- `-workspace <Cargo.toml>` — explicit ports-workspace path

Output legend: `✓` ported · `▶` ready · `○` pending · `·` no source on disk.

**Inspect imports before committing to a small port.** A 52-LOC leaf can balloon if it pulls in a missing runtime module (e.g. `titanous/rocacheck` needs `math/big` + `crypto/rsa`). Runtime gaps are the priority — never skip them; plan for the extra runtime LOC up front.

## 8. Debug and bug hunting using `rr` and `gdb`

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

## 9. Errors — `goish::var!` and Doctrine 2 (active doctrine)

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

### When porting

- **Don't write hand-rolled `pub fn ErrFoo() -> error { ... lazy SpinLock ... }`.**
  Use `goish::var!` instead.
- **Don't use `errors::error` qualified.** The bare `error` type (or
  `goish::error`) is canonical; `errors::error` was removed from call
  sites in commit `8515436`.
- The macro doesn't allow same-name `pub fn` and `pub const` to coexist
  in the same module. Each module migrates as a unit (see
  `DISCUSSION_VAR.md` §13 if relevant).
- `syscall::Errno` (typed errors with custom semantic `Is()`) is a
  different shape — deferred until source-controller forces it.

Background: `DISCUSSION_VAR.md` at the repo root captures the full
design rationale (three doctrines, why Doctrine 2 won, the trait-
bound widening on `errors::Is`, the migration plan).

## 10. Working directories

Repo layout (all under `/home/chanwit/Dropbox/projects/goro-workspace/`):

```
goro-workspace/
├── goish-v1/                         ← this repo (the goish runtime)
│   ├── src/                          runtime
│   ├── examples/                     137 e2e examples
│   ├── goish-macros/                 proc-macros (#[goish::main],
│   │                                  goish::reflect!, var_emit_error_marker)
│   ├── doc/                          chapter drafts (untracked, in progress)
│   ├── DISCUSSION_VAR.md             ← Doctrine 2 design record
│   ├── AGENTS.md                     ← this file
│   └── CLAUDE.md                     `@AGENTS.md` redirect
│
└── ports/                            sibling workspace, NOT a git repo
    ├── Cargo.toml                    workspace manifest (~46 ports)
    ├── flux_source_controller/       excluded from workspace (2k+ errors)
    ├── go_logr_logr/                 ← shipped 2026-05-04
    ├── Masterminds_semver_v3/
    ├── fluxcd_pkg_*/
    ├── go_openapi_swag_*/
    └── ...                           (see ports/Cargo.toml for full list)
```

### Important paths

| Path | Purpose |
|---|---|
| `/home/chanwit/Dropbox/projects/goro-workspace/goish-v1/` | goish runtime (this repo) |
| `/home/chanwit/Dropbox/projects/goro-workspace/ports/` | port crates workspace |
| `/nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/` | Go 1.25 SDK source — consult before porting |
| `~/go/pkg/mod/` | Go module cache — source for third-party ports |
| `/tmp/source-controller/` | flux source-controller checkout (port target) |

### Test commands

| Command | What it does |
|---|---|
| `cargo check --lib` | typecheck goish runtime |
| `cargo build --examples` | build all 137 e2e examples |
| `make e2e LOOPS=1` | run all examples once each (~30s) |
| `make e2e LOOPS=10 FILTER='^chan_'` | stress one family |
| `cd ../ports && cargo check --workspace` | typecheck all ports |

### Conventions

- **goish-v1 is a git repo.** All runtime + example changes commit here.
- **ports/ is NOT a git repo.** Edits there don't get tracked. If a port
  needs a permanent home, bring it under version control separately.
- **Doc files in `goish-v1/doc/` are intentionally untracked.** Per
  recent commit conventions (e.g. `92d80b5`, `b702cb7`), goish source
  commits explicitly exclude `doc/*.md`.

## 11. Status — what's done (2026-05-04)

### Doctrine 2 + `goish::var!` shipped

- `errors::IsTarget` trait, `errors::Is::<T: IsTarget>` widened
- `error::__ptr_eq` accessor for marker `PartialEq` impls
- `goish-macros::var_emit_error_marker` proc-macro (token-level, no
  `syn`/`quote`/`paste` deps — matches existing crate posture)
- `goish::var!` muncher in `builtin_macros.rs`: 3 arms (string-literal,
  typed-payload-brace, plain-const fallback), recursive munch handles
  arbitrary block size
- `extern crate self as goish;` in `lib.rs` so proc-macro emitting
  `::goish::...` paths resolves inside the goish crate itself

### Stdlib sentinel migration complete

Zero `pub fn Err*() -> error` sentinel functions remain. Migrated:

| Module | Sentinels |
|---|---|
| `errors` | `ErrUnsupported` |
| `io` | `EOF`, `ErrShortWrite`, `ErrUnexpectedEOF`, `ErrShortBuffer`, `ErrNoProgress` |
| `io/fs` | `ErrInvalid`, `ErrPermission`, `ErrExist`, `ErrNotExist`, `ErrClosed` |
| `os` | `ErrInvalid`, `ErrPermission`, `ErrExist`, `ErrNotExist`, `ErrClosed` (also fixed pre-existing identity bug) |
| `context` | `Canceled`, `DeadlineExceeded` (typed-payload form) |
| `bufio` | 9 sentinels |
| `archive/tar` | `ErrHeader`, `ErrFieldTooLong` |
| `testing/iotest` | `ErrTimeout` (typed-payload) |
| `os/exec` | `ErrNotFound` |
| `encoding/csv` | `ErrBareQuote`, `ErrQuote`, `ErrFieldCount` |
| `encoding/json` | `ErrSyntax`, `ErrUnexpectedEnd` |
| `io/pipe` | `ErrClosedPipe` |
| `net/mail` | `ErrHeaderNotPresent` |
| `net/http/chunked` + `httputil` | `ErrLineTooLong` |
| `net/http/server` | `ErrServerClosed`, `ErrBodyNotAllowed`, `ErrHijacked`, `ErrContentLength`, `ErrAbortHandler`, `ErrHandlerTimeout` |
| `net/http/request` | 9 sentinels (4 string + 4 typed-payload + ErrMaxBytes) |
| `strconv` | `ErrSyntax`, `ErrRange` |
| `path` | `ErrBadPattern` |

### Naming standardization

`errors::error` → `error` everywhere. Zero qualified references remain.
The type still lives in `src/errors/mod.rs` with all impls; the canonical
public path is `goish::error` via `pub use errors::error;` at lib root.

### Other fixes shipped this session

- Lib warnings: 98 → 0
- gomap `MapRefIter::next()` mid-bucket skip bug fixed
- `fmt::Sprintf("%+v")` sorts map keys (Go-faithful)
- `os::IsPathSeparator(c uint8) bool` added (unblocked
  `monochromegane_go_gitignore`)
- New examples: `gomap_smoke`, `gomap_range_smoke`, `var_marker_smoke`

### Ports workspace

`cargo check --workspace` from `/home/chanwit/Dropbox/projects/goro-workspace/ports/`
**succeeds for ALL crates** (after this session's fixes — see commit
history). `flux_source_controller` is intentionally excluded from the
workspace; it has 2k+ unrelated errors that are tracked separately.

### Open / deferred

- `#[goish::main]` eager-init pass — defer until a port forces it
- `goish::const!` macro for true compile-time constants — open design
- `iota`-style sequences — separate problem
- `syscall::Errno` typed errors with custom semantic `Is()` — different
  shape than string-message sentinels; defer

### Session commit history

| Commit | What |
|---|---|
| `92d80b5` | gomap iterator + json key-sort + smoke tests |
| `05e3e7b` | All 98 lib warnings → 0 |
| `2690340` | Ship `goish::var!` macro (Doctrine 2 infra) |
| `03215a9` | First-batch sentinel migration (~17 sentinels) |
| `52429ff` | Complete sentinel migration (zero fn-form remain) |
| `8515436` | Standardize call sites on `error` (canonical at goish::error) |
| `ef72dc6` | `os::IsPathSeparator` — unblock final port |

E2e at every commit boundary: **137/137 green**.
