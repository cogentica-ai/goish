# goish agent reminders

This file captures the project conventions so that any coding agent
can discover them. **Scope: the goish runtime itself** (this repo).

## Repo layout (read first)

```
goish-v1/
├── src/                          runtime
├── examples/                     e2e examples
├── goish-macros/                 proc-macros (#[goish::main],
│                                  goish::interface, goish::var!, …)
├── doc/                          chapter drafts (untracked, in progress)
├── DISCUSSION_VAR.md             ← Doctrine 2 design record
├── AGENTS.md                     ← this file
└── CLAUDE.md                     `@AGENTS.md` redirect
```

### Test commands

**Run the suite on CI, not locally.** `make e2e` is 225 examples, and the
tiered/full modes run the stress families 50x each. Locally, verify with
`cargo check --lib`, `cargo build --examples`, goishlint, and the
individual example binaries a change actually touches. For suite-level
confidence, push and watch:
`gh run watch <id> --repo cogentica-ai/goish --exit-status`.

Two workflows split the cost:

| workflow | when | what it runs |
|---|---|---|
| `e2e.yml` | every push to `main`/`dev`, every PR | `make e2e LOOPS=1` — every example once |
| `e2e-race.yml` | nightly (18:00 UTC) + manual | `make e2e` — per-test tiers, races/stress at 50x |

The per-push gate is deliberately race-free: a ~2%-reproduction bug is
invisible at one iteration, so paying for stress loops there buys
wall-clock, not signal. **After changing the scheduler, allocator, or
anything in `runtime/`, don't wait for the nightly** — dispatch
`e2e-race` manually with `mode: full` (every example x50):

```bash
gh workflow run e2e-race.yml --repo cogentica-ai/goish -f mode=full --ref <branch>
```

Both workflows cancel superseded runs on the same ref, so pushing again
replaces an in-flight run rather than queueing behind it.

| Command | What it does |
|---|---|
| `cargo check --lib` | typecheck goish runtime |
| `cargo build --examples` | build all e2e examples |
| `make lint` | **goishlint ratchet - run before every commit** |
| `make e2e` | **tiered**: each example at its own loop count |
| `make e2e-full` | everything x50 - required for runtime-core changes |
| `make e2e LOOPS=1` | force one run each (uniform; overrides tiers) |
| `make e2e LOOPS=10 FILTER='^chan_'` | stress one family |

#### `make lint` - the backlog may shrink, never grow

`goishlint src` reports ~13.4k findings, so reading its output is not a
check. `scripts/lint_baseline.json` records the count per
**(file, rule)**; `make lint` fails only when a pair goes up.

| Command | What it does |
|---|---|
| `make lint` | fail on NEW findings (`SCOPE=src/crypto` to narrow) |
| `make lint-new` | findings in files absent from the baseline |
| `make lint-update` | re-record after fixing - review the diff |

Two consequences worth knowing before they surprise you:

- **A file not in the baseline must be lint-clean.** New ports start at
  zero and stay there. `make lint-new` is the pre-commit check for a
  file you just wrote.
- **Fixing file A cannot pay for a regression in file B.** Nor can
  moving code between files launder a violation.

The gate runs goishlint's **fidelity tier** (GOISH017/018/019/020/021),
which opens the Go file each anchor cites and diffs it against the port
- a Go func with no ported counterpart, a struct whose fields drifted, a
wrong arity, a dropped type/const/var. These are opt-in in goishlint and
were switched off for this repo's first ~1000 ported functions.

**Unanchored code is invisible to all of it.** GOISH018 only sees fns
that carry a `// go:` anchor, so a package can read 48/49 in
port_coverage while nothing verifies a single declaration - which is
exactly what `fips140/edwards25519` did. `scripts/anchor_by_name.py`
(with `--dry-run`) anchors an already-written port by name, using the
enclosing `impl` block to pick the right Go receiver.

When a deviation is deliberate, **name the symbol in the waiver**:

```rust
// goishlint:ignore GOISH021 ctrAble, aesCtrWrapper — no runtime type assertion
```

The bare `// goishlint:ignore GOISH021 — <reason>` form still works and
still means file-wide, which blinds the file to every *future* dropped
declaration. Prefer the narrow form. Put the waiver next to the prose
that justifies it.

#### e2e loop tiers - the loop count is a property of the TEST

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
  tests that look unrelated to the change - per-test tiers are not
  enough there.

Tests that reach the real internet (`NETWORK_FLAKY` in the runner,
currently `https_real_smoke`) tolerate timeouts as long as at least one
iteration passes and nothing panics; anything else is a real failure.

### Conventions

- **goish-v1 is a git repo.** All runtime + example changes commit here.
- **Doc files in `doc/` are intentionally untracked.** Per
  recent commit conventions (e.g. `92d80b5`, `b702cb7`), goish source
  commits explicitly exclude `doc/*.md`.

## 1. Consult Go 1.25 source when designing APIs

When designing any Go API, verify signatures, semantics, and edge
cases against the actual Go source in a Go 1.25 SDK checkout (e.g.
`$(go env GOROOT)/src`) rather than reasoning from memory. Read the
Go file before you write the goish version.

## 2. User-facing Go idioms + Rust safety are top priorities

Public API surface should read like Go:
- Lowercase types: `string`, `slice<T>`, `byte`, `rune`, `int`
- Free-function builtins: `len`, `cap`, `make`, `append`, `copy`, `string()`, `bytes()`, `runes()`
- `range!(x)` macro - **hard rule, see below**
- Multi-return tuples

Internal implementation must rely on Rust ownership / borrow-check, not unsafe-by-default. No shared mutable backing across slice handles, no leaking `&str` / `&[u8]` into public signatures except where unavoidable.

### 2a. No `as <type>` casts - use goish types

Never use Rust's `as` cast syntax (e.g., `x as usize`, `y as int`) in goish code. Goish defines its own type equivalents; use those instead. If a cast is needed, use the goish-provided conversion functions or types. This keeps the code looking like Go, not Rust.

### 2b. `range!()` is mandatory - if it doesn't work, fix the runtime

**Hard rule:** All iteration over goish collections (`slice<T>`, `map<K,V>`, `string`) **must** use `for (i, v) in range!(collection)`.

If `range!()` fails to compile for a given type or context (e.g., `range!(&node.childNodes)` produces `&&slice<T>` which lacks a `RangeIter` impl), **do not** work around it with raw Rust `for` loops, `.iter()`, or index-based `for i in 0..len`. Instead:

1. **Stop immediately.**
2. **Identify the missing `RangeIter` impl** or macro issue.
3. **Fix the goish runtime** (in `src/range.rs` or the relevant type module).
4. **Only continue once the runtime fix lands.**

This keeps all goish code uniform and benefits every future consumer of that type. Working around `range!()` fragments the codebase and defeats the purpose of a Go-like runtime.

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

**Return types stay `string`** - only parameters get the generic.

### Internal Rust helpers - relaxed rule

For **internal Rust helper functions** that are not part of the public Go API surface (e.g. private `fn`, `pub(crate)` helpers, builder internals), we relax the restriction. You may use `impl Into<String>` (Rust's `String`) when the parameter will be converted to `String` internally and the function is not meant to be called with goish `string` types. This avoids an extra `string → String` hop when the helper immediately needs a Rust `String`.

Two prerequisite impls in `gostring.rs` must stay:
- `impl From<&str> for string` - literal-coercion path
- `impl From<&string> for string` - borrow-friendly clone

**Struct-literal field assignment gap**: Rust does not auto-call `From` for field values, so `Cookie { Name: string("sid"), … }` still requires explicit wrap. Constructor methods or builder macros are the path forward.

**`json::Value` From impls**: `From<&str>`, `From<string>`, `From<bool>`, `From<f64>`, `From<int>` are wired so `obj.Set("k", "v")` and `obj.Set("count", 42_i64)` materialise as JSON nodes directly.

## 5. Go-shape structs - field layout must match Go exactly

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

## 6. Polymorphic `nil` - single sentinel, multiple types

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

## 7. Debug and bug hunting using `rr` and `gdb`

Compile with debug symbols (cargo's `dev` profile is fine). Use `rr` to record and replay; use gdb breakpoints + reverse-execution to trace.

### rr setup on hybrid P+E-core hosts

Plain `rr record` can abort with `[FATAL ... PerfCounters.cc:488] Got 0 branch events ...` on hybrid Intel CPUs because `PERF_COUNT_HW_BRANCH_INSTRUCTIONS` only registers on the P-core PMU. Workaround: pin to P-cores with `taskset -c <p-core list> rr record …`.

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
- **Hardware watchpoints in reverse: unreliable.** Prefer software BPs at raw instruction addresses (`break *0x21125d`) found via `objdump -d` + `addr2line -e bin -f -C 0x...`. Keep `commands` blocks simple - `silent`, `info registers`, `x/...`, `when`, `bt N`, `continue`. Complex Rust-typed expressions often error.
- **`break <symbol>` may skip the prologue** - gdb maps the symbol to the first source-line PC, not the literal entry. For exact entry, BP at the raw address.
- **Stale binaries fool bisects.** When a test source doesn't exist at a rev, cargo silently builds only the lib and the leftover binary from a prior bisect step gets timed. Always `rm -f target/.../examples/<test>` before each step AND guard with `[ -f examples/<test>.rs ]` before building.
- **Single-thread illusion in replay.** A thread can appear "stuck" in the same frame for hundreds of events because rr's deterministic-replay schedule has paused it; this isn't real-time spin.

## 8. Errors - `goish::var!` and Doctrine 2 (active doctrine)

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
    /// Unexported (no `pub`) - internal sentinel.
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
// Comparison: bare symbol - no parens, no .into()
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
  different shape - deferred.

Background: `DISCUSSION_VAR.md` at the repo root captures the full
design rationale (three doctrines, why Doctrine 2 won, the trait-
bound widening on `errors::Is`, the migration plan).

## 9. Interfaces - `#[goish::interface]` and `goish::cast!`

Go interfaces are modelled with the `#[goish::interface]` attribute on
a `trait` declaration. It emits the nil sentinel, the `Send + Sync`
supertraits, the per-trait downcast registry, and the `&T` / `&mut T`
forwarding blankets.

- Interface-typed **borrow params** must spell the full
  `&(dyn Trait + Send + Sync + 'static)` - `dyn Trait` alone does not
  match the macro-emitted `impl … for dyn Trait + Send + Sync`.
- Interface methods must return **owned** types, not borrows - the
  macro's `Hook<dyn Trait>` forwarding impl can't return a value
  borrowed from inside its lock guard.
- `goish::cast!(carrier, Iface)` is Go's comma-ok type assertion
  `v, ok := x.(Iface)` - yields `(&dyn Iface, bool)`; on a miss the
  value is a nil-interface sentinel whose methods panic.

The worked example is `net/http`'s ResponseWriter / Flusher /
Hijacker / Pusher family in `src/net/http/server.rs`.

### 9b. Two ways a type assertion silently always misses

Both fail the same way - `ok == false`, no panic, no compile error - so
a wrong `else` branch is the only symptom. Rule out both before
concluding a type does not implement an interface.

**`cast!` only takes a `dyn Trait` carrier.** Go's most common shape is
`v, ok := x.(Iface)` where `x` is `interface{}`; the goish carrier for
that is a `goany::Any`, and `cast!` **cannot ever succeed on one**. It
resolves through the blanket `impl<T: Sized> HasDynAny for T`
(`goany.rs:635`), which hands back the carrier itself - for an `Any`
that is `Any`'s own `TypeId`, never the payload's. Spell an
`interface{}` assertion with the **interface** form of the inherent
method instead, which unwraps the payload via `as_any()`:

```rust
match priv_.As::<dyn crypto::Signer + Send + Sync>() { … }
```

Worked example: `x509::CreateCertificate`. It surfaced as
`x509: certificate private key does not implement crypto.Signer` for an
Ed25519 key that plainly does - a plausible, on-message error that reads
like a user mistake.

**The per-trait downcast registry starts empty.** Both `cast!` and
`.As::<dyn Trait>()` resolve a concrete type through a registry that
`#[goish::interface]` emits but nothing populates: the concrete type
must appear in a `__goish_register_<Trait>_impl::<C>()` call, run once
from `goish::init()`. `crypto::RegisterStandardHashes` /
`RegisterStandardSigners` are the pattern. **This is not a caller
obligation** - a comment saying a use site must call one is wrong.

As of 2026-08-12 **25 of the 56 interface traits have concrete
implementors and zero registrations**, including `io::Writer` (20
impls), `io::Reader` (17), `io::Closer` (11), `hash::Hash` (11),
`http::Handler` (11), `fmt::Stringer`, `json::Marshaler` and
`crypto::Decrypter`. So `if c, ok := w.(io.Closer)` - and every
assertion like it - misses today regardless of carrier. Registering a
trait's implementors is the fix; check the trait before relying on an
assertion, and register what your port needs.

### 9a. Embedded interfaces - `#[goish::interface(embeds)]`

Go's `type Cloner interface { Hash; Clone() … }` embeds another
interface. Spell that as a real Rust supertrait **plus the `embeds`
flag**:

```rust
#[goish::interface(embeds)]
pub trait Cloner: Hash { … }        // Hash is itself an interface
```

Without `embeds` the macro re-declares its hidden helpers
(`__is_nil_iface`, `__goish_as_dyn_any`) on both traits, and every call
on `dyn Cloner` is E0034 "multiple applicable items in scope". With it,
the helpers are inherited and the downcast impls delegate up the chain
(`Cloner` -> `Hash` -> `io::Writer`), so a concrete type overriding
`__goish_as_dyn_any` **once** - in its innermost `impl` - is castable
through every interface above it.

Do **not** pass `embeds` when the supertrait is a plain Rust trait: there
is nothing to inherit. That case keeps the old behaviour, pinned by
`examples/interface_auto_composite.rs`.

Two further constraints:

- A composite trait (any non-marker supertrait, `embeds` or not) has
  **no nil sentinel**, so `cast!` rejects it at compile time. Use
  `carrier.As::<dyn Iface + Send + Sync>()` (`goany.rs::AsExt`). If the
  interface needs a nil value, hand-write the sentinel plus
  `impl From<Nil> for Box<dyn Iface + Send + Sync>` - see
  `hash::__NilCloner`.
- **Two** interface supertraits are still ambiguous (inheritance picks
  one owner). `hash::XOF: io::Writer + io::Reader` is a plain trait for
  that reason.

Debugging: a compile error inside generated code points only at the
attribute. `GOISH_IFACE_DUMP=<dir> cargo check --lib` writes every
expansion to `<dir>/<Trait>.rs`.

The worked example is `hash::Hash` / `hash::Cloner` in `src/hash/hash.rs`,
consumed by `crypto/internal/fips140/hmac`.

## 10. Ground truth comes from Go, not from transcription

A runnable Go 1.25.5 toolchain is available. **`scripts/goref.sh
<import-path> <ref-test-file>`** copies GOROOT to a writable directory
and runs a throwaway `TestGoishRef` *inside* it, so the reference file
can import `crypto/internal/...` and reach unexported symbols:

```bash
scripts/goref.sh crypto/internal/fips140/tls13 /tmp/tls13_ref.go
```

The ref file declares `package <pkg>` (not `<pkg>_test`) and prints the
values a port needs to match.

Prefer this to transcribing published vectors. Hand-copied expectations
have twice produced plausible-but-wrong literals in this repo — a CMAC
vector whose line continuation collapsed, and an SSH-KDF tag-F row
pasted against a tag-D call. Both cost a debugging cycle chasing a port
bug that did not exist. For packages with no published vectors (mlkem,
nistec, bigmod) it is the only option.

Published vectors still earn their place as a *second* anchor when they
exist — matching both Go and NIST is stronger than matching either.

## 11. Pre-flight before porting a package

`scripts/port_deps.py <import-path>` first, every time. It answers the
three questions that decide whether a port can land at all: is every
import present in goish, does each one actually export the *symbols*
this package calls, and is the target path free. Never claim a
dependency is missing or present without a command proving it.

```bash
scripts/port_deps.py crypto/x509/pkix       # can this package be ported?
scripts/port_deps.py --ready crypto         # rank what is portable now
scripts/port_coverage.py crypto --pkg tls   # what is missing, and why
```

Three failure modes it exists to catch, each of which has actually
happened here:

- **A path can be squatted.** `src/crypto/ecdsa/` held 915 lines of
  hand-rolled P-256 — invented code with no Go counterpart — and read
  `present` for four sessions. `port_deps` now reports SQUATTER (path
  exists, zero anchors, zero coverage) and refuses to call it READY.
- **The gap column is not the work.** `--ready` has separate `port` and
  `asm` columns and ranks on the portable one, because a Go func with no
  body is an assembly stub, not something to port by reading Go. Three
  wrong leverage claims came from reading the combined number:
  crypto/sha1, sha256 and sha512 all look like 1-2 function ports and
  are 100% assembly.
- **A present import is not a usable one.** `crypto/x509/pkix` read
  READY while `encoding/asn1` was missing `Marshal` — the one symbol it
  needs. Inherent impls also do not satisfy a `#[goish::interface]`
  trait; that `impl Trait for T` block has to exist.

### Waiving a decl goish resolves elsewhere

Some Go declarations will never have a same-named counterpart here, and
counting them as missing makes the number lie downward — the squatter
problem inverted. The motivating case is a `//go:linkname` pair: Go
writes the body on one side and a bodyless stub on the other, and goish,
having no linkname, writes it once on whichever side can reach the
field. `crypto/sha3` read 26/27 forever for exactly that reason.

Declare it in the goish file, with a reason:

```rust
// go: waived fips140hash_sha3Unwrap — linkname body ported once, on the
//     crypto/internal/fips140hash side; a second copy here would be the
//     same function twice.
```

Waived decls leave the denominator — they are not remaining work — but
`port_coverage` prints them on their own WAIVED line and in the TOTAL,
so they can never quietly inflate a percentage. **The reason text after
the em dash is required**; a bare `// go: waived Foo` is ignored, which
is what stops this from becoming a way to launder a gap into 100%.

Reach for it only when no counterpart *can* exist. A function that is
merely hard, unported, or blocked is MISSING, not waived.

crypto/ is 1108/1452 = 76.3%; the 344 left are 330 portable + 14
assembly, and 37 counted names are still UNVERIFIED.
