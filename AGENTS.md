# goish agent reminders

This file captures the project conventions from `.claude/goish-reminder.md` so that any coding agent can discover them.

## Working directories (read first)

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

### 7a. Hard rule — if a port can't be done, fix the runtime instead of stepping aside

**If you can't port a chosen target because something is missing (a stdlib subpackage, a runtime API, a transpiler capability, a `range!()` impl, a `goish::var!` shape, etc.), the correct response is to ADD that missing piece to the goish runtime — not to silently move on to a different leaf.**

Concrete examples:
- `go-logr/stdr` needs `funcr` (914 LOC subpackage of `go-logr/logr`) → port `funcr`, then `stdr` (don't drop `stdr` for a smaller unrelated leaf).
- A `range!(&x)` failure on a borrowed value → fix `range.rs`, don't fall back to a raw Rust `for` loop in the port.
- A missing `math/rand/v2::Float64()` → add it to the runtime, don't inline a private RNG in the port.
- A `Cookie { Name: string("sid"), … }` struct-literal hop → propose a constructor / builder fix in the runtime, don't leave a hand-conversion comment in the port.

**What "stepping aside" looks like and why it's wrong:**
- Picking a different leaf because the chosen one needs a missing dep.
- Hand-stubbing a Go API in a port crate that should live in the runtime.
- Working around a runtime gap with Rust idioms that violate the public-API rules in §2 / §3 / §5.

Each step-aside fragments the codebase, leaves the gap unfilled for every future port, and erodes the runtime → ports invariant. Filling the gap once benefits every consumer forever. **Runtime first. Always.**

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

## 10. goishc translate→fix→retranslate loop (the porting methodology)

**The default workflow for porting a new Go module** is the translate→fix
loop, NOT hand-rolling Rust from scratch. Every error the transpiler
produces is either:

- **A transpiler bug** — fix once in goishc and every future port benefits.
- **A runtime gap** — fix once in goish-v1 and every future port benefits.
- **A hand-edit pattern** — for structural issues that are too port-
  specific to generalise (typed sentinel statics, newtype wrappers for
  Go func-types-with-methods, etc.). Document with `// HAND-EDIT:`
  comments so re-translation can re-merge.

### The loop

```
1. goishc pkg -o crate/src/lib.rs <go-source-dir>
2. Add crate to ports workspace (Cargo.toml members)
3. cargo check -p <crate> 2>&1 | grep -E "^error\[" | sort | uniq -c
   → Categorise by error code, count cascades
4. Pick highest-impact fix:
   - Cluster of N identical errors → one root, fix it
   - One error blocking all subsequent code → fix it
5. Apply fix in goishc (transpiler) OR goish-v1 (runtime) OR both
6. Re-build goishc (`go build -o ~/bin/goishc`) when transpiler changed
7. Re-translate (overwrites lib.rs) — DO NOT lose hand-edits if any!
8. Recount; verify drop (or note cascading new errors surfacing)
9. Repeat until count plateaus OR remaining errors are single
   instances with no clear cascading root
10. Switch to hand-edits for the residual; document each
11. Verify e2e (138/138) AND full ports `cargo check --workspace`
    after every runtime change — runtime additions can break other
    crates that already passed
```

### Recipes proven by the `uber_multierr` session (2026-05-04)

**Transpiler-side fixes worth replicating:**

| Symptom | Root | Fix location |
|---|---|---|
| `bytes` defined multiple times (E0252) | prelude `bytes` collides with `import "bytes"` | `main.go` UseLinesPass — skip prelude name if also in goishMods |
| `.clone()` on `&mut dyn io::Writer` | auto-clone for all locals | `bodies.go` `collectNoCloneParams` — detect `&mut` stdlib trait params |
| `if recv == nil` on `&mut self` | Go nil-receiver guard | `bodies.go` `emitIf` — elide via `isReceiverNilCheck` |
| `#[derive(Default, Clone)]` fails on atomic field | unconditional Clone derive | `decls.go` `structHasNonCloneField` — drop Clone for atomic/sync.Mutex/etc |
| `pool.Get().MustAs::<&T>()` | type-assert on already-typed Pool result | track `PoolGlobals` in IR; elide assertion in body emitter |
| `cannot find value 'res'` (named returns) | Go `(res T)` slot never declared | `bodies.go` `collectNamedReturns` + EmitBlock prelude + emitReturn substitution |
| `Error()/String()` method on `&mut self` blocks Trait impl | pointer-receiver always emits `&mut self` | `decls.go` `isStringReturningNullary` — override to `&self` for trait shapes |
| `*p = …` on `&p: &T` | pointer params always become `&T` | `decls.go` `pointerParamsWrittenThrough` — promote to `&mut T` if body writes |
| `append(s, other...)` lost spread | Ellipsis not preserved | `bodies.go` — append builtin keeps `...` token; macro has TT-muncher arm |
| Type-assert emits `As::<&T>` (with `&`) | `*T` mapped to `&T` then leaked | `bodies.go` — strip leading `&` before `.As::<T>()` emit |

**Runtime additions worth keeping:**

| Addition | Module | Future ports unlocked |
|---|---|---|
| `From<E: ErrorTrait> for error` blanket | `errors/mod.rs` | Any port with custom error types — `MyErr {…}.into()` works at error slots |
| Auto `impl ErrorTrait for T` (when T has `Error() string`) | goishc `decls.go::emitErrorTraitImpl` | Same — pairs with the blanket |
| `error::As<T: ErrorTrait + Default>(&self) -> (Arc<T>, bool)` | `errors/mod.rs` | Comma-ok type assertion `merr, ok := err.(*T)` |
| `&error == Nil`, `&mut error == Nil` | `errors/mod.rs` | `range!(errs)` yields `&error`, `*error` write-through params |
| `bytes::Buffer: Clone` | `bytes/mod.rs` | sync.Pool + Buffer pool patterns |
| `fmt::State: io::Writer` + `fmt::Formatter` | `fmt/mod.rs` | Any port with custom `Format(fmt.State, rune)` |
| `append!(xs, other...)` spread (TT-muncher) | `builtin_macros.rs` | Every Go `append(s, other...)` byte-identical |

**Hand-edit recipes when transpiler gaps remain:**

| Symptom in transpiled output | Hand-edit |
|---|---|
| `static X: int = bytes("...")` (wrong type from `[]byte` conv inference) | `static X: Lazy<slice<byte>> = Lazy::new(\|\| bytes("..."));` |
| `bytes::Buffer { }` empty-literal in Pool init | `bytes::Buffer::default()` |
| `pool.Get()` then `.clone()` per call | bind owned `let mut buff = …; …writeXxx(&mut buff); pool.Put(buff);` |
| `f.Flag(b'+')` in Formatter (State::Flag takes int) | `f.Flag('+' as int)` |
| `self.writeXxx(f)` where `f: &mut dyn fmt::State` and writeXxx wants `&mut dyn io::Writer` | upcast `f as &mut dyn io::Writer` (works since `State: io::Writer`) |
| `match n { len(&xs) => … }` (non-const arm) | restructure as `if n == len(&xs)` chain |
| `pub type X = Arc<dyn Fn() -> Y>` + `impl X` (Go func-type with method) | newtype: `pub struct X(pub Arc<dyn Fn() -> Y + Send + Sync>); impl Trait for X { … (self.0)() … }` |
| `closer.Close` (Go method-value capture) | `Arc::new(SpinLock::new(closer))` + `move \|\| handle.lock().Close()` |
| `err.As::<dyn SomeTrait>()` (As on a trait — fails T:Default bound) | short-circuit through the one concrete impl: `err.As::<ConcreteType>()` |
| `*into = Append(*into, …)` (move out of `&mut` borrow) | `*into = Append(into.clone(), …)` |
| `(/* TODO(goishc): expr *ast.ArrayType */)(nil.into())` (cast-nil-to-slice) | `make!([]T, 0)` |

### Performance note (TT-muncher specifically)

Macro recursion overhead from the spread-detecting `append!` muncher is
unmeasurable: cold-cache `cargo check` timing for both the goish lib
(217 existing `append!` call sites) and the full ports workspace stays
within timing noise. Don't worry about adding more TT-munchers when
they enable Go-faithful syntax.

### When to STOP iterating and switch to hand-edits

The loop has diminishing returns when:

- **Remaining errors don't cluster** — singletons with no shared root.
- **Fix would touch one Go-specific shape** — Go's method values, named
  return shadowing, multiple-init in one statement, etc. Generalised
  transpiler support costs more than annotated hand-edits in 2-3 ports.
- **Cascade unblocks more than it fixes** — e.g. the Pool.Get fix (iter 6)
  briefly raised total count by exposing a downstream auto-clone issue.
  Take the win on that fix anyway; the cascade was visible-but-latent.

For the `uber_multierr` session, the loop stopped at 26 errors (after
13 transpiler/runtime improvements); the residual 26 needed
~80 lines of `// HAND-EDIT:`-marked hand-tuning to reach 0.

## 11. Status — what's done (2026-05-04)

### Doctrine 2 + `goish::var!` shipped

- `errors::IsTarget` trait — widens `errors::Is::<T: IsTarget>` to
  accept identity-stable markers in addition to `error` values
- `error::__ptr_eq` accessor — backs the marker-side `PartialEq` impls
- `goish-macros::var_emit_error_marker` proc-macro — token-level only,
  no `syn`/`quote`/`paste` deps (matches the existing crate posture)
- `goish::var!` muncher in `builtin_macros.rs` — 3 arms (string-literal,
  typed-payload-brace, plain-const fallback); recursive munch handles
  arbitrary block size
- `extern crate self as goish;` in `lib.rs` — lets the proc-macro emit
  `::goish::...` paths that resolve inside the goish crate itself

### Stdlib sentinel migration complete

Zero `pub fn Err*() -> error` sentinel functions remain across the
runtime. Coverage spans `errors`, `io`, `io/fs`, `os`, `context`,
`bufio`, `archive/tar`, `testing/iotest`, `os/exec`, `encoding/csv`,
`encoding/json`, `io/pipe`, `net/mail`, `net/http/*`, `strconv`, and
`path`. To enumerate, `grep -rn 'goish::var!' src/` is authoritative.

### Naming standardization

`errors::error` → `error` everywhere; zero qualified references remain.
The type still lives in `src/errors/mod.rs` with all impls; the
canonical public path is `goish::error` via `pub use errors::error;` at
lib root.

### Other fixes shipped this session

- Lib warnings: 98 → 0
- gomap `MapRefIter::next()` — mid-bucket skip bug fixed
- `fmt::Sprintf("%+v")` — sorts map keys (Go-faithful)
- `os::IsPathSeparator(c uint8) bool` — unblocks
  `monochromegane_go_gitignore`
- `gomap::GoHash` for `f64` / `f32` — bit-pattern hash; NaN behavior
  matches Go (writeable but unretrievable); required by
  `quantile.NewTargeted(map[float64]float64)` in `beorn7_perks`
- `runtime::Caller` / `FuncForPC` / `Func` — slim stubs returning
  `<unknown>` / empty-name; real DWARF backtrace deferred. Minimum
  surface to unblock `funcr` (and any port that inspects the call site
  without depending on the answer).
- `types::uintptr` (= `u64`) — re-exported at lib root for ports that
  mirror Go's `uintptr` in signatures
- New examples: `gomap_smoke`, `gomap_range_smoke`, `var_marker_smoke`

### `goarray::array<T, const N: usize>` — first-class fixed array (`[N]T`)

Models Go 1.25 spec §Array_types: length-in-type, value-copy assignment
(when `T: Copy`), element-wise comparability + hashability, constant
`Len()`. Methods: `Len`, `Index<int>`, `IndexMut<int>`,
`slice(low, high) -> slice<T>`, `to_slice() -> slice<T>`,
`Deref<Target=[T]>` for raw-byte hot paths, `RangeIter` (so `range!(a)`
works), `From<[T;N]>` / `Into<[T;N]>` boundary helpers, polymorphic
`nil` wiring (zero-array == nil).

**Companion `array!` macro** covers Go's 4 composite-literal shapes:

- `array!([N]T)` — zero
- `array!([N]T{e1, e2, …})` — full / partial (rest zero-filled,
  requires `T: Default`)
- `array!([...]T{e1, e2, …})` — length inferred via internal
  `__count_exprs!` recursion
- Sparse-keyed `[N]T{2: 99}` deferred

Multi-dim composes naturally: `array<array<int, 5>, 3>` ports `[3][5]int`.

Re-exported as `goish::array` at lib root; macro is `goish::array!`.
`make!` deliberately rejects array types — Go's `make` is slice/map/chan
only (spec §Making_slices_maps_and_channels); `array!` owns the
fixed-array slot exclusively.

**v1 deviation** (carried over from `slice<T>`): `a.slice(low, high)` /
`a.to_slice()` *copy* the elements; Go's `a[:]` shares the underlying
array. Same ROADMAP.md entry as the slice-subslicing deviation.

**Rust coherence note**: only `Index<int>` is impl'd; the
`Index<I: SliceIndex<[T]>>` blanket conflicts with future
`i64: SliceIndex<[T]>` impls. Range expressions (`a[0..4]`) on array
fields use `(*a)[0..4]` — explicit deref to `[T]`. Same constraint that
`slice<T>` already lives with.

**Regression check**: `rs_xid::ID` retrofitted from
`pub struct ID(pub [u8; 12])` to `pub struct ID(pub array<byte, 12>)` —
full workspace + 138/138 e2e green post-change.

### Ports shipped this session (Batch C)

| Port | LOC | Notes |
|---|---|---|
| `go_logr_logr` | ~340 | `logr.Logger` / `LogSink` trait + capability sub-traits |
| `go_openapi_swag_conv` | — | numeric conversions |
| `cenkalti_backoff_v5` | 487 | `BackOff` trait, `ExponentialBackOff`, `Retry` generic, `Ticker` |
| `beorn7_perks` | ~580 | quantile + histogram + topk in one crate |
| `go_logr_logr/funcr` | ~700 | structured key=value / JSON formatter (sub-module of `go_logr_logr`) |
| `go_logr_stdr` | ~225 | logr-on-top-of-Go-stdlib-log (depends on `funcr`) |
| `rs_xid` | ~390 | `xid.ID` — 12-byte Mongo-ObjectId-compatible globally-unique id |
| `pmezard_go_difflib` | ~684 | `SequenceMatcher` / `WriteUnifiedDiff` / `WriteContextDiff` (Python difflib partial port) |
| `uber_multierr` | ~330 | `Combine` / `Append` / `AppendInto` / `Errors` / `extractErrors` / `Invoker`. **First port driven by the goishc translate→fix→retranslate loop** — 13 transpiler/runtime improvements + targeted hand-edits, 46 → 0 cargo-check errors |

**Per-port gotchas** (only items not already generalised in §10):

- `beorn7_perks/quantile` — replaced Go's `func(*stream, float64)`
  private field with an `invariantKind` enum to dodge `Box<dyn Fn>` in
  a struct field. Hand-rolled overlap-safe shifts (Rust's
  `clone_from_slice` panics on overlapping right shift).
- `beorn7_perks/topk` — internal `Arc<RefCell<Element>>` for
  pointer-aliased `mon`/`min` (preserves Go's evict-min in-place
  semantics including orphan-after-evict). Public types stay by-value.
- `funcr` — reflection fallback covers primitives only via
  `downcast_ref`; unknown types render `"<unhandled>"`. Full
  struct/slice/map walking needs a `dyn AnyReflect` registry —
  deferred. Hook fields omitted (Doctrine 5). `Formatter::depth` is
  `AtomicI64` so `Init(&self, info)` flows.
- `rs_xid` — Go init-order via per-state `goish::lazy::Lazy<T>` (one
  per `dec` table, `objectIDCounter`, `machineID`, `pid`). Eager init
  to match Go's package-load timing is deferred to `#[goish::main]`.
  `atomic.AddUint32` modernised to typed `atomic::Uint32::Add`.
- `pmezard_go_difflib` — see Memory entry
  `feedback_defer_moves_captured_value.md` for the bufio-vs-`defer!`
  drop. `IsJunk` demoted to private `Option<Box<dyn Fn>>` (Doctrine 5).
  Recursive nested closure (`var matchBlocks func(...)`) hoisted to
  private method — Rust local closures can't self-recurse.
  `type ContextDiff UnifiedDiff` → `pub type ContextDiff = UnifiedDiff`
  (no methods on either side, so a zero-cost alias is fine).
- `uber_multierr` — first goishc-loop port; see §10. Residual ~80 LOC
  `// HAND-EDIT:` tags. Notable port-specific shapes:
  Go func-type-with-method → newtype struct (not `pub type` alias —
  E0116); `closer.Close` method-value → `Arc<SpinLock<Box<dyn Closer
  + Send + Sync>>>` + `move || handle.lock().Close()` (RefCell is
  `!Sync`); `err.As::<dyn Trait>` short-circuited through the one
  concrete carrier; `&mut dyn fmt::State → &mut dyn io::Writer` upcast
  needs explicit `as` despite supertrait declaration.

### Ports workspace

`cargo check --workspace` from `/home/chanwit/Dropbox/projects/goro-workspace/ports/`
**succeeds for ALL crates** (after this session's fixes — see commit
history). `flux_source_controller` is intentionally excluded from the
workspace; it has 2k+ unrelated errors tracked separately.

### Open / deferred

- `#[goish::main]` eager-init pass — defer until a port forces it
- `goish::const!` macro for true compile-time constants — open design
- `iota`-style sequences — separate problem
- `syscall::Errno` typed errors with custom semantic `Is()` —
  different shape from string-message sentinels; defer

### Session commit history

`git log --oneline` is authoritative. Notable landmarks of this
session: `2690340` ships `goish::var!`; `52429ff` completes the
sentinel migration; `8515436` standardises `error`. Uncommitted at
time of writing: `goarray`, the `errors` blanket + `As<T>`,
`bytes::Buffer: Clone`, `fmt::State` supertrait, `append!` spread,
the 11 transpiler improvements from the `uber_multierr` loop, the
codegen-test split, and the ports `funcr`/`stdr`/`rs_xid`/`uber_multierr`.

E2e at every commit boundary: **138/138 green** (137 pre-`goarray`,
138 once `goarray_smoke` joined the suite).
