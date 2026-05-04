# DISCUSSION — `goish::var!` for package-level declarations

Status: **Doctrine 2 chosen, macro shipped, stdlib migration deferred.**
Date: 2026-05-04. Merged from prior `DISCUSSION_ERRORS.md`.

## Update — 2026-05-04 (post-prototype)

Doctrine 2 (bare-symbol sentinels via marker ZST + `IsTarget`) was selected
and the macro is now shipped. Validation: `examples/var_marker_smoke.rs`
exercises all 12 use positions (`Is`, `==` both directions, `.into()`,
`From`, identity stability, chain walking, cross-sentinel discrimination,
plain-const fallback, nil coexistence) — all green. Full e2e: 137/137.

Components landed:

- `errors::IsTarget` trait + reflexive `error: IsTarget` impl
- `errors::Is::<T: IsTarget>` widened
- `error::__ptr_eq` accessor for marker `PartialEq` impls
- `goish-macros::var_emit_error_marker` proc-macro (token-level, no `syn`/`quote`/`paste`)
- `goish::var!` muncher in `builtin_macros.rs`: single-line + block forms, mixed `error` + plain-const
- Existing `__SkipDirMarker` / `__SkipAllMarker` in `path/filepath` migrated to `IsTarget`

Pending — see §13 below for the migration plan:

1. **Stdlib migration**: 133 `io::EOF()` / `io::ErrShortWrite()` / etc. call
   sites across 48 files. Mechanical (drop parens), but the const-vs-fn
   name clash prevents both forms coexisting in the same module — so each
   module migrates as a unit. Defer until next session.
2. **`#[goish::main]` eager-init**: still deferred per open decision #5.
3. **`const!` macro**: still deferred per open decision #2.

The doctrine choice and trade-off analysis below remain the architectural
record, even though the recommendation in §10 is now superseded.

The original question was narrow ("how do we declare error sentinels less
verbosely?") and grew into something bigger: a single `goish::var!` macro that
covers every Go package-level `var` declaration — error sentinels, primitive
constants, channels, mutexes, typed structs — emitted by `goishc` *and* usable
directly from hand-written goish code.

This doc captures the full design space: the motivating constraint (error
sentinels), the spectrum of options, and the open decisions.

---

## 1. The premise

Go has uniform `var`-at-file-scope syntax that handles many distinct semantic
cases:

```go
var X int = 42                              // primitive immutable-ish
var counter int = 0                         // primitive mutable  (counter++)
var EOF = errors.New("EOF")                 // sentinel error
var DefaultClient = &Client{...}            // address-stable struct
var Mu sync.Mutex                           // zero-value, addressable
var Buf bytes.Buffer                        // zero-value, mutable
var ch = make(chan int, 8)                  // channel
var m = map[string]int{}                    // map
var s = []int{1, 2, 3}                      // slice literal
var f = func() { ... }                      // function value
var _ = doSetupThing()                      // side-effecting registration
```

In Go, all of these are accessed by bare name (`pkg.X`, no parens) and have
addressable storage at well-defined locations. They run at package init time
in dep-graph order.

The proposal: have goishc emit `goish::var! { pub Name: Type = expr; }`
uniformly for each, and make the macro the single dispatch point for "what
backing storage and what access shape does this Go var get?"

**`goishc` is not the only consumer.** The macro must also be ergonomic for
hand-written goish code — the same way `make!`, `slice!`, `range!`, `delete!`
are usable directly. Anything that's only nice as transpiler output is wrong.

---

## 2. The motivating problem — error sentinels

Today, every error sentinel is hand-written boilerplate:

```rust
// io/mod.rs
pub fn EOF() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || errors::New("EOF"))
}
```

Use sites: `errors::Is(err, io::EOF())` — function call, parens required.

### Why this shape — three stacked constraints

#### 2.1 `error` wraps `Arc<dyn ErrorTrait>` — not a `const`-friendly type

```rust
pub struct error(Option<Arc<dyn ErrorTrait>>);
```

`Arc::new(...)` allocates on the heap. Heap allocation can't happen at compile
time, so this doesn't compile:

```rust
pub const EOF: error = error(Some(Arc::new(MyErrType)));   // ✗ not const-fn
```

Lazy initialization is mandatory the moment the inner payload is heap-allocated.

(Compare: `errors::nil = error(None)` IS a real `pub const`, because `None`
carries no allocation.)

#### 2.2 Pointer-identity is the matching contract

Go's `var EOF = errors.New("EOF")` makes ONE pointer. Then
`errors.Is(err, io.EOF)` does pointer-equality. Goish mirrors that:

```rust
// errors::Is uses Arc::ptr_eq under the hood
errors::Is(err, io::EOF())  // must match the SAME Arc identity every call
```

If `io::EOF()` returned a *new* `errors::New("EOF")` each call, the strings
would be equal but the Arcs would be different objects, and `errors::Is` would
return `false`. So we need to cache and hand out clones of the SAME Arc.

#### 2.3 `no_std` removes the easy answers

| Option | Why not |
|---|---|
| `std::sync::OnceLock` | not in `core`; goish is `no_std` |
| `core::cell::OnceCell` | not `Sync` — can't be a `static` |
| `lazy_static!` / `once_cell` | external deps; some assume `std`, all add macro complexity |
| `AtomicPtr` + manual CAS | works but reinvents what SpinLock already provides cleanly |

### Why SpinLock specifically

`runtime::spin::SpinLock` is the smallest `Sync` primitive goish has — just an
`AtomicBool` plus a payload, no parking, no futex, no OS calls. It already
exists for the scheduler internals, so reusing it costs nothing.

- **First call:** acquires lock, builds the `Arc`, stores `Some(...)`, returns a clone.
- **Every subsequent call:** acquires lock (uncontended ~1 atomic CAS), clones the `Arc`, drops lock.

Contention is effectively zero: the slot becomes `Some` very early and
`lock()` becomes a single cmpxchg that succeeds on first try. Sentinels also
live on the exceptional path.

### The cost in one line

We pay **one cmpxchg + one Arc clone (~10ns)** per sentinel access in exchange
for **`errors::Is(err, io::EOF())` working via pointer-equality**, which is
the contract every Go program assumes. Without that, every typed error chain
(`io.EOF`, `os.ErrNotExist`, `context.Canceled`, …) breaks.

---

## 3. Where errors actually appear — Go 1.25 SDK catalog

For deciding what `var!` must support, here's the full inventory of how the Go
stdlib uses errors. The macro only needs to address category **A**; B/C/D are
unchanged from today.

### A. Package-level sentinel definitions (need identity stability)

**A.1 — Single-line, exported:**
```go
var EOF              = errors.New("EOF")          // io/io.go
var ErrUnexpectedEOF = errors.New("unexpected EOF")
```

**A.2 — Single-line, unexported:**
```go
var errInvalidWrite = errors.New("invalid write result")
var errWhence       = errors.New("Seek: invalid whence")
```

**A.3 — Block form, mixed visibility:**
```go
// net/interface.go
var (
    errInvalidInterface         = errors.New("invalid network interface")
    errInvalidInterfaceIndex    = errors.New("invalid network interface index")
    errInvalidInterfaceName     = errors.New("invalid network interface name")
    errNoSuchInterface          = errors.New("no such network interface")
    errNoSuchMulticastInterface = errors.New("no such multicast network interface")
)
```

**A.4 — Block form with per-item doc comments:**
```go
// net/net.go
var (
    // For connection setup operations.
    errNoSuitableAddress = errors.New("no suitable address found")

    // For connection setup and write operations.
    errMissingAddress = errors.New("missing address")
)
```

**A.5 — Block form mixing `errors.New` with typed-value sentinels:**
```go
// net/net.go
var (
    errCanceled = canceledError{}                      // typed value sentinel
    ErrClosed   = errors.New("use of closed network connection")
)
```

### B. Custom error types (struct definitions, not inline)

**B.1 — Struct error with `Error() + Unwrap()`:**
```go
type PathError struct { Op, Path string; Err error }
func (e *PathError) Error() string { return e.Op + " " + e.Path + ": " + e.Err.Error() }
func (e *PathError) Unwrap() error { return e.Err }
```

**B.2 — Struct error with custom `Is()` (semantic matching):**
```go
type Errno uintptr
func (e Errno) Is(target error) bool {
    switch target {
    case oserror.ErrPermission: return e == EACCES || e == EPERM
    ...
    }
}
```

### C. Inline error creation (no definition needed)

```go
// C.1 — bare errors.New at return site
return nil, errors.New("not a directory")

// C.2 — typed struct construction at return site
return nil, &PathError{Op: "openat", Path: name, Err: errors.New("unsupported")}

// C.3 — fmt.Errorf plain
return fmt.Errorf("user: %s", err)

// C.4 — fmt.Errorf with %w wrap verb
return fmt.Errorf("os/user: failed: %w", err)

// C.5 — errors.Join
return errors.Join(err1, err2, err3)
```

### D. Matching / inspection APIs (read-side, not creation)

```go
errors.Is(err, fs.ErrExist)      // ptr-eq on sentinels, semantic on types-with-Is()
errors.As(err, &pathErr)          // walks Unwrap chain, downcasts to typed
errors.Unwrap(err)                // one-level unwrap
```

### What goish already has

| Go | goish | Status |
|---|---|---|
| `errors.New("text")` | `errors::New("text")` | ✓ |
| `errors.Is(err, target)` | `errors::Is(err, target)` | ✓ |
| `errors.As(err, &T)` | `errors::As::<T>(err) -> Option<Arc<T>>` | ✓ |
| `errors.Unwrap(err)` | `errors::Unwrap(err)` | ✓ |
| `errors.Join(...)` | `errors::Join(slice<error>)` | ✓ |
| `fmt.Errorf("…%w", e)` | `fmt::Errorf!("…%w", e)` | ✓ (macro form) |
| Typed `&PathError{...}` | `errors::Wrap(MyErr { … })` | ✓ |
| `var X = errors.New(...)` | `pub fn X() -> error { lazy SpinLock cache }` | ✓ but **boilerplate-heavy** |

**The only gap is (A) — sentinel definitions.** That's exactly what `var!`
fills.

---

## 4. The shape question — three doctrines

Rust gives three top-level shapes:

| Form | What you get | What you can't do |
|---|---|---|
| `pub const X: T = ...` | inlined value at every use site | mutate, take address, init from non-const fn |
| `pub static X: T = ...` | one address, `&'static T` | init from non-const fn (without lazy machinery) |
| `pub fn X() -> T` | computed each call, can wrap lazy init | take a stable address, mutate |

A unified `var!` has to pick a *consistent* exposure shape so the transpiler
can emit consistent use sites.

### Doctrine 1 — Always a function: `pkg::X()`

```rust
goish::var! { pub EOF: error = "EOF"; }      // → fn EOF() -> error { ...lazy... }
goish::var! { pub MaxBuf: int = 4096; }      // → fn MaxBuf() -> int { 4096 }
goish::var! { pub Mu: sync::Mutex = ...; }   // → fn Mu() -> &'static sync::Mutex { ... }
```

- **Pro:** one shape everywhere; transpiler emits `pkg::X()` for every `pkg.X`,
  no type-to-shape table needed.
- **Pro:** lazy init is the natural fit for any non-const-fn type.
- **Con:** every `MaxBuf` access goes through a fn call (likely inlined for
  trivial cases).
- **Con:** mutable vars are awkward.

### Doctrine 2 — Always a static: `pkg::X` (bare)

```rust
goish::var! { pub EOF: error = "EOF"; }      // → static EOF: ErrLazy = ...
goish::var! { pub MaxBuf: int = 4096; }      // → static MaxBuf: int = 4096
```

- **Pro:** bare-symbol use everywhere, matches Go syntax exactly.
- **Con:** forces a ZST-with-`Borrow` trick (see §5 below) for `error`,
  `chan`, `map`, etc. The trait-bound spread (`errors::Is`, `errors::As`,
  `errors::Wrap`, every `==`) is the killer.

### Doctrine 3 — Dispatch, transpiler-aware

Macro produces the right shape per type; transpiler emits `pkg::X()` or
`pkg::X` accordingly based on the var's Go type.

- **Pro:** zero overhead, accurate semantics per type.
- **Con:** transpiler needs a *type-to-call-shape* table that has to stay in
  sync with the macro's arm list — two places, easy to drift.

---

## 5. Why bare `io::EOF` (Doctrine 2) is hard — the ZST trick and its cost

An init step alone doesn't unlock bare `io::EOF`. Even with a runtime init
pass that pre-populates every sentinel, you can't write:

```rust
pub static EOF: error = ???;   // can't construct an error containing Arc<dyn> as a const
```

The actually-viable shape uses a Zero-Sized-Type wrapper:

```rust
pub struct EofRef;
pub const EOF: EofRef = EofRef;
static EOF_PTR: AtomicPtr<error> = AtomicPtr::new(null_mut());
impl Borrow<error> for EofRef {
    fn borrow(&self) -> &error {
        // CAS-init lazily; on first call do Box::leak(Box::new(errors::__new("EOF")))
        // and CAS the leaked pointer into EOF_PTR. Return &*EOF_PTR.load(Acquire).
    }
}
// errors::Is widens to:
pub fn Is<T: Borrow<error>>(err: error, target: T) -> bool {
    Arc::ptr_eq(&err.0, &target.borrow().0)
}
```

Now `errors::Is(err, io::EOF)` compiles. Cost:

| | Cost |
|---|---|
| Per-sentinel | one `Box::leak` (~80 B) on first use; ~30 sentinels → ~2.5 KB process-wide, never freed |
| Init path | one `AtomicPtr::compare_exchange` instead of one `SpinLock::lock` (similar cost) |
| **API surface** | `errors::Is`, `errors::As`, `errors::Wrap`, every `==`/`!=` against a sentinel — all need `T: Borrow<error>` (or parallel impls). Generic bounds spread to anywhere errors are compared. |
| Source code | every sentinel definition is bigger (struct + const + static + impl), but hidden behind the macro |
| Backwards compat | breaks the `io::EOF()` form, OR keep both fn + const ZST and accept duplicate symbols |

**The trait-bound spread is the killer.** Every error-handling API widens.
For one keystroke saved per call site.

### The eager-init side benefit (independent of doctrine)

Two real wins from a `#[goish::main]`-driven init pass, neither about syntax:

1. **Eager warm-up** — eliminates first-use latency on the SpinLock.
2. **Cross-package ordering** — explicit init order beats accidental
   "whoever called first wins" if typed-error chains start growing.

---

## 6. Mutability — Go's `var` is mutable

Go: `var counter int = 0` then later `counter++`. In Rust:

| Type class | Rust equivalent | Macro arm |
|---|---|---|
| Primitive (`int`, `bool`, …) mutable | `static COUNTER: AtomicI64 = AtomicI64::new(0)` | needs to know mutability |
| `error`, `chan`, `map` (Arc/Box-backed) | `static SLOT: SpinLock<Option<T>>` + lazy | already lazy |
| User struct | `static X: SpinLock<T>` or `static X: T` (if const-fn) | depends on `T: const Default` |

`var!` needs a mutability hint. Two ways:

```rust
// Option A: explicit mut keyword
goish::var! { pub mut counter: int = 0; }      // mutable → AtomicI64 backing
goish::var! { pub     EOF: error = "EOF"; }    // immutable-handle → lazy fn

// Option B: split into var! / const!
goish::var!   { pub counter: int = 0; }        // mutable
goish::const! { pub MaxBuf: int = 4096; }      // immutable
```

Option B matches Go's surface syntax (`var` vs `const`) and reduces the
macro's dispatch space. Probably cleaner.

---

## 7. Single-line and block syntax — both must work

Go has two forms:

```go
var X = 1                // single
var (                    // block
    A = 1
    B = 2
    C = errors.New("C")
)
```

Goish must support both. They aren't different macros — they're the same
syntactic shape (a sequence of declarations) with the block form being the
multi-item case of the single-line form. A standard "munch" macro covers both:

```rust
// Single-line
goish::var! { pub EOF: error = "EOF"; }

// Block — multiple decls, mixed types, all dispatched per-item
goish::var! {
    pub EOF: error              = "EOF";
    pub ErrUnexpectedEOF: error = "unexpected EOF";
    pub ErrShortWrite: error    = "short write";
    pub MaxBuf: int             = 4096;
    pub DefaultPath: &str       = "/etc/goish";
}
```

### Macro shape (munch pattern)

```rust
#[macro_export]
macro_rules! var {
    // Entry point: forward everything to the internal muncher.
    ( $($decl:tt)* ) => {
        $crate::__var_internal! { $($decl)* }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __var_internal {
    // Base case — no more declarations.
    () => {};

    // ── error sentinel: string-literal form ────────────
    ($vis:vis $name:ident : error = $msg:literal ; $($rest:tt)*) => {
        $vis fn $name() -> $crate::error {
            static SLOT: $crate::runtime::spin::SpinLock<Option<$crate::error>>
                = $crate::runtime::spin::SpinLock::new(None);
            $crate::errors::__cached_error(&SLOT, || $crate::errors::__new($msg))
        }
        $crate::__var_internal! { $($rest)* }
    };

    // ── error sentinel: typed-payload form ─────────────
    ($vis:vis $name:ident : error = $expr:expr ; $($rest:tt)*) => {
        $vis fn $name() -> $crate::error {
            static SLOT: $crate::runtime::spin::SpinLock<Option<$crate::error>>
                = $crate::runtime::spin::SpinLock::new(None);
            $crate::errors::__cached_error(&SLOT, || $crate::errors::Wrap($expr))
        }
        $crate::__var_internal! { $($rest)* }
    };

    // ── plain const fallback ───────────────────────────
    ($vis:vis $name:ident : $ty:ty = $val:expr ; $($rest:tt)*) => {
        $vis const $name: $ty = $val;
        $crate::__var_internal! { $($rest)* }
    };
}
```

**Mechanics:**

- **Single line** = the muncher consumes one item, recurses on empty rest, hits the base case.
- **Block** = the muncher consumes one item per recursion until the rest is empty.
- Each arm dispatches on the type-position token (`error` literal, otherwise generic `$ty:ty`) and emits the right shape.
- Trailing `;` is required after every decl (including the last) — keeps the munch pattern simple.

### Manual-use ergonomics (the primary win)

Hand-written code becomes a clean Go-style block:

```rust
// io/mod.rs — no transpiler involved
goish::var! {
    pub EOF: error                = "EOF";
    pub ErrShortWrite: error      = "short write";
    pub ErrUnexpectedEOF: error   = "unexpected EOF";
    pub ErrShortBuffer: error     = "short buffer";
}
```

…replaces ~30 lines of repetitive `pub fn X() -> error { static SLOT: ... }`
boilerplate. Mapping cleanly onto Go's `var (...)` block. **This is the
primary ergonomic win regardless of whether goishc ever emits `var!`.**

### Variants we'd add as ports demand them

- `var const`-style block (immutable):
  ```rust
  goish::const! { pub MaxBuf: int = 4096; pub Min: int = 1; }
  ```
- `var iota` Go-style sequence — defer until a port forces it.

### Caveats

- **Lexical type-token dispatch.** A path-form like `goish::error` won't hit
  the specialised arm; users must write the unqualified `error` type name.
  Idiomatic anyway.
- **Order of arms matters.** Specialised arms (`error`) must come before the
  generic fallback (`$ty:ty`). Standard macro_rules! gotcha.
- **Visibility / attributes.** The sketch handles `pub` via `$vis:vis`. To
  support `#[doc = "..."]` or other attributes per-decl, prepend
  `$(#[$attr:meta])*` to each arm.

---

## 8. Init order — when does `expr` run?

Go evaluates package-level `var = expr` at program load, in dep-graph order
across packages. Rust offers two extremes:

- **Eager + const-fn:** value materialised at compile time. Doesn't work for
  `Arc::new`, `Box::new`, channels, mutexes-with-non-const-init.
- **Lazy first-touch:** value materialised on first access (current
  `cached_error` pattern). Doesn't match Go semantics for code that reads a
  var without ever writing it AND for side-effecting init expressions like
  `var _ = doSetupThing()`.

### Proposed: link-time init registry

Every `goish::var!` declaration also registers an init thunk into a
link-time-collected list. `#[goish::main]` walks that list before user main
runs, forcing eager evaluation in registration order. Gives Go-faithful
semantics on top of the lazy machinery, with no API change at use sites.

Implementation options:

- **`inventory` crate** — proc-macro-driven, works on stable, ELF/Mach-O/COFF.
  Pulls one external dep.
- **Hand-rolled `.init_array`-style** — manual section-name attributes on
  per-var thunks. `no_std`-friendly, but platform-specific glue.
- **Manual registry call in macro expansion** — each `var!` emits a
  `ctor_register(&__init_thunk)` at module-load time.

Hand-rolled probably wins given goish's `no_std` posture and bias against
external deps.

---

## 9. The big trade-off

| | Win | Cost |
|---|---|---|
| **Single verb (`goish::var!`) for all Go vars** | one place to evolve storage strategy; new "magic" type → one new macro arm | macro grows arms per "magic" type |
| **Doctrine 1 (always-fn)** | uniform call shape; lazy init natural; no transpiler type table | call syntax everywhere (`pkg::X()`); mutable vars need explicit access |
| **Doctrine 2 (always-static)** | bare-symbol use sites match Go exactly | trait-bound tax forever (`Borrow<T>` everywhere) |
| **Doctrine 3 (dispatch)** | best of both: bare for primitives, fn for complex | macro and transpiler must stay in sync |
| **Eager init via registry** | Go-faithful side-effecting init order | ~50 lines of platform glue + per-var registration |

---

## 10. Recommendation

- **Don't pursue Doctrine 2.** The `()` cost is one keystroke per sentinel
  reference, on a path that's already exceptional. The ZST approach scatters
  ~30 new types and trait-bound noise across the runtime to save that one
  keystroke. Goish already paid the cost of being honest about the
  heap-allocation requirement of `error` — fighting it harder gives a
  cosmetic win at structural cost.

- **Ship Doctrine 1 with `goish::var!`.** A 50–100 line macro that emits
  fn-form for `error` (lazy SpinLock cache) and plain `const` fallback for
  everything else. Keeps `errors::Is(err, io::EOF())` syntax unchanged but
  collapses definition-site boilerplate from ~6 lines per sentinel to one
  line in a block.

- **Defer eager-init phase** until a port forces it (e.g., a Go package with
  `var _ = init_side_effect()` we need to honour). When it lands, ~50 lines
  of `#[goish::main]` registry-walk + per-var thunk registration. No API
  impact at use sites.

- **Inline error creation needs no new macro.** `errors::New`,
  `fmt::Errorf!`, `errors::Wrap`, `errors::Join` already cover Go categories
  C.1–C.5. Don't pre-build a `errors::wrap! { Path { ... } }` macro until a
  port produces enough `errors::Wrap(SomeStruct{...})` call sites for it to
  grate.

---

## 11. Open decisions for next session

1. **Doctrine 1, 2, or 3?** Lean: **1**.
2. **Mutability**: `pub mut X` form, or split into `var!`/`const!`? Lean: **split**, mirrors Go.
3. **Trailing `;` on last decl in a block**: required (simple) vs optional (one extra arm). Lean: **required** — matches Rust expression-statement convention.
4. **Per-decl attributes (`#[doc = "..."]`)**: support in v1 or defer? Lean: **support** — small pattern addition, important for `///` doc comments.
5. **Eager init**: ship the `#[goish::main]` registry walk in v1, or defer? Lean: **defer until forced**.
6. **Specialised arms in v1**: just `error`, or also `chan` / `map` / `Mutex` / atomic-backed primitives? Lean: **start with `error` + plain const fallback**, add others as ports demand.
7. **Init registry mechanism**: `inventory` crate, hand-rolled `.init_array`, or manual call? Lean: **hand-rolled** to stay no-dep.
8. **Backwards compat**: keep existing `pub fn EOF() -> error { … }` functions alongside macro emission, or migrate every sentinel in goish-v1 stdlib? Lean: **migrate** — single source of truth, smaller stdlib surface.
9. **`iota`-style sequences**: design now or defer? Lean: **defer** — its own design problem and not on the source-controller critical path.

---

## 12. Resume points

- ~~Decide doctrine before writing code.~~ → **Doctrine 2 chosen 2026-05-04.**
- ~~Write minimal `goish::var!`.~~ → **Shipped 2026-05-04.**
- **Next**: stdlib migration per §13.
- If we ever extend to typed-error sentinels (`PathError`, `Errno`, `os.ErrNotExist`): the existing brace-form arm (`= { TypedErr { ... } }`) handles them. Validate with one prototype before en-masse migration.
- Connect to goishc emission: does the transpiler emit `goish::var!` or a lower-level form? Lean: emit the macro and let it dispatch — keeps goishc rules thin.
- If we commit to eager init: prototype the link-time registry on Linux first; cross-platform later.

---

## 13. Migration plan — stdlib sentinel rewrite

Inventory at 2026-05-04:

- **133 call sites** across **48 files** in `src/` and `examples/` reference
  current fn-form sentinels (`io::EOF()`, `io::ErrShortWrite()`,
  `io::ErrUnexpectedEOF()`, `io::ErrShortBuffer()`, `io::ErrNoProgress()`).
- `os::ErrNotExist`, `os::ErrPermission`, `errors::ErrUnsupported`, etc.
  add roughly another ~50 sites.
- Total: estimated **~200 call sites** across the goish v1 codebase.

### Why we can't ship both forms in the same module

A `pub const EOF: __EofMarker = …` and `pub fn EOF() -> error { … }` in the
same module collide on the symbol `EOF`. There is no way to have the macro
*add* the marker without removing the fn. So each module migrates as a unit:

1. Define markers via `goish::var!` in the module.
2. Drop the old `pub fn EOF()` body.
3. Sweep all call sites: `io::EOF()` → `io::EOF` (comparison) or
   `io::EOF.into()` (conversion).
4. Run e2e for that module's tests; commit.

### Recommended migration order

Smallest blast radius first, building confidence:

1. **`errors::ErrUnsupported`** — single sentinel, ~5 call sites.
2. **`io/*`** — 5 sentinels, ~133 call sites. Biggest single hop. Mostly
   in goish stdlib internals (`bufio`, `compress/*`, `encoding/csv`,
   `archive/tar`) which we control.
3. **`os/*`** — `ErrNotExist`, `ErrExist`, `ErrPermission`, `ErrInvalid`,
   `ErrClosed`, `ErrDeadlineExceeded`, etc.
4. **`net/*`** — `ErrClosed`, `ErrWriteToConnected`, etc.
5. **`context::Canceled`, `context::DeadlineExceeded`** — already
   fn-form via `runtime/spin`-cached pattern; convert to macro.
6. **`syscall::E*` (Errno values)** — these are `int`-typed errors with
   custom `Is()`. Different shape — defer to a separate design pass.

### Mechanical sweep technique

For each module `M`:

```bash
# (1) Drop parens at all call sites:
find src/ examples/ -name '*.rs' -exec sed -i \
    -e 's/M::EOF()/M::EOF/g' \
    -e 's/M::ErrShortWrite()/M::ErrShortWrite/g' \
    {} +

# (2) For positions where `error` is needed (let-binding, return slot,
#     struct field, tuple slot), add `.into()`. These can't be sed'd
#     blindly — need cargo check + per-error fixup.

cargo check --lib --examples 2>&1 | grep "expected.*error.*found" | ...
```

### Risk

- Most call sites are in `if errors::Is(err, M::X)` / `if err == M::X` /
  `return M::X` positions — `Is` and `==` work bare; `return` needs `.into()`.
- The `.into()` annotations needed in non-comparison positions are
  predictable from the rustc errors. Each module migration is roughly:
  drop parens (mechanical) → cargo check → add `.into()` where rustc
  complains → run module's tests → commit.

### Backwards-compat shim option (rejected)

Considered: keep `pub fn EOF()` as a deprecated wrapper that calls
`EOF.into()`. **Rejected** because Rust forbids const + fn with the same
name in the same module. We'd have to rename the const (`EOF_S` / `_EOF` /
inside private submodule), which breaks the bare-symbol Go-shape entirely.
Better to bite the migration bullet once.
