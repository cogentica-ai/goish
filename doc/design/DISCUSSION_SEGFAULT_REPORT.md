# DISCUSSION_SEGFAULT_REPORT.md — intercept stack-overflow SEGV and report which goroutine to fix

Companion design note for trapping `SIGSEGV` from a goroutine that exhausted its stack and surfacing a useful diagnostic to the user — telling them *which* `go!()` spawn site needs to be fixed.

---

## Problem

Today, when a goroutine overflows its stack, the process dies with no useful information:

```
$ ./prod_server
[silent] Segmentation fault (core dumped)
```

The user has no idea which goroutine overflowed, where it was spawned, or whether the right fix is `stack(N)`, `maybe_grow_step` at recursion sites, or something else. Common scenarios that hit this:

- A `go!(stack(N), …)` opt-out goroutine recursing past N (bounded stack exhausted).
- An auto-grow `go!()` whose body overflows tier-3 (1 MiB cap reached).
- A heavy-bodied goroutine with no recursion (e.g. `select!` with many cases) that crowds tier-1 before any pivot fires — the failure mode that bit `chan_nil` and `select_smoke` earlier this session.

Goal: convert these into a panic-style report identifying the spawn site and the run-time stack bounds, so the user can act.

---

## Mechanism

Install a `SIGSEGV` handler with `SA_ONSTACK`. The handler runs on the per-M alt signal stack — already wired up by `runtime::sched::m::install_signal_stack` for SIGURG (commit `eada612` M18b-δ.3). Critically, the alt stack is the only place that's *guaranteed* to have room when the user G's stack is exhausted.

When SEGV fires, the handler:

1. Reads `si_addr` from the `siginfo_t`.
2. Looks up the currently-running G via `current_g()` (lock-free TLS read, same pattern as `gopark`/`mcall`).
3. Classifies the fault by checking `si_addr` against:
   - **Home-stack overflow:** `si_addr ∈ [g.stack.lo - PAGE, g.stack.lo + PAGE]`.
   - **Grown-region overflow:** `si_addr ∈ [region.lo - PAGE, region.lo + PAGE]` for any region in `g.growth_chain`.
   - **Genuine memory bug:** chain to default handler, abort with core dump.
4. Emits a diagnostic.
5. Calls `Exit(2)` (process abort, v1).

---

## What exists vs. what's missing

| Piece | Status |
|---|---|
| Alt signal stack per M (`sigaltstack(2)`) | ✅ shipped (M18b-δ.3) |
| `current_g()` lock-free TLS read | ✅ shipped |
| `G.stack.lo` / `G.stack.hi` accessible | ✅ shipped |
| `G.growth_chain` for grown-region bounds | ✅ shipped (lazy-allocated 8 B pointer post-`19d0f6c`) |
| SIGSEGV handler install | ❌ — clone of `runtime::preempt::install_sigurg` |
| `si_addr` classification logic | ❌ — ~30 LOC |
| Spawn-site capture on `G` | ❌ — `go!()` macro pinch + 16 B per G |
| Guard pages on stackpool slots | ❌ — would disambiguate "stack overflow" from "wild pointer" |

---

## Diagnostic shape (option 1: process abort)

```
goish: stack overflow
  goroutine spawned at: examples/foo.rs:42 (`go!(|| crawl_tree(root))`)
  g.stack:    0x7f3a00102000 - 0x7f3a00102800 (2 KiB home)
  growth:     none (auto-grow body never pivoted past tier-1)
  fault addr: 0x7f3a00101f80 (8 bytes below stack base)
  saved RIP:  0x55a3c9d4e2b8 (in `crawl_tree` at examples/foo.rs:18)

  suggestion:
    - if recursion depth is bounded, use `go!(stack(64 * KB), …)` at
      the spawn site
    - if depth is unbounded, wrap each level in
      `runtime::sched::maybe_grow_step(|| …)` so the goroutine
      auto-grows past tier-1
```

After this, `Exit(2)`. Other goroutines are killed via process exit but the user gets a precise, actionable pointer to fix.

---

## Diagnostic shape (option 2: per-G panic recovery)

`gogo` to the G's `panic_recover` gobuf with `panic_value` set to a stack-overflow error. The G dies, other goroutines continue. The user can `recover!()` in a `defer!{}` if they want — and the stack-overflow goroutine still appears in the log.

**Risk:** with the global stackpool design (16 stacks per 32 KiB span), an overflowing G can corrupt a neighbor's stack 2 KiB below its base. Recovery in this case papers over real memory damage. Adjacent goroutines from the same span keep running with corrupted state. Without guard pages between slots, this is unsafe.

---

## Spawn-site identification

Add to the `go!()` macro:

```rust
go!(|| body)
// expands to (added file/line capture):
$crate::runtime::sched::newproc_at(file!(), line!(), Box::new($closure))
```

Stash on G as:
- `spawn_file: &'static str` — 16 B (str slice ptr + len)
- `spawn_line: u32` — 4 B

With commit `19d0f6c`'s `sizeof(G) = 256` (class 256, 16 slots/span), there are ~18 B of padding after `growable: bool`. The 20 B of spawn-site fields cross the 256→288 size-class boundary. Two mitigations:

1. **Pack `spawn_line` into existing padding** alongside `growable`/`select_wait_len`/`status` (1+1+1+1 = 4 bytes already; could overlay `u32 line_spawn`). 16 B remains for `spawn_file` ptr+len, but stays under 256 if we drop `panic_recover`'s 64 B Gobuf via lazy allocation (next field-shrink step).

2. **Defer the field add**: keep file/line in a side table `static SPAWN_SITES: SpinLock<map<*mut G, (str, u32)>>` indexed by G pointer. Looked up only on SEGV (cold path) — no per-G memory cost. 32 B per spawn entry × N concurrent goroutines is small relative to the G heap, and the table can be GC'd at goexit.

Recommendation: side table. Keeps `sizeof(G) = 256` intact for the 1M demo.

---

## Guard-page question

Without guard pages, `si_addr` classification is *heuristic*:

- A wild pointer that happens to land near `g.stack.lo` looks like a stack overflow.
- Heuristic mitigation: inspect the faulting instruction at `ucontext.RIP`. CALL / PUSH / `SUB rsp, X; MOV [rsp+Y], …` patterns indicate a stack write. Other instructions (`MOV [rax], …` on a wild pointer) indicate the user's bug.
- Imperfect — fragile across compiler-emitted prologue variants.

Adding `PROT_NONE` guard pages at the bottom of each stackpool carve costs 4 KiB per stack (doubles per-G virtual). Kills the 1M-goroutine story (2 GiB → 6 GiB virtual at 1M).

**For v1:** skip guard pages, accept heuristic classification. Document it in the diagnostic ("likely stack overflow at fault addr X within K bytes of stack base"). The 99% case (real overflow) is identified correctly; the 1% case (wild pointer near stack base) gets a misleading message — still better than silent SEGV.

**For v2:** consider guard pages on a per-spawn opt-in basis (`go!(stack(N), guard, || …)`) for goroutines where the user really wants a hard line.

---

## Acceptance criteria

1. **Build a smoke test** that overflows on purpose:
   ```rust
   #[inline(never)]
   fn overflow(n: i64) -> i64 {
       let _scratch: [u8; 4096] = [0; 4096];   // big frame, fast overflow
       overflow(n + 1) + _scratch[0] as i64
   }
   #[goish::main]
   fn main() {
       go!(stack(2 * KB), move || { overflow(0); });   // line 42
       schedule();
   }
   ```
2. Running it should print the diagnostic above and exit with code 2.
3. The exit code should be distinguishable from non-stack-overflow SEGV (which still aborts with the default handler / core dump).
4. e2e regression: `make e2e LOOPS=5` stays 690/690 (the handler is dormant unless SIGSEGV fires).

---

## Engineering plan (if we ship)

| Step | LOC | File |
|---|---|---|
| 1. Add SIGSEGV install path | ~50 | `runtime/preempt.rs` |
| 2. Classification logic + diagnostic | ~80 | new `runtime/segv.rs` |
| 3. Side-table for spawn sites | ~40 | new — lock-free hashmap of `*mut G → (file, line)` |
| 4. `go!()` macro pinch — capture `file!()`/`line!()` | ~10 | `builtin_macros.rs` |
| 5. `newproc_at(file, line, closure)` runtime fn | ~15 | `runtime/sched/scheduler.rs` |
| 6. `examples/segv_diagnostic_smoke.rs` | ~40 | new |
| 7. Doc update | ~20 | `AGENTS.md` (new §11 or §12) |

Total: ~255 LOC. About a half-day's careful work.

---

## Recommendation

Ship **option 1 (process abort with diagnostic)** + **side-table for spawn sites** + **heuristic classification (no guard pages)** for v1. About 2-3 hours. Per-G recovery (option 2) is correct only after guard pages land, which is a separate memory-budget conversation.

The user-facing benefit is enormous: today a stack overflow is a silent SEGV with a core dump; under this design it's a precise pointer to the `go!()` site that needs `stack(N)` or `maybe_grow_step`. That's a quality-of-life win for every Goish user who has ever had to bisect "which goroutine overflowed."

---

## Cross-references

- `runtime::sched::m::install_signal_stack` — the SA_ONSTACK / sigaltstack setup we'd reuse.
- `runtime::preempt::install_sigurg` — the SIGURG handler-install pattern; SIGSEGV install is a clone with different signum + different handler body.
- `runtime::sched::g::G::panic_recover` — would be the gogo target if we ever ship option 2.
- `examples/grow_park_smoke.rs`, `examples/grow_3tier_smoke.rs` — existing auto-grow tests; unrelated but in the same family.
- `feedback_main_is_not_a_goroutine.md` (memory) — the bootstrap thread is *not* a goroutine and has no `current_g()`; the SIGSEGV handler must check for that and chain to default.
