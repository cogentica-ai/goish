# M18b-δ.3 — Clobber-Free Resume-PC Algorithm (offline design)

This document specifies, *offline* (i.e. without modifying the running runtime),
a per-G resume-PC delivery algorithm for the SIGURG async-preempt path that is
clobber-free **by construction** — not by defended races. A standalone proof
harness (`examples/preempt_slot_offline_proof.rs`) exercises the algorithm in
isolation and verifies the construction holds under multi-thread stress.
Integration into `src/runtime/preempt.rs` happens only after the proof passes.

The red zone is preserved (SysV ABI is a fixed constraint — see
`feedback_no_redzone_off_limits.md`). All slot writes happen *below* the user's
128-byte red zone window, exactly like the current scheme.

## Current scheme (M18b-δ.2)

```
handler:                          trampoline (asm):
  *fs:[X] = pc                      sub rsp, 128
  ucontext.RSP -= 8                 push qword fs:[X]      ← snapshot M-slot to G stack
  ucontext.RIP = trampoline         push rbp ; ...
                                    call async_preempt2
                                    ... restore ...
                                    add rsp, 128 ; add rsp, 8
                                    jmp qword [rsp - 144]  ← read snapshot
```

Two writers, one reader, one shared per-M intermediate (`MStorage.preempt_resume_pc`).
The trampoline copies the per-M slot to G's own stack at `[user_sp - 144]`
within the first 2 instructions, after which subsequent preempts on the same M
can freely overwrite the per-M slot without affecting the in-flight trampoline.

The window between `handler write` and `trampoline snapshot` is defended by the
`is_in_trampoline(pc)` filter in the handler — a re-entrant SIGURG arriving in
that window sees PC ∈ trampoline range and skips. The defense is structurally
correct, but introduces a coordination point that is non-trivial to reason
about and potentially adds a load-bearing role for `is_in_trampoline`'s exact
PC range.

## Proposed scheme (M18b-δ.3) — handler-direct G-stack write

Eliminate the per-M intermediate entirely. The handler writes the resume PC
*directly* to the G's stack at the same `[user_sp - 144]` slot the trampoline
already reads. The trampoline skips the snapshot push and just advances RSP
past the slot.

```
handler:                          trampoline (asm):
  *((sp - 144) as *mut u64) = pc    sub rsp, 128
  ucontext.RSP -= 8                 sub rsp, 8             ← skip pre-written slot
  ucontext.RIP = trampoline         push rbp ; ...
                                    call async_preempt2
                                    ... restore ...
                                    add rsp, 128 ; add rsp, 8
                                    jmp qword [rsp - 144]  ← read slot (handler wrote)
```

The `MStorage.preempt_resume_pc` field can be deleted. There is no per-M
shared intermediate. The handler-to-trampoline data path is a single store
to G-private memory.

### Slot location: `[ucontext.RSP - 144]`

The slot offset is unchanged from the current scheme so the trampoline epilogue's
final `jmp qword [rsp - 144]` reads the correct address. The address is computed
from the kernel-saved RSP (which is the user G's pre-SIGURG RSP), so it is
stable across thread migration, OS preemption, and signal nesting.

### Why this is clobber-free *by construction*

Let `S_i = ucontext.RSP_i - 144` for the i-th preemption of any G.

**Property 1: Slot is on G's own stack.**
By construction, `ucontext.RSP_i` is the user G's RSP at the moment of preemption,
which lies within `[g.stack.base, g.stack.top)` (this is the SP-range check the
handler already runs as condition #6 of `isAsyncSafePoint`). So
`S_i ∈ [g.stack.base - 144, g.stack.top - 144)`, which is on G's stack
(modulo the 144-byte adjustment, which is well within the 64 KiB stack since
the SP-range check requires `sp ≥ stack_lo + ASYNC_PREEMPT_STACK = stack_lo + 1024`).

**Property 2: Different Gs occupy disjoint stack regions.**
Each `Stack` is a separate `mmap` (see `runtime::sched::stack`); the kernel
guarantees disjoint virtual address ranges. Therefore for distinct goroutines
G_a and G_b, their slots `S_a` and `S_b` are at distinct physical addresses.

**Property 3: At any moment, at most one M is preempting any given G.**
Preemption acts only on `current_g` of an M. A G is `current_g` of at most
one M at a time (scheduler invariant: G's status transitions Runnable→Running
under exclusive ownership). So sequential preemptions of the same G happen
in M-serialized order, never in parallel.

**Property 4: Within a single trampoline lifecycle on G, the slot is not
overwritten between write and read.**

The lifecycle:
- T0: handler writes `*S = pc` (handler runs on M's thread, with G suspended
       by the kernel).
- T1: kernel sigreturn → trampoline executes on G's stack.
- T2: trampoline shifts RSP to `user_sp - 8 - 128 = user_sp - 136`, then
       `sub rsp, 8` → `user_sp - 144`. **No write to `[user_sp - 144]`.**
- T3: trampoline pushes `rbp` at `[user_sp - 152]`, then `pushfq` at
       `[user_sp - 160]`, then save area at `[user_sp - 544]` and below.
       **All writes are below `[user_sp - 152]`, never touching `S`.**
- T4: trampoline calls `async_preempt2` → `Gosched` → `swap_context` to g0.
       G's stack becomes dormant; M dispatches another G.
- T5: M (or another M, if stolen) re-dispatches G. `swap_context` restores
       G's gobuf-saved RSP and RBP. Control returns mid-`async_preempt2`,
       which returns to the trampoline body, which restores GPRs/XMMs.
- T6: epilogue tears down: `lea rsp, [rbp-8]` → `popfq` → `pop rbp` (RSP
       now `user_sp - 144`) → `add rsp, 8` (RSP `user_sp - 136`, **skipping
       slot S**) → `mov rax, [rsp]` (reads user_rax slot at -136) →
       `add rsp, 128` (RSP `user_sp - 8`) → `add rsp, 8` (RSP `user_sp`).
- T7: `jmp qword [rsp - 144]` reads `*S` (which still contains `pc`) and
       jumps.

At T2 and T6, RSP transits through `user_sp - 144` via `sub`/`add` — these
instructions modify RSP but **do not memory-access the slot**. No instruction
in the trampoline writes to `[user_sp - 144]` between T0 and T7.

Step T4 (yield + dispatch other Gs) is the cross-park scenario. While G is
dormant, only the scheduler / runtime / other Gs are running. By Property 2,
their writes are to other Gs' stacks, never G's. Therefore S is preserved
across the yield.

**Property 5: Re-entrant SIGURG during the trampoline cannot redirect to
overwrite S.**

Between T0 and T7, if a re-entrant SIGURG arrives:

- During the trampoline asm (T1-T2, T6-T7): handler's `is_in_trampoline(pc)`
  filter rejects injection. Handler does not write S.
- During `async_preempt2` (T3-T4): PC is in `goish_rt_text` section; handler's
  `is_in_runtime(pc)` filter rejects injection. Handler does not write S.
- During swap_context: handler's `is_in_swap_context(pc)` filter rejects
  injection. Handler does not write S.
- During scheduler / dispatcher work on g0: `current_g` is None or some other
  G; handler either skips (no curg) or writes a *different* slot (other G's
  stack). Does not touch S.

In no re-entrant case does the handler write to S of the in-flight trampoline.
This relies on the same PC-filter machinery the current scheme uses, but with
a strictly smaller exposed surface — the `(handler write) → (trampoline push)`
window is gone.

### Differences vs current scheme

| Property                          | Current (δ.2) | Proposed (δ.3) |
|-----------------------------------|---------------|----------------|
| Per-M `preempt_resume_pc` slot    | yes (UnsafeCell<u64>) | gone |
| Trampoline reads `fs:[X]`         | yes (push)    | no |
| Slot writer                       | handler + trampoline (copy) | handler only |
| Slot reader                       | trampoline final jmp | trampoline final jmp |
| Window: handler→snapshot          | ~3 instructions | ZERO (handler writes final slot) |
| Defended by `is_in_trampoline`    | yes (load-bearing) | yes (still used to skip during trampoline body) |
| Async-signal-safe                 | yes           | yes (single 8-byte aligned store) |

### Async-signal safety of the handler write

The handler writes a single 8-byte aligned `u64` to G's stack. This is
async-signal-safe:
- The store is a single x86-64 `MOV` — atomic at the word boundary.
- The destination is memory the M owns (G's stack, while G is current_g).
- G's user code is suspended (the kernel saved its context to invoke the
  handler), so no concurrent write from G's own thread.
- Other Ms cannot reach G's stack (G is current_g of this M only —
  Property 3).

No locks acquired, no allocations, no syscalls. ✓

## Standalone proof harness

`examples/preempt_slot_offline_proof.rs` simulates the algorithm at the
data-plane level (no actual signals or asm). It allocates N fake "goroutine
stacks" via `mmap`, mirrors the handler/trampoline slot mechanics in plain
Rust, and stress-tests:

- **Single-thread sequential proof**: for each of N stacks, write a unique
  PC to slot, read back, assert equal. Repeat M times across stacks
  interleaved. Verifies no aliasing.
- **Cross-park proof**: thread T1 writes slot_a, then writes slot_b, then
  reads slot_a (must still be pc_a). Verifies a yielded G's slot is not
  clobbered by subsequent preempts on different Gs.
- **Multi-thread independent-stacks proof**: K threads, each owning a disjoint
  subset of stacks, repeat the sequence. Verifies no false sharing across Ms.

If all three sub-proofs pass with zero clobbers across millions of iterations,
the slot mechanism's structural claim is empirically corroborated. This does
*not* prove the integrated path — that requires `chan_micro_select_send_only`
stress on the real runtime — but it proves the *slot algorithm* in isolation.

## Integration plan

1. Modify `src/runtime/preempt.rs`:
   - Handler: replace `*storage.preempt_resume_pc.get() = pc` with a direct
     write to `((sp - 144) as *mut u64).write(pc)`.
   - Trampoline: replace `push qword ptr fs:[{resume_pc_offset}]` with
     `sub rsp, 8`. Remove the `resume_pc_offset` template arg.
2. Remove `MStorage.preempt_resume_pc` field (`src/runtime/sched/m.rs`).
3. Build, run `examples/chan_micro_select_send_only` stress (≥500 iterations),
   compare residual rate to δ.2's 4%.
4. Run full 130-example regression suite.
5. Commit as M18b-δ.3.

If the residual rate drops to 0%, the per-M slot was indeed load-bearing and
the algorithm fixed it. If it stays ~4%, the bug is elsewhere — the proof
still has standalone value (simpler scheme, fewer race windows), and the
investigation continues with the per-M slot ruled out.

## Post-mortem: integration regressed (441/500 = 88.2% pass, vs δ.2's ~96%)

**The algorithm-as-designed has a flaw. The proof harness missed it.**

When the SIGURG handler runs on Linux x86-64 *without* `SA_ONSTACK`, the
kernel allocates a `rt_sigframe` directly on the user's stack, immediately
below the 128-byte red zone. The frame layout is:

```
sp_user                                  ← user's RSP at preempt
sp_user - 128                            ← end of red zone (kernel skips this)
[(sp_user - 128) aligned down to 16]     ← top of rt_sigframe
  pretcode  (8 bytes)                    ← restorer pointer
  uc_flags  (8 bytes)                    ← start of ucontext
  ...uc_link, uc_stack, uc_mcontext...
  ...siginfo_t...
  ...FPU state (XSAVE area, can be ~3 KB on AVX-512 hosts)...
[bottom of rt_sigframe]
[handler's own stack frame]              ← handler RSP starts here
```

So at handler-time, the address `[sp_user - 144] = [sp_user - 128 - 16]` is
**inside the kernel's still-active rt_sigframe** — specifically clobbering
~16 bytes of `pretcode` + `uc_flags`. After the handler returns, the kernel's
sigreturn reads from this same frame to restore user state. Sometimes this
succeeds (the clobbered field happens to be unused on this path); sometimes
it fails (uc_flags affects sigreturn behavior; pretcode if used by SA_RESTORER
== 0). Hence intermittent regression to 11.8%.

The δ.2 scheme works because the trampoline's `push qword fs:[…]` runs
**after** sigreturn, when the rt_sigframe has been popped — so writing to
`[sp_user - 144]` at trampoline-time hits free user-stack territory. My
δ.3 design moved the write into the handler, into still-occupied sigframe
territory.

### Why the proof harness gave a false green

`examples/preempt_slot_offline_proof.rs` correctly verified slot
**disjointness across G stacks** and **per-stack fidelity** under simulated
trampoline body writes. It did **not** simulate sigframe occupancy at
handler-time, because the harness ran without actual signals and modeled the
slot as if the user stack were "free below the red zone" (which is true
post-sigreturn but not at handler-time).

A correct future proof harness would either:
- Run an actual SIGURG path with the proposed slot offset, observing
  whether sigreturn succeeds, OR
- Statically compute the rt_sigframe size on the target kernel (parse
  `/proc/sys/kernel/exec_envvars` or use `getauxval(AT_MINSIGSTKSZ)` if
  available) and assert the slot is below it.

### Path forward (if pursuing this further)

Two options:

1. **Deeper slot offset (e.g., `[sp_user - 8192]`)** that's reliably below
   any plausible rt_sigframe. Requires:
   - Bumping `ASYNC_PREEMPT_STACK` to ≥ 8192 + working budget.
   - Updating the trampoline epilogue's final `jmp qword [rsp - N]` with
     the new offset.
   - A standalone test that *measures* actual sigframe size on this kernel
     (CPU FPU class) and asserts the chosen offset is safe.

2. **Use `SA_ONSTACK` + `sigaltstack(2)`** so the signal handler runs on a
   dedicated alternate stack. Then the user's stack at `[sp_user - 144]` is
   genuinely free at handler-time. This is what Go does
   (`runtime/signal_unix.go:setSignalstackSP` + `signalstack`). Substantially
   more infrastructure, but matches Go's design exactly.

Option 2 is the right answer long-term, but is a larger undertaking. Option 1
is a tactical fix.

### Status as of revert

- `src/runtime/preempt.rs` and `src/runtime/sched/m.rs`: **reverted to δ.2.**
- `doc/M18b-delta3-clobber-free-resume-pc.md`: kept (this file).
- `examples/preempt_slot_offline_proof.rs`: kept; passes its 4 sub-proofs
  but the proofs are *necessary but not sufficient* — they don't model
  sigframe occupancy. Future work should add a sigframe-aware sub-proof.
- `feedback_no_redzone_off_limits.md`: stays in memory — preserving SysV
  ABI is still a fixed constraint.

Net effect: zero behavioral change vs δ.2 baseline. We learned that the
δ.2 per-M slot scheme is *not* incidental — it's load-bearing because it
relegates the G-stack write to post-sigreturn, where the sigframe is gone.
Eliminating the per-M slot requires eliminating sigframe occupancy first
(option 2 above).
