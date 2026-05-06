# DISCUSSION_G_M_P.md — false-sharing risk on the stackpool path under goish's M-placement policy

Companion design note to `runtime::sched::stackpool` and the M/P scheduler. Captures a 2026-05-06 discussion about whether goish's stackpool design exposes goroutines to false-sharing across Ms, and whether the existing scheduler policy mitigates or aggravates it.

---

## The premise

Goroutine stacks are not allocated as individual OS pages. The runtime manages its own memory from larger chunks obtained from the OS, and sub-allocates goroutine stacks from those chunks. Linux's 4 KiB page granularity therefore does **not** apply at the goroutine level — the per-G memory accounting is whatever the runtime carves, not whatever the kernel reserved.

In goish, this is `runtime::sched::stackpool`: each 32 KiB span carries 16 stacks of 2 KiB. A million default goroutines therefore reserve ≈ 1M × 2 KiB = 2 GiB virtual, *not* 1M × 4 KiB = 4 GiB.

The cost is sharing: 16 goroutines per span means 16 stacks share the same ~8 cache lines per page across that 32 KiB region.

## The asymmetry

> The false-sharing risk on the stackpool path is asymmetric with respect to scheduler decisions. If the scheduler tends to co-locate goroutines from the same span on the same M (e.g., LIFO local runqueue), you get cache locality wins; if it spreads them across Ms, you get the contention. Worth measuring under the actual M-placement policy before deciding it's a real cost.

Two opposing scenarios share the same allocator design. Which one dominates depends on the scheduler's placement policy.

## What goish actually does

### Stackpool ownership: global single-locked, no per-M affinity

`stackpool.rs:1-23`:

> "Drops Go's per-P `stackcache` (deferred to a later refinement) … One global `SpinLock<StackPool>`."

Allocation order = spawn order = whoever holds the lock at that moment. There is **no per-M affinity at allocation time**. Slot N is handed to whichever M's `go!()` call is sequenced Nth through the lock, regardless of which M is bound to the calling goroutine.

### Runqueue placement: LIFO-ish on the spawning M

`p.rs:99` (`runnext: AtomicPtr<G>`) and `p.rs:489` (`runqget`):

- `go!()` → `newproc` → `enqueue_runnable` → puts the new G into the **spawning M's** per-P runqueue.
- Per-P `runnext` slot holds the most-recently-readied G; `runqget` tries `runnext` first, then drains the FIFO ring head.
- Net effect: recently-spawned Gs from one M tend to dispatch back on that same M.

This is the **co-location win** from the asymmetry — sequentially-spawned Gs share both stackpool span lines AND the M they run on.

### Work-stealing: random-victim + 50%-batch when contended

`scheduler.rs:111` (`find_runnable`):

```
local P → global runq → steal_work × 4 tries → netpoll
```

`p.rs:697` (`runqsteal`) grabs *half* of the victim's ring (Go's classic 50%-batch port).

This is the **contention path** from the asymmetry — when an M idles out, it pulls half of another M's local runq, splitting goroutines that were co-located on one M across two Ms.

## Behavior matrix

| Pattern | Cache effect |
|---|---|
| Burst spawn of N Gs from one M, low contention, mostly local-runq churn | **Locality win.** Sequentially-spawned Gs share a stackpool span and dispatch back to the spawning M via runnext+local. Same L1/L2 lines stay warm across context switches. |
| Contended fanout: 1 M spawns, several idle Ms steal | **Contention.** Half the runq migrates to a stealing M. If those stolen Gs were from the same span as the ones staying, two Ms now write to overlapping pages of that 32 KiB span. Cache-line ping-pong on the shared region. |
| All Ms saturated, no stealing fires | **Locality win** by default — each M churns its own local runq. |
| Sparse workload, lots of `Gosched` / chan-park-resume cycles | **Mostly locality win** — goready places G into the readying M's local runq. |

## What this means for the 1M-goroutine test

`examples/spawn_million.rs` is a *benign* shape:

- Initial spawn-and-distribute: 1M goroutines created from main, immediately park on a chan recv.
- Parked phase: zero stack writes per G (RSP saved in gobuf, no pages touched). False-sharing impossible — there are no writers.
- Wake-burst: each G does ~1 cache line of writes (atomic increments, EXITED store, WG.Done frame), one-shot.

After the spawn-distribute settles, false-sharing would only arise if multiple Ms wake adjacent slots on the same span concurrently. Bounded by GOMAXPROCS, transient, not a hot path.

The test passes 1M cleanly and the wake/release wave finishes in well under a second. **The asymmetry is real but doesn't bite this workload.**

## Where the asymmetry would bite

CPU-bound fan-out where the workers run concurrently on different Ms while hot:

- A parallel parser that fan-outs `go!()` workers, each crunching different segments of input.
- A sharded hash-map rebalance.
- Any "spawn N workers, all do CPU work" pattern.

In those, the contention path can dominate. The cost would show up as L1/L2 miss rate, measurable via `perf stat -e cache-misses` on goish-v1 binaries.

## Existing knobs for measurement

- `crate::runtime::flags::WORK_STEALING` (checked in `steal_work` at scheduler.rs:163) — toggle work-stealing at runtime via env var. Disable to bound the locality side; enable to bound the contention side; diff the metric.
- `crate::runtime::flags::STEAL_RUNNEXT` — toggle whether the last steal pass is allowed to claim a victim's `runnext` (which is the *most cache-warm* G, so stealing it has the highest contention cost).
- `GOISH_COOP_PREEMPT` (`flags.rs:9`) — disables cooperative preemption, removing one source of cross-M migration noise.

## The deferred lever

`stackpool.rs:1-23` itself names the fix: per-P stackcache. Each P (and therefore each M) allocates from its own pool, so spans are not shared across Ms. Eliminates the contention case entirely. Cost: more VMA / less span sharing → higher per-G memory cost (each P holds full spans even if only some slots are used).

The current "global-lock, share spans across Ms" choice optimizes for **span density** (the 1M-G memory budget) over **cache locality**. Given the M26 demonstration target (1M parked goroutines on a single 4 GB-physical machine), that's the right default.

If a workload-specific benchmark shows false-sharing as a hot spot, the per-P stackcache refactor is the correct response — at the cost of revisiting the 1M memory budget.

## Recommendation

**Measure before optimizing.** The asymmetry is real; the magnitude depends on the workload. The 1M demonstration test is benign for the reason described. Real CPU fan-out workloads need a `perf stat` pass before deciding whether per-P stackcache is worth its memory cost.

The toggleable flags above give the bisect tools without code changes.

---

## Appendix: relevant code paths

| File:line | What |
|---|---|
| `src/runtime/sched/stackpool.rs:20-23` | "One global `SpinLock<StackPool>`. … per-P stackcache deferred." |
| `src/runtime/sched/stackpool.rs:128-156` | `StackPool` definition; `partial[order]` head pointers per size class. |
| `src/runtime/sched/p.rs:97-99` | `runnext: AtomicPtr<G>` — the LIFO slot. |
| `src/runtime/sched/p.rs:401-450` | `runqput(gp, next)` — where `go!()` newly-spawned Gs land. |
| `src/runtime/sched/p.rs:489-530` | `runqget` — runnext first, then FIFO ring head. |
| `src/runtime/sched/p.rs:697-728` | `runqsteal` — half-batch 50% steal. |
| `src/runtime/sched/scheduler.rs:111-124` | `find_runnable` — local → global → steal → netpoll order. |
| `src/runtime/sched/scheduler.rs:160-217` | `steal_work` — 4 tries × random-permutation. |
| `src/runtime/flags.rs` | `WORK_STEALING`, `STEAL_RUNNEXT`, `COOP_PREEMPT` — runtime toggles. |
