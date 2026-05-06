# M17b-δ: Math Model of the Sudog Wake Protocol

A formal state-transition model of goish's chan/select wake
protocol, used to determine whether the empirical rc=2
("send on closed channel" panic on a never-closed channel)
can be produced by the protocol itself, or whether the bug
must lie outside it.

## 1. State

```
Per chan c:
  c.closed : Bool                     -- false initially, monotonically Bool
  c.cap    : ℕ                        -- immutable after construction
  c.buf    : List<T>                  -- |c.buf| ∈ [0, c.cap]
  c.sendq  : List<*Sudog>              -- FIFO of parked senders
  c.recvq  : List<*Sudog>              -- FIFO of parked receivers
  c.lock   : Mutex                    -- exclusive access to all c.*

Per Sudog s (stack-allocated on owning G):
  s.value  : Option<T>                -- send: Some(v); recv: None initially
  s.success: Bool                     -- false initially
  s.g      : *G                       -- immutable: owning G
  s.coord  : Option<*SelectCoord>      -- None for plain Send/Recv

Per SelectCoord k (stack-allocated):
  k.done   : AtomicBool               -- false initially

Per G g:
  g.status : { Idle, Runnable, Running, Waiting, Dead }

Per M m:
  m.curg, m.waitunlockf, m.waitlock, m.locks
```

**Sudog lifetime invariant (LIVE):** at any time, every entry of
every chan's `sendq`/`recvq` points to a Sudog whose owning G is
in state `Waiting` (parked) or in the brief transition window
between "matched by waker" and "G resumes execution".

## 2. Transitions (atomic w.r.t. `c.lock`)

### TS — `Send(c, v)` from goroutine `g`

```
1. lock(c)
2. if c.closed → unlock; PANIC "send on closed"      -- T_send_closed
3. for s in c.recvq:
     if try_claim(s):                                -- T_send_match_recv
       c.recvq.remove(s)
       s.value  := Some(v)
       s.success := true
       goready(s.g)
       unlock(c); RETURN
4. if |c.buf| < c.cap:                              -- T_send_buf
     c.buf.push_back(v); unlock(c); RETURN
5. -- Park path                                      -- T_send_park
   s_s := new_send(g, v)
   c.sendq.push_back(&s_s)
   gopark(chan_park_commit, c.lock_atom)
   -- (chan_park_commit unlocks c on g0 post-swap)
   -- RESUME after some waker calls goready(g)
6. if !s_s.success: PANIC "send on closed"           -- T_send_resume_panic
7. RETURN
```

### TR — `Recv(c) → (v, ok)` from goroutine `g`

```
1. lock(c)
2. if c.closed ∧ |c.buf|==0 → unlock; RETURN (zero, false)
3. for s in c.sendq:
     if try_claim(s):                                -- T_recv_match_send
       c.sendq.remove(s)
       sender_v := s.value.take()                    -- s.value becomes None
       v := if c.cap==0 then sender_v
            else (let h = c.buf.pop_front();
                  c.buf.push_back(sender_v); h)
       s.success := true
       goready(s.g)
       unlock(c); RETURN (v, true)
4. if |c.buf| > 0:                                   -- T_recv_buf
     v := c.buf.pop_front(); unlock(c); RETURN (v, true)
5. -- Park path                                      -- T_recv_park
   s_r := new_recv(g)
   c.recvq.push_back(&s_r)
   gopark(...)
   -- RESUME
6. if !s_r.success: RETURN (zero, false)
7. v := s_r.value.take(); RETURN (v, true)
```

### TC — `Close(c)`

```
1. lock(c)
2. if c.closed → unlock; PANIC "close of closed"
3. c.closed := true                                  -- T_close_set
4. for s in c.recvq (claimable):                     -- T_close_wake_recv
     remove(s); s.success := false; s.value := None
     goready(s.g)
5. for s in c.sendq (claimable):                     -- T_close_wake_send
     remove(s); s.success := false
     goready(s.g)
6. unlock(c)
```

### TSel — Select with N cases (sketch)

```
P1 (try): lock all chans (lock-order). For each case in poll order,
   try TS step 3-4 or TR step 3-4 under held locks. On hit,
   release all, run body.
P2 (register+park): allocate select coord k, allocate sudogs
   {s_i} with s_i.coord = &k. Register each s_i in its chan's
   queue. selparkcommit unlocks all chans on g0 post-swap.
P3 (cancel): post-resume, walk chans; for each, lock, retain
   (remove s_i if still there), unlock. Identify winner = the
   case whose retain found nothing. Run that body.
```

`try_claim(s)` semantics:
- if `s.coord == None`: returns `true` unconditionally.
- if `s.coord == Some(k)`: returns `k.done.cas(false, true)` — the
  first claimer wins; subsequent attempts fail.

## 3. Invariants

**INV-WAKE**: For every G `g` parked via `T_send_park` (i.e.,
`g.status` transitions to `Waiting` with sudog `s_s` in some
`c.sendq`), the unique `goready(g)` call that resumes `g` is
issued by exactly one of:
- (W-match) `T_recv_match_send` on chan `c`, having set
  `s_s.success := true`.
- (W-close) `T_close_wake_send` on chan `c`, having set
  `s_s.success := false`.

**INV-CLOSED**: `c.closed` is `false → true` monotonic; only
`T_close_set` writes it.

## 4. Theorem (chan-protocol soundness)

**Claim.** If `c.closed` remains `false` throughout the lifetime
of program execution (no `Close(c)` ever runs on chan `c`), then
no goroutine `g` parked via `T_send_park` on chan `c` resumes
with `s_s.success == false`.

**Proof.**

Consider any goroutine `g` that completes `T_send_park` on `c`
with sudog `s_s ∈ c.sendq`. By INV-WAKE, `g` resumes only via
`goready(g)` issued by either (W-match) or (W-close).

(W-close) requires `T_close_wake_send` on `c`, which requires
`T_close_set` to have run, which sets `c.closed := true`. By
hypothesis `c.closed` is `false`. Contradiction. So (W-close)
cannot happen.

Therefore the only path to `goready(g)` is (W-match), which sets
`s_s.success := true` before issuing the wake. By the memory-
ordering chain (Lemma 5 below), `g`'s post-resume read of
`s_s.success` returns `true`. ∎

## 5. Memory-ordering Lemma

The chan-lock release on the waker's M (in `unlock(c)` or in
`chan_park_commit` for the parker side) is a `Release` store on
`c.lock_atom`. The next acquirer's `Acquire` CAS synchronizes-
with that Release. Within `T_recv_match_send` the writes
`s_s.value := Some(v)` and `s_s.success := true` happen-before
`goready(s.g)`. `goready` calls `enqueue_runnable → runqput`,
whose tail store is `Release` (`p.rs:350`). The dispatcher M's
`runqget` does `runqhead.load(Acquire)` and `runqtail.load(Acquire)`
(`p.rs:414-415`). Acquire-Release synchronizes; all writes on
the waker M before `runqput` are visible after `runqget` on the
dispatcher M. The dispatcher's `swap_context` restores the
parker's RIP/RSP; the very next instruction reads `s_s.success`
and observes `true`. ∎

## 6. Where the bug must lie (since the model is sound)

The empirical stress test produces rc=2 panics on a chan that is
never closed. By §4, the chan protocol *as modeled* cannot
produce this. The bug therefore lies in something the model
does not capture:

**Candidate 1 — runtime/scheduler interactions outside the chan
lock.**
- Async-preempt (SIGURG) injection during runtime-asm windows.
  The handler has guards (m.locks==0, waitunlockf==None, PC
  range, status==Running, SP range). If any guard is wrong, an
  injection mid-park could leave `m.waitunlockf` pointing to
  preempt's commit fn while the chan-park's commit fn was
  already consumed — leading to chan lock leaked or sudog
  abandoned in queue.
- `cooperative_preempt_check` in `raw_unlock` calls `Gosched`
  unconditionally on flag set. If the flag is set spuriously
  while a chan operation is mid-handoff but post-unlock, the G
  yields with a sudog still pointing to a stale stack frame.

**Candidate 2 — G memory reuse (UAF on freed stacks).**
- A G dies (status=Dead) and its 64 KiB mmap stack is
  `munmap`-ed (`stack.rs:79`).
- The kernel later returns the same VA to a fresh `mmap` for a
  newly-spawned G.
- A stale sudog pointer (in some chan's `sendq`/`recvq`)
  pointing to the dead G's stack now points into the *new* G's
  stack at the same offset. The new G's sudog (freshly
  initialized with `success=false`) gets observed by an
  unrelated waker who follows the stale pointer.

  For this to fire we need a sudog to outlive its G. The chan
  protocol says no (pass-3 + waker-removal cleans up before
  G returns). So this requires a *bug in cleanup*: e.g., a
  pass-3 cancel that runs but fails to retain the right
  pointer, or a panic mid-cleanup.

**Candidate 3 — concurrent write to `s.success` outside the
chan lock.**
- The chan lock release (Release) → next chan lock acquire
  (Acquire) synchronizes the value of `s.success` between
  waker and parker. But if anything *else* writes `s.success`
  *without* going through the chan lock, the synchronization
  chain is broken.
- Audit candidates: the macro pass-3 dispatch code reads
  `$br_sn.success` / `$pr_sn.success` / `$s_sn.success`. None
  write `success`. ✓
- Plain `Send`/`Recv` post-park reads `my_sudog.success` and
  for recv `my_sudog.value.take()`. The take mutates `value`
  but not `success`. ✓
- `Sudog::new_*` constructors set `success := false`. These
  run on the owner's stack frame at function entry — the
  sudog isn't yet visible in any queue, so no waker can
  concurrently access it. ✓

  No code outside `T_recv_match_send` / `T_send_match_recv` /
  `T_close_wake_*` writes `s.success`.

## 7. Conclusion

The chan/select wake protocol, in isolation, cannot produce the
rc=2 panic on a never-closed chan. The bug must lie in
Candidate 1 (scheduler/preempt) or Candidate 2 (G memory
reuse). Candidate 1 is more likely because:
- The 64 KiB stack pool turns over slowly (only on G death).
- The test creates 10 Gs at startup that never die (they all
  finish exactly after `schedule()` drains).
- If only 10 Gs ever exist and they all stay alive through the
  whole test, no stack reuse is possible.

  → Candidate 2 is **ruled out** by the test's structure.

Therefore the bug is in the **scheduler/preempt path**, and
the next investigation should target:
- The window between SIGURG handler's guard checks and
  injection.
- `cooperative_preempt_check` mid-chan-op.
- A possible `goready` reaching a parked sender via a
  non-chan path (timer, sema, preempt).

## 8. Targeted next experiment

A small, controlled program that:
1. Spawns exactly 2 goroutines — one sender, one receiver — on
   a single unbuffered chan.
2. Loops `N=1e6` Send/Recv iterations.
3. Disables select! entirely (no coord, no pass-3 races).
4. Asserts that the sender never sees `success=false`.

If this micro-test reproduces rc=2, the bug is in the
fundamental chan/scheduler interaction (rules out select
specifics). If it doesn't, the bug needs the multi-goroutine
+ select interaction surface (10 Gs + 4 chans).

Either result narrows the search significantly.
