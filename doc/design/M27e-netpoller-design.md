# M27e — epoll netpoller design

Goal: lift the NumCPU-concurrency cap on `net::Listener::Accept` /
`net::Conn::Read` / `net::Conn::Write`. After M27e, an HTTP server
running on N=4 P's handles thousands of in-flight connections;
goroutines parked on I/O do not pin an M.

This is a slim port of `runtime/netpoll.go` + `runtime/netpoll_epoll.go`
(Go 1.25). Sections below name the Go file:line we're porting from.

## Surface area we port (and what we skip)

Ported (M27e):
- `pollDesc { fd, rg, wg }` — per-fd parker state (netpoll.go:75).
- `netpollinit` — single epoll fd + single eventfd (netpoll_epoll.go:21).
- `netpollopen / netpollclose` — register/unregister fd as `EPOLLIN |
  EPOLLOUT | EPOLLRDHUP | EPOLLET` (netpoll_epoll.go:49, :57).
- `netpollblock / netpollunblock` — gopark current G into rg/wg, atomic
  CAS unblock from `pdWait` → ready (netpoll.go:548, :591).
- `netpoll(delay) → gList` — drain epoll_wait, build runnable list
  (netpoll_epoll.go:99). delay∈{-1, 0, ns}.
- `netpollBreak` — eventfd write, wakes a blocked netpoll
  (netpoll_epoll.go:67).

Deferred to a follow-up milestone:
- Deadlines (`rd`, `wd`, `rt`, `wt` timer fields, `pollSetDeadline`,
  `netpolldeadlineimpl`). API stubs return `nil` so user code that
  calls `SetReadDeadline` keeps compiling.
- Tagged-pointer `fdseq` (netpoll.go:79) — stale-event protection
  across fd close/reopen. EPOLL_CTL_DEL + close drops pending events
  on Linux, so v1 is safe under the current API; revisit if we ever
  recycle pollDescs without going through close.
- `pollCache` slab (netpoll.go:688). v1 leaks one `Box<PollDesc>` per
  open fd (~80 bytes). Same Box-leak strategy we already use for `G`.
- `closing` / `eventErr` / `pollInfo` atomic bits — useful for shutdown
  semantics; the v1 API surface is "Close drops the fd, parked
  goroutines wake with EBADF on retry" which is good enough.

## Public API (no churn for callers)

The signatures of `net::Listen`, `net::Dial`, `Listener::Accept`,
`Conn::Read`, `Conn::Write`, `Conn::Close` do **not** change. What
changes is what they do internally:

- Listening / dialed sockets get `O_NONBLOCK` set.
- Each fd lazily gets a `PollDesc` registered on first I/O.
- Blocking syscalls become `try → EAGAIN → netpoll_block(pd, mode) → retry`.

User code (`http_hello.rs` and friends) is untouched.

## Internal layout

```
src/runtime/netpoll/
  mod.rs        — pollDesc, init, open, close, block, ready, break, netpoll(delay)
                  ~350 LOC. Single epoll fd + eventfd. Box::leak for pollDesc.
src/syscall/mod.rs
  + SYS_EVENTFD2 (= 290)
  + EFD_CLOEXEC, EFD_NONBLOCK
  + Eventfd(initval, flags) -> i32
src/net/mod.rs
  Listener.fd is now O_NONBLOCK; lazy pd field.
  Conn.fd is now O_NONBLOCK; lazy pd field.
  Accept/Read/Write loops on EAGAIN.
src/runtime/sched/scheduler.rs
  find_runnable() — after steal_work, call netpoll::poll(0) and push
    its gList onto the global runq before returning None.
src/runtime/sysmon.rs
  Periodic netpoll::poll(0) tick — keeps slow-path I/O moving even if
  every M is in user code with a non-empty runq.
```

## pollDesc state machine (verbatim from Go)

`rg` and `wg` are `AtomicUsize`, each in one of four states:
| value     | meaning                                         |
|-----------|-------------------------------------------------|
| `pdNil=0` | no waiter, no pending notification              |
| `pdReady=1` | fd is ready; next `block` returns immediately |
| `pdWait=2` | a goroutine is preparing to park on this slot |
| `*G`        | the parked goroutine                          |

Transitions:
- `block`: `Nil→Wait→{*G or Ready (race)}`. If `Ready`, consume → `Nil` and return ready.
- `unblock` (from epoll-ready): old → `Ready`. If old was `*G`, return that G to caller.
- `unblock` (from close): old → `Nil`. If old was `*G`, return G; caller wakes.

Concurrent block calls in the same mode are forbidden (Go panics
"runtime: double wait"). For Conn this is naturally enforced — a Conn
is owned by one goroutine for reading and one for writing.

## Scheduler integration

`find_runnable()` (scheduler.rs:110) is the only hot integration point:

```rust
fn find_runnable() -> Option<NonNull<G>> {
    if let Some(p) = current_p() { if let Some(g) = unsafe { p.runqget() } { return Some(g); } }
    if let Some(g) = globrunqget_one() { return Some(g); }
    if let Some(g) = steal_work() { return Some(g); }
    // M27e: opportunistic netpoll.
    if let Some(g) = netpoll::poll_nonblocking() { return Some(g); }
    None
}
```

`poll_nonblocking()` calls `netpoll(0)`, drops the head G into the
global runq, and pops it. If the netpoll returned multiple Gs, the
rest go to the global runq. Zero allocation in the empty case.

For full-blocking netpoll (every P idle, no work anywhere), v1 uses
sysmon as the polling thread — it ticks every ~10ms and drains
`netpoll(0)`. A dedicated netpoll-M with `netpoll(-1)` is a small
optimization we can add later.

## Test plan

1. `examples/netpoll_smoke.rs` — open a Listener, spawn 1000 goroutines
   each dialing it, assert all 1000 Accept's return on a 4-P scheduler
   (impossible without netpoll: would deadlock or serialize on NumCPU).
2. `examples/http_hello.rs` rerun with 1000 concurrent curls — should
   match the existing 200/200 baseline at 5× the load with no
   degradation.
3. Strace one connection — verify exactly one `epoll_ctl(EPOLL_CTL_ADD)`
   per fd lifetime, accept loop sees `EAGAIN` then proceeds after
   `epoll_pwait` returns with `EPOLLIN`.
4. 100-run stress (`net_smoke` in a loop) — no SEGVs, no hangs.

## Sub-tasks

- **α** — syscall::Eventfd helper + EFD_* constants.
- **β** — `src/runtime/netpoll/mod.rs`: pollDesc + init/open/close/block/ready/break/poll. No callers yet.
- **γ** — wire `net::Listener` and `net::Conn` to use netpoll: O_NONBLOCK + EAGAIN loop + lazy pd registration.
- **δ** — scheduler `find_runnable` + sysmon hookup.
- **ε** (optional) — examples + 100-run stress + strace verification.
