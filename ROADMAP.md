# Roadmap

What is left, in the order it makes sense to do it. Current state lives
in [PROGRESS.md](PROGRESS.md); conventions and the rules a port must
follow live in [CONTRIBUTING.md](CONTRIBUTING.md).

## 0. Six decisions, and what each one closes

Sections 2b onward grew one finding at a time, and a reader cannot see
from them that most of what is open traces back to six choices. This
is that view. Nothing here is new; it is the same items, grouped by
what would settle them.

### A. The request body is read eagerly (biggest)

`__read_request_server` reads the whole body during the parse, before a
handler exists. Go hands the handler a stream. Everything below is that
one fact:

  - a slow body is cut off, but the handler NEVER RUNS, where Go runs it
    and lets its ReadAll see the truncation (2k). Costs observability,
    not safety.
  - request bodies are capped at 16 MiB and a request DECLARING more is
    refused with a 400 before it sends anything (2k). Go has no default
    limit. An upload over 16 MiB simply does not work.
  - the server sends `100 Continue` unconditionally, so a handler that
    would reject cannot do so before the client uploads (2k,
    http_expect100_server_smoke's second row). **Re-measured
    2026-09-06 and still exactly true:** `write_interim_100` fires from
    `__read_request_server` for any HTTP/1.1-or-later request with a
    body, between header parse and the eager body read, where Go defers
    it to the first `Read` through `expectContinueReader`
    (server.go:1022). The handler has not run when goish sends it.
  - a client request body is always Content-Length framed, never
    chunked, so a goish client cannot upload something it is still
    producing (client_wire_ref_smoke's KNOWN GAP).

Deciding to stream request bodies closes all four. Deciding NOT to is
also fine — but then the 16 MiB number wants choosing deliberately
rather than inheriting.

### B. The transport keeps two implementations

`readLoop`/`writeLoop` are a faithful port that nothing starts —
`__spawn_loops`'s only caller is an example — while `RoundTrip` reads
inline (2h). Wiring the loops up is the Go-faithful answer and a large
change; deleting them is honest if the inline path is the maintained
one; keeping both guarantees drift. `removeIdleConn` being uncalled is
a symptom, not a separate item.

**A second symptom, measured 2026-09-06:** `Transport.idleConnWait` is
written by `queueForIdleConn` and read nowhere. In Go the read is in
`tryPutIdleConn`, and the call reaching it — `tryPutIdleConn(rc.treq)`
at transport.go:2336 — is INSIDE `persistConn.readLoop`. The waiter
queue is dead for exactly the reason `removeIdleConn` is uncalled: the
loop that would drive it does not run.

That gives this decision a concrete cost rather than a stylistic one.
While the loops stay unwired, a connection freed while another request
is waiting is parked in the idle pool instead of handed to that
request, and `getConn` dials — so goish opens a connection wherever Go
reuses one. Deleting the loops means accepting that permanently and
deleting `idleConnWait` with them; wiring them up recovers the reuse.

**The full inventory, so the decision can be sized.** Five members of
the ported transport machinery are unwired, all by the same choice of
an inline path over Go's looped one:

| ported | why it is dead |
|---|---|
| `readLoop` / `writeLoop` | `__spawn_loops`'s only caller is an example |
| `removeIdleConn` | called from the loops in Go |
| `idleConnWait` | written by queueForIdleConn, read only by Go's tryPutIdleConn, which readLoop calls |
| `startDialConnForLocked` | Go's queueForDial spawns through it; goish's calls `dialConnFor` inline, and its own comment says "the goroutine form stays available" |
| `cleanFrontCanceled` | Go's caller is the dialsInProgress bookkeeping the inline dial does not carry |
| `persistConn.cancelRequest` | Go calls it from readLoop (transport.go:2410) AND roundTrip (:2883); goish's cancellation expires the conn's netpoll deadline instead |

Every one is a faithful port with a verified anchor, and every one is
unreachable. That is the drift this decision exists to stop: the cost
is not the dead code, it is that a reader cannot tell which path is
the maintained one, and a change to the live path leaves the ported
one silently stale.

`cancelRequest` is the one with two causes, and it is the more
interesting entry. Its readLoop call site does not exist because the
loop does not run; its roundTrip call site was replaced deliberately,
because goish cancels by expiring the conn's netpoll deadline rather
than by cancelling the request — a divergence documented at length in
client.rs, and the reason the context CAUSE has to be mapped back at
the error choke point. Deciding B does not settle that half.

### C. The conn is not shareable

`GotConnInfo.Conn` is `Arc<dyn Conn>` and the client path has no such
value — the conn is a `TCPConn` owned inside a `ConnSrc` that owns its
fd. That blocks the last of httptrace's six hooks, and five of them are
straightforward once it is settled (2j). Either the field takes a
non-owning handle — a deliberate divergence from Go — or the transport
moves to a shared conn.

### D. Two public API shapes predate what they now have to express

  - `Value::Number(f64)` drops the number literal, which is why "1.0"
    decodes into an int where Go refuses and why the max int64 needs a
    clamp (2l).
  - `Hijacker` returns a concrete `(TCPConn, error)` where Go returns
    an interface, so an HTTPS handler cannot hijack — no wss:// upgrade
    from goish (https_iface_ref_smoke).

Both are version-boundary changes rather than bug fixes.

### E. A Handler is handed a borrowed ResponseWriter

`Handler::ServeHTTP` receives `&(dyn ResponseWriter + …)`, and the
server builds that writer as a stack local. Anything needing to keep
the writer past the call cannot have it, and one thing does:
`ReverseProxy.copyResponse` — the method that gives `FlushInterval`
its meaning — takes an `Arc<dyn ResponseWriter>`, because
`maxLatencyWriter` arms its flush through `time::AfterFunc`, whose
closure must be `'static`.

So copyResponse is not merely uncalled, it is UNCALLABLE from the one
place Go calls it, and http_maxlatency_smoke passes only because it
constructs an Arc-wrapped writer of its own. That is why 2m's
ServeHTTP flushes after every write instead.

Three ways out, none local: change `Handler::ServeHTTP`'s signature
tree-wide; have the serve loop allocate its `response` into an `Arc`
and hand out a clone, in both server.rs and server_tls.rs; or
restructure `maxLatencyWriter` so the timer cannot outlive the call.

Closely related to C — both are "the thing the caller needs to keep is
owned by someone who will not share it" — and probably wants the same
answer.

### F. NewSingleHostReverseProxy's return type

Go's returns a `*ReverseProxy`, so a caller can then set
`ModifyResponse`, `ErrorHandler` or `Transport` on it. goish's returns
an opaque `Arc<dyn Handler>` wrapping the hookless slim proxy. Since
2m, `ReverseProxy` is a Handler and could be returned instead, which
would retire `reverseProxyHandler` entirely — but it changes an
exported signature every existing caller uses. Smallest of the six,
and the only one that is purely an API choice.

### Not blocked on anything

2c and 2d are their own work. (2i, response header order, is fixed —
see below.) 2f is no longer a worklist: every FIPS CAST is inert
because `Enabled_` is a `const false`, so the twelve unported files are
a structural-fidelity decision, not twelve fixes.
### §2v — runtime/pprof protobuf profiles (issue #9): what is missing

The largest remaining issue, and the inventory decides how it is staged.
What already exists:

  compress/gzip        ported (gzip.rs, gunzip.rs) — the outer envelope
  runtime/pprof         282 lines, the Profile/Lookup surface
  net/http/pprof        exists
  MemStats              declares Mallocs / TotalAlloc / HeapAlloc

**CORRECTION to the first version of this note.** It claimed "nothing
returns a PC list for the current G" and listed a stack walker as the
load-bearing gap. Both wrong, and checking before writing code would
have caught it — `runtime::Callers` has existed all along, Go-shaped,
over `collect_frames` → `segv::walk_frames`, with the skip semantics
right. I wrote ~100 lines of duplicate before finding it. What was
missing was not the capability but the EVIDENCE: it had never been
diffed against Go. It is now, by `runtime_callers_ref_smoke` against
`tools/gen_callers_ref.go` — seven rows including every skip value,
which is the part an off-by-one breaks while the frame count still
looks right.

So the stack side is DONE. What remains:

  SIGPROF + setitimer   DONE as machinery, NOT wired to the public API.
                        `syscall` gains SIGPROF, ITIMER_*, Itimerval and
                        Setitimer; `runtime/pprof/sample.rs` arms
                        ITIMER_PROF and its SIGPROF handler walks the
                        INTERRUPTED stack out of the ucontext, splicing
                        the interrupted PC in as frame 0 (the walk
                        returns RETURN addresses, so without it the
                        innermost function is missing from every sample
                        and its time lands on the caller).
                        pprof_sampler_smoke verifies real stacks at
                        100 Hz.

                        `StartCPUProfile` STILL returns its unsupported
                        error, on purpose. Joining the sampler to the
                        encoder needs an API decision: Go keeps `w` in a
                        package global from Start to Stop, and
                        `&mut dyn Writer` cannot be stored past the
                        call. Either the parameter becomes
                        `Box<dyn Writer + Send>` (diverges from Go's
                        `io.Writer`) or a raw pointer carries Go's own
                        "must outlive the profile" contract as an
                        explicit unsafe. Issue #9 is explicit that a
                        partial implementation must not emit misleading
                        files, so the error stands until that is chosen.

  (was) SIGPROF          no ITIMER_PROF, no SIGPROF anywhere in syscall.
                        A CPU profile is a sampling timer plus a handler
                        that captures the interrupted stack; goish has
                        the signal plumbing (os/signal, the SIGURG
                        preempt path) and now a verified walker, but not
                        this timer. NOTE: `Callers` walks the CURRENT
                        stack from a normal call; a sampler needs the
                        INTERRUPTED stack out of the signal's ucontext,
                        which is a different entry point —
                        `segv::walk_frames` already takes an explicit
                        RBP, so the piece is there.
  protobuf encoding     DONE. `runtime/pprof/proto.rs` encodes
                        profile.proto and is BYTE-IDENTICAL to Go's
                        `internal/profile` encoder for the same profile
                        (182 bytes), pinned by pprof_proto_ref_smoke
                        against tools/gen_pprof_proto_ref.go. gzip
                        envelope included. `go tool pprof -top` reads
                        both the raw and gzipped forms and reports the
                        encoded numbers.

                        The trap worth knowing: the first version let
                        the CALLER intern strings. Output was the same
                        182 bytes, pprof printed the right numbers, and
                        every string index was permuted — because Go's
                        `preEncode` builds the table in its own
                        traversal order ("" , sample_type type/unit,
                        mappings, function name/system/filename,
                        drop/keep frames, period_type). pprof resolves
                        indexes, so the tool CANNOT see the difference.
                        Only a byte comparison can.
  allocator accounting  CORRECTION: the counters DO work. A probe shows
                        Mallocs, TotalAlloc, HeapAlloc and Sys all
                        moving correctly across 200 x 4 KiB allocations.
                        The earlier claim here was written from a grep
                        and was wrong — the third such claim in this
                        section, after the stack walker and `Callers`.
                        A heap PROFILE still needs what MemStats does
                        not have: per-allocation-site STACKS, i.e. Go's
                        mprof hash of stack -> (allocs, frees, bytes).
                        Counters are not a profile.

  StartCPUProfile       DONE. `StartCPUProfile` starts a real profile
                        and `StopCPUProfile` writes a gzipped
                        profile.proto to the writer. The obstacle
                        recorded here was "an API decision" about the
                        writer's lifetime; it was not one. goish has a
                        settled convention for a writer stored past the
                        call — take it by value, box it inside — used by
                        `flag.SetOutput`, `log.SetOutput`,
                        `jsontext.Encoder` and `os/exec`. Treating a
                        settled convention as an open question is the
                        same failure as the absence claims above, one
                        step removed.
                        DEVIATION: Go streams to `w` from a
                        `profileWriter` goroutine; goish buffers in the
                        sampler's 8192-entry ring and encodes at Stop.
                        Past ~82s at 100 Hz the ring wraps and the
                        OLDEST samples are lost. `__taken` reports the
                        true count so a caller can see it happened.
                        `net/http/pprof.Profile` is wired through and
                        collects into a shared byte sink, since its
                        ResponseWriter is borrowed.
                        Pinned by `pprof_cpu_ref_smoke`: 15 rows from
                        `internal/profile` parsing Go's own output,
                        checked by a hand-rolled protobuf reader so the
                        decode does not share code with the encode.

  heap and allocs       DONE. `Lookup("heap")` and `Lookup("allocs")`
                        return registered builtins and
                        `WriteTo(w, 0)` emits a gzipped profile.proto
                        that `go tool pprof -top` accepts — validated
                        out of band, reporting `Type: inuse_space` and
                        `Type: alloc_space` respectively and attributing
                        1212 kB of 300 x 4096 to the workload function
                        by name.
                        Go's output settled the design before any code:
                        both profiles carry the SAME four value types
                        and differ ONLY in default_sample_type ("" vs
                        "alloc_space"), so "allocs needs no free
                        tracking" was wrong and inuse is why
                        `runtime/mprof.rs` exists. Also measured: a heap
                        profile sets time_nanos and leaves
                        duration_nanos at zero (it is a snapshot), and
                        `scaleHeapSample` keeps reported bytes-per-object
                        near 4096 even at rate 4096.
                        Allocator frames are stripped from the top of a
                        stack BY NAME, not by a skip count — the hook is
                        `#[inline]`, so the frame depth depends on the
                        optimizer. That only became possible once v0
                        symbols demangled.
                        MEASURED COST of the sampler's hook on the
                        allocator, release, 20M 64-byte alloc/free
                        pairs, six runs each
                        (examples/alloc_hook_bench):
                          no hook at all     76-80 ns
                          hook, all inline   87-89 ns  (+~10 ns, 13%)
                          hook, cold split   81-85 ns  (+~6 ns, 8%)
                        Pushing the recording out of line behind
                        `#[cold]` bought back four of the ten; the rest
                        is the four loads and one store the per-M
                        countdown needs on every allocation. `rate = 0`
                        measures the same as the 512 KiB default, so
                        what the 8% pays for is the countdown, not the
                        recording. It is a CEILING — the benchmark does
                        nothing between allocations. A debug build
                        cannot see any of it: ~1400 ns per pair there,
                        and rate 0 measured SLOWER than rate 512 KiB.
                        Also note e2e elapsed is useless for this: it
                        ranged 1009s-1622s across six consecutive
                        commits, so runner variance swamps a 8%
                        allocator change.
                        Still open: the debug>=1 legacy TEXT format for
                        these two, which returns an error rather than
                        writing an empty file; and the four builtins
                        with no substrate (block, mutex, goroutine,
                        threadcreate), which Lookup returns nil for
                        rather than registering empty.

  a v0 demangler        DONE (`src/runtime/symbolize/demangle_v0.rs`).
                        goish demangled only the LEGACY `_ZN…E` form
                        while this build emits v0, so NOTHING was
                        demangled: every panic, SIGSEGV backtrace,
                        `runtime.Callers` result and pprof text profile
                        printed `_RNvNtNtCs…`. 19231 v0 symbols in one
                        example binary, none readable.
                        Verified by compiling the SHIPPING source as a
                        std program and diffing it against
                        rustc-demangle over every v0 symbol in seven
                        example binaries: 24127 exact, 0 bails, 0
                        disagreements. Four bugs the corpus found that
                        a hand-written table would not have: the
                        discard pass failing on a zero-length buffer
                        (14363 symbols), the disambiguator needing
                        `+ 1` (1142 wrong closure indices), unnamed
                        lifetime binders making two different `for<>`
                        types print identically, and v0's leading-zero
                        length rule (the last 227, all nested
                        closures).
                        This also unblocks stripping allocator frames
                        from a heap profile BY NAME instead of by a
                        skip count that inlining can shift.

  signal relay ordering goish's `dispatch_pending` (runtime/signal.rs)
                        reads one per-signal counter at a time while
                        scanning signal numbers ascending, so a signal
                        arriving mid-scan is served a whole pass late.
                        Go's `sigqueue` instead swaps the entire pending
                        MASK out in one atomic word operation and serves
                        that snapshot, which is why Go's order is
                        ascending-by-number 191 times in 200.
                        NOT a correctness bug: measured over 200 trials
                        (tools/gen_signal_order_ref.go), Go produces
                        four distinct orders for three signals raised
                        low-to-high and six for high-to-low — including
                        the exact `USR2|WINCH|USR1` that goish's e2e
                        failed on, 20 times in 200. POSIX does not
                        specify the order either. So
                        `signal_notify_ref_smoke` now asserts the SET,
                        and this entry records that goish's order is
                        more variable than Go's while staying inside
                        what Go permits.
                        Matching the snapshot would also mean matching
                        Go's COALESCING — `sigsend` drops a signal whose
                        bit is already pending, measured 97 of 100
                        trials collapsing five SIGUSR1 into one — which
                        is a semantic change to every delivery, so it is
                        a decision and not a tidy-up.

  a goroutine registry  Needed by `GoroutineProfile`, which is a stub.
                        Its own comment blamed a missing stack walker;
                        that is no longer true. A parked G's `gobuf`
                        holds the rsp/rbp/pc a walk needs, exactly as
                        the SIGPROF handler reads them from a ucontext.
                        What is absent is a LIST: `live_g_count` is a
                        counter. A registry is not just a Vec — a G in
                        it must not be freed while a profiler walks it,
                        which is why Go pairs `allgs` with
                        stop-the-world. New runtime state with a
                        use-after-free failure mode.

Remaining: the writer-lifetime decision above, then heap accounting
(MemStats declares Mallocs/TotalAlloc that heap.rs does not maintain; a
heap profile needs per-size-class counts carrying stacks). Every other
piece — walker, sampler, encoder, gzip — exists and is verified.

The issue is explicit that a downstream shim "would only create files
with misleading or invalid contents", so a partial implementation must
keep `StartCPUProfile` returning its current honest error rather than
emitting an empty-but-valid profile.

### §2w — sync.Cond lost notifications (FIXED)

`sync_cond_smoke` timed out on CI (2026-09-12, 8016235) after passing
its first three cases, and REPRODUCES locally: 1 hang in 40 runs, rc=124.
Not caused by the commit it appeared on — that added only a pure
encoder module — and it does not appear in the four e2e runs before it,
so it is rare rather than new.

Case 4 is a bounded ping-pong: two goroutines alternate `phase` under a
Mutex, each `cond.Wait()`ing while the parity is wrong and
`cond.Broadcast()`ing after unlocking. That is legal Go, and the
logic cannot deadlock on its own terms — A waits only on odd, B only on
even, so they cannot both be waiting.

DIAGNOSED, with one decisive state sample. A watchdog build that dumps
the Cond's internals when `phase` stops advancing caught it:

    STALL phase=2 waiters=2 credit=0 qlen=2

Both goroutines are parked on the semaphore, no credit, at an EVEN
phase — where only B's predicate can hold. A is waiting at a phase
where it should be running, so a notification was lost.

ROOT CAUSE: goish's Cond counts waiters in a separate atomic and leans
on the semaphore's credit, where Go uses `notifyList` TICKETS
(runtime/sema.go:571-588). The difference is what a notification leaves
behind:

  Go       `notifyListAdd` returns t = wait++ BEFORE the unlock;
           `notifyAll` sets notify = wait. `notifyListWait(l, t)`
           returns IMMEDIATELY if less(t, notify). The notification is
           a WATERMARK, so a waiter holding a ticket that has not
           parked yet still sees it.
  goish    `Broadcast` does `waiters.swap(0)` and, when that reads 0,
           DOES NOTHING AT ALL. A notification that arrives while a
           waiter is between `waiters.fetch_add` and `sema.acquire`
           leaves no record for it to find. The sema's
           credit-store-on-no-waiter papers over the single-waiter case,
           which is why Wait's comment claims the window is closed and
           why this survives ~50 runs out of 51.

FIX DIRECTION: port Go's notifyList discipline — a ticket taken before
the unlock and a notify watermark — rather than patching the counter.
Patching cannot close it: any scheme where a notification is dropped
when the counter reads zero has the same hole.

FIXED by porting `notifyList` (`sync/notifylist.rs`), with evidence in
three directions rather than "it stopped happening":

    before (count + credit)          1/40 and 1/51 hangs
    after (notifyList)               0 / 150
    after, less(t, notify) disabled  1/25 hangs

The ablation is the part that matters. Disabling that one early return
brings the hang straight back, with exactly the predicted state —
`issued=5 notified=4 qlen=2`, one ticket outstanding and both goroutines
parked. So the ticket check is what fixes it, not a timing accident.

Two header comments were corrected, both of which had actively misled
me while reading the code:

  cond.rs  listed "notifyList replaced by an AtomicI64 waiter count +
           the internal Sema" under "Slim deviations". It was not a slim
           deviation, it was the bug.
  sema.rs  claimed its credit rule "is what makes this race-free against
           the classic lost-wakeup pattern". True for PAIRED
           acquire/release and nothing more — reading it as a general
           shield is what let Cond be built on it. It now says when this
           type is the wrong primitive.

The diagnostic accessors are kept (`Cond::__debug_state`,
`Sema::__debug_state`, `NotifyList::__debug_state`): they are what
turned an unfalsifiable theory into one decisive sample.

REGRESSION TEST. `sync_cond_smoke`'s ping-pong is how the bug was found
but it is a poor guard — it needs the race to land, about once in fifty
runs. `sync_notifylist_smoke` drives `NotifyList` directly and forces
the window open by hand: `Add`, then `NotifyAll`, then `Wait`, which
must return without parking. Measured both ways — 5/5 pass with the
watermark check, 3/3 TIMEOUT without it. Deterministic rather than
probabilistic, and a timeout rather than a diff, which is the honest
shape for "a wakeup was lost".

### §2v1 — slice backing-array sharing (issue #26): measured, and sized

Go's slice is a header over a backing array, so a copy aliases and an
append that FITS writes into the shared array. goish's `slice<T>` owns a
`Vec<T>`; `Clone` deep-copies and `slice()` / `slice3()` each document
returning "an independent copy, not a view".

`tools/gen_slice_alias_ref.go` generates the contract. The issue's own
oracle, reproduced:

    two_appends_base    [1 2] len 2 cap 3
    two_appends_first   [1 2 9]        both appends wrote index 2,
    two_appends_second  [1 2 9]        and the SECOND won

    header_copy_aliases           99
    sub_len_cap                   len 2 cap 7    s[1:3] of len5/cap8
    sub_write_visible             77
    sub_append_overwrites_parent  s[3] = 88
    sub3_len_cap                  len 2 cap 2    s[1:3:3] caps it
    sub3_append_detaches          s[3] still 3, sub[2] = 88
    beyond_cap_detaches           base[0] 1, grown[0] 42
    independent_lengths           len 2/4, cap 4/4   cap is the ARRAY's
    copy_through_subslice         s = [8 9 3 4]
    overlapping_copy_forward      [1 1 2 3 4]
    overlapping_copy_backward     [2 3 4 5 5]
    tail_len_cap                  s[2:2] of len2/cap4 -> len 0 cap 2
    tail_append_into_parent_array cap(s) 4, len(s) 2, tail[0] 7
    append_nil_leaves_nil_nil     true, 0, [1]

TWO ROWS THE ISSUE DOES NOT LIST, both of which an implementation can
get wrong while satisfying every row it does list:

  overlapping copy   `copy` is MEMMOVE, not a forward element loop.
                     `copy(s[1:], s[0:4])` is `[1 1 2 3 4]`; a naive
                     forward loop gives `[1 1 1 1 1]`. Unreachable today
                     because subslices are detached, so it becomes
                     reachable exactly when the sharing lands.
  cap after s[lo:hi] `cap` runs to the END of the backing array, so
                     `s[1:3]` of a len5/cap8 is cap 7. goish gives cap 2.

WHERE goish STANDS, measured:

    row                        Go          goish        
    two_appends_first          [1 2 9]     [1 2 7]      GAP
    two_appends_second         [1 2 9]     [1 2 9]      ok (by luck)
    sub_len_cap                2 / 7       2 / 2        GAP
    copy through a subslice    propagates  invisible    GAP
    overlapping copy           memmove     unreachable  blocked

`two_appends_second` agreeing is worth naming as luck: the last writer
wins in Go, and in goish it is simply the only writer of its own copy.

A JUDGMENT, recorded so it is not revisited as an easy win: do NOT fix
`cap` on its own. With detached copies, a larger cap makes the
divergence LESS visible, not more — an append that fits would stop
reallocating and still fail to propagate, so the symptom changes from
"obviously a different array" to "silently dropped write". Capacity has
to land with the sharing.

SIZING, and this is the larger of the two value-semantics changes:

    __from_vec   2310 sites in src, 1545 in examples
    __into_vec    400 sites in src,  218 in examples
    as_ref        601 sites in src,  499 in examples

`__from_vec` mostly survives — a shared representation can still build a
slice from an owned Vec. The two that do not are the problem. `__into_vec`
CONSUMES the slice for its Vec, which a shared backing cannot hand over;
and `as_ref() -> &[T]` cannot be returned from behind a lock, which is
the same wall #7 hits with `Index` and `GetRef` but 1100 call sites wide
instead of 24.

So the mutation strategy the issue asks for is the whole problem, not a
detail of it. `Arc<UnsafeCell<[T]>>` with blanket Send/Sync is what #7
rules out for maps and the same objection applies here. Unlike the map
case, there is no "return owned copies instead" escape: `as_ref` is how
every `&[u8]` in the crypto and encoding paths is obtained.

### §2u — map value semantics (issue #7): measured, and sized

Go's map is a header referencing backing state, so a copy aliases.
goish's `map<K, V>` owns its table and `Clone` copies every entry, so
two handles diverge silently. `tools/gen_map_alias_ref.go` generates
the contract:

    assign_alias        m["b"]=2, len 2 both       a copy sees later writes
    return_alias        3, len 3                   returning aliases
    arg_alias           9, len 4                   passing aliases
    clone_no_alias      false, 4 vs 5              maps.Clone is the ONE that does not
    delete_visible      false                      delete through one header shows in the other
    clear_visible       0, 0                       so does clear
    nil_is_nil          true
    empty_is_nil        false
    nil_read            0                          reading a nil map is legal
    nil_read_ok         0, false
    nil_len             0
    nil_range_iters     0                          ranging a nil map is legal
    nil_delete_ok       true                       deleting FROM a nil map is legal
    nil_write_panic     true                       only writing panics
    value_is_copy       1                          a value read out is a copy
    inner_map_aliases   2, len 2                   but an inner MAP value aliases

The last two together are the subtle pair: sharing the outer table must
not deep-copy values, and a value that is itself a map must still
alias, because it is a header too.

Four rows added 2026-09-12, after re-reading the list against what an
implementer would actually trip over:

    nil_clear_ok            true     clear on nil is legal too, like delete
    nil_write_panic_msg     "assignment to entry in nil map"
    mapsclone_of_nil_is_nil true     Clone of nil is NIL, not empty
    nil_through_call_still_nil true

The second replaces a `recover() != nil` bool. Any panic satisfied that,
and goish has to emit Go's exact text, so the text is what the row pins
now. The third is the one most likely to be got wrong: a deep copy that
starts from a fresh table returns an allocated-empty map where Go
returns nil, and nothing else in the file would have caught it.

WHERE goish ACTUALLY STANDS, measured rather than inferred from the
issue (a throwaway probe against current dev):

    row                      Go       goish     
    clone_aliases            true     false     GAP
    return_aliases           true     false     GAP
    mapsclone_independent    true     true      ok
    empty_eq_nil             false    true      GAP
    nil_eq_nil               true     true      ok
    len_empty / len_nil      0 / 0    0 / 0     ok
    nil_read                 0,false  0,false   ok
    nil_write panics         yes      NO        GAP

So four gaps, exactly the four the issue names, and the three rows that
already agree are worth knowing too: whatever the new representation
does, it must not regress them.

SCOPE, since the issue names the blocker itself. The borrowed APIs
cannot survive a lock-backed `Arc` unchanged, because a reference
cannot outlive a guard:

    __iter    54 sites in src, 7 in examples
    Index     17 sites in src, 7 in examples
    GetRef     5 sites in src, 2 in examples

225 `map<…>` declarations in src. So the representation change is one
commit and the API migration is the bulk of the work; `__iter` is the
one to design first, since a snapshot-returning form is cheap for small
maps and wrong for large hot ones.

Explicitly NOT to be done with `Arc<UnsafeCell<_>>` plus blanket
Send/Sync, which the issue also calls out: copied handles crossing
goroutines would let safe goish code cause Rust UB, and goish's own
`schedule: holding locks` work this cycle is the reminder that "Go
permits the race" is not the same as "Rust may have UB".

WHAT THE BORROWED APIs SHOULD BECOME, settled by precedent rather than
left as a design question — the mistake §2u nearly repeated after #9
taught it (see the note on StartCPUProfile):

  `Index`    Go's `m[k]` yields a COPY of the value, so an owned
             accessor IS Go's contract. `Get(k) -> (V, bool)` already
             exists and already returns owned, so the convention is
             established; Rust's `Index` trait cannot return an owned
             value anyway. The 24 sites become `.Get(k).0`, and the
             `Index` impls go.

DONE. Four notes, because the plan above was wrong about the size and
silent about the cost.

THE COUNT WAS 81, NOT 24 — 9 in src and 72 in examples. It was taken by
disabling the four impls with `#[cfg(any())]` and reading the E0608s
back, which is the only honest census: `m[k]` cannot be grepped apart
from slice indexing, and `IndexMut` writes look nothing like reads.

AND `cargo check --examples` UNDER-REPORTS: it stops at the first
failing target, so the first census came back "2 sites in examples"
and the next build found a third, then a fourth. `--keep-going` gives
the whole set in one pass. Worth remembering for any tree-wide API
removal — the first number cargo prints is a lower bound, not a count.

WHAT WENT WITH THE IMPLS IS `m[k] = v` AND `m[k] += n`. There is no
replacement spelling: those become `m.Set(k, v)` and
`m.Set(k, m.Get(k).0 + n)`. That is a readability loss against Go on
about forty call sites and it is not recoverable — Rust's `IndexMut`
returns `&mut V`, and a lock-backed header cannot produce one. `Set`
is now documented as the only write form.

The mechanical rewrite has one silent failure mode, and all three
instances of it made it past the compiler: a line whose assignment is
followed by a trailing comment does not match an "ends with `;`"
pattern, so it rewrites as a READ — and `m.Get(k).0 = v` compiles,
because it assigns to a field of a temporary tuple. It is a no-op.
`gomap_smoke`, `map_smoke` and `gomap_range_smoke` each caught their
own; the grep that finds the rest is `\.Get(.*)\.0 *=`.

A REAL DIVERGENCE FELL OUT, in `textproto.MIMEHeader`. Go's `Values` is
`return h[CanonicalMIMEHeaderKey(key)]`, so a miss yields the zero
value and the zero slice is NIL. goish had `if !h.Has(k) { return
slice::__from_vec(Vec::new()) }` — an allocated-empty slice, which
compared unequal to nil once slices grew a nil flag. Measured against
Go 1.25.5: `MIMEHeader{}.Values("X") == nil` is true, and so is
`MIMEHeader(nil).Values("X") == nil`. `textproto_ref_smoke` asserted
only `len() != 0`, which passes for both, so nothing was watching; it
now asserts nil, asserts that a PRESENT key is not nil, and covers the
nil header.

`Add`, `Get` and the two append sites in `mail` and `textproto/reader`
lost a `Has` probe each on the way — Go writes `h[key] =
append(h[key], value)` with ONE lookup, and goish was hashing the key
twice to avoid a missing-key panic that `Get` does not have.

STILL DIVERGENT, and out of scope here: Go's `Values` returns the LIVE
slice. Measured — mutating the returned slice changes what `Get` reads
afterwards. goish clones, so it does not. That is #26, not #7.
  `__iter`   Go's `range` yields COPIES of key and value, so an
             owned-yielding iterator is the faithful shape, not a
             concession. It currently yields `(&K, &V)`.

STATUS: 61 sites down to 3. Everything that was a `for (k, v) in
m.__iter()` is now `__for_each` or, where Go's body returns or breaks,
`__try_for_each`. The three that remain are not the same problem as
each other:

  range.rs (2)   DONE. `range!(m)` now yields owned `(K, V)`, which is
                 Go's contract — its `range` copies both. 26 callers in
                 src, censused by disabling the impls; only 8 needed a
                 change, because a `.clone()` on an owned value still
                 compiles. That is the hazard: the compiler flags the
                 derefs (`*v`) and nothing flags a clone that is now
                 redundant, so the 26 had to be read rather than built.
                 The snapshot iterator holds no borrow, which also let
                 FOUR defensive whole-map `.clone()`s go — the ones
                 written only so the loop body could mutate the map it
                 was walking (`verify.rs` ×3, `cert_pool.rs`).
  json/mod.rs    NOT mechanical, and now MEASURED rather than assumed.
                 See below. `__iter` is `pub(crate)` so this stays the
                 only borrowed walk while the design is decided: the
                 public API no longer has one at all.

THE OWNED-STACK FIX WAS TRIED, AND MEASUREMENT REJECTED IT. Writing
it down because the reasoning below reads like it should work.

`Task::Val(Value, usize)` plus a consuming map drain gives exactly ONE
clone — the root — and every deeper level then MOVES rather than
copies, so it is O(n) and not the O(n·d) a per-level snapshot costs.
That much is true. What it misses is that `Value`'s derived `Clone`
RECURSES, one frame per level, so the single clone reimposes the very
ceiling the work stack exists to remove:

    examples/json_encode_depth_smoke, debug build, 8 MiB stack
      baseline (borrowed stack)   encodes depth 100000
      owned stack (root clone)    faults between 12000 and 12500

An 8x loss, and the same regression `Unmarshal` already removed once —
see the `maxNestingDepth` note, "CLONE — avoided … one frame per level
over the whole tree". It would trade a representation problem for a
denial-of-service one. Reverted; the consuming drain went with it,
since keeping an API with no caller is how dead code gets mistaken for
progress.

AND MEASURING IT FOUND SOMETHING ELSE. Three things here recurse, and
the encoder is no longer the tightest:

    Value::clone    faults 12000..12500    derived, one frame/level
    Value::drop     faults 19000..20000    derived, one frame/level
    encode_value    survives 100000        explicit work stack

So making the encoder iterative moved the bound onto `Value`'s own
derived `Clone` and `Drop`, and nothing had noticed because nothing
measured it. Both are far above the v1 parser's cap of 2000, which is
what keeps a ROUND TRIP safe — only a hand-built `Value` reaches
either. It is worth knowing that `let v = deep_value; drop(v);` faults
around 19000 all by itself, with no encoder involved.

`json_encode_depth_smoke` now pins the encoder at 2000 (every depth a
round trip can reach) and 16000 (clear of the clone ceiling, below the
drop one, so the row cannot report the wrong recursion). Reintroducing
the root clone turns it red.

RESOLVED, AND NOT THE WAY THIS SECTION EXPECTED. `Value::Object` gave
up `map<string, Value>` for an `Object` that owns its pairs, so the
encoder's borrowed stack became sound WITHOUT the encoder changing at
all. `__iter` is now fully private: zero borrowed map APIs remain
anywhere, and #7's API migration is done.

The argument that settled it is CORRECTNESS, not the encoder, and it is
the one this section missed. Once a map copy shares backing state —
which is the entire point of #7 — a `map` field inside a
`#[derive(Clone)]` type stops deep-copying. `Value` is a value type and
`Unmarshal` relies on its clone being independent, so two `Value`s
cloned from one another would silently have SHARED objects. Keeping
`gomap` inside `Value` was going to be a bug the moment the header
landed, encoder or no encoder. Go has no equivalent hazard: its DOM is
`map[string]any` and its users already expect reference semantics.

Everything else fell out cheaply. `Object` owns its pairs, so five
`__for_each` / `__try_for_each` closures went back to plain `for` loops
with real `return`s. And the struct decoder generated by
`#[goish::reflect]` stopped deep-cloning: it looked each field up with
`map::Get`, which returns the value BY CLONE, so decoding a struct
deep-copied every field's subtree just to read it. It borrows now.

The cost is that object lookup is a scan rather than a hash — the right
trade here, since JSON objects are small and the scan replaces a deep
clone, but worth stating rather than discovering.

Duplicate keys measured against Go 1.25.5 to be sure the scan-and-
replace matches: `{"b":1,"a":2,"a":3,"b":9}` decoded into `any` and
re-marshalled gives `{"a":3,"b":9}` in Go, and the same here.

FOUND WHILE MEASURING THAT, and unrelated to #7: `json.Indent` and
`json.Compact` are NOT faithful, and the doc comment claimed they were
("Faithful for valid input"). Go's are TEXTUAL — they walk the bytes
inserting whitespace, so key order survives and duplicate keys survive.
goish parses to a `Value` and re-encodes, so it sorts and dedups:

    Go's json.Indent      b, a, a, b   order kept, duplicates kept
    goish, via the DOM    a, b         sorted, last value wins

The DOM answer is a correct re-encoding of the document's MEANING, and
is exactly what Go's `Unmarshal`-then-`MarshalIndent` gives — but
`Indent` does not promise meaning, it promises the same bytes with
whitespace added. Fixing it needs a byte-level indenter that never
builds a `Value`, which is also the only shape that can round-trip a
duplicate key. Recorded at the call site; not fixed here.

WHAT REMAINS ON #7 is now only the representation swap itself: `map`
becomes a shared header behind a lock, `Clone` copies the handle, and
the aliasing reproducer in the issue passes. No call site has to move
for it.

THE ORIGINAL BLOCKER, kept because the measurement is the reusable part. `encode_indent`
is an explicit work stack of `Task<'a>` holding `&'a Value` and
`&'a string` borrowed out of the object map, and the stack outlives the
iteration that filled it. A guard-scoped closure cannot serve that, and
a shared header cannot hand the references out at all.

The fix has to remove the RECURSION, not the borrow. Two candidates,
both changing a public payload type, so both get their own commit and
their own call-site sweep (19 `Value::Object` sites, 9 of them in
examples):

  `Value::Object(map<string, Arc<Value>>)` — cloning becomes O(width)
  and FLAT, since cloning an `Arc` does not descend. `Value::Array`
  needs the same or a deep array chain still recurses on clone.

  Drop `gomap` from `Value::Object` altogether, for a
  `slice<(string, Value)>`. `Value` is a goish-only DOM — Go's
  encoding/json has no `Value` type, it uses `map[string]any` — so
  nothing here requires Go map semantics, and the encoder sorts the
  keys anyway, so the hash ordering buys nothing. This REMOVES the #7
  problem rather than working around it, and it is the smaller change
  of the two.

The second looks right, and the reason to say so rather than just do it
is that it also decides what a JSON object is in goish's public API.

OWNED RANGE MADE A #26 DIVERGENCE OBSERVABLE, which is worth having in
writing before someone hits it. Measured against Go 1.25.5:

    s := map[string][]int{"x": {1,2,3}}
    for _, v := range s { v[0] = 99 }
    -> x=[99 2 3]              the write LANDS
    for _, v := range s { v = append(v, 4) }
    -> x=[99 2 3] (len 3)      the append does not

Go's copy of a `[]T` value is a slice HEADER, so it shares the backing
array: writing through the loop variable reaches the map. goish's slice
clone is a DEEP copy until #26, so it does not. The append half already
agrees. `gomap_range_smoke` now asserts goish's CURRENT behaviour with
the divergence named in the failure message, so #26 turns the row red
and forces the revisit; leaving it unasserted would have kept it
silent.

THE OWNED FORM IS NOT RIGHT EVERYWHERE, and going owned by default
recreated exactly the regression this section predicted. Three
per-request HTTP paths read only — the trailer-prefix scan in
`responsewriter.rs`, the `Trailer` key validation in `transfer.rs`, and
`validateHeaders` in `transport.rs` — and `range!` made each of them
snapshot the header map and DEEP-COPY every value slice, two of them
without even looking at the value. They are `__try_for_each` now. The
rule that falls out: `range!` is for callers that keep the values;
anything on a per-request path that only reads takes the closure.

PERTURBING THOSE THREE FOUND A COVERAGE HOLE, which is the part worth
recording. Disabling all three checks left 239 of 241 examples green:
only the trailer-prefix scan was watched. So two control-flow rewrites
— a `return` inside a loop becoming a `ControlFlow::Break` — had
nothing to catch getting them wrong.

`validateHeaders` was covered for its VALUE branch and not its FIELD
NAME branch, so half the function was untested. And the `Trailer` key
check had no coverage at all; measuring it needed Go, and Go had two
surprises: the refusal is case-INSENSITIVE and quotes the CANONICAL
key back, and the check is unreachable unless the body is chunked,
because `newTransferWriter` nils Trailer outright otherwise ("Sanitize
Trailer", transfer.go:145). A first reference test showed every key
"accepted" for exactly that reason. Both are covered now, and both
rows turn red under the perturbation that found them.

TWO THINGS FOUND WHILE WALKING THE SITES:

`reflect`'s map impl carried the comment "Goish's map<K,V> is
BTreeMap-backed, so __iter() walks keys in sorted order … which means
json.Marshal output is deterministic for free." All three clauses were
false: the map is bucket-based with a randomized start bucket, the walk
is not sorted, and json.Marshal is deterministic because `encode_map`
sorts the keys itself. No live defect — `encode_map` is the only
consumer of that order, and Go's own `reflect.Value.MapKeys` promises
nothing either — but the comment invited the next caller to rely on an
order that was never there.

`http.Header.Clone`, `cloneMultipartForm`, `maps::Clone`, `maps::Copy`
and `sync.Map.Range` all had to grow a staging Vec: the visitor borrows
the source map, so the destination cannot be written from inside it
when the two are the same map or when the borrow checker cannot prove
they are not. That allocation is real and it is the price of the
borrowed form; it disappears again for the sites that move to owned
iteration.
  `GetRef`   No Go counterpart at all — Go has no way to take a
             reference into a map. It is a goish-only optimisation, so
             its 7 sites fold into `Get`.

DONE, and the `GetRef` fold was not the mechanical one predicted above.
Its five src sites went three ways, not one:

  2 (server.rs)  discarded the value and read only `ok`, so they are
                 `Has` — no owned read at all.
  3 (session.rs, mapfs.rs)  fold into `Get` as predicted, but session.rs
                 needed its ctor changed too: `CACHE` was built with
                 `new_no_zero()`, and `Get`'s miss path reads the zero
                 sentinel, so the fold alone turns a normal cache miss
                 into a panic. Its value type is `slice<cachedSession>`,
                 which has a `Default` — the no-zero ctor was never
                 needed. `tls_session_expiry_smoke` resets the cache
                 itself and had the same call, which is how it was
                 caught: the smoke, not the compiler.
  0              fold for a non-`Clone` V, and this is the one the plan
                 above missed.

THE NON-`Clone` V IS THE REAL LIMIT, and it is worth stating before the
header lands rather than discovering it underneath. For a value type
that is neither `Clone` nor `Default` — `map<string, Box<dyn Trait>>`,
goish's spelling of Go's interface-typed map — a shared header behind a
lock can hand the value out NEITHER by reference (it would outlive the
guard) NOR by value (nothing to clone). Go has no such problem: reading
`map[string]Hasher` copies a two-word interface value.

Measured, this is not yet load-bearing: `new_no_zero` /
`with_capacity_no_zero` have exactly ONE src construction site (the
session cache above, which did not need them), and the only genuinely
non-`Clone` map in the tree is in `gomap_no_zero_smoke`. So the header
is not blocked. The access path for that shape is the guard-scoped
closure — `__for_each` / `__try_for_each`, which take `&V` for the
duration of the call and need no bound at all — and the smoke now reads
its `Box<dyn Hasher>` values that way, so the sanctioned path has a
user. Should a future port need an interface-typed map with an owned
read, the answer is `Arc<dyn Trait>` (Go's interface value is a copyable
pair, and `Arc` is goish's copyable pointer), not a borrowed accessor.

So none of the three needs a new API to be invented; each has either a
Go contract that is already owned or no Go counterpart. That is roughly
90 call sites of mechanical change, and the representation underneath
can then be a lock without fighting any signature.

BUT `__iter` CANNOT BE OWNED-ONLY, and the reason is a coupling to #26.

Go's `range` copies the value, and for `map[string][]string` that is a
slice HEADER — O(1). goish's `slice<T>::clone` is a DEEP copy until #26
lands, so owned iteration copies the bytes. Measured exposure:

    map declarations in src        230
      slice-valued                  43   deep-copy per entry
      map-valued                     1
      scalar / string-valued        81   cheap (string is Arc<[u8]>)

43 of 230 is bad enough; WHICH 43 is worse. `http.Header` is
`map<string, slice<string>>` and it is iterated on the per-response
header-write path (server.rs:984) and the request path (server.rs:3674).
Owned iteration would deep-copy every header value slice on every
request — a regression on the hottest path in the library, in exchange
for semantics no caller can observe there.

MEASURED how far the closure form actually reaches, because a closure
cannot `break` its caller's loop:

    map-iteration sites in src        56
      visit-everything                44   closure-safe
      break / return / ? in the body  12   need an early exit

The 12 are real and not obscure: a labelled break in `server.rs`'s
header matching, an early return in `routing_index`, and the `maps`
package's All / Equal short circuits. Forcing them to snapshot would be
the deep copy the borrowed form exists to avoid, so there is a third
shape rather than two.

So `__iter` needs BOTH shapes:

    owned `(K, V)`        Go-shaped `range`, for callers that keep the
                          values. Faithful, and cheap once #26 makes a
                          slice clone a header copy.
    borrowed, closure     `__for_each(|&K, &V|)`, guard-scoped, for the
                          44 internal hot paths that only read.
    borrowed, early exit  `__try_for_each(|&K, &V| -> ControlFlow<B>)`
                          for the 12 that stop partway.

Issue #7 already says this — "use a guard/closure form only for
genuinely borrowed internal operations" — so this measurement confirms
its guidance rather than contradicting it, and says which call sites it
was talking about.

ORDERING CONSEQUENCE: #7's aliasing half does not have to wait for #26,
but the sites that keep the borrowed form should be revisited when #26
lands, because most of them exist only to avoid a deep copy that will no
longer be deep.

    THAT ORDERING IS WRONG, AND SO IS THE THREE-SHAPE DESIGN ABOVE.
    Measured after the API migration finished; see the next block.

─── THE GUARD-SCOPED CLOSURE DOES NOT SURVIVE THE HEADER ──────────────

The design above gives `__for_each` / `__try_for_each` as the borrowed
shapes that a shared header CAN serve, on the reasoning that a
reference confined to a closure never outlives the guard. That is true
of the reference and false of the guard: holding a lock across a
user callback deadlocks the moment the callback touches the same
backing store, and after #7 "the same backing store" is reachable
through a DIFFERENT HANDLE, which the borrow checker does not stop.

MEASURED, because the whole question is whether Go permits it. Go
1.25.5, same goroutine:

    m := map[string]int{"a":1,"b":2}
    for k := range m { m[k+"x"] = 1 }
    -> survived, visited 2, len now 4

    p := map[string]int{"a":1,"b":2}
    q := p                      // second header, same backing map
    for range p { q["z"] = 9 }
    -> survived, visited 3, len now 3

Both are LEGAL Go. The spec allows it explicitly — an entry created
during iteration "may be produced during the iteration or may be
skipped" — and Go's `hashWriting` fatal is about CONCURRENT access from
another goroutine, not this. So a representation that hangs here is
refusing something Go accepts, and hanging is the worst way to refuse.

Two call sites reach it today, found by scanning every callback body
for map operations (45 sites, 2 hits):

  `maps::Equal(&m1, &m2)` walks m1 and calls `key_matches(m2, …)`,
  which walks m2. Both are `&` of the same type, so `let b = a.clone();
  maps::Equal(&a, &b)` nests two walks on ONE store — and after #7 that
  is not a contrived call, it is the ordinary one.

  `copyValues(dst: &mut …, src: &…)` — the borrow checker stops dst and
  src being one BINDING; it does nothing about two handles.

  (`Header::sortedKeyValues` walks `self.inner` and reads `exclude`,
  but they are `map<string, slice<string>>` and `map<string, bool>` —
  different types, so they cannot be the same store. Safe by typing,
  not by design.)

SO `__for_each` MUST SNAPSHOT: lock, clone the pairs, unlock, then call
back with references into the snapshot. Same signature, no deadlock,
and the walk sees the pre-write state — which is one of the two
outcomes Go's spec permits. The alternatives are worse: a re-entrant
lock still lets a nested write mutate buckets under a live iterator,
and detecting re-entry to panic refuses what Go accepts.

WHICH REVERSES THE ORDERING. If every walk snapshots, and a snapshot of
`map<string, slice<string>>` deep-copies every value slice until #26,
then landing #7 first puts a deep copy on every header walk on every
request — the exact regression this section set out to avoid, arrived
at from the other direction. **#26 should land before #7's header.**

It also collapses the three shapes into one: `__for_each` and
`__into_iter` both become "snapshot, then walk", differing only in
whether the caller gets `&K, &V` or `K, V`. The closure forms keep
their value — they are still the shape that works for a non-`Clone` V,
and they still express early exit — but not for the reason given above,
and not as a way to avoid a copy.

None of the API migration is wasted: the borrowed walk had to leave the
public API either way, and `__iter` is private now. What changes is
that the header is no longer the next commit.

DECOMPOSITION. The four gaps do not all need the header:

  nil identity   `empty_eq_nil` and the missing write-panic need only an
                 explicit nil FLAG on the existing owning map. No API
                 migration: reads, len, range and delete stay legal on
                 nil, so no borrowed signature changes. `maps::Clone` of
                 nil returning nil falls out of the same flag.
  aliasing       `clone_aliases` and `return_aliases` need the shared
                 header, and therefore the `__iter` / `Index` / `GetRef`
                 migration above.

Doing nil identity first is not a way of avoiding the hard half — it is
independently correct, it unblocks a second consumer already waiting on
it, and the flag survives the later header change unchanged.

That second consumer is `net/http/clone.rs`, whose own header says
"Three of these five exist to preserve Go's nil-map-versus-empty-map
distinction, and goish's `map` does not have one … fixing it belongs
there." `cloneURLValues` cannot return nil for nil and
`cloneOrMakeHeader`'s make-a-fresh-one branch is unreachable. Both
become real with the flag, and that comment becomes stale with it.

THE MIGRATION COST of the nil flag, measured rather than assumed. Go's
zero-value map IS nil, so `Default for map` must produce nil and a write
to it must panic — which is correct Go behaviour and can still turn
working goish code into a panic. Five structs derive `Default` with a
`map` field and are the sites to audit:

    mime/multipart/formdata.rs   Form
    net/http/fcgi/child.rs       request
    crypto/x509/cert_pool.rs     CertPool
    crypto/tls/mod.rs            Config
    testing/benchmark.rs         BenchmarkResult

`map::new()` stays NON-nil, because that is what `make` produces; only
`Default` and `From<Nil>` are nil.

### §2t — nil vs allocated-empty slice (issue #14): the JSON criterion is v1's

Measured before implementing, because the issue's acceptance criteria
would have pointed the work at a DIVERGENCE:

                       nil slice   empty slice
    v1 json.Marshal    null        []
    v2 json.Marshal    []          []

v2 formats a nil slice as `[]`. So "marshal nil slice as null", which
issue #14 lists as required, is v1's contract; goish's current `[]` is
already right for v2, and the downstream report of a zero-value record
marshaling as `[]` where Go gives `null` can only be about v1 (or about
a record whose field is `omitzero`).

Where v2 DOES observe the distinction, from
`tools/gen_slice_nil_ref.go`:

    omitzero_nil    {}            nil IS the zero value, so omitted
    omitzero_empty  {"s":[]}      allocated-empty is NOT

FULL CONTRACT, both versions, after extending the generator on
2026-09-12 so the v1-versus-v2 question is settled by data rather than
by reading a report:

    language level
      nil_is_nil            true
      literal_is_nil        false     []int{}
      make_is_nil           false     make([]int, 0)
      nil_len / literal_len 0 / 0
      append_nil_is_nil     false     appending allocates
      nil_slice0_is_nil     TRUE      nilSlice[:0] stays nil
      empty_slice0_is_nil   false     emptyLiteral[:0] does not
      copy_nil_is_nil       true
      three_slice0_is_nil   false

    marshal                 v1        v2
      nil                   null      []
      []int{}               []        []
      make([]int, 0)        []        []
      Rec{}                 {"s":null} {"s":[]}
      Rec{S: []int{}}       {"s":[]}  {"s":[]}
      omitempty nil         {}        {}
      omitempty empty       {}        {}
      omitzero nil          -         {}
      omitzero empty        -         {"s":[]}

    unmarshal (identical in v1 and v2)
      null  -> nil, INCLUDING over an existing non-empty slice
      []    -> allocated-empty, not nil

So #14's "marshal nil slice as null" is v1's contract and goish's `[]` is
already right for v2. An implementation must do BOTH, which is what
removes the need for an answer on which version the downstream uses.

`nil_slice0_is_nil` is the row a flag-based implementation will get
wrong: re-slicing a nil slice to zero length has to PRESERVE nil, while
the same expression on an allocated-empty slice must not.
    omitempty_*     {}            both omitted — no distinction here
    dec null  -> nil        (true)
    dec []    -> non-nil    (false)
    dec null over [1,2] -> nil
    dec []   over [1,2] -> non-nil

And the operational rules a representation has to preserve:

    nil == nil           true
    []int{} == nil       false      (and make([]int,0) likewise)
    append(nil, 1)       non-nil
    nilSlice[:0]         STILL nil
    emptyLiteral[:0]     non-nil
    three[:0]            non-nil    (keeps its backing array)
    copy of nil          nil

So the work is still needed — a nilness bit, honest construction paths,
`== nil` testing identity rather than `Len() == 0`, omitzero, and
decode — but NOT "nil marshals as null" under v2.

WHY THIS IS STAGED. Flipping `PartialEq<Nil>` from `Len() == 0` to nil
identity is a semantic change with NO compile error: all 64 candidate
`== nil` sites in src/ keep compiling and quietly change meaning, and
e2e passing would only say the examples still pass. The representation,
the construction paths and the JSON integration land first and are
verifiable on their own; the comparison flip needs each site read.

### §2s — `goish::Any` has no JSON v2 codec (issue #15)

`Command.Arguments *[]any` and `ExecuteCommandParams.Arguments *[]any`
are unportable with their real shape, because `slice<T>` requires its
element to implement the v2 traits and `Any` does not.

Go's contract is captured in `tools/gen_json_any_ref.go` (run it under
`GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 …`). The
transcript is more demanding than the issue's summary. Decoding into an
interface that ALREADY holds a value is six distinct behaviours, not
one:

    {"x":1,"y":2} -> any(Point{9,9})           decodes INTO the Point;
                                               the dynamic type is kept
    5             -> any(Point{9,9})           error, Point unchanged
    5             -> any("old")                error, string unchanged
    {"x":1}       -> any(map[string]any{k:1})  MERGES
    [9]           -> any([]any{1,2,3})         REPLACES
    null          -> any(Point{9,9})           nils the whole interface

Into an empty interface Go picks nil / bool / string / float64 /
[]any / map[string]any — a number is ALWAYS float64, so storing an int
for `1` round-trips and diverges the moment anything reads the type.

Why this is not a downcast table: Go dispatches on arbitrary dynamic
types, including structs and custom marshalers reachable only through
the interface. goish already has the machinery for a trait surviving
the `Any` wrap — the per-trait registry `#[goish::interface]` emits —
so `MarshalerTo` is registered that way.

**Marshal: done.** `v2::RegisterAnyMarshaler::<C>()` adds a concrete
type; `#[goish::reflect]` emits one per struct into `.init_array`, so a
generated message inside an `any` field needs nothing written by hand.
`__register_builtin_marshalers` covers the types Go's own decoder
produces. An unregistered type errors and the message NAMES it, which
is the difference between a one-line fix and a bisect.
`json_any_marshal_ref_smoke` pins ten rows against Go.

One trap, found the hard way: `Any` is itself `'static + Sized + Send +
Sync`, so the blanket `HasDynAny` gives `AsExt::As` a view of the
NEWTYPE. Every lookup asked the registry about `TypeId::of::<Any>()`
and missed. Use `self.as_any()`, one level in.

**Unmarshal: done**, and `Command.Arguments *[]any` round-trips —
which also needed `impl FromValue for Any`, since `#[goish::reflect]`
emits a v1 codec as well as a v2 one.

Into an EMPTY interface the default types need no registration.
Decoding into a HELD value does, through
`v2::RegisterAnyUnmarshaler::<C>()` — and that one is deliberately NOT
emitted by the reflect macro: it needs `Clone + PartialEq` to copy the
held value and put the result back, and a generated struct is not
required to have either. Emitting it unconditionally broke three
existing examples (`reflect_json`'s `Person`, `Bag`, `Bare`), so it
stays opt-in and the error names both the type and the call. Marshaling
is automatic either way.

`json_any_ref_smoke` pins 27 rows.

**Still open:** nothing known. Issue #15's remaining acceptance items
are `options` and deeper malformed-input parity, which ride on the
surrounding v2 contracts rather than on `Any` itself.


## 1. `crypto/tls` — the record layer is the last invented code

**Re-measured 2026-09-04, re-checked 2026-09-06.** Everything this
section used to describe as unwritten is written:
`scripts/port_coverage.py crypto/tls --by-decl` reports **353/353 =
100%** across its two packages — run it rather than trusting the ratio
here, which read 275/291 = 94.5% two days ago. The
anchor count that used to sit in this sentence is deliberately gone:
it read 891 and was 896 two days later, moved by ordinary work on the
file, which is what a number in prose does. Every file
the old order-of-work table listed — alert, common_string, defaults,
prf, cipher_suites, auth, ticket, key_agreement, conn,
handshake_client, handshake_server, handshake_server_tls13, common,
ech, quic, cache — now exists as an anchored port.

The 16 QUIC declarations that used to sit here — HandleData,
NextEvent, Start, StoreSession, SetTransportParameters and the eleven
`quic*` helpers — are still unported. They are no longer counted
because they are now **waived**: all 24 waivers in `crypto/tls` are
QUIC (`QUICClient`, `QUICServer`, `QUICConn.*`, `Conn.quic*`,
`newQUICConn`, `quicError`), justified in-tree as dead code without a
QUIC transport. That is why the ratio reads 353/353 — the numerator did
not climb to meet the denominator, the denominator came down. Nothing
else Go declares in `crypto/tls` is missing.

What is left of the demolition:

| file | LOC | anchors | state |
|---|--:|--:|---|
| `record.rs` | 975 | 1 | invented. `conn.rs` is Go's record layer, ported with 55 anchors, and both are live. **Diffing it against conn.rs has produced five security defects** — three on 2026-09-04, two more on 2026-09-14 (the SPKI walk that skipped the algorithm OID, and the absent Lucky13 countermeasure) — each fixed with a smoke. One more was reported and then RETRACTED — a discarded RNG error: `crypto::rand::Read` calls `fatal` on failure, so the `let _ =` could not leave a zero IV. The file header carries the retraction and lists what was checked clean. Three of its hand-rolled crypto primitives were deleted on 2026-09-14 (the SPKI walk, the TLS 1.2 PRF, the CBC padding check), each delegating to the anchored port behind a Go-generated table. Retiring it is still the goal; until then it is no longer unexamined. |
| `session.rs` | 261 | 0 | invented. Diffed 2026-09-06 against Go's lruSessionCache: it bounded tickets PER HOST and nothing bounded the host count, where Go bounds keys. Fixed, and the smoke's existing capacity row could not have caught it — 200 tickets on one host was already bounded. |

### The invented CLIENT handshake, audited 2026-09-06

`record.rs` got this treatment on 2026-09-04. The other half of §1's
invented code is the client handshake — `do_client_handshake` and the
`do_client_handshake_tls13*` family, about 2,400 lines across
handshake_client.rs and handshake_client_tls13.rs, exported from
mod.rs. Three defects, all in authentication:

  * `verify_cert_verify` returned SUCCESS for any signature algorithm
    its match did not list, with a comment saying it skipped
    verification. CertificateVerify is what proves the peer holds the
    private key, so a party with a copy of a server's public
    certificate could name an unlisted algorithm and be accepted. Go
    refuses at two gates (handshake_client_tls13.go:680 and :686).
  * `do_client_handshake` and `do_client_handshake_chacha20_only` took
    a `skip_verify` parameter and IGNORED it — the underscore said so.
    Neither performs any certificate verification: no chain, no
    hostname, no roots. A caller passing `false` to ask for
    verification got an unauthenticated channel silently. They now
    refuse rather than pretend.
  * the TLS 1.3 decrypt path had no maxPlaintext bound, which
    record.rs applies at both of its decrypt sites. Bounded overage
    rather than unbounded — `read_record` caps the ciphertext — so a
    spec deviation, not a DoS.

Checked and found CORRECT, so the next reader need not redo it:

  * the server Finished verify_data is compared in constant time and a
    mismatch aborts.
  * the X25519 all-zero shared secret check is present in the invented
    path and correct (constant-time OR, then compare) — RFC 8446
    requires the abort.
  * `client_random` checks its `rand::Read` result at both sites. The
    six `let _ = rand::Read(…)` elsewhere are all SAFE: goish's Read
    ports Go's contract and calls `fatal` on failure, so it cannot
    return an error or short-read. This was misread once already —
    see the retraction in record.rs's header.
  * the downgrade canary (RFC 8446 4.1.3) is checked on the LIVE path,
    a faithful port including the operator precedence.

**A FOURTH, found 2026-09-13, in the same function's caller.** The
audit above fixed `verify_cert_verify` accepting an unlisted signature
algorithm. It did not look one level up: when
`parse_tls13_cert_verify` returned `None`, the caller CONTINUED —

    None => {
        // Continue — don't abort for parse failure
        //            (shouldn't happen with well-formed servers)
    }

— skipping the signature check entirely. The parser returns `None` for
anything truncated, so a one-byte body was enough, which makes this
strictly easier to trigger than the algorithm case: an attacker need
not choose an algorithm at all. CertificateVerify is the only thing in
TLS 1.3 binding the certificate to the connection, and a MITM already
holds the handshake secret from its own key exchange, so skipping it
means any public certificate can be presented and believed. Go never
reaches the decision — `readHandshake` fails to unmarshal and aborts.

"Shouldn't happen with well-formed servers" is true and beside the
point. A hostile server is the case this code exists to survive, and
that comment is the whole defect in one line.

Found by sweeping `#![allow(unused_variables)]`, which is how the
`net/lookup.rs` context defect had just been found. The suppression
here was a benign no-op three lines below the bug — it did not hide it,
it pointed at it.

THE SWEEP FINISHED 2026-09-13, and it is worth recording what it cost
and returned. Three files carried `#![allow(unused_variables)]`. Two
sat on a real defect (the dead `ctx` in `net/lookup.rs`, this one).
The third, `dnsmessage/mod.rs`, was hiding NOTHING — removing it
produced zero warnings, so it was stale. Widening to that file's
sibling allows found one unused import and nothing else; widening to
`lookup.rs`'s siblings found a dead `ERR_MALFORMED_DNS`, which turned
out to be a fourth defect of its own (see below). All four suppressions
that hid nothing are gone, so the signal is back for those files.

Yield: 3 files swept, 2 defects, 1 stale suppression, and one more
defect from the follow-on `dead_code` sweep. A blanket `allow` at the
top of a ported file is worth reading as a to-do list.

The decision is now `cert_verify_decision`, extracted so the refusal is
testable, with a `__cert_verify_decision` hook and
`tls13_certverify_refuse_smoke`. The smoke asserts THREE DISTINCT
refusal causes, not just three refusals: every row rejects something,
so a decision function that refused everything would pass them all.

Scope worth carrying: none of the FOUR defects is reachable from
`tls::Dial`. That runs Conn::Handshake -> handshakeContext ->
clientHandshake -> the ported clientHandshakeStateTLS13, which was
traced rather than assumed. handshake_client_tls13.rs's header claimed
the invented client was "the live TLS 1.3 client"; it is not, and that
is corrected. The invented family is public API, which is why the
defects were worth fixing rather than waiting for retirement.

The lesson repeats: the audit that fixed the algorithm case listed
what it had checked CLEAN, which is the right habit, and the caller was
in neither list. Auditing a function is not auditing its callers.

`handshake_client.rs` and `handshake_server_tls13.rs` are no longer
squatters — they carry 22 and 19 anchors.

### A FIFTH, found 2026-09-14: X509KeyPair's consistency check ran backwards

Not in the handshake — in the loader every server calls first.
`tls.X509KeyPair` verifies that the private key you handed it actually
belongs to the certificate you handed it. Go's version
(tls.go:320-352) switches on the **certificate's** public key, and
every arm fails closed, `default` included:

    switch pub := x509Cert.PublicKey.(type) {
    case *rsa.PublicKey:      priv, ok := privateKey.(*rsa.PrivateKey); if !ok { … type error }
    case *ecdsa.PublicKey:    …
    case ed25519.PublicKey:   …
    default:                  return fail("tls: unknown public key algorithm")
    }

goish switched on the **private** key, implemented the RSA arm only,
and — because it read the leaf's key with a bespoke
`decode_x509_rsa_pubkey` rather than the real parser — treated "the
certificate's key is not RSA" as *nothing to check* and returned
success. A non-RSA private key downcast to nothing and skipped the
block entirely.

Measured, not argued. `examples/tls_common_smoke.rs` now drives a 3×7
matrix — RSA, ECDSA P-256 and Ed25519 certificates against seven keys
— whose twenty-one expected results were read off Go 1.25.5's own
`X509KeyPair`, not transcribed from tls.go. Restoring the old code
turns **20 of the 21 cells red**: seventeen of the eighteen mismatched
pairs were accepted, the only one ever caught being RSA-cert +
different-RSA-key.

**This is not a vulnerability, and it is worth being precise about
why.** A mismatched pair fails closed one layer down: the peer verifies
the handshake signature against the certificate it was sent, and a key
that does not match cannot produce one. What was lost is the
*diagnosis*. Go names an operator's mixed-up PEM files at startup, on
the line that loaded them; goish accepted them and surfaced the problem
later as an unexplained handshake failure on a different machine.

Two smaller things fell out of the same read:

  * `Certificate.Leaf` was never populated. Go sets it by default
    (tls.go:314, gated on the `x509keypairleaf` godebug, whose default
    is on), so every goish caller that wanted the parsed leaf re-parsed
    the DER. Three of the matrix's cells pin it.
  * The doc comment said the check "is applied for RSA keys only" —
    accurate when written, and therefore the thing that stopped anyone
    looking. Re-measure a documented deviation before trusting it.

One cell is worth keeping in mind for anyone extending this: `ECDSA
P-256 cert + a P-384 key` is a **match** failure, not a type failure.
Go compares X and Y and never looks at the curve here, so a
curve-equality shortcut would diverge.

### Three copies of an X.509 parser, and what the third one cost

The X509KeyPair read above turned on one detail: goish extracted the
leaf's public key with a bespoke `decode_x509_rsa_pubkey` rather than
the ported parser. Grepping that name found the pattern had three
instances, not one — three independent hand-rolled walks from the
certificate DER down to the SubjectPublicKeyInfo:

| where | what it was for |
|---|---|
| `record.rs` | `decode_x509_rsa_pubkey` + its own `find_spki_in_tbs` |
| `legacy_p256.rs` | `decode_x509_ec_p256_pubkey` + a SECOND `find_spki_in_tbs` |
| `handshake_client_tls13.rs` | `parse_server_pubkey`, sniffing the algorithm OID against a three-entry table |

Each walked the same path — outer SEQUENCE, TBSCertificate, count six
fields, **step over the AlgorithmIdentifier**, take the BIT STRING —
and none of them read the algorithm it stepped over. Measured, with a
throwaway example: an RSASSA-PSS certificate handed to
`decode_x509_rsa_pubkey` came back as a perfectly good 2048-bit RSA
key, where `x509::ParseCertificate` on the same bytes reports
`PublicKeyAlgorithm 0` and produces no key at all — Go does the same.
They also skipped Go's `N.Sign() <= 0` and `E <= 0` checks, so a
negative modulus parsed fine.

Not a vulnerability: the callers are the invented client handshakes,
which do no certificate verification and now refuse outright unless
the caller passes `skip_verify`. The removal condition was already in
the file, in `legacy_p256.rs`'s own header — *"stays goish-only until
crypto/x509 is ported and can supply it"*. crypto/x509 is ported. All
three now delegate, and the two `find_spki_in_tbs` copies and the OID
table are gone.

**The delegation moved a hazard, and only a perturbation found it.**
`P256PublicKey` is two 32-byte arrays, and `big.Int::FillBytes` PANICS
into a buffer too small for the value. The old code failed closed on a
P-384 certificate by accident — it passed the raw BIT STRING to
`ParseUncompressedPublicKey(P256, …)`, which rejected the 97-byte point
on length. The real parser hands back a valid P-384 key instead, so
without an explicit curve check the process dies with `math/big: buffer
too small to fit value`, reachable from a server's Certificate message.
The check is there, and `x509_ecdsa_smoke` has the row; deleting it is
how the panic was demonstrated rather than assumed.

Worth separating the two guards the rewrite added, because they are not
equally real. The `PublicKeyAlgorithm != RSA` / `!= ECDSA` checks are
**redundant** — removing them leaves the smoke fully green, since
ParseCertificate already declines to produce a key it cannot name. The
curve check is **load-bearing**. Both are annotated as such in the
code; an untested guard that reads as the protection is how the
original comment (*"the caller has already matched the OID"*) survived
being true of one caller and false of the other.

### §1's remaining backlog is smaller than this section implied

`crypto/tls/mod.rs` is 9,253 lines with zero `go: sdk` anchors, which
read as 9,000 lines of unaudited invented code. Counted 2026-09-14:
**8,553 of those lines are `#[doc(hidden)]` test hooks** — 197 of the
214 functions — existing because Go's `crypto/tls` tests are in-package
and goish's examples are not. The production surface is **ten public
functions and about 676 lines**: `Client`, `Server`, `Dial`,
`DialChaCha20Only`, `make_dead_conn`, `X509KeyPair`, `LoadX509KeyPair`,
`NewListener`, `Listen`, `register_tls_impls`, plus the private
`parsePrivateKey`. All have now been read against Go. One defect
(`X509KeyPair`, above); the rest are faithful. Two were checked and are
worth not re-checking:

  * `Dial`'s hostname derivation is `rfind(':')` with a whole-string
    fallback, which is *exactly* Go's `strings.LastIndex` + `colonPos =
    len(addr)`. Brackets are not stripped from an IPv6 literal in
    either. It looks wrong and is not.
  * Go's `dial` closes `rawConn` when the handshake fails, and goish's
    `Dial` does not — it returns the Conn alongside the error. That is
    not a descriptor leak: `net::TCPConn` has a `Drop` that closes, so
    the caller's early `return` releases it. Go must close explicitly
    because it returns `nil, err` and the caller cannot.
  * `Listen` checks only `Certificates.Len() == 0` where Go's condition
    also spares `GetCertificate` and `GetConfigForClient`. goish's
    Config has neither field, so the reduction is exact; the error text
    still names them, as Go's does.

So what is actually left of §1 is `record.rs`'s record layer and
`session.rs`, both already audited, and the invented client handshake,
audited across five findings. The demolition, not an audit backlog.

One more stale claim fell out of the same pass, and it is §2b-v's
pattern rather than §1's: `handshake_messages.rs` carried a GOISH018
waiver reading *"marshalCertificate takes common.go's Certificate,
which is not ported yet (mod.rs declares a hand-written one)"*.
`marshalCertificate` is ported — anchored at
handshake_messages.go:1484-1518 — and `Certificate` lives in
`common.rs`, which `mod.rs` re-exports. Deleting the waiver leaves
port_lint at the same 7,846, so it was suppressing nothing and
explaining it with something false. Grep the REASON, not just the
count.

Worth reading before planning the retirement: this section used to
describe record.rs as a tidiness problem. It was a security backlog.
Three defects in one afternoon, all of the same shape — invented crypto
that no test had ever compared to the Go it replaces — and none of them
would have been found by the coverage or anchor tiers, because the file
claims to port nothing. A fourth was claimed and retracted, which is
its own lesson: the retraction lived in the code and the summary above
it kept saying four, so the same non-defect was rediscovered on
2026-09-06. Retire `record.rs` and
`session.rs` the way the ecdsa eviction was sequenced: the live
handshake is behind `tls_smoke` and the tier-3 (×50) stress family, so a
regression there is an outage rather than a test failure. Dispatch
`e2e-race.yml -f mode=full` after each swap.

## 2. Runtime defects blocking a clean CI

0. **`Transport.idleConnWait` is written and never read**, found
   2026-09-06. `queueForIdleConn` pushes a waiter onto it on an idle
   miss (transport.rs) and nothing pops it — the field's only other
   mentions are its declaration and its initialiser. Go reads the same
   map in `tryPutIdleConn`, handing a returning connection to a waiter
   BEFORE parking it in `idleConn`; `__try_put_idle` has every other
   guard Go has, in Go's order, but not that one.

   The push is dead rather than wrong: `getConn` ignores the `false`
   return and calls `queueForDial`, so an idle miss always dials. What
   it costs is reuse — a connection freed while a request is waiting is
   parked instead of handed over, so goish opens a connection where Go
   does not.

   NOT fixed here on purpose. Delivering means popping the queue under
   the pool lock and calling `tryDeliver`, and a half-wired handoff in a
   connection pool is the kind of defect that surfaces as an
   intermittent hang nobody can reproduce. It wants someone who can run
   the race suite.

   Third instance of this shape today, after jsontext's
   `AllowInvalidUTF8` and net/lookup's nine ignored contexts: state
   whose WRITES are all present, so the bookkeeping reads as finished,
   and only grepping for a READ tells them apart.

   **This is section 0 B's symptom, not its own item.** Go's read sits
   in `tryPutIdleConn`, reached from `persistConn.readLoop` at
   transport.go:2336 — the loop goish does not start. It is fixed by
   DECIDING B, not by wiring delivery into `__try_put_idle`, which
   would leave two half-connected paths where there is one working one
   today.


1. ~~**`Timer::Stop()` and the `Sleep` beneath it.**~~ **Verified
   2026-09-06**, which is what the entry asked for. `Stop` stores
   `stopped` with `Release` and only then calls `timer_cancel`
   (tick.rs:66-67), and the tick loop reads it with `Acquire` at all
   THREE points where it could otherwise miss it: before parking, after
   a cancelled park, and after winning the fire CAS but before sending.
   That last one is the race the entry was about — the fire and the
   Stop can both be in flight — and it is handled rather than argued
   about. A Release store with no matching Acquire would have been the
   defect worth finding here; there isn't one.

   Covered functionally by `time_stop_no_pin_smoke`, whose
   discriminator is wall time (a stopped 30s timer must not pin exit)
   so a Stop that "works" by never arming cannot pass it, and by
   `timer_reset_ref_smoke` against Go. Not covered: the race itself
   under contention, which needs repetition to provoke and is left to
   the tier-3 stress family rather than a smoke.
2. **`cast!` on an `Any` carrier.** Still open; documented as
   CONTRIBUTING.md §9b. Three options were scoped: reject at compile
   time with a `const` assert pointing at `.As::<>()`, narrow the
   blanket `HasDynAny` impl, or wait for specialization.
3. ~~**`ecdsa::PrivateKey` must implement `crypto::Signer`.**~~
   **Done** — `impl crypto::Signer for PrivateKey` is in
   `crypto/ecdsa/ecdsa.rs`. It is the one pair `split_brain_check.py`
   still reports, deliberately and with a note saying so.

## 2b. Unanchored files — the code no tier can check

Added 2026-09-04, because it turned out to be where the defects were.

A file with no `// go: sdk` anchor is invisible to every tier this
project has: `port_coverage.py` cannot count it, `anchor_check.py` has
nothing to check, and `port_bodydiff.py` has no Go body to compare. If
it also carries a header saying "Port of …", it reads as done. Reading
three such files against their Go on one afternoon produced seven
defects, in three separate packages:

| file | lines | found |
|---|--:|---|
| `crypto/tls/record.rs` | 938 | no record-length bound; no decrypted-length bound; a padding oracle (distinguishable bad-MAC vs bad-padding, and an early return) |
| `crypto/tls/session.rs` | 145 | cached tickets never expired; the cache was unbounded, so the peer decided how much it held |
| `net/dnsclient.rs` | 1143 | a xorshift transaction ID where Go uses the OS-seeded generator; a truncated answer returned as success |

**`src/net/lookup.rs` — context accepted and ignored, found 2026-09-06.**
Nine public methods take `ctx: &Arc<dyn context::Context>` —
`Resolver::LookupHost`, `LookupIPAddr`, `LookupIP`, `LookupCNAME`,
`LookupAddr`, `LookupTXT`, `LookupNS`, `LookupMX`, `LookupSRV` — and
not one reads it. There is no `ctx.Done()`, `ctx.Err()` or
`ctx.Deadline()` anywhere in the file. A caller who bounds a DNS lookup
with a one-second context gets an unbounded lookup.

The file header says so ("Context parameters are accepted but not yet
wired into cancellation"), and `#![allow(unused_variables)]` at the top
suppresses the warning that would otherwise say it every build. It was
not tracked in this document, which is why it is here now.

**Do not fix this with an entry-time `ctx.Err()` check.** Measured
against a running Go: Go does not short-circuit on a done context. It
carries the context into the dial, so the error is a `*DNSError` whose
`Err` is `dial udp [resolver]:53: operation was canceled`, with
`IsTimeout=false, IsTemporary=true`; for an expired deadline it is
`... : i/o timeout` with `IsTimeout=true, IsTemporary=true`. An entry
check returning a bare "context canceled" would swap one divergence for
a narrower but equally wrong one, and would look like a fix. The real
work is wiring the context into `dnsclient`'s dial, which is what the
header means by "the underlying dnsclient is context-free in this port".

A smoke for this cannot pin the error text verbatim — it contains the
resolver's address, which differs per machine — but the three flags and
the message suffix are stable and are what to compare.

**A THIRD DEFECT IN THIS FILE, 2026-09-13: malformed records were
filtered SILENTLY.** Go drops records whose names are not valid domain
names and returns an error ALONGSIDE the survivors, at five sites —
LookupCNAME, LookupSRV, LookupMX, LookupNS, LookupAddr. Its doc is
explicit that a caller must be able to tell: "those records are
filtered out and an error will be returned alongside the remaining
results, if any."

goish filtered — every `is_domain_name` check was present — and
returned `errors::nil`. A partly-malformed response is a signal about
the resolver, and swallowing it makes a broken or hostile one look
clean. `LookupCNAME` did report, with "invalid CNAME", which is not
Go's text; its inner path reported `errors::New(host)`, so the error
TEXT was the hostname.

The evidence it was intended and abandoned: `ERR_MALFORMED_DNS`, Go's
exact string, was declared in the file and never used. It surfaced only
when `#![allow(dead_code)]` came off.

Measured against Go 1.25.5: `Err` is the constant verbatim, the
rendered form is `lookup 192.0.2.42: DNS response contained records
which contain invalid names`, and IsTimeout / IsTemporary / IsNotFound
are all FALSE — so a caller branching on `IsTemporary` must not retry
this.

`dns_malformed_records_smoke` pins the predicate against Go's
`isDomainName` on the five inputs Go was actually asked about, and pins
the error's text, flags and rendering. It does NOT cover the five call
sites end to end, and says so: every `Resolver` method reads
`get_system_dns_config()` directly, so pointing one at a fake
nameserver needs an injection point that does not exist. That is the
gap to close if this area is revisited.

**FIXED 2026-09-13, and wiring the context is not the headline.**
Going to thread the context turned up a defect underneath it: goish's
DNS UDP query DID NOT TIME OUT AT ALL. Measured on the commit before
the fix, against a resolver that never answers, with
`timeout_secs = 1`: still blocked after 60 seconds.

`SO_RCVTIMEO` does not survive a signal. A `recvfrom` interrupted
before any data returns EINTR, and the retry restarts the timeout from
zero. goish's scheduler preempts with signals far more often than any
DNS timeout, so the receive was interrupted, restarted, interrupted —
**1688 EINTRs in 20 seconds, and not one EAGAIN**, against a socket
whose timeout was 100 ms. The loop's `if n == -4 { continue }` was
correct about EINTR and silent about the clock, which is an unbounded
wait wearing a timeout's clothes.

No attacker needed: a nameserver whose UDP/53 is firewalled to DROP
rather than REJECT is ordinary, and it hung every goish program that
resolved a hostname. The fix tracks the deadline in the loop rather
than leaving it to the kernel, so EINTR and EAGAIN both land on the
same check.

That is also why the sliced wait below is not optional. It looked like
a refinement for cancellation latency; it is what makes the timeout
exist.

**The context wiring, also done.** Ten methods take
`ctx: &Arc<dyn context::Context>` and the file contained ZERO calls to
`ctx.Done()`, `ctx.Err()` or `ctx.Deadline()`. Every `Resolver` method
now passes its context to `dnsclient`, which bounds the socket wait AND
the retry loop by it — bounding only the socket would still let
`attempts x servers` rounds run past the deadline. The package-level
`LookupHost` / `LookupIP` / `LookupCNAME` take no context and stay
unbounded, which is Go: they are the `Background()` forms.

`#![allow(unused_variables)]` is gone from lookup.rs. It was the only
automatic signal that the parameters were dead, and it was suppressing
it.

RE-MEASURED against Go 1.25.5 rather than trusting the note above,
`(&net.Resolver{PreferGo: true}).LookupHost`:

    cancelled ctx      DNSError Err="dial udp [ns]:53: operation was canceled"
                       IsTimeout=false IsTemporary=true IsNotFound=false
    expired deadline   DNSError Err="dial udp [ns]:53: i/o timeout"
                       IsTimeout=true  IsTemporary=true IsNotFound=false
    1ms deadline       nil — the lookup BEAT the deadline

The rendered form is `lookup <name> on <ns>:53: dial udp <ns>:53: …`.
The third row is the reason a smoke must not use a short deadline
against a real resolver: it is a race, and it resolved in under a
millisecond here.

HOW TO TEST IT DETERMINISTICALLY, which is the part that was missing.
`DnsConfig` is public and so are `servers` and `timeout_secs`, and
`dnsclient::lookup` takes `&DnsConfig` — so a smoke can point the
resolver at a UDP socket it bound itself and never reads from. That is
a true blackhole: no egress, no real DNS, no ICMP-unreachable race (an
unbound 127.0.0.1 port would give ECONNREFUSED immediately, which is
not the case under test). `syscall::Socket` / `Bind` are enough to make
one. The assertion is then: with a 1-second context the call returns in
roughly a second, not `attempts × servers × timeout_secs`.

THE PLUMBING, since the chain is not obvious from the entry point:

    lookup.rs (10 methods, have ctx)
      -> dnsclient::lookup / go_lookup_ip_cname_order / lookup_host
        -> try_one_name
          -> exchange(server, q, timeout_secs, use_tcp, ad)
            -> dns_packet_round_trip  (UDP)   SO_RCVTIMEO from timeout_secs
            -> dns_stream_round_trip  (TCP)   SO_RCVTIMEO + SO_SNDTIMEO

`dnsclient` is `pub mod`, so the four `pub fn` in that chain want
`_ctx` variants with the existing names delegating on
`context::Background()` — non-breaking, and it keeps the no-deadline
path byte-identical, which is what every internal caller uses today.

Both round trips take `timeout_secs: u64`, so the smallest honest unit
is SUB-SECOND granularity plus a deadline: a 1-second context cannot be
expressed at all right now. For CANCELLATION rather than a deadline the
socket timeout has to be SLICED — set SO_RCVTIMEO to
`min(remaining, ~100ms)` and loop, checking `ctx.Err()` each time round
— because a cancel arriving mid-`recvfrom` is otherwise invisible until
the full timeout expires. The recv loop already loops (for EINTR), so
the shape is there; what it lacks is distinguishing EAGAIN
(`syscall::EAGAIN`, 11) from a real error, which it currently folds
into one "recvfrom: timeout".

All three now carry a "What has been diffed against Go" block listing
what was checked CLEAN as well as what was fixed, so the next reader
starts where this left off rather than repeating it.

`scripts/example_coverage.py` finds packages no example imports. The
equivalent for this class is a one-liner — every `.rs` over 200 lines
with zero `go: sdk` anchors — and the remaining candidates were
`encoding/json/jsontext/mod.rs` (1500) and `runtime/netpoll/mod.rs`
(1112). `crypto/ssh/mod.rs` (1235) was read and is invented with no Go
counterpart at all; its header says what that means.

**Worked 2026-09-06.** `jsontext` gave up one: `AllowInvalidUTF8` was
stored and never read, so the decoder accepted invalid UTF-8 that Go
refuses — a parser differential, fixed and pinned by
`jsontext_utf8_ref_smoke`. `runtime/netpoll` was read and found to
handle EINTR correctly at both sites; it has no Go counterpart to diff
against, so it is a different kind of gap from the rest of this list.

**Worked 2026-09-06, and it paid.**
`src/encoding/asn1/mod.rs` (1226 lines, 7 anchors). The zero-anchor
one-liner cannot see this file — it HAS anchors — but seventeen of its
declarations are DER parsers carrying only a prose reference
(`/// parseBool (asn1.go:56)`), not a `// go: sdk` anchor:
`parseBool`, `checkInteger`, `parseInt32`, `parseInt64`,
`parseBitString`, `parseObjectIdentifier`, `parseBase128Int`,
`parseTagAndLength`, and the seven string parsers. `anchor_check.py`
cannot re-open a prose reference against the Go tree, so those line
numbers have never been verified and nothing would notice if they
drifted.

The package reads 77/77 = 100%, because `port_coverage.py` matched
Go's `parseBool` to goish's `ParseBool` case-insensitively. What
surfaced it was the new case-only line under that script's TOTAL: a
counted name differing from Go's in case alone AND carrying no anchor.
That is a DENSITY signal where the old one-liner was a ZERO signal,
which is why it sees a file with seven anchors and 1226 lines.

The naming is deliberate and documented (goish exports Go's unexported
parsers so `asn1_marshal_smoke` can reach them); it was the missing
anchors, not the capital letters, that left them unchecked.

All sixteen now carry `// go: sdk` anchors (75 under the package, all
verified by anchor_check) and every body was read against its Go range.
One defect, in `parseBitString`: Go's `||` short-circuits so
`1<<bytes[0]` only ever runs with a shift of 7 or less, and goish
computed that mask eagerly — a u32 shifted by 32 or more for any BIT
STRING whose first byte is 32 or more. Debug panics, release silently
yields 255, and `make e2e` builds debug, so the two profiles disagreed
about a byte that arrives in an X.509 signature or public key. Fixed
and pinned by `asn1_bitstring_ref_smoke` (14 rows, exits nonzero on
divergence).

The other fifteen are faithful, and the notable part is that
`parseInt64` ALREADY used `wrapping_shl` to avoid this exact debug
panic. So the hazard was known in this file and missed one line away —
which is the argument for reading a whole file rather than grepping it
for a pattern.

**Worked 2026-09-06: `src/os/mod.rs`.** Named by the same
anchors-but-not-enough-of-them signal as asn1 — 120 fn declarations
against 13 anchors — and by its own header, which recorded that a
sample had been read on 2026-09-05 and ended "the rest of the 61 have
NOT been read. This note records where the sample stopped, not that the
file is clear."

Six defects in the rest:

| what | effect |
|---|---|
| `ReadFile` sized its buffer to `Stat().Size()` | every file in /proc and /sys read back EMPTY, with a nil error |
| `dirFS.join` had neither of Go's boundary checks | `DirFS("")` resolved against `/`; a NUL in the name opened a different file than the one validated |
| `Rename` returned EEXIST too early | `Rename(missing, dir)` said "file exists" instead of the oldname's error |
| `Chtimes` skipped NsecToTimespec's correction | every pre-1970 timestamp with a fractional part failed with EINVAL |
| `Getwd` fell through when `stat(".")` failed | a bare "getwd failed" where Go reports the stat error |
| four paths returned `errors.New("<call> failed")` | the errno was gone, so ENOENT and EACCES were indistinguishable |

All six are pinned: `os_readfile_ref_smoke`, `os_dirfs_ref_smoke`,
`os_chtimes_ref_smoke`, and a new `rename/missingoverdir` row in the
existing `os_link_ref_smoke`. Thirteen more functions were read and
found clean, listed in the file header so nobody repeats them.

**Three of the six were held open by a COMMENT.** `Rename`'s omission
was labelled a case-sensitivity simplification, which covered half of
what it dropped. `Getwd`'s note asserted Go "falls through ... including
a stat of '.' that failed", which Go does not do. `ReadFile`'s doc cited
a line number 132 lines stale. In this tree a comment explaining why
goish differs from Go is a claim to re-measure, not context to trust —
2 above says the same thing about deviation notes and it keeps proving
out.

The file is now fully anchored: 89 anchors under `src/os`, all verified,
and `port_lint` findings fell 8244 -> 8189 across the pass. `Hostname`
is the one documented divergence left, and it is unreachable on Linux.

**The density signal's full hit rate, measured 2026-09-06.** Ranking
every `.rs` that HAS anchors but accounts for under half its `fn`
declarations gave 14 candidates. Walking all 14:

- **Productive (2).** `encoding/asn1/mod.rs` — one defect
  (parseBitString). `os/mod.rs` — six.
- **Known and tracked (5).** `jsontext/mod.rs` and `runtime/netpoll`
  (worked above), `crypto/tls/record.rs` and
  `handshake_client_tls13.rs` (1), `regexp/mod.rs` (2c).
- **Legitimately unanchored (7).** `convert.rs` is Go's BUILTIN
  conversions, which have no declarations to anchor — and its edge
  cases are pinned anyway: `runeconv_ref_smoke` covers both directions
  including invalid runes to U+FFFD. `math/mod.rs` delegates to `libm`
  and is compared against Go by four smokes. `syscall/mod.rs` is raw
  Linux syscalls with no Go counterpart to cite. `encoding/json/mod.rs`
  and `json/v2` are documented reimplementations, `key_schedule.rs` is
  anchored where it matters, `runtime/mod.rs` is goish's own startup.

So 2 of 14 held defects — a far better rate than the zero-anchor
one-liner's 0 of 70, and still mostly false positives. The signal is
worth running once and reading; it is not worth automating into a gate.
The 7 above do NOT need re-walking, which is the point of listing them.

**What the density signal is actually for, established the same day.**
It was built to find UNANCHORED code and it does, but its two biggest
hits were stale BANNERS: handshake_server.rs called a 1989-line port of
the TLS 1.2 server state machine "one function", and client.rs denied
the connection pool and TLS support that transport.rs has carried for
some time. Both read as capability statements. So the signal finds
files whose DOCUMENTATION has drifted from their contents, of which
missing anchors is one symptom and a wrong banner another.

All twelve current candidates have now had their banners read. Two were
wrong and are fixed; the rest are accurate or already tracked here —
syscall (raw syscalls, no Go contract to cite), json and json/v2
(documented reimplementations), convert.rs (Go builtins), math (libm
delegation), regexp (2c; the banner's no-linear-time divergence was
re-measured and still true WHEN THIS WAS WRITTEN — it is false now,
because §2c landed on 2026-09-14 and the banner was rewritten with it,
which is the outcome this signal exists to produce), record.rs and
handshake_client_tls13.rs (1), key_schedule and runtime/mod.rs. Do not
re-walk them; re-run the signal after work lands instead.

**Case-only credits: two packages fixed, the rest left visible on
purpose.** `port_coverage` matches case-insensitively, so Go's
unexported half of an exported/unexported pair is credited to the
exported one — a DIFFERENT declaration, counted as ported with nothing
having checked it. The `--case-detail` line added 2026-09-06 prints the
count on every run.

`strings` and `bytes` are now waived clean, because their two each —
`indexFunc` and `lastIndexFunc` — were verified inlined against Go:
IndexFunc is `indexFunc(s, f, true)` and TrimLeftFunc is the same
helper with `truth` false, spelled as each loop's own condition. Those
packages went from a flattering 109/109 and 115/115 to an honest
107/107 and 113/113.

About 109 remain — math 47, os 22, runtime 18, net 16, and a handful
elsewhere — and they are NOT waived. Most are Go's `Acos`/`acos`
shape, where goish's exported function delegates to `libm` and Go's
unexported implementation genuinely has no goish counterpart. Waiving
them would be accurate and would cost 109 edits for precision the
report line already discloses on every run. Verify the inlining before
waiving any of them: the two that were done here were checked function
by function against Go first, and `bufio.Reader.reset` is the reminder
that this shape sometimes hides a declaration with no counterpart at
all rather than an inlined one.

**A coverage percentage is a claim about the DENOMINATOR too.**
Recorded 2026-09-06 after losing the start of a session to it.

`encoding/binary` read 14/42 = 33.3% and looked like the most tractable
gap in `encoding/`. It was picked as one on that basis. The file header
says the opposite: Go sizes values from `reflect.Value` at RUN time and
moves bytes through `encoder`/`decoder` structs, while goish decides at
COMPILE time through a `Fixed` trait, so those 28 declarations have no
counterpart and will not get one. That was already written in a
GOISH018 ignore — which `port_coverage.py` does not read. It reads
`// go: waived`. The same fact recorded in a form one tool understands
and the other does not.

Three distinct things look identical in a MISSING list, and only the
first should be waived:

1. **The design replaces it.** binary's reflective walk; `slices`'
   pdqsort engine, delegated to Rust's `sort_unstable`; its
   `overlaps`/`startIdx` aliasing helpers, unnecessary because goish's
   Insert/Delete/Replace take `slice<T>` by value and return a new one.
   Waive, with a reason.
2. **Ported elsewhere in the package.** `net/net.rs`'s Close/Read/Write
   live on TCPConn; `flag`'s Args/NArg are in mod.rs. port_coverage
   searches the package directory and already counts them.
3. **Ported under a non-`fn` item.** `slices.Sort` is a MACRO — Go's
   Sort mutates in place, which a Rust fn taking `&mut` cannot express
   at the call site — published as
   `pub use crate::__goish_slices_sort as Sort;`. Fixed in the TOOL, not
   waived: port_coverage now credits `pub use … as <Name>`, 15 such
   aliases tree-wide.

There is a fourth that must NOT be waived: **blocked work.**
`testing/quick`'s seven need reflect over function and composite types
and goish's `reflect::Value` is a data-only tree with a no-op `Call`.
That is a real gap waiting on a real capability, and waiving it would
launder it into 100%.

Cross-referencing GOISH018 ignores against MISSING lists gives 81
declarations across 12 packages in this shape — flag 25, filepath 17,
quick 7, slog 6, textproto 5. Each needs its REASON read to sort case 1
from case 4. binary (28) and slices (41) are done; the rest are not, and
a bulk waive would be wrong.

There is already one guard against over-waiving, and it is worth knowing
about before adding more: `provenance.yml` asserts a DENOMINATOR FLOOR
for crypto — `if want < 1709: exit`, with the comment "declarations
stopped being counted". Waiving enough of crypto would trip it. No other
package has that floor, so `binary`, `slices` and anything waived next
rely on the printed WAIVED line and on the reason text being read.

A related trap in the same script, fixed 2026-09-06: `asm_decls` split
the gap into portable and assembly by testing whether a joined signature
ENDS WITH `{`, so every ONE-LINE Go function — which ends with `}` —
counted as an assembly stub. 3937 of those in the Go tree against 2915
genuinely bodyless declarations. `net` read `635 portable + 20 assembly`
and is `652 portable + 3 assembly`. If a package's assembly column ever
looks implausibly large, that was why.

**`src/io/pipe.rs` — 360 lines, zero anchors. Anchored 2026-09-06.**

The file called itself a "line-by-line port of io/pipe.go" and carried
no `// go: sdk` anchor and no `decls:` manifest, so no tier compared it
to Go. Its six `pipe.*` methods read as MISSING in port_coverage, which
is what surfaced it. All fifteen of io/pipe.go's functions were present
in a clean 1:1 mapping, with renamed receivers (`pipe` -> `PipeData`,
`onceError` -> `OnceError`).

Anchoring it took two attempts, and the first failure is the lesson.
Adding fifteen anchors made goishlint report GOISH018 0 -> 13 —
"Go function `Close` in pipe.go has no anchored Rust counterpart" for
functions that were anchored. Three hypotheses were wrong: it was not
the missing manifest, not receiver-qualified vs bare symbols, and not
unanchored Go declarations (pipe.go has exactly fifteen `func`s and all
fifteen carried an anchor).

The answer was in goishlint's source, which is a sibling repo — out of
scope to MODIFY, but reading it is what solved this.
`find_comment_block_top` walks up over CONTIGUOUS comment lines and
returns the topmost, then `validate_anchor_line` runs on THAT line. An
anchor placed anywhere but the very top of the block is invisible: the
function is skipped entirely and its anchor never counted. Thirteen of
the fifteen had a `// Go: func (p *pipe) read(…)` prose line or a `///`
doc line directly above, because the insertion stopped when it saw
"go:" in the line above — and `// Go:` matched that test.

Re-anchored at the true block top: GOISH018 zero, anchor_check 149/149
ok under src/io with nothing UNATTACHED, io/ 87/98 -> 93/98 with io
itself at 46/46, and port_lint findings 8100 -> 8085 because fifteen
GOISH014 "unanchored fn" findings resolved at the same time.

The general rule, which GOISH014 states and this proves the cost of: an
anchor is only an anchor when it is the FIRST line of the comment block
above the declaration. Anywhere else it is a comment.

**The same scan then found `src/sync/cond.rs`** — 116 lines, no anchors,
no manifest, six of Go's seven cond.go declarations present. Anchored
the four that map (NewCond, Cond.Wait, Cond.Signal, Cond.Broadcast) with
documented ignores for what does not: Go's `copyChecker` compares a
Cond's own address against a stored one to catch a copy after first use,
and `noCopy` is the zero-size marker `go vet` keys on. Rust's moves and
borrows make both unnecessary — a Cond here borrows its Locker for its
lifetime, so the copy that breaks Go cannot be written.

**That exhausts this signal, which is the point of recording it.**
Looking for a `.rs` with zero anchors whose fn names match the
declarations of a same-named Go file returns exactly two candidates,
both now done. Widening it to any Go file in the matching package adds
one more and it is a false positive:
`encoding/binary/native_endian_little.rs` matches seven names that
belong to `littleEndian` in binary.go, which Go's `nativeEndian`
inherits by EMBEDDING — the file is a forwarding impl and already
carries the manifest and ignore that say so.

This is a much better signal than 2b's original "over 200 lines with no
anchors", which returned about 70 candidates and was all false
positives. The difference is requiring a NAME MATCH against real Go
declarations rather than the absence of anchors alone.

**The one-liner does not generalise, and the failure is worth keeping**
so nobody rebuilds it. Run against everything over 250 lines it
returns about 70 files and the sampled ones were all false positives:
`mod.rs` re-export roots, generated tables (`p256_table`,
`*_tables.rs`), goish-specific runtime (`scheduler`, `gomap`,
`gochan`), and documented REIMPLEMENTATIONS that are diffed anyway —
`math/big` (7110 lines, no anchors, three ref smokes) and
`net/dnsmessage` (1995, one). "No anchors" separates nothing on its
own; this tree has far more legitimately-unanchored code than
unchecked code.

Two other sweeps came back empty the same day, recorded for the same
reason. Auditing by FILENAME for packages with no `*_ref_smoke` is
useless here: `hpke_smoke` decrypts Go-produced ciphertexts,
`des_smoke` uses vectors lifted from Go's own `des_test.go`, and
`fips140_tls13_smoke` checks against an independent RFC 8446 HKDF
implementation — none of them named `_ref_smoke`. And `os/exec`
(1148 lines, no anchors, absent from the list above) is covered:
`lookpath_ref_smoke` pins Go 1.19's ErrDot including the empty-entry
and trailing-entry cases, and `exec_cmd_ref_smoke` pins Env
duplicate-key collapsing.

What did work, three times running, was reading a file this section
already names.

### Relocated packages, and the two that aliasing must not touch

Added 2026-09-06 alongside the `RELOCATED` fix in §2b-ii. Aliasing
`vendor/...` Go packages onto the goish paths that hold them credited
86 anchored declarations. The obvious next step — find the REST of the
relocated packages and alias those too — is a trap, and the reason is
worth writing down.

A second sweep for Go packages with `rs_files=0` whose leaf name
matches a goish directory gives 23 candidates. Most are leaf-name
coincidences: `internal/runtime/maps` is not `src/maps`,
`cmd/compile/internal/types` is not `src/go/types`,
`cmd/vendor/.../pprof/internal/driver` is not `src/database/sql/driver`.
Four are real, and their headers say so outright:

| Go package | goish | lines | anchors | state |
|---|---|--:|--:|---|
| `cmd/vendor/golang.org/x/term` | `term` | 144 | 8 | **anchored 2026-09-06**, in RELOCATED, 10/44 |
| `vendor/golang.org/x/crypto/chacha20poly1305` | `crypto/chacha20poly1305` | 210 | 12 | **anchored 2026-09-06**, in RELOCATED, 9/18 |
| `vendor/golang.org/x/crypto/internal/poly1305` | `crypto/poly1305` | 344 | 23 | **anchored 2026-09-06**, in RELOCATED, 15/20 |
| `vendor/golang.org/x/net/dns/dnsmessage` | `net/dnsmessage` | 1995 | 0 | **cannot be anchored against 1.25.5** — see below |

Three of the four are done, and each took the same shape: split the file
the way Go splits it (GOISH015 allows one Go file per `.rs`, and both
ports had two Go files in one `mod.rs`), anchor each declaration, then
fix whatever goishlint could suddenly see — tail expressions and casts
that a `mod.rs` was never checked for. Each then entered `RELOCATED` by
the map's own criterion rather than by hand, because the derivation
grep started reporting it.

Anchoring is also what finds things. chacha20poly1305 turned out to
have dropped Go's `errOpen` sentinel, building the same message inline
at two sites so neither could match the other by identity; term's
`errno_err` had a `// go: none` that was not first in its comment block
and so attached to nothing.

**All four have zero anchors, and that is why they stay out of the
map** — but the reason is narrower than it first looks, and the first
version of this section overstated it, so both are recorded.

Aliasing them was measured rather than argued about. It credits **85**
declarations, not the ~245 the line count suggests, and every one of
the 85 is reported UNVERIFIED, because a zero-anchor file marks all its
names unanchored:

    term                10/44   all 10 unverified
    chacha20poly1305     7/18   all  7 unverified
    poly1305            13/20   all 13 unverified
    dnsmessage          55/163  all 55 unverified

So aliasing would NOT launder them — the report says exactly what the
credit rests on. And these four are not unchecked: `dnsmessage` has
`dnsmessage_ref_smoke`, chacha20poly1305 has
`chacha20_poly1305_ref_smoke`, `term` has `term_pty_smoke`, and
poly1305 rides the chacha smoke. That is §2b's own lesson — "no
anchors" does not mean unchecked — and it cuts against the argument for
excluding them.

What decides it is the invariant. `RELOCATED`'s entries earn their
credit from anchors `anchor_check.py` validates against the Go tree;
entries earning it from a name match break that property and make the
map's rationale incoherent. The cost is concrete: tree-wide ported
would go 5,917 to 6,002 with nothing newly verified, and the
name-level figure the README publishes would go from 1.4% to 2.7%. A
worse headline number bought with no additional checking.

Both readings have a point — 0/163 for `dnsmessage` is a false "not
ported", and 55/163-all-unverified would at least be true. The fix that
satisfies both is to anchor these four, which is the work; aliasing
them is the shortcut that removes the reason to do it.

Note the asymmetry that makes the map safe to extend correctly: `grep
'// go: sdk .*vendor/' src/` finds relocated packages that ARE anchored,
which are precisely the ones eligible. A relocated package the grep
cannot see is a relocated package with nothing to credit.

**dnsmessage is the fourth, and it cannot be done.** Investigated
2026-09-06 by trying to anchor it. Go 1.25.5 — the SDK this tree pins,
and the only one `goref.sh` can diff against — vendors a dnsmessage of
ONE file, `message.go`, with no `svcb.go` and no SVCB at all. goish's
port has `SVCBResource`, `TypeSVCB` = 64 and `TypeHTTPS` = 65. So its
`@go1.26.0` header is not sloppiness: it is accurate, and it is
evidence that the code came from a newer x/net than this tree can open.

That makes anchoring impossible rather than merely unfinished. Half the
declarations have no counterpart in 1.25.5, and the other half would
carry line ranges from a source that is not the one they were ported
from — an anchor that `anchor_check.py` would happily validate against
the wrong file. The work is to pin the x/net version this was taken
from, or to re-port against 1.25.5 and lose SVCB. Until then
`dnsmessage_ref_smoke` is what checks it, and it checks the wire
format, which is the part that matters most.

**dnsclient.rs: the 1.25.5 anchors VALIDATE, and the cleanup is the
blocker.** Attempted 2026-09-06 and reverted, because the result is
worth more as a measurement than as a half-finished file.

Every declaration in `src/net/dnsclient.rs` maps to a Go 1.25.5 one by
the camelCase-to-snake_case fold this tree already uses — `new_request`
/ `newRequest`, `try_one_name` / `tryOneName`, `is_domain_name` /
`isDomainName`, and so on for all of them. Splitting the file per Go
file (`dnsclient.go` keeps `equalASCIIName` and `isDomainName`;
everything else is `dnsclient_unix.go`) and anchoring thirteen
declarations, **`anchor_check.py` exits 0**: every range names exactly
the declaration claimed, against the pinned 1.25.5 tree. So unlike
dnsmessage there is nothing here that only a newer x/net or Go could
provide, and the port is anchorable against the SDK this repo has.

What stops it is the cleanup, not the provenance. The file predates the
tree's conventions and goishlint has 95 findings for it once it is
split and anchored:

  - 25 that are a pure path move, and the baseline proves it — the old
    `src/net/dnsclient.rs` entry reads GOISH005 11, GOISH006 1,
    GOISH007 1, GOISH010 12, and the new path reproduces those four
    counts exactly. `String::from` twelve times, a `Result<T, E>`
    return, `.as_str()`: a public surface in Rust types rather than
    goish ones.
  - ~60 that are new, and they are the price of the anchors: GOISH018
    and GOISH021 fire because a file citing `net/dnsclient_unix.go`
    OWES its declarations, and goish ports about half — no
    `goLookupHostOrder`, `goLookupCNAME`, `avoidDNS`, no
    `hostLookupOrder` constants, no `resolverConfig`. Removing the
    manifests does not help; that was measured too, and drops only the
    six GOISH017.

So the work is: migrate the public surface off `String`/`Vec<String>`/
`&str`/`Result` onto goish types, then split, anchor and waive the
genuinely unported half. That is a package-sized job on the live
resolver, and it wants doing as one, not as an annotation pass that
locks sixty waivers around code that should be rewritten anyway.

**The version claim on the two dnsclient files, with no evidence either
way.** `dnsclient.rs` and `dnsconfig.rs` also say 1.26.0, and
unlike dnsmessage nothing in them settles it: Go 1.25.5 has both
`net/dnsclient_unix.go` and `net/dnsconfig.go`, and goish's `DnsConfig`
carries 10 of Go's 14 fields — `single_request`, `use_tcp`, `trust_ad`,
`no_reload` among them — all of which exist in 1.25.5 too. So the claim
is neither corroborated nor contradicted; it is simply unchecked, which
is the whole point. Three files in total claim a Go version this tree
does not have:

    src/net/dnsclient.rs        @ Go 1.26.0
    src/net/dnsconfig.rs        @ Go 1.26.0
    src/net/dnsmessage/mod.rs   @go1.26.0

All 6,402 `// go: sdk` anchors in `src/` say 1.25.5, `go env GOROOT`
here is 1.25.5, and `scripts/goref.sh` diffs against `go env GOROOT` —
so these three claims cannot be checked by any tool in the repo, and if
they are accurate the code was ported from a source nobody here can
open. Together they are 3,584 lines carrying no anchors, and they are
the DNS resolver the README advertises. `dnsmessage` is the exception
worth knowing: `examples/dnsmessage_ref_smoke.rs` diffs it against a
running Go, so its wire format IS pinned and only the version line is
unverified. `dnsclient.rs` and `dnsconfig.rs` have neither anchors nor
a diffing smoke. Each file now carries the warning; the work is to
re-verify against 1.25.5 and correct the line or the code.

### A smoke that asserts nothing still prints ok

Added 2026-09-07, from a self-inflicted case. A ref smoke whose rows
run through a `chk()` helper counts FAILURES, and its gate read
`if FAILED == 0 { print "ok N/N"; exit 0 }`. In
os_file_readdir_ref_smoke four of its rows were still plain `Printf`
calls — the conversion to `chk` had silently not applied — so ZERO
assertions ran and it printed "ok 4/4" and exited 0.

It looked gated, because removing the ported method made it fail to
COMPILE. That is a real gate for a missing API and no gate at all for
a wrong value, and the two were conflated.

The fix is one clause: gate on `FAILED == 0 && seen == GO.len()`, so a
smoke that skipped its assertions cannot pass. Ten of the day's ref
smokes had the same shape and now carry it; the loop-driven ones
(which iterate GO itself, so a row cannot be skipped) do not need it.

The check that finds this is not reading the smoke, it is PERTURBING
it: change one expected value and confirm the smoke fails. A smoke
that passes both ways is measuring nothing.

### A sharper one: grep the REMOVAL CONDITION

Added 2026-09-07. The banner grep above finds dated claims. A subset of
them state, in the comment itself, exactly what would make them false:

    Remove this ignore when <X> lands | once <X> is ported
    when <X> lands | until <X> exists

That is ten comments in the tree, and SIX of their conditions had
already been met:

  * testing.rs, three of them — `Helper` "has no observable effect …
    until callSite lands" (callSite landed and `frameSkip` consults
    `helperPCs`), `Setenv`'s parallel guard "has to land with
    Parallel" (both landed; `checkParallel` panics with Go's message),
    and `newTestState` having "no runTests yet, and no field to store
    a matcher in" (runTests exists, and the field is filled by
    `runTestsWithMatch`).
  * `ecdh/x25519.rs`'s shims, "once crypto/tls is ported" — crypto/tls
    is 353/353, and what still uses them is section 1's INVENTED
    client handshake, which is the actual dependency.
  * `ed25519.rs`, "when fips140cache lands" — it landed, and never
    caches by design, so wiring it would buy nothing. The ignore is
    right; its reason was not.
  * `net/http/server.rs`, fields "carried now … when it lands" — the
    background reader landed, under a netpoller design that will never
    set `inRead` or `hasByte`.

One of the ten was gettable wrong in a way worth recording, because
the detector invites it. `crypto/tls` deferred ECH round-trip coverage
to "once computeAndUpdateOuterECHExtension lands", and the first
correction — mine, on the same day — read "the sealer IS ported, so
the coverage is writable and simply has not been written". Both halves
of the condition were met: the sealer landed AND the test was written.
`handshake_client_echRoundTrip` drives client seal into server open,
and tls_common_smoke has asserted the recovered inner ServerName ever
since. The right move on a met condition is to check whether the WORK
behind it was also done, not just the dependency it named.

Four were accurate and stay: ChaCha8 (math/rand/v2 is PCG only),
internal/godebug, internal/testlog, and crypto/ssh, which is not in
Go's standard library at all.

Why this beats the banner grep: a removal condition is falsifiable by
ONE grep, and it names the thing to grep for. No judgement about
whether a limitation still holds — just "does X exist yet".

### A detector that does work: grep the banner, not the anchors

Added 2026-09-06. The zero-anchor scan above fails because "no anchors"
does not distinguish UNCHECKED from LEGITIMATELY UNANCHORED, and this
tree has far more of the latter. Grepping the first ~45 lines of every
`.rs` for the phrases a deferral is written in does distinguish them:

    in v1 | Phase A | not yet | no ... yet | will be added
    is deferred | are deferred | for now, | stub only | not implemented

That is 31 files. It works because it does not ask whether code is
checked — it finds a DATED CLAIM, and a dated claim can simply be
re-run. Every one is falsifiable by a grep, which the zero-anchor
candidates were not.

Of the 31, about seventeen were wrong and the rest were accurate and
left alone. What the wrong ones have in common is that the work
happened and the sentence did not move: `net/mod.rs` promised an epoll
netpoller "in Phase B" from a file that imports it; `net/http/server.rs`
claimed no keep-alive and a pre-wildcard mux; `textproto/mod.rs` listed
five reader functions as unported that `reader.rs` had corrected the
same day in its own header. The accurate ones are worth naming too,
because they are the reason not to sed the phrases away: no AES-NI, no
SHA-NI, `term::ReadPassword`, `net/lookup`'s unwired context,
`os/user`'s supplementary groups, and `GOMAXPROCS(n)` not rescaling.

Two of the wrong ones were not merely stale. `crypto/tls`'s TLS 1.3
server cannot serve an ECDSA certificate "because ecdsa::SignASN1 which
Goish does not have yet"; it has it. `fips140/rsa`'s drbg shims stand
in for a package that exists and differ from it. Both are §2m. That is
the pattern worth carrying forward: when the REASON for a limitation
goes stale, the limitation stops being re-examined, and it is the
limitations that matter most that acquire the longest-lived excuses.

## 2b-ix. exec.Cmd had no ProcessState — FIXED

Go's `Cmd.ProcessState` (os/exec/exec.go:243) is documented as "Wait or
Run will populate its ProcessState when the command completes", and it
is how a caller reads the exit code, the signal, and — since
os.Process.Wait was ported — UserTime and SystemTime. goish's Cmd has
`Process` and no `ProcessState` at all, so none of that is reachable
after a Run.

Found by reading Go's struct next to goish's while checking the
`Cmd.Process` citation, which pointed at Dir's doc comment.

The fix was cheap only because os.Process.Wait had just landed:
`Cmd.Wait` called `syscall::Wait4` itself with a NULL rusage, where Go
reaps through `c.Process.Wait()` (exec.go:922). So the field could not
have been filled usefully before — UserTime would have read zero
however it was wired. Delegating to Process.Wait supplies the state AND
the rusage in one move and deletes the duplicate wait path.

Pinned by exec_processstate_ref_smoke, 8/8: what the field holds before
Start (nil), after a clean exit, a non-zero exit and a signal death,
that a SECOND Wait is refused with "exec: Wait was already called"
while the state survives, and that a busy child out-burns a sleeper
through Cmd — the row that could not have passed before.

## 2b-viii. 200 single-line prose citations name a symbol that is not there

Measured 2026-09-07 with `scripts/citation_check.py`, after teaching it
the single-line form. The first version matched only RANGES
(`x.go:12-20`), which saw 552 citations. Accepting `x.go:189` and
`x.go line 189` as well brings the tree total to 1942 — most prose
citations name one line, not a range — and 200 of those name a symbol
in backticks that is not on the line they cite.

The first one the fix found: `Cmd.Process` cited to
os/exec/exec.go:189, which is inside `Dir`'s doc comment. The field is
at 238, three fields further down.

Classified by how far the named symbol actually is:

  * **51 within ten lines** — version drift, and the cheapest to fix.
    Go moved a line or three between the port and 1.25.5 and the
    comment did not follow. `net.Listen` cited to dial.go:897, which is
    `var lc ListenConfig`, one line below `func Listen`.
  * **106 further away** — these need judgement and must NOT be
    rewritten mechanically. A citation may legitimately point at a
    CALL SITE or one interesting line inside a function rather than at
    the declaration; "the symbol is not on that line" is then correct
    and expected.
  * **33 where the symbol is not in the cited file at all** — either
    the wrong file, or the backticked name is goish's own rather than
    Go's, which is the checker's main false positive.

So the fixable-by-rule population is 51, not 200, and a sample of six
suggested otherwise: every one of the six happened to be drift, because
drift is what a small sample of a sorted list surfaces first. The
histogram is what settled it — measure the distribution, not the head
of the list.

Not started. §2b-vii's lesson applies to the fix as much as the
detector: the transformation is self-checking here (re-run the script
and the count must fall), which makes it safer than most, but a
mechanical rewrite of the 106 would silently destroy correct call-site
citations.

## 2b-vii. 22 smokes whose assertions cannot fail the process — FIXED

Measured and fixed 2026-09-07. e2e gates on the exit status of 848
examples (§ "printing a mismatch is not a gate"). Twenty-two of them
printed a mismatch and then exited ZERO, so every regression they were
written to catch was invisible to CI.

Three shapes, all confirmed by reading the tail of the file:

  * **no failure counter at all** — `tls_padding_oracle_smoke` ended
    `if ln != GO.len() { Printf("[!!] produced %d lines …") }` and fell
    off the end of `main`. A wrong plaintext, a MAC that stopped
    failing, a padding oracle reopening: all printed `[!!]` and exited 0.
  * **a counter that is printed, not returned** — `dns_txid_smoke`
    accumulated `bad`, then printed `"dns_txid_smoke: %v FAILED"` and
    returned normally. It said the word FAILED to a job that reads rc.
  * **Exit(1) exists but only for setup** — `http_bodyless_status_smoke`
    exited non-zero when Listen or Dial failed, which is what made the
    file LOOK gated; the assertion path below it had no exit at all.
    `tls_padding_oracle_smoke` and `tar_fileinfo_stat_smoke` had the
    mirror problem — five setup failures that printed and `return`ed,
    so a broken encrypt or a missing tempdir was also a pass. Those are
    Exit(1) now too.

The security-relevant ones are why this was not cosmetic:
`tls_padding_oracle_smoke`, `tls_record_overflow_smoke`,
`tls_record_iv_smoke`, `tls_session_expiry_smoke`,
`http_request_header_injection_smoke` and `dns_txid_smoke`. None was
failing — checked by building and running all of them before touching
anything — so this bought protection, not a rescue.

**The detector, and how it lied twice.** "Prints a mismatch but never
calls Exit(1)" gives 14 and misses `http_bodyless_status_smoke`, whose
setup errors do exit. "Mismatch print not followed by an exit within N
lines" gives 318 — it flags every smoke using a `chk()` helper, where
the print is in one function and the gate in another. The question that
separates them is narrower: **is ANY `Exit(1)` driven by a failure
aggregate rather than an error value?**

That gave 60, and 38 of those were WRONG. A smoke can be perfectly
gated without an `Exit(1)` anywhere: `math_big_smoke` ends
`syscall::Exit(if p == t { 0 } else { 1 })`, `tls12_smoke` runs a real
`testing::Main` harness over `t.Fatal`, and `http_dumpout_ref_smoke`
exits on `f == 0`. Excluding those three shapes gives 22, which is the
number that survived reading. Worth remembering: a detector for
"nothing enforces this" has to enumerate every way the thing CAN be
enforced, and the first draft never does. The 60 went into this file
before the check — the correction is the entry.

**How each fix was verified.** Not by reading. Two smokes were
perturbed — one expected value changed — and confirmed to exit 1
(`FAILED 1 check(s)`), then changed back. The first perturbation
attempt hit the string in the file's HEADER COMMENT rather than in
`GO[]` and reported rc=0, which reads exactly like a gate that does not
work; the perturbation has to land in the array the assertion reads.

## 2b-ii. 110 declarations are ported AND anchored AND counted missing

Measured 2026-09-06. For each Go package, take its MISSING list and
keep only the names that a `// go: sdk` anchor in the tree already
cites AGAINST THAT SAME GO PACKAGE. That was 110 declarations in 15
packages, and is 51 in 12 now that the first cause below is fixed — code that exists, carries provenance `anchor_check.py`
validates, and still reads as unported.

Do the same check without the same-package restriction and it gives 855
across 280 packages, nearly all noise: `Close`, `Open`, `Clean` and
`Base` are anchored somewhere in every tree. The restriction is what
makes it a signal, and it is the third time today a detector needed a
name match against the right Go package to stop being useless.

Two distinct causes, and they want different fixes:

**The package is not where the tool looks — FIXED.**
`vendor/golang.org/x/crypto/cryptobyte` reported `0/85` with
`rs_files=0` and `anchors=0`, while `src/crypto/cryptobyte` held four
files and 22 anchors in `builder.rs` alone. `build()` joined Go
packages to goish directories positionally, `scan_go(GOROOT/src/X)`
against `scan_rs(src/X)`, with no alias table, so a package goish
placed at a path of its own was invisible in BOTH directions: absent
from the scan looking for it, and ignored by the scan holding it, which
had no Go package of that name to match its files to.

`port_coverage.py` now carries a `RELOCATED` map, and its three entries
are not guessed — they are what the anchors say. `grep '// go: sdk
.*vendor/' src/` reports, for each goish directory, the Go package its
own anchors cite, and gives exactly three:

| Go package | goish |
|---|---|
| `vendor/golang.org/x/crypto/cryptobyte` | `crypto/cryptobyte` |
| `vendor/golang.org/x/crypto/cryptobyte/asn1` | `crypto/cryptobyte/asn1` |
| `vendor/golang.org/x/net/http/httpproxy` | `net/http/httpproxy` |

Tree-wide that is **+86 ported with the denominator unchanged** (5,831
to 5,917 of 37,808) — none of it new code, all of it credit for work
that was already written and already anchored. cryptobyte goes 0/85 to
**69/85**, its asn1 to 2/2, httpproxy to 15/15. The sixteen cryptobyte
declarations still missing are real remaining work, visible for the
first time.

The subtree runs are unaffected, which is the point to check before
touching this file: `crypto --by-decl` is still 1720/1720 = 100%, so
`provenance.yml`'s floor is untouched, and `net`, `net/http` and the
name-mode figures are all unchanged. The keys are subtree-relative, so
the map only takes effect for the whole tree — running the `vendor`
subtree directly still reports zero, because `src/vendor` does not
exist.

**The method is ported under a name Rust will not let it share (the
rest).** `archive/tar` (35) and `compress/flate`'s
`huffmanBitWriter.write` are this shape, and in tar the renames are not
style — they are forced, and the files say so:

  - `Format.String` is `impl Display::fmt`. Go's `String()` satisfies
    `fmt.Stringer` structurally; the Rust equivalent is `Display::fmt`,
    "which cannot be called `String`".
  - `headerGNU.accessTime` is `gnu_accessTime`. Go reaches these by
    casting `*block` to `*headerV7` and slicing; Rust will not
    reinterpret one array type as another, so the four views are
    flattened onto `block` with a prefix per view, and "the Rust name
    therefore cannot equal the Go one."
  - flate's `write` splits into `write_buf` and `write_slice`, because
    Go passes `w.bytes[:n]`, a view, and a goish `slice<byte>` owns its
    buffer.

`--by-decl` credits an anchored `Recv.Method` only when a fn of exactly
that method name is in the file, so every one of these loses its
credit. Waiving them would be wrong — they are ported, not absent.

**Fixed 2026-09-06, with the rule port_coverage already applied one
case over.** For a BARE anchored name it credits a snake_case fn, and
the comment there gives the reason: "the anchor is the evidence:
anchor_check re-opens its line range against the Go tree and `make
lint` gates on it, so the declaration named is the declaration that
exists." The same argument licenses crediting an anchored `Recv.Method`
whose anchor is ATTACHED to a declaration, whatever that declaration is
called, and `anchored_attached_keys` now does exactly that.

The evidence chain is two-sided, which is what makes it sound rather
than trusting. `anchor_check.py` re-opens the anchor's range against
the Go tree and confirms it names that declaration; GOISH014 then
requires the Rust item under the anchor to carry the same name, a
snake_case fold of it, or an explicit `goishlint:ignore GOISH014 -
<reason>`. A rename is therefore never silent, and the reasons read
like reasons: `errors`' `joinError.Unwrap` is `UnwrapMulti` because Go
has two optional unwrap methods of the same name and different
signatures and one Rust trait cannot carry both.

**110 anchored-yet-missing declarations became 5.** Tree-wide +45 with
the denominator unchanged and UNVERIFIED still 79 — every credit rests
on an anchor, none on a name. archive/tar alone gained 33.

The five left are all BARE names, and the rule excludes those
deliberately: `poly1305`'s `newMACGeneric` and `shiftRightBy2`,
`encoding/json`'s `appendString`, `json/v2`'s `makeFloatArshaler`,
`time`'s `match`. Widening the attachment rule to bare names would
credit a free function from an anchor that merely precedes an unrelated
one, and there is no receiver to constrain the match. What must not be
done either way is a name-similarity rule: crediting any fn whose name
starts with the method would let `write` claim `writeBytes`.

`testing/iotest` was a third of this list and is fixed: its five
`Read` methods were real trait impls under goish's `*Impl` receiver
names, and five anchors naming Go's receivers took the package from
13/18 to 18/18.

## 2b-iii. 129 GOISH018 waivers named declarations that exist

Found 2026-09-06 while doing the §2b waiver triage this file asks for.
Reading `flag`'s GOISH018 ignore — 58 names it says the port does not
have — twelve of them are `fn`s in that same file, each carrying a
`// go: sdk` anchor: `Parse`, `parseOne`, `PrintDefaults`,
`UnquoteUsage`, `isZeroValue`, `numError`, `usage`, `NFlag`, `Visit`,
`Set`, `String`, `SetOutput`.

A waiver naming a ported declaration is not merely untidy: GOISH018 is
the rule that reports a DROPPED declaration, so every stale name is a
declaration the rule can no longer speak about. If one of those twelve
were deleted tomorrow, nothing would say so.

Swept tree-wide with lint as the oracle rather than trusting the
name-match, which is the same trap that once credited Go's
`List.remove` to goish's `List.Remove`: remove from every GOISH018
ignore any name that is both a `fn` in the file and anchored, then run
`port_lint`. Anything genuinely needed fires as a new finding. Nothing
did — **129 names across 13 files, and port_lint stayed OK with none
new**, which is the proof that all 129 were dead.

    testing/testing.rs 50   slog/logger.rs 14   textproto/reader.rs 12
    slog/value.rs      10   slog/record.rs  8   testing/benchmark.rs 7
    flag/flag.rs       12   sort/sort.rs    3   url/url.rs           2
    …and four more

Two of the reasons were false in the same way the names were.
`sort`'s said `Ints`, `Float64s` and `Strings` are "macros in the module
root rather than functions"; all three are `pub fn`s in that file,
anchored to sort.go. `textproto/reader.rs`'s list had already been
corrected in its prose earlier the same day while the waiver kept the
names.

**The triage set, re-measured after that cleanup: 109 declarations
across 22 packages** that are both waived by their OWN package's
GOISH018 and still MISSING. That same-package constraint matters —
without it the query says 364 across 207 packages, because a name
waived in goish's syscall matches a missing declaration in
`cmd/vendor/golang.org/x/sys/unix`. Third time this session a detector
needed it to be worth anything.

    flag 25   sort 12   internal/poll 9   os/user 7   testing/quick 7
    log/slog 6   os 6   net/textproto 5   io/fs 4   testing 4   …

**`sort` is done: 38/71 to 41/41.** Thirty of its thirty-three missing
declarations are Go's pdqsort engine and the zsortfunc/zsortinterface
copies its generator emits of each piece — `pdqsort`, `choosePivot`,
`partialInsertionSort`, `breakPatterns`, `median`, `order2`,
`partition`, `heapSort`, `xorshift.Next` and the rest. goish's `Sort`
is a heapsort, so there is no counterpart to name: case 1, waived with
that reason, the same shape as `slices`' 41.

The other three were not case 1 and are now ported rather than waived.
`IntSlice.Search`, `Float64Slice.Search` and `StringSlice.Search` are
one-line forwards to `SearchInts`/`SearchFloat64s`/`SearchStrings`,
which goish already had, onto types goish already had. `search.rs`
carried a waiver saying goish's "convenience types carry no Search" —
true, and precisely the reason to spend three lines instead of a
waiver, so a caller holding an `IntSlice` can write `p.Search(x)` as in
Go. sort_ref_smoke 7/7, sort_smoke 11/11, sort_nan_ref_smoke 8/8.

**os/user and net/textproto followed.** os/user's seven —
`readColonFile`, the two `match*IndexValue` closure builders and the
four `find*` wrappers — are case 1 and now waived with the reason
already written into the file: goish folds all seven into
`find_user_by` / `find_group_by`. 15/51 to 15/44.

net/textproto's five split three ways, which is why per-declaration
reading beats a bulk decision. `noValidation` and
`mustHaveFieldNameColon` are case 1 — Go declares them as the only two
closures `readContinuedLineSlice` is ever passed, and goish spells the
choice as the `ValidatorKind` enum — so they are waived. `trim` was
NOT a case at all: it is ported, as `trim_slice`, with prose
provenance and no anchor, so it got the anchor it deserved rather than
a waiver. `Dial` and `NewConn` stay missing: they are the SMTP/NNTP
client surface, simply unwritten, and a waiver claims "resolved
elsewhere by design", which would be a lie.

**A mechanism note that cost a round trip.** `// go: waived` and
`goishlint:ignore GOISH018` are ORTHOGONAL. The first removes a
declaration from port_coverage's denominator; the second stops
goishlint reporting it as dropped. Waiving does not satisfy the lint
rule, so a waived declaration still needs the ignore. And an anchored
declaration under a sanctioned rename still reads as dropped to
GOISH018, because that rule keys off the anchor attaching by NAME —
which is the same gap `anchored_attached_keys` closed on the coverage
side in §2b-ii, still open on the lint side.

**io/fs, context and log: thirteen more, all case 1, all with the
reason already written in the file.** The pattern by now is that the
package told me the answer and nobody had transcribed it into the form
port_coverage reads.

  - `io/fs` — Go declares five one-line accessors (`errInvalid`,
    `errPermission`, `errExist`, `errNotExist`, `errClosed`) because
    the values live in `internal/oserror` and io/fs only re-exports
    them; goish declares the sentinels directly in its `var!` block.
    **40/45 to 40/40.**
  - `context` — `contextName` type-switches over the concrete contexts
    to find their `String`, which goish reaches through a trait method;
    `propagateCancel`, `parentCancelCtx` and `removeChild` serve the
    parent's `children` map, which goish replaces with a watcher
    goroutine. 25/32 to 25/28.
  - `log` — Go pools the header buffer through a `sync.Pool`
    (`bufferPool`/`getBuffer`/`putBuffer`); goish allocates one per
    Output call, the same output at a different cost. `Writer` and
    `Logger.Writer` hand the destination `io.Writer` back out, which
    goish refuses because it holds that behind a Mutex and handing it
    out would escape the lock. Root 35/39 to 35/35.

Ref smokes after: context_ref_smoke 10/10, context_string_ref_smoke ok,
iofs_ref_smoke 91/91, log_flags_ref_smoke 9/9.

One care point worth repeating from §2b's own text: waive the EXACT
missing set, not the ignore list. `io/fs`'s ignore names five and all
five are missing, but `context`'s names five where only four are, and
waiving a ported declaration pulls it out of the numerator as well —
which is how `strings` once read 108/113 instead of 110/115.

**os: four waived, two refused — and the refusal is the point.** Its
GOISH018 reasons read as one class but are two. `chtimesUtimes`,
`readFileContents` and `statOrZero` are helpers Go factors out and
goish inlines into the body below ("statOrZero's whole contract is 'a
failed Stat is size 0, not an error', which is the else-0 arm here");
`runtime_rand` is a runtime linkname goish has no hook for, replaced by
an LCG seeded from the monotonic clock. Case 1, waived.

`openDirAt` and `removeAllFrom` are NOT. Their reason says Go's unix
RemoveAll walks the tree with openat(2)/unlinkat(2) relative
descriptors "so a rename between the stat and the unlink cannot
redirect it", and goish's "walks by PATH; it is the same traversal
without that race guard". That is a missing TOCTOU protection blocked
on syscalls goish does not have — case 4, and waiving it would have
laundered a security gap into a coverage number. Bulk-waiving `os`'s
six on the strength of the other four would have done exactly that.

**Two packages deliberately NOT waived at all.** `internal/poll` is
3/130: goish ports the two deadline sentinels and nothing else, because
"goish's descriptor runtime is not this one — sockets go through `net`,
files through `os`, and both call the kernel directly rather than
through a shared poller". That reason would justify waiving all 127,
which would report 3/3 = 100% for a package goish does not implement.
3/130 is the honest number and it stays. `testing/quick`'s seven are
§2b's own case-4 example.

Triage so far: **52 declarations waived across six packages** — sort
30, os/user 7, io/fs 5, context 4, log 4, textproto 2 — plus one
declaration ported (`trim`) and three added (`sort`'s Search methods),
against `flag`'s 25, `testing/quick`'s 7, `os`'s 2 and
`internal/poll`'s 127 that must not be. `log/slog`'s six then split
four ways, which is the strongest argument yet for reading each one:

  - `GroupAttrs` and `byteSlice` are case 1 and waived. Go adds
    `GroupAttrs` beside `Group` only because its `Group` takes `...any`
    and cannot accept a `[]Attr`; goish's already takes the slice. Go's
    `[]byte` fast path in `appendTextValue` reflects over the boxed
    `any` to spot a byte slice; goish's `Value` cannot hold one, so
    there is nothing for the path to match.
  - `appendJSONMarshal` is also case 1, and its reason turns on a
    clause easy to skim past. "goish has no reflective marshaller"
    sounds like blocked work; the sentence continues "so those two
    kinds render through Value::append and Value::String, which produce
    the same bytes for every payload slog can hold". Same output by
    another route is case 1. Waived.
  - `NewLogLogger` is not. Its reason is "the package-level wrappers
    and the `...any` form are not ported" — unwritten, not resolved
    elsewhere, so it stays missing along with `countAttrs` and `stack`,
    which serve that same unported `...any` path.
  - `NewRecord` was case 2 all along: it is in `mod.rs` and already
    counted, so its entry in record.rs's ignore is merely stale rather
    than a waiver candidate.

slog 124/154 to 124/151. slog_handler_ref_smoke, slog_group_smoke and
slog_default_ref_smoke all match Go after.

What this does NOT resolve is the rest of the triage. `flag` keeps 43 names
and they are ROADMAP case 4, blocked work rather than case 1: the
package is a hand-written v1 FlagSet, and Go's `Var`/`Value` surface —
`newBoolValue` and the ten other `newXValue` constructors, `BoolVar`
and the ten other `XVar` binders — waits on the interface work, not on
a decision. Waiving those would launder a real gap into 100%.

## 2b-iv. One goish function credited to two Go declarations

Found 2026-09-07 while auditing the 231 case-only credits — the names
port_coverage counts because they differ from Go's only in case, with
no anchor behind them. The file's own note says they are "mostly Go's
own exported-wraps-unexported pair (`Acos`/`acos`), where the body is
here under the exported name. Not all: `bufio.Reader.reset` had no
counterpart at all."

Testing that: for each credit, does the Go package declare ANY name
equal to it ignoring case? A pair like `Bind`/`bind` or `Flush`/`flush`
does; a credit with no sibling at all is goish's exported `Foo`
answering for a Go `foo` that has no `Foo`. **14 of the 231.**

Two false starts are worth recording, because the naive version of this
check is wrong in both directions. Capitalising only the first letter
misses Go's actual spelling (`uint32n` pairs with `Uint32N`, not
`Uint32n`), and a regex for `var X` misses a name declared inside a
`var ( … )` block, which is where `os.ErrDeadlineExceeded` lives. Both
looked like findings until they were opened.

**Eight of the fourteen are a double count.** `runtime: readGCStats`,
`setGCPercent`, `setMaxStack`, `setMaxThreads`, `setMemoryLimit`,
`setPanicOnFault`, `setTraceback`, `start`. Go declares those in
package `runtime` as the linknamed implementations that
`runtime/debug`'s exported functions call. goish has them once, in
`src/runtime/debug.rs`, and `scan_rs` exposes a non-`mod` file BOTH as
part of its directory's package and as a package of its own — the rule
that lets Go's `crypto/rsa` find goish's `crypto/rsa.rs`. Go has both
`runtime` and `runtime/debug`, so the same file answers to both:
`SetGCPercent` is counted in `runtime/debug` by name AND in `runtime`
by case against `setGCPercent`. `runtime` reads 36/2800 with eight of
those 36 borrowed from a file that is already fully counted next door.

**Scope measured 2026-09-07, and it is narrow.** The first version of
this entry said a fix "would change every package's numbers". That was
pessimism, not measurement. The double count needs a goish file
`X/Y.rs` exposed as package `X/Y` where `X` is ALSO a Go package, and
there are exactly three in the tree:

    runtime/debug     (parent runtime is a Go package too)
    runtime/trace     (parent runtime is a Go package too)
    testing/iotest    (parent testing is a Go package too)

`crypto/rsa.rs`, the case the file-as-package rule exists for, is not
one: goish keeps `crypto/rsa` as a DIRECTORY, so no file-form entry is
created. And of the three, only `runtime/debug` actually inflates
anything, because the double count bites only where a name coincides
between the parent and sub packages — `SetGCPercent` against runtime's
`setGCPercent`. `testing/iotest`'s `OneByteReader` has no counterpart
in Go's `testing`, so it costs nothing.

So the damage was eight declarations in one package. **Fixed
2026-09-07**: `scan_rs` now keeps each directory's own paths and its
file-package paths, and `build` recomputes a directory's facts without
any file-package that is ITSELF in `gp`. Recomputed from source rather
than by subtracting ident sets, because subtraction would also remove a
name the parent legitimately declares elsewhere.

`runtime` reads 28/2800 where it read 36, with UNVERIFIED 15 to 4, and
nothing else in the tree moves: crypto stays 1720/1720 for
provenance.yml, net/http 721/776 by declaration and 639/639 by name,
io/fs 40/40, sort 41/41, context 25/28, testing 235/261. Tree-wide
UNVERIFIED 60 to 49, 1.0% to 0.8%.

What made it look hard was placement, not breadth: `scan_rs` is where a file is
attributed and it knows nothing about Go packages, while `build` knows
`gp` but sees merged fact sets rather than per-file ones. Excluding all
non-`mod` files from their directory's package would be wrong in the
common case — `net/http/client.rs` must count toward `net/http`,
because `net/http/client` is not a Go package. So the condition is "the
file-as-package is itself in `gp`", which is why the paths ride along
from the scan into `build` where `gp` is known.

The other six are `syscall: execve, exitThread, fcntl, fork, ioctl,
utimensat`. Go keeps those unexported and offers a different public
surface; goish exports `Execve`, `Fcntl`, `Fork`, `Ioctl`,
`Utimensat` directly, which is the whole point of a raw-syscall
runtime. Crediting them is defensible and they are single-counted. They
are listed here so the next audit does not re-open them.

## 2b-v. 95 suppressions that suppress nothing

Measured 2026-09-07, after the GOISH018 and GOISH021 name sweeps had
removed 185 dead NAMES from waiver lists. This is the general version
of that question: not "does this waiver name something that exists"
but "does this waiver stop anything at all".

Method, one lint run rather than hundreds: strip every
comment-only `goishlint:ignore` line in `src/`, run `port_lint.py`, and
collect the (file, rule) pairs that fire. Any pair that HAD an ignore
and does NOT fire is inert — the rule would say nothing about that file
even with the suppression gone.

    comment-only (file, rule) ignores   399
      fired when removed                295
      never fired, rule ran elsewhere    95
      rule never ran at all               9

    GOISH018 28   GOISH019 28   GOISH014 12   GOISH021 11
    GOISH020  9   GOISH017  6   GOISH023  1

**The first attempt was wrong and the error is worth keeping.** It
stripped whole LINES containing the marker, which for an inline
suppression — `let fd32 = fd as i32; // goishlint:ignore GOISH005 …` —
deletes the code that violates the rule along with the waiver for it.
GOISH005, GOISH006 and GOISH008 then reported nothing and looked
entirely dead, 50 pairs of them. Restricting the strip to lines that
are comments start to finish is what makes the number mean anything.

The nine "rule never ran" pairs are GOISH005/006/008/016/022, which
`port_lint.py` does not enable — its FLAGS are `--enable-goish017` and
`--enable-goish018`, and the second switches on 018/019/020/021 as a
group. Those suppressions may well be load-bearing under a fuller
goishlint invocation; this tool cannot say.

**62 of them name no symbol at all.** Found 2026-09-07 after two turned
up by hand — `auth.rs`'s `goishlint:ignore GOISH018  —` and
`pprof/mod.rs`'s pair. Sweeping the five symbol-keyed rules
(GOISH017/018/019/020/021) for markers whose symbol list is empty gives
62, spread over crypto, net/http, unicode, compress, log/slog and more.

Nearly all of them DO name the symbol — in the reason, after the em
dash: "`checkFIPS140Only` (pbkdf2.go) rejects…", "`init` (md5[go])
is…". goishlint reads the tokens BEFORE the reason, so it sees an empty
list and the marker suppresses nothing. None of the rules fire on those
files either — `md5.rs`'s baseline carries GOISH005 and GOISH023 and no
GOISH018 — so nothing is being hidden today. What is wrong is that each
reads as a recorded decision and is not one, and a future run that DID
start reporting those symbols would find a waiver already there,
looking deliberate, silencing nothing.

The fix per marker is to move the symbol in front of the em dash, or to
drop the marker and keep the prose — and which one depends on whether
the rule has anything to say about that symbol, which is the same
per-declaration reading the rest of this section wants. `auth.rs`,
`pprof/mod.rs` and `slogtest.rs` are done that way; 59 to go.

**Removal is NOT the obvious follow-up, which is why this is a note and
not a commit.** A waiver that no longer suppresses anything often still
carries the only explanation of a divergence — `testing.rs`'s GOISH019
on `M` describes exactly which fields Go's M holds and why goish's does
not, and that paragraph is worth more than the suppression ever was.
Ninety-five of these want reading one at a time: some are noise and
should go, some should lose the marker and keep the prose as a plain
comment. What must not happen is a bulk delete that takes the reasons
with it.

## 2b-vi. net/http's 100% is a by-name figure; 18 declarations have no anchor

Found 2026-09-07 while closing `net/http/cgi`'s last waiver, by running
the package in both coverage modes instead of one.

PROGRESS's net/http section read "639 / 639 functions (100.0%)", "All
twelve packages are at 100.0%", and "This is an anchored port, not a
name match". Measured by declaration the same tree is **721/775
(93.0%)** — root 536/586 (91.5%), `httputil` 52/56 (92.9%). Since
measured, `httputil` is CLOSED — 55/55, the first package off this
list — putting the tree at 724/774 (93.5%) with 50 left.

The gap is not method-counting noise. **None of the 54 as measured
carried a `// go: sdk` anchor anywhere in its package**, by intersecting
the MISSING list against every anchor symbol under `src/net/http/`:
zero of 50 in the root, zero of 4 in `httputil`. Nor are they renamed
-but-anchored ports. goish's per-connection loop is
`Server::serve_conn` at server.rs line 3390, and its whole comment is
"Per-connection serving loop. See keep-alive doc (M27f-β)".

Why the coarse mode reads 100%: it folds a method onto its bare name,
and `norm()` folds case but not underscores. Go's `Server.Serve` and
`conn.serve` both key as `serve`, which goish's exported `Serve`
satisfies — the connection loop credited to the function that starts
it. `serve_conn` earns nothing (`serveconn` != `serve`). This is the
conflation PROGRESS already documents for crypto ("the first one made
all fifteen look done"), sitting unremarked in the larger package.

What the 54 are — plumbing, not leaf helpers:

- server: `conn.{serve,readRequest,close,finalFlush}`,
  `chunkWriter.{Write,close,flush,writeHeader}`,
  `expectContinueReader.{Read,Close}`, `response.WriteString`,
  `checkConnErrorWriter.Write`, `timeoutWriter.Push`
- transport: `persistConn.{Read,readResponse,roundTrip}`,
  `persistConnWriter.{Write,ReadFrom}`,
  `bodyEOFSignal.{Read,Close,condfn}`, `Client.send`,
  `Transport.{CancelRequest,protocols,removeIdleConnLocked,
  onceSetNextProtoDefaults,prepareTransportCancel}`
- bodies: `gzipReader.{Read,Close}`, `cancelTimerBody.{Read,Close}`,
  `readTrackingBody.{Read,Close}`, `bodyLocked.Read`,
  `body.{readLocked,unreadDataSizeLocked}`, `maxBytesReader.Close`
- `httputil`: **DONE.** `ServerConn.{Read,Pending,Write}` were the
  half of a half-ported type; `delegateReader.Read` is waived, since
  it feeds a fake-conn round trip goish's DumpRequestOut does not do.
  Opening it turned up two live defects in DumpRequestOut (a missing
  transport header, and a dump that consumed the request body), both
  hidden behind stale "unported" notes. 55/55.

The functionality is largely present — goish serves keep-alive
connections and streams chunked bodies — so this is a PROVENANCE gap
rather than a hole, which is exactly what this section exists to list:
the code no tier can check. Both of this tree's proven defect nurseries
(§1's invented `crypto/tls`, §2b's unanchored files) have this shape.

Open, and not answerable from the names: each of the 50 is either a
restructured port that should carry an anchor to Go's range, or a
deliberate divergence that should carry a waiver with a reason. Those
are different answers, and the per-declaration read is the work.

The first one read confirms why it is worth doing. `gzipReader.Read`
is a restructured port — goish's `Body` is a closed enum and Go's
wrapper type is its `FramedBody::Gzip` variant — and reading it found
a live divergence. Go's `zerr` is commented "sticky"; goish returned
the gzip error once and then EOF, because the next Read re-ran
gzip::NewReader over an already-consumed reader. A caller that read
again after an error saw a corrupt body as a complete empty one. Go
also checks zerr BEFORE the closed flag, so the error survives Close.
Fixed and pinned by gzip_sticky_ref_smoke against Go 1.25.5. The
declaration was not missing, and it was not correct either — which is
the state this whole section is about.

The two read after it were the same. `cancelTimerBody.Read` had its
predicate computed and dropped, so Client.Timeout killing a body read
said "read tcp …: i/o timeout" instead of naming the deadline (fixed,
pinned in client_timeout_ref_smoke). `readTrackingBody.{Read,Close}`
is answered by `Body.__was_read`, which returned true for every
framing except Eager — so an UNTOUCHED streaming request body read as
consumed, and a retry Go performs (the request never reached the wire)
failed here with errCannotRewind. Now tracked as Go tracks it, with
`did_read`/`did_close` flags; for an Eager body the answer is
identical to the old `off > 0`.

`maxBytesReader.Close` was the fourth, and the only one so far that
was simply MISSING rather than subtly wrong. Go's MaxBytesReader
returns an `io.ReadCloser` and closes what it wrapped, which is what
makes the documented idiom `r.Body = http.MaxBytesReader(w, r.Body,
n)` work — the handler puts the wrapper back, and closing the request
body closes the real one. goish's wrapper implemented Reader only, so
it could not be put back at all (`Body::from_reader` wants a
ReadCloser) and the idiom was unwritable. Now a conditional
`impl Closer` forwards, as Go's one-line `return l.r.Close()` does,
pinned in http_maxbytes_close_smoke.

`transportReadFromServerError.{Error,Unwrap}` and
`nothingWrittenError.Unwrap` are the fifth and sixth, and they are a
pair: goish replaces both wrapper types with SENTINELS, which is
enough for the retry decision (identity is all it needs) and lossy for
the caller. Go keeps the cause and, on the path where the request will
NOT be retried, unwraps it — transport.go:716-724, commented "Issue
16465: return underlying net.Conn.Read error from peek, as we've
historically done." A reused conn failing a non-idempotent request
therefore told the caller "http: transport read from server" where Go
says "connection reset by peer". The write half already returned the
real error; the read half now does too.

`ServeMux.matchingMethods` was the seventh, and it is the one a user
would have hit. It builds the Allow header of a 405, and Go runs the
tree match TWICE — once for the path as given, again with a trailing
slash appended, "because matchOrRedirect will try appending a trailing
slash if there is no match". goish ran it once, so a mux carrying only
`POST /x/` answered `GET /x` with 404 where Go answers 405 and names
POST. A 404 says the route does not exist; a 405 says it exists under
another method, and the wrong one sends a client hunting a bug that is
not there. Fixed, and pinned by http_mux_allow_ref_smoke — five lines
including the guard that matters: when the METHOD matches, the path
must still REDIRECT (`GET /z` against a registered `GET /z/` is a 301),
so the second match must not swallow the redirect path.

`Transport.Clone` was the eighth and the worst, because it was silent.
Go's Clone copies EVERY exported field; goish copied fifteen and
dropped four — `Dial`, `DialTLS`, `DialTLSContext`,
`ForceAttemptHTTP2`. The three dial hooks are read at the dial site, so
a Transport configured to reach the network a particular way handed
its clone none of it and the clone dialled straight out. Clone's own
doc listed those four among "Go fields goish's Transport does not
have" — it EXPLAINED the omission instead of describing it, which is
why nothing questioned it. Pinned by http_transport_clone_ref_smoke,
and the smoke was checked to FAIL without the fix (`used=false`), which
matters here more than usual: the request still returns 200 either
way, so nothing but the assertion can see the bypass.

`removeIdleConnLocked` was the ninth and was not a defect at all: a
faithful port of Go's method carrying `// go: none — goish-only`. A
wrong label hides a real port from every tier that checks one. It is
anchored now (transport.go:1242-1272), which is also why the count
moved without any behaviour changing.

Four more were READ and are NOT defects, which is worth recording so
they are not re-opened: `response.WriteString` has no behavioural
effect here, because goish's `io::WriteString` has no StringWriter
fast path to assert on and always calls Write — the two are
consistent, and the gap is source compatibility only.
`checkConnErrorWriter.Write` cancels the request context on a write
failure in Go; goish reaches the same place from the other side, since
its netpoller disconnect watch (startBackgroundRead/abortPendingRead)
is wired to the request cancel, so a client that goes away cancels
either way. What is not separately wired is the write error itself.
`Transport.{protocols,onceSetNextProtoDefaults}` need HTTP/2 and a
`Transport.Protocols` field goish deliberately does not have, and
`Transport.CancelRequest` indexes the `reqCanceler` map already waived
above as absent by design — Go deprecates it for Request.WithContext
and says it may become a no-op.

A correction to this section's own premise, found by reading it out.
Not all 50 were unexamined: TEN waivers in the tree name a Go METHOD
by its bare name, and a waiver matches EXACTLY, so `--by-decl` — which
keys a method `Recv.Method` — never applied them. Eight are in
net/http (`conn.finalFlush`, `conn.maybeServeUnencryptedHTTP2`,
`bodyEOFSignal.condfn`, `body.readLocked`,
`body.unreadDataSizeLocked`, `Transport.prepareTransportCancel`, and
the two h2 accessors), one in strings (`Builder.copyCheck`), one in
compress/flate (`decompressor.makeReader`). They were reasoned about
and deliberately waived; the count simply could not see it. Both
spellings are carried now, the same fix cgi's `neverEnding.Read`
needed. net/http root drops 45 to 37 without a line of behaviour
changing, and crypto is untouched (1720/1720, so provenance's
denominator floor is safe).

Worth noting what did NOT come out of that scan: `slices`'s
`rotateLeft`/`rotateRight` look method-only to a naive `^func name(`
grep and are not — they are GENERIC free functions,
`func rotateLeft[E any](...)`, so those waivers were right as written.
A pattern that cannot see generics would have "fixed" two correct
waivers into wrong ones.

Seven more came off the list once they had been READ rather than
counted: Go layers a response body in wrapper TYPES (gzipReader,
cancelTimerBody, readTrackingBody), and goish's Body is a closed enum
carrying the same behaviours as framings and BodyState fields, so the
wrappers have no counterpart under their own names. They are waived
against the place each behaviour actually lives, and every waiver
names the smoke that would catch a regression — which is the point:
reading these three is what found the sticky-error, Client.Timeout and
rewind defects above. `ServeMux.matchingMethods` is the seventh, now
inlined-but-correct and pinned. Root 37 to 30, net/http 726/756
(96.0%).

`bodyEOFSignal.{Read,Close}` came off the list by being MEASURED
rather than reasoned about. Go's wrapper keeps `rerr` so a failed read
keeps failing; the guess was that goish, having no such field outside
gzip, would decay to EOF on the second read — the exact defect found
in the gzip reader earlier. It does not: against a truncated response
(Content-Length 100, ten bytes sent, conn closed) goish matches Go on
all five lines, sticky repeat included, because each read hits the same
dead connection. `examples/http_body_sticky_ref_smoke.rs` pins it, and
is worth having precisely because this function has been edited three
times today.

Six more were waived after being read and found EQUIVALENT, not
absent: `Client.send` (Go's jar sandwich, inlined into the redirect
loop because that loop is the per-hop unit),
`transportReadFromServerError.{Error,Unwrap}` and
`nothingWrittenError.Unwrap` (goish uses sentinels for the retry
decision and hands the caller the underlying cause directly, so the
wrappers have nothing left to carry), `response.WriteString` (goish's
io::WriteString makes no StringWriter assertion, so there is no
interface to satisfy — the gap is the spelling, not the wire) and
`checkConnErrorWriter.Write` (the disconnect watch cancels the request
context from the read side; only a peer that stops READING while still
connected is uncovered). Root 28 to 22, net/http 726/748 (97.1%).

A small trap worth recording, since it cost a lint round: a
`// go: waived` line placed directly above an anchored fn becomes the
FIRST line of that fn's comment block, and GOISH014 then reports the
fn as unanchored. Waivers go above a non-fn item, or in a block of
their own.

`persistConnWriter.{Write,ReadFrom}` are classified but NOT waived,
because the difference is real even if narrow. Go's Write exists to
maintain `pc.nwrite`, and `mapRoundTripError` asks
`pc.nwrite == startBytesWritten` — zero bytes on the wire — before
calling a failure `nothingWrittenError`, which is what licenses
retrying a request that is not replayable. goish approximates that
with a `head_failed` flag: the head write returned an error. The two
agree except in one window, a head write that lands PARTIALLY: Go
counts bytes, sees more than zero and declines to retry; goish sees
the error and retries. A truncated header block is not an actionable
request, so a server cannot have acted on it, which is why this is
recorded rather than fixed — but Go's rule is a byte count and
goish's is a proxy for one, and that is the kind of difference worth
knowing about before someone relies on it. `ReadFrom` is Go's
sendfile hook (io.Copy to the conn); goish's body write copies through
userspace, which is performance, not behaviour.

`bodyLocked.Read` was the next defect, and it was visible from the
constant alone: `ErrBodyReadAfterClose` was ported, anchored, and
returned by NOTHING — §2e's "ported, anchored, and never called"
shape, with a behaviour missing behind it. Go's server request body
carries a `closed` flag and answers that error once closed; goish let
the handler keep reading:

    Go     read-after-close n=0 err=http: invalid Read on closed Body
    goish  read-after-close n=5 err=<nil>

The reason it was missing is a real distinction goish had collapsed.
An Eager body's Close is deliberately a NO-OP, because Go wraps a
CLIENT's outgoing body in io.NopCloser and without that no-op a
307/308 redirect cannot replay it. Both rules are correct, of
different bodies: the outgoing one must survive Close, the incoming
one must not. goish has one Body type for both, so the request parser
now marks what it builds, and the closed-body message follows from
that — the two differ in Go too ("read on closed response body" vs
"invalid Read on closed Body"). Pinned by
examples/http_reqbody_close_ref_smoke.rs, checked to fail without it.

`Request.closeBody` and `bufioFlushWriter.Write` close the round of
equivalents. The first is Go's "close it if there is one", called from
the paths that abandon a request; goish calls `__close_shared` at the
same three points, so the helper has no separate work. The second
wraps CONNECT's write side so a tunnel is not stalled inside a
`*bufio.Writer` — and goish's client write path holds no buffered
writer at all, handing every write to the conn directly, so there is
nothing to flush.

`transportRequest.logf` goes with them: it fires only when the
request context carries an unexported key (`tLogKey{}`) holding a log
function, and the only thing that installs one is net/http's own
export_test.go. Nothing outside the package can reach it.

Where the section stands: 37 when it was written this morning, 18 now.
Nine defects fixed, one mislabelled port re-anchored, ten waivers made
visible to the by-declaration count, and the rest read and waived
against the place their behaviour actually lives. What is left is the
big restructured machinery — `conn.{serve,readRequest,close}`,
`chunkWriter.*`, `persistConn.*` — plus the two blocked on §0 A
(`expectContinueReader`) and the client-side upgrade surface.

The same read applied to `mime/multipart` found two missing pieces of
PUBLIC surface, both now ported and pinned by
examples/multipart_rawpart_ref_smoke.rs: `Reader.NextRawPart`, which
returns a part WITHOUT the quoted-printable decoding NextPart applies
(a proxy relaying a part, or a signature over the encoded form, needs
the bytes as sent), and `Part.Read` — Go's Part IS an io.Reader, which
is how a handler copies an upload into a file, and goish exposed only
a `Body` field, so that spelling did not compile.

It also showed why `src/mime/multipart/reader.rs` cannot be anchored
piecemeal, which is worth recording before someone tries again. The
file is an unanchored slim port. Adding a `// go: sdk` anchor to the
two new declarations made it CLAIM multipart.go, and the rule is
all-or-nothing: GOISH018 immediately demanded an anchored counterpart
for the sixteen declarations it does not port (the streaming scanner
Go needs and this design replaces), and GOISH015 demanded a rename to
multipart.rs. The anchors came back out and the Go origin of each is
named in prose instead. Anchoring that file properly — port or waive
all sixteen, then rename — is a unit of its own.

That unit has started from the end that matters. Before waiving
thirteen scanner internals as "the slim design replaces them", the
design was tested where a scanner goes wrong:
examples/multipart_boundary_ref_smoke.rs runs eight bodies through
both implementations — LWSP after the delimiter and after the final
boundary (RFC 2046 5.1 allows it and Go honours it with skipLWSPChar,
so an exact-match scan would find NO parts), LF-only line endings
(which Go accepts and switches to, "a violation of the spec, but
occurs in practice"), a preamble that must be discarded rather than
returned, a part with no headers, and a part with an empty body. goish
matches Go on all eight. That is the evidence a waiver for those
declarations should rest on, and it did not exist until now.

Continuing that read past the scanner found TWO real defects, which is
the answer to whether it was worth doing:

  * `matchAfterPrefix` (multipart.go line 295) decides whether bytes
    that START like a boundary are one — the next byte must be space,
    tab, CR, LF or `-`. goish matched the prefix alone, so a part
    carrying a line like `--Bxyz` was TRUNCATED there and the text
    after it was then read as a header block, failing the parse with
    "malformed header". Data loss first, confusing error second, and
    for an upload the data is the user's file. Fixed on the part scan
    and the preamble scan both; pinned by
    examples/multipart_falseboundary_ref_smoke.rs.
  * A part's headers are CONTINUED lines, not CRLF-delimited ones. Go
    reads them with textproto.ReadMIMEHeader, where a line starting
    with space or tab continues the header before it. goish split on
    CRLF, so every folded header was "malformed" and the whole part
    failed — legal input rejected outright. Fixed, with Go's joining
    rule measured rather than guessed (one space, continuation
    left-trimmed, final value left-trimmed: a wide fold collapses,
    `X: a\r\n ` keeps its trailing space, `X: \r\n b` is "b"), and
    pinned by examples/multipart_headers_ref_smoke.rs, which fails 6
    of 10 without it.

With that read done, the thirteen ARE waived now — each against the
place its behaviour lives and each citing the smoke that would catch a
regression, which is the order this section keeps arguing for: measure
first, fix what the measurement breaks, waive what survives it. mime
is 90/90 by declaration.

Still divergent and recorded rather than fixed: the error TEXT. Go's
malformed-header failures carry textproto's wording ("malformed MIME
header initial line: ..."), goish's say "multipart: malformed header".
The decision to reject matches on every case tried; the message does
not, here or anywhere else in this reader.

`readWriteCloserBody.{Read,CloseWrite}` were the last piece of missing
SURFACE rather than missing machinery. After a 101 the response body IS
the connection, and Go's caller asserts
`res.Body.(io.ReadWriteCloser)` to speak the negotiated protocol.
goish had the carrier — `FramedBody::Upgraded` plus `__take_upgraded`,
used end-to-end by ReverseProxy — and kept it `pub(crate)`, so an
external caller could READ an upgraded body and never write to it.
Half an upgrade, and the half that cannot send a WebSocket frame.
`Body::Upgraded` is the extraction goish spells where Go writes the
comma-ok, and `UpgradedConn` carries Read/Write/Close/CloseWrite;
examples/http_upgrade_client_ref_smoke.rs drives a real 101 against a
socket and matches Go on all three lines. Root gap 18 to 16, net/http
726/742 (97.8%).

Two of these are FIXED BUT NOT PINNED, worth stating plainly.
Reaching either failing path needs a retry — an idle conn closed
between the request being handed over and written — and reproducing
that on demand is a timing race, the kind this tree has been bitten by
in e2e before. `rewindBody` is `pub(crate)`, so an example cannot call
it directly. The peek-error one is worse: whether the RST lands at
write time or at peek time decides WHICH path runs, so a smoke would
assert whichever won that day. `TCPConn::SetLinger(0)` makes the RST
itself deterministic, so what a pin still needs is forced pool reuse
and control of the peek ordering. The Eager and non-reused paths are
covered by the client smokes; these two rest on reading Go's rule and
matching it.

## 2p. `flag` has no Value interface, so no user-defined flag types — FIXED 2026-09-13

Recorded 2026-09-07 while waiving the `*Var` family.

Go's `flag.Var(value Value, name, usage string)` is the package's
extension point: a program implements `String()` and `Set(string)
error` and gets a flag of its own type. `TextVar` is the same idea for
anything implementing encoding.TextUnmarshaler.

goish's FlagSet stores each flag as a `FlagKind` — a CLOSED enum over
the types it knows (Bool, Int, Int64, Uint, Uint64, Float64, Duration,
String, and now Func/BoolFunc). A caller cannot add an arm, so `Var`
has nothing to accept and `TextVar` has no counterpart at all.

`Func` and `BoolFunc`, ported today, cover the half of Var's uses that
are really "call me with the string" — a repeatable option, a counter,
a validator. They do not cover a custom TYPE with its own String(),
which is what `Var` is for and what shows up in a `-help` listing.

Closing it means either an open trait (a `dyn Value` arm on FlagKind,
which is the faithful shape) or accepting that goish's flag types are
fixed. The first is a small change to a hand-written type and belongs
with section 2o's NewFlagSet work, since both touch the same file for
the same reason: this FlagSet was written before the port and its
shape, not its behaviour, is what diverges.

**DONE, with the open trait.** `FlagKind::Custom(Arc<SpinLock<Box<dyn
Value>>>)` is the arm that makes the enum open, and `Var` /
`FlagSet::Var` are the extension point. `Value` had been exported all
along — but only for READING, as `Flag.Value`; there was no way to
supply one.

ONE FORCED DIVERGENCE. Go takes a pointer the caller keeps
(`var v myType; flag.Var(&v, …)`); Rust ownership moves the value into
the FlagSet, so `Var` returns a `ValueHandle` instead. That is the
shape every other goish definer already uses, so it is consistent
rather than novel — but it is a signature difference a porter meets
immediately, which is the good kind.

`IsBoolFlag` is a defaulted method on `Value` rather than a separate
interface: Go's `boolFlag` is an OPTIONAL interface tested with a type
assertion, and Rust has no such test on a `dyn`. So the two fuse, and
`IsBoolFlag` stays on the GOISH018 waiver because there is no Go
declaration mapping to it one-to-one — the behaviour is pinned by the
smoke instead.

Measured against Go 1.25.5, and one row was a divergence until it was
checked: a Value's own `Set` error is WRAPPED as `invalid value %q for
flag -%s: %v`, not returned raw. goish already wrapped it identically —
the smoke asserts the whole string rather than a substring, because
`Contains("empty tag")` would pass on the unwrapped form too.

**`TextVar` DONE too.** Go's is
`TextVar(p TextUnmarshaler, name string, value TextMarshaler, usage
string)`; goish's takes two of those four. Both omissions are the same
one: they police at RUNTIME what Rust settles at compile time. Go
copies `value` into `*p` by reflection and panics if the types differ
("default type does not match variable type") or if `p` is not a
pointer; goish's caller passes a `T` already holding its default, and a
mismatch does not compile. There is nothing left to check and nothing
to copy, which is why `newTextValue` stays waived.

The handle is TYPED — `TextHandle<T>` — so a caller reads their own `T`
back rather than the text form, which is strictly better than the
`dyn Value` `Var` can offer.

Measured against Go 1.25.5, all matching:

    DefValue before parse        "vv"
    Value.String() before parse  "vv"
    after -level vvvv            n=4, String() "vvvv"
    bad value                    invalid value "xyz" for flag -level:
                                 level must be all v

That leaves nothing outstanding in §2p.

AND A SEPARATE GAP FOUND WHILE DOING IT, **fixed in the next commit**:
in Go, every definer routes through `Var`, so all of them get its three
panics — a name beginning with `-`, a name containing `=`, and a
redefinition. goish's ten definers each pushed onto `defs` directly and
validated NOTHING, so `flag.Bool("-x", …)` or a duplicate name
succeeded silently where Go panics.

All eleven now take one path, `FlagSet::__define`. Measured against Go
1.25.5 — the messages are verbatim, and each is written to Output
before the panic, which is what Go's `sprintf` does:

    flag "-x" begins with -
    flag "a=b" contains =
    prog flag redefined: dup      named set
    flag redefined: dup           unnamed set

`sprintf` came off the GOISH018 waiver with them — a fourth pass
finding that waiver naming a declaration the file now has.

The panics run as subprocesses (`flag_definer_panic_probe`), with a
`ok` case that exits 7 as the CONTROL: "panicked" proves nothing if a
definer that rejected everything would pass every row.

A duplicate name is now fatal where it used to be silently accepted, so
the whole declared example suite was run rather than the flag subset —
a second definition of the same flag anywhere in the tree would now
take the process down.

## 2o. `flag` always continues on a parse error — FIXED 2026-09-13

Found 2026-09-07 while porting flag.Uint64.

Go's `NewFlagSet(name, errorHandling)` takes a policy that Parse acts
on (flag.go:1164): ContinueOnError returns the error, ExitOnError
calls `os.Exit(2)` — or 0 for -help — and PanicOnError panics.
`flag.CommandLine`, the set behind the top-level `flag.Parse()`, is an
ExitOnError set, so a Go program with a bad flag STOPS.

goish's FlagSet is hand-written and its `NewFlagSet()` takes neither
argument. Parse always returns the error and the process carries on —
ContinueOnError semantics for everything, including `flag.Parse()`.

Two consequences worth separating. The signature difference is a
compile error, which a porter sees immediately. The behaviour
difference is SILENT: a program that relied on ExitOnError to stop on a
bad flag runs on with a default value, which shows up as odd behaviour
somewhere else entirely. The module header now says so.

Closing it means giving NewFlagSet Go's two parameters and the
ErrorHandling enum, then honouring it in Parse — a public API change to
a hand-written type, so it wants doing deliberately rather than as a
side effect of the next flag port.

**DONE, and the missing `name` came with it.** `NewFlagSet(name,
errorHandling)` now matches Go, `Parse` switches on the policy, and
`CommandLine` is ExitOnError as Go's is. The two omissions were the
same omission: `usage()` carried a comment saying it could only take
Go's unnamed "Usage:" branch and pointed at this very parameter, so
adding the policy fixed the header too.

Measured against Go 1.25.5 rather than read off the source:

    ContinueOnError=0 ExitOnError=1 PanicOnError=2
    ContinueOnError, bad flag  err + message + usage on Output
    -help                      flag.ErrHelp, "flag: help requested"
    PanicOnError               panics with the error VALUE
    ExitOnError                os.Exit(2), or Exit(0) for -h/-help

`flag_errorhandling_smoke` drives the exit cases as a SUBPROCESS,
because a process that stops cannot assert anything about itself and
goish's `recover!()` does not resume, so the panic case cannot be
caught in-process either. Three details worth keeping:

  * a clean parse exits 7, as the CONTROL. "Exited 2" proves nothing if
    the probe always exits 2.
  * ExitOnError and PanicOnError BOTH exit 2, so the exit code cannot
    tell them apart; the runtime's panic banner is the discriminator,
    and one row asserts the ExitOnError case does NOT print it.
  * the probe is in e2e's EXCLUDE list — it exits 7 and 2 by design.

Three names came off the GOISH018 waiver — NewFlagSet, Name,
ErrorHandling — which had been listing declarations goish now has. That
is §2b-iii's pattern for the second time in this file.

Left for §2p: `Var`/`TextVar`, which need the open trait, not a
parameter.

**Two neighbouring defects, found while reading this and FIXED.** Both
were about what a user SEES, and both hid the same way — the error
value was right, so every existing assertion passed:

  * `-h` printed the flag list with no header. Go's defaultUsage writes
    "Usage of <name>:", or "Usage:" unnamed, first. flag_ref_smoke
    drives PrintDefaults directly and asserts it byte for byte, so
    nothing exercised the usage() path -h actually takes.
  * a bad flag printed NOTHING. Go's failf writes the message to
    Output and then the usage listing before returning the error, even
    under ContinueOnError. goish returned an identical error value and
    stayed silent, so a user who mistyped a flag saw nothing at all —
    while flag_ref_smoke, which asserts those very errors, never looked
    at the output buffer.

Both are pinned now (flag_usage_ref_smoke, flag_failf_ref_smoke). The
pattern is worth carrying: a gap can sit BETWEEN two well-tested
things. PrintDefaults was checked byte for byte and the parse errors
were checked by value; what neither covered was the path that joins
them.

## 2c. `regexp` does not keep Go's linear-time guarantee — FIXED 2026-09-14

**Everything from here to "STAGE 1 LANDED" is the ORIGINAL REPORT,
kept because the fix is only legible against it. It is history as of
2026-09-14: goish runs the RE2 construction now, and the numbers below
are the engine it replaced.**

Go's regexp documents that it "is guaranteed to run in time linear in
the size of the input", and keeps it by simulating an NFA (RE2).
goish's was a BACKTRACKING matcher — its own header said so — and was
therefore exponential on nested quantifiers.

Measured 2026-09-05, `(a+)+$` against n 'a's then '!', where Go answers
each in under a millisecond:

| n | goish |
|--:|--:|
| 10 | 5 ms |
| 14 | 95 ms |
| 18 | 1,419 ms |
| 20 | 5,939 ms |
| 22 | 27,338 ms |

Each character roughly doubles the work: n=30 is about two hours. The
answer is correct at every size — this is an unbounded result, not a
wrong one.

The consequence is a caller-visible one. Go's regexp is safe against an
untrusted pattern or subject; this is not, and about twenty-five bytes
hangs the process. Any port that relies on the guarantee — a router, a
log filter, an input validator — inherits a denial of service it did
not have in Go.

Re-measured 2026-09-06 in a RELEASE build, which the first table did
not state: n=14 90 ms, n=16 367 ms, n=18 1,467 ms, n=20 6,194 ms.
Same doubling, so the numbers above are not a debug-build artifact.

The fix is the RE2 construction: compile to an instruction program and
simulate the NFA with a thread list (`regexp/exec.go` plus
`regexp/syntax/`). That is a rewrite of the matcher rather than a patch
to it — goish's regexp is one 2,129-line file against Go's ~10,400
across `syntax/` and three exec engines.

Two cheaper fixes have been considered and neither works:

  A step budget trades an unbounded hang for a WRONG answer on
  patterns Go answers correctly, which is a worse divergence than the
  one it fixes.

  Memoizing the backtracker — what Go's own `backtrack.go` does — does
  not port. Go keys a visited bitmap on `pc*(end+1) + pos`
  (backtrack.go:118-123): two small integers, because compiling to a
  program makes the continuation implicit in the pc. goish's matcher is
  continuation-passing over the AST — `try_match(node, text, pos, caps,
  cont)` where `cont` is the remaining node slice — so the state to key
  on is (node, pos, caps, continuation), and the continuation varies.
  There is no bounded pair to memoize. Getting one means compiling to a
  program, which IS the rewrite.

  Worth knowing either way: Go uses its bounded backtracker only for
  small programs and falls back to the NFA beyond `maxBacktrackVector`,
  so even Go does not treat memoized backtracking as the general
  answer.

**STAGE 1 LANDED 2026-09-13.** `src/regexp/syntax/` exists, with
`prog.rs` — `Prog`, `Inst`, `InstOp`, `EmptyOp`, `EmptyOpContext`,
`IsWordChar`, `MatchRune`/`MatchRunePos`/`MatchEmptyWidth`, `Prefix`,
`StartCond` and the dump — and `parse.rs` carrying parse.go's `Flags`,
which `Inst.Arg` holds. `examples/regexp_prog_ref_smoke.rs` pins 214
rows from `scripts/goref.sh regexp/syntax
tools/gen_regexp_prog_ref.go`.

Nothing is wired to the live matcher. That is deliberate: each stage is
inert until the last one swaps, so the tree never carries two live
engines — the drift §0.B exists to warn about.

The remaining stages, and the reason for this order:

| stage | files | Go lines | state |
|---|---|---|---|
| 2a | `syntax/regexp.rs` (the AST), `syntax/op_string.rs` | ~520 | **done** |
| 2b-i | `syntax/parse.rs` — the character-class layer | ~400 | **done** |
| 2b-ii | `syntax/parse.rs` — the error type, limits, stateless helpers, group tables | ~450 | **done** |
| 2b-iii | `syntax/parse.rs` — the node arena and stack machinery | ~750 | **done** |
| 2b-iv | `syntax/parse.rs` — `Parse` and the text sub-parsers | ~1,100 | **done** |
| 3 | `syntax/simplify.rs`, `syntax/compile.rs` | ~450 | **done** |
| 4a | `regexp/exec.rs` — the NFA machine | ~400 | **done** |
| 4b | the swap: `Regexp`'s public surface onto the NFA | ~200 | **done** |

`parse.rs` opens with GOISH018 and GOISH021 lines naming all 100 of
parse.go's other declarations, in the shape `root_openat.rs`
established: **unported, NOT waived**. That list is stage 2's
checklist, and it shrinks as the port advances rather than sitting
there as a permanent excuse.

**STAGE 2a LANDED 2026-09-13.** The `Regexp` AST, `Op`, `Equal`,
`MaxCap`, `CapNames` and — the hard one — `String()`.
`examples/regexp_ast_ref_smoke.rs` pins 500 rows.

`String()` is harder than it looks, and worth the space: Go does not
print the pattern it was given, it prints a CANONICAL form, and
reaching one takes a whole flag-placement pass. `calcFlags` walks the
tree computing which of `(?i` `(?m` `(?s` must and cannot be active
around each node, finds the conflicts, and inserts spans; `writeRegexp`
renders them. So `(?i)a(?-i)b` comes back as `(?i:a)b`, and
`(?i)[a-z]` as `[A-Za-zſK]` — the fold compiled into the class, the two
extra runes being the long s and the Kelvin sign.

**The trees in the smoke are GENERATED, not written.** The reference
dumps each parsed tree as an s-expression and a script turns that into
the Rust constructors, because goish has no parser yet and hand-writing
91 trees is how this port has already produced one false divergence.

Two structural notes:

  * `Sub` is `Vec<Arc<Regexp>>` and the print-flags map is keyed on the
    Arc's address, because Go's `map[*Regexp]printFlags` is keyed on
    POINTER identity — including the aliasing case, where a node the
    parser reuses is one pointer in Go and one Arc here.
  * `Sub0`/`Rune0` are not ported and carry a GOISH019 suppression
    saying so. They are Go's inline storage for the short cases and
    hold nothing `Sub` and `Rune` do not; a Vec cannot borrow from its
    own struct, so the optimisation does not translate.

One thing the reference already earned. The first probe table used
sparse values and a REAL binary-search bug — `c <= r` written as
`c < r`, which differs only when the subject equals a range START —
turned exactly one row red. Reprobing every range start and end, plus
one either side, took that to thirteen. A perturbation that barely
fails is a table that barely tests.

**STAGE 2b-i LANDED 2026-09-13.** The character-class layer:
`appendRange`, `appendFoldedRange`, `appendClass`,
`appendFoldedClass`, `appendNegatedClass`, `appendTable`,
`appendNegatedTable`, `negateClass`, `cleanClass`, `inCharClass`,
`minFoldRune` and the `ranges` comparator.
`examples/regexp_class_ref_smoke.rs` pins 118 rows.

This half comes before the parser because it is the half that can be
tested without one — rune lists in, rune lists out, no state machine
and no input string. Every `[...]`, `\d`, `\pL` and case-fold in a
pattern is built by it, and the class it produces is the shape a match
ultimately binary-searches.

**A dependency, not a deferral: `\p{Han}` is BLOCKED.** `unicodeTable`
and `canonicalName` read `unicode.Categories`, `unicode.Scripts` and
their Fold twins, and goish's `unicode` does not have those maps — see
the GOISH021 waiver at the top of src/unicode/letter.rs. That is a
unicode-package item that regexp inherits, and stage 2b-ii will have to
either carry it or refuse `\p` explicitly rather than silently.

**And a comment that was wrong before it was committed.** The port
claimed `cleanClass`'s hi-DECREASING tie-break was load-bearing — that
it puts the widest range of a tied lo first so the forward merge
subsumes the narrower ones. The smoke's perturbation deleting the
tie-break came back GREEN, and rather than widen the table, the claim
got checked: two million random classes cleaned both ways, zero
differences. It cannot matter, because the merge tracks a running
maximum `hi`, so a tied pair extends it in whichever order the two
arrive. The tie-break is reproduced because it is Go's; the comment now
says that and says it was measured.

That is the counterpart to the lesson below, and worth stating as its
own rule: a perturbation that comes back green is EITHER a thin table
OR a wrong belief about the code, and the two are told apart by
measuring, not by adding rows.

**STAGE 2b-ii LANDED 2026-09-13.** Everything the parser is BUILT FROM
that does not need the parser to exercise: the `Error`/`ErrorCode` pair
it returns and its sixteen codes, the four limits it enforces
(`maxHeight` `maxSize` `maxRunes` and their unit sizes), the seven pure
functions it calls on nodes — `isValidCaptureName`, `isalnum`,
`isCharClass`, `matchRune`, `appendLiteral`, `cleanAlt`,
`mergeCharClass`, `literalRegexp`, `repeatIsValid`, `checkUTF8` — the
`\d`/`[:alpha:]` group tables from perl_groups.go, and the three
synthetic `RangeTable`s. `examples/regexp_helpers_ref_smoke.rs` pins
251 rows.

Worth knowing from the rows:

  * `Error.Expr` is the REMAINDER at the point of failure, not the
    whole pattern: `checkUTF8("a\xffb")` quotes `\xffb`.
  * `cleanAlt` turns a class covering every rune into `OpAnyChar` and
    one covering everything but `\n` into `OpAnyCharNotNL`, so `[^\n]`
    and `.` become the same node.
  * `mergeCharClass` of two literals differing only in FLAGS still
    makes a class — `a` and `(?i)a` are not the same literal.
  * `asciiFoldTable` is ASCII plus the long s and the Kelvin sign, the
    two non-ASCII runes that fold into it. Without them
    `(?i)\p{ASCII}` would fail to match a K that `(?i)K` matches.

`perlGroup` and `posixGroup` are linear scans where Go has map
literals. Six and twenty-eight entries, reached once per `\d` in a
pattern; the lookup is not where either spends its time.

**A padding bug the reference caught, worth stating once for every
future smoke:** Go's `fmt` measures a string's `%-8s` width in RUNES,
not bytes — "For strings, byte slices and byte arrays … width is
measured in runes." Padding by byte length puts `"é"` one space short.
Six rows red, and every earlier smoke got away with it only because
every input was ASCII.

**STAGE 2b-iii LANDED 2026-09-14.** The half of the parser that builds
the tree: `push`, `maybeConcat`, `literal`, `op`, `repeat`, `concat`,
`alternate`, `parseVerticalBar`, `swapVerticalBar`, `collapse`,
`factor`, `leadingString`/`leadingRegexp` and their removals, over a
node arena. `examples/regexp_parser_ref_smoke.rs` pins 223 rows.

**Why an arena.** Go's parser works on `*Regexp` and leans on that
being a pointer three ways: it MUTATES nodes in place while they are
reachable from the stack and from another node's `Sub`; it keeps a FREE
LIST and recycles them; and it keys `height` and `size` on the pointer.
`Arc<Regexp>` gives none of the three, so the parser works in an arena
where a `u32` index is the pointer, and the public tree is materialised
from it once at the end.

The free list is not an allocation detail that could be skipped.
`numRegexp` counts real allocations, and `checkSize`/`checkHeight`
start tracking only once it crosses a threshold — so a port that never
recycles counts higher, starts tracking sooner, and can report
`ErrLarge` on a pattern Go accepts. Every row carries `numRegexp` for
exactly that reason; deleting the recycling turns 22 rows red.

**Both sides are driven through the same SCRIPT of operations**, with
the stack dumped after each, so a divergence names the operation that
caused it rather than the pattern that eventually showed it.

Two perturbations came back green and both were the table, not the
code — and finding out took building the missing inputs, not assuming:

  * `factor`'s round-2 restriction (factor a common leading regexp only
    if it is a character class or a FIXED repeat of one) needed an
    alternation whose branches share a non-class prefix. `a*x|a*y` must
    NOT factor; `[a-z]{2}x|[a-z]{2}y` must. 0 red -> 5.
  * `swapVerticalBar`'s `re1.Op > re3.Op` swap needed a literal and a
    class as adjacent alternatives. Without the swap,
    `mergeCharClass`'s OpLiteral arm reads `src.Rune[0]` out of a
    CLASS, where it is a range start and not a rune — the perturbed
    build PANICS. Green -> panic.

The first attempt at the alternation scripts was worse than thin, it
was VACUOUS: pushing an `opVerticalBar` marker directly leaves it on
the stack, and `alternate` scans down and stops at it, so `factor`
never saw more than one branch. The fix was to script Go's real closing
sequence — `concat(); if swapVerticalBar() { pop }; alternate()` —
which is what `parse`'s end and `parseRightParen` both write out.
Popping the marker is what leaves the alternatives adjacent.

**STAGE 2b-iv LANDED 2026-09-14 — THE PARSER IS COMPLETE.** `Parse`,
`parseRepeat`, `parseInt`, `parsePerlFlags`, `parseEscape`,
`parseClassChar`, `parsePerlClassEscape`, `parseNamedClass`,
`appendGroup`, `parseUnicodeClass`, `parseClass`, `parseRightParen`,
`nextRune`, `unhex`, `canonicalName` and `unicodeTable`.
`examples/regexp_parse_ref_smoke.rs` runs 168 patterns under three flag
sets — Perl, POSIX and Literal — and compares Go's canonical
`String()`, the capture count, and the exact error for the ~40 that do
not parse. 506 rows.

`String()` is the right thing to compare rather than a tree dump: it is
CANONICAL, so a wrong flag placement, a missed factoring and a
mis-parsed class all show up in it, and stage 2a pinned it
independently.

**ONE REAL GAP, and it is `unicode`'s, not regexp's.** `\p{Han}`,
`\p{L}` and every named group ERROR with `invalid character class
range` where Go resolves them. `unicodeTable` reads
`unicode.Categories`, `unicode.Scripts` and their Fold twins, and
goish's `unicode` has neither those maps nor the tables behind them —
`tables.rs` exports `Mn` and `Zs` and nothing else. `\p{Any}` and
`\p{ASCII}` work, because their tables are built in parse.go itself.

It is a refusal, not a wrong match: a pattern using one fails to
compile rather than silently matching the wrong runes. The smoke
asserts goish's answer in a GAP block that records Go's beside it, so
the two rows GO RED the day the unicode tables land — which is the
reminder to move them back into the shared corpus.

**Go's `recover` has no counterpart.** Go's limit checks
`panic(ErrLarge)` and a `defer`/`recover` at the top of `parse` turns
it into an error. goish's `recover!()` does not resume, so the checks
RETURN their code and it propagates like any other error. Same errors
reach the caller; what differs is that the propagation is visible.

**A harness bug worth more than the perturbations it hid.** Three of
five perturbations came back green, and one of those was not a thin
table at all — the edit had 16 spaces of indentation where the file has
12, so `str.replace` silently did nothing, the rebuild was a cache hit,
and the smoke passed. A perturbation that never applies is
indistinguishable from one that does not bite, and it sends you
widening a table that was already sufficient. Every perturbation script
now asserts its match count. With the edit actually applied, that one
turns 5 rows red.

The other two were genuinely thin, and both wanted inputs the corpus
had no reason to contain: `a{01}` for `parseInt`'s leading-zero
refusal, and a twenty-four-digit count for its overflow clamp — because
`a{99999999999}` exceeds 1000 either way, and only a value long enough
to WRAP distinguishes the clamp from its absence.

**STAGE 3 LANDED 2026-09-14 — THE AST NOW COMPILES TO A PROG.**
`Simplify`, `simplify1`, and the whole of compile.go: `patchList`,
`frag`, `Compile` and the twelve `compiler` methods.
`examples/regexp_compile_ref_smoke.rs` takes 119 patterns through
parse → simplify → compile and pins five rows each — the parse, the
simplification, the program's shape, the prefix and start condition,
and the full instruction dump. 591 rows.

**Everything §2c needs is now in place except the engine.** A match is
about to become a walk over integer program counters, which is what
makes the memo key `(pc, pos)` — two small integers — and leaves the
backtracker's exponential blowup nowhere to live.

The one piece of cleverness is Go's patch list, and its comment earns
its place: "Because the pointers haven't been filled in yet, we can
reuse their storage to hold the list. It's kind of sleazy, but works
well in practice." A fragment is compiled before its successor exists,
so the unfilled `Out`/`Arg` fields ARE the worklist, each holding the
index of the next hole. `head == 0` terminates it, which is safe only
because every program starts with a `fail` at index 0 — nothing ever
wants to point at its output.

Six perturbations, and three started thin in the same way: the corpus
had one shape where the code has two branches.

  simplify1 idempotence, `(?:a+)+` -> `a+`        9 red
  cap's NumCap high-water mark                   22 red
  star's nullable `(f1+)?` fix (issue 46123)      4 -> 18
  rune's FoldCase clearing                        2 -> 11
  quest's non-greedy Out/Arg swap                 1 -> 11
  loop's non-greedy Out/Arg swap                  6 red

The three that grew wanted, respectively: a nullable star body in more
than one shape (`(a|)*`, `((a)?)*`, `(a*b*)*`); a rune with NO fold
orbit under `(?i)`, since only then is the flag cleared and `InstRune1`
chosen; and a non-greedy quantifier over something other than a bare
literal. In each case the first number was the corpus's fault.

**STAGE 4a LANDED 2026-09-14 — THE ENGINE RUNS, AND THE DoS IS GONE.**
`queue`, `entry`, `thread`, `machine`, `lazyFlag`, `add`, `step`,
`match`. `examples/regexp_exec_ref_smoke.rs` runs 73 (pattern, subject)
pairs END TO END — parse, simplify, compile, execute — under both match
semantics, against Go's PUBLIC `FindStringSubmatchIndex`. 151 rows.

Measured, on the pattern this section opened with:

| n | backtracker (release) | NFA (release) |
|--:|--:|--:|
| 14 | 90 ms | — |
| 18 | 1,467 ms | — |
| 20 | 6,194 ms | — |
| 22 | ~27,000 ms | **42 µs** |
| 200 | ~2 × 10^57 ms | **334 µs** |

**The bound is ASSERTED, not timed.** A wall-clock assertion is a flake
waiting to happen on shared CI, so the machine counts its `add` calls
instead and the smoke checks a RATIO: doubling the input may at most
triple the work. The counts come out 154, 304, 604, 1204, 2404 for n =
25, 50, 100, 200, 400 — exactly `6n + 4`. A backtracker fails that
assertion by a factor of 2^100.

And the guarantee is one line of `add`: it refuses to enqueue a pc
already on the queue. So each queue holds at most one entry per
instruction, each position does at most O(len(prog)) work, and no input
can push past it. Deleting that refusal does not merely slow the smoke
down — the perturbed build BLOWS THE STACK.

Not ported, and safe not to be: Go's `onepass` and `backtrack` engines
and its literal-prefix fast path. All three are optimisations over this
one, which is why Go falls back to it; they change how fast an answer
arrives, not what it is, and the smoke compares answers.

Five perturbations:

  add's pc dedup                   stack overflow (the blowup itself)
  step's first-match truncation    7 red
  lazyFlag's word-boundary sense   4 red
  step's longest-mode cutoff       2 red
  (and the REDOS ratio assertion, which the first one also fails)

WHAT REMAINED at this point was 4b: `Regexp`'s public surface still
called the old backtracker. The engine was complete and pinned; the
swap was a separate change because it touches every caller in the tree.
It landed the same day — see below.

**STAGE 4b LANDED 2026-09-14 — THE SWAP. §2c IS CLOSED.**

`Regexp` now holds a compiled `Prog` and runs the NFA. `Compile` parses
with `syntax.Parse`, simplifies, and compiles; `find_from` — the one
function every search driver in the file routes through — builds a
machine and runs it. The AST, the recursive-descent parser and the
continuation-passing backtracker are DELETED: 1,363 lines out, about
200 in. Two engines is what §0.B exists to warn about, so there is one.

Measured through the PUBLIC api, release build:

| n | before | after |
|--:|--:|--:|
| 14 | 90 ms | 46 µs |
| 18 | 1,467 ms | 35 µs |
| 22 | 27,338 ms | **41 µs** |
| 2000 | (heat death) | **3.4 ms** |

**The evidence the swap is CORRECT and not merely fast** is
`examples/regexp_fold_diff.rs`: 7,254 rows byte-exact against real Go —
30 patterns × 53 inputs for match and submatch, plus 12 × 14 × 6 for
FindAll, FindAllIndex, FindAllSubmatch and Split. It covers the `(?i)`
scope rules, class folding before negation, and the two empty-match
rules in the successive-match scan. It passed unchanged on the new
engine.

Three things came free with the swap, because they were Go's parser all
along and goish's had none of them:

  * Compile's error is now Go's text — `error parsing regexp: <code>:
    \`<expr>\`` — where goish invented its own.
  * `Regexp.Longest()` exists. The leftmost-longest branch was in the
    machine's `step` from stage 4a and unreachable until now.
  * `(?U)` and `(?)` compile, because Go accepts them.

That last one broke a test, and it is the interesting failure of this
stage. `regexp_fold_diff` asserted that `(?U)a`, `(?)a`, `(?-)a` and
`(?=a)` are all REJECTED — an assertion written against the OLD
parser's limits. Measured against Go 1.25.5: it accepts the first two
and rejects the last two. The example's own comment had already
anticipated this once ("`(?s)`, `(?m)` and `(?P<name>...)` used to be
on this list… asserting that they are REJECTED would now be asserting a
bug") and it happened again to `(?U)`. The two that Go accepts are now
asserted POSITIVELY, including what `(?U)` does: `(?U)a+` against
`"aaa"` matches `"a"`.

Sweep: 133 examples downstream of regexp, all green.

Stage 2a repeated the lesson twice, which is why it is written down
here rather than left in a commit message. `sub.Op > OpCapture` → `>=`
(the precedence rule) started at 2 red and reached 11 once every Op
either side of that boundary was quantified in the table.
`must&subCant || subMust&cant` with the second half deleted started at
2 and reached 7 once the table had patterns whose CANT comes before
their MUST — `k(?i)k`, not only `(?i)k(?-i)k`. Both times the first
number was the table's fault, not the code's.

## 2d. Three recursions stand between the JSON limit and Go's

**Worked 2026-09-06.** This section used to say the fix was Go's
design — an explicit state stack instead of recursion — "after which
both can carry Go's number". That was measured and is half right; the
half it missed is the useful part.

Doing it turned up a chain, each link only visible once the one before
it was gone. All measured in a DEBUG build (what `make e2e` runs) on
an 8 MiB goroutine stack:

| recursion | ceiling | state |
|---|--:|---|
| `parse_value` into `parse_array`/`parse_object` | 8000 without a pivot, 8500 with | **fixed** — explicit frame stack, `maybe_grow` pivot removed |
| `Value::clone` via `Unmarshal`'s `T::from_value(&raw)` | between 8000 and 9000 | **avoided** — `from_value_owned` moves the tree instead |
| `encode_value` through `encode_array`/`encode_object` | — | **fixed** — work stack; those two removed. Serves `Compact`, `Indent`, `Value::String` |
| `encode_reflect`, which is what `Marshal` actually uses | 3500 survives, 4000 faults | **open**, and the BINDING one |

The encoder was never mentioned in this section, and it is less than
half the parser's ceiling. So `maxNestingDepth = 2000` was never really
about the parser: the margin it buys is about 1.8x against the
encoder, not the 4x the old note claimed against the parser. That
number was measured on the wrong path.

Raising the limit to Go's 10000 needs `encode_reflect` iterative too.
Note which encoder that is: `Marshal` is generic over
`reflect::Reflect` and never calls `encode_value`, so making the
`Value` encoder iterative — worth doing, and done — moved the ceiling
not at all. Finding that out cost a fourth pass.

One thing to settle before a fifth. `maxNestingDepth` guards the
PARSER only; `Marshal` has no depth check, and neither does Go's —
Go's encoder has `startDetectingCyclesAfter = 1000`, which is cycle
detection, not depth. So the design matches and the consequence does
not: Go's goroutine stacks grow, goish's are fixed at 8 MiB, so Go
survives depths that fault here at about 3750.

That bounds the exposure and it is why this is not urgent. Parsing
caps at 2000 and marshalling survives 3500, so a parse-then-marshal
round trip is safe by construction. Reaching the encoder's ceiling
takes a value built deliberately in code, not one that arrived over a
wire. A fifth pass should make `encode_reflect` iterative — NOT add a
depth limit Go does not have, which would refuse documents Go
encodes.

**FIFTH PASS, 2026-09-14: the encoder's ceiling was not the stack at
all, and the entry above was measuring the wrong failure.**

Re-measured before touching anything, which is the only reason this
was found. `Marshal` of the nested value did not fault at 4000 as
recorded — it died at 2550..2600 with `mcentral: span table
exhausted`, an ALLOCATOR error, and identically in a release build.
A stack ceiling moves between debug and release; this one did not,
because it was never the stack.

The cause is `reflect::Value::MapIndex`, which returns `v.clone()` — a
DEEP copy of the whole remaining subtree — so a walk that recurses
through it clones the rest of the document at every level. Quadratic.
Measured, release build, on a document 14 KB long:

| depth | before | after |
|--:|--:|--:|
| 200 | 7.8 ms | 151 µs |
| 400 | 30.6 ms | 300 µs |
| 800 | 128 ms | 798 µs |
| 1600 | 499 ms | 1.5 ms |
| 2400 | **1,127 ms** | **2.4 ms** |
| 2600 | allocator exhausted | 2.6 ms |
| 20000 | — | 19.6 ms |

Four times the work for twice the depth, before; linear after, and
2400 is 460x faster.

**This was reachable from untrusted input.** The parser caps at 2000,
so a 12 KB document nested 1999 deep parses fine — and marshalling it
back, which any proxy or re-serialiser does, cost about a second of
CPU and millions of live allocations. Go's `MapIndex` returns a
three-word header, so the same code is linear there.

`Index` and `Field` clone the same way. All three now have borrowing
twins — `__index_ref`, `__map_index_ref`, `__field_ref`, plus
`__map_keys_ref` — and the encoder uses them. The cloning versions
stay: they are Go's signatures, and a caller that wants an owned value
needs them.

**This is the THIRD instance of the same bug.** `Unmarshal`'s
`T::from_value(&raw)` was the first (fixed with `from_value_owned`),
`encode_value`'s owned work stack the second (an 8x loss from ONE root
clone). A cloning accessor inside a tree walk is evidently the shape
this codebase reaches for, and only the third one was quadratic rather
than linear.

**So the fix was followed by a directed sweep, and it found a FOURTH —
in `fmt`.** `write_reflect_value` is what `%v` and `%+v` reach for any
type deriving Reflect, and it is a third recursive walk over the same
tree using the same three cloning accessors. Also quadratic:

| depth | before | after |
|--:|--:|--:|
| 200 | 8.5 ms | 299 µs |
| 400 | 42.1 ms | 556 µs |
| 800 | 143.2 ms | 1.0 ms |
| 1600 | **583.7 ms** | **1.8 ms** |
| 20000 | — | 28.2 ms |

`fmt.Printf("%v", v)` on a deep structure — logging one — cost half a
second for 11 KB of output.

It had NO deep-value coverage at all, and the reason is worth keeping:
`FmtBuf` is private, so no example could reach the reflect printer.
`fmt::__reflect_fmt_bytes` is the hook that makes it testable, and
`json_encode_depth_smoke` now pins all THREE walks — `encode_value`,
`encode_reflect` and the printer — because they are three different
routes over one tree and covering one covered neither of the others.

The lesson for the next one: when a bug turns out to have three
instances, the sweep for the fourth is worth doing IMMEDIATELY, while
the pattern is exact enough to grep for. `Index`, `MapIndex` and
`Field` are the names; any recursive walk calling them is a candidate.
The remaining callers are flat field reads on small structs
(`crypto/x509`'s ASN.1 decoders), which is the same call in a shape
where it costs nothing.

Where that leaves the limit. `encode_reflect`'s ceiling is now
12000..13000 in a debug build — a 4.7x improvement, and the failure is
the stack again, where this entry expected it. Go's `maxNestingDepth`
is 10000 and goish's is still 2000, so raising it is now POSSIBLE
without making `encode_reflect` iterative. It is not done here, for
two reasons: the margin at 10000 would be 1.2x, and doing two things
at once means a CI failure cannot be attributed. The iterative encoder
is still the right fifth-and-a-half pass, and it buys the headroom
that makes 10000 comfortable rather than tight.

`examples/json_encode_depth_smoke.rs` now covers BOTH encoders. It
only ever covered `encode_value`, and `Marshal` never calls it — which
is exactly how a quadratic walk sat there unnoticed. The new rows
marshal at 2000 and 10000; restoring the clone makes them blow the
stack.
Verified that it is genuinely the only one left: with parse and clone
both handled, depth 10000 parses and 10001 is refused, exactly Go's
behaviour — and then the marshal of that tree faults. Parsing a
document that crashes on re-encode is a denial of service with an
extra step, so the limit stays until the encoder is done.

Not a constraint, checked so nobody re-checks it: dropping a deep
tree. Rust's Drop glue recurses too, but its frames are small — 2000,
5000 and 10000 all drop cleanly.

`jsontext` keeps Go's 10000 and is unaffected; its decoder was already
iterative.

## 2e-i. Ported, anchored, correct — and NOT REACHABLE (2026-09-13)

A sharper variant of §2e below, found by sweeping
`#![allow(dead_code)]` off all 34 files that carried it.

`flag::Arg`, `flag::Func`, `flag::BoolFunc` and `flag::Uint64` are
ported, anchored to their Go lines, counted by `port_coverage` — and
were missing from `flag/mod.rs`'s `pub use` list. `flag::Arg(0)` did
not compile. Proven by writing the call, not inferred from the export
list.

Two things make this worth its own entry:

`port_coverage` cannot see it. It matches a Go `func` against an `fn`
of the same name ANYWHERE in the package directory, so a declaration
that no user can reach counts exactly like one they can. The tier
reports 100% and the API is not there.

AND THE SMOKES WERE GREEN. `flag_func_ref_smoke` and
`flag_uint64_ref_smoke` exist and pass — they call `fs.Func(…)`,
`fs.Uint64(…)`, `fs.Arg(0)`, the METHODS on a FlagSet. The feature was
tested; the package-level surface never was. A smoke proves the unit
works, not that anything can reach it.

`exported_api_smoke` now calls all four through `goish::flag::`, so
the failure mode is a compile error rather than a silent absence.

**THE SWEEP GENERALISED, and found three more.** `dead_code` only
catches an unreachable item when NOTHING uses it, so anything used once
inside its own module stays invisible. Comparing each package's
declarations against its `pub use` list directly finds those too — 9
private submodules with Go-shaped `pub` items missing from the
re-export list. Probing each (writing the call, not reading the list)
left three real:

  `unicode::CaseRanges`   Go's `var CaseRanges = _CaseRanges`. The
                          table was present with no name to reach it.
  `testing::B`            only reachable as `testing::benchmark::B`,
                          where Go writes `*testing.B`.
  `testing::RunTests`     plus `InternalTest`, its parameter type —
                          exported TOGETHER, since a function whose
                          argument type cannot be named is not callable.

The `crypto::cipher` interfaces (AEAD, Block, BlockMode, Stream) came
up as candidates and are FINE — reachable by another route the sweep's
regex missed. Probing is what separated them; the list alone would have
produced four unnecessary edits.

**AND ONE DELIBERATELY NOT FIXED.** `testing::MainStart` is a `pub fn`
with a Go anchor and is not exported — but its `deps` parameter is a
`pub(crate) trait`, so exporting the name would produce a function no
caller could ever satisfy. That is this same defect wearing a fix's
clothes. goish's test entry point is the `#[goish::test_main]`
attribute, so `MainStart` being internal is a design decision. The
smoke says so, at the point where it would otherwise be tempting.

WHAT THE SWEEP COST AND RETURNED, since the same trick paid much better
one commit earlier: 34 files, 57 dead items, and only 6 were fields or
constants — the shape that has hidden real defects before. Of those:
`TLS_FALLBACK_SCSV` in handshake_messages.rs was a DUPLICATE of the one
in cipher_suites.rs that both server handshakes actually read (a change
to one would silently not reach the check); `Parser::depth` in
encoding/json was vestigial, and its doc still claimed "this parser
recurses, so the same bound is … the only thing standing between a
document and the stack" when the parser is an explicit stack and the
field was never read — a field that does nothing, described as the only
thing preventing a stack overflow, is how a later reader deletes the
check that works. `maxInt64` and `STACK_SIZE` are deliberate and
documented as such (the second is `#[deprecated]`), and the
`omithttp2.rs` cluster is the HTTP/2-omitted stub by design.

So: no security defect this time. `allow(dead_code)` is mostly
load-bearing in a port — Go declarations carried for symmetry with
consumers not yet written — which is the opposite of
`allow(unused_variables)`, where two of three files sat on a real bug.
Worth knowing before the next sweep.

## 2e-iii. Declared twice where Go declares it once, 2026-09-14

Three findings in two days had the same shape and each was found by
hand: a fourth `hasPort` deciding the SNI a TLS client sends, a third
walk down to a certificate's SubjectPublicKeyInfo, and — once those
were fixed — the question of what else. `scripts/dup_impl_check.py`
asks it mechanically: **which free functions does goish declare more
often than Go does?**

The comparison has to be against Go's own count, because plenty of
names are legitimately per-package — `GenerateKey` exists once per
algorithm in both trees. Two false-positive classes were worth fixing
before the tool was worth running, and both are recorded in it:

  * Go generics. `func pHash[H hash.Hash](` did not match a `^func
    NAME(` regex, so `pHash` read as a goish duplicate when Go declares
    it twice.
  * Go's `vendor/`. The stdlib genuinely vendors golang.org/x/net,
    goish ports those files, and their anchors point at them. Skipping
    it reported `hasPort`, `canonicalAddr`, `idnaASCII` and `isASCII` as
    duplicates when every copy is an anchored port — including the
    `hasPort` that had just been FIXED.

With both fixed the list is 9, and two of them are key derivation.

### Two TLS 1.2 PRFs, and two HKDF-Expand-Labels

| Go declares | goish declared |
|---|---|
| `prf12` once, in `crypto/tls/prf.go`, delegating to `tls12.PRF` | `prf.rs::prf12` (the port) **and** `record.rs::prf12`, hand-rolled, SHA-256 only |
| `ExpandLabel` once, in `crypto/internal/fips140/tls13` — `key_schedule.go` has no such function | `fips140/tls13::ExpandLabel` (the port) **and** `key_schedule.rs::ExpandLabel`, hand-rolled |

Between them these derive the TLS 1.2 master secret and key block, and
every TLS 1.3 traffic key, IV and Finished key. A disagreement is a
handshake that negotiates different keys depending on which half of the
library got there first.

**They agreed.** That is the ordinary outcome for this finding — all
three of the earlier duplicates agreed with their originals too — and
it is why the value here is the guarantee rather than a fix. Two
implementations of one rule drift, and the copy a later edit corrects
may not be the copy the live path calls.

**Except in one place, where the copy had already lost something.** Go's
`ExpandLabel` refuses `len("tls13 ")+len(label) > 255` and
`len(context) > 255`, with a comment explaining at length why it chose
a panic over a randomized return. `key_schedule.rs`'s copy wrote both
lengths with `as byte`, so a 250-byte label silently wrapped its length
prefix and produced an HkdfLabel no peer would agree on. Not reachable
through the protocol — labels are fixed constants and context is a
transcript hash — so duplication, not a vulnerability. But that guard
is exactly the kind of thing a second copy loses, and nothing would
have told anyone.

**How they were retired.** Both smokes PREDATE the deletions, which is
the point:

  * `tls_prf_dup_smoke` — 315 vectors from Go's own `tls12.PRF`, via
    `scripts/goref.sh crypto/internal/fips140/tls12`, run through both
    implementations. 630 green checks.
  * `tls13_expandlabel_dup_smoke` — 648 vectors from Go's own
    `tls13.ExpandLabel` over SHA-256 and SHA-384, same method. 1,296
    green checks.

Neither table grades one goish copy against the other; both are graded
against Go, because two copies wrong the same way would otherwise pass.
Perturbations: swapping the `label||seed` order in record.rs turns 120
of its 315 rows red, and xor-ing the context-length byte in
key_schedule.rs turns all 648 of its rows red.

Both hand-rolled bodies are gone, along with a now-dead `hmac_sha256`
helper; what remains at each site is a shape adapter, and the tables
stay to pin those.

### The rest of the list, and why it is quiet

`ctEq` in `record.rs` looks like the same thing and is not: Go's single
`ctEq` is bigmod's, over `uint`, and record.rs's is a documented
byte-wise 255/0 adapter over the ported `subtle` primitive — Go writes
the same fold inline as `subtle.ConstantTimeCompare(...) & int(...)`.
`LEUint64`/`LEPutUint64` are the same edwards25519 shape as
`ConstantTimeByteEq` — Go's `scalar.go` and `fe.go` call
`byteorder.LEUint64` and goish has two private copies — and here the
copies are RIGHT. The ported `LEUint64` takes an owned `slice<byte>`,
so delegating from the `&[byte]` these hold would allocate on every
call, inside field-element decoding and scalar multiplication. The body
is `u64::from_le_bytes`, which cannot drift from
`binary.LittleEndian.Uint64`. Both now say so at the site, so the next
run of the tool does not re-chase them — which is the other thing this
kind of list needs: a recorded answer, not just a recorded finding.
`ParseBool`, `NewScanner`, `needsEncoding` are unrelated functions that
share a name.

`ConstantTimeByteEq` I first wrote off as another shim, and it was not
— which is worth recording, because the check that caught it was
opening the third file rather than trusting the pattern. goish's two
`subtle` copies are Go's two; the extra was a PRIVATE hand-rolled body
in `edwards25519.rs`, where Go's `tables.go` calls
`subtle.ConstantTimeByteEq`. Its two callers select a point from the
precomputed table during scalar multiplication, so constant time there
is what stops the private scalar leaking through timing. The body was
the same expression, so no defect — a third copy of a constant-time
primitive is still the last place to keep one. It now delegates, with
an exhaustive 65,536-pair table (every `(x, y)` byte pair, all three
implementations) rather than a sample.

So: 9 candidates, 2 real, and the tool paid for itself on its first
run. Re-run it after any port that adds a helper — the duplicate is
cheapest to find while it is still one name.

### The ones the tool cannot see, and the fourth duplicate

`dup_impl_check.py` matches on NAME, so it misses every duplicate that
was given a goish-flavoured one — which is most of `record.rs`, whose
functions are called `decrypt_record`, `derive_aead_key_material`,
`compute_mac`. The same question has to be asked by hand there: for
each of its fifteen remaining functions, what ported code already does
this?

The first answer was `extract_padding`. `conn.rs` carries the anchored
port of `extractPadding` (conn.go:281-314); `record.rs` had a second
copy — of the CBC padding check, in the file whose 2026-09-04 audit
found a padding oracle.

They were not even written alike. Go computes `t` in `uint` and
broadcasts with `byte(int32(^t) >> 31)`, narrowing to 32 bits
deliberately; `conn.rs` mirrors that. `record.rs` used `i64` and
`>> 63`. Both are right, because `^t` is either all-high-bits-set or a
small positive in every reachable case so bits 31 and 63 agree — and
"happens to agree" is precisely what a second copy leaves you relying
on.

`tls_extractpadding_dup_smoke` settles it with 1,041 vectors from Go's
own `extractPadding`, which is unexported — `scripts/goref.sh
crypto/tls` runs the reference test INSIDE a writable GOROOT copy so it
can be called at all. The grid is the branch structure, not random
input: all 256 one-byte payloads, well-formed padding of every length
1..258, each with a byte corrupted at the front and in the middle,
paddingLen exceeding the payload, and the exact-fit case.

Two perturbations, and the pair is the interesting part. Dropping a
step of the `good &= good << 4` fold turns **511** rows red — the table
is broad. Narrowing the scan bound from 256 to 255 turns **exactly one**
row red: `bad_first_256`, the only payload where a corrupted byte sits
at offset 255. That is not a sparse table (cf. §2b's "one red row means
the probe grid is too thin"); it is the single input that can
distinguish the two bounds, and the grid contains it because it was
built from the boundaries rather than sampled. Worth remembering that
the two diagnoses look identical from one perturbation and different
from two.

Collapsed, with the cost stated: delegating copies the record payload
once per record. That is acceptable HERE and nowhere hotter — this is
the invented handshake's path, not `tls::Dial`'s, the AES decrypt
beside it dwarfs the memcpy, and §1 has the file slated for retirement.
Contrast `LEUint64` above, where the same delegation would have
allocated per call inside scalar multiplication and the copy stays.

### A FIFTH defect in record.rs: the Lucky13 countermeasure was absent

Continuing the same per-function question found `compute_mac`, a second
copy of `cipher_suites.go`'s `tls10MAC` — and this one had lost
something, the way `ExpandLabel`'s copy had lost its length guard.

Go's `tls10MAC` ends:

    res := h.Sum(out)
    if extra != nil { h.Write(extra) }

`conn.go:443` passes the stripped PADDING as `extra`, so the hash is fed
the same number of bytes — and does the same number of
compression-function blocks — whatever padding length was removed.
Without it the MAC's cost tracks the padding, which is the timing
signal Lucky13 reads to turn CBC decryption into a padding oracle.

`record.rs`'s `compute_mac` had **no `extra` parameter at all**. It
hashed only the plaintext, whose length is exactly what the attacker is
trying to learn.

Two things make this worth writing down beyond the fix.

**It was already written down, in the smoke the same audit produced.**
§1's 2026-09-04 pass fixed the padding ORACLE in `decrypt_record` —
three distinguishable errors folded into one constant-time branch — and
its `tls_padding_oracle_smoke` (514ff76, the same day) closes with:

> What this does NOT establish is constant TIME. `extract_padding` is
> Go's, examining a fixed 256 bytes rather than stopping at the claimed
> length, but the MAC is still computed over a variable-length payload,
> which is the other half of Lucky13.

So nobody missed it. It was named, in the right file, on the right day,
and left — which is §2b's REMOVAL-CONDITION pattern and not an audit
gap at all: a comment that states exactly what would make it false, and
then outlives the ten minutes it would have taken. Grepping for
sentences of that shape has now paid twice.

**`conn.rs` had it right all along.** The record layer `tls::Dial`
actually runs passes `payload.slice(n + macSize, payload.Len())`,
mirroring Go. So this is a divergence between goish's two record
layers, and it is the fourth finding this week whose whole content is
"there were two of these". Scope is the same as §1's other invented-client
findings: the only non-example caller is the invented TLS 1.2
handshake, which refuses outright unless the caller passes
`skip_verify`.

Fixed by deleting the copy — `compute_mac` now builds `macSHA1` and
calls the anchored `tls10MAC`, gaining the `extra` parameter in the
process, and `decrypt_record` passes the padding exactly where Go does.

**What pins it, and what does not.** No timing measurement: a timing
test on a shared machine is a coin flip, and this tree does not run
stress tests. `tls_lucky13_smoke` pins the STRUCTURAL property the
countermeasure rests on — that the number of bytes handed to the hash
does not move with the padding length — over every padding length from
1 to 236 (beyond which the block cannot still hold a MAC, which is
`__mac_split`'s stated precondition). The two spans are the live
expressions: `decrypt_record` calls `__mac_split` rather than repeating
the arithmetic, so the test is not grading a copy. Perturbing the extra
span to empty turns all 474 checks red.

It cannot see someone changing `tls10MAC` itself to ignore its `extra`
argument — but that is one anchored function, and it is conn.rs's
guarantee too.

`record.rs` is 975 lines now, from 1,145 — and the drop understates it,
since each collapse traded a hand-rolled body for a longer explanation
of why it is gone.

### record.rs, all fifteen functions: the sweep is finished

Every function in the file has now had the same question put to it. The
answers, so the next reader does not redo it:

**Collapsed onto the anchored port** (each behind a Go-generated table,
written before the deletion): `decode_x509_rsa_pubkey`, `prf12`,
`extract_padding`, `compute_mac`. The last two were defects, not just
duplication — the padding check was fine but unverified, and
`compute_mac` was missing Lucky13 entirely.

**Verified equivalent and KEPT, because they are specialisations rather
than copies**: `derive_master_secret`, `derive_key_material`,
`derive_aead_key_material`. These are `keysFromMasterSecret` with one
cipher suite's parameters fixed, and the PRF underneath them now
delegates, so what remains is the RFC 5246 §6.3 span layout. Checked
against Go's slicing order rather than assumed — clientMAC, serverMAC,
clientKey, serverKey, clientIV, serverIV, which with (20,16,16) gives
0/20/40/56/72/88 over 104 bytes and with (0,16,4) collapses to
0/16/32/36 over 40. The seed for the key block is
serverRandom||clientRandom, the reverse of the master secret's order;
that asymmetry is real in the RFC and not a transcription slip.

**Checked clean**: `encode_record`, `hmac_sha1`, `ctEq` (a documented
255/0 adapter over the ported `subtle` primitive, not a rival to
bigmod's `ctEq`), `encrypt_record`, `encrypt_record_aead`,
`decrypt_record_aead`, `read_record`. Two details in the AEAD path are
worth not re-deriving: the nonce comes from the wire while the AAD's
sequence number comes from local state — which is Go's arrangement
exactly, and is what makes a replayed record fail its tag — and
`plain_len = len(ct_and_tag) - 16` is Go's `len(payload) -
c.Overhead()`.

**One deviation found and RECORDED rather than patched.** The record
header's version field is neither checked nor authenticated on this
path. `read_record` drops hdr[1] and hdr[2] — it takes a bare
`io::Reader` and has no `c.vers` to compare against, the same
statelessness that already limits its length bound — and `compute_mac`
and `decrypt_record_aead` splice a constant `3,3` where Go splices
`record[:3]` into the MAC input and the AEAD additionalData. So an
attacker may flip those two bytes and nothing notices, where Go raises
alertProtocolVersion and would fail the tag.

Spec deviation rather than an exploitable one: the field is legacy in
TLS 1.2 and nothing downstream reads it. Not patched, because fixing it
properly needs connection state and the whole record — which is
`conn.rs`'s `readRecordOrCCS`, the port this file exists to be replaced
by, and a half-stateful check here would be a third behaviour to
maintain. The constants now carry the explanation.

That closes record.rs as an audit target. What is left is the
retirement, which §1 already sequences. Three of its hand-rolled
crypto primitives are gone this week — the SPKI walk, the TLS 1.2 PRF,
the padding check — and each left a Go-generated table behind.

## 2e-ii. Written and never READ: the field sweep, 2026-09-14

§2e asks which ported FUNCTIONS nothing calls. The same question about
struct FIELDS found `Transport.idleConnWait` (item 0 of §2), jsontext's
`AllowInvalidUTF8` and net/lookup's nine ignored contexts, one at a
time. Run mechanically it is: 3,750 fields under `src/`, **200 with no
`.field` read anywhere in `src/` or `examples/`**.

`scripts/write_only_check.py` is that sweep, kept so it can be re-run;
it is a triage list and deliberately NOT a gate. (It reads 199/41 now,
because `Resolver.StrictErrors` below is read.)

200 is not a list anyone reads, and most of it is legitimate — an
ASN.1 marshalling shape is written and handed to `asn1::Marshal`, and a
field on a public error type exists for the CALLER. The discriminating
question is §2e's: **does Go read it?** That cuts 200 to 42, and the 42
sort themselves quickly:

  * `HTTP2Config`'s eleven fields and all of `omithttp2.rs` — HTTP/2 is
    not ported and these are its config surface. Inert by construction.
  * `syscall`'s `statfs`, `utsname`, `StackT` — kernel ABI shapes.
  * `debug.BuildInfo`'s `Deps`/`Settings`/`GoVersion` — read by Go's
    own `String()`, which goish has.

Four were worth opening, and three of the four were fine for a reason
worth writing down:

  * `transfer.rs`'s `IsResponse`. Go reads it once, to wrap a chunked
    body writer in `FlushAfterChunkWriter` — but ONLY when the writer is
    a `*bufio.Writer`, which on goish's client path it never is.
    `persistConn` has no buffered writer; that is the same fact
    §2e already records under `writeBufferSize`. The guarded condition
    cannot be true, so the field is legitimately unread.
  * `transfer.rs`'s `bodyReadError`. Go reads it in `Request.write` to
    re-wrap the error as `requestBodyReadError`, which `writeLoop` uses
    to call `setError` EARLY — its comment says why: "before sending on
    the channels below or calling pc.close()". That priority exists to
    beat a concurrent readLoop. goish is sequential and already calls
    `treq.setError(werr)` on the write path unconditionally, so there is
    no race to win. §0.B again.
  * `conn.rs`'s `peerSigAlg`. All five of Go's WRITE sites are ported
    faithfully. Go's single read feeds
    `ConnectionState.testingOnlyPeerSignatureAlgorithm`, one of two
    `testingOnly*` fields goish deliberately omits — documented at
    conn.rs and common.rs. Dead state by design.
  * `lookup.rs`'s **`Resolver.StrictErrors` — the one real finding.**
    See below.

### Resolver.StrictErrors was accepted and ignored

Go's doc: "For a query composed of multiple sub-queries (such as an
A+AAAA address lookup, or walking the name server suffix list when
AbsDomain is not fully qualified), strict errors mean that the query as
a whole fails when any sub-query fails."

goish declared the field, let callers set it, and read it nowhere. That
matters here and would not in a simpler resolver: goish's
`go_lookup_ip_cname_order_ctx` DOES issue both A and AAAA, and DOES
walk `cfg.name_list`. So a dual-stack host whose A query returned
SERVFAIL came back **v6-only, with no error at all** — exactly the
downgrade Go's own comment says the flag exists to prevent: "This
ensures that network flakiness cannot turn a dualstack hostname
IPv4/IPv6-only."

The structure was half there already. goish had the `else if lastErr ==
nil || fqdn == name+"."` arm verbatim; what was missing was the arm
above it. Now threaded from `Resolver.StrictErrors` through both
`Resolver` call sites (the package-level `LookupHost`/`LookupIP` pass
false, as Go's `DefaultResolver` does), with `hit_strict_error` per
fqdn and `addrs.clear()` before the `!addrs.is_empty()` break — that
ordering is the point, or a lookup where AAAA answered and A failed
would still return the v6 half.

**How it is pinned, and what is not pinned.** The whole decision is one
line of Go (`nerr.Temporary() && r.strictErrors()`), so it is extracted
as `dnsclient::strict_abort` and driven by
`dns_strict_errors_smoke` over eight errors × strict on/off. All
sixteen expected values came out of Go 1.25.5 itself — a `TestGoishRef`
inside a writable GOROOT copy (`scripts/goref.sh net`), which can name
the unexported sentinels and run Go's own predicate — transcribed
programmatically. Two perturbations: ignoring temporariness turns
exactly the five non-temporary sentinels red, and dropping the strict
gate turns exactly the three temporary ones red.

The NEGATIVE rows are what the table is for. Aborting on a temporary
error is the easy half; the half that breaks a resolver is aborting on
`errNoSuchHost`, because NXDOMAIN is the ordinary answer while walking
a search list. Five of the eight sentinels must NOT abort and are named.

What is NOT pinned is the loop wiring — that `hit_strict_error` is set
from this predicate and that `addrs.clear()` runs. Pinning it needs a
DNS server that answers AAAA and SERVFAILs A, which the tree has no
fixture for. That is the next step for anyone extending this, and the
gap is stated rather than papered over: a green `strict_abort` table
proves the unit, not that the lookup consults it.

## 2e. Ported, anchored, correct — and never called

The defect shape every tier passes. `anchor_check` sees a well-formed
anchor. `port_coverage` counts the Go declaration as ported.
`port_bodydiff` compares the body against Go's and finds it faithful.
goishlint has nothing to say. An example may even test the function
directly and find it right. The function is a correct port of the right
Go code, and nothing in the library ever calls it.

`net/http/transport.rs`'s `validateHeaders` was this: anchored to
`transport.go:565-579`, covered by `http_transport_opts_smoke`, and
called from nowhere, while Go calls it twice in `Transport.roundTrip`.
Six malformed header shapes went onto the wire verbatim. Fixed in
"net/http: the client never validated the headers it sent".

`scripts/dead_port_check.py` now looks for it. The check that carries
the signal is TESTED_NOT_WIRED: an anchored fn that `examples/` calls
and that nothing under `src/` calls. On its own that is 28 + 227
findings, most of them legitimate — `container/list`'s `Front` is API
for users, and an example is its rightful only caller. So it asks Go's
own tree the discriminating question: does Go's stdlib call this symbol
from some other file? That cuts the list to 28, every one worth reading.

Getting there took three corrections, each the same mistake in a
different place:

  - keying on `pub` missed it — `validateHeaders` is `pub` in a `pub
    mod`, so visibility says nothing about whether the library uses it;
  - counting name mentions missed it — a GOISH waiver comment in
    `net/http/internal/httpcommon` names `validateHeaders` in prose, and
    that comment alone made it look wired;
  - asking Go the same way missed it — `fmt/doc.go` names `Sscanf` in
    package docs and `math/bits/make_examples.go` is a `//go:build
    ignore` generator that calls everything, which between them made 21
    of the first 53 findings noise.

Each was caught only by running the checker against the tree as it
stood BEFORE the known defect was fixed and demanding that it name
`validateHeaders`. A checker that cannot find the bug that motivated it
is worse than none, because it reports OK.

### Working through the list

**Read 2026-09-07, four findings, one change.** The list is 28 and the
hit rate is not what §2b's lists gave — these need opening one at a
time, and three of the four were fine:

  - `header.rs`'s `headerNewlineToSpace` looked like the worst possible
    case, a CR/LF sanitiser with no caller. It is not: `Header.Write`
    calls `sanitize_header_value`, which does the replacement; the
    exported function only publishes the same mapping "so the mapping
    has one definition". No defect.
  - `header.rs`'s `timeFormats` is uncalled because `ParseTime` parses
    the same three formats by hand rather than looping a layout table.
    One divergence falls out and is NOT worth changing: on failure Go
    returns the last `time.Parse` error, a `*time.ParseError`, where
    goish returns `errors::New("http: invalid date format")`.
    `http_time_smoke` checks only whether an error occurred, so nothing
    pins it — but Go does not document an error type here, so the text
    is an implementation detail either way.
  - `client.rs`'s `checkRedirect` WAS being honoured, by an inlined
    copy of its body in the redirect loop. Not a defect, but the policy
    decision was written in two places and the anchored method had no
    caller. Now the loop calls `self.checkRedirect(&next, &via[..])`,
    as Go's does. http_checkredirect_smoke 4/4, http_redirect_smoke
    3/3, http_redirect_semantics_smoke 13/13, http_redirect_creds_smoke
    ok.

**The list is 71 now, not 28.** That number in the paragraph above was
right when written; the section counts entries carrying Go-caller
evidence and it has grown with the port. Most of the growth is benign —
`math/bits`' `Len32`/`Add32`/`Mul32` family, `container/list`'s
`Front`/`Back`, `sync.Map`'s `LoadOrStore` — public API whose Go
callers live in generic or per-width code goish does not have.

Three more read the same day, all duplication rather than defect, and
all already reasoned about in the tree:

  - `server.rs`'s `idleTimeout` and `readHeaderTimeout` are unused
    because the conn loop uses `idle_timeout_ns`. The comment above
    them says why and refuses to collapse the two: Go tests `!= 0` and
    returns a NEGATIVE IdleTimeout as-is, where `idle_timeout_ns` tests
    `> 0` and treats it as unset. Go's negative value becomes a
    deadline in the past and closes the idle conn at once; goish falls
    through to ReadTimeout. A real divergence, on an input nobody
    writes, recorded deliberately.
  - `request.rs`'s `parseRequestLine` is unused because the server
    splits with `parse_request_line`, a byte-view version that interns
    the method and proto. The two agree on every input I traced,
    including a line with three spaces.

**Eight more read 2026-09-14, no defect, one de-duplication.** Chosen
for consequence — a function that is unwired in a security path is
worth more than one that is unwired in `math/bits`. Recorded by name so
the next pass does not re-read them:

  - `http.rs`'s `isNotToken` — uncalled in GO TOO in 1.25.5. The only
    reference is its own definition. Faithful.
  - `http.rs`'s `aLongTimeAgo` — Go's single caller is
    `connReader.abortPendingRead`, which goish diverges from
    deliberately: goish disarms the poller watch where Go pokes a
    deadline into the past, because goish's background read is a watch
    and not a blocked goroutine. Documented at the site.
  - `clone.rs`'s `cloneURL` and `cloneMultipartForm` — `Request.Clone`
    relies on derived `Clone` being deep, and that CHECKS OUT:
    `slice<T>` wraps a `Vec` and `map` is a value type, so goish's
    clone is at least as isolating as Go's.
  - `transfer.rs`'s `didEarlyClose`, `bodyRemains` and
    `registerOnHitEOF` — all three trace to §0.A. The server's eager
    body read makes `requestBodyRemains` false for every request, so
    only the drained arm can run; `closedRequestBodyEarly` is CALLED
    and returns false unconditionally for the same reason. The seam
    where the branch returns is marked in `server.rs`.
  - `transport.rs`'s `tlsHost` — the one worth the time, because it
    picks the name the peer's certificate is matched against. Not a
    defect: Go's `dialConn` takes the `connectMethod` and asks it,
    goish's takes the `connectMethodKey` and reaches the same string
    via `host_without_port(key.addr)`. `key()` only blanks `addr` when
    a proxy is in use AND the target scheme is `http`, and both call
    sites are guarded by `scheme == "https"`, so the two agree exactly
    there.

**The de-duplication.** Chasing `tlsHost` turned up a FOURTH `hasPort`
in the tree. Go has two — `net/http.hasPort` and
`net/http/cookiejar.hasPort` — and goish carries both plus
`httpproxy`'s, all faithful. The fourth was goish's own, a
hand-written backwards scan in `client.rs`, and it is what decides the
SNI the TLS handshake is given. It agreed with the anchored one on
every input traced, so this is not a fix; it is removing the
possibility that a later edit makes them disagree about which
certificate the client accepts. It now delegates.

That is the same shape §2e recorded for `checkRedirect`: a rule
written in two places with the anchored one unwired. The rate holds at
roughly one defect per ten entries, and the defect that motivated the
section remains the only one found.

**Three more, chosen for consequence rather than order, all fine.**

  - `transport.rs`'s `writeBufferSize` is uncalled and the field it
    reads says why in its own doc: `WriteBufferSize` is INERT because
    Go applies it at `pconn.bw = bufio.NewWriterSize(…)` and goish's
    persistConn has no buffered writer to size. Its sibling
    `ReadBufferSize` IS honoured, and records that it once was not.
  - `gcm/ctrkdf.rs`'s `DeriveKey` has exactly one caller in Go —
    `cast.go`, the algorithm self-test — and §2f already records that
    every FIPS CAST here is inert. A ported building block whose
    consumer is a test goish does not run.
  - `transport.rs`'s `tlsHost` took real checking and is the one worth
    writing down. Go calls it to get "the host name to match against
    the peer's TLS certificate"; goish's `addTLS` takes that name from
    `host_without_port(&key.addr)` instead. The two agree — but only
    because of a detail one step away: Go's `cm.addr()` returns the
    PROXY address when proxying while `cm.tlsHost()` always returns the
    target, so deriving the TLS name from an addr field would be a
    certificate-verification bug through a proxy. goish's
    `connectMethodKey.key()` sets `addr` to `targetAddr` and blanks it
    only for plain HTTP through a proxy, where the scheme is `http` and
    no TLS name is needed. Correct, and correct for a reason that is
    not obvious from either function alone.

The lesson for the rest of the list: TESTED_NOT_WIRED plus "Go calls it"
is a question, not a verdict, and the answer is usually "goish reaches
it another way". Nine read, one change. That is the opposite of §2b's
curated lists, where nearly every named entry held something, and the
difference is worth knowing before someone budgets time against the
remaining 65.

Fixed so far, one per finding read:

  - `Redirect` did not call `hexEscapeNonASCII`, so the Location header
    went out unescaped.
  - `Getwd` did not call `SameFile`, so it never honoured `$PWD` and
    returned the physical path where Go returns the symlinked one.
  - `NewRequest` did not call `removeEmptyPort`, so a URL written
    `http://example.com:/p` kept its trailing colon onto the wire as
    `Host: example.com:`.
  - The default client did not call `ProxyFromEnvironment`, because
    there was no `DefaultTransport` for it to live in — `http::Get`
    ignored HTTP_PROXY entirely.
  - `dialConn` did not consult the roundtrip deadline, so
    `Client.Timeout` never bounded a connect (2g).
  - `RoundTrip` rejected every non-http scheme BEFORE consulting
    `alternateRoundTripper`, so `RegisterProtocol` could not serve any
    of the schemes it exists for — including the `file` example in
    filetransport.go's own doc comment. Two more defects fell out of
    testing that path end to end: the redirect loop resolved Location
    through `resp.Location()` (which needs `resp.Request`, set only on
    the wire path) instead of against the current request's URL, and a
    malformed Location returned the 3xx as though it were the final
    response.
  - `ServeTLS` did not call `adjustNextProtos`, and set `NextProtos`
    nowhere else, so goish's HTTPS server advertised no ALPN at all
    where Go negotiates `http/1.1`. Wiring it up naively then made
    goish advertise — and negotiate — `h2`, which it cannot speak, so
    the advertisement is built from `protocols()` with HTTP/2 forced
    off. That is a deliberate divergence from the literal port and is
    documented at the call site.
  - Nothing called `maxHeaderResponseSize`, so
    `Transport.MaxResponseHeaderBytes` did nothing and — since Go's
    default when it is unset is 10 MiB — goish had NO bound on a
    response head at all. A server answering with many short headers
    could grow a client's Header map until the process died.
  - Nothing called `readBufferSize`/`writeBufferSize`, so
    `Transport.ReadBufferSize` and `.WriteBufferSize` do nothing —
    goish always uses bufio's 4096 default, which is also Go's default,
    so the fields are inert rather than wrong. STILL OPEN. Chasing
    them, though, turned up a real defect next door: the client read
    header lines with a single `ReadSlice` and failed the whole
    response with "bufio: buffer full" on any line over ~4 KiB, where
    Go's textproto accumulates. Fixed.
  - Neither serve loop called `numLeadingCRorLF`, and neither tracked
    a last method to gate it on, so stray CR/LF before a request line
    after a POST got a 400 where Go serves the request.
  - The serve loops did not call `doKeepAlives`, so
    `SetKeepAlivesEnabled(false)` set a flag nothing read, and
    `wantsHttp10KeepAlive` — which I had wrongly triaged as
    redundant, below — turned out to be the thing that distinguishes
    the two signals goish had conflated.

One entry that WAS on this list was triaged wrong, and it is worth
recording how. `wantsHttp10KeepAlive` was dismissed on the grounds that
`request_keep_alive` is `!shouldClose(...)` and Go's `shouldClose` on
HTTP/1.0 is `hasClose || !hasKeepAlive`, so its negation already means
"the 1.0 client asked to keep the connection". That much is true. What
it missed is that Go needs the request-side answer SEPARATELY from the
server-side reuse decision: `writeHeader` sets the 1.0
`Connection: keep-alive` header off `wants10KeepAlive` alone, ungated,
while `closeAfterReply` is gated on `keepAlivesEnabled`. goish had one
flag doing both jobs, so it could not produce Go's answer for a 1.0
client talking to a server with keep-alives disabled.

The lesson is that "goish computes the same predicate a different way"
is not sufficient. The question is whether it computes the same NUMBER
of predicates.

`net/http/httputil`'s `ReverseProxy` is a third category again. Its
`modifyResponse`, `copyResponse`, `copyHeader` and `handleError` are
all uncalled because the type has NO `ServeHTTP` — it is not a Handler
at all. That is recorded on the type itself as STAGED: ServeHTTP needs
the streaming response copy, which needs Body as io.ReadCloser. The
working proxy is `NewSingleHostReverseProxy`'s `reverseProxyHandler`,
which has none of the hooks. So `ReverseProxy.ModifyResponse` and
`.ErrorHandler` cannot be reached — not silently ignored at runtime,
but not usable either.

Read and found NOT defects, which is the other half of the work:

  - `cloneURL` / `cloneMultipartForm`. Go's `Request.Clone` needs them
    because Go copies a struct by value and the pointers inside stay
    shared. goish's `slice` is a `Vec` and its `map` clones
    element-wise, and `URL`/`Userinfo` are by-value, so `derive(Clone)`
    already deep-copies. Redundant, not missing.
  - `isH2Upgrade`. In Go it does two things, and both are about the
    HTTP/2 client preface: skip the missing-Host 400, and mark the
    connection unusable afterwards. goish speaks HTTP/1.x only, so the
    connection is finished either way.
  - `didEarlyClose` / `bodyRemains` / `registerOnHitEOF`. All three
    serve Go's STREAMING request body. goish materialises the body into
    a `slice<byte>` before the handler runs, so there is no
    early-closed stream to get out of sync with — `closedRequestBodyEarly`
    is documented as always-false for that reason, and it is right.
  - `Log1p`, `Sincos`, `J0`, `J1`, `Y0`. Go composes `Asinh`, `Acosh`,
    `Atanh`, `Jn` and `Yn` out of these; goish delegates each of those
    to `libm` instead, so the internal edges do not exist here. That is
    only acceptable if libm agrees with Go, and it does: math_ref_smoke
    and math2_ref_smoke pin all of them as raw IEEE-754 BIT PATTERNS
    against Go 1.25.5, and both pass. Bit-for-bit, not near enough.
  - `LoadOrStore` / `LoadAndDelete` / `CompareAndDelete`. Go's only
    internal caller is `sync/hashtriemap.go`, which goish does not
    port. They are `sync.Map` API and an example is their rightful
    caller.
  - `Skipped` / `Helper`. Go calls both from `testing/fuzz.go`.
    goish's `testing/fuzz.rs` carries a GOISH018 waiver saying F and
    the fuzzing engine are not ported, so the callers do not exist.
  - `tlsRecordHeaderLooksLikeHTTP` — FIXED. Plaintext HTTP sent to an
    HTTPS port got the connection dropped with no explanation, where Go
    answers "Client sent an HTTP request to an HTTPS server."
  - `rangesMIMESize`. Go must precompute the encoded length of a
    multipart/byteranges body because it streams it through an
    io.Pipe; goish builds the body into a buffer and takes its length,
    which is exact by construction. Measured end to end rather than
    assumed: `http_multirange_smoke` now compares the whole response
    against Go for two multi-range requests and one single-range
    control, and the bodies are BYTE-IDENTICAL — Content-Length 364,
    485 and 10, the part headers, and the boundary delimiters.
  - `removeIdleConn`. Go's only non-HTTP/2 caller is `readLoop`'s
    deferred cleanup, and goish's readLoop is not wired to anything —
    see 2h. The inline path's pool hygiene holds without it.
  - `VolumeName`. Go's caller is `path/filepath/symlink_windows.go`.
    goish is Linux-only.
  - `IsPermission`. Go's caller is `os/removeall_noat.go`, the
    fallback for systems without `openat`. goish does not port it.

That leaves `DeriveKey`, which is not a false positive but is not a
missing call either — see 2f.

`cancelRequest`, `handleFunc`/`findHandler` and `socksNewDialer` close
out the original list. goish tears an in-flight request down by arming
a netpoll cancel watch on the raw socket rather than through a per-conn
`cancelRequest`, and http_complex_api's two ctx-cancel cases prove that
path works. `servemux121`'s own header already records that `use121()`
is always false because goish has no `internal/godebug`.

`cancelRequest` is also what exposed a flaw in the checker. It reported
"Go: called from h2_bundle.go" when Go's real callers are two lines in
transport.go itself — the script skipped the whole declaring file to
avoid matching the declaration, so it missed same-file callers and
matched an unrelated same-named method elsewhere in the package. It now
skips only the declaration's own line range, which the anchor already
names.

That first attempt reported 88 hot findings, and 15 of those were the
script reading a declaration as its own caller. `strip_go_comments`
dropped the newlines inside `/* */`, so every line number after a block
comment shifted and the declaration-span exclusion missed. Newlines are
kept now, and the honest numbers are 73 hot and 177 cold — still
forty-seven more than the 26 the whole-file exclusion allowed through.

The dominant pattern among the hot findings, once the false ones are
gone, is same-package COMPOSITION rather than a missing edge: Go builds
`LeadingZeros32` out of `Len32`, `PushBackList` out of `Front`,
`Asinh` out of `Log1p`, and goish implements each entry point directly
— with a Rust intrinsic, with libm, or over its own internals. Those
are pinned against Go by the ref smokes and are not defects. It still
has to be read one at a time, because `validateHeaders` was same-file
too, and it was real.

## 2f. Every FIPS CAST in the tree is inert, ported or not

**Re-measured 2026-09-05.** This section used to say "twelve unported
`cast.go` files" and treat it as a worklist. Measuring the mechanism
first changes what the worklist is worth.

`fips140::CAST` opens with Go's own guard:

    if !Enabled_ { return; }

and `Enabled_` is `const false` in `fips140.rs` — not a runtime flag.
The early return precedes the closure call, so the self-test body is
never entered. Measured, not read: a probe calling `fips140::CAST`
with a closure that sets an `AtomicBool` reports the body did NOT run.
That applies to all six CASTs already ported.

**This is not a divergence from Go.** Go's `CAST` has the same
`if !Enabled { return }`, and Go's `Enabled` is off unless
`GODEBUG=fips140=on`. `crypto/internal/fips140test` runs the CASTs by
re-exec'ing itself with that variable set (check_test.go:39). Default
Go does not run them either.

The difference is switchability: Go's is a `var` set from GODEBUG,
goish's is a `const`, and goish has no GODEBUG by an explicit earlier
decision (see `crypto/internal/fips140only`). So there is no
configuration goish can reach in which any CAST executes.

That corrects the claim this section used to make — that goish "would
not NOTICE if the algorithms became wrong, which is the entire point
of a CAST". With FIPS mode off, neither implementation notices. The
algorithms' outputs are diffed against Go elsewhere, and that is what
is actually guarding them.

So the twelve missing files are a **structural-fidelity** question, not
a correctness one:

  Present: root `cast.go`, `ecdh`, `rsa`, `nistec/fiat`, `ed25519`,
           `ecdsa`.
  Missing: `pbkdf2`, `sha512`, `tls12`, `tls13`, `sha3`, `hmac`,
           `mlkem`, `drbg`, `hkdf`, `aes`, `aes/gcm`, `sha256`.

They are small — 32 to 58 lines each, about 486 in total — and porting
them costs little. But porting them adds twelve more files that cannot
run, and it is worth deciding the upstream question first:

  **Should `Enabled_` become switchable?** If yes, the twelve are worth
  porting because they would then do something, and the six existing
  ones would start earning their keep. If no, the whole fips140 CAST
  tree is structurally faithful decoration, which is a legitimate
  choice for this port but should be written down rather than
  rediscovered.

Note the wiring trap either way: Go calls most of these from `init()`,
which goish has no equivalent of. The ported ones use an `AtomicBool`
latch invoked from the algorithm's own entry points. Twelve new files
with no caller would be twelve TESTED_NOT_WIRED findings, so
`dead_port_check.py` should be re-run after any such port.

## 2g. Client.Timeout did not bound a dial that never completes — FIXED

Found while checking that http_default_proxy_smoke fails without its
fix. With the fix reverted the example does not fail, it HANGS, and
the harness kills it at the e2e timeout — while `c.Timeout` is set to
three seconds.

The request is a GET to 192.0.2.1 (TEST-NET-1, never routed), so the
connect syscall never completes and never errors. Go's `Client.Timeout`
covers "the time limit for requests made by this Client... including
connection time"; goish's does not reach a dial that is stuck.

Two things follow, and they compound:

  - `DefaultTransport` has no `DialContext`, so there is no 30-second
    dial timeout (see the note on that function — setting the hook
    costs ctx cancellation, so it is not a one-line fix); and
  - `Client.Timeout` does not rescue the caller from that.

Together they mean a goish client can wait forever on an address that
black-holes packets, with no configuration available to prevent it.
That is the shape of an outage rather than an error.

Diagnosed and fixed. Neither guess was right: the deadline was never
CONSULTED. `dialConn` called `net::Dial`, which takes no deadline at
all, while `net::DialTimeout` — sharing the same `dial_deadline`
underneath — bounds the identical connect correctly. Measured on
192.0.2.1: `net::DialTimeout` returned in 2.008s with `i/o timeout`
while the Client was still blocked at forty seconds.

`Transport::dialDeadline` now reads `effective_deadline` (which already
combined `Client.Timeout`'s ctx deadline with `Transport.Timeout`) and
dials with the remaining time. Both plain-dial sites use it.

The error text needed a second fix to match Go. Go wraps it:

  Go     context deadline exceeded (Client.Timeout exceeded while
         awaiting headers)
  goish  context deadline exceeded

net/http's `timeoutError` (transport.go:2716) was not ported, so the
annotation had nowhere to live, and `Client.Do` bound Go's `didTimeout`
closure to `_did_timeout` and dropped it. The suffix is how a caller
tells "my Client.Timeout fired" from "the context I was handed
expired", and the wrapper is what makes `err.(net.Error).Timeout()`
answer true. Both are in now, with the interface registration the
assertion needs.

Go's `errTimeout` singleton is deliberately not ported with it: its
only Go caller is the ResponseHeaderTimeout path, which goish does not
implement, and a ported-but-uncalled decl is the shape this work
exists to remove.

STILL OPEN: `DefaultTransport` has no 30-second default dial timeout,
because Go supplies it through `DialContext` and setting that hook
costs ctx cancellation (see 2e's note). A caller who sets no timeout at
all still waits forever.

## 2h. The transport's readLoop/writeLoop are not wired to anything

`persistConn::readLoop` (163 lines) and `writeLoop` (50) are a careful
port of Go's transport conn loops. `__spawn_loops`, which starts them,
has exactly one caller in the whole tree:
`examples/http_transport_loops_smoke.rs`. Nothing under `src/` starts
them. `Transport::RoundTrip` reads the response head inline and hands
the conn back through the body's `reuse_fn`.

So goish has TWO implementations of the same responsibilities — the
response-head read, the 100-continue dance, the body hand-back, the
conn's death — one of which runs in production and one of which is
exercised only by a smoke. They can drift, and the smoke will not
notice, because it tests the one that does not run.

This is the never-called shape at subsystem scale, and it is why
several entries on the 2e list resolve at once rather than one at a
time. `removeIdleConn` is the clearest: Go's only non-HTTP/2 caller is
`readLoop`'s deferred cleanup, so with readLoop unwired there is
nothing to call it.

That particular gap is NOT a live defect, which took checking rather
than assuming. The inline path's pool hygiene holds on its own:

  - a conn is banked only when the framing is clean, so a broken or
    desynced conn never enters the idle pool at all;
  - a conn the peer closed while idle is caught on the way OUT —
    `queueForIdleConn` pops anything `isBroken()` or too old; and
  - `closeConnIfStillIdle` reaps on the IdleConnTimeout.

Go's `removeIdleConn` would remove a dead conn EAGERLY rather than on
next use. With `MaxIdleConns` now live at Go's 100, that difference is
worth keeping in mind — dead entries occupy idle slots until someone
tries that host — but nothing hands out a dead conn.

The real question this raises is which of the two implementations to
keep. Wiring readLoop up is the Go-faithful answer and is a large
change; deleting it is the honest alternative if the inline path is the
one being maintained. Leaving both is the option that guarantees drift.

## 2i-fixed. The response head had no "headers are frozen" moment

Recorded here because sniff_server_ref_smoke called this "the
eager-vs-deferred difference behind the other structural gaps in this
port" and named the fix: goish's writer had no moment at which the
header map stopped mattering.

Go clones the handler's header when the head is committed
(`cw.header = w.handlerHeader.Clone()`), so a `Header().Set` after the
handler's first write is ignored. goish rendered the head from the LIVE
map at flush time and honoured those late sets. Measured two ways:

  a plain header set after the first Write reached the wire; Go drops it
  a trailer announced and set without an explicit Flush was emitted
    BOTH in the head and after the last chunk; Go emits it once, as a
    trailer

`respInner.committed` is that moment now — snapshot on WriteHeader, on
the implicit one at the first Write, and on the promotion to chunked.
`finalTrailers` still reads the LIVE map, which is what Go does, so the
trailer half stays correct.

This closed a gap the tree had already identified and pinned to goish's
answer: sniff_server_ref_smoke's `ct-after-write` row now carries Go's
line rather than a documented divergence.

## 2i-fixed. Response header ORDER now matches Go

**Fixed 2026-09-05.** Found while diffing multipart range responses
byte for byte. goish sorted every response header, including
`Connection`, into one block:

  Go     Accept-Ranges, Content-Length, Content-Type, Date, Connection
  goish  Accept-Ranges, Connection, Content-Length, Content-Type, Date

Go writes the handler's own headers sorted through `WriteSubset`, then
appends the ones the SERVER derived through `extraHeader.Write` in one
fixed order — Date, Content-Length, Content-Type, Connection,
Transfer-Encoding (server.go:1265).

The subtlety that makes this more than a sort order: Go's wire order is
not one fixed sequence. A header the HANDLER set stays in the sorted
block; only a server-derived one moves to the extra block. So a
ServeContent response puts Content-Type BEFORE Date and a sniffed one
AFTER, from the same code.

goish can now make that distinction because of the header-commit
snapshot added in 2i-fixed above: whatever `finalizeHeaders` adds after
the snapshot is derived. `derived_extras` diffs the two and
`build_head` renders sorted-then-extra.

Wired at all four head-build sites — two in `responsewriter.rs` and,
less obviously, two more in `server_tls.rs`, which builds its own heads
and does not share the plain server's. Fixing only the plain pair left
HTTPS diverging and no existing smoke could see it, because nothing
pinned an HTTPS response head.

`http_header_order_ref_smoke` pins six rows against Go 1.25.5: three
response shapes over plain HTTP and the same three over TLS. The TLS
rows were not redundant — they caught the auto Content-Length being
snapshotted on the handler-set side, which made a bodied HTTPS response
lead with Content-Length instead of Date.

`http_multirange_smoke` and its generator no longer sort the header
block on either side; it now compares the whole response byte for byte,
which is what its own header comment always claimed. Three other smokes
(`http_head_framing_smoke`, `http_bodyless_status_smoke`,
`http_trailer_ref_smoke`) still sort, but only because their references
were transcribed sorted — their comments used to cite this divergence
as the reason and now say so plainly.

## 2j. httptrace is inert — not one hook fires

`httptrace.ClientTrace` is a complete, documented public API in goish:
every field Go has, `WithClientTrace`, `ContextClientTrace`, `compose`
with Go's ordering policy, and `hasNetHooks`. A caller can build a
trace, put it in a request's context, and receive NOTHING. Counted
across the whole tree, the call sites outside `httptrace/trace.rs` are:

  ConnectStart 0   ConnectDone 0   DNSStart 0
  DNSDone      0   GetConn     0   GotConn  0

`httptrace_smoke` passes. It exercises `compose`, the context
round-trip, and the hook types by invoking them itself — the struct,
not the wiring. Nothing checks that a REQUEST fires anything, which is
the same shape as validateHeaders and Redirect.

The file's own header explains part of it: `WithClientTrace` does not
install an `internal/nettrace.Trace`, because that package is not
ported, so the connect and DNS hooks have no path. That note is
accurate and covers four hooks. It does not cover the rest — Go's
transport calls `GetConn`, `GotConn`, `WroteHeaders`, `WroteRequest`,
`GotFirstResponseByte` and `PutIdleConn` DIRECTLY, with no nettrace
involved, and those are unimplemented for no recorded reason.

Measured against Go 1.25.5, an ordinary plaintext GET
(tools/gen_httptrace_ref.go):

  reuse=false  GetConn GotConn(reused=false) WroteHeaders WroteRequest
               GotFirstResponseByte PutIdleConn
  reuse=true   GetConn GotConn(reused=true)  WroteHeaders WroteRequest
               GotFirstResponseByte PutIdleConn

Six hooks, in that order, with `Reused` the only difference between a
fresh conn and a pooled one — which is exactly what most callers of
this API are measuring.

**Scoped 2026-09-06. Five of the six are call-site work; the sixth
needs an ownership decision.** The plumbing is further along than the
zero call sites suggest — `transfer.rs`'s `writeHeader` already takes
`Option<&ClientTrace>` and fires `WroteHeaderField` from it. Its two
callers pass `None`. Where each hook goes:

| hook | site |
|---|---|
| `GetConn(hostPort)` | before `self.getConn(&rt_req, &cm)` in `Transport::RoundTrip` |
| `WroteHeaders()` | after the `tw.writeHeader(&mut hb, None)` block, which already wants the trace |
| `WroteRequest(info)` | after the body write, with the write error |
| `GotFirstResponseByte()` | at the first byte of the response read |
| `PutIdleConn(err)` | where the conn returns to the pool |

`GotConn` is the one that is not a call site. `GotConnInfo.Conn` is
`Arc<dyn Conn>` because Go's is a `net.Conn` interface value that the
Transport keeps owning and hands to the hook by reference. goish's
transport owns the connection BY VALUE, inside a
`bufio::Reader<TCPConn | tls::Conn | DynConn>` in `ConnSrc`; there is
no `Arc<dyn Conn>` anywhere on that path to hand out, and a socket
wrapper cannot be cloned to make one. So firing `GotConn` means either
making the transport's conn `Arc`-shared — a real ownership change on
the request hot path — or narrowing `GotConnInfo.Conn` to an `Option`
and passing `None`, which is a public API change and would leave the
field permanently empty.

That matters because `GotConn` carries `Reused`, and `Reused` is what
most callers of this API are actually measuring — so the cheap five do
not deliver the interesting one. Deciding the ownership question first
is what makes this worth doing at all, and it belongs with §0 B, which
is the other item gated on how the transport holds its connections.

Five of the six are straightforward: their hook types take a string, a
`WroteRequestInfo`, an `error`, or nothing, and every call site exists
in the inline RoundTrip path already.

`GotConn` is the one that needs a decision, not a patch.
`GotConnInfo.Conn` is `Arc<dyn Conn>`, and the client path has no such
value: the conn is a `TCPConn` owned inside a `ConnSrc`, and it owns
its fd, so it cannot be handed out behind an Arc without either
double-close hazards or sharing the conn through the whole transport.
The options are to give `GotConnInfo.Conn` a non-owning handle — a
deliberate divergence from Go's field — or to move the transport to a
shared conn. Wiring the other five and leaving GotConn out would mean
pinning a hook order that is not Go's, so it is recorded whole rather
than done by halves.

## 2k. ReadTimeout bounds a slow body, but not the way Go does

Go documents `Server.ReadTimeout` as "the maximum duration for reading
the entire request, including the body", and the slow-BODY form of
slowloris is the case that needs it: headers arrive inside every header
timeout, and only a bound on the whole request stops the connection
being held open.

goish bounds it. Measured with ReadTimeout 500ms against a body
dribbled over 1.5s:

  Go     handler RUNS, its ReadAll returns read=2 and an i/o timeout
  goish  handler NEVER RUNS, and nothing is written back

Neither is a hole — the connection is bounded either way. The
difference follows from the eager body: Go calls the handler as soon as
the headers parse and lets it discover the truncation, while goish
reads the body inside the request parse, so the read fails before a
handler exists to be told.

What that costs is observability, not safety. A handler that logs or
meters every request it is given sees nothing in goish for a request
Go would have shown it, and cannot answer 408 itself.

Making goish match means a streaming request body, which is the same
decision as 2h and 2j rather than a patch.

A third consequence, measured on the wire: the SERVER sends its
interim `100 Continue` unconditionally, where Go sends it only when the
handler actually reads the body.

  handler reads the body      Go 100 then 200      goish same
  handler rejects, unread     Go 401 alone         goish 100, then 401
  unrecognised Expect         Go 417               goish same

The middle row is the whole point of the mechanism. Go lets a handler
answer 401 BEFORE the client uploads; goish makes the client send the
body first, because the request parse reads it before a handler exists
to reject. On a large upload to an endpoint that would have refused it,
that is the difference between a wasted round trip and a wasted upload.

http_expect100_server_smoke pins all four rows, with the middle one
pinned to GOISH's answer and labelled as the divergence — it will start
failing when the body streams, which is the marker for that work.

The same root produces a second, blunter divergence: request bodies are
capped at 16 MiB (`MAX_BODY` in request.rs), and a request DECLARING
more is refused before it sends anything —

  Content-Length: 17000000, zero body bytes sent
    Go     accepts the request; the handler decides what to read
    goish  HTTP/1.1 400 Bad Request, immediately

So an upload over 16 MiB does not work at all. Go has no default body
limit; it leaves the bound to the handler, via MaxBytesReader. goish
cannot, because it buffers the body before the handler exists, and the
cap is the honest mitigation for that — 16 MiB is a guess, and any
other number would be too until the body streams.

One hypothesis about that cap was tested and DISPROVED, which is worth
recording so nobody re-derives it: the read path calls
`Vec::with_capacity(want)` on the CLIENT-DECLARED length before any
bytes arrive, which looks like a cheap amplification — a hundred-byte
request buying a multi-megabyte allocation. It does not measure that
way. Ten connections each declaring 4 MiB and sending no body moved
VmRSS by 432 kB and VmSize by 680 kB, not by 40 MiB, on two runs. The
reservation does not become resident or even mapped, so the cap's
rationale holds without that hazard behind it.

http_readtimeout_body_smoke pins both rows and is verified to fail if
the bound stops working: raising ReadTimeout above the stall makes the
slow-body row read `handler_runs=1 read=10` immediately. The
prompt-body row is the control and DOES match Go exactly, so a "fix"
that refused every request carrying a body could not pass.

## 2l. encoding/json's Value loses the number literal

`Value::Number(float64)` keeps the VALUE and drops the text it was
parsed from, and three separate symptoms come out of that one fact:

  - `Unmarshal("1.0", &mut int)` succeeds where Go errors with "json:
    cannot unmarshal number 1.0 into Go value of type int". Go rejects
    it because the literal carried a fraction, not because the value is
    non-integral — 1.0 is. Same for "1e2".
  - `number_to_int` needs a clamp at 2^63, because the maximum int64
    literal has already rounded to 2^63 as an f64 by the time an
    integer target sees it. Go parses the digits with ParseInt and
    answers 9223372036854775807 exactly.
  - json_decode_ref_smoke carries both as KNOWN GAP rows with Go's
    answers quoted beside goish's.

The fix is for the parser to keep the literal — a second field, or an
Int variant beside Number — and for integer targets to parse digits
rather than convert a float.

It is a DECISION rather than a patch because `Value` is public API: the
module's own doc advertises `pub enum Value { … Number(f64) … }`, so
every user pattern match on it is affected, and `FromValue` would want
a way to see the raw text. That is a deliberate API change to make at a
version boundary, not a rider on a bug fix.

## 2n. A chunked response never reuses its connection, and never
##     exposes its trailers

Measured 2026-09-07 against Go 1.25.5 with
tools/gen_chunked_reuse_ref.go: three requests to a handler that
Flushes (so the response is chunked), counting connections with
Server.ConnState.

    Go     three chunked requests opened 1 connection
    goish  three chunked requests opened 3 connections

Same body, same `te=chunked`, `resp.Close` false and no Connection
header on either side. Only the reuse differs, so every chunked
response costs a fresh TCP connection — and a fresh TLS handshake over
https.

The cause is not the reuse logic. goish never reads the TRAILER
section of a chunked response. `readTrailer` is ported and correct,
and it is wired to exactly one caller: request.rs, the SERVER reading
a chunked request body. Nothing on the client side runs it, so two
things follow from one gap:

  * `resp.Trailer` is never populated for a chunked response, where
    Go's is.
  * The trailer bytes stay unread on the wire, so the connection is
    DESYNCED at the point the body reports EOF. Banking it would hand
    the next request a conn whose stream begins mid-trailer, which is
    a response-smuggling shape, not an optimisation — close_locked's
    own comment says exactly that.

So the conservative close is CORRECT as it stands, and this entry is
not "goish forgot to reuse a connection". It is: the client half of
readTransfer's trailer read is unported, and connection reuse for
chunked is one of the things blocked behind it.

**RE-MEASURED 2026-09-13, and most of the above is now HISTORY.** The
client does read the trailer section — `client.rs`, the
`FramedBody::Chunked` arm, calls `transfer::readTrailer` when the
chunked reader hits EOF and sets `chunk_drained` only on a clean read,
so a malformed trailer still kills the conn instead of banking a
desynced one. The reuse numbers that open this entry are stale:

    Go     three chunked requests opened 1 connection
    goish  three chunked requests opened 1 connection

pinned, along with the trailered case, by
`examples/http_chunked_reuse_ref_smoke.rs` (6/6).

ONE HALF REMAINS: `resp.Trailer` is still empty. The trailers are read
into a scratch Header and dropped, and the reason is not laziness —
`Response.Trailer` is a public field of value-typed `Header`, and
goish's `map` is a VALUE type where Go's is a reference. Go's `body`
can write the caller's Trailer because it holds the `*Response` and the
Header aliases; a goish body holding a `Header` holds a copy. Making it
work means either a shared handle in `Response` (public API) or making
`Header` reference-typed (all of net/http, and it is really the map
design). So this is decision-shaped like §0.D, not a patch — and it is
the ONLY thing left in this entry.

FIXED in that order — trailers first. The chunked arm of the body
read now calls `readTrailer` when the reader hits its terminator, and
only a CLEAN trailer read marks the body drained; a malformed one
leaves the stream anywhere, so the conn dies instead. Close banks the
conn only when it is drained AND nothing is buffered ahead of it,
since goish cannot push read-ahead bytes back. Three chunked requests
now open one connection, matching Go, and so do three requests whose
responses carry a real trailer section — that second case is the one
that decides it, because a leftover trailer line makes the NEXT
response on the conn parse as garbage.
`examples/http_chunked_reuse_ref_smoke.rs` pins both, and was checked
to fail without the fix.

The near miss is worth keeping. The obvious change — let the bank-back
accept a Chunked framing — makes the connection count go green while
quietly introducing the desync, because nothing in the count can see a
trailer left on the wire. It was written, measured and reverted before
the real cause turned up.

STILL OPEN, and unchanged by this: `resp.Trailer` is never populated.
The trailers are consumed and dropped, because goish's Header wraps a
value-typed map, so a Body cannot write into the Response's copy the
way Go's `body` does through its reference-typed Header. Exposing them
is a Response-shaped change.

## 2m. RSA's drbg shims predate the drbg package they stand in for

Found 2026-09-06 by re-measuring header claims, not by looking for a
crypto defect. `crypto/internal/fips140/rsa` reads randomness through
two local shims in `rsa.rs`, `read_with_reader` and `drbg_read`, each
annotated "crypto/internal/fips140/drbg has no goish package yet".
That package exists, with `Read`, `ReadWithReader` and
`ReadWithReaderDeterministic` all ported and anchored.

The shims are not equivalent to it, in two ways that are worth naming
separately:

1. **`read_with_reader` skips `randutil::MaybeReadByte`.** The shim's
   own comment says the `DefaultReader` fast path and `MaybeReadByte`
   are "FIPS-mode-only". They are not — the ported `ReadWithReader` has
   no `fips140::Enabled()` branch and calls `MaybeReadByte` on every
   non-default reader. Go reads one extra byte on a coin flip so that
   callers cannot depend on how many bytes a key generation consumes.
   goish consumes a fixed count, so `GenerateKey` over a deterministic
   reader yields a different key here than in Go. That is the shape
   this tree normally catches with a ref smoke, and there is no smoke
   over a fixed reader to catch it.

2. **One shim serves two Go functions.** `keygen.rs` calls
   `read_with_reader` where Go calls `ReadWithReader`; `pkcs1v22.rs`
   calls the same shim where Go calls `ReadWithReaderDeterministic`.
   Those two differ in exactly the `MaybeReadByte` call, so the shim
   cannot be right for both. It currently matches the Deterministic
   one.

3. **`drbg_read` always takes the kernel CSPRNG**, where the real
   `drbg::Read` branches on `fips140::Enabled()` and uses the approved
   DRBG under FIPS. goish makes no FIPS 140-3 claim and the service
   indicator is inert, so this is a conformance divergence rather than
   a weaker RNG.

**A near-miss worth recording, same day.** The TLS 1.3 server's banner
says it serves "RSA (PSS signatures) and Ed25519", not ECDSA, "because
ECDSA signing needs ecdsa::SignASN1 which Goish does not have yet". The
reason is false — SignASN1 exists and `crypto::Signer` is implemented
and registered for `ecdsa::PrivateKey` — and I wrote this section up as
a live ECDSA gap on that basis. Then I read the code. `pickCertificate`
defers to `auth::selectSignatureScheme`, which lists the `ECDSAWithP*`
schemes, and the CertificateVerify signs through `auth::signerOf` into
`crypto::Signer::Sign`; the server never names a key type. Nothing
excludes an ECDSA certificate. The banner was stale in its FACT as well
as its reason, and believing the fact because the reason was checkable
nearly put a fictional limitation in this file. No smoke pins an ECDSA
handshake, so "nothing excludes it" is as far as the evidence goes.

**A third instance — DONE 2026-09-06, and it was a deletion.**
`crypto/x509/goish_rsa_der.rs` was a hand-written RSA-only DER walk
whose banner said goish "has `asn1.Marshal` but not `asn1.Unmarshal`
... so none of those three can be ported today", and stated its own
exit condition: "when `asn1.Unmarshal` lands, pkcs1.go and pkcs8.go get
real ports and this file is deleted". `asn1::Unmarshal` had landed and
`pkcs1.rs`, `pkcs8.rs` and `sec1.rs` were all real ports; only the
deletion had not happened, so hand-rolled ASN.1 stayed on the TLS key
path for the commonest key type.

`parsePrivateKey` is now the port rather than something near it:
PKCS#1, then PKCS#8 with a type switch, then SEC 1, matching Go's
tls.go line for line. That fixed a divergence beyond the deletion — Go's type switch
has a `default` arm returning "tls: found unknown private key type in
PKCS#8 wrapping", and goish had none, so a PKCS#8 key of a type it did
not accept (an X25519 ecdh key, which `ParsePKCS8PrivateKey` does
return) fell through to SEC 1 and surfaced as "failed to parse private
key". The bespoke `parse_pkcs8_ed25519` went too: `ParsePKCS8PrivateKey`
handles RFC 8410, and `x509_keys_smoke` pins that with an Ed25519
PKCS#8 vector.

Validated by running the smokes, not by reading: asn1_smoke 13/13,
x509_keys_smoke 91 checks / 0 failures, tls_common_smoke 1473 checks /
0 failed, tls_ref_smoke 70/70, https_server_smoke OK. crypto --by-decl
still 1720/1720; crypto/x509 176/176.

**The work:** point the four call sites (`keygen.rs` twice,
`pkcs1v22.rs` twice) at the real package and delete the shims.

**Two things make it more than a rename, both found 2026-09-06 while
scoping it.** First the bounds: `drbg::ReadWithReader` takes `&mut (dyn
io::Reader + Send + Sync + 'static)` and so does
`randutil::MaybeReadByte`, while `fips140/rsa::GenerateKey` — the
public entry point — takes a bare `&mut dyn io::Reader`. Wiring them up
means widening a public crypto signature, not editing a call site.

Second, and the reason the obvious shortcut is wrong: adding
`MaybeReadByte` to the shim would CREATE a divergence rather than
remove one. Go calls it only on the non-default path —

    if _, ok := r.(DefaultReader); ok { Read(b); return nil }
    fips140.RecordNonApproved()
    randutil.MaybeReadByte(r)

— and goish's callers normally pass `crypto::rand::Reader`, which is
that default. A shim that called MaybeReadByte unconditionally would
consume an extra byte where Go consumes none. Any fix has to carry the
DefaultReader test with it, and that test is `goish::cast!`, which
needs the same bounds as above. So the order is: widen the signature,
then delete the shims, then pin the whole thing with a fixed-reader ref
smoke — which is also the only thing that would have caught the
original divergence. The
signatures differ — the shims take `&mut [byte]` where drbg takes
`&mut slice<byte>` — so it is a real edit, not a rename, and it moves
the RSA key path. It wants a ref smoke over a fixed reader first, which
would also pin item 1.

## 2r. Leftover temp directories are a defect signal, not untidiness

2026-09-07. `os::RemoveAll` followed symlinks and deleted what they
pointed at (28367c7). It was found because a smoke PASSED and left its
temp tree on disk — and once found, /tmp turned out to hold a week of
the same evidence:

    80  goish_dirent*                each containing exactly one entry: a symlink
     1  goish-chmod-symlink-smoke    a DANGLING relative link
     1  goish-evalsymlinks-smoke     a symlink CYCLE, cycA -> cycB -> cycA
    38  goish_link*                  each containing one symlink

Dated Sep 1 through Sep 7 18:10 — the newest an hour before the fix.
After it, every one of those smokes leaves nothing. Three different
symlink shapes, one bug, a week of unread evidence.

**Why this beats reading the code:** a failing cleanup is invisible to
the smoke (its cleanup is `let _ = os::RemoveAll(...)`, and rightly so)
and invisible to e2e (which reads the exit status). It is visible only
in the filesystem afterwards, and only if someone looks.

**It can now be a gate, and that took tidying.** A leftover only means
something if the ones left BY DESIGN are gone. Six smokes cleaned only
at the START — idempotent, but permanently littering — and now clean at
the end as well: http_fileserver_dir_smoke, os_readfile_smoke,
os_readdir_smoke, http_fileserver_range_smoke, osfile_offset_ref_smoke,
osfile_error_ref_smoke. One more, `goish_os_rename_ref`, was debris
from a smoke that no longer exists and is simply deleted.

After that, running the ten filesystem smokes leaves /tmp with ZERO
`goish*` entries. So a post-run `ls -d /tmp/goish*` is now a clean
signal, and wiring it into e2e as a gate is a small change with no
known exceptions to carve out. Whoever does it should keep the two
causes apart in the message — "cleanup failed" is a defect, "no cleanup
written" is untidiness — because only the first is worth failing a
build over.

## 2q. os.Root is ported except FS

Landed 2026-09-07 across five commits: the walk (`doInRoot`,
`splitPathInRoot`, openat + O_NOFOLLOW) and `Root`, `OpenRoot`,
`OpenInRoot`, and Root's `Name Close Open OpenFile Create OpenRoot
Stat Lstat Readlink ReadFile WriteFile Mkdir MkdirAll Remove RemoveAll
Rename Link Symlink Chmod Chown Lchown Chtimes`. Pinned by five ref
smokes (20+21+15+19+14 rows), each rule verified by its own
perturbation.

**COMPLETE 2026-09-13.** `Root.FS` and the `rootFS` adapter landed with
all four optional interfaces — `StatFS ReadFileFS ReadDirFS
ReadLinkFS` — and `dirFS` gained the `Lstat`/`ReadLink` pair Go 1.25
added for `io/fs.ReadLinkFS`. `examples/root_fs_ref_smoke.rs` pins 77
rows; perturbing `isValidRootFSPath` to accept everything turns 11 red.

The reference is worth reading for the contrast in its last row: the
same symlink out of the tree is refused by `Root.FS()` (`statat escape:
path escapes from parent`) and followed by `os::DirFS` (`data=
"SECRET"`). Both are Go's answers. One is a boundary and one is a
prefix.

Four defects the reference found, none NUL-related:

  * `os::ReadDir` opened without `O_DIRECTORY`, so a regular file was
    opened happily and failed at the first getdents. Go's `openDir`
    lets the KERNEL refuse it, which is why Go says `open ok.txt: not
    a directory` where goish said `readdirent`.
  * Worse, in the same function: the fd was closed BEFORE the error was
    built, and `fdErr` reports `ErrClosed` whenever `fd < 0`. Every
    getdents failure — every one, not just this input — came back as
    "file already closed" with the real errno thrown away.
  * `Root.Open` named the `File` by the name relative to the root. Go
    uses `joinPath(root.Name(), name)`, so every File-level error from
    a Root-opened file (`readdirent`, `stat`, `read`) named a fragment
    that resolves against the process cwd instead. `Root.OpenRoot` had
    the same bug, and there it compounds: a nested Root's Name is what
    the next `joinPath` builds on.
  * `dirFS` did none of Go's five `err.(*PathError).Path = name`
    rewrites, so its errors named the joined path. Go does it in
    `Open ReadFile ReadDir Stat Lstat` and deliberately NOT in
    `ReadLink` — measured, and now pinned both ways.

**AND A DEFECT FOUND WHILE PREPARING THAT PORT, 2026-09-13 — issue
#29.** `Root.FS`'s guard in Go is `isValidRootFSPath`, which is
`fs.ValidPath` plus a Windows check. Reading it raised the question of
whether `fs.ValidPath` is enough, because `dirFS.join` in this tree
already answers no — its comment records that ValidPath checks path
ELEMENTS, not bytes, so `"f\0junk"` passes and then truncates at the C
string boundary.

Measured, and it is worse than a `Root.FS` concern: the whole `os`
surface has it.

    fs::ValidPath("f\0junk")        true
    Root.ReadFile("f\0junk")        err=<nil> data="SECRET"
    os::ReadFile("<dir>/f\0junk")   err=<nil> data="SECRET"

Go 1.25.5 refuses all of them with `openat f\x00junk: invalid
argument`, and `fs.ValidPath` is true THERE TOO — so Go's protection is
not the path check. It is `syscall.BytePtrFromString` at the syscall
boundary, which every wrapper goes through and which returns EINVAL for
an embedded NUL.

Not a containment escape: the truncated path stays inside the root. It
is a name/identity mismatch, which matters most for `Root` precisely
because `Root` exists to be a validated boundary — a caller that checks
a name and passes it in does not get the file it checked.

The fix is Go's chokepoint, not scattered checks: one checked
string→C-string helper returning EINVAL, with the 41 inline `push(0)`
sites under `src/os/` routed through it. The construction is uniform
and scriptable; what is not is the `PathError` Op each site returns.

Reported rather than patched, because a partial fix is worse than none
here — "NUL is rejected" is exactly what a caller would generalise from
`Root` to `os`. `Root.FS` should land on top of it, not before it.

**FIXED 2026-09-13.** `syscall::ByteSliceFromString` is the chokepoint;
every `push(0)` under `src/os/` now goes through it, `os/exec`
included, and `examples/nul_path_ref_smoke.rs` pins 49 rows against Go
1.25.5 — every entry point, both error shapes, and the two `.data`
rows that say the refused read returned nothing.

Writing the reference found FIVE more defects that the fix alone did
not close, which is the argument for pinning every entry point rather
than trusting the chokepoint:

  * `Root.Symlink` and `Root.MkdirAll` do not use `__path_op`, so they
    kept the bug after it was "fixed" — both answered "file exists"
    about the truncated name.
  * `Root.Lstat` reported op `lstatat`. Go has one `rootStat` behind
    Stat and Lstat and it says `statat` for both. Nothing pinned it.
  * `Root.RemoveAll` reported `statat` from the inner lstat; Go names
    the op the caller asked for, `RemoveAll`.
  * `os.RemoveAll` reported `lstat`; Go reaches `unlinkat` by way of
    the parent fd.

Two came with the fix, both in `os/exec` and both worse than the file
case because a truncated exec path runs a DIFFERENT BINARY:

  * `Cmd.Start` never called `environ()`. The function was ported —
    dedup, the PWD-from-Dir rule, and `dedupEnv`'s NUL rejection — and
    only `Cmd.Environ()` called it, so the child was built from a raw
    `Env`/`os::Environ()` and `Env: ["A=b\0c"]` reached execve
    truncated to `A=b`.
  * Go's `startProcess` pre-flight `Stat` of `Dir`, with the
    `PathError`'s Op rewritten to `chdir`, was missing. Without it a
    bad `Dir` surfaced as the child's `fork/exec <Path>` errno, naming
    the wrong path.

STILL OPEN, filed separately: `os::RemoveAll` recurses by path where
Go recurses by parent fd (`removeall_at.go`). That is a TOCTOU
difference, not only an error-string one.

**Two divergences, both deliberate.** `MkdirAll` walks a prefix at a
time where Go uses one walk with a custom `openDirFunc` that creates
missing intermediates (root_openat.go:170, the only caller that passes
one). Each prefix is an independent resolution, so an escape anywhere
is refused before anything is created — more syscalls, identical
permissions, and the walk does not grow a parameter for one caller.
`Chmod`, `Chtimes` and `Stat` detect a final-component symlink with a
NOFOLLOW fstatat and hand it to the walk, because Linux has no working
AT_SYMLINK_NOFOLLOW for fchmodat: following is the walk's job, never
the kernel's.

**Three defects were found by the references, all in code written the
same hour, and every one had every other row passing.** They are worth
listing because they are three different ways for a guarded path to go
wrong:

  * `Root.Stat` passed flags=0 to fstatat, so the KERNEL followed a
    symlink out of the root and described a file the caller must not
    see. A shared guard does not cover the final step.
  * `Root.RemoveAll` FAILED OPEN. `RemoveAll("../victim")` returned
    nil: the escape surfaced as a Remove error and the "already gone is
    not an error" branch swallowed it. A refusal reported as success is
    the worst shape a check can fail in, and it is invisible to any
    test that only asks whether the happy path works.
  * `Root.MkdirAll` double-wrapped its error, reporting the prefix it
    failed on nested inside the original path.

The rule that caught all three: give EVERY operation the same
refusals — "..", an absolute path, and a symlink pointing outside —
rather than one row saying it works.

## 3. Gaps other packages will hit next

Re-measured 2026-09-04; four of the five entries this section used to
carry were stale.

- `reflect` is **58/353 (16.4%)** — the largest gap by count outside
  `runtime`. The parts `encoding/asn1` and `encoding/json` need are
  done.
- `iter` is **0/4**: the `Seq`/`Seq2` shapes are real and used across
  `strings`, `bytes`, `slices` and `maps`, but Go's `Pull` and `Pull2`
  are absent. The old "squatter, no anchors" reading undersells it —
  what is missing is the pull adapter, not the iterator model.
- `internal/godebug` is still absent, so every `GODEBUG` branch takes
  the unset default. Ported verbatim and marked unreachable.
- ~~`net/netip` is absent entirely.~~ **Present** — 1825 lines, with
  `netip_ref_smoke` and `netip_ctor_ref_smoke` against a running Go.
- ~~`net::IP` is IPv4-only.~~ **Not true** — `IP` holds 4, 16 or 0
  bytes. (The IPv4-only wildcard in `net`'s listener is a separate,
  pinned divergence.)

Whole-subtree coverage, same measurement:

| subtree | ported | % |
|---|--:|--:|
| `crypto` | 1431/1447 | 98.9% |
| `io` | 74/79 | 93.7% |
| `net` | 966/1413 | 68.4% |
| `archive` | 79/182 | 43.4% |
| `os` | 148/366 | 40.4% |
| `encoding` | 234/999 | 23.4% |
| `text` | 47/271 | 17.3% |
| `runtime` | 88/2722 | 3.2% |

`text/template` (0/224) and `archive/zip` (0/69) are the largest
single unported packages with a plausible port; `encoding`'s remaining
gap is mostly the new `encoding/json/v2` internals.

## 4. Keeping the tooling honest

The pre-flight scripts exist because each of them has been wrong once,
in a way that cost a session:

- `port_deps.py` — reports SQUATTER for a path with no anchors and zero
  coverage; follows `pub use` re-exports; skips Go files a linux/amd64
  build never compiles. Three false blockers came from missing these.
- `port_coverage.py` — separates assembly stubs from portable work,
  drops build-tag routes goish did not take, flags UNVERIFIED names, and
  supports `// go: waived <Symbol> — <reason>` for a declaration goish
  resolves elsewhere (a `//go:linkname` pair, say). Waived decls leave
  the denominator but print on their own line, and the reason is
  mandatory, so a gap cannot be laundered into 100%.
- `anchor_by_name.py` — anchors an already-written port by name, using
  the enclosing `impl` block to disambiguate a shared method name. Its
  `--dry-run` is what exposed the tls squatter.

Anything a tool asserts should be re-checked against Go before it
changes a plan. Five wrong-leverage calls this cycle came from trusting
a number; the fifth was produced by the tooling itself.

## 2m-fixed. httputil.ReverseProxy is a Handler now

**Found 2026-09-05, fixed 2026-09-06.** goish had two unrelated
reverse proxies. `reverseProxyHandler` is unexported, is what
`NewSingleHostReverseProxy` returns, and had the only `ServeHTTP`.
`ReverseProxy` is the exported struct with `Rewrite`, `Director`,
`FlushInterval`, `ErrorLog`, `ModifyResponse`, `BufferPool` and
`ErrorHandler`, every supporting method implemented — and no
`ServeHTTP` and no `impl Handler`. The compiler said so:

    the trait bound `ReverseProxy: net::http::Handler` is not satisfied

So the exported API was unreachable. `ModifyResponse` and the rest
were inert not because they were unwired but because the type could
not be invoked at all — the ResponseController and CGI-Flusher shape
one level up, where every piece is individually correct and tested and
the assembly is missing.

Two things kept it hidden. The struct's own doc called `ServeHTTP`
"staged" because it "needs the streaming response copy, which needs
Body as io.ReadCloser", and that reason had gone stale: `Response.Body`
is an `io::Reader` and the slim handler had been streaming through it
for some time. And the ANCHOR for `ReverseProxy.ServeHTTP` sat on
`reverseProxyHandler`'s `ServeHTTP`, so every provenance tier saw the
function as ported.

`ServeHTTP` is now ported from the pieces the file already had, plus
the `Transport` field Go reads first and goish lacked. The anchor sits
on the port; the slim handler is marked goish-only.
`http_reverseproxy_ref_smoke` pins seven rows against Go — the
Director and Rewrite paths differ deliberately on X-Forwarded-For,
both assert the Connection-named hop-by-hop header does not reach the
client, ModifyResponse's error gives 502, ErrorHandler overrides it,
a 3xx is relayed rather than followed, and Director-plus-Rewrite is
Go's documented error.

Writing that smoke found a second, unrelated defect: `Client.do`
closed the hop's response body BEFORE calling `CheckRedirect`, so
`ErrUseLastResponse` returned a response whose body had already gone.
Go closes it at the top of the next iteration, only once it commits to
following, and that distinction is the whole contract Go documents as
returning the response "with its body unclosed". Fixed with it.

### Still open, deliberately

Two decisions were left alone rather than guessed at.

  1. `NewSingleHostReverseProxy` still returns the slim handler, not a
     `*ReverseProxy` as Go's does. Changing it would retire
     `reverseProxyHandler` and match Go, but it changes an exported
     signature every existing caller uses.
  2. `FlushInterval` is still not honoured — see the addendum below,
     which is unchanged and is the reason. The body is flushed after
     every write instead, which is what the slim handler does and the
     only thing a borrowed writer can do. This is stated on the struct
     rather than left silent.

### 2m addendum: why FlushInterval is still not honoured

Attempting the port turned up a second, harder problem, and it
is the one part that did NOT get fixed with the rest of 2m. `copyResponse`
— the method that gives `FlushInterval` its meaning — takes

    dst: Arc<dyn ResponseWriter + Send + Sync + 'static>

but `Handler::ServeHTTP` receives

    w: &(dyn ResponseWriter + Send + Sync + 'static)

and there is no way from the second to the first. The server builds its
writer as a stack local (`let w = response::__new_with_cnc(conn, cnc)`,
server.go's serve loop) and passes `&w`; nothing owns it in an `Arc`.

The `Arc` is not incidental. `maxLatencyWriter` arms its flush through
`time::AfterFunc`, whose closure must be `'static`, so the writer has
to be shared-owned rather than borrowed. `copyResponse` is therefore
not merely uncalled — it is UNCALLABLE from the one place Go calls it,
and `http_maxlatency_smoke` passes only because it constructs an
`Arc::new(counting)` writer of its own.

That is why the slim `reverseProxyHandler` flushes after every write
instead: it is the only thing a `&dyn` writer can do. Its comment says
so ("Go gets the same effect via ReverseProxy.FlushInterval / the
periodicFlusher") without noting that the Go route is closed here.

Three ways out, none of them local:

  1. `Handler::ServeHTTP` takes an `Arc<dyn ResponseWriter>`. Matches
     what the proxy needs; changes the signature every handler in the
     tree implements.
  2. The serve loop allocates its `response` into an `Arc` and hands
     out a clone. Contained to the server, costs an allocation per
     request, and needs the same change in `server_tls.rs`, which
     builds its own.
  3. Restructure `maxLatencyWriter` so the timer does not outlive the
     call and can borrow. Closest to Go, whose `rw` is an interface
     value copied freely, but needs a cancellation story `AfterFunc`
     does not give.

This belongs with the §0 decisions rather than in a port commit: it is
the same class as "shareable conn for httptrace", and probably the
same answer.
