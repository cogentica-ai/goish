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
| `record.rs` | 1145 | 1 | invented. `conn.rs` is Go's record layer, ported with 55 anchors, and both are live. **Diffing it against conn.rs on 2026-09-04 produced three security defects** — two missing length bounds and a padding oracle — each fixed with a smoke. A fourth, a discarded RNG error, was reported and then retracted: `crypto::rand::Read` calls `fatal` on failure, so the `let _ =` could not leave a zero IV. The file header carries the retraction and lists what was checked clean. Retiring it is still the goal; until then it is no longer unexamined. |
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

Scope worth carrying: none of the three defects is reachable from
`tls::Dial`. That runs Conn::Handshake -> handshakeContext ->
clientHandshake -> the ported clientHandshakeStateTLS13, which was
traced rather than assumed. handshake_client_tls13.rs's header claimed
the invented client was "the live TLS 1.3 client"; it is not, and that
is corrected. The invented family is public API, which is why the
defects were worth fixing rather than waiting for retirement.

`handshake_client.rs` and `handshake_server_tls13.rs` are no longer
squatters — they carry 22 and 19 anchors.

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
delegation), regexp (2c; its no-linear-time divergence re-measured and
still true, and its NFA mentions are citations of Go's reference
behaviour, not claims about goish's algorithm), record.rs and
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

## 2c. `regexp` does not keep Go's linear-time guarantee

Go's regexp documents that it "is guaranteed to run in time linear in
the size of the input", and keeps it by simulating an NFA (RE2).
goish's is a BACKTRACKING matcher — its own header says so — and is
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
