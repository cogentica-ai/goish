# Roadmap

What is left, in the order it makes sense to do it. Current state lives
in [PROGRESS.md](PROGRESS.md); conventions and the rules a port must
follow live in [CONTRIBUTING.md](CONTRIBUTING.md).

## 1. `crypto/tls` — the record layer is the last invented code

**Re-measured 2026-09-04.** Everything this section used to describe as
unwritten is written: `port_coverage.py crypto --pkg tls` reports
**275/291 = 94.5%** across 21 Go files and 891 anchors, and every file
the old order-of-work table listed — alert, common_string, defaults,
prf, cipher_suites, auth, ticket, key_agreement, conn,
handshake_client, handshake_server, handshake_server_tls13, common,
ech, quic, cache — now exists as an anchored port.

The 16 remaining declarations are **all QUIC**: HandleData, NextEvent,
Start, StoreSession, SetTransportParameters and the eleven `quic*`
helpers. Five more are already waived by design.

What is left of the demolition:

| file | LOC | anchors | state |
|---|--:|--:|---|
| `record.rs` | 938 | 0 | invented. `conn.rs` is Go's record layer, ported with 55 anchors, and both are live. **Diffing it against conn.rs on 2026-09-04 produced four security defects** — two missing length bounds, a padding oracle, and a discarded RNG error — each fixed with a smoke. The file header lists what was checked clean. Retiring it is still the goal; until then it is no longer unexamined. |
| `session.rs` | 145 | 0 | invented. |

`handshake_client.rs` and `handshake_server_tls13.rs` are no longer
squatters — they carry 22 and 19 anchors.

Worth reading before planning the retirement: this section used to
describe record.rs as a tidiness problem. It was a security backlog.
Four defects in one afternoon, all of the same shape — invented crypto
that no test had ever compared to the Go it replaces — and none of them
would have been found by the coverage or anchor tiers, because the file
claims to port nothing. Retire `record.rs` and
`session.rs` the way the ecdsa eviction was sequenced: the live
handshake is behind `tls_smoke` and the tier-3 (×50) stress family, so a
regression there is an outage rather than a test failure. Dispatch
`e2e-race.yml -f mode=full` after each swap.

## 2. Runtime defects blocking a clean CI

1. **`Timer::Stop()` and the `Sleep` beneath it.** `tick.rs` now calls
   `timer_cancel` and documents the ordering (the flag must be visible
   before the wake). Re-verify before acting on this entry — the text
   here predates that code.
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

All three now carry a "What has been diffed against Go" block listing
what was checked CLEAN as well as what was fixed, so the next reader
starts where this left off rather than repeating it.

`scripts/example_coverage.py` finds packages no example imports. The
equivalent for this class is a one-liner — every `.rs` over 200 lines
with zero `go: sdk` anchors — and the remaining candidates are
`encoding/json/jsontext/mod.rs` (1500) and `runtime/netpoll/mod.rs`
(1112). `crypto/ssh/mod.rs` (1235) was read and is invented with no Go
counterpart at all; its header says what that means.

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

The fix is the RE2 construction: compile to an instruction program and
simulate the NFA with a thread list (`regexp/exec.go` plus
`regexp/syntax/`). That is a rewrite of the matcher rather than a patch
to it. A step budget was considered and rejected — it trades an
unbounded hang for a wrong answer on patterns Go answers correctly.

## 2d. The JSON parsers recurse where Go's do not

`encoding/json`'s v1 scanner keeps an explicit `parseState` stack; both
goish JSON parsers are recursive descent. Go can therefore afford
`maxNestingDepth = 10000` at no stack cost, and goish cannot.

Measured 2026-09-05 in a DEBUG build — the profile `make e2e` uses — on
an 8 MiB goroutine stack: without a pivot at the recursion site, depth
8000 SIGSEGVs; with `maybe_grow`, 8000 survives and 8500 does not. The
implementation ceiling is near 8200, below Go's limit.

`encoding/json` therefore refuses past **2000**, roughly a 4x margin,
and that divergence is deliberate: rejecting a document Go accepts is a
divergence, crashing on one is a denial of service. `jsontext` keeps Go's
10000 — its frames are leaner and 10000 was measured safe there.

The fix is Go's design: replace the recursion with an explicit state
stack, after which both can carry Go's number. That is a rewrite of the
parser loop rather than a patch.

Worth noting for anyone verifying a change here: `PROFILE ?= debug` in
the Makefile, so `make e2e` builds DEBUG. A `cargo build --release`
check passes at depths the debug build faults on — which is how the
first version of this limit reached CI.

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
and that nothing under `src/` calls. On its own that is 29 + 227
findings, most of them legitimate — `container/list`'s `Front` is API
for users, and an example is its rightful only caller. So it asks Go's
own tree the discriminating question: does Go's stdlib call this symbol
from some other file? That cuts the list to 29, every one worth reading.

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

Fixed so far, one per finding read:

  - `Redirect` did not call `hexEscapeNonASCII`, so the Location header
    went out unescaped.
  - `Getwd` did not call `SameFile`, so it never honoured `$PWD` and
    returned the physical path where Go returns the symlinked one.

Read and found NOT defects, which is the other half of the work:

  - `cloneURL` / `cloneMultipartForm`. Go's `Request.Clone` needs them
    because Go copies a struct by value and the pointers inside stay
    shared. goish's `slice` is a `Vec` and its `map` clones
    element-wise, and `URL`/`Userinfo` are by-value, so `derive(Clone)`
    already deep-copies. Redundant, not missing.
  - `didEarlyClose` / `bodyRemains` / `registerOnHitEOF`. All three
    serve Go's STREAMING request body. goish materialises the body into
    a `slice<byte>` before the handler runs, so there is no
    early-closed stream to get out of sync with — `closedRequestBodyEarly`
    is documented as always-false for that reason, and it is right.

The count drops by one each time a call is added, so it is a worklist
that measures its own progress. What is left is unread. They are not
all defects — the question to ask of each is whether Go's call is one
goish should be making too. Run:

    scripts/dead_port_check.py          # the ranked list
    scripts/dead_port_check.py -v       # including the quiet 227

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
