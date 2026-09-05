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

## 2f. Two thirds of the FIPS CASTs are not ported

`dead_port_check` flagged `crypto/internal/fips140/aes/gcm`'s
`DeriveKey` because Go's only non-test caller of it is that package's
`cast.go`. Following that up turns out to name something larger than
one call: Go has 18 `cast.go` files under `crypto/internal/fips140`
and goish ports 6.

Present: the root `cast.go`, `ecdh`, `rsa`, `nistec/fiat`, `ed25519`,
`ecdsa`.

Missing: `pbkdf2`, `sha512`, `tls12`, `tls13`, `sha3`, `hmac`,
`mlkem`, `drbg`, `hkdf`, `aes`, `aes/gcm`, `sha256`.

A CAST is a known-answer self-test that FIPS 140-3 requires an
algorithm to pass before it is used. The port has the mechanism —
`fips140::CAST` exists and six modules call it — so this is not a
design gap, it is twelve unported files. Whether it matters depends on
whether the fips140 tree is meant to be structurally faithful or
merely to compute the right answers, which is a decision that has not
been written down anywhere.

Note what this is NOT: evidence that the twelve algorithms are wrong.
Their outputs are diffed against Go elsewhere. It means goish would
not NOTICE if they became wrong, which is the entire point of a CAST.


The count drops by one each time a call is added, so it is a worklist
that measures its own progress. What is left is unread. They are not
all defects — the question to ask of each is whether Go's call is one
goish should be making too. Run:

    scripts/dead_port_check.py          # the ranked list
    scripts/dead_port_check.py -v       # including the quiet 227

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

## 2i. Response header ORDER differs from Go

Found while diffing multipart range responses byte for byte. goish
sorts every response header, including `Connection`, into one block:

  Go     Accept-Ranges, Content-Length, Content-Type, Date, Connection
  goish  Accept-Ranges, Connection, Content-Length, Content-Type, Date

Go writes the user's headers sorted and then appends Date and
Connection through `extraHeader`, so those two land last. goish puts
Connection in the header map, where it sorts alphabetically.

Header order is not significant in HTTP, so this is cosmetic — but it
is a real difference, and anything doing a byte comparison of a
response (a cache key, a recorded fixture, a proxy test) sees it.
http_multirange_smoke normalises the order on BOTH sides and says so,
rather than pretending the responses match exactly.

Not fixed here because the change is in the shared header writer, and
every pinned smoke that records a response head currently encodes
goish's order. Doing it means re-measuring all of them in one pass,
which is a job on its own rather than a rider on a range test.

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
