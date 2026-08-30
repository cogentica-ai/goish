# Progress

Where the port actually stands, and how much of it is *proven* rather
than merely counted. Numbers are regenerated with
`scripts/port_coverage.py`; the last full refresh was 2026-08-15, with
the `compress` row refreshed 2026-08-17 and the `hash` and `encoding`
rows 2026-08-30.

## The whole tree — 4452 / 11061 functions (40.3%)

Across the 169 packages of the Go 1.25.5 standard library that have a
goish port: **89 are at 100%**, and there are **5477 `// go:`
provenance lines**, 3484 of them `sdk` anchors citing the exact Go
file and line range.

The anchors are not spread evenly, and that is the single most important
thing on this page. **`crypto/`, `net/` and `testing/` together hold
92% of them.** Coverage says a name exists; an anchor is what lets
goishlint diff the port against the Go file it came from.

| subtree | ported | % | anchors |
|---|--:|--:|--:|
| `crypto` | 1431/1447 | 98.9% | **3041** |
| `net` | 788/1413 | 55.8% | **1570** |
| `math` | 307/661 | 46.4% | 5 |
| `testing` | 217/247 | 87.9% | 402 |
| `encoding` | 215/1018 | 21.1% | 156 |
| `compress` | 148/151 | 98.0% | 83 |
| `os` | 112/366 | 30.6% | 3 |
| `bytes` | 84/107 | 78.5% | 1 |
| `strings` | 76/101 | 75.2% | 1 |
| `archive` | 71/182 | 39.0% | 0 |
| `time` | 71/184 | 38.6% | 4 |
| `sync` | 66/126 | 52.4% | 3 |
| `hash` | 98/114 | 86.0% | 338 |

Within `net`, the entire jump since the last refresh is **`net/http`,
now complete: 639/639 functions (100.0%) across all twelve of its
packages, with 1476 `// go:` lines** — see its section below.

So: `math` at 46.4% and `crypto/x509` at 100% are not comparable
claims. The first means 307 functions share a name with Go's; the second
means 158 functions were each diffed against the Go source and their
outputs checked byte-for-byte against a running Go. Treat unanchored
subtrees as working code, not as verified ports.

`compress` is the clearest illustration of the gap, because both halves
are now visible inside one subtree. Its 42 `// go:` lines — 34 of them
`sdk` anchors — are **all** in `compress/bzip2`, ported 2026-08-17:
20/20 functions by name and by declaration, every one citing
its Go file and line range, and checked against Go's own test vectors
plus seven `testdata/` corpora — 567 KB of English text, 16 KB of
random bytes, a 1 MiB sawtooth and the issue-5747 overrun case — all
byte-identical to a running Go. `flate`, `gzip`, `lzw` and `zlib` carried
122 name-level ports and zero anchors between them. Same subtree, same
percentage column, two different claims.

`flate` has since been split the way `bzip2` already was, one Go file
at a time: **`dict_decoder.go` and `huffman_code.go` are now their own
anchored files**, 10/10 and 18/18, with 41 anchors between them. The
recovered declarations are the ones that had been inlined or replaced
by a Rust idiom — `writeSlice`/`writeMark` at the decompressor's call
site, and `byLiteral`/`byFreq`'s `sort`/`Len`/`Less`/`Swap`, which had
been two `sort_by` closures. `flate` is 89/92 now, with only
inflate.go's three left. The other five Go files are still in `mod.rs`
and still unanchored: 66 of the 89 counted names have nothing behind
them.

Both halves are checked against a running Go rather than against
themselves. Six DEFLATE streams from Go's own compressor — chosen to
drive `dist < length` run-length expansion, the 32 KiB window wrap and
`readFlush`'s cursor reset — inflate to 236 KB that matches byte for
byte; and in the other direction goish's compressor at
DefaultCompression emits **byte-identical output to Go's** for all six,
which is the only check that reaches the Huffman generator's output
rather than its round-trip. Nothing in the format requires two
compressors to agree, so that is a statement about the port, not about
DEFLATE.

`hash` moved for the same reason and in the same shape. **`hash/crc64`
(19/19, 49 `// go:` lines), `hash/adler32` (13/13, 34) and `hash/fnv`
(17/17, 162) are complete and anchored, and `hash/crc32` is 29/33
(87.9%, 71)** — ported 2026-08-30. In each case that is the whole of
every portable Go file in the package, including the fast paths, the
128-bit FNV pair, and the marshal/unmarshal/Clone surface the earlier
slim ports had skipped. None of the four is a name match: `crc64`'s
`Checksum` is checked byte-for-byte against a running Go at eight
lengths straddling both of Go's path thresholds (64 bytes and 2048)
for ISO, ECMA and a custom polynomial, `crc32`'s at nine straddling
its `slicing8Cutoff` of 16 for IEEE, Castagnoli and Koopman,
`adler32`'s at ten straddling its `nmax`=5552 block boundary, `fnv`'s
128-bit digests over six inputs, and every marshaled state — the crc32
and crc64 table checksums included — matches Go's byte for byte.

`crc32`'s remaining 4 are all of crc32_amd64.go: three assembly
symbols (`castagnoliSSE42`, `castagnoliSSE42Triple`, `ieeeCLMUL`) and
`castagnoliShift`, which exists only to feed them. goish ports
crc32_otherarch.go — the `!amd64` half of Go's own build — instead, so
"no hardware CRC-32" is a true statement about this runtime rather
than a stub. `maphash` (20/32) is the one `hash` package still short,
blocked on `internal/abi`.

`encoding/pem` moved the same way, and is the clearest small case of
why the anchor column is the one to read. It counted 5/8 and carried
**zero** anchors: every name in it matched Go by name only, so a
dropped argument or an invented body would have been invisible to
GOISH018. It is now 8/8 with 18 anchors — the three that were missing
are `lineBreaker`'s `Write` and `Close` and `writeHeader`, i.e. the
whole of the 64-column line-breaking Encode does — and its output is
checked byte-for-byte against a running Go on either side of a line
boundary, over the RFC 1421 §4.6.1.1 header ordering, and through
`Decode` over leading junk, trailing junk and an unterminated BEGIN.

`container/list` is the same story one size smaller: 20/23 with zero
anchors, now 23/23 with 35. The three that were missing were `lazyInit`,
`insertValue` and `move` — the whole of the link surgery every public
method funnels through — and its element order is now replayed against
a running Go step by step, including the no-ops Go documents for a
foreign element and for moving an element relative to itself. `ring` (17
anchors) and `heap` (15) followed the same day, so the subtree is
38/38 with **67 anchors and zero unverified names** — the first whole
subtree in the tree where every counted name is one goishlint can diff
against Go.

`text/tabwriter` is the fourth in the same sweep: 17/20 with zero
anchors, now 19/19 with 26 and one declaration waived. The waived one
is `handlePanic`, and it is the honest kind — Go's is a deferred
`recover()` that turns a `panic(osError{err})` thrown deep inside
`format` back into a returned error, and goish v1 aborts on panic
rather than unwinding, so there is nothing to build it on. The error it
carries travels in a latched field instead. Recovered along the way:
`append`, `dump`, and the `vbar`/`hbar` package vars, which had been
inlined as literals. Its output is now checked byte-for-byte against a
running Go across sixteen layouts — every flag, both escape modes, a
ragged table, a form feed and non-ASCII cells.

`encoding/binary` is split rather than finished: varint.go is now its
own anchored `varint.rs` at 8/8 with 13 anchors, including the
`ReadUvarint`/`ReadVarint` pair that was missing, while binary.go's
half stays in `mod.rs`, still 15 unanchored names and still short the
reflection-driven `Encode`/`Decode`/`Size` surface. Both varint
overflow rules are now checked against a running Go, including the one
that refuses to read an eleventh byte at all
(golang.org/issue/41185) — a guard whose absence would be invisible
until it read past a buffer.

`iter` (0/4) and `database` (0/130) have directories but no ported
functions. `iter` is a squatter — goish fakes Go 1.23 iterator support
with slices wherever it is needed.

## crypto/ — 1722 / 1722 declarations (100.0%)

**All 66 crypto packages are at 100% by receiver-qualified
declaration**, with 26 declarations waived out of the denominator on
in-tree justifications (24 of them the QUIC transport surface). The
name-level counter reads 1431/1447 (98.9%) only because the QUIC
waiver is recorded per declaration: the 16 residual *names*
(`quicSetReadSecret`, `HandleData`, …) are exactly that waived
surface. There is no unported non-QUIC function left.

| | |
|---|--:|
| ported (by declaration) | 1722 |
| remaining, portable | 0 |
| remaining, assembly stubs | 0 |
| waived (resolved elsewhere by design) | 26 |
| provenance anchors | 3041 |
| unverified names (see below) | 0 |

Complete and byte-checked against Go: `tls` (the full client and
server handshakes — `handshake_loopback` runs the ported client and
server against each other), `x509` (158/158 by name, 169/169 by
declaration), `ecdsa`,
`ecdh`, `rsa`, `elliptic`, `cipher`, `aes`, `sha1/256/512/3`, `hmac`,
`hkdf`, `pbkdf2`, `mlkem`, `nistec` + `fiat`, `bigmod`,
`edwards25519`, `ed25519`, `dsa`, `rand`, `sysrand`, `drbg`, `entropy`,
`x509/pkix`, `tls12`/`tls13` key schedules, and the rest of the
`fips140` tree.

Assembly stubs are counted separately on purpose: a Go func with no body
is not something you port by reading Go. That column is now **zero** —
`crypto/sha1`, `sha256` and `sha512` read as small gaps for a while and
turned out to be measurement, not assembly (see the `--by-decl` note
below).

## net/http — 639 / 639 functions (100.0%)

**All twelve packages are at 100.0%**, with 1476 `// go:` lines (the
root package alone carries 1085) and 33 declarations waived on in-tree
justifications. This is an anchored port, not a name match: request
and response bodies stream both directions through the ported
`transfer.go` machinery, the client pools connections through Go's
full `getConn`/`persistConn` call graph (idle reaping, GetBody rewind,
sentinel-mapped retries, Expect: 100-continue), and the server runs
`connReader` with Go's total-head byte limit (431/501 paths included).

| package | ported | | package | ported |
|---|--:|---|---|--:|
| `.` (root) | 465/465 | | `cgi` | 15/15 |
| `httputil` | 47/47 | | `pprof` | 13/13 |
| `fcgi` | 28/28 | | `internal` | 12/12 |
| `httptest` | 28/28 | | `internal/ascii` | 5/5 |
| `cookiejar` | 21/21 | | `httptrace` | 4/4 |

`net/http/pprof` serves from a new `runtime/pprof` user-registry
(`Profile.Add` captures real stacks via `runtime::Callers`; `WriteTo`
symbolizes live through `runtime::FuncForPC`); the CPU, trace and
protobuf arms return Go-shaped unsupported errors rather than fake
output.

## testing/ — 217 / 247 functions (87.9%)

The root package is at **141/149 (94.6%)**, and `fstest` (38/38),
`iotest` (11/11) and `slogtest` (10/10) are complete; 402 `// go:`
lines across the tree. `testing.B`, `testing.M` and `t.Parallel()` are
ported. The root's eight missing functions are the fuzzing entry
points (`testing.F` is not ported), the profiling hooks
(`writeProfiles`/`before`/`after`) and the synctest bridge — excluding
fuzzing and profiling, the tree reads 97.3%. Still open: `quick`
(7/14, blocked on a real `reflect` redesign — goish's `reflect` is a
value tree), `internal/testdeps` (10/21, the fuzz/profile plumbing),
and `synctest` (0/4).

## The percentages are optimistic, and by how much

`port_coverage.py` counts **unique names, not declarations**. Go methods
that share a name across types collapse into one entry — and a name
counts as ported when **any one** type implements it.

| | |
|---|--:|
| crypto/ Go declarations (receiver-qualified) | 1722 |
| unique names — what the metric counts | 1447 |
| invisible to the metric | **275 (16%)** |

`crypto/tls` is the extreme case: **350 declarations behind 291 counted
names**, because `marshal`/`unmarshal` repeat across fifteen message
types. `handshake_messages.go` alone collapses 52 declarations → 17
names. So porting a seventh `marshal` method cannot move the number,
and the first one made all fifteen look done.

This was found by measurement, not estimate: six verbatim message ports
landed with byte-exact vectors and the percentage did not move.

`--by-decl` reports the receiver-qualified figure, on both sides:

| | by name | by declaration |
|---|--:|--:|
| crypto/ | 1431/1447 (98.9%) | **1722/1722 (100.0%)** |
| crypto/tls | 275/291 (94.5%) | 350/350 (100.0%) |

`--by-decl` had an understating defect of its own, found the same way:
15 ported, anchored declarations read MISSING because goish ports a Go
method whose receiver is a `&mut` value type as a *free fn* (sha1's
`digest.checkSum`, des's `desCipher.generateSubkeys`, …), and the
matcher only synthesized `Recv.Method` keys from Rust `impl` blocks.
The fix credits an anchored `Recv.Method` when the fn exists in the
same file — sound now that `anchor_check.py` verifies every range
names exactly that declaration and `make lint` gates on it. With the
handshake/dial work now finished, the by-declaration residual is zero;
the 24 QUIC declarations are waived with in-tree justifications (dead
code without a QUIC transport).

The first thing it found was concrete: `crypto/x509` read 100% by name
while missing `CertificateRequest.CheckSignature` and
`RevocationList.CheckSignatureFrom` — both credited because
`Certificate` has same-named methods. Both are now ported, and x509 is
169/169 either way.

The anchors do not have this problem — `anchor_by_name.py` keys methods
by `Recv.Method`, so the 2238 anchors are receiver-qualified and
GOISH018 diffs each one individually. **Anchor counts are the honest
signal; percentages are an upper bound.** Fixing the counter is a small
change to `scan_go` and would restate every figure here downward.

## What "ported" means here

Three tiers, weakest to strongest. The distinction matters because every
one of the defects found this cycle passed the weak tier and failed the
strong one.

1. **Name match** — a goish `fn` shares a Go declaration's name. This is
   what a coverage percentage counts, and on its own it proves nothing.
   `crypto/ecdsa` read "present" for four sessions while holding 915
   lines of hand-rolled P-256 with no Go counterpart.
2. **Anchored** — the fn carries `// go: sdk 1.25.5 <file>:<lines>
   <Symbol>`, so goishlint's fidelity tier (GOISH017-021) opens the Go
   file and diffs signature, arity and struct fields against it. A
   dropped argument or a renamed field fails the build gate.
   **goishlint resolves the symbol by name and never reads the line
   range** — 401 of 1892 ranges were wrong when first measured, some
   pointing hundreds of lines away at a different function.
   `scripts/anchor_check.py` now gates `make lint` on that.
3. **Ground-truthed** — an example asserts values generated by
   `scripts/goref.sh`, which runs a throwaway test *inside* a writable
   GOROOT copy so it can reach unexported symbols. Expectations are
   generated, never transcribed.

`port_coverage.py` reports tier-1 counts and flags anything still at
tier 1 as **UNVERIFIED**. That number went 121 → 3 this cycle, and is
now **0**: the last flag (`prf12`) turned out to be shadowing from
`tls/record.rs` — the hand-written pre-verbatim record layer, which
defines an *invented* `prf12` while the real port sits anchored in
`prf.rs`. record.rs and session.rs now carry explicit goish-only
legacy banners and are slated for deletion once the remaining
handshake declarations replace their call sites.

### Why byte-exactness, specifically

Four defects landed in one package while compiling cleanly and producing
plausible, well-formed DER. A field-comparison test would have passed
every one:

- `reflect::Zero` answered `Invalid` for composite kinds, so `asn1`'s
  OPTIONAL-omission test never fired — an empty element inside every
  `AlgorithmIdentifier` Go writes bare.
- `reflect::Zero(Kind::Interface)` lost the type of a nil interface, so
  `asn1.Unmarshal` into anything reaching an X.509 Name — every CRL —
  failed outright.
- `asn1::ParseBigInt` was not a port at all: it mishandled negative DER
  INTEGERs in both sign and magnitude. Reachable from
  `Certificate.SerialNumber`, which RFC 5280 permits to be negative.
- `crypto/rsa`'s `PrivateKey.Sign` dropped Go's PSS arm, so a caller
  asking for PSS silently received a PKCS#1 v1.5 signature.

Two more of the same shape turned up in `crypto/tls`, and they matter
for what they say about the *lint* tier rather than the port:

- `encryptedExtensionsMsg.marshal` emitted only `alpnProtocol` and
  `serverNameAck`, dropping `quicTransportParameters`, `earlyData` and
  `echRetryConfigs`.
- `serverHelloMsg.marshal` dropped `ocspStapling`, `ticketSupported`,
  `secureRenegotiationSupported`, `extendedMasterSecret`, `scts` and
  `encryptedClientHello` — six extensions.

Both carried a `// go: sdk` anchor naming the exact Go line range.
**GOISH018 compares signatures, arity and struct fields — not the
statements inside a function.** An extension a port forgot to emit is
therefore invisible to tier 2 and visible only at tier 3. There is now a
sweep in `tls_common_smoke` that marshals all seventeen message types
with every field populated and diffs the wire against `goref.sh`; it is
the only thing standing between this class of defect and a release.

## Test suite

417 examples are declared in `Cargo.toml` and run by `make e2e` at
tiered loop counts — deterministic ones once, memory-subsystem ones ×10,
and the race-sensitive scheduler/chan/select/timer/server families ×50.
**Only declared examples run**; an `examples/*.rs` file without an
`[[example]]` block is invisible to CI.

Local verification is `cargo check --lib`, `cargo build --examples`,
`make lint`, and the individual binaries a change touches. `make e2e`
belongs on CI.

### `make lint` is a ratchet

`scripts/lint_baseline.json` records goishlint's finding count per
**(file, rule)**; `make lint` fails only when a pair increases. Two
consequences: a file absent from the baseline must be lint-clean, and
fixing file A cannot pay for a regression in file B. Current total:
13081.

## Known defects, open

Each is reproduced and recorded rather than worked around. Both need
`make e2e-full` to validate, so neither is bundled into a port.
(A third, `Timer::Stop()` leaving its sleeper goroutine pinned, was
fixed in `3b97cc5` — one goroutine per timer, zero post-Stop lifetime,
tripwired by `time_stop_no_pin_smoke`.)

- **`goish::cast!` cannot succeed on a `goany::Any` carrier.** It
  resolves through the blanket `HasDynAny for T`, probing the wrapper's
  `TypeId` and never the payload's. Silent — a comma-ok assertion
  reports `false`. Use `.As::<dyn Trait + Send + Sync>()`. See
  CONTRIBUTING.md §9b.
- **`crypto/ecdsa::PrivateKey` does not implement `crypto::Signer`**
  (Go's does), so an ECDSA key cannot yet sign an X.509 certificate.

### Structural divergences, pinned by assertions

- `time::Parse` rejects a numeric zone offset where Go accepts one —
  `time::Time` carries no `Location`. RFC 5280 requires `Z` in
  certificates, so certificate parsing is unaffected.
- goish value types collapse two Go states into one: `big::Int` (nil vs
  present-and-zero) and `time::Time` (year 1 vs Unix epoch). The common
  case is correct in both; the rare one is documented at the symptom and
  at the cause, with the `goref.sh` bytes for each.

## CI

Two workflows: `e2e.yml` on every push (`make e2e LOOPS=1`) and
`e2e-race.yml` nightly (stress families ×50). Dispatch the full sweep by
hand after any scheduler, allocator or `runtime/` change:

```bash
gh workflow run e2e-race.yml --repo cogentica-ai/goish -f mode=full --ref <branch>
```
