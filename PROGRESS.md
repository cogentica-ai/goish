# Progress

Where the port actually stands, and how much of it is *proven* rather
than merely counted. Numbers are regenerated with
`scripts/port_coverage.py`; the last refresh was 2026-08-12.

## The whole tree — 3156 / 7938 functions (39.8%)

Across 179 in-scope packages of the Go 1.25.5 standard library: **134
have a port, 86 are at 100%**, and there are **2358 provenance
anchors**.

The anchors are not spread evenly, and that is the single most important
thing on this page. **`crypto/` holds 92% of them.** Coverage says a
name exists; an anchor is what lets goishlint diff the port against the
Go file it came from.

| subtree | ported | % | anchors |
|---|--:|--:|--:|
| `crypto` | 1192/1452 | 82.1% | **2181** |
| `net` | 308/1794 | 17.2% | 9 |
| `math` | 307/661 | 46.4% | 5 |
| `encoding` | 210/1018 | 20.6% | 125 |
| `compress` | 122/151 | 80.8% | 0 |
| `os` | 112/366 | 30.6% | 2 |
| `bytes` | 84/107 | 78.5% | 1 |
| `strings` | 76/101 | 75.2% | 1 |
| `archive` | 71/182 | 39.0% | 0 |
| `time` | 71/184 | 38.6% | 4 |
| `sync` | 66/126 | 52.4% | 0 |
| `hash` | 65/114 | 57.0% | 26 |

So: `compress` at 80.8% and `crypto/x509` at 100% are not comparable
claims. The first means 122 functions share a name with Go's; the second
means 158 functions were each diffed against the Go source and their
outputs checked byte-for-byte against a running Go. Treat unanchored
subtrees as working code, not as verified ports.

`iter` (0/4) and `database` (0/137) have directories but no ported
functions. `iter` is a squatter — goish fakes Go 1.23 iterator support
with slices wherever it is needed.

## crypto/ — 1404 / 1452 functions (96.7%)

**65 of the 66 crypto packages are at 100%.** The single exception is
`crypto/tls`, which holds all 48 remaining functions — and by
declaration those split **35 real + 24 QUIC** (see below).

| | |
|---|--:|
| ported | 1404 |
| remaining, portable | 48 |
| remaining, assembly stubs | 0 |
| waived (resolved elsewhere by design) | 2 |
| provenance anchors | 2919 |
| unverified names (see below) | 0 |

Complete and byte-checked against Go: `x509` (158/158), `ecdsa`,
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

## The percentages are optimistic, and by how much

`port_coverage.py` counts **unique names, not declarations**. Go methods
that share a name across types collapse into one entry — and a name
counts as ported when **any one** type implements it.

| | |
|---|--:|
| crypto/ Go declarations (receiver-qualified) | 1780 |
| unique names — what the metric counts | 1493 |
| invisible to the metric | **287 (16%)** |

`crypto/tls` is the extreme case: **727 declarations behind 296 counted
names**, because `marshal`/`unmarshal` repeat across fifteen message
types. `handshake_messages.go` alone is 52 declarations → 17 names. So
porting a seventh `marshal` method cannot move the number, and the
first one made all fifteen look done.

This was found by measurement, not estimate: six verbatim message ports
landed with byte-exact vectors and the percentage did not move.

`--by-decl` reports the receiver-qualified figure, on both sides:

| | by name | by declaration |
|---|--:|--:|
| crypto/ | 1404/1452 (96.7%) | **1674/1733 (96.6%)** |
| crypto/tls | 248/296 (83.8%) | 315/374 (84.2%) |

`--by-decl` had an understating defect of its own, found the same way:
15 ported, anchored declarations read MISSING because goish ports a Go
method whose receiver is a `&mut` value type as a *free fn* (sha1's
`digest.checkSum`, des's `desCipher.generateSubkeys`, …), and the
matcher only synthesized `Recv.Method` keys from Rust `impl` blocks.
The fix credits an anchored `Recv.Method` when the fn exists in the
same file — sound now that `anchor_check.py` verifies every range
names exactly that declaration and `make lint` gates on it. With that,
the residual gap is exactly the remaining tls work: 35 handshake/dial
declarations plus 24 QUIC declarations awaiting a scope decision.

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

271 examples are declared in `Cargo.toml` and run by `make e2e` at
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

Each is reproduced and recorded rather than worked around. All three
need `make e2e-full` to validate, so none is bundled into a port.

- **`Timer::Stop()` does not cancel the sleeping goroutine.** The
  watcher exits; the `Sleep` under it runs to completion. Harmless to
  program exit since main's return now terminates the process (Go's
  rule), but a stopped timer still occupies a goroutine for its full
  duration. Was previously fatal: it held ten examples for 60 s each
  and turned CI red at `timeout: 10, fail: 0`.
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
