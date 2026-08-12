# Roadmap

What is left, in the order it makes sense to do it. Current state lives
in [PROGRESS.md](PROGRESS.md); conventions and the rules a port must
follow live in [AGENTS.md](AGENTS.md).

## 1. `crypto/tls` — the whole remaining crypto gap

266 of the 266 outstanding crypto functions are here. It is the last
package below 100%, and it is not simply unwritten — it needs a
demolition before it needs a port.

### What is actually there

goish ships a **hand-written TLS client and server** across nine `.rs`
files. Five of them carry no provenance anchor at all, and
`scripts/anchor_by_name.py --dry-run` reports **zero Go counterparts**
in `record.rs`, `session.rs`, `handshake_client.rs` and
`handshake_server_tls13.rs` — not one function Go declares. The names
are invented: `do_client_handshake`, `encrypt_record`,
`derive_master_secret`, `read_record`.

This is the same shape as the `crypto/ecdsa` squatter that read
"present" for four sessions. It read 12.5% ported until
`port_coverage.py` stopped folding underscores, which had been letting
`read_record` count as a port of Go's `readRecord`. The honest figure is
10.1%, and most of even that is unverified.

The working TLS 1.2/1.3 client is *real* — `tls_smoke`, `tls12_smoke`,
`tls_server_smoke` and `https_real_smoke` pass against live servers. It
is simply not a port of Go, so it cannot be counted as one and cannot be
diffed against Go by the fidelity tier.

### Order of work

Go's 21 in-scope files split into layers. Port the leaves first: each
lands as a stem-matching `.rs` file with anchors, and none of them
depends on the invented implementation.

| Go file | LOC | notes |
|---|--:|---|
| `alert.go` | 111 | alert codes + `String`/`Error`. Fully isolated — start here. |
| `common_string.go` | 120 | generated `String()` methods |
| `defaults.go` | 102 | default cipher-suite and curve lists |
| `prf.go` | 296 | TLS 1.0-1.2 PRF, master secret, finished hash |
| `cipher_suites.go` | 724 | suite tables + AEAD constructors |
| `auth.go` | 285 | signature-scheme selection and verification |
| `ticket.go` | 430 | session-ticket encode/decode |
| `key_agreement.go` | 382 | TLS 1.2 key agreement |
| `conn.go` | 1692 | the record layer — replaces `record.rs` |
| `handshake_client.go` | 1333 | replaces `handshake_client.rs` |
| `handshake_server.go` | 1028 | no goish counterpart yet |
| `handshake_server_tls13.go` | 1162 | replaces `handshake_server_tls13.rs` |
| `common.go` | 1805 | `Config`, `ConnectionState` — the type surface everything else hangs on |

`ech.go` and `quic.go` are the largest remaining consumers after that.
`cache.go` needs weak pointers and `runtime.AddCleanup`, which goish
does not have.

Retire the invented files only as their Go counterparts land, the way
the ecdsa eviction was sequenced — the live handshake is behind
`tls_smoke` and the tier-3 (×50) stress family, so a regression there is
a real outage, not a test failure. Dispatch `e2e-race.yml -f mode=full`
after each swap.

## 2. Runtime defects blocking a clean CI

All three are reproduced and recorded (see PROGRESS.md). Each is a
`runtime/`-adjacent change, so each needs `make e2e-full` — all examples
×50 — and none belongs in a porting commit.

1. **Process exit waits for every goroutine.** goish exits when
   `LIVE_G_COUNT == 0`; Go exits when `main` returns and kills what is
   still running. Combined with a `Timer::Stop()` that does not cancel
   its sleeper, this holds ten declared examples for 60 s each and turns
   `make e2e` red at its 15 s timeout. Fixing exit semantics is the
   larger and more correct half.
2. **`cast!` on an `Any` carrier.** Three options were scoped: reject it
   at compile time with a `const` assert pointing at `.As::<>()`
   (cheapest, converts a silent miss into an error), narrow the blanket
   `HasDynAny` impl (needs a marker trait threaded through every
   implementor), or wait for specialization. Documented as AGENTS.md
   §9b in the meantime.
3. **`ecdsa::PrivateKey` must implement `crypto::Signer`** so an ECDSA
   key can sign a certificate. Small and self-contained.

## 3. Gaps other packages will hit next

- `net/netip` is absent entirely. `crypto/x509`'s `matchURIConstraint`
  takes a documented narrowing via `net::ParseIP` instead.
- `net::IP` is IPv4-only, so `marshalSANs` cannot round-trip an IPv6
  SAN.
- `iter` is a squatter: 0/4, no anchors. Go 1.23 iterator support
  (`iter.Seq`) is faked with slices wherever it is needed.
- `internal/godebug` is absent, so every `GODEBUG` branch takes the
  unset default. Ported verbatim and marked unreachable.
- `reflect` is 56/353. The parts `encoding/asn1` and `encoding/json`
  need are done; setter dispatch was added this cycle.

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
