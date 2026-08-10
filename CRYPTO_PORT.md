# crypto/ — 100% verbatim port tracking

Goal: every in-scope `crypto/...` package from the Go 1.25 SDK ported
function-for-function, with machine-checkable provenance, so "100%" is a
number the toolchain reports rather than a claim we make.

Baseline (2026-08-10): 391/1575 = 24.8%, 0 anchors.
Current: **513/1561 = 32.9%**, 444 anchors, **21 packages fully verified**
— each exits 0 under `goishlint --enable-goish017 --enable-goish018`:

| verified | fns | .go → .rs |
|---|--:|---|
| `crypto/rc4` | 4/4 | 1 → 2 |
| `crypto/subtle` | 8/8 | 3 → 4 |
| `crypto/des` | 14/14 | 3 → 4 |
| `crypto/ed25519` | 11/11 | 1 → 2 |
| `crypto/hkdf` | 3/4 | 1 → 2 |
| `crypto/pbkdf2` | 1/1 | 1 → 2 |
| `crypto/hmac` | 2/2 | 1 → 2 |
| `crypto/sha256` | 4/4 | 1 → 2 |
| `crypto/internal/fips140/subtle` | 12/12 | 4 → 4 |
| `crypto/internal/fips140/ed25519` | 28/28 | 2 → 3 |
| `crypto/internal/fips140/hmac` | 10/10 | 2 → 2 |
| `crypto/internal/fips140/sha256` | 16/18 | 6 → 4 |
| `crypto/internal/fips140/sha512` | 17/18 | 6 → 4 |
| `crypto/sha512` | 8/8 | 1 → 2 |
| `crypto/internal/fips140/aes` | 37/45 | 11 → 9 |
| `crypto/aes` | 2/2 | 1 → 2 |
| `crypto/internal/fips140/alias` | 2/2 | 1 → 2 |
| `crypto/md5` | 15/15 | 4 → 4 |
| `crypto/sha1` | 17/19 | 5 → 4 |
| `crypto/internal/fips140deps/byteorder` | 11/11 | 1 → 2 |
| `internal/byteorder` (outside crypto/) | 18/18 | 1 → 2 |
| **total** | **240** | |

The only functions missing from that table are assembly entry points:
`blockAVX2`/`blockSHANI` in fips140/sha256 and in crypto/sha1,
`blockAVX2` in fips140/sha512, and in fips140/aes the seven `*Asm`
symbols plus
`EncryptionKeySchedule` (which exists solely to hand the key schedule to
the GCM assembly, so it lands with that work). They are tracked under
"Assembly" below. Everything else in the table is complete.

The percentage moves slowly because most verified packages were already
name-complete; what changed is that their completeness is now *proven*
rather than assumed, and several real gaps were closed on the way
(`WithDataIndependentTiming`, `aligned`/`words`/`xorLoop`, des's three
missing permutation tables, and sha256's `maxAsmSize` chunking loop in
`Write`). Regenerate:

```bash
export GOROOT=$(go env GOROOT)          # or point at a Go 1.25 checkout
python3 scripts/port_coverage.py crypto            # table
python3 scripts/port_coverage.py crypto --md       # markdown (this doc)
python3 scripts/port_coverage.py crypto --pkg tls  # per-package missing list
```

## Per-package conversion recipe (proven on rc4, subtle, des)

1. `git mv <pkg>/mod.rs <pkg>/<gofile>.rs`, then split along Go's file
   boundaries — one `.rs` per `.go`, same stem. A Rust keyword filename
   (`const.go`) keeps the Go name via `#[path = "const.rs"] mod konst;`.
2. New `mod.rs`: `// go: package crypto/<pkg>` plus `mod`/`pub use` only.
3. Head each file with `// go: file crypto/<pkg>/<f>.go decls: <funcs>` —
   **functions only**; naming a type there reads to GOISH017 as a dropped
   function.
4. `scripts/anchor_port.py src/crypto/<pkg>/<f>.rs` rewrites legacy
   `// Go: f.go:77` markers into real anchors with the Go line span.
   Goish-only helpers get `// go: none — <reason>` and a manifest entry.
5. Run `goishlint --enable-goish017 --enable-goish018 src/crypto/<pkg>/`
   until it exits 0, then the package smoke, then
   `cargo build --examples` (zero diagnostics).

Two traps this surfaced repeatedly:

* **An anchor citing another Go file drags that whole file's contents in.**
  GOISH018 then demands every func of `block.go` inside `cipher.rs`. Keep
  each file's anchors pointing at its own `.go`.
* **A deliberate rename needs `// goishlint:ignore GOISH021 — <reason>`.**
  `desCipher` → `Cipher` (Go returns it behind `cipher.Block`, which goish
  cannot express for a value type) is a rename, not a drop.

### Denominator fix: `//go:build ignore` files

`port_coverage.py` was counting standalone generators — md5's `gen.go`,
nistec's `generate.go`, tls's `generate_cert.go` and four others. They are
`package main` programs behind `//go:build ignore`, which `go build` never
compiles into the package, so their funcs (`dup`, `idx`, `main`,
`relabel`, `rotate`, `seq` …) inflated the denominator with code that is
not part of the library. Skipped now, same rationale as `_asm/`. The
total went 1575 → 1561; nothing "became ported" as a result.

## How "100%" is measured

Three checkers, in dependency order. The last one is authoritative; the first
two exist to make it possible.

| rule | what it enforces | state in crypto/ |
|---|---|---|
| **GOISH014** | every `fn` carries a `// go: sdk 1.25.5 crypto/aes/cipher.go:31-49` anchor (or `// go: none — <reason>`) | 859 missing |
| **GOISH015** | one `.rs` per `.go`; a module root holds only `mod`/`pub use` | 15 violations |
| **GOISH018** | opens the Go file each anchor cites and reports every Go `func` with no anchored Rust counterpart | **cannot run — 0 anchors** |

That last row is the whole problem. `goishlint --enable-goish018` over
`src/crypto/` today reports nothing, not because the port is complete but
because there is no anchor to resolve a Go file from. `scripts/port_coverage.py`
is the stopgap: it name-matches Go `func` idents against goish `fn` idents per
package, which ranks the work but cannot see a body that diverged. Once anchors
land, GOISH018 replaces it as the gate.

## The structural blocker

goish's crypto tree is 47 files, overwhelmingly one `mod.rs` per package:

```
src/crypto/aes/mod.rs          ← Go: crypto/aes/{aes.go,cipher.go,...}
src/crypto/x509/mod.rs         ← Go: crypto/x509/*.go  (14 amd64-relevant files, 7356 LOC)
```

One `mod.rs` absorbing 20 Go files cannot satisfy GOISH015, and its functions
cannot carry meaningful per-file anchors. **Splitting to one `.rs` per `.go` is
a prerequisite for measurement, not a cosmetic cleanup.**

## Closed: the hash-interface blocker

Until 2026-08-10 the sha256 and hmac ports had a shared hole. Go 1.25's
`hash.Hash` implementations also satisfy `encoding.BinaryMarshaler`,
`encoding.BinaryAppender`, `encoding.BinaryUnmarshaler` and the (new in
1.25) `hash.Cloner`; goish's `hash` package declared none of them. That
cost six functions in `fips140/sha256` (`MarshalBinary`, `AppendBinary`,
`UnmarshalBinary`, `consumeUint32`, `consumeUint64`, `Clone`) and the
whole `marshalable` fast path in `fips140/hmac` — the FIPS 198-1 §6
cached-state optimisation, which is most of what makes a reused HMAC
cheap.

What it took:

1. **`hash.Cloner` and `hash.XOF`** added to `hash/hash.go`'s port.
2. **`Hash` and `Cloner` became `#[goish::interface](embeds)`**, so a
   `Box<dyn Hash + Send + Sync>` is a valid `cast!` carrier — that is the
   goish spelling of Go's `h.inner.(marshalable)`.
3. **A macro change** (`goish-macros`): a trait whose supertrait clause
   models Go's *interface embedding* now inherits the hidden downcast
   helpers instead of re-declaring them. Re-declaring made every
   `self.__is_nil_iface()` call on `dyn Cloner` ambiguous (E0034), which
   is why `io/fs.rs` had to flatten Go's embedded interfaces by hand. The
   `embeds` flag is opt-in, so a composite trait over a plain foreign
   trait keeps the old behaviour (`examples/interface_auto_composite.rs`
   pins both).
4. **`internal/byteorder` + `crypto/internal/fips140deps/byteorder`**
   ported, so the `byteorder.BEAppendUint32` calls the Go source makes
   resolve to a real package instead of a private copy.

Verified by `examples/hash_marshal_smoke.rs`: marshal round-trip, SHA-224
rejecting a SHA-256 state, clone independence, and the HMAC fast path
checked against RFC 4231 test case 2 across four Reset cycles. A silent
regression here produces a wrong MAC, not a crash, so every assertion
compares against a pinned vector rather than against itself.

`fips140/sha512` followed immediately, on the same template: extracted
from `crypto/sha512`'s single `mod.rs` into `sha512[go]` / `sha512block[go]`
/ `sha512block_noasm[go]`, gaining the same six marshal/Clone functions
plus `New512_224`/`New512_256`/`New384`, and registered with hmac so
HMAC-SHA-512 and HMAC-SHA-384 take the cached path too.

`fips140/aes` came last and was the largest — 45 functions over 11 Go
files, against a goish `crypto/aes` that inlined the whole cipher in one
853-line `mod.rs`. Splitting it produced aes[go] / aes_generic[go] /
aes_noasm[go] / const[go] / cbc[go] / cbc_noasm[go] / ctr[go] /
ctr_noasm[go], and required porting `crypto/internal/fips140/alias`
(the buffer-overlap checks every cipher mode is contractually required
to make, which goish had simply omitted). `crypto/aes` is now Go's
wrapper: `NewCipher` plus `KeySizeError`.

Worth noting for the assembly work: goish's CBC and CTR were previously
reachable only through `crypto/cipher`'s own generic implementations.
The fips140-native `CBCEncrypter`/`CBCDecrypter`/`CTR` are the types the
`*Asm` entry points plug into, so `examples/fips140_aes_smoke.rs` pins
them against NIST SP 800-38A §F now, before any assembly exists to
change their behaviour.

Still open, and the reason `hash` as a whole is not yet verified: the
legacy `hash/{adler32,crc32,crc64,fnv,maphash}` ports predate the anchor
grammar and are one `mod.rs` each.

## Invented-code hotspots

Low coverage in a package that already has Rust code means the existing code is
not a port of anything. The worst case:

- **`crypto/ecdsa` — 0/43.** All 31 functions are invented: `VerifyP256`,
  `decode_x509_ec_p256_pubkey`, `p256_ecdh_generate_and_compute`,
  `find_spki_in_tbs`. Go's ecdsa has `GenerateKey`/`Sign`/`Verify`/`PublicKey`/
  `PrivateKey`. This needs a rewrite against `crypto/ecdsa/ecdsa.go` plus
  `crypto/internal/fips140/ecdsa`, not incremental patching.
- **`crypto/x509` — 8/160** and **`crypto/tls` — 37/298**: real ports of a thin
  slice (enough for a TLS 1.3 client/server handshake), with the rest absent.
  Both are honest partial ports, not invented — but the anchors will have to say
  so per function.

## Work order

Waves are ordered so each one's dependencies are already anchored. Within a
wave, ascending Go LOC.

### Wave A — lock in what is already complete (12 packages, 214 fns)

These are at or near 100% by name. Work is structural only: split per Go file,
add anchors, let GOISH018 confirm. Any package that survives this wave is
*provably* complete and gets a CI gate.

| package | Go .go | Go LOC | Go fns | ported | % | .rs | anchors |
|---|--:|--:|--:|--:|--:|--:|--:|
| `crypto/internal/fips140/bigmod` | 3 | 1287 | 60 | 57 | 95.0% | 1 | 0 |
| `crypto/internal/fips140/rsa` | 5 | 1703 | 39 | 39 | 100.0% | 1 | 0 |
| `crypto/internal/fips140/edwards25519/field` | 4 | 719 | 34 | 32 | 94.1% | 1 | 0 |
| `crypto/internal/fips140/ed25519` | 2 | 404 | 28 | 28 | 100.0% | 1 | 0 |
| `crypto/des` | 3 | 556 | 14 | 14 | 100.0% | 1 | 0 |
| `crypto/ed25519` | 1 | 242 | 11 | 11 | 100.0% | 1 | 0 |
| `crypto/sha512` | 1 | 123 | 8 | 8 | 100.0% | 1 | 0 |
| `crypto/subtle` | 3 | 115 | 8 | 7 | 87.5% | 1 | 0 |
| `crypto/rc4` | 1 | 85 | 4 | 4 | 100.0% | 1 | 0 |
| `crypto/sha256` | 1 | 74 | 4 | 4 | 100.0% | 1 | 0 |
| `crypto/aes` | 1 | 48 | 2 | 2 | 100.0% | 1 | 0 |
| `crypto/hmac` | 1 | 65 | 2 | 2 | 100.0% | 1 | 0 |

### Wave B — finish the partial ports (14 packages, 735 fns)

Existing Rust code, real gaps. `ecdsa` is a rewrite (see hotspots); `tls` and
`x509` are the two giants and should be split into their own sub-waves by Go
file once anchored.

| package | Go .go | Go LOC | Go fns | ported | % | .rs | anchors |
|---|--:|--:|--:|--:|--:|--:|--:|
| `crypto/tls` | 23 | 14341 | 298 | 37 | 12.4% | 8 | 0 |
| `crypto/x509` | 14 | 7356 | 160 | 8 | 5.0% | 1 | 0 |
| `crypto/internal/fips140/edwards25519` | 6 | 2291 | 49 | 28 | 57.1% | 1 | 0 |
| `crypto/ecdsa` | 4 | 970 | 43 | 0 | 0.0% | 1 | 0 |
| `crypto/rsa` | 5 | 1493 | 40 | 27 | 67.5% | 1 | 0 |
| `crypto/cipher` | 7 | 1040 | 33 | 28 | 84.8% | 7 | 0 |
| `crypto/sha3` | 1 | 245 | 27 | 20 | 74.1% | 1 | 0 |
| `crypto/md5` | 5 | 619 | 21 | 8 | 38.1% | 1 | 0 |
| `crypto/sha1` | 5 | 434 | 19 | 8 | 42.1% | 1 | 0 |
| `crypto/ecdh` | 3 | 536 | 17 | 1 | 5.9% | 1 | 0 |
| `crypto/internal/fips140` | 7 | 259 | 12 | 9 | 75.0% | 1 | 0 |
| `crypto/.` | 1 | 255 | 7 | 4 | 57.1% | 2 | 0 |
| `crypto/rand` | 3 | 209 | 5 | 1 | 20.0% | 1 | 0 |
| `crypto/hkdf` | 1 | 84 | 4 | 3 | 75.0% | 1 | 0 |

### Wave C — not started (37 packages, 625 fns)

Nothing in goish yet. Biggest first: `internal/fips140/nistec` (77),
`internal/fips140/mlkem` (70), `internal/fips140/nistec/fiat` (62),
`crypto/x509/internal/macos` (54), `internal/fips140/aes` (45),
`internal/fips140/aes/gcm` (41), `internal/fips140/sha3` (33),
`internal/fips140/ecdsa` (30), `elliptic` (27), `internal/hpke` (19),
`internal/fips140/sha256` (18), `internal/fips140/sha512` (18), and 25 smaller. Run `scripts/port_coverage.py crypto` for the live list.

Note the shape of Wave C: most of it is `internal/fips140/*`, the primitives
that Waves A/B currently reimplement directly. Porting them properly means
`crypto/aes` and friends become the thin Go-shaped wrappers they are in Go,
with the real work in `internal/fips140`. Sequence Wave C's fips140 packages
*before* re-doing the Wave B packages that would sit on them.

## Assembly is in scope (performance requirement)

Go's crypto carries hand-written assembly for the hot primitives — AES-NI
(`aes_amd64.s`), SHA-NI (`sha256block_amd64.s`), GHASH (`gcm_amd64.s`),
P-256 (`p256_asm_amd64.s`) — behind `//go:build !purego`, with
`*_generic.go` / `*_noasm.go` fallbacks for everything else.

**goish can write assembly and should**: the runtime already ships
hand-written amd64 (`gogo`, `mcall`, `swap_context`, the async-preempt
trampoline) via `global_asm!` / `asm!`. So the `*_asm.go` declarations and
their `.s` bodies are part of a 100% port, tracked as performance work
rather than skipped.

Practical sequencing per package:

1. Port the `*_generic.go` / `*_noasm.go` path first — it is the reference
   implementation and makes the package correct and testable.
2. Then port the `.s` body as a `global_asm!` block with the same symbol
   shape, and dispatch to it the way Go's `*_asm.go` does.
3. Keep both: Go keeps the generic path for correctness testing, and
   goish's own `--purego` coverage view exists so the asm-free subset
   stays visible.

`scripts/port_coverage.py crypto` counts the asm entry points; add
`--purego` for the asm-free view. The gap between the two numbers is the
outstanding assembly work.

## Out of scope

Excluded from the denominator by `scripts/port_coverage.py`, and the reasons:

| excluded | why |
|---|---|
| `crypto/internal/boring`, `crypto/boring` | BoringSSL via cgo; cgo is rejected outright (see `FFI_BOUNDARIES`) |
| `**/_asm/**` | Go's avo *generators* — Go programs that emit the `.s` files. goish ports the emitted assembly (see "Assembly"), not the generator |
| `crypto/internal/cryptotest`, `**/checktest` | test harness helpers |
| `crypto/tls/fipsonly` | build-tag-only policy shim |
| `*_s390x.go`, `*_ppc64x.go`, `*_arm64.go`, `*_darwin.go`, … | other GOARCH/GOOS build constraints; goish is `x86_64-unknown-linux-gnu` only. `_amd64`/`_generic`/`_noasm`/`_asm`/`_linux` files stay in scope (52 funcs excluded this way) |

`crypto/x509/internal/macos` (54 fns) is counted but is Darwin-only; goish is
single-target `x86_64-unknown-linux-gnu`, so it should be declared
`// go: none — darwin-only, goish is linux/amd64` rather than ported.

## Definition of done

For each package, in order:

1. one `.rs` per `.go` (GOISH015 clean)
2. every `fn` anchored to its Go file+line span (GOISH014 clean)
3. `goishlint --enable-goish018 src/crypto/<pkg>/` reports no dropped function
4. an `examples/<pkg>_smoke.rs` exercising it against Go-derived test vectors,
   declared in `Cargo.toml` (undeclared examples never run — see the runner's
   discovery note)
5. `scripts/port_coverage.py crypto --pkg <pkg>` reads 100%

Whole-subtree done: `python3 scripts/port_coverage.py crypto` reports
`TOTAL 1575/1575 = 100.0%` and `goishlint --enable-goish017 --enable-goish018
src/crypto/` exits 0.
