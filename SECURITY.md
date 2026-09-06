# Security

## Status: not audited, not production-ready

goish implements cryptography, TLS, and a memory allocator and scheduler
in `no_std` Rust on raw syscalls. **None of it has had third-party
security review.** Do not use it to protect anything you would mind
losing.

The rest of this file is specific about *which* parts are weakest,
because "use at your own risk" is not actionable.

### `crypto/tls` is ported now, and still not audited

goish ships a working TLS 1.2/1.3 client and a server. They complete
real handshakes against real servers, and they are exercised in CI at
50× under the race-sensitive tier.

**This section used to say the package was hand-written and ~10%
ported. That is no longer true, and the correction is the point of the
paragraph.** `scripts/port_coverage.py crypto/tls --by-decl` now reports
**353/353 declarations (100%)** across its two packages, behind 901
`// go:` lines — run it rather than trusting this number, which is the
kind that goes stale. Read that 100% with its waivers in view: 24
declarations sit outside the denominator, and all 24 are QUIC
(`QUICClient`, `QUICServer`, `QUICConn.*`, `Conn.quic*`), which goish
does not implement. There is no QUIC transport here to attack, and
no QUIC support to rely on. A dialled connection runs ported code end to end:
`tls::Dial` → `Conn::Handshake` → `handshakeContext` → `clientHandshake`
→ the ported `clientHandshakeStateTLS13`, over `conn.rs`, which is Go's
record layer.

Two hand-written files are still live, reachable through the
`do_client_handshake*` functions the package exports rather than through
`Dial`: `record.rs` (1,145 lines, its own record layer) and `session.rs`
(261 lines, a client session cache). Both were diffed against their Go
counterparts in September 2026, and that diffing produced four
security fixes — two missing length bounds and a padding oracle in
`record.rs`, and a cache that bounded tickets per host while nothing
bounded the host count in `session.rs`. Retiring both is
[roadmap](ROADMAP.md) §1.

What has *not* changed is the assurance argument. A port is not an
audit, and a TLS implementation's security lives in the details a
passing handshake does not exercise: downgrade protection, alert
handling, certificate-chain policy, nonce discipline, timing behaviour
on failure paths. None of that has had third-party review here.

### The rest of `crypto/`

All 66 packages are ported declaration-by-declaration from Go 1.25.5
with machine-checked provenance, and their test vectors are generated from
Go rather than transcribed. That is a meaningful assurance argument, and
it is still not an audit. Constant-time properties in particular are
inherited from Go's algorithm choices, **not** verified in goish's
compiled output.

### Known security-relevant defects

| | |
|---|---|
| `goish::cast!` on an `Any` carrier always reports "no" | A type assertion silently takes the wrong branch. Use `.As::<dyn Trait + Send + Sync>()`. |
| FIPS service indicator is inert | `fips140::Record{Non,}Approved` are ported but write through a runtime stub, so `ServiceIndicator()` always reports false. goish makes **no** FIPS 140-3 claim. |

See [PROGRESS.md](PROGRESS.md) for the full list, including non-security
divergences.

## Reporting a vulnerability

Please report privately rather than opening a public issue.

- **Contact:** [hello@cogentica.ai](mailto:hello@cogentica.ai), with
  `security` in the subject line.
- Please include a description, affected version or commit, and a
  reproduction if you have one.
- There is no bug bounty, and no formal response-time commitment while
  the project is pre-1.0.

## Supported versions

goish is pre-1.0 (`1.0.0-alpha.8`). Only `main` is
supported. There is no security backporting.
