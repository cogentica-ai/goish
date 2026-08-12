# Security

## Status: not audited, not production-ready

goish implements cryptography, TLS, and a memory allocator and scheduler
in `no_std` Rust on raw syscalls. **None of it has had third-party
security review.** Do not use it to protect anything you would mind
losing.

The rest of this file is specific about *which* parts are weakest,
because "use at your own risk" is not actionable.

### `crypto/tls` is not a port of Go — treat it as experimental

goish ships a working TLS 1.2/1.3 client and a server. They complete
real handshakes against real servers, and they are exercised in CI at
50× under the race-sensitive tier.

They are nonetheless **hand-written**, not ported from Go. Four of the
nine files in `src/crypto/tls/` contain no function Go declares, and the
package sits at ~10% ported. That has two consequences worth stating
plainly:

- The provenance tooling that checks every other crypto package against
  the Go source **cannot check this one**. Where `crypto/x509` is
  verified function-by-function against Go, the TLS state machine is
  verified only by its own tests.
- A TLS implementation's security lives in the details a passing
  handshake does not exercise: downgrade protection, alert handling,
  certificate-chain policy, nonce discipline, timing behaviour on
  failure paths.

Replacing it with a verbatim port of Go's `crypto/tls` is the top item
on the [roadmap](ROADMAP.md).

### The rest of `crypto/`

65 of 66 packages are ported function-by-function from Go 1.25.5 with
machine-checked provenance, and their test vectors are generated from
Go rather than transcribed. That is a meaningful assurance argument, and
it is still not an audit. Constant-time properties in particular are
inherited from Go's algorithm choices, **not** verified in goish's
compiled output.

### Known security-relevant defects

| | |
|---|---|
| `goish::cast!` on an `Any` carrier always reports "no" | A type assertion silently takes the wrong branch. Use `.As::<dyn Trait + Send + Sync>()`. |
| `crypto/ecdsa::PrivateKey` does not implement `crypto::Signer` | ECDSA keys cannot sign X.509 certificates. |
| FIPS service indicator is inert | `fips140::Record{Non,}Approved` are ported but write through a runtime stub, so `ServiceIndicator()` always reports false. goish makes **no** FIPS 140-3 claim. |

See [PROGRESS.md](PROGRESS.md) for the full list, including non-security
divergences.

## Reporting a vulnerability

Please report privately rather than opening a public issue.

<!-- TODO(maintainer): replace with a monitored address or a GitHub
     private vulnerability reporting link before publishing. A security
     policy with no working contact is worse than none, because it
     implies a channel that does not exist. -->

- **Contact:** _to be filled in before release_
- Please include a description, affected version or commit, and a
  reproduction if you have one.
- There is no bug bounty, and no formal response-time commitment while
  the project is pre-1.0.

## Supported versions

goish is pre-1.0 (`0.1.0`) and has no released versions. Only `main` is
supported. There is no security backporting.
