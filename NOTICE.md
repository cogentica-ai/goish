# Third-party attribution

**This is not legal advice.** It records what the code actually is, so
that whoever reviews licensing has the facts. Confirm the conclusions
with counsel before a release.

## goish contains substantial derivative work from Go

goish is a *port*, not a reimplementation from a specification. Large
parts of `src/` were written by reading a Go 1.25.5 source file and
translating it function by function, keeping Go's names, field layouts,
control flow and comments. That makes those parts **derivative works of
the Go standard library**.

As of 2026-08-12: **876 provenance anchors across 176 files**, each
naming the Go file and line range its code came from.

| upstream | license | ported into |
|---|---|---|
| The Go standard library | BSD-3-Clause, © The Go Authors | most of `src/` |
| `golang.org/x/crypto` | BSD-3-Clause, © The Go Authors | `src/crypto/cryptobyte`, `chacha20`, `hkdf` and others |
| `golang.org/x/text` | BSD-3-Clause, © The Go Authors | `src/text/` |

The full BSD-3-Clause text is in [LICENSE-GO](LICENSE-GO).

### What that means in practice

- goish's **own** contributions — the runtime, scheduler, allocator, the
  `goish::*` macros, the type system that makes Go idioms compile as
  Rust — are licensed MIT (see [LICENSE](LICENSE)).
- The **ported** portions carry the Go Authors' BSD-3-Clause terms in
  addition. BSD-3-Clause is permissive and compatible with MIT, so the
  combination is redistributable — but its first
  condition requires the copyright notice and disclaimer to travel with
  both source and binary redistributions, which is why `LICENSE-GO`
  exists and why it must ship with any binary.
- The third condition forbids using the Go Authors' or Google's name to
  endorse or promote goish. goish is **not** affiliated with, endorsed
  by, or supported by Google or the Go project.

### Identifying ported code

Every ported declaration carries an anchor naming its origin:

```rust
// go: sdk 1.25.5 crypto/x509/x509.go:1810-1818 ParseCRL
```

`// go: none — <reason>` marks goish-only code with no Go counterpart.
`scripts/port_coverage.py` reports the totals, and goishlint's fidelity
tier verifies each anchor against the Go file it cites.

## Go is a trademark

"Go" and the Go gopher are trademarks of Google LLC. goish uses the name
descriptively, to say what it is a port of.
