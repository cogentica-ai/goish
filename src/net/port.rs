// net/port — Go 1.25.5 src/net/port.go.
//
// One `.rs` per `.go` (§33). The whole file is `parsePort`.

#![allow(non_snake_case)]

use crate::types::int;

// go: sdk 1.25.5 net/port.go:15-63 parsePort
/// Go: "parses service as a decimal integer and returns the
/// corresponding value as port. It is the caller's responsibility to
/// parse service as a non-decimal integer when needsLookup is true."
///
/// Three behaviours here are deliberate in Go and easy to lose:
///
///   * An EMPTY service is port 0 with needsLookup false — Go calls
///     this "the legacy behavior … golang.org/issue/13610", not an
///     error.
///   * A leading `+` or `-` is consumed before the digits, so "+80"
///     parses as 80 and "-1" as -1. Anything else non-digit — a
///     leading space included — makes the whole thing a service NAME.
///   * Oversized numbers are NOT rejected early. Go's comment: "Some
///     system resolvers will return a valid port number when given a
///     number over 65536 … Alas, the parser can't bail early". They
///     saturate here and are rejected by the caller, which is what
///     produces "address 65536: invalid port" rather than a parse
///     failure.
pub(crate) fn parsePort(service: &str) -> (int, bool) {
    if service.is_empty() {
        // Go: "Lock in the legacy behavior that an empty string means
        // port 0. See golang.org/issue/13610."
        return (0, false);
    }
    const MAX: u32 = u32::MAX; // Go: uint32(1<<32 - 1)
    const CUTOFF: u32 = 1 << 30;

    let bytes = service.as_bytes();
    let mut neg = false;
    let rest: &[u8] = if bytes[0] == b'+' {
        &bytes[1..]
    } else if bytes[0] == b'-' {
        neg = true;
        &bytes[1..]
    } else {
        bytes
    };

    let mut n: u32 = 0;
    for &b in rest {
        let d: u32 = if b.is_ascii_digit() {
            u32::from(b - b'0')
        } else {
            return (0, true);
        };
        if n >= CUTOFF {
            n = MAX;
            break;
        }
        // Go's arithmetic here is uint32 and wraps; the overflow is
        // caught by the `nn < n` test below, not by the multiply.
        n = n.wrapping_mul(10);
        let nn = n.wrapping_add(d);
        if nn < n {
            n = MAX;
            break;
        }
        n = nn;
    }

    let mut port: int = if !neg && n >= CUTOFF {
        int::from(CUTOFF - 1)
    } else if neg && n > CUTOFF {
        int::from(CUTOFF)
    } else {
        int::from(n)
    };
    if neg {
        port = -port;
    }
    return (port, false);
}
