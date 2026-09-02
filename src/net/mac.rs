// go: file net/mac.go decls: HardwareAddr.String, ParseMAC
//
// mac.go — IEEE 802 hardware addresses.
//
// This file used to carry NO provenance anchors and no manifest: it was
// one of twenty-five declarations under net/ that port_coverage reports
// as UNVERIFIED, matching Go by name only. Diffing it against a running
// Go found a real defect — see `ParseMAC`.
//
// `xtoi` and `xtoi2` live in Go's parse.go, which this tree has not
// ported; they are marked as goish's here rather than anchored, so that
// this file does not claim to port parse.go.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int};

// go: sdk 1.25.5 net/mac.go:7-7 hexDigit
/// Go: `const hexDigit = "0123456789abcdef"`.
pub(crate) const HEX_DIGIT: &[byte] = b"0123456789abcdef";

// go: sdk 1.25.5 net/mac.go:10-10 HardwareAddr
/// Go: "A HardwareAddr represents a physical hardware address."
///
/// Goish models Go's `type HardwareAddr []byte` as a transparent
/// `slice<byte>` with associated free functions, since `slice<T>`
/// can't host inherent methods directly.
pub type HardwareAddr = slice<byte>;

// go: sdk 1.25.5 net/mac.go:12-25 HardwareAddr.String
/// Go: `func (a HardwareAddr) String() string` — colon-separated hex.
/// The EMPTY address is the empty string, not "00", and a one-byte
/// address has no separator at all.
///
/// goish spells it as a free function because `HardwareAddr` is a type
/// ALIAS for `slice<byte>`, which cannot host inherent methods.
pub fn HardwareAddrString(a: &HardwareAddr) -> string {
    // Go: mac.go:13 — if len(a) == 0 { return "" }
    if a.len() == 0 {
        return string::from_static("");
    }
    // Go: mac.go:16 — buf := make([]byte, 0, len(a)*3-1)
    let mut buf: Vec<byte> = Vec::with_capacity(a.len() * 3 - 1);
    let raw: &[byte] = a;
    // Go: mac.go:17 — for i, b := range a { ... }
    for (i, b) in raw.iter().enumerate() {
        if i > 0 {
            buf.push(b':');
        }
        buf.push(HEX_DIGIT[(b >> 4) as usize]);
        buf.push(HEX_DIGIT[(b & 0x0F) as usize]);
    }
    string::from_bytes(&buf)
}

// ─── ParseMAC (mac.go:39) ────────────────────────────────────────────────────

// go: sdk 1.25.5 net/mac.go:39-86 ParseMAC
/// Go: "ParseMAC parses s as an IEEE 802 MAC-48, EUI-48, EUI-64, or a
/// 20-octet IP over InfiniBand link-layer address."
///
/// The failure path used to build its message by hand:
///
///     "address " + s + ": invalid MAC address"
///
/// which was wrong twice. Go returns `&AddrError{Err: "invalid MAC
/// address", Addr: s}`, and `AddrError.Error` OMITS the "address …: "
/// prefix when Addr is empty — so `ParseMAC("")` is "invalid MAC
/// address" in Go and was "address : invalid MAC address" here. More
/// importantly the hand-built one was an `errors.New`, so
/// `errors.As(err, &net.AddrError{})` could never match it and a caller
/// could not ask the error what address had failed.
pub fn ParseMAC<S: Into<string>>(s: S) -> (HardwareAddr, error) {
    let s: string = s.into();
    let raw = crate::gostring::__crate_as_bytes(&s);

    // Go: mac.go:40 — if len(s) < 14 { goto error }
    if raw.len() < 14 {
        return (slice::__from_vec(alloc::vec![]), addr_error(&s));
    }

    // Go: mac.go:44 — if s[2] == ':' || s[2] == '-' { ... }
    if raw[2] == b':' || raw[2] == b'-' {
        // Go: mac.go:45 — (len(s)+1)%3 != 0 → error
        if (raw.len() + 1) % 3 != 0 {
            return (slice::__from_vec(alloc::vec![]), addr_error(&s));
        }
        // Go: mac.go:48 — n := (len(s) + 1) / 3
        let n = (raw.len() + 1) / 3;
        if n != 6 && n != 8 && n != 20 {
            return (slice::__from_vec(alloc::vec![]), addr_error(&s));
        }
        // Go: mac.go:52 — hw = make(HardwareAddr, n)
        let mut hw: Vec<byte> = alloc::vec![0u8; n];
        let mut x = 0usize;
        for i in 0..n {
            let (b, ok) = xtoi2(&raw[x..], raw[2]);
            if !ok {
                return (slice::__from_vec(alloc::vec![]), addr_error(&s));
            }
            hw[i] = b;
            x += 3;
        }
        return (slice::__from_vec(hw), errors::nil);
    }

    // Go: mac.go:60 — else if s[4] == '.' { ... }
    if raw[4] == b'.' {
        // Go: mac.go:61 — (len(s)+1)%5 != 0 → error
        if (raw.len() + 1) % 5 != 0 {
            return (slice::__from_vec(alloc::vec![]), addr_error(&s));
        }
        // Go: mac.go:64 — n := 2 * (len(s) + 1) / 5
        let n = 2 * (raw.len() + 1) / 5;
        if n != 6 && n != 8 && n != 20 {
            return (slice::__from_vec(alloc::vec![]), addr_error(&s));
        }
        // Go: mac.go:68 — hw = make(HardwareAddr, n)
        let mut hw: Vec<byte> = alloc::vec![0u8; n];
        let mut x = 0usize;
        let mut i = 0usize;
        while i < n {
            // Go: mac.go:71 — xtoi2(s[x:x+2], 0) — terminator '\0' i.e. no-check.
            let (b0, ok0) = xtoi2(&raw[x..x + 2], 0);
            if !ok0 {
                return (slice::__from_vec(alloc::vec![]), addr_error(&s));
            }
            hw[i] = b0;
            // Go: mac.go:74 — xtoi2(s[x+2:], s[4]) — must be followed by '.'.
            let (b1, ok1) = xtoi2(&raw[x + 2..], raw[4]);
            if !ok1 {
                return (slice::__from_vec(alloc::vec![]), addr_error(&s));
            }
            hw[i + 1] = b1;
            x += 5;
            i += 2;
        }
        return (slice::__from_vec(hw), errors::nil);
    }

    // Go: mac.go:80 — fallthrough error.
    (slice::__from_vec(alloc::vec![]), addr_error(&s))
}

// ─── helpers ────────────────────────────────────────────────────────────────

// go: none — goish idiom: Go's `xtoi` lives in net/parse.go, which this
//     tree has not ported (src/net/parse.rs is a slim TCPAddr file, not
//     a port of it). Anchoring to parse.go from here would claim this
//     file ports it and make every other parse.go declaration read as
//     dropped, so the two helpers ParseMAC needs are marked as goish's
//     until parse.go gets a file of its own.
/// Go's `xtoi` (net/parse.go:146) — hex to int, returning (value,
/// characters consumed, ok).
fn xtoi(s: &[byte]) -> (int, int, bool) {
    let mut n: int = 0;
    let mut i: usize = 0;
    while i < s.len() {
        let c = s[i];
        if c.is_ascii_digit() {
            n = n * 16 + (c - b'0') as int;
        } else if (b'a'..=b'f').contains(&c) {
            n = n * 16 + ((c - b'a') as int + 10);
        } else if (b'A'..=b'F').contains(&c) {
            n = n * 16 + ((c - b'A') as int + 10);
        } else {
            break;
        }
        // Go: parse.go:161 — overflow guard.
        if n >= 0xFFFFFF {
            return (0, i as int, false);
        }
        i += 1;
    }
    if i == 0 {
        return (0, i as int, false);
    }
    (n, i as int, true)
}

// go: none — goish idiom: see the note on `xtoi`.
/// Go's `xtoi2` (net/parse.go:172): "xtoi2 converts the next two hex
/// digits of s into a byte. If s is longer than 2 bytes then the third
/// byte must be e."
fn xtoi2(s: &[byte], e: byte) -> (byte, bool) {
    if s.len() > 2 && s[2] != e {
        return (0, false);
    }
    let take = if s.len() < 2 { s.len() } else { 2 };
    let (n, ei, ok) = xtoi(&s[..take]);
    (n as byte, ok && ei == 2)
}

// go: none — goish idiom: Go writes the composite literal
//     `&AddrError{Err: "invalid MAC address", Addr: s}` at its single
//     `error:` label; goish spells it once here because the label is
//     reached from eight places and Rust has no goto.
fn addr_error(s: &string) -> error {
    return errors::Wrap(crate::net::net::AddrError {
        Err: string::from_static("invalid MAC address"),
        Addr: s.clone(),
    });
}
