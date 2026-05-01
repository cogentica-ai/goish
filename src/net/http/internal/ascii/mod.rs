// net/http/internal/ascii — ASCII-only fast paths used by net/http.
//
// Line-by-line port of:
//   /nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/
//     net/http/internal/ascii/print.go
//
//   Go                                       goish
//   ──────────────────────────────────────   ─────────────────────────────────
//   ascii.EqualFold(s, t)                    ascii::EqualFold(s, t)  — bool
//   ascii.IsPrint(s)                         ascii::IsPrint(s)       — bool
//   ascii.Is(s)                              ascii::Is(s)            — bool
//   ascii.ToLower(s)                         ascii::ToLower(s)       — (string, bool)
//
// Slim deviations:
//   • None — this is an exact ASCII-byte-level port.

#![allow(non_snake_case)]

extern crate alloc;

use crate::string;
use crate::types::{byte, int};

// Go: print.go:14
// EqualFold is [strings.EqualFold], ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
pub fn EqualFold<S1: Into<string>, S2: Into<string>>(s: S1, t: S2) -> bool {
    let s = s.into();
    let t = t.into();
    // Go: print.go:15
    if crate::builtin::len(&s) != crate::builtin::len(&t) {
        return false;
    }
    // Go: print.go:18-22 — byte-wise ASCII-lowercase compare.
    let n = crate::builtin::len(&s);
    let mut i: int = 0;
    while i < n {
        if lower(s[i]) != lower(t[i]) {
            return false;
        }
        i += 1;
    }
    // Go: print.go:23
    true
}

// Go: print.go:27
// lower returns the ASCII lowercase version of b.
fn lower(b: byte) -> byte {
    // Go: print.go:28-30
    if b'A' <= b && b <= b'Z' {
        return b + (b'a' - b'A');
    }
    b
}

// Go: print.go:36
// IsPrint returns whether s is ASCII and printable according to
// https://tools.ietf.org/html/rfc20#section-4.2.
pub fn IsPrint<S: Into<string>>(s: S) -> bool {
    let s = s.into();
    // Go: print.go:37-41 — every byte must be in [' ', '~'].
    let n = crate::builtin::len(&s);
    let mut i: int = 0;
    while i < n {
        let c = s[i];
        if c < b' ' || c > b'~' {
            return false;
        }
        i += 1;
    }
    // Go: print.go:42
    true
}

// Go: print.go:46
// Is returns whether s is ASCII.
pub fn Is<S: Into<string>>(s: S) -> bool {
    let s = s.into();
    // Go: print.go:47-51 — unicode.MaxASCII == 0x7F.
    let n = crate::builtin::len(&s);
    let mut i: int = 0;
    while i < n {
        if s[i] > 0x7F {
            return false;
        }
        i += 1;
    }
    // Go: print.go:52
    true
}

// Go: print.go:56
// ToLower returns the lowercase version of s if s is ASCII and printable.
pub fn ToLower<S: Into<string>>(s: S) -> (string, bool) {
    let s = s.into();
    // Go: print.go:57-59
    if !IsPrint(s.clone()) {
        return (string::new(), false);
    }
    // Go: print.go:60 — strings.ToLower (slim ASCII path is sufficient
    // here because IsPrint already rejected non-ASCII).
    (crate::strings::ToLower(s), true)
}
