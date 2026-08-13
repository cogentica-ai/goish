// go: package net/http/internal/ascii
//
// go: file net/http/internal/ascii/print.go decls: EqualFold, lower, IsPrint, Is, ToLower
//
// Go: "ASCII-only equivalents of the strings/unicode helpers net/http
// needs on its hot paths."
//
// Header field names and values are ASCII by definition, so net/http
// never wants strings.EqualFold's Unicode simple-folding here: that
// would make the Kelvin sign K fold equal to "k" and let a crafted
// header name match a check it should not.

#![allow(non_snake_case)]

use crate::string;
use crate::types::{byte, int};

// go: sdk 1.25.5 net/http/internal/ascii/print.go:14-24 EqualFold
/// EqualFold is [strings.EqualFold], ASCII only. It reports whether s and t
/// are equal, ASCII-case-insensitively.
pub fn EqualFold<S1: Into<string>, S2: Into<string>>(s: S1, t: S2) -> bool {
    let s = s.into();
    let t = t.into();
    if crate::builtin::len(&s) != crate::builtin::len(&t) {
        return false;
    }
    let n = crate::builtin::len(&s);
    let mut i: int = 0;
    while i < n {
        if lower(s[i]) != lower(t[i]) {
            return false;
        }
        i += 1;
    }
    return true;
}

// go: sdk 1.25.5 net/http/internal/ascii/print.go:27-32 lower
/// lower returns the ASCII lowercase version of b.
fn lower(b: byte) -> byte {
    if b'A' <= b && b <= b'Z' {
        return b + (b'a' - b'A');
    }
    return b;
}

// go: sdk 1.25.5 net/http/internal/ascii/print.go:36-43 IsPrint
/// IsPrint returns whether s is ASCII and printable according to
/// https://tools.ietf.org/html/rfc20#section-4.2.
pub fn IsPrint<S: Into<string>>(s: S) -> bool {
    let s = s.into();
    let n = crate::builtin::len(&s);
    let mut i: int = 0;
    while i < n {
        if s[i] < b' ' || s[i] > b'~' {
            return false;
        }
        i += 1;
    }
    return true;
}

// go: sdk 1.25.5 net/http/internal/ascii/print.go:46-53 Is
/// Is returns whether s is ASCII.
pub fn Is<S: Into<string>>(s: S) -> bool {
    let s = s.into();
    let n = crate::builtin::len(&s);
    let mut i: int = 0;
    while i < n {
        // Go's unicode.MaxASCII is an untyped rune constant, so the
        // comparison against a byte converts it.
        if s[i] > crate::byte(crate::unicode::MaxASCII) {
            return false;
        }
        i += 1;
    }
    return true;
}

// go: sdk 1.25.5 net/http/internal/ascii/print.go:56-61 ToLower
/// ToLower returns the lowercase version of s if s is ASCII and printable.
pub fn ToLower<S: Into<string>>(s: S) -> (string, bool) {
    let s = s.into();
    if !IsPrint(s.clone()) {
        return (string::new(), false);
    }
    return (crate::strings::ToLower(s), true);
}
