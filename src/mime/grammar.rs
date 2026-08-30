// go: file mime/grammar.go decls: isTSpecial, isTokenChar, isToken
//
// mime/grammar.go — the RFC 1521 / RFC 2045 'tspecials' and 'token'
// character classes.
//
// Go writes each class as a 128-bit constant bitmap and tests a byte
// with two shifts and two ands, relying on Go's rule that a shift
// count of 64 or more yields zero — which is how `c >= 128` falls out
// as `false` without a range check. Rust panics on an over-wide shift
// instead, so the two halves are tested explicitly and the same
// constants are kept verbatim.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::gostring::string;
use crate::types::byte;

// go: none — goish idiom: Go's `(uint64(1)<<c)&low | (uint64(1)<<(c-64))&high`
//     leans on Go's spec, where a shift of 64 or more is zero and
//     `c-64` wraps for small `c`. Rust panics on both, so the halves
//     are selected by a comparison. Same bitmap, same answer.
const fn bitmapHas(low: u64, high: u64, c: byte) -> bool {
    if c < 64 {
        return (low >> c) & 1 != 0;
    }
    if c < 128 {
        return (high >> (c - 64)) & 1 != 0;
    }
    return false;
}

// go: sdk 1.25.5 mime/grammar.go:7-35 isTSpecial
/// Whether `c` is in 'tspecials' as defined by RFC 1521 and RFC 2045.
///
/// Go's comment lists them:
///   tspecials := "(" / ")" / "<" / ">" / "@" /
///                "," / ";" / ":" / "\" / <"> /
///                "/" / "[" / "]" / "?" / "="
pub fn isTSpecial(c: byte) -> bool {
    // All fifteen are below 0x40 except '@', '[', '\\', ']'.
    const LOW: u64 = (1 << b'(')
        | (1 << b')')
        | (1 << b'<')
        | (1 << b'>')
        | (1 << b',')
        | (1 << b';')
        | (1 << b':')
        | (1 << b'"')
        | (1 << b'/')
        | (1 << b'?')
        | (1 << b'=');
    const HIGH: u64 =
        (1 << (b'@' - 64)) | (1 << (b'\\' - 64)) | (1 << (b'[' - 64)) | (1 << (b']' - 64));
    return bitmapHas(LOW, HIGH, c);
}

// go: sdk 1.25.5 mime/grammar.go:37-70 isTokenChar
/// Whether `c` is in 'token' as defined by RFC 1521 and RFC 2045.
///
///   token := 1*<any (US-ASCII) CHAR except SPACE, CTLs, or tspecials>
pub fn isTokenChar(c: byte) -> bool {
    const LOW: u64 = (((1u64 << 10) - 1) << b'0')
        | (1 << b'!')
        | (1 << b'#')
        | (1 << b'$')
        | (1 << b'%')
        | (1 << b'&')
        | (1 << b'\'')
        | (1 << b'*')
        | (1 << b'+')
        | (1 << b'-')
        | (1 << b'.');
    const HIGH: u64 = (((1u64 << 26) - 1) << (b'a' - 64))
        | (((1u64 << 26) - 1) << (b'A' - 64))
        | (1 << (b'^' - 64))
        | (1 << (b'_' - 64))
        | (1 << (b'`' - 64))
        | (1 << (b'{' - 64))
        | (1 << (b'|' - 64))
        | (1 << (b'}' - 64))
        | (1 << (b'~' - 64));
    return bitmapHas(LOW, HIGH, c);
}

// go: sdk 1.25.5 mime/grammar.go:72-84 isToken
/// Whether `s` is a 'token' as defined by RFC 1521 and RFC 2045.
pub fn isToken<S: Into<string>>(s: S) -> bool {
    let s: string = s.into();
    if s.Len() == 0 {
        return false;
    }
    for c in s.as_bytes().iter() {
        if !isTokenChar(*c) {
            return false;
        }
    }
    return true;
}
