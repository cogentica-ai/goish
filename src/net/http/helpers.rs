// net/http/helpers — line-by-line port of small private helpers from
// Go 1.25 src/net/http/http.go (lines 109-171).
//
// These helpers are package-private in Go; we expose them as
// `pub(crate)` so other modules in `crate::net::http` can use them.
// Tests reach them via `crate::net::http::helpers::*`.

#![allow(non_snake_case)]

use crate::gostring::string;
use crate::strconv;
use crate::strings;
use crate::types::{byte, int};
use crate::unicode::utf8;
use crate::{append, make};

/// `hasPort` — http.go:111.
///
/// Given a string of the form "host", "host:port", or "[ipv6::address]:port",
/// return true if the string includes a port.
///
/// Go: `func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }`
pub fn hasPort(s: &string) -> bool {
    strings::LastIndex(s.clone(), string::from(":")) > strings::LastIndex(s.clone(), string::from("]"))
}

/// `removeEmptyPort` — http.go:115.
///
/// Strips the empty port in ":port" to "" as mandated by RFC 3986
/// Section 6.2.3.
pub fn removeEmptyPort(host: string) -> string {
    // Go: if hasPort(host) { return strings.TrimSuffix(host, ":") }
    if hasPort(&host) {
        return strings::TrimSuffix(host, string::from(":"));
    }
    // Go: return host
    host
}

/// `isTokenByte` — RFC 7230 token char. Allows alnum and
/// `!#$%&'*+-.^_` `\`` `|~`. Mirrors `httpguts.IsTokenRune` for ASCII.
fn isTokenByte(b: byte) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
        b'^' | b'_' | b'`' | b'|' | b'~' |
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
}

/// `isToken` — http.go:127.
///
/// Reports whether v is a valid RFC 7230 token (also known as
/// `ValidHeaderFieldName` for historical reasons; see Go issue #67031).
///
/// Slim: bytes-only ASCII check. Real Go calls into
/// `golang.org/x/net/http/httpguts.ValidHeaderFieldName`, which
/// validates each rune; for ASCII the result is the same.
pub fn isToken(v: &string) -> bool {
    // Go: if len(s) == 0 { return false } — implicit; httpguts checks this.
    if v.Len() == 0 {
        return false;
    }
    // Go: for each rune, !httpguts.IsTokenRune(r) ...
    for i in 0..v.Len() {
        if !isTokenByte(v[i]) {
            return false;
        }
    }
    true
}

/// `stringContainsCTLByte` — http.go:133.
///
/// Reports whether s contains any ASCII control character.
pub fn stringContainsCTLByte(s: &string) -> bool {
    // Go: for i := 0; i < len(s); i++ {
    //         b := s[i]; if b < ' ' || b == 0x7f { return true }
    //     }
    for i in 0..s.Len() {
        let b = s[i];
        if b < b' ' || b == 0x7f {
            return true;
        }
    }
    // Go: return false
    false
}

/// `hexEscapeNonASCII` — http.go:143.
///
/// Percent-encodes any byte ≥ 0x80 as `%XX` (lowercase hex).
/// Used when emitting `Location:` headers so non-ASCII bytes survive
/// transit.
pub fn hexEscapeNonASCII(s: string) -> string {
    // Go: newLen := 0
    let mut newLen: int = 0;
    // Go: for i := 0; i < len(s); i++ {
    //         if s[i] >= utf8.RuneSelf { newLen += 3 } else { newLen++ }
    //     }
    for i in 0..s.Len() {
        if s[i] >= utf8::RuneSelf {
            newLen += 3;
        } else {
            newLen += 1;
        }
    }
    // Go: if newLen == len(s) { return s }
    if newLen == s.Len() {
        return s;
    }
    // Go: b := make([]byte, 0, newLen)
    let mut b = make!([]byte, 0, newLen);
    // Go: var pos int
    let mut pos: int = 0;
    // Go: for i := 0; i < len(s); i++ {
    for i in 0..s.Len() {
        // Go: if s[i] >= utf8.RuneSelf {
        if s[i] >= utf8::RuneSelf {
            // Go: if pos < i { b = append(b, s[pos:i]...) }
            if pos < i {
                let chunk = string::from_bytes(&s.as_bytes()[pos as usize..i as usize]);
                for j in 0..chunk.Len() {
                    b = append!(b, chunk[j]);
                }
            }
            // Go: b = append(b, '%')
            b = append!(b, b'%');
            // Go: b = strconv.AppendInt(b, int64(s[i]), 16)
            b = strconv::AppendInt(b, s[i] as int, 16);
            // Go: pos = i + 1
            pos = i + 1;
        }
    }
    // Go: if pos < len(s) { b = append(b, s[pos:]...) }
    if pos < s.Len() {
        let tail = string::from_bytes(&s.as_bytes()[pos as usize..]);
        for j in 0..tail.Len() {
            b = append!(b, tail[j]);
        }
    }
    // Go: return string(b)
    crate::convert::string(b)
}
