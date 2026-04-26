// unicode/utf8 — Go's `unicode/utf8`, ported.
//
// Translates between UTF-8 byte sequences and Unicode code points
// (`rune` = i32). Follows Go's API surface line-for-line:
//
//   Go                                     goish
//   ────────────────────────────────────   ────────────────────────────────────
//   r, sz := utf8.DecodeRune(b)            let (r, sz) = utf8::DecodeRune(&b);
//   r, sz := utf8.DecodeRuneInString(s)    let (r, sz) = utf8::DecodeRuneInString(&s);
//   n := utf8.EncodeRune(buf, r)           let n = utf8::EncodeRune(&mut buf, r);
//   n := utf8.RuneCountInString(s)         let n = utf8::RuneCountInString(&s);
//   if utf8.ValidRune(r) { ... }           if utf8::ValidRune(r) { ... }
//
// Byte-slice arguments take `&[byte]` (Rust borrow); since `GoSlice<T>`
// derefs to `[T]`, callers pass `&xs` and Rust's auto-deref does the
// rest. String arguments take `&GoString` (cheap — just a borrow of an
// `Arc<[u8]>` handle).

use crate::gostring::GoString;
use crate::types::{byte, int, rune};

extern crate alloc;
use alloc::vec::Vec;

// ─── Constants — same names, same values as Go's unicode/utf8 ──────────

/// The "error" rune / Unicode replacement character. Returned for
/// any decoding failure (matches Go's `RuneError` = '�').
pub const RuneError: rune = 0xFFFD;

/// Bytes < `RuneSelf` represent themselves in a single byte
/// (the ASCII fast-path threshold).
pub const RuneSelf: byte = 0x80;

/// Maximum valid Unicode code point.
pub const MaxRune: rune = 0x10FFFF;

/// Maximum number of bytes of a UTF-8 encoded rune.
pub const UTFMax: int = 4;

const SURROGATE_MIN: rune = 0xD800;
const SURROGATE_MAX: rune = 0xDFFF;

// ─── Decode ────────────────────────────────────────────────────────────

/// Decode the first rune in `p`. Returns (rune, byte-size).
///
/// On error: `(RuneError, 1)` if `p` starts with an invalid byte
/// or a partial sequence; `(RuneError, 0)` only if `p` is empty.
#[allow(non_snake_case)]
pub fn DecodeRune(p: &[byte]) -> (rune, int) {
    if p.is_empty() {
        return (RuneError, 0);
    }
    let b0 = p[0];

    // ASCII fast path
    if b0 < RuneSelf {
        return (b0 as rune, 1);
    }

    // Determine sequence length from the leading byte's high bits.
    // Anything not matching a valid pattern is invalid.
    let n: usize = if b0 & 0xE0 == 0xC0 {
        2
    } else if b0 & 0xF0 == 0xE0 {
        3
    } else if b0 & 0xF8 == 0xF0 {
        4
    } else {
        return (RuneError, 1);
    };

    if p.len() < n {
        return (RuneError, 1);
    }

    // Accumulate code point from leading + continuation bytes.
    let mut r: rune = match n {
        2 => (b0 & 0x1F) as rune,
        3 => (b0 & 0x0F) as rune,
        4 => (b0 & 0x07) as rune,
        _ => unreachable!(),
    };
    for i in 1..n {
        let bi = p[i];
        if bi & 0xC0 != 0x80 {
            return (RuneError, 1);
        }
        r = (r << 6) | ((bi & 0x3F) as rune);
    }

    // Reject overlong encodings, surrogates, and out-of-range code points.
    let min: rune = match n {
        2 => 0x80,
        3 => 0x800,
        4 => 0x10000,
        _ => 0,
    };
    if r < min || r > MaxRune || (r >= SURROGATE_MIN && r <= SURROGATE_MAX) {
        return (RuneError, 1);
    }

    (r, n as int)
}

/// Decode the first rune in `s`. Same semantics as `DecodeRune`.
#[allow(non_snake_case)]
pub fn DecodeRuneInString(s: &GoString) -> (rune, int) {
    DecodeRune(s.as_bytes())
}

/// Decode the *last* rune in `p` (scans backward to find a leading byte).
#[allow(non_snake_case)]
pub fn DecodeLastRune(p: &[byte]) -> (rune, int) {
    let n = p.len();
    if n == 0 {
        return (RuneError, 0);
    }
    // Scan back at most UTFMax bytes for a leading byte.
    let start = n.saturating_sub(UTFMax as usize);
    let mut i = n - 1;
    while i >= start {
        if RuneStart(p[i]) {
            let (r, sz) = DecodeRune(&p[i..]);
            // Must consume exactly the trailing slice — partial decodes
            // mean the leading byte we found wasn't really one.
            if sz as usize == n - i {
                return (r, sz);
            }
            break;
        }
        if i == start {
            break;
        }
        i -= 1;
    }
    (RuneError, 1)
}

#[allow(non_snake_case)]
pub fn DecodeLastRuneInString(s: &GoString) -> (rune, int) {
    DecodeLastRune(s.as_bytes())
}

// ─── Encode ────────────────────────────────────────────────────────────

/// Encode `r` into `p` (which must be at least `RuneLen(r)` bytes).
/// Invalid runes are encoded as `RuneError`. Returns bytes written.
#[allow(non_snake_case)]
pub fn EncodeRune(p: &mut [byte], r: rune) -> int {
    let r = if !ValidRune(r) { RuneError } else { r };
    if r < 0x80 {
        p[0] = r as byte;
        1
    } else if r < 0x800 {
        p[0] = 0xC0 | (r >> 6) as byte;
        p[1] = 0x80 | (r as byte & 0x3F);
        2
    } else if r < 0x10000 {
        p[0] = 0xE0 | (r >> 12) as byte;
        p[1] = 0x80 | ((r >> 6) as byte & 0x3F);
        p[2] = 0x80 | (r as byte & 0x3F);
        3
    } else {
        p[0] = 0xF0 | (r >> 18) as byte;
        p[1] = 0x80 | ((r >> 12) as byte & 0x3F);
        p[2] = 0x80 | ((r >> 6) as byte & 0x3F);
        p[3] = 0x80 | (r as byte & 0x3F);
        4
    }
}

/// Number of bytes needed to encode `r` in UTF-8. -1 if `r` is invalid.
#[allow(non_snake_case)]
pub fn RuneLen(r: rune) -> int {
    if !ValidRune(r) {
        -1
    } else if r < 0x80 {
        1
    } else if r < 0x800 {
        2
    } else if r < 0x10000 {
        3
    } else {
        4
    }
}

/// Append the UTF-8 encoding of `r` to `p`, returning the extended slice.
#[allow(non_snake_case)]
pub fn AppendRune(p: crate::goslice::GoSlice<byte>, r: rune) -> crate::goslice::GoSlice<byte> {
    let r = if !ValidRune(r) { RuneError } else { r };
    let mut v: Vec<byte> = p.into_vec();
    if r < 0x80 {
        v.push(r as byte);
    } else if r < 0x800 {
        v.push(0xC0 | (r >> 6) as byte);
        v.push(0x80 | (r as byte & 0x3F));
    } else if r < 0x10000 {
        v.push(0xE0 | (r >> 12) as byte);
        v.push(0x80 | ((r >> 6) as byte & 0x3F));
        v.push(0x80 | (r as byte & 0x3F));
    } else {
        v.push(0xF0 | (r >> 18) as byte);
        v.push(0x80 | ((r >> 12) as byte & 0x3F));
        v.push(0x80 | ((r >> 6) as byte & 0x3F));
        v.push(0x80 | (r as byte & 0x3F));
    }
    crate::goslice::GoSlice::from_vec(v)
}

// ─── Counting / validation ─────────────────────────────────────────────

/// Number of runes in `p`. Each invalid byte counts as one rune.
#[allow(non_snake_case)]
pub fn RuneCount(p: &[byte]) -> int {
    let mut i = 0usize;
    let mut n: int = 0;
    while i < p.len() {
        n += 1;
        if p[i] < RuneSelf {
            i += 1;
        } else {
            let (_, sz) = DecodeRune(&p[i..]);
            i += sz as usize;
        }
    }
    n
}

#[allow(non_snake_case)]
pub fn RuneCountInString(s: &GoString) -> int {
    RuneCount(s.as_bytes())
}

/// True if `b` is the first byte of a UTF-8 sequence (not a continuation).
#[allow(non_snake_case)]
pub fn RuneStart(b: byte) -> bool {
    b & 0xC0 != 0x80
}

/// True if `p` is valid UTF-8.
#[allow(non_snake_case)]
pub fn Valid(p: &[byte]) -> bool {
    let mut i = 0usize;
    while i < p.len() {
        if p[i] < RuneSelf {
            i += 1;
            continue;
        }
        let (r, sz) = DecodeRune(&p[i..]);
        if r == RuneError && sz == 1 {
            return false;
        }
        i += sz as usize;
    }
    true
}

#[allow(non_snake_case)]
pub fn ValidString(s: &GoString) -> bool {
    Valid(s.as_bytes())
}

/// True if `r` is a valid Unicode code point (not a surrogate, ≤ MaxRune).
#[allow(non_snake_case)]
pub fn ValidRune(r: rune) -> bool {
    r >= 0 && r <= MaxRune && !(r >= SURROGATE_MIN && r <= SURROGATE_MAX)
}

/// True if `p` contains at least one full UTF-8 sequence at its start.
#[allow(non_snake_case)]
pub fn FullRune(p: &[byte]) -> bool {
    if p.is_empty() {
        return false;
    }
    let b0 = p[0];
    if b0 < RuneSelf {
        return true;
    }
    let need: usize = if b0 & 0xE0 == 0xC0 {
        2
    } else if b0 & 0xF0 == 0xE0 {
        3
    } else if b0 & 0xF8 == 0xF0 {
        4
    } else {
        // Invalid lead byte — DecodeRune will return (RuneError, 1) i.e.
        // it can produce a result without more bytes, so "full" is true.
        return true;
    };
    p.len() >= need
}

#[allow(non_snake_case)]
pub fn FullRuneInString(s: &GoString) -> bool {
    FullRune(s.as_bytes())
}
