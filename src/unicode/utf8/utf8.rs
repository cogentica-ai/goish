// go: file unicode/utf8/utf8.go decls: FullRune, FullRuneInString, DecodeRune, DecodeRuneInString, DecodeLastRune, DecodeLastRuneInString, RuneLen, EncodeRune, encodeRuneNonASCII, AppendRune, appendRuneNonASCII, RuneCount, RuneCountInString, RuneStart, Valid, ValidString, ValidRune
//
// goishlint:ignore GOISH021 first, acceptRanges, acceptRange, xx, as, s1, s2, s3, s4, s5, s6, s7, locb, hicb, t1, t5, mask2, mask3, mask4 — Go decodes
//     with a 256-entry `first` table whose nibbles index a five-entry
//     `acceptRanges` table; the constants above exist only to build
//     those two, and to make the table's source line up in columns.
//     goish's `DecodeRune` branches on the leading byte's range
//     directly, so there is no table and nothing for them to name.
//     The accepted byte ranges are identical — that is what the
//     smoke's Go-derived vectors check.
//
// unicode/utf8/utf8.go — translation between UTF-8 byte sequences and
// Unicode code points (`rune` = i32).
//
// Byte-slice arguments take `&[byte]`; since `slice<T>` derefs to
// `[T]`, callers pass `&xs` and Rust's auto-deref does the rest.
// String arguments take `&string`, which is a borrow of an `Arc<[u8]>`
// handle.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::convert::{byte as tobyte, int as toint, rune as torune, uint32 as touint32};
use crate::types::{byte, int, rune};

extern crate alloc;
use alloc::vec::Vec;

// ─── Constants — Go's own, same names and values ──────────────────────

// go: sdk 1.25.5 unicode/utf8/utf8.go:14-19 RuneError
/// The "error" rune, a.k.a. the Unicode replacement character.
pub const RuneError: rune = 0xFFFD;

// go: sdk 1.25.5 unicode/utf8/utf8.go:14-19 RuneSelf
/// Characters below `RuneSelf` are represented as themselves in a
/// single byte.
pub const RuneSelf: byte = 0x80;

// go: sdk 1.25.5 unicode/utf8/utf8.go:14-19 MaxRune
/// Maximum valid Unicode code point.
pub const MaxRune: rune = 0x10FFFF;

// go: sdk 1.25.5 unicode/utf8/utf8.go:14-19 UTFMax
/// Maximum number of bytes in a UTF-8 encoded Unicode character.
pub const UTFMax: int = 4;

// go: sdk 1.25.5 unicode/utf8/utf8.go:22-25 surrogateMin
/// Code points in the surrogate range are not valid for UTF-8.
const surrogateMin: rune = 0xD800;

// go: sdk 1.25.5 unicode/utf8/utf8.go:22-25 surrogateMax
const surrogateMax: rune = 0xDFFF;

// go: sdk 1.25.5 unicode/utf8/utf8.go:27-60 tx
/// The continuation-byte tag, `0b10xxxxxx`.
const tx: byte = 0b1000_0000;

// go: sdk 1.25.5 unicode/utf8/utf8.go:27-60 t2
const t2: byte = 0b1100_0000;

// go: sdk 1.25.5 unicode/utf8/utf8.go:27-60 t3
const t3: byte = 0b1110_0000;

// go: sdk 1.25.5 unicode/utf8/utf8.go:27-60 t4
const t4: byte = 0b1111_0000;

// go: sdk 1.25.5 unicode/utf8/utf8.go:27-60 maskx
const maskx: byte = 0b0011_1111;

// go: sdk 1.25.5 unicode/utf8/utf8.go:27-60 rune1Max
const rune1Max: rune = (1 << 7) - 1;

// go: sdk 1.25.5 unicode/utf8/utf8.go:27-60 rune2Max
const rune2Max: rune = (1 << 11) - 1;

// go: sdk 1.25.5 unicode/utf8/utf8.go:27-60 rune3Max
const rune3Max: rune = (1 << 16) - 1;

// go: sdk 1.25.5 unicode/utf8/utf8.go:62-66 runeErrorByte0
/// The three bytes of `RuneError`'s encoding, precomputed as Go does.
const runeErrorByte0: byte = t3 | ((RuneError >> 12) as byte); // goishlint:ignore GOISH005 - a `const` initialiser cannot call `byte(...)`.

// go: sdk 1.25.5 unicode/utf8/utf8.go:62-66 runeErrorByte1
const runeErrorByte1: byte = tx | (((RuneError >> 6) as byte) & maskx); // goishlint:ignore GOISH005 - a `const` initialiser cannot call `byte(...)`.

// go: sdk 1.25.5 unicode/utf8/utf8.go:64-68 runeErrorByte2
const runeErrorByte2: byte = tx | ((RuneError as byte) & maskx); // goishlint:ignore GOISH005 - a `const` initialiser cannot call `byte(...)`.

// ─── Decode ────────────────────────────────────────────────────────────

// go: sdk 1.25.5 unicode/utf8/utf8.go:157-195 DecodeRune
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
        return (torune(b0), 1);
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
        2 => torune(b0 & 0x1F),
        3 => torune(b0 & 0x0F),
        4 => torune(b0 & 0x07),
        _ => unreachable!(),
    };
    for i in 1..n {
        let bi = p[i];
        if bi & 0xC0 != 0x80 {
            return (RuneError, 1);
        }
        r = (r << 6) | torune(bi & 0x3F);
    }

    // Reject overlong encodings, surrogates, and out-of-range code points.
    let min: rune = match n {
        2 => 0x80,
        3 => 0x800,
        4 => 0x10000,
        _ => 0,
    };
    if r < min || r > MaxRune || (r >= surrogateMin && r <= surrogateMax) {
        return (RuneError, 1);
    }

    return (r, toint(n));
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:205-243 DecodeRuneInString
/// Decode the first rune in `s`. Same semantics as `DecodeRune`.
#[allow(non_snake_case)]
pub fn DecodeRuneInString<S: AsRef<str>>(s: S) -> (rune, int) {
    return DecodeRune(s.as_ref().as_bytes());
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:253-280 DecodeLastRune
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
    return (RuneError, 1);
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:290-317 DecodeLastRuneInString
#[allow(non_snake_case)]
pub fn DecodeLastRuneInString<S: AsRef<str>>(s: S) -> (rune, int) {
    return DecodeLastRune(s.as_ref().as_bytes());
}

// ─── Encode ────────────────────────────────────────────────────────────

// go: sdk 1.25.5 unicode/utf8/utf8.go:336-348 EncodeRune
/// Writes into `p` (which must be large enough) the UTF-8 encoding of
/// `r` and returns the number of bytes written. If `r` is out of range,
/// or a surrogate half, it writes the encoding of [`RuneError`].
pub fn EncodeRune(p: &mut [byte], r: rune) -> int {
    // This function is inlineable for fast handling of ASCII.
    if touint32(r) <= touint32(rune1Max) {
        p[0] = tobyte(r);
        return 1;
    }
    return encodeRuneNonASCII(p, r);
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:350-379 encodeRuneNonASCII
/// Go takes the rune unsigned so a negative value falls into the
/// default arm and encodes `RuneError`, rather than needing its own
/// test.
fn encodeRuneNonASCII(p: &mut [byte], r: rune) -> int {
    let i = touint32(r);
    if i <= touint32(rune2Max) {
        p[0] = t2 | tobyte(r >> 6);
        p[1] = tx | (tobyte(r) & maskx);
        return 2;
    }
    if i < touint32(surrogateMin) || (touint32(surrogateMax) < i && i <= touint32(rune3Max)) {
        p[0] = t3 | tobyte(r >> 12);
        p[1] = tx | (tobyte(r >> 6) & maskx);
        p[2] = tx | (tobyte(r) & maskx);
        return 3;
    }
    if i > touint32(rune3Max) && i <= touint32(MaxRune) {
        p[0] = t4 | tobyte(r >> 18);
        p[1] = tx | (tobyte(r >> 12) & maskx);
        p[2] = tx | (tobyte(r >> 6) & maskx);
        p[3] = tx | (tobyte(r) & maskx);
        return 4;
    }
    // Out of range, or a surrogate half.
    p[0] = runeErrorByte0;
    p[1] = runeErrorByte1;
    p[2] = runeErrorByte2;
    return 3;
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:321-337 RuneLen
/// Number of bytes needed to encode `r` in UTF-8. -1 if `r` is invalid.
#[allow(non_snake_case)]
pub fn RuneLen(r: rune) -> int {
    return if !ValidRune(r) {
        -1
    } else if r < 0x80 {
        1
    } else if r < 0x800 {
        2
    } else if r < 0x10000 {
        3
    } else {
        4
    };
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:381-390 AppendRune
/// Appends the UTF-8 encoding of `r` to the end of `p` and returns the
/// extended buffer. If the rune is out of range, it appends the
/// encoding of [`RuneError`].
pub fn AppendRune(p: crate::goslice::slice<byte>, r: rune) -> crate::goslice::slice<byte> {
    // This function is inlineable for fast handling of ASCII.
    if touint32(r) <= touint32(rune1Max) {
        let mut v: Vec<byte> = p.__into_vec();
        v.push(tobyte(r));
        return crate::goslice::slice::__from_vec(v);
    }
    return appendRuneNonASCII(p, r);
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:392-405 appendRuneNonASCII
fn appendRuneNonASCII(p: crate::goslice::slice<byte>, r: rune) -> crate::goslice::slice<byte> {
    let mut v: Vec<byte> = p.__into_vec();
    let i = touint32(r);
    if i <= touint32(rune2Max) {
        v.push(t2 | tobyte(r >> 6));
        v.push(tx | (tobyte(r) & maskx));
    } else if i < touint32(surrogateMin) || (touint32(surrogateMax) < i && i <= touint32(rune3Max))
    {
        v.push(t3 | tobyte(r >> 12));
        v.push(tx | (tobyte(r >> 6) & maskx));
        v.push(tx | (tobyte(r) & maskx));
    } else if i > touint32(rune3Max) && i <= touint32(MaxRune) {
        v.push(t4 | tobyte(r >> 18));
        v.push(tx | (tobyte(r >> 12) & maskx));
        v.push(tx | (tobyte(r >> 6) & maskx));
        v.push(tx | (tobyte(r) & maskx));
    } else {
        v.push(runeErrorByte0);
        v.push(runeErrorByte1);
        v.push(runeErrorByte2);
    }
    return crate::goslice::slice::__from_vec(v);
}

// ─── Counting / validation ─────────────────────────────────────────────

// go: sdk 1.25.5 unicode/utf8/utf8.go:408-418 RuneCount
/// Number of runes in `p`. Each invalid byte counts as one rune.
///
/// Generic over `AsRef<[u8]>` so callers can pass `&[u8]`,
/// `slice<byte>` (via Deref), `bytes::Buffer::Bytes()`, or any other
/// byte source without a manual coercion. Goish §3 forbids leaking
/// `&[u8]` in port-facing signatures, so the bound preserves the
/// goish call-style while keeping internal callers ergonomic.
#[allow(non_snake_case)]
pub fn RuneCount<P: AsRef<[byte]>>(p: P) -> int {
    let bytes = p.as_ref();
    let mut i = 0usize;
    let mut n: int = 0;
    while i < bytes.len() {
        n += 1;
        if bytes[i] < RuneSelf {
            i += 1;
        } else {
            let (_, sz) = DecodeRune(&bytes[i..]);
            i += sz as usize;
        }
    }
    return n;
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:421-426 RuneCountInString
#[allow(non_snake_case)]
pub fn RuneCountInString<S: AsRef<str>>(s: S) -> int {
    return RuneCount(s.as_ref().as_bytes());
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:431-431 RuneStart
/// True if `b` is the first byte of a UTF-8 sequence (not a continuation).
#[allow(non_snake_case)]
pub fn RuneStart(b: byte) -> bool {
    return b & 0xC0 != 0x80;
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:434-482 Valid
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
    return true;
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:485-528 ValidString
#[allow(non_snake_case)]
pub fn ValidString<S: AsRef<str>>(s: S) -> bool {
    return Valid(s.as_ref().as_bytes());
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:532-540 ValidRune
/// True if `r` is a valid Unicode code point (not a surrogate, ≤ MaxRune).
#[allow(non_snake_case)]
pub fn ValidRune(r: rune) -> bool {
    return r >= 0 && r <= MaxRune && !(r >= surrogateMin && r <= surrogateMax);
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:110-127 FullRune
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
    return p.len() >= need;
}

// go: sdk 1.25.5 unicode/utf8/utf8.go:130-147 FullRuneInString
#[allow(non_snake_case)]
pub fn FullRuneInString<S: AsRef<str>>(s: S) -> bool {
    return FullRune(s.as_ref().as_bytes());
}
