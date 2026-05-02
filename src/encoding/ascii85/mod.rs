// encoding/ascii85 — Go's `encoding/ascii85`, ported.
//
// btoa / Adobe PostScript and PDF base85 encoding.
//
// Slim deviations:
//   * No NewEncoder / NewDecoder streaming wrappers (Go uses these for
//     io.Writer / io.Reader streaming; goish callers use one-shot
//     Encode/Decode).
//   * `CorruptInputError` is a goish-style typed error.

#![allow(non_snake_case)]

use crate::errors::{error, nil, ErrorTrait, Wrap};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

// ─── MaxEncodedLen (ascii85.go:86) ────────────────────────────────────

/// `ascii85.MaxEncodedLen(n)` — maximum encoded length for `n` source
/// bytes.
pub fn MaxEncodedLen(n: int) -> int {
    // Go: return (n + 3) / 4 * 5
    (n + 3) / 4 * 5
}

// ─── Encode (ascii85.go:27) ───────────────────────────────────────────

/// `ascii85.Encode(dst, src)` — encode `src` into the start of `dst`'s
/// buffer; returns bytes written. Caller is responsible for sizing `dst`
/// to at least `MaxEncodedLen(len(src))`.
///
/// Goish-specific: returns `(slice<byte>, int)` — the resulting `dst`
/// (with the `n` encoded bytes prefilled) and `n` the count.
pub fn Encode(dst: slice<byte>, src: slice<byte>) -> (slice<byte>, int) {
    let mut dv: Vec<byte> = dst.__into_vec();
    let max = MaxEncodedLen(src.Len()) as usize;
    if dv.len() < max {
        dv.resize(max, 0);
    }
    let src_raw: &[byte] = &src;
    let n = encode_into(&mut dv, src_raw);
    (slice::__from_vec(dv), n as int)
}

fn encode_into(dst: &mut [byte], mut src: &[byte]) -> usize {
    if src.is_empty() {
        return 0;
    }
    let mut n: usize = 0;
    let mut di: usize = 0;
    while !src.is_empty() {
        // Go: dst[0..4] = 0
        for k in 0..5 {
            dst[di + k] = 0;
        }
        // Go: unpack up to 4 bytes into uint32 (BE).
        let mut v: u32 = 0;
        let l = src.len();
        if l >= 4 {
            v |= src[3] as u32;
        }
        if l >= 3 {
            v |= (src[2] as u32) << 8;
        }
        if l >= 2 {
            v |= (src[1] as u32) << 16;
        }
        v |= (src[0] as u32) << 24;

        // Go: special case zero (!!!!!) shortens to 'z'.
        if v == 0 && src.len() >= 4 {
            dst[di] = b'z';
            di += 1;
            src = &src[4..];
            n += 1;
            continue;
        }

        // Go: 5 base-85 digits starting at '!'.
        let mut i: i32 = 4;
        let mut vv = v;
        while i >= 0 {
            dst[di + i as usize] = b'!' + (vv % 85) as byte;
            vv /= 85;
            i -= 1;
        }

        // Go: short tail — discard low (4-len) bytes.
        let mut m: usize = 5;
        if src.len() < 4 {
            m -= 4 - src.len();
            src = &[];
        } else {
            src = &src[4..];
        }
        di += m;
        n += m;
    }
    n
}

// ─── Decode (ascii85.go:186) ──────────────────────────────────────────

/// `ascii85.Decode(dst, src, flush)` — decode `src` into `dst`. Returns
/// `(ndst, nsrc, err)` matching Go's signature. `flush=true` indicates
/// `src` is the full input (process trailing partial block).
pub fn Decode(dst: slice<byte>, src: slice<byte>, flush: bool) -> (slice<byte>, int, int, error) {
    let src_raw: &[byte] = &src;
    let mut dv: Vec<byte> = dst.__into_vec();
    // Ensure dst large enough — caller may pass exact size; we extend
    // conservatively to MaxEncodedLen-derived bound.
    let need = (src_raw.len() / 5 * 4) + 8;
    if dv.len() < need {
        dv.resize(need, 0);
    }

    let (ndst, nsrc, err) = decode_into(&mut dv, src_raw, flush);
    dv.truncate(ndst as usize);
    (slice::__from_vec(dv), ndst, nsrc, err)
}

fn decode_into(dst: &mut [byte], src: &[byte], flush: bool) -> (int, int, error) {
    let mut v: u32 = 0;
    let mut nb: u32 = 0;
    let mut ndst: usize = 0;
    let mut nsrc: usize = 0;

    let mut i = 0;
    while i < src.len() {
        if dst.len() - ndst < 4 {
            return (ndst as int, nsrc as int, nil);
        }
        let b = src[i];
        if b <= b' ' {
            // whitespace / control — skip
            i += 1;
            continue;
        } else if b == b'z' && nb == 0 {
            nb = 5;
            v = 0;
        } else if b'!' <= b && b <= b'u' {
            v = v.wrapping_mul(85).wrapping_add((b - b'!') as u32);
            nb += 1;
        } else {
            return (
                0,
                0,
                Wrap(CorruptInputError { offset: i as int }),
            );
        }
        if nb == 5 {
            nsrc = i + 1;
            dst[ndst] = (v >> 24) as byte;
            dst[ndst + 1] = (v >> 16) as byte;
            dst[ndst + 2] = (v >> 8) as byte;
            dst[ndst + 3] = v as byte;
            ndst += 4;
            nb = 0;
            v = 0;
        }
        i += 1;
    }

    if flush {
        nsrc = src.len();
        if nb > 0 {
            // Go: nb == 1 is invalid (not enough bits to recover any byte).
            if nb == 1 {
                return (
                    0,
                    0,
                    Wrap(CorruptInputError { offset: src.len() as int }),
                );
            }
            // Go: pad with worst-case digit 84 to nudge top bits.
            let mut k = nb;
            while k < 5 {
                v = v.wrapping_mul(85).wrapping_add(84);
                k += 1;
            }
            // Go: emit nb-1 high bytes.
            let mut k = 0;
            while k < (nb - 1) as usize {
                dst[ndst] = (v >> 24) as byte;
                v <<= 8;
                ndst += 1;
                k += 1;
            }
        }
    }

    (ndst as int, nsrc as int, nil)
}

// ─── CorruptInputError (ascii85.go:166) ───────────────────────────────

/// `ascii85.CorruptInputError` (ascii85.go:166) — illegal ascii85 byte
/// at the given input offset.
pub struct CorruptInputError {
    pub offset: int,
}

impl ErrorTrait for CorruptInputError {
    fn Error(&self) -> string {
        // Go: "illegal ascii85 data at input byte " + strconv.FormatInt(...)
        let mut out = alloc::string::String::from("illegal ascii85 data at input byte ");
        let mut n = self.offset;
        if n < 0 {
            out.push('-');
            n = -n;
        }
        let mut digits: Vec<u8> = Vec::new();
        if n == 0 {
            digits.push(b'0');
        } else {
            while n > 0 {
                digits.push(b'0' + ((n % 10) as u8));
                n /= 10;
            }
        }
        for &d in digits.iter().rev() {
            out.push(d as char);
        }
        crate::gostring::string::from_bytes(out.as_bytes())
    }
}
