// encoding/base64 — Go's base64 codec.
//
// Reference: /share/go/src/encoding/base64/base64.go.
//
// Public API:
//
//   base64::StdEncoding.EncodeToString(&src)        // "+/=" alphabet
//   base64::URLEncoding.EncodeToString(&src)        // "-_=" alphabet
//   base64::RawStdEncoding.EncodeToString(&src)     // no '=' padding
//   base64::RawURLEncoding.EncodeToString(&src)     // no '=' padding
//   base64::StdEncoding.DecodeString(&s) -> (Vec<u8>, error)
//
// All four are values of type `Encoding`. The alphabet + padding
// flag are stored in the Encoding; methods are dispatched on it.
//
// What v1 omits: NewEncoding, WithPadding, Strict, NewEncoder/
// NewDecoder (io wrappers), AppendEncode/AppendDecode. Add later.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use alloc::vec;
use alloc::vec::Vec;

use crate::errors::{error, ErrorTrait};
use crate::gostring::string;
use crate::types::int;

const STD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const PAD_CHAR: u8 = b'=';

/// `base64.Encoding` — alphabet + padding configuration.
#[derive(Copy, Clone)]
pub struct Encoding {
    alphabet: &'static [u8; 64],
    padded: bool,
    /// Reverse-lookup table built lazily-static at module init.
    /// 255 = "not in alphabet".
    decode_table: &'static [u8; 256],
}

// Decode tables — computed at compile time for the two alphabets.
const STD_DECODE: [u8; 256] = build_decode_table(STD_ALPHABET);
const URL_DECODE: [u8; 256] = build_decode_table(URL_ALPHABET);

const fn build_decode_table(alphabet: &[u8; 64]) -> [u8; 256] {
    let mut t = [255u8; 256];
    let mut i = 0;
    while i < 64 {
        t[alphabet[i] as usize] = i as u8;
        i += 1;
    }
    t
}

/// Standard base64 encoding (RFC 4648 §4) with `=` padding.
pub static StdEncoding: Encoding = Encoding {
    alphabet: STD_ALPHABET,
    padded: true,
    decode_table: &STD_DECODE,
};

/// URL-safe base64 encoding (RFC 4648 §5) with `=` padding.
pub static URLEncoding: Encoding = Encoding {
    alphabet: URL_ALPHABET,
    padded: true,
    decode_table: &URL_DECODE,
};

/// Standard base64 encoding without `=` padding.
pub static RawStdEncoding: Encoding = Encoding {
    alphabet: STD_ALPHABET,
    padded: false,
    decode_table: &STD_DECODE,
};

/// URL-safe base64 encoding without `=` padding.
pub static RawURLEncoding: Encoding = Encoding {
    alphabet: URL_ALPHABET,
    padded: false,
    decode_table: &URL_DECODE,
};

impl Encoding {
    /// Length of the encoded output for `n` source bytes.
    pub fn EncodedLen(&self, n: int) -> int {
        if self.padded {
            (n + 2) / 3 * 4
        } else {
            (n * 8 + 5) / 6
        }
    }

    /// Maximum length of the decoded output for `n` source chars.
    pub fn DecodedLen(&self, n: int) -> int {
        if self.padded {
            n / 4 * 3
        } else {
            n * 6 / 8
        }
    }

    /// Encode `src` into the `Encoding`'s alphabet and return as
    /// string. Mirrors `Encoding.EncodeToString`
    /// (base64.go:206).
    pub fn EncodeToString(&self, src: &[u8]) -> string {
        let mut dst = vec![0u8; self.EncodedLen(src.len() as int) as usize];
        self.encode_into(&mut dst, src);
        string::from_bytes(&dst)
    }

    fn encode_into(&self, dst: &mut [u8], src: &[u8]) {
        let mut di = 0usize;
        let mut si = 0usize;
        let alpha = self.alphabet;

        // Process full 3-byte groups → 4 chars.
        while si + 3 <= src.len() {
            let v = ((src[si] as u32) << 16)
                | ((src[si + 1] as u32) << 8)
                | (src[si + 2] as u32);
            dst[di] = alpha[((v >> 18) & 0x3f) as usize];
            dst[di + 1] = alpha[((v >> 12) & 0x3f) as usize];
            dst[di + 2] = alpha[((v >> 6) & 0x3f) as usize];
            dst[di + 3] = alpha[(v & 0x3f) as usize];
            di += 4;
            si += 3;
        }

        // Tail: 1 or 2 leftover bytes.
        let remain = src.len() - si;
        if remain == 0 {
            return;
        }
        let mut v: u32 = (src[si] as u32) << 16;
        if remain == 2 {
            v |= (src[si + 1] as u32) << 8;
        }
        dst[di] = alpha[((v >> 18) & 0x3f) as usize];
        dst[di + 1] = alpha[((v >> 12) & 0x3f) as usize];
        if remain == 2 {
            dst[di + 2] = alpha[((v >> 6) & 0x3f) as usize];
            if self.padded {
                dst[di + 3] = PAD_CHAR;
            }
        } else if self.padded {
            dst[di + 2] = PAD_CHAR;
            dst[di + 3] = PAD_CHAR;
        }
    }

    /// Decode `s` (a base64 string) into bytes. Mirrors
    /// `Encoding.DecodeString` (base64.go).
    pub fn DecodeString(&self, s: &str) -> (Vec<u8>, error) {
        let src = s.as_bytes();
        // Estimate; trim once we know exact length.
        let max_len = self.DecodedLen(src.len() as int) as usize + 3;
        let mut dst = vec![0u8; max_len];
        let (n, err) = self.decode_into(&mut dst, src);
        dst.truncate(n as usize);
        (dst, err)
    }

    fn decode_into(&self, dst: &mut [u8], src: &[u8]) -> (int, error) {
        let table = self.decode_table;
        // Strip trailing '=' for both padded and unpadded variants;
        // count how many we stripped to compute output size.
        let mut end = src.len();
        let mut pad_count = 0usize;
        while end > 0 && src[end - 1] == PAD_CHAR {
            end -= 1;
            pad_count += 1;
        }
        let nominal = &src[..end];

        let mut di = 0usize;
        let mut si = 0usize;
        // Process full 4-char groups (no padding) → 3 bytes.
        while si + 4 <= nominal.len() {
            let mut v: u32 = 0;
            for k in 0..4 {
                let b = table[nominal[si + k] as usize];
                if b == 255 {
                    return (di as int, crate::errors::Wrap(CorruptInputError(si + k)));
                }
                v = (v << 6) | (b as u32);
            }
            dst[di] = (v >> 16) as u8;
            dst[di + 1] = (v >> 8) as u8;
            dst[di + 2] = v as u8;
            di += 3;
            si += 4;
        }

        // Tail: 0, 2, or 3 chars (4 is impossible — handled above).
        let remain = nominal.len() - si;
        if remain == 1 {
            return (di as int, crate::errors::Wrap(CorruptInputError(si)));
        }
        if remain >= 2 {
            let b0 = table[nominal[si] as usize];
            let b1 = table[nominal[si + 1] as usize];
            if b0 == 255 || b1 == 255 {
                return (di as int, crate::errors::Wrap(CorruptInputError(si)));
            }
            dst[di] = ((b0 << 2) | (b1 >> 4)) as u8;
            di += 1;
        }
        if remain == 3 {
            let b1 = table[nominal[si + 1] as usize];
            let b2 = table[nominal[si + 2] as usize];
            if b2 == 255 {
                return (di as int, crate::errors::Wrap(CorruptInputError(si + 2)));
            }
            dst[di] = ((b1 << 4) | (b2 >> 2)) as u8;
            di += 1;
        }

        // For padded variant, validate padding count is consistent
        // with remain (1 char of padding for remain==3, 2 chars
        // for remain==2). For unpadded, pad_count should be 0.
        let _ = pad_count; // not strictly enforced in v1
        (di as int, crate::errors::nil)
    }
}

#[derive(Clone)]
struct CorruptInputError(usize);

impl ErrorTrait for CorruptInputError {
    fn Error(&self) -> string {
        let prefix = b"illegal base64 data at input byte ";
        let n_str = crate::strconv::Itoa(self.0 as int);
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(n_str.as_bytes());
        string::from_bytes(&buf)
    }
}
