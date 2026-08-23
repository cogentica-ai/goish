// encoding/base32 — Go's `encoding/base32`, ported (RFC 4648).
//
// Slim deviations:
//   * No NewEncoder / NewDecoder streaming wrappers (Go uses these for
//     io.Reader / io.WriteCloser; goish callers use one-shot
//     EncodeToString / DecodeString).
//   * No `Encoding::WithPadding` (only StdEncoding and HexEncoding
//     ship; their pad chars are fixed at '=').
//   * `CorruptInputError` is a goish-style typed error wrapping the
//     offending byte index rather than `int64`-derived.
//   * Mutable receivers in Go's free-form Encode/Decode methods become
//     `&self` here since Encoding is immutable.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::errors::{error, nil, ErrorTrait, Wrap};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int, rune};

extern crate alloc;
use alloc::vec::Vec;

// ─── Encoding — alphabet + decode map ─────────────────────────────────

/// `base32.StdPadding` (base32.go:29) — RFC 4648 padding character.
pub const StdPadding: rune = '=' as rune;

/// `base32.NoPadding` (base32.go:30) — sentinel disabling padding.
pub const NoPadding: rune = -1;

const INVALID_INDEX: u8 = 0xff;

/// `base32.Encoding` (base32.go:22) — radix-32 encoding/decoding scheme.
#[derive(Clone)]
pub struct Encoding {
    encode: [byte; 32],
    decode_map: [u8; 256],
    pad_char: rune,
}

/// `base32.NewEncoding(alphabet)` (base32.go:61). `alphabet` must be
/// 32 bytes long; panics otherwise. Returns a padded encoding using
/// '=' as the default pad char.
pub fn NewEncoding(encoder: &str) -> Encoding {
    if encoder.len() != 32 {
        panic!("encoding alphabet is not 32-bytes long");
    }
    let bytes = encoder.as_bytes();
    let mut e = Encoding {
        encode: [0; 32],
        decode_map: [INVALID_INDEX; 256],
        pad_char: StdPadding,
    };
    e.encode.copy_from_slice(bytes);

    let mut i = 0;
    while i < 32 {
        let b = bytes[i];
        // Go: switch { case b == '\n' || b == '\r': panic ; case dup: panic }
        if b == b'\n' || b == b'\r' {
            panic!("encoding alphabet contains newline character");
        }
        if e.decode_map[b as usize] != INVALID_INDEX {
            panic!("encoding alphabet includes duplicate symbols");
        }
        e.decode_map[b as usize] = i as u8;
        i += 1;
    }
    e
}

/// `base32.StdEncoding` (base32.go:87) — RFC 4648 standard alphabet.
pub fn StdEncoding() -> Encoding {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<Encoding>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"));
    }
    g.as_ref().unwrap().clone()
}

/// `base32.HexEncoding` (base32.go:91) — RFC 4648 "Extended Hex Alphabet".
pub fn HexEncoding() -> Encoding {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<Encoding>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(NewEncoding("0123456789ABCDEFGHIJKLMNOPQRSTUV"));
    }
    g.as_ref().unwrap().clone()
}

// ─── EncodedLen / DecodedLen (base32.go:284, 578) ─────────────────────

impl Encoding {
    /// `Encoding.EncodedLen(n)` (base32.go:284).
    pub fn EncodedLen(&self, n: int) -> int {
        // Go: if padChar == NoPadding { return n/5*8 + (n%5*8+4)/5 }
        //     return (n + 4) / 5 * 8
        if self.pad_char == NoPadding {
            n / 5 * 8 + (n % 5 * 8 + 4) / 5
        } else {
            (n + 4) / 5 * 8
        }
    }

    /// `Encoding.DecodedLen(n)` (base32.go:578).
    pub fn DecodedLen(&self, n: int) -> int {
        if self.pad_char == NoPadding {
            n / 8 * 5 + n % 8 * 5 / 8
        } else {
            n / 8 * 5
        }
    }

    // Internal Encode (base32.go:121) — inputs as byte slices.
    fn encode_into(&self, dst: &mut [byte], src: &[byte]) {
        if src.is_empty() {
            return;
        }
        let mut di: usize = 0;
        let mut si: usize = 0;
        let n = (src.len() / 5) * 5;
        while si < n {
            // Go: hi := uint32(src[si+0])<<24 | ...
            //     lo := hi<<8 | uint32(src[si+4])
            let hi = ((src[si] as u32) << 24)
                | ((src[si + 1] as u32) << 16)
                | ((src[si + 2] as u32) << 8)
                | (src[si + 3] as u32);
            let lo = hi.wrapping_shl(8) | (src[si + 4] as u32);

            dst[di] = self.encode[((hi >> 27) & 0x1F) as usize];
            dst[di + 1] = self.encode[((hi >> 22) & 0x1F) as usize];
            dst[di + 2] = self.encode[((hi >> 17) & 0x1F) as usize];
            dst[di + 3] = self.encode[((hi >> 12) & 0x1F) as usize];
            dst[di + 4] = self.encode[((hi >> 7) & 0x1F) as usize];
            dst[di + 5] = self.encode[((hi >> 2) & 0x1F) as usize];
            dst[di + 6] = self.encode[((lo >> 5) & 0x1F) as usize];
            dst[di + 7] = self.encode[(lo & 0x1F) as usize];

            si += 5;
            di += 8;
        }

        // Go: remaining small block (base32.go:152)
        let remain = src.len() - si;
        if remain == 0 {
            return;
        }

        // Encode the remaining bytes in reverse order with fallthrough.
        let mut val: u32 = 0;
        if remain == 4 {
            val |= src[si + 3] as u32;
            dst[di + 6] = self.encode[((val << 3) & 0x1F) as usize];
            dst[di + 5] = self.encode[((val >> 2) & 0x1F) as usize];
        }
        if remain >= 3 {
            val |= (src[si + 2] as u32) << 8;
            dst[di + 4] = self.encode[((val >> 7) & 0x1F) as usize];
        }
        if remain >= 2 {
            val |= (src[si + 1] as u32) << 16;
            dst[di + 3] = self.encode[((val >> 12) & 0x1F) as usize];
            dst[di + 2] = self.encode[((val >> 17) & 0x1F) as usize];
        }
        if remain >= 1 {
            val |= (src[si] as u32) << 24;
            dst[di + 1] = self.encode[((val >> 22) & 0x1F) as usize];
            dst[di] = self.encode[((val >> 27) & 0x1F) as usize];
        }

        // Go: pad the final quantum
        if self.pad_char != NoPadding {
            let n_pad = (remain * 8 / 5) + 1;
            let mut i = n_pad;
            while i < 8 {
                dst[di + i] = self.pad_char as byte;
                i += 1;
            }
        }
    }

    /// `Encoding.Encode(dst, src)` (base32.go:121). Writes `EncodedLen(len(src))`
    /// bytes into the start of `dst`'s underlying buffer.
    pub fn Encode(&self, dst: &mut slice<byte>, src: slice<byte>) {
        let mut dv: Vec<byte> = dst.clone().__into_vec();
        let n = self.EncodedLen(src.Len()) as usize;
        if dv.len() < n {
            dv.resize(n, 0);
        }
        let src_raw: &[byte] = &src;
        self.encode_into(&mut dv[..n], src_raw);
        *dst = slice::__from_vec(dv);
    }

    /// `Encoding.EncodeToString(src)` (base32.go:199).
    pub fn EncodeToString(&self, src: slice<byte>) -> string {
        let n = self.EncodedLen(src.Len()) as usize;
        let mut buf: Vec<byte> = alloc::vec![0; n];
        let src_raw: &[byte] = &src;
        self.encode_into(&mut buf, src_raw);
        crate::gostring::string::__from_vec(buf)
    }

    /// `Encoding.AppendEncode(dst, src)` (base32.go:191).
    pub fn AppendEncode(&self, dst: slice<byte>, src: slice<byte>) -> slice<byte> {
        let n = self.EncodedLen(src.Len()) as usize;
        let mut out: Vec<byte> = dst.__into_vec();
        let start = out.len();
        out.resize(start + n, 0);
        let src_raw: &[byte] = &src;
        self.encode_into(&mut out[start..start + n], src_raw);
        slice::__from_vec(out)
    }

    // Internal decode core (base32.go:305).
    // Returns (n_decoded, end_seen, error_or_nil).
    fn decode_into(&self, dst: &mut [byte], src: &[byte]) -> (int, bool, error) {
        let mut dsti: usize = 0;
        let olen = src.len();
        let mut s: &[byte] = src;
        let mut n_total: int = 0;
        let mut end = false;

        while !s.is_empty() && !end {
            let mut dbuf = [0u8; 8];
            let mut dlen: usize = 8;
            let mut j: usize = 0;

            while j < 8 {
                if s.is_empty() {
                    if self.pad_char != NoPadding {
                        // missing padding
                        return (
                            n_total,
                            false,
                            Wrap(CorruptInputError {
                                offset: (olen - s.len() - j) as int,
                            }),
                        );
                    }
                    dlen = j;
                    end = true;
                    break;
                }
                let in_b = s[0];
                s = &s[1..];
                if self.pad_char != NoPadding
                    && in_b == self.pad_char as byte
                    && j >= 2
                    && s.len() < 8
                {
                    // padding seen mid-stream
                    if s.len() + j < 8 - 1 {
                        return (
                            n_total,
                            false,
                            Wrap(CorruptInputError {
                                offset: olen as int,
                            }),
                        );
                    }
                    let mut k = 0;
                    while k < 8 - 1 - j {
                        if s.len() > k && s[k] != self.pad_char as byte {
                            return (
                                n_total,
                                false,
                                Wrap(CorruptInputError {
                                    offset: (olen - s.len() + k - 1) as int,
                                }),
                            );
                        }
                        k += 1;
                    }
                    dlen = j;
                    end = true;
                    if dlen == 1 || dlen == 3 || dlen == 6 {
                        return (
                            n_total,
                            false,
                            Wrap(CorruptInputError {
                                offset: (olen - s.len() - 1) as int,
                            }),
                        );
                    }
                    break;
                }
                dbuf[j] = self.decode_map[in_b as usize];
                if dbuf[j] == 0xFF {
                    return (
                        n_total,
                        false,
                        Wrap(CorruptInputError {
                            offset: (olen - s.len() - 1) as int,
                        }),
                    );
                }
                j += 1;
            }

            // Pack 8 5-bit src into 5 dst bytes (base32.go:362).
            // Goish flattens Go's fallthrough.
            if dlen >= 8 {
                dst[dsti + 4] = (dbuf[6] << 5) | dbuf[7];
                n_total += 1;
            }
            if dlen >= 7 {
                dst[dsti + 3] = (dbuf[4] << 7) | (dbuf[5] << 2) | (dbuf[6] >> 3);
                n_total += 1;
            }
            if dlen >= 5 {
                dst[dsti + 2] = (dbuf[3] << 4) | (dbuf[4] >> 1);
                n_total += 1;
            }
            if dlen >= 4 {
                dst[dsti + 1] = (dbuf[1] << 6) | (dbuf[2] << 1) | (dbuf[3] >> 4);
                n_total += 1;
            }
            if dlen >= 2 {
                dst[dsti] = (dbuf[0] << 3) | (dbuf[1] >> 2);
                n_total += 1;
            }
            dsti += 5;
        }
        (n_total, end, nil)
    }

    /// `Encoding.Decode(dst, src)` (base32.go:394). Returns `(n, err)`
    /// where `n` is bytes written into `dst`.
    pub fn Decode(&self, dst: &mut slice<byte>, src: slice<byte>) -> (int, error) {
        let src_raw: &[byte] = &src;
        // Go: buf := make([]byte, len(src)); l := stripNewlines(buf, src)
        let mut buf: Vec<byte> = Vec::with_capacity(src_raw.len());
        let mut i = 0;
        while i < src_raw.len() {
            let b = src_raw[i];
            if b != b'\r' && b != b'\n' {
                buf.push(b);
            }
            i += 1;
        }
        let n_dst = self.DecodedLen(buf.len() as int) as usize;
        let mut dv: Vec<byte> = dst.clone().__into_vec();
        if dv.len() < n_dst {
            dv.resize(n_dst, 0);
        }
        let (n, _end, err) = self.decode_into(&mut dv[..n_dst], &buf);
        *dst = slice::__from_vec(dv);
        (n, err)
    }

    /// `Encoding.DecodeString(s)` (base32.go:421). Returns the decoded
    /// bytes plus any error.
    pub fn DecodeString<S: Into<string>>(&self, s: S) -> (slice<byte>, error) {
        let s: string = s.into();
        let bv: Vec<byte> = crate::gostring::__crate_as_bytes(&s).to_vec();
        let n_max = self.DecodedLen(bv.len() as int) as usize;
        // Strip newlines first (matches Go's stripNewlines).
        let mut filt: Vec<byte> = Vec::with_capacity(bv.len());
        for &b in &bv {
            if b != b'\r' && b != b'\n' {
                filt.push(b);
            }
        }
        let mut dst: Vec<byte> = alloc::vec![0; n_max];
        let (n, _end, err) = self.decode_into(&mut dst, &filt);
        dst.truncate(n as usize);
        (slice::__from_vec(dst), err)
    }

    /// `Encoding.AppendDecode(dst, src)` (base32.go:405).
    pub fn AppendDecode(&self, dst: slice<byte>, src: slice<byte>) -> (slice<byte>, error) {
        let src_raw: &[byte] = &src;
        // Trim trailing pad chars to size estimate.
        let mut n = src_raw.len();
        while n > 0 && (src_raw[n - 1] as rune) == self.pad_char {
            n -= 1;
        }
        // Go: n = decodedLen(n, NoPadding) — use the no-padding formula
        // since we just trimmed padding off to compute n.
        let est = (n / 8 * 5 + n % 8 * 5 / 8) as usize;
        let mut out: Vec<byte> = dst.__into_vec();
        let start = out.len();
        out.resize(start + est, 0);
        // Strip newlines into a scratch buffer.
        let mut filt: Vec<byte> = Vec::with_capacity(src_raw.len());
        for &b in src_raw {
            if b != b'\r' && b != b'\n' {
                filt.push(b);
            }
        }
        let (n_decoded, _end, err) = self.decode_into(&mut out[start..start + est], &filt);
        out.truncate(start + n_decoded as usize);
        (slice::__from_vec(out), err)
    }
}

// ─── CorruptInputError (base32.go:295) ────────────────────────────────

/// `base32.CorruptInputError` (base32.go:295) — illegal base32 byte at
/// the given input offset.
pub struct CorruptInputError {
    pub offset: int,
}

impl ErrorTrait for CorruptInputError {
    fn Error(&self) -> string {
        // Go: "illegal base32 data at input byte " + strconv.FormatInt(...)
        let mut out = alloc::string::String::from("illegal base32 data at input byte ");
        // simple integer to string
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
