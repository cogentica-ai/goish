// go: file encoding/base64/base64.go decls: NewEncoding, Encoding.WithPadding, Encoding.Strict, Encoding.Encode, Encoding.AppendEncode, Encoding.EncodeToString, encoder.Write, encoder.Close, NewEncoder, Encoding.EncodedLen, CorruptInputError.Error, Encoding.decodeQuantum, Encoding.AppendDecode, Encoding.DecodeString, decoder.Read, Encoding.Decode, assemble32, assemble64, newlineFilteringReader.Read, NewDecoder, Encoding.DecodedLen, decodedLen
//
// goishlint:ignore GOISH021 decodeMapInitialize — Go's 256-byte
//     initialiser string exists so `NewEncoding` can `copy` it into
//     `decodeMap` in one call. goish's `NewEncoding` is a `const fn`
//     that fills the array with `invalidIndex` in its struct literal,
//     so there is nothing to copy from.
//
// The `decls:` manifest above lists base64.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// `Encoding`, `CorruptInputError` or the padding constants there would
// report them as dropped ports. They are not dropped — each carries its
// own `// go: sdk` anchor below.
//
// encoding/base64/base64.go — radix-64 encoding as defined in RFC 4648.
//
// An `Encoding` is four owned fields: the 64-byte alphabet, its 256-byte
// reverse map, a padding rune and a strict flag. Go takes the receiver
// *by value* in `WithPadding` and `Strict` precisely so they can return
// a modified copy, which is why the tables are owned rather than shared.
//
// The decoder is where the complexity is, and it is deliberately split
// in two. `Decode` runs three loops — eight source bytes to six output
// bytes, then four to three, then one quantum at a time — and the fast
// paths bail to `decodeQuantum` the moment `assemble64`/`assemble32`
// sees a byte outside the alphabet. So the fast paths handle only clean
// complete quanta, and every awkward case is in `decodeQuantum`:
// newlines skipped mid-quantum, padding that must be complete, trailing
// garbage after the padding, and strict mode's requirement that the
// discarded low bits of the final byte be zero.
//
// Decode borrows the caller's slice in place: it neither allocates a larger
// destination nor truncates its length. Bytes beyond the returned count can
// be touched by Go's wide stores, including before an error; callers retain
// those writes exactly as in base64.go:518-584.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use alloc::vec;
use alloc::vec::Vec;

use crate::convert::{
    byte as tobyte, int as toint, rune as torune, uint as touint, uint32 as touint32,
    uint64 as touint64,
};
use crate::errors::{error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int, rune, uint};

const STD_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// go: sdk 1.25.5 encoding/base64/base64.go:31-34 StdPadding
/// `base64.StdPadding` — the standard padding character.
pub const StdPadding: rune = '=' as rune; // goishlint:ignore GOISH005 - a const initialiser cannot call `rune(...)`.

// go: sdk 1.25.5 encoding/base64/base64.go:31-34 NoPadding
/// `base64.NoPadding` — disables padding.
pub const NoPadding: rune = -1;

// go: sdk 1.25.5 encoding/base64/base64.go:36-56 invalidIndex
/// The `decodeMap` entry for a byte that is not in the alphabet.
const invalidIndex: u8 = 0xff;

// go: sdk 1.25.5 encoding/base64/base64.go:24-29 Encoding
/// `base64.Encoding` — a radix-64 encoding/decoding scheme, defined by
/// a 64-character alphabet.
///
/// The four fields are Go's, owned by value: an `Encoding` is copied by
/// `WithPadding` and `Strict`, which is why Go takes the receiver by
/// value in both.
#[derive(Copy, Clone)]
pub struct Encoding {
    // Go: encode [64]byte — symbol index to symbol byte
    encode: [byte; 64],
    // Go: decodeMap [256]uint8 — symbol byte to symbol index
    decodeMap: [u8; 256],
    // Go: padChar rune
    padChar: rune,
    // Go: strict bool
    strict: bool,
}

// go: sdk 1.25.5 encoding/base64/base64.go:64-87 NewEncoding
/// `base64.NewEncoding(encoder)` — a new `Encoding` over the given
/// 64-byte alphabet, using `StdPadding`.
///
/// The alphabet is a sequence of byte values with no special treatment
/// for multi-byte UTF-8. Panics, as Go does, if it is not 64 bytes, if
/// it contains a newline, or if it repeats a symbol.
///
/// This is a `const fn` so the four package-level encodings below can
/// be `static`s, as they are package-level `var`s in Go. A panic in a
/// `const` context is a compile error, which is stricter than Go and
/// strictly better.
pub const fn NewEncoding(encoder: &str) -> Encoding {
    let b = encoder.as_bytes();
    // Go: if len(encoder) != 64 { panic(...) }
    if b.len() != 64 {
        panic!("encoding alphabet is not 64-bytes long");
    }
    let mut e = Encoding {
        encode: [0; 64],
        decodeMap: [invalidIndex; 256],
        // Go: e.padChar = StdPadding
        padChar: StdPadding,
        strict: false,
    };
    // Go: copy(e.encode[:], encoder)
    let mut i = 0;
    while i < 64 {
        e.encode[i] = b[i];
        i += 1;
    }
    // Go: for i := 0; i < len(encoder); i++ { … }
    //
    // The padding character is deliberately *not* rejected here: the
    // caller may switch the padding later with WithPadding, so Go
    // documents the restriction without enforcing it.
    i = 0;
    while i < 64 {
        if b[i] == b'\n' || b[i] == b'\r' {
            panic!("encoding alphabet contains newline character");
        }
        if e.decodeMap[b[i] as usize] != invalidIndex {
            panic!("encoding alphabet includes duplicate symbols");
        }
        // goishlint:ignore GOISH005 - a `const fn` cannot call `byte(...)`.
        e.decodeMap[b[i] as usize] = i as u8; // goishlint:ignore GOISH005 - a `const fn` cannot call `byte(...)`.
        i += 1;
    }
    return e;
}

impl Encoding {
    // go: sdk 1.25.5 encoding/base64/base64.go:96-108 Encoding.WithPadding
    /// `(enc Encoding).WithPadding(padding)` — a copy of `enc` using
    /// `padding`, or [`NoPadding`] to disable it.
    ///
    /// The padding character must not be CR or LF, must not be in the
    /// alphabet, must not be negative, and must be at or below `\xff`.
    /// A padding character above `\x7f` is written as its exact byte
    /// value rather than as UTF-8.
    pub const fn WithPadding(mut self, padding: rune) -> Encoding {
        // Go: case padding < NoPadding || padding == '\r' || padding == '\n' || padding > 0xff
        // goishlint:ignore GOISH005 - a `const fn` cannot call `rune(...)`.
        if padding < NoPadding
            || padding == ('\r' as rune) // goishlint:ignore GOISH005 - const fn
            || padding == ('\n' as rune) // goishlint:ignore GOISH005 - const fn
            || padding > 0xff
        {
            panic!("invalid padding");
        }
        // Go: case padding != NoPadding && enc.decodeMap[byte(padding)] != invalidIndex
        //
        let pb = padding as u8; // goishlint:ignore GOISH005 - a `const fn` cannot call `byte(...)`.
        if padding != NoPadding && self.decodeMap[pb as usize] != invalidIndex {
            panic!("padding contained in alphabet");
        }
        self.padChar = padding;
        return self;
    }

    // go: sdk 1.25.5 encoding/base64/base64.go:113-116 Encoding.Strict
    /// `(enc Encoding).Strict()` — a copy of `enc` with strict decoding
    /// enabled: trailing padding bits must be zero (RFC 4648 §3.5).
    ///
    /// The input is still malleable, since CR and LF remain ignored.
    pub const fn Strict(mut self) -> Encoding {
        self.strict = true;
        return self;
    }

    // go: none — goish idiom: `padChar != NoPadding`, spelled once. Go
    //     writes the comparison inline at each of its four use sites.
    const fn padded(&self) -> bool {
        return self.padChar != NoPadding;
    }
}

// go: sdk 1.25.5 encoding/base64/base64.go:119-120 StdEncoding
/// `base64.StdEncoding` — the standard encoding (RFC 4648 §4).
pub static StdEncoding: Encoding = NewEncoding(STD_ALPHABET);

// go: sdk 1.25.5 encoding/base64/base64.go:122-123 URLEncoding
/// `base64.URLEncoding` — the alternate URL/filename-safe encoding
/// (RFC 4648 §5).
pub static URLEncoding: Encoding = NewEncoding(URL_ALPHABET);

// go: sdk 1.25.5 encoding/base64/base64.go:128-128 RawStdEncoding
/// `base64.RawStdEncoding` — the standard raw, unpadded encoding
/// (RFC 4648 §3.2).
pub static RawStdEncoding: Encoding = NewEncoding(STD_ALPHABET).WithPadding(NoPadding);

// go: sdk 1.25.5 encoding/base64/base64.go:133-133 RawURLEncoding
/// `base64.RawURLEncoding` — the unpadded URL/filename-safe encoding.
pub static RawURLEncoding: Encoding = NewEncoding(URL_ALPHABET).WithPadding(NoPadding);

impl Encoding {
    // go: sdk 1.25.5 encoding/base64/base64.go:290-295 Encoding.EncodedLen
    /// Length of the encoded output for `n` source bytes.
    pub fn EncodedLen(&self, n: int) -> int {
        return if self.padded() {
            (n + 2) / 3 * 4
        } else {
            (n * 8 + 5) / 6
        };
    }

    // go: sdk 1.25.5 encoding/base64/base64.go:654-656 Encoding.DecodedLen
    /// Maximum length of the decoded output for `n` source chars.
    pub fn DecodedLen(&self, n: int) -> int {
        return if self.padded() { n / 4 * 3 } else { n * 6 / 8 };
    }

    // go: sdk 1.25.5 encoding/base64/base64.go:206-210 Encoding.EncodeToString
    /// Encode `src` into the `Encoding`'s alphabet and return as
    /// string. Mirrors `Encoding.EncodeToString`
    /// (base64.go:206).
    pub fn EncodeToString(&self, src: &[u8]) -> string {
        let mut dst = vec![0u8; self.EncodedLen(toint(src.len())) as usize];
        self.encode_into(&mut dst, src);
        return string::from_bytes(&dst);
    }

    // go: sdk 1.25.5 encoding/base64/base64.go:145-196 Encoding.Encode
    // goishlint:ignore GOISH014 — the anchor names Go's `Encode`; the
    //     Rust fn is `encode_into` because the public `Encode` wrapper
    //     converts `slice<byte>` to the borrowed form this needs. Same
    //     split as `decode_into`.
    /// The body of `Encode`, over borrowed slices. Go's `Encode(dst,
    /// src []byte)` takes views; a goish `slice<byte>` owns its buffer,
    /// so the public wrappers convert and this does the work.
    fn encode_into(&self, dst: &mut [u8], src: &[u8]) {
        let mut di = 0usize;
        let mut si = 0usize;
        let alpha = &self.encode;

        // Process full 3-byte groups → 4 chars.
        while si + 3 <= src.len() {
            let v =
                (touint32(src[si]) << 16) | (touint32(src[si + 1]) << 8) | touint32(src[si + 2]);
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
        let mut v: u32 = touint32(src[si]) << 16;
        if remain == 2 {
            v |= touint32(src[si + 1]) << 8;
        }
        dst[di] = alpha[((v >> 18) & 0x3f) as usize];
        dst[di + 1] = alpha[((v >> 12) & 0x3f) as usize];
        if remain == 2 {
            dst[di + 2] = alpha[((v >> 6) & 0x3f) as usize];
            if self.padded() {
                dst[di + 3] = tobyte(self.padChar);
            }
        } else if self.padded() {
            dst[di + 2] = tobyte(self.padChar);
            dst[di + 3] = tobyte(self.padChar);
        }
    }

    // go: sdk 1.25.5 encoding/base64/base64.go:429-433 Encoding.DecodeString
    /// Decode `s` (a base64 string) into bytes. Returns
    /// `(slice<byte>, error)` — Go's `[]byte` shape. Mirrors
    /// `Encoding.DecodeString` (base64.go).
    pub fn DecodeString<S: Into<string>>(&self, s: S) -> (slice<byte>, error) {
        let s = s.into();
        let src = s.as_bytes();
        // Estimate; trim once we know exact length.
        let max_len = self.DecodedLen(toint(src.len())) as usize + 3;
        let mut dst: Vec<u8> = vec![0u8; max_len];
        let (n, err) = self.decode_into(&mut dst, src);
        dst.truncate(n as usize);
        return (slice::__from_vec(dst), err);
    }

    // go: sdk 1.25.5 encoding/base64/base64.go:518-587 Encoding.Decode
    // goishlint:ignore GOISH014 — the anchor names Go's `Decode`; the
    //     Rust fn is `decode_into` because the public `Decode` wrapper
    //     above converts `slice<byte>` to the borrowed form this needs.
    /// The body of `Decode`: three loops, exactly as Go writes them.
    ///
    /// The first two are the fast paths — eight source bytes to six
    /// output bytes, then four to three — and each falls back to
    /// `decodeQuantum` the moment `assemble64`/`assemble32` reports a
    /// byte that is not in the alphabet. That fallback is what makes
    /// newlines, padding and errors work at all: the fast paths handle
    /// only clean, complete quanta.
    fn decode_into(&self, dst: &mut [u8], src: &[u8]) -> (int, error) {
        if src.is_empty() {
            return (0, crate::errors::nil);
        }
        let mut n: usize = 0;
        let mut si: usize = 0;
        let mut err: error = crate::errors::nil;

        // Go: for strconv.IntSize >= 64 && len(src)-si >= 8 && len(dst)-n >= 8
        while src.len() - si >= 8 && dst.len() - n >= 8 {
            let s2 = &src[si..si + 8];
            let (dn, ok) = assemble64(
                self.decodeMap[s2[0] as usize],
                self.decodeMap[s2[1] as usize],
                self.decodeMap[s2[2] as usize],
                self.decodeMap[s2[3] as usize],
                self.decodeMap[s2[4] as usize],
                self.decodeMap[s2[5] as usize],
                self.decodeMap[s2[6] as usize],
                self.decodeMap[s2[7] as usize],
            );
            if ok {
                // Go: byteorder.BEPutUint64(dst[n:], dn)
                dst[n..n + 8].copy_from_slice(&dn.to_be_bytes());
                n += 6;
                si += 8;
            } else {
                let (nsi, ninc, e) = self.decodeQuantum(&mut dst[n..], src, si);
                si = nsi;
                n += ninc;
                if !e.IsNil() {
                    return (toint(n), e);
                }
            }
        }

        // Go: for len(src)-si >= 4 && len(dst)-n >= 4
        while src.len() - si >= 4 && dst.len() - n >= 4 {
            let s2 = &src[si..si + 4];
            let (dn, ok) = assemble32(
                self.decodeMap[s2[0] as usize],
                self.decodeMap[s2[1] as usize],
                self.decodeMap[s2[2] as usize],
                self.decodeMap[s2[3] as usize],
            );
            if ok {
                // Go: byteorder.BEPutUint32(dst[n:], dn)
                dst[n..n + 4].copy_from_slice(&dn.to_be_bytes());
                n += 3;
                si += 4;
            } else {
                let (nsi, ninc, e) = self.decodeQuantum(&mut dst[n..], src, si);
                si = nsi;
                n += ninc;
                if !e.IsNil() {
                    return (toint(n), e);
                }
            }
        }

        // Go: for si < len(src)
        while si < src.len() {
            let (nsi, ninc, e) = self.decodeQuantum(&mut dst[n..], src, si);
            si = nsi;
            n += ninc;
            if !e.IsNil() {
                return (toint(n), e);
            }
            err = e;
        }
        return (toint(n), err);
    }

    // go: sdk 1.25.5 encoding/base64/base64.go:312-407 Encoding.decodeQuantum
    /// `(enc *Encoding).decodeQuantum(dst, src, si)` — decode up to
    /// four base64 bytes, returning the new source index, the number of
    /// bytes written, and any error.
    ///
    /// This is where every awkward case lives: CR and LF are skipped
    /// mid-quantum by decrementing `j`, the padding character ends the
    /// quantum and must be complete, anything after the padding is
    /// trailing garbage, and in strict mode the discarded low bits of
    /// the final byte must be zero.
    fn decodeQuantum(&self, dst: &mut [u8], src: &[u8], si0: usize) -> (usize, usize, error) {
        let mut si = si0;
        let mut dbuf: [u8; 4] = [0; 4];
        let mut dlen: usize = 4;
        let mut err: error = crate::errors::nil;

        // Go: for j := 0; j < len(dbuf); j++
        let mut j: usize = 0;
        while j < 4 {
            if src.len() == si {
                // Go: case j == 0: return si, 0, nil
                if j == 0 {
                    return (si, 0, crate::errors::nil);
                }
                // Go: case j == 1, enc.padChar != NoPadding
                if j == 1 || self.padded() {
                    return (si, 0, corrupt(si - j));
                }
                dlen = j;
                break;
            }
            let inb = src[si];
            si += 1;

            let out = self.decodeMap[inb as usize];
            if out != invalidIndex {
                dbuf[j] = out;
                j += 1;
                continue;
            }

            // Go: if in == '\n' || in == '\r' { j--; continue }
            //
            // Go decrements j so the newline does not consume a slot;
            // goish simply does not advance it.
            if inb == b'\n' || inb == b'\r' {
                continue;
            }

            // Go: if rune(in) != enc.padChar { return si, 0, CorruptInputError(si-1) }
            if torune(inb) != self.padChar {
                return (si, 0, corrupt(si - 1));
            }

            // Go: we've reached the end and there's padding
            if j == 0 || j == 1 {
                // Go: incorrect padding
                return (si, 0, corrupt(si - 1));
            }
            if j == 2 {
                // Go: "==" is expected, the first "=" is already consumed.
                while si < src.len() && (src[si] == b'\n' || src[si] == b'\r') {
                    si += 1;
                }
                if si == src.len() {
                    // Go: not enough padding
                    return (si, 0, corrupt(src.len()));
                }
                if torune(src[si]) != self.padChar {
                    // Go: incorrect padding
                    return (si, 0, corrupt(si - 1));
                }
                si += 1;
            }

            // Go: skip over newlines
            while si < src.len() && (src[si] == b'\n' || src[si] == b'\r') {
                si += 1;
            }
            if si < src.len() {
                // Go: trailing garbage
                err = corrupt(si);
            }
            dlen = j;
            break;
        }

        // Go: convert 4x 6bit source bytes into 3 bytes
        let val: uint = (touint(dbuf[0]) << 18)
            | (touint(dbuf[1]) << 12)
            | (touint(dbuf[2]) << 6)
            | touint(dbuf[3]);
        dbuf[2] = tobyte(val);
        dbuf[1] = tobyte(val >> 8);
        dbuf[0] = tobyte(val >> 16);

        // Go's switch falls through from 4 to 3 to 2.
        if dlen == 4 {
            dst[2] = dbuf[2];
            dbuf[2] = 0;
        }
        if dlen >= 3 {
            dst[1] = dbuf[1];
            if self.strict && dbuf[2] != 0 {
                return (si, 0, corrupt(si - 1));
            }
            dbuf[1] = 0;
        }
        if dlen >= 2 {
            dst[0] = dbuf[0];
            if self.strict && (dbuf[1] != 0 || dbuf[2] != 0) {
                return (si, 0, corrupt(si - 2));
            }
        }

        return (si, dlen - 1, err);
    }
}

// go: sdk 1.25.5 encoding/base64/base64.go:589-603 assemble32
/// Assemble four base64 digits into three bytes, in the top 24 bits of
/// the returned `uint32`. Reports `false` if any digit is `0xff`, which
/// sends the caller to `decodeQuantum`.
fn assemble32(n1: u8, n2: u8, n3: u8, n4: u8) -> (u32, bool) {
    // Go: if n1|n2|n3|n4 == 0xff { return 0, false }
    if (n1 | n2 | n3 | n4) == invalidIndex {
        return (0, false);
    }
    return (
        (touint32(n1) << 26) | (touint32(n2) << 20) | (touint32(n3) << 14) | (touint32(n4) << 8),
        true,
    );
}

// go: sdk 1.25.5 encoding/base64/base64.go:605-620 assemble64
/// Assemble eight base64 digits into six bytes, in the top 48 bits of
/// the returned `uint64`. See [`assemble32`].
#[allow(clippy::too_many_arguments)]
fn assemble64(n1: u8, n2: u8, n3: u8, n4: u8, n5: u8, n6: u8, n7: u8, n8: u8) -> (u64, bool) {
    // Go: if n1|n2|n3|n4|n5|n6|n7|n8 == 0xff { return 0, false }
    if (n1 | n2 | n3 | n4 | n5 | n6 | n7 | n8) == invalidIndex {
        return (0, false);
    }
    return (
        (touint64(n1) << 58)
            | (touint64(n2) << 52)
            | (touint64(n3) << 46)
            | (touint64(n4) << 40)
            | (touint64(n5) << 34)
            | (touint64(n6) << 28)
            | (touint64(n7) << 22)
            | (touint64(n8) << 16),
        true,
    );
}

// go: none — goish idiom: Go writes `CorruptInputError(n)` and lets the
//     assignment to `error` do the conversion; goish wraps explicitly.
fn corrupt(n: usize) -> error {
    return crate::errors::Wrap(CorruptInputError(n));
}

#[derive(Clone)]
struct CorruptInputError(usize);

impl ErrorTrait for CorruptInputError {
    // go: sdk 1.25.5 encoding/base64/base64.go:303-305 CorruptInputError.Error
    fn Error(&self) -> string {
        let prefix = b"illegal base64 data at input byte ";
        let n_str = crate::strconv::Itoa(toint(self.0));
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(n_str.as_bytes());
        return string::from_bytes(&buf);
    }
}

// ───── Goish-style additive API (slice<byte> public types) ───────────
//
// These methods mirror Go's signatures using goish's `slice<byte>`
// instead of the legacy `&[u8]` / `&str` placeholders kept above for
// existing callers. They share the `encode_into` / `decode_into`
// internals.

impl Encoding {
    // go: sdk 1.25.5 encoding/base64/base64.go:145-194 Encoding.Encode
    // Go: base64.go:145
    //   func (enc *Encoding) Encode(dst, src []byte)
    //
    // Writes `EncodedLen(len(src))` bytes into the start of dst's
    // backing buffer, growing it if needed.
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

    // go: sdk 1.25.5 encoding/base64/base64.go:198-203 Encoding.AppendEncode
    // Go: base64.go:198
    //   func (enc *Encoding) AppendEncode(dst, src []byte) []byte
    pub fn AppendEncode(&self, dst: slice<byte>, src: slice<byte>) -> slice<byte> {
        let n = self.EncodedLen(src.Len()) as usize;
        let mut out: Vec<byte> = dst.__into_vec();
        let start = out.len();
        out.resize(start + n, 0);
        let src_raw: &[byte] = &src;
        self.encode_into(&mut out[start..start + n], src_raw);
        return slice::__from_vec(out);
    }

    // go: sdk 1.25.5 encoding/base64/base64.go:518-584 Encoding.Decode
    // Go: base64.go:518
    //   func (enc *Encoding) Decode(dst, src []byte) (n int, err error)
    pub fn Decode(&self, dst: &mut slice<byte>, src: slice<byte>) -> (int, error) {
        return self.decode_into(dst, &src);
    }

    // go: sdk 1.25.5 encoding/base64/base64.go:413-424 Encoding.AppendDecode
    // Go: base64.go:413
    //   func (enc *Encoding) AppendDecode(dst, src []byte) ([]byte, error)
    pub fn AppendDecode(&self, dst: slice<byte>, src: slice<byte>) -> (slice<byte>, error) {
        let mut out: Vec<byte> = dst.__into_vec();
        let start = out.len();
        let max_len = self.DecodedLen(src.Len()) as usize + 3;
        out.resize(start + max_len, 0);
        let src_raw: &[byte] = &src;
        let (n, err) = self.decode_into(&mut out[start..], src_raw);
        out.truncate(start + n as usize);
        return (slice::__from_vec(out), err);
    }
}

// ───── Streaming Encoder (Go: base64.go:212-286) ─────────────────────
//
// Mirrors Go's `encoder` struct:
//
//   type encoder struct {
//       err  error
//       enc  *Encoding
//       w    io.Writer
//       buf  [3]byte
//       nbuf int
//       out  [1024]byte
//   }
//
// `Write` buffers up to 3 bytes of input, flushes 4-byte encoded
// blocks. `Close` flushes any pending partial block. After Close,
// further Write calls are errors.
pub struct Encoder<W: crate::io::Writer> {
    err: error,
    enc: Encoding,
    w: W,
    buf: [byte; 3],
    nbuf: usize,
    out: [byte; 1024],
}

impl<W: crate::io::Writer> Encoder<W> {
    // go: sdk 1.25.5 encoding/base64/base64.go:221-265 Write
    // Go: base64.go:221
    //   func (e *encoder) Write(p []byte) (n int, err error)
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }

        let mut p_raw: &[byte] = &p;
        let mut n: int = 0;

        // Leading fringe: fill the 3-byte buffer if a previous Write
        // left a partial block.
        if self.nbuf > 0 {
            let mut i = 0usize;
            while i < p_raw.len() && self.nbuf < 3 {
                self.buf[self.nbuf] = p_raw[i];
                self.nbuf += 1;
                i += 1;
            }
            n += toint(i);
            p_raw = &p_raw[i..];
            if self.nbuf < 3 {
                return (n, crate::errors::nil);
            }
            // Flush the now-full buffer as 4 encoded bytes.
            let buf_copy = [self.buf[0], self.buf[1], self.buf[2]];
            self.enc.encode_into(&mut self.out[..4], &buf_copy);
            let chunk = slice::__from_vec(self.out[..4].to_vec());
            let (_, werr) = self.w.Write(chunk);
            if !werr.IsNil() {
                self.err = werr.clone();
                return (n, werr);
            }
            self.nbuf = 0;
        }

        // Large interior chunks: encode `nn` source bytes (multiple
        // of 3) and flush as `nn/3*4` output bytes.
        while p_raw.len() >= 3 {
            let mut nn = self.out.len() / 4 * 3; // 768 bytes max per pass
            if nn > p_raw.len() {
                nn = p_raw.len();
                nn -= nn % 3;
            }
            // Stage src into a local Vec to avoid borrow conflict
            // between &mut self.out and &p_raw.
            let src_chunk: alloc::vec::Vec<byte> = p_raw[..nn].to_vec();
            let out_len = nn / 3 * 4;
            self.enc.encode_into(&mut self.out[..out_len], &src_chunk);
            let chunk = slice::__from_vec(self.out[..out_len].to_vec());
            let (_, werr) = self.w.Write(chunk);
            if !werr.IsNil() {
                self.err = werr.clone();
                return (n, werr);
            }
            n += toint(nn);
            p_raw = &p_raw[nn..];
        }

        // Trailing fringe: stash remaining 0..3 bytes.
        let p_len = p_raw.len();
        let mut i = 0usize;
        while i < p_len {
            self.buf[i] = p_raw[i];
            i += 1;
        }
        self.nbuf = p_len;
        n += toint(p_len);
        return (n, crate::errors::nil);
    }

    // go: sdk 1.25.5 encoding/base64/base64.go:269-277 Close
    // Go: base64.go:269
    //   func (e *encoder) Close() error
    pub fn Close(&mut self) -> error {
        if self.err.IsNil() && self.nbuf > 0 {
            let nbuf = self.nbuf;
            let elen = self.enc.EncodedLen(toint(nbuf)) as usize;
            // Stage src so we don't borrow self.buf and self.out together.
            let src_buf: [byte; 3] = self.buf;
            self.enc
                .encode_into(&mut self.out[..elen], &src_buf[..nbuf]);
            let chunk = slice::__from_vec(self.out[..elen].to_vec());
            let (_, werr) = self.w.Write(chunk);
            if !werr.IsNil() {
                self.err = werr.clone();
            }
            self.nbuf = 0;
        }
        return self.err.clone();
    }
}

// `Encoder<W>` is itself an `io.Writer`. Allows `io::Copy(enc, src)`
// patterns and lets it slot into pipelines (e.g. quoted-printable +
// base64). Note: Close() must still be called explicitly to flush.
impl<W: crate::io::Writer> crate::io::Writer for Encoder<W> {
    // go: sdk 1.25.5 encoding/base64/base64.go:221-265 Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return Encoder::Write(self, p);
    }
}

// go: sdk 1.25.5 encoding/base64/base64.go:284-286 NewEncoder
// Go: base64.go:284
//   func NewEncoder(enc *Encoding, w io.Writer) io.WriteCloser
//
// Goish takes `Encoding` by value (it's `Copy`) and the writer by
// move. The returned `Encoder<W>` exposes both `Write` and `Close`.
pub fn NewEncoder<W: crate::io::Writer>(enc: Encoding, w: W) -> Encoder<W> {
    return Encoder {
        err: crate::errors::nil,
        enc,
        w,
        buf: [0; 3],
        nbuf: 0,
        out: [0; 1024],
    };
}

// ───── Streaming Decoder (Go: base64.go:435-650) ─────────────────────
//
// Mirrors Go's `decoder` struct + `newlineFilteringReader`:
//
//   type decoder struct {
//       err     error
//       readErr error
//       enc     *Encoding
//       r       io.Reader
//       buf     [1024]byte
//       nbuf    int
//       out     []byte
//       outbuf  [1024 / 4 * 3]byte
//   }
//
// `Read` reads from the wrapped reader (already newline-stripped) into
// `buf`, decodes 4-byte chunks, and writes 3-byte triples into `p` (or
// stages into `outbuf` if `p` is too small).

/// Go: base64.go:622
///   type newlineFilteringReader struct { wrapped io.Reader }
///
/// Wraps an inner Reader and strips '\r' and '\n' bytes in-place
/// before returning to the caller. Re-reads when an entire chunk was
/// whitespace.
struct NewlineFilteringReader<R: crate::io::Reader> {
    wrapped: R,
}

impl<R: crate::io::Reader> NewlineFilteringReader<R> {
    // go: sdk 1.25.5 encoding/base64/base64.go:626-646 newlineFilteringReader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let (mut n, mut err) = self.wrapped.Read(p);
        while n > 0 {
            // Strip '\r' and '\n' from p[..n] in-place.
            let mut offset: int = 0;
            for i in 0..n {
                let b = p[i];
                if b != b'\r' && b != b'\n' {
                    if i != offset {
                        p[offset] = b;
                    }
                    offset += 1;
                }
            }
            if offset > 0 {
                return (offset, err);
            }
            // Whole chunk was whitespace — read again.
            let (n2, err2) = self.wrapped.Read(p);
            n = n2;
            err = err2;
        }
        return (n, err);
    }
}

/// `base64.Decoder` — streaming base64 decoder. Wraps an inner
/// `io::Reader` providing base64 text (with '\r'/'\n' tolerated and
/// stripped). Implements `io::Reader` over the decoded byte stream.
pub struct Decoder<R: crate::io::Reader> {
    err: error,
    read_err: error, // error from r.Read
    enc: Encoding,
    r: NewlineFilteringReader<R>,
    buf: [byte; 1024], // leftover input
    nbuf: usize,
    out_start: usize,             // current read offset within outbuf
    out_end: usize,               // one past last valid byte in outbuf
    outbuf: [byte; 1024 / 4 * 3], // decoded output staging (768 bytes)
}

impl<R: crate::io::Reader> Decoder<R> {
    // go: sdk 1.25.5 encoding/base64/base64.go:446-516 decoder.Read
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Use leftover decoded output from last read.
        if self.out_end > self.out_start {
            let avail = self.out_end - self.out_start;
            let plen = p.Len() as usize;
            let n = if plen < avail { plen } else { avail };
            for i in 0..n {
                p[toint(i)] = self.outbuf[self.out_start + i];
            }
            self.out_start += n;
            return (toint(n), crate::errors::nil);
        }

        if !self.err.IsNil() {
            return (0, self.err.clone());
        }

        // Refill buffer. Read at most `len(p)/3*4` (rounded up to >=4
        // and capped at d.buf size) bytes per iteration.
        while self.nbuf < 4 && self.read_err.IsNil() {
            let mut nn = (p.Len() as usize) / 3 * 4;
            if nn < 4 {
                nn = 4;
            }
            if nn > self.buf.len() {
                nn = self.buf.len();
            }
            // Read into self.buf[self.nbuf..nn] via a temp slice.
            let want = nn - self.nbuf;
            let mut tmp = slice::__from_vec(vec![0u8; want]);
            let (got, rerr) = self.r.Read(&mut tmp);
            self.read_err = rerr;
            let got_usize = got as usize;
            // Copy got bytes from tmp into self.buf[self.nbuf..]
            let tmp_raw: &[byte] = &tmp;
            for i in 0..got_usize {
                self.buf[self.nbuf + i] = tmp_raw[i];
            }
            self.nbuf += got_usize;
        }

        if self.nbuf < 4 {
            // Final partial fragment — only valid for unpadded Encoding.
            if !self.enc.padded() && self.nbuf > 0 {
                // Decode final fragment without padding.
                let nbuf = self.nbuf;
                let src_buf: alloc::vec::Vec<byte> = self.buf[..nbuf].to_vec();
                let outbuf_len = self.outbuf.len();
                let (nw, derr) = self.enc.decode_into(&mut self.outbuf[..], &src_buf);
                let _ = outbuf_len;
                self.err = derr;
                self.nbuf = 0;
                self.out_start = 0;
                self.out_end = nw as usize;
                // Copy as much as fits into p.
                let avail = self.out_end - self.out_start;
                let plen = p.Len() as usize;
                let nout = if plen < avail { plen } else { avail };
                for i in 0..nout {
                    p[toint(i)] = self.outbuf[self.out_start + i];
                }
                self.out_start += nout;
                if nout > 0 || (p.Len() == 0 && self.out_end > self.out_start) {
                    return (toint(nout), crate::errors::nil);
                }
                if !self.err.IsNil() {
                    return (0, self.err.clone());
                }
            }
            self.err = self.read_err.clone();
            // Mid-record EOF → ErrUnexpectedEOF.
            if crate::errors::Is(self.err.clone(), crate::io::EOF) && self.nbuf > 0 {
                self.err = crate::io::ErrUnexpectedEOF.into();
            }
            return (0, self.err.clone());
        }

        // Decode a chunk into p, or into outbuf and then into p when
        // the caller's buffer is too small to hold a whole 3-byte
        // triple.
        let nr = self.nbuf / 4 * 4; // input bytes to consume
        let nw = self.nbuf / 4 * 3; // output bytes that will be produced
        let plen = p.Len() as usize;
        let n: int;
        if nw > plen {
            // Decode into outbuf, then copy a prefix into p.
            let src_buf: alloc::vec::Vec<byte> = self.buf[..nr].to_vec();
            let (nw_actual, derr) = self.enc.decode_into(&mut self.outbuf[..], &src_buf);
            self.err = derr;
            self.out_start = 0;
            self.out_end = nw_actual as usize;
            let avail = self.out_end - self.out_start;
            let nout = if plen < avail { plen } else { avail };
            for i in 0..nout {
                p[toint(i)] = self.outbuf[self.out_start + i];
            }
            self.out_start += nout;
            n = toint(nout);
        } else {
            // Decode into a scratch Vec sized to nw, then copy to p.
            let src_buf: alloc::vec::Vec<byte> = self.buf[..nr].to_vec();
            let mut tmp_dst: alloc::vec::Vec<byte> = vec![0u8; nw];
            let (n_actual, derr) = self.enc.decode_into(&mut tmp_dst, &src_buf);
            n = n_actual;
            self.err = derr;
            let nout = n_actual as usize;
            for i in 0..nout {
                p[toint(i)] = tmp_dst[i];
            }
        }

        // Shift remaining unconsumed bytes in self.buf to the front.
        let remaining = self.nbuf - nr;
        for i in 0..remaining {
            self.buf[i] = self.buf[nr + i];
        }
        self.nbuf = remaining;
        return (n, self.err.clone());
    }
}

// `Decoder<R>` is itself an `io::Reader`. Allows `io::Copy(&mut buf,
// &mut dec)` patterns.
impl<R: crate::io::Reader> crate::io::Reader for Decoder<R> {
    // go: none — goish idiom: Go's `NewDecoder` returns an `io.Reader`
    //     interface value; goish returns the concrete `Decoder<R>`, so
    //     the trait impl forwards to the inherent method above.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Decoder::Read(self, p);
    }
}

// go: sdk 1.25.5 encoding/base64/base64.go:648-650 NewDecoder
// Go: base64.go:647
//   func NewDecoder(enc *Encoding, r io.Reader) io.Reader
//
// Goish takes `Encoding` by value (it's `Copy`) and the inner reader
// by move (or by `&mut R` via the `io::Reader` blanket impl on `&mut
// R`, which lets callers keep ownership of `r`).
pub fn NewDecoder<R: crate::io::Reader>(enc: Encoding, r: R) -> Decoder<R> {
    return Decoder {
        err: crate::errors::nil,
        read_err: crate::errors::nil,
        enc,
        r: NewlineFilteringReader { wrapped: r },
        buf: [0; 1024],
        nbuf: 0,
        out_start: 0,
        out_end: 0,
        outbuf: [0; 1024 / 4 * 3],
    };
}
