// go: file encoding/base32/base32.go decls: NewEncoding, Encoding.WithPadding, Encoding.Encode, Encoding.AppendEncode, Encoding.EncodeToString, encoder.Write, encoder.Close, NewEncoder, Encoding.EncodedLen, CorruptInputError.Error, Encoding.decode, Encoding.Decode, Encoding.AppendDecode, Encoding.DecodeString, readEncodedData, decoder.Read, stripNewlines, newlineFilteringReader.Read, NewDecoder, Encoding.DecodedLen, decodedLen
//
// goishlint:ignore GOISH021 decodeMapInitialize — Go's 256-byte
//     initialiser string exists so `NewEncoding` can `copy` it into
//     `decodeMap` in one call. goish's `NewEncoding` is a `const fn`
//     that fills the array with `invalidIndex` in its struct literal,
//     so there is nothing to copy from.
//
// The `decls:` manifest above lists base32.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// `Encoding`, `encoder`, `decoder`, `CorruptInputError` or the padding
// constants there would report them as dropped ports. They are not
// dropped — each carries its own `// go: sdk` anchor below.
//
// encoding/base32/base32.go — radix-32 encoding as defined in RFC 4648.
//
// An `Encoding` is three owned fields: the 32-byte alphabet, its
// 256-byte reverse map and a padding rune. Go takes the receiver *by
// value* in `WithPadding` precisely so it can return a modified copy,
// which is why the tables are owned rather than shared.
//
// base32 works in 5-byte input / 8-character output quanta. Unlike
// base64 there is no assemble/quantum fast-path split: `decode` is a
// single loop that walks eight source bytes at a time and handles
// padding, short tails and errors inline.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::convert::{byte as tobyte, int as toint, uint32 as touint32};
use crate::errors::{error, nil, ErrorTrait, Wrap};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int, rune};

const STD_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HEX_ALPHABET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

// go: sdk 1.25.5 encoding/base32/base32.go:28-31 StdPadding
/// `base32.StdPadding` — the standard padding character.
pub const StdPadding: rune = '=' as rune; // goishlint:ignore GOISH005 - a const initialiser cannot call `rune(...)`.

// go: sdk 1.25.5 encoding/base32/base32.go:28-31 NoPadding
/// `base32.NoPadding` — disables padding.
pub const NoPadding: rune = -1;

// go: sdk 1.25.5 encoding/base32/base32.go:33-51 invalidIndex
/// The `decodeMap` entry for a byte that is not in the alphabet.
const invalidIndex: u8 = 0xff;

// go: sdk 1.25.5 encoding/base32/base32.go:22-26 Encoding
/// `base32.Encoding` — a radix-32 encoding/decoding scheme, defined by
/// a 32-character alphabet.
///
/// The three fields are Go's, owned by value: an `Encoding` is copied
/// by `WithPadding`, which is why Go takes the receiver by value there.
#[derive(Copy, Clone)]
pub struct Encoding {
    // Go: encode [32]byte — symbol index to symbol byte
    encode: [byte; 32],
    // Go: decodeMap [256]uint8 — symbol byte to symbol index
    decodeMap: [u8; 256],
    // Go: padChar rune
    padChar: rune,
}

// go: sdk 1.25.5 encoding/base32/base32.go:61-85 NewEncoding
/// `base32.NewEncoding(encoder)` — a new `Encoding` over the given
/// 32-byte alphabet, using `StdPadding`.
///
/// The alphabet is a sequence of byte values with no special treatment
/// for multi-byte UTF-8. Panics, as Go does, if it is not 32 bytes, if
/// it contains a newline, or if it repeats a symbol.
///
/// This is a `const fn` so the two package-level encodings below can be
/// `static`s, as they are package-level `var`s in Go. A panic in a
/// `const` context is a compile error, which is stricter than Go and
/// strictly better.
pub const fn NewEncoding(encoder: &str) -> Encoding {
    let b = encoder.as_bytes();
    // Go: if len(encoder) != 32 { panic(...) }
    if b.len() != 32 {
        panic!("encoding alphabet is not 32-bytes long");
    }
    let mut e = Encoding {
        encode: [0; 32],
        decodeMap: [invalidIndex; 256],
        // Go: e.padChar = StdPadding
        padChar: StdPadding,
    };
    // Go: copy(e.encode[:], encoder)
    let mut i = 0;
    while i < 32 {
        e.encode[i] = b[i];
        i += 1;
    }
    // Go: for i := 0; i < len(encoder); i++ { … }
    //
    // The padding character is deliberately *not* rejected here: the
    // caller may switch the padding later with WithPadding, so Go
    // documents the restriction without enforcing it.
    i = 0;
    while i < 32 {
        if b[i] == b'\n' || b[i] == b'\r' {
            panic!("encoding alphabet contains newline character");
        }
        if e.decodeMap[b[i] as usize] != invalidIndex {
            panic!("encoding alphabet includes duplicate symbols");
        }
        e.decodeMap[b[i] as usize] = i as u8; // goishlint:ignore GOISH005 - a `const fn` cannot call `byte(...)`.
        i += 1;
    }
    return e;
}

impl Encoding {
    // go: sdk 1.25.5 encoding/base32/base32.go:100-109 Encoding.WithPadding
    /// `(enc Encoding).WithPadding(padding)` — a copy of `enc` using
    /// `padding`, or [`NoPadding`] to disable it.
    ///
    /// The padding character must not be CR or LF, must not be in the
    /// alphabet, must not be negative, and must be at or below `\xff`.
    /// A padding character above `\x7f` is written as its exact byte
    /// value rather than as UTF-8.
    pub const fn WithPadding(mut self, padding: rune) -> Encoding {
        // Go: case padding < NoPadding || padding == '\r' || padding == '\n' || padding > 0xff
        if padding < NoPadding
            || padding == ('\r' as rune) // goishlint:ignore GOISH005 - const fn
            || padding == ('\n' as rune) // goishlint:ignore GOISH005 - const fn
            || padding > 0xff
        {
            panic!("invalid padding");
        }
        // Go: case padding != NoPadding && enc.decodeMap[byte(padding)] != invalidIndex
        let pb = padding as u8; // goishlint:ignore GOISH005 - a `const fn` cannot call `byte(...)`.
        if padding != NoPadding && self.decodeMap[pb as usize] != invalidIndex {
            panic!("padding contained in alphabet");
        }
        self.padChar = padding;
        return self;
    }

    // go: none — goish idiom: `padChar != NoPadding`, spelled once. Go
    //     writes the comparison inline at each of its use sites.
    const fn padded(&self) -> bool {
        return self.padChar != NoPadding;
    }
}

// go: sdk 1.25.5 encoding/base32/base32.go:87-87 StdEncoding
/// `base32.StdEncoding` — the standard base32 encoding (RFC 4648).
pub static StdEncoding: Encoding = NewEncoding(STD_ALPHABET);

// go: sdk 1.25.5 encoding/base32/base32.go:91-91 HexEncoding
/// `base32.HexEncoding` — the "Extended Hex Alphabet" of RFC 4648,
/// typically used in DNS.
pub static HexEncoding: Encoding = NewEncoding(HEX_ALPHABET);

// ───── Lengths ───────────────────────────────────────────────────────

impl Encoding {
    // go: sdk 1.25.5 encoding/base32/base32.go:284-289 Encoding.EncodedLen
    /// Length in bytes of the base32 encoding of `n` source bytes.
    pub fn EncodedLen(&self, n: int) -> int {
        // Go: if enc.padChar == NoPadding { return n/5*8 + (n%5*8+4)/5 }
        return if self.padded() {
            (n + 4) / 5 * 8
        } else {
            n / 5 * 8 + (n % 5 * 8 + 4) / 5
        };
    }

    // go: sdk 1.25.5 encoding/base32/base32.go:576-580 Encoding.DecodedLen
    /// Maximum length in bytes of the data decoded from `n` bytes of
    /// base32-encoded input.
    pub fn DecodedLen(&self, n: int) -> int {
        return decodedLen(n, self.padChar);
    }
}

// go: sdk 1.25.5 encoding/base32/base32.go:582-587 decodedLen
fn decodedLen(n: int, padChar: rune) -> int {
    return if padChar == NoPadding {
        n / 8 * 5 + n % 8 * 5 / 8
    } else {
        n / 8 * 5
    };
}

// ───── Encoder ───────────────────────────────────────────────────────

impl Encoding {
    // go: sdk 1.25.5 encoding/base32/base32.go:121-187 Encoding.Encode
    // goishlint:ignore GOISH014 — the anchor names Go's `Encode`; the
    //     Rust fn is `encode_into` because the public `Encode` wrapper
    //     converts `slice<byte>` to the borrowed form this needs. Same
    //     split as `decode_into`.
    /// The body of `Encode`, over borrowed slices. Go's `Encode(dst,
    /// src []byte)` takes views; a goish `slice<byte>` owns its buffer,
    /// so the public wrappers convert and this does the work.
    fn encode_into(&self, dst: &mut [byte], src: &[byte]) {
        if src.is_empty() {
            return;
        }
        let mut di: usize = 0;
        let mut si: usize = 0;
        let n = (src.len() / 5) * 5;
        while si < n {
            // Go: hi := uint32(src[si+0])<<24 | uint32(src[si+1])<<16 |
            //          uint32(src[si+2])<<8 | uint32(src[si+3])
            //     lo := hi<<8 | uint32(src[si+4])
            let hi = (touint32(src[si]) << 24)
                | (touint32(src[si + 1]) << 16)
                | (touint32(src[si + 2]) << 8)
                | touint32(src[si + 3]);
            let lo = hi.wrapping_shl(8) | touint32(src[si + 4]);

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

        // Go: base32.go:152 — the trailing partial quantum, written in
        // reverse with `switch remain { case 4: … fallthrough … }`.
        let remain = src.len() - si;
        if remain == 0 {
            return;
        }
        let mut val: u32 = 0;
        if remain == 4 {
            val |= touint32(src[si + 3]);
            dst[di + 6] = self.encode[((val << 3) & 0x1F) as usize];
            dst[di + 5] = self.encode[((val >> 2) & 0x1F) as usize];
        }
        if remain >= 3 {
            val |= touint32(src[si + 2]) << 8;
            dst[di + 4] = self.encode[((val >> 7) & 0x1F) as usize];
        }
        if remain >= 2 {
            val |= touint32(src[si + 1]) << 16;
            dst[di + 3] = self.encode[((val >> 12) & 0x1F) as usize];
            dst[di + 2] = self.encode[((val >> 17) & 0x1F) as usize];
        }
        if remain >= 1 {
            val |= touint32(src[si]) << 24;
            dst[di + 1] = self.encode[((val >> 22) & 0x1F) as usize];
            dst[di] = self.encode[((val >> 27) & 0x1F) as usize];
        }

        // Go: base32.go:180 — pad the final quantum.
        if self.padded() {
            let nPad = (remain * 8 / 5) + 1;
            let mut i = nPad;
            while i < 8 {
                dst[di + i] = tobyte(self.padChar);
                i += 1;
            }
        }
    }

    // go: sdk 1.25.5 encoding/base32/base32.go:121-187 Encoding.Encode
    // goishlint:ignore GOISH014 — see `encode_into`; this is the public
    //     `slice<byte>` wrapper the anchor above shares.
    /// `(enc *Encoding).Encode(dst, src)` — writes
    /// `EncodedLen(len(src))` bytes into the start of `dst`'s backing
    /// buffer, growing it if needed.
    pub fn Encode(&self, dst: &mut slice<byte>, src: slice<byte>) {
        let mut dv: Vec<byte> = dst.clone().__into_vec();
        let n = self.EncodedLen(src.Len()) as usize;
        if dv.len() < n {
            dv.resize(n, 0);
        }
        let src_raw: &[byte] = &src;
        self.encode_into(&mut dv[..n], src_raw);
        *dst = slice::__from_vec(dv);
        return;
    }

    // go: sdk 1.25.5 encoding/base32/base32.go:191-196 Encoding.AppendEncode
    /// Appends the base32 encoding of `src` to `dst` and returns the
    /// extended buffer.
    pub fn AppendEncode(&self, dst: slice<byte>, src: slice<byte>) -> slice<byte> {
        let n = self.EncodedLen(src.Len()) as usize;
        let mut out: Vec<byte> = dst.__into_vec();
        let start = out.len();
        out.resize(start + n, 0);
        let src_raw: &[byte] = &src;
        self.encode_into(&mut out[start..start + n], src_raw);
        return slice::__from_vec(out);
    }

    // go: sdk 1.25.5 encoding/base32/base32.go:199-203 Encoding.EncodeToString
    /// The base32 encoding of `src`, as a string.
    pub fn EncodeToString(&self, src: slice<byte>) -> string {
        let n = self.EncodedLen(src.Len()) as usize;
        let mut buf: Vec<byte> = vec![0; n];
        let src_raw: &[byte] = &src;
        self.encode_into(&mut buf, src_raw);
        return string::__from_vec(buf);
    }
}

// go: sdk 1.25.5 encoding/base32/base32.go:205-212 encoder
/// Go: base32.go:205
///
///   type encoder struct {
///       err  error
///       enc  *Encoding
///       w    io.Writer
///       buf  [5]byte    // buffered data waiting to be encoded
///       nbuf int        // number of bytes in buf
///       out  [1024]byte // output buffer
///   }
///
/// `Write` buffers up to five bytes of input and flushes eight-byte
/// encoded blocks; `Close` flushes any pending partial block. After
/// `Close`, a further `Write` is an error.
pub struct Encoder<W: crate::io::Writer> {
    err: error,
    enc: Encoding,
    w: W,
    buf: [byte; 5],
    nbuf: usize,
    out: [byte; 1024],
}

impl<W: crate::io::Writer> Encoder<W> {
    // go: sdk 1.25.5 encoding/base32/base32.go:214-260 encoder.Write
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }

        let mut p_raw: &[byte] = &p;
        let mut n: int = 0;

        // Leading fringe: top the 5-byte buffer up if a previous Write
        // left a partial quantum.
        if self.nbuf > 0 {
            let mut i = 0usize;
            while i < p_raw.len() && self.nbuf < 5 {
                self.buf[self.nbuf] = p_raw[i];
                self.nbuf += 1;
                i += 1;
            }
            n += toint(i);
            p_raw = &p_raw[i..];
            if self.nbuf < 5 {
                return (n, nil);
            }
            // Flush the now-full buffer as eight encoded bytes.
            let buf_copy = self.buf;
            self.enc.encode_into(&mut self.out[..8], &buf_copy);
            let chunk = slice::__from_vec(self.out[..8].to_vec());
            let (_, werr) = self.w.Write(chunk);
            if !werr.IsNil() {
                self.err = werr.clone();
                return (n, werr);
            }
            self.nbuf = 0;
        }

        // Large interior chunks: encode `nn` source bytes (a multiple
        // of 5) and flush `nn/5*8` output bytes.
        while p_raw.len() >= 5 {
            let mut nn = self.out.len() / 8 * 5; // 640 source bytes per pass
            if nn > p_raw.len() {
                nn = p_raw.len();
                nn -= nn % 5;
            }
            // Stage src into a local Vec: `&mut self.out` and `&p_raw`
            // cannot both borrow `self`.
            let src_chunk: Vec<byte> = p_raw[..nn].to_vec();
            let out_len = nn / 5 * 8;
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

        // Trailing fringe: stash the remaining 0..5 bytes.
        let p_len = p_raw.len();
        let mut i = 0usize;
        while i < p_len {
            self.buf[i] = p_raw[i];
            i += 1;
        }
        self.nbuf = p_len;
        n += toint(p_len);
        return (n, nil);
    }

    // go: sdk 1.25.5 encoding/base32/base32.go:262-271 encoder.Close
    /// Flushes any pending output from the encoder.
    pub fn Close(&mut self) -> error {
        if self.err.IsNil() && self.nbuf > 0 {
            let nbuf = self.nbuf;
            let encodedLen = self.enc.EncodedLen(toint(nbuf)) as usize;
            let src_buf: [byte; 5] = self.buf;
            self.enc
                .encode_into(&mut self.out[..encodedLen], &src_buf[..nbuf]);
            self.nbuf = 0;
            let chunk = slice::__from_vec(self.out[..encodedLen].to_vec());
            let (_, werr) = self.w.Write(chunk);
            if !werr.IsNil() {
                self.err = werr.clone();
            }
        }
        return self.err.clone();
    }
}

// `Encoder<W>` is itself an `io::Writer`, which is what lets it stand
// in for the `io.WriteCloser` Go's `NewEncoder` returns.
impl<W: crate::io::Writer> crate::io::Writer for Encoder<W> {
    // go: sdk 1.25.5 encoding/base32/base32.go:214-260 encoder.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return Encoder::Write(self, p);
    }
}

// go: sdk 1.25.5 encoding/base32/base32.go:278-280 NewEncoder
/// A new base32 stream encoder. Data written to the returned writer is
/// encoded with `enc` and written on to `w`.
///
/// base32 encodings operate in five-byte blocks; when finished writing,
/// the caller must `Close` the returned encoder to flush any partially
/// written block.
///
/// Goish takes `Encoding` by value (it is `Copy`) and the writer by
/// move; the returned `Encoder<W>` exposes both `Write` and `Close`.
pub fn NewEncoder<W: crate::io::Writer>(enc: Encoding, w: W) -> Encoder<W> {
    return Encoder {
        err: nil,
        enc,
        w,
        buf: [0; 5],
        nbuf: 0,
        out: [0; 1024],
    };
}

// ───── CorruptInputError ─────────────────────────────────────────────

// go: sdk 1.25.5 encoding/base32/base32.go:295-295 CorruptInputError
/// `base32.CorruptInputError` — an illegal base32 byte at the given
/// input offset.
#[derive(Clone)]
pub struct CorruptInputError(pub int);

impl ErrorTrait for CorruptInputError {
    // go: sdk 1.25.5 encoding/base32/base32.go:297-299 CorruptInputError.Error
    fn Error(&self) -> string {
        // Go: "illegal base32 data at input byte " + strconv.FormatInt(int64(e), 10)
        let prefix = b"illegal base32 data at input byte ";
        let n_str = crate::strconv::FormatInt(self.0, 10);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(n_str.as_bytes());
        return string::from_bytes(&buf);
    }
}

// go: none — goish idiom: Go writes `CorruptInputError(n)` and lets the
//     assignment to `error` do the conversion; goish wraps explicitly.
fn corrupt(n: int) -> error {
    return Wrap(CorruptInputError(n));
}

// ───── Decoder ───────────────────────────────────────────────────────

impl Encoding {
    // go: sdk 1.25.5 encoding/base32/base32.go:305-386 Encoding.decode
    // goishlint:ignore GOISH014 — the anchor names Go's unexported
    //     `decode`; the Rust fn is `decode_into` because the public
    //     `Decode` wrapper converts `slice<byte>` to the borrowed form
    //     this needs. Same split as `encode_into`.
    /// The body of `decode`, over borrowed slices: like `Decode` but
    /// with an extra `end` result reporting whether end-of-message
    /// padding was seen, after which any further data is an error.
    ///
    /// Assumes `src` has already been stripped of '\r' and '\n'.
    fn decode_into(&self, dst: &mut [byte], src: &[byte]) -> (int, bool, error) {
        let mut dsti: usize = 0;
        let olen = src.len();
        let mut s: &[byte] = src;
        let mut n: int = 0;
        let mut end = false;

        while !s.is_empty() && !end {
            // Decode one quantum: eight source bytes to five output.
            let mut dbuf = [0u8; 8];
            let mut dlen: usize = 8;
            let mut j: usize = 0;

            while j < 8 {
                if s.is_empty() {
                    // Go: base32.go:315 — a short tail is only legal
                    // for an unpadded Encoding.
                    if self.padded() {
                        return (n, false, corrupt(toint(olen - s.len() - j)));
                    }
                    dlen = j;
                    end = true;
                    break;
                }
                let in_b = s[0];
                s = &s[1..];
                if self.padded() && in_b == tobyte(self.padChar) && j >= 2 && s.len() < 8 {
                    // Go: base32.go:330 — padding seen mid-quantum. The
                    // rest of this quantum, and the rest of the input,
                    // must be padding too.
                    if s.len() + j < 8 - 1 {
                        return (n, false, corrupt(toint(olen)));
                    }
                    let mut k = 0usize;
                    while k < 8 - 1 - j {
                        if s.len() > k && s[k] != tobyte(self.padChar) {
                            return (n, false, corrupt(toint(olen - s.len() + k - 1)));
                        }
                        k += 1;
                    }
                    dlen = j;
                    end = true;
                    // Go: base32.go:361 — 1, 3 and 6 are not valid
                    // quantum lengths, so the padding was misplaced.
                    if dlen == 1 || dlen == 3 || dlen == 6 {
                        return (n, false, corrupt(toint(olen - s.len() - 1)));
                    }
                    break;
                }
                dbuf[j] = self.decodeMap[in_b as usize];
                if dbuf[j] == invalidIndex {
                    return (n, false, corrupt(toint(olen - s.len() - 1)));
                }
                j += 1;
            }

            // Go: base32.go:368 — pack eight 5-bit groups into five
            // bytes. Go writes this as a `switch dlen` with
            // fallthrough; goish flattens it to descending `if`s.
            if dlen >= 8 {
                dst[dsti + 4] = (dbuf[6] << 5) | dbuf[7];
                n += 1;
            }
            if dlen >= 7 {
                dst[dsti + 3] = (dbuf[4] << 7) | (dbuf[5] << 2) | (dbuf[6] >> 3);
                n += 1;
            }
            if dlen >= 5 {
                dst[dsti + 2] = (dbuf[3] << 4) | (dbuf[4] >> 1);
                n += 1;
            }
            if dlen >= 4 {
                dst[dsti + 1] = (dbuf[1] << 6) | (dbuf[2] << 1) | (dbuf[3] >> 4);
                n += 1;
            }
            if dlen >= 2 {
                dst[dsti] = (dbuf[0] << 3) | (dbuf[1] >> 2);
                n += 1;
            }
            dsti += 5;
        }
        return (n, end, nil);
    }

    // go: sdk 1.25.5 encoding/base32/base32.go:394-399 Encoding.Decode
    /// Decodes `src` into `dst` and returns the number of bytes
    /// written. '\r' and '\n' are ignored.
    pub fn Decode(&self, dst: &mut slice<byte>, src: slice<byte>) -> (int, error) {
        let src_raw: &[byte] = &src;
        // Go: buf := make([]byte, len(src)); l := stripNewlines(buf, src)
        let mut buf: Vec<byte> = vec![0; src_raw.len()];
        let l = stripNewlines(&mut buf, src_raw) as usize;
        let n_dst = self.DecodedLen(toint(l)) as usize;
        let mut dv: Vec<byte> = dst.clone().__into_vec();
        if dv.len() < n_dst {
            dv.resize(n_dst, 0);
        }
        let (n, _end, err) = self.decode_into(&mut dv[..n_dst], &buf[..l]);
        *dst = slice::__from_vec(dv);
        return (n, err);
    }

    // go: sdk 1.25.5 encoding/base32/base32.go:405-416 Encoding.AppendDecode
    /// Appends the base32-decoded `src` to `dst` and returns the
    /// extended buffer. A malformed input yields the partial decode and
    /// an error.
    pub fn AppendDecode(&self, dst: slice<byte>, src: slice<byte>) -> (slice<byte>, error) {
        let src_raw: &[byte] = &src;
        // Go: compute the output size without padding, so a padded
        // input does not over-allocate.
        let mut n = src_raw.len();
        while n > 0 && crate::convert::rune(src_raw[n - 1]) == self.padChar {
            n -= 1;
        }
        let est = decodedLen(toint(n), NoPadding) as usize;

        let mut out: Vec<byte> = dst.__into_vec();
        let start = out.len();
        out.resize(start + est, 0);
        let mut tail = slice::__from_vec(out[start..].to_vec());
        let (n_decoded, err) = self.Decode(&mut tail, src);
        let tail_raw: &[byte] = &tail;
        let mut i = 0usize;
        while i < n_decoded as usize {
            out[start + i] = tail_raw[i];
            i += 1;
        }
        out.truncate(start + n_decoded as usize);
        return (slice::__from_vec(out), err);
    }

    // go: sdk 1.25.5 encoding/base32/base32.go:421-426 Encoding.DecodeString
    /// The bytes represented by the base32 string `s`. A malformed
    /// input yields the partial decode and a [`CorruptInputError`].
    /// '\r' and '\n' are ignored.
    pub fn DecodeString<S: Into<string>>(&self, s: S) -> (slice<byte>, error) {
        let s: string = s.into();
        let mut buf: Vec<byte> = s.as_bytes().to_vec();
        let l = stripNewlines_inplace(&mut buf) as usize;
        // Go decodes in place: `enc.decode(buf, buf[:l])`. The decoded
        // output is never longer than its input, so goish splits the
        // buffer rather than aliasing it.
        let src: Vec<byte> = buf[..l].to_vec();
        let (n, _end, err) = self.decode_into(&mut buf, &src);
        buf.truncate(n as usize);
        return (slice::__from_vec(buf), err);
    }
}

// go: sdk 1.25.5 encoding/base32/base32.go:439-456 readEncodedData
/// Reads from `r` into `buf` until at least `min` bytes are available
/// or an error stops it. A short read at EOF becomes
/// `io.ErrUnexpectedEOF`, except for an unpadded encoding, where a
/// message may end on any byte.
fn readEncodedData<R: crate::io::Reader>(
    r: &mut R,
    buf: &mut [byte],
    min: int,
    expectsPadding: bool,
) -> (int, error) {
    let mut n: int = 0;
    let mut err: error = nil;
    while n < min && err.IsNil() {
        let want = buf.len() - (n as usize);
        if want == 0 {
            // goish guard: Go relies on min <= len(buf); an empty
            // `r.Read` would otherwise spin here forever.
            break;
        }
        let mut tmp = slice::__from_vec(vec![0u8; want]);
        let (nn, e) = r.Read(&mut tmp);
        err = e;
        let raw: &[byte] = &tmp;
        let mut i = 0usize;
        while i < nn as usize {
            buf[(n as usize) + i] = raw[i];
            i += 1;
        }
        n += nn;
    }
    // Data was read, but less than min bytes of it.
    if n < min && n > 0 && crate::errors::Is(err.clone(), crate::io::EOF) {
        err = crate::io::ErrUnexpectedEOF.into();
    }
    // No data was read and the buffer already holds some. With padding
    // disabled this is not an error: the message can be any length.
    if expectsPadding && min < 8 && n == 0 && crate::errors::Is(err.clone(), crate::io::EOF) {
        err = crate::io::ErrUnexpectedEOF.into();
    }
    return (n, err);
}

// go: sdk 1.25.5 encoding/base32/base32.go:539-541 newlineFilteringReader
/// Go: base32.go:539
///   type newlineFilteringReader struct { wrapped io.Reader }
///
/// Wraps an inner reader and strips '\r' and '\n' in place before
/// returning, reading again when a whole chunk was newlines.
struct NewlineFilteringReader<R: crate::io::Reader> {
    wrapped: R,
}

impl<R: crate::io::Reader> NewlineFilteringReader<R> {
    // go: sdk 1.25.5 encoding/base32/base32.go:557-570 newlineFilteringReader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let (mut n, mut err) = self.wrapped.Read(p);
        while n > 0 {
            let mut offset: int = 0;
            let mut i: int = 0;
            while i < n {
                let b = p[i];
                if b != b'\r' && b != b'\n' {
                    if i != offset {
                        p[offset] = b;
                    }
                    offset += 1;
                }
                i += 1;
            }
            if !err.IsNil() || offset > 0 {
                return (offset, err);
            }
            // Previous buffer entirely whitespace — read again.
            let (n2, err2) = self.wrapped.Read(p);
            n = n2;
            err = err2;
        }
        return (n, err);
    }
}

impl<R: crate::io::Reader> crate::io::Reader for NewlineFilteringReader<R> {
    // go: sdk 1.25.5 encoding/base32/base32.go:557-570 newlineFilteringReader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return NewlineFilteringReader::Read(self, p);
    }
}

// go: sdk 1.25.5 encoding/base32/base32.go:545-555 stripNewlines
/// Removes newline characters, returning the number of non-newline
/// bytes copied to `dst`.
fn stripNewlines(dst: &mut [byte], src: &[byte]) -> int {
    let mut offset: usize = 0;
    let mut i = 0usize;
    while i < src.len() {
        let b = src[i];
        i += 1;
        if b == b'\r' || b == b'\n' {
            continue;
        }
        dst[offset] = b;
        offset += 1;
    }
    return toint(offset);
}

// go: none — goish idiom: Go calls `stripNewlines(buf, buf)` with one
//     aliased buffer, which Rust's borrow checker rejects. Same loop,
//     one `&mut` instead of two.
fn stripNewlines_inplace(buf: &mut [byte]) -> int {
    let mut offset: usize = 0;
    let mut i = 0usize;
    while i < buf.len() {
        let b = buf[i];
        i += 1;
        if b == b'\r' || b == b'\n' {
            continue;
        }
        buf[offset] = b;
        offset += 1;
    }
    return toint(offset);
}

// go: sdk 1.25.5 encoding/base32/base32.go:428-437 decoder
// goishlint:ignore GOISH019 Decoder — Go's `out []byte` is a subslice
//     of this struct's own `outbuf` field. Rust cannot express a
//     self-referential borrow in a struct, so goish carries the same
//     window as the `(out_start, out_end)` index pair. Nothing is
//     dropped: `outbuf` is still there, and `out` is still its live
//     range.
/// Go: base32.go:428
///
///   type decoder struct {
///       err    error
///       enc    *Encoding
///       r      io.Reader
///       end    bool       // saw end of message
///       buf    [1024]byte // leftover input
///       nbuf   int
///       out    []byte // leftover decoded output
///       outbuf [1024 / 8 * 5]byte
///   }
///
/// Go's `out` is a subslice of `outbuf`; goish carries the same window
/// as a `(out_start, out_end)` pair, since a struct cannot borrow its
/// own field.
pub struct Decoder<R: crate::io::Reader> {
    err: error,
    enc: Encoding,
    r: NewlineFilteringReader<R>,
    end: bool,
    buf: [byte; 1024],
    nbuf: usize,
    out_start: usize,
    out_end: usize,
    outbuf: [byte; 1024 / 8 * 5],
}

impl<R: crate::io::Reader> Decoder<R> {
    // go: sdk 1.25.5 encoding/base32/base32.go:458-537 decoder.Read
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let plen = p.Len() as usize;

        // Use leftover decoded output from the last read.
        if self.out_end > self.out_start {
            let n = self.copy_out(p);
            if self.out_start == self.out_end {
                return (toint(n), self.err.clone());
            }
            return (toint(n), nil);
        }

        if !self.err.IsNil() {
            return (0, self.err.clone());
        }

        // Read a chunk.
        let mut nn = (plen + 4) / 5 * 8;
        if nn < 8 {
            nn = 8;
        }
        if nn > self.buf.len() {
            nn = self.buf.len();
        }

        // The minimum number of bytes that must be read this cycle.
        let min: int;
        let expectsPadding: bool;
        if self.enc.padChar == NoPadding {
            min = 1;
            expectsPadding = false;
        } else {
            min = toint(8 - self.nbuf);
            expectsPadding = true;
        }

        // Go: nn, d.err = readEncodedData(d.r, d.buf[d.nbuf:nn], min, expectsPadding)
        let want = nn.saturating_sub(self.nbuf);
        let mut window: Vec<byte> = vec![0; want];
        let (nread, rerr) = readEncodedData(&mut self.r, &mut window, min, expectsPadding);
        self.err = rerr;
        let mut i = 0usize;
        while i < nread as usize {
            self.buf[self.nbuf + i] = window[i];
            i += 1;
        }
        self.nbuf += nread as usize;
        if toint(self.nbuf) < min {
            return (0, self.err.clone());
        }
        if nread > 0 && self.end {
            return (0, corrupt(0));
        }

        // Decode the chunk into p, or into outbuf and then p when p is
        // too small to take a whole quantum.
        let nr: usize = if self.enc.padChar == NoPadding {
            self.nbuf
        } else {
            self.nbuf / 8 * 8
        };
        let nw = self.DecodedLenOfBuffered();

        let n: int;
        let err: error;
        let src: Vec<byte> = self.buf[..nr].to_vec();
        if nw > plen {
            let (nw2, end2, e) = self.enc.decode_into(&mut self.outbuf[..], &src);
            self.end = end2;
            err = e;
            self.out_start = 0;
            self.out_end = nw2 as usize;
            n = toint(self.copy_out(p));
        } else {
            let mut dv: Vec<byte> = vec![0; nw];
            let (n2, end2, e) = self.enc.decode_into(&mut dv, &src);
            self.end = end2;
            err = e;
            n = n2;
            let mut k = 0usize;
            while k < n2 as usize {
                p[toint(k)] = dv[k];
                k += 1;
            }
        }
        self.nbuf -= nr;
        let mut k = 0usize;
        while k < self.nbuf {
            self.buf[k] = self.buf[k + nr];
            k += 1;
        }

        if !err.IsNil() && (self.err.IsNil() || crate::errors::Is(self.err.clone(), crate::io::EOF))
        {
            self.err = err;
        }

        if self.out_end > self.out_start {
            // Not all decoded bytes fit in the caller's buffer, so
            // return a nil error to make sure Read is called again. The
            // stored error, if any, comes back with the last bytes.
            return (n, nil);
        }
        return (n, self.err.clone());
    }

    // go: none — goish idiom: `nw := d.enc.DecodedLen(d.nbuf)`, hoisted
    //     so `self.enc` is not borrowed across the `self.buf` copy.
    fn DecodedLenOfBuffered(&self) -> usize {
        return self.enc.DecodedLen(toint(self.nbuf)) as usize;
    }

    // go: none — goish idiom: Go's `n = copy(p, d.out); d.out = d.out[n:]`
    //     over the `(out_start, out_end)` window this struct carries in
    //     place of Go's self-referential `out` subslice.
    fn copy_out(&mut self, p: &mut slice<byte>) -> usize {
        let avail = self.out_end - self.out_start;
        let plen = p.Len() as usize;
        let n = if plen < avail { plen } else { avail };
        let mut i = 0usize;
        while i < n {
            p[toint(i)] = self.outbuf[self.out_start + i];
            i += 1;
        }
        self.out_start += n;
        return n;
    }
}

// `Decoder<R>` is itself an `io::Reader`, which is what lets it stand
// in for the `io.Reader` Go's `NewDecoder` returns.
impl<R: crate::io::Reader> crate::io::Reader for Decoder<R> {
    // go: none — goish idiom: Go's `NewDecoder` returns an `io.Reader`
    //     interface value; goish returns the concrete `Decoder<R>`, so
    //     the trait impl forwards to the inherent method above.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Decoder::Read(self, p);
    }
}

// go: sdk 1.25.5 encoding/base32/base32.go:572-574 NewDecoder
/// A new base32 stream decoder over `r`, which supplies base32 text
/// with '\r' and '\n' tolerated.
///
/// Goish takes `Encoding` by value (it is `Copy`) and the inner reader
/// by move — or by `&mut R`, via the `io::Reader` blanket impl on
/// `&mut R`, which lets the caller keep ownership of `r`.
pub fn NewDecoder<R: crate::io::Reader>(enc: Encoding, r: R) -> Decoder<R> {
    return Decoder {
        err: nil,
        enc,
        r: NewlineFilteringReader { wrapped: r },
        end: false,
        buf: [0; 1024],
        nbuf: 0,
        out_start: 0,
        out_end: 0,
        outbuf: [0; 1024 / 8 * 5],
    };
}
