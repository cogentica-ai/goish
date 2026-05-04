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
//   base64::StdEncoding.DecodeString(&s) -> (slice<byte>, error)
//   base64::StdEncoding.Encode(&mut dst, src)       // in-place encode
//   base64::StdEncoding.AppendEncode(dst, src)      // appends → slice<byte>
//   base64::StdEncoding.Decode(&mut dst, src)       // in-place decode
//   base64::StdEncoding.AppendDecode(dst, src)      // appends → slice<byte>
//   base64::NewEncoder(enc, w)                      // streaming encoder
//
// All four pre-baked encodings are values of type `Encoding`. The
// alphabet + padding flag are stored in the Encoding; methods are
// dispatched on it.
//
// What v1 omits: NewEncoding (runtime alphabet), WithPadding, Strict.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use alloc::vec;
use alloc::vec::Vec;

use crate::errors::{error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int};

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

    /// Decode `s` (a base64 string) into bytes. Returns
    /// `(slice<byte>, error)` — Go's `[]byte` shape. Mirrors
    /// `Encoding.DecodeString` (base64.go).
    pub fn DecodeString(&self, s: &str) -> (slice<byte>, error) {
        let src = s.as_bytes();
        // Estimate; trim once we know exact length.
        let max_len = self.DecodedLen(src.len() as int) as usize + 3;
        let mut dst: Vec<u8> = vec![0u8; max_len];
        let (n, err) = self.decode_into(&mut dst, src);
        dst.truncate(n as usize);
        (slice::__from_vec(dst), err)
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

// ───── Goish-style additive API (slice<byte> public types) ───────────
//
// These methods mirror Go's signatures using goish's `slice<byte>`
// instead of the legacy `&[u8]` / `&str` placeholders kept above for
// existing callers. They share the `encode_into` / `decode_into`
// internals.

impl Encoding {
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

    // Go: base64.go:198
    //   func (enc *Encoding) AppendEncode(dst, src []byte) []byte
    pub fn AppendEncode(&self, dst: slice<byte>, src: slice<byte>) -> slice<byte> {
        let n = self.EncodedLen(src.Len()) as usize;
        let mut out: Vec<byte> = dst.__into_vec();
        let start = out.len();
        out.resize(start + n, 0);
        let src_raw: &[byte] = &src;
        self.encode_into(&mut out[start..start + n], src_raw);
        slice::__from_vec(out)
    }

    // Go: base64.go:518
    //   func (enc *Encoding) Decode(dst, src []byte) (n int, err error)
    pub fn Decode(&self, dst: &mut slice<byte>, src: slice<byte>) -> (int, error) {
        let mut dv: Vec<byte> = dst.clone().__into_vec();
        let max_len = self.DecodedLen(src.Len()) as usize + 3;
        if dv.len() < max_len {
            dv.resize(max_len, 0);
        }
        let src_raw: &[byte] = &src;
        let (n, err) = self.decode_into(&mut dv, src_raw);
        dv.truncate(n as usize);
        *dst = slice::__from_vec(dv);
        (n, err)
    }

    // Go: base64.go:413
    //   func (enc *Encoding) AppendDecode(dst, src []byte) ([]byte, error)
    pub fn AppendDecode(
        &self,
        dst: slice<byte>,
        src: slice<byte>,
    ) -> (slice<byte>, error) {
        let mut out: Vec<byte> = dst.__into_vec();
        let start = out.len();
        let max_len = self.DecodedLen(src.Len()) as usize + 3;
        out.resize(start + max_len, 0);
        let src_raw: &[byte] = &src;
        let (n, err) = self.decode_into(&mut out[start..], src_raw);
        out.truncate(start + n as usize);
        (slice::__from_vec(out), err)
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
            n += i as int;
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
            n += nn as int;
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
        n += p_len as int;
        (n, crate::errors::nil)
    }

    // Go: base64.go:269
    //   func (e *encoder) Close() error
    pub fn Close(&mut self) -> error {
        if self.err.IsNil() && self.nbuf > 0 {
            let nbuf = self.nbuf;
            let elen = self.enc.EncodedLen(nbuf as int) as usize;
            // Stage src so we don't borrow self.buf and self.out together.
            let src_buf: [byte; 3] = self.buf;
            self.enc.encode_into(&mut self.out[..elen], &src_buf[..nbuf]);
            let chunk = slice::__from_vec(self.out[..elen].to_vec());
            let (_, werr) = self.w.Write(chunk);
            if !werr.IsNil() {
                self.err = werr.clone();
            }
            self.nbuf = 0;
        }
        self.err.clone()
    }
}

// `Encoder<W>` is itself an `io.Writer`. Allows `io::Copy(enc, src)`
// patterns and lets it slot into pipelines (e.g. quoted-printable +
// base64). Note: Close() must still be called explicitly to flush.
impl<W: crate::io::Writer> crate::io::Writer for Encoder<W> {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        Encoder::Write(self, p)
    }
}

// Go: base64.go:284
//   func NewEncoder(enc *Encoding, w io.Writer) io.WriteCloser
//
// Goish takes `Encoding` by value (it's `Copy`) and the writer by
// move. The returned `Encoder<W>` exposes both `Write` and `Close`.
pub fn NewEncoder<W: crate::io::Writer>(enc: Encoding, w: W) -> Encoder<W> {
    Encoder {
        err: crate::errors::nil,
        enc,
        w,
        buf: [0; 3],
        nbuf: 0,
        out: [0; 1024],
    }
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
    // Go: base64.go:626
    //   func (r *newlineFilteringReader) Read(p []byte) (int, error)
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
        (n, err)
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
    out_start: usize, // current read offset within outbuf
    out_end: usize,   // one past last valid byte in outbuf
    outbuf: [byte; 1024 / 4 * 3], // decoded output staging (768 bytes)
}

impl<R: crate::io::Reader> Decoder<R> {
    // Go: base64.go:446
    //   func (d *decoder) Read(p []byte) (n int, err error)
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Use leftover decoded output from last read.
        if self.out_end > self.out_start {
            let avail = self.out_end - self.out_start;
            let plen = p.Len() as usize;
            let n = if plen < avail { plen } else { avail };
            for i in 0..n {
                p[i as int] = self.outbuf[self.out_start + i];
            }
            self.out_start += n;
            return (n as int, crate::errors::nil);
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
            if !self.enc.padded && self.nbuf > 0 {
                // Decode final fragment without padding.
                let nbuf = self.nbuf;
                let src_buf: alloc::vec::Vec<byte> =
                    self.buf[..nbuf].to_vec();
                let outbuf_len = self.outbuf.len();
                let (nw, derr) =
                    self.enc.decode_into(&mut self.outbuf[..], &src_buf);
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
                    p[i as int] = self.outbuf[self.out_start + i];
                }
                self.out_start += nout;
                if nout > 0 || (p.Len() == 0 && self.out_end > self.out_start) {
                    return (nout as int, crate::errors::nil);
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
            let (nw_actual, derr) =
                self.enc.decode_into(&mut self.outbuf[..], &src_buf);
            self.err = derr;
            self.out_start = 0;
            self.out_end = nw_actual as usize;
            let avail = self.out_end - self.out_start;
            let nout = if plen < avail { plen } else { avail };
            for i in 0..nout {
                p[i as int] = self.outbuf[self.out_start + i];
            }
            self.out_start += nout;
            n = nout as int;
        } else {
            // Decode into a scratch Vec sized to nw, then copy to p.
            let src_buf: alloc::vec::Vec<byte> = self.buf[..nr].to_vec();
            let mut tmp_dst: alloc::vec::Vec<byte> = vec![0u8; nw];
            let (n_actual, derr) =
                self.enc.decode_into(&mut tmp_dst, &src_buf);
            n = n_actual;
            self.err = derr;
            let nout = n_actual as usize;
            for i in 0..nout {
                p[i as int] = tmp_dst[i];
            }
        }

        // Shift remaining unconsumed bytes in self.buf to the front.
        let remaining = self.nbuf - nr;
        for i in 0..remaining {
            self.buf[i] = self.buf[nr + i];
        }
        self.nbuf = remaining;
        (n, self.err.clone())
    }
}

// `Decoder<R>` is itself an `io::Reader`. Allows `io::Copy(&mut buf,
// &mut dec)` patterns.
impl<R: crate::io::Reader> crate::io::Reader for Decoder<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Decoder::Read(self, p)
    }
}

// Go: base64.go:647
//   func NewDecoder(enc *Encoding, r io.Reader) io.Reader
//
// Goish takes `Encoding` by value (it's `Copy`) and the inner reader
// by move (or by `&mut R` via the `io::Reader` blanket impl on `&mut
// R`, which lets callers keep ownership of `r`).
pub fn NewDecoder<R: crate::io::Reader>(enc: Encoding, r: R) -> Decoder<R> {
    Decoder {
        err: crate::errors::nil,
        read_err: crate::errors::nil,
        enc,
        r: NewlineFilteringReader { wrapped: r },
        buf: [0; 1024],
        nbuf: 0,
        out_start: 0,
        out_end: 0,
        outbuf: [0; 1024 / 4 * 3],
    }
}
