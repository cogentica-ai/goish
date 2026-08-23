// encoding/ascii85 — Go's `encoding/ascii85`, ported.
//
// btoa / Adobe PostScript and PDF base85 encoding.
//
// Reference: /share/go/src/encoding/ascii85/ascii85.go.
//
// Slim deviations:
//   * `CorruptInputError` is a goish-style typed error (see bottom of
//     file). Go uses an `int64` newtype; we use a struct field to
//     keep the public-API rule of "no Rust scalars in error names."
//   * The streaming `Encoder` / `Decoder` wrap any `io::Writer` /
//     `io::Reader` (generic over `W` / `R`), matching the goish base64
//     streaming pattern shipped earlier; Go uses interface-typed fields.

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
            return (0, 0, Wrap(CorruptInputError { offset: i as int }));
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
                    Wrap(CorruptInputError {
                        offset: src.len() as int,
                    }),
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

// ─── Streaming Encoder (ascii85.go:95-161) ────────────────────────────
//
// Mirrors Go's `encoder` struct:
//
//   type encoder struct {
//       err  error
//       w    io.Writer
//       buf  [4]byte
//       nbuf int
//       out  [1024]byte
//   }
//
// 4-byte input blocks → 5-byte output blocks (or 1 byte for `z`-shortened
// runs of zeros).

/// `ascii85` streaming encoder (ascii85.go:95). Wraps any `io::Writer`
/// and converts incoming bytes into ascii85 in 4-byte input chunks.
/// Caller must call `Close()` to flush any trailing partial block.
pub struct Encoder<W: crate::io::Writer> {
    err: error,
    w: W,
    buf: [byte; 4],
    nbuf: usize,
    out: [byte; 1024],
}

impl<W: crate::io::Writer> Encoder<W> {
    // Go: ascii85.go:103
    //   func (e *encoder) Write(p []byte) (n int, err error)
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: if e.err != nil { return 0, e.err }
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }

        let mut p_raw: &[byte] = &p;
        let mut n: int = 0;

        // Go: leading fringe — fill the 4-byte buffer.
        if self.nbuf > 0 {
            let mut i = 0usize;
            while i < p_raw.len() && self.nbuf < 4 {
                self.buf[self.nbuf] = p_raw[i];
                self.nbuf += 1;
                i += 1;
            }
            n += i as int;
            p_raw = &p_raw[i..];
            // Go: if e.nbuf < 4 { return }
            if self.nbuf < 4 {
                return (n, nil);
            }
            // Go: nout := Encode(e.out[0:], e.buf[0:])
            //     if _, e.err = e.w.Write(e.out[0:nout]); e.err != nil { return n, e.err }
            let buf_copy = [self.buf[0], self.buf[1], self.buf[2], self.buf[3]];
            let nout = encode_into(&mut self.out[..], &buf_copy);
            let chunk = slice::__from_vec(self.out[..nout].to_vec());
            let (_, werr) = self.w.Write(chunk);
            if !werr.IsNil() {
                self.err = werr.clone();
                return (n, werr);
            }
            self.nbuf = 0;
        }

        // Go: large interior chunks — encode `nn` bytes (multiple of 4).
        //     nn := len(e.out) / 5 * 4
        while p_raw.len() >= 4 {
            let mut nn = self.out.len() / 5 * 4; // 819 → 816 multiple of 4 below
            if nn > p_raw.len() {
                nn = p_raw.len();
            }
            // Go: nn -= nn % 4
            nn -= nn % 4;
            if nn > 0 {
                // Stage src into a local Vec to avoid borrow conflict
                // between &mut self.out and &p_raw.
                let src_chunk: alloc::vec::Vec<byte> = p_raw[..nn].to_vec();
                let nout = encode_into(&mut self.out[..], &src_chunk);
                let chunk = slice::__from_vec(self.out[..nout].to_vec());
                let (_, werr) = self.w.Write(chunk);
                if !werr.IsNil() {
                    self.err = werr.clone();
                    return (n, werr);
                }
            }
            n += nn as int;
            p_raw = &p_raw[nn..];
        }

        // Go: trailing fringe — copy remaining 0..3 bytes to e.buf.
        let p_len = p_raw.len();
        let mut i = 0usize;
        while i < p_len {
            self.buf[i] = p_raw[i];
            i += 1;
        }
        self.nbuf = p_len;
        n += p_len as int;
        (n, nil)
    }

    // Go: ascii85.go:153
    //   func (e *encoder) Close() error
    pub fn Close(&mut self) -> error {
        // Go: if e.err == nil && e.nbuf > 0 {
        //         nout := Encode(e.out[0:], e.buf[0:e.nbuf])
        //         e.nbuf = 0
        //         _, e.err = e.w.Write(e.out[0:nout])
        //     }
        if self.err.IsNil() && self.nbuf > 0 {
            let nbuf = self.nbuf;
            let src_buf: [byte; 4] = self.buf;
            let nout = encode_into(&mut self.out[..], &src_buf[..nbuf]);
            let chunk = slice::__from_vec(self.out[..nout].to_vec());
            let (_, werr) = self.w.Write(chunk);
            if !werr.IsNil() {
                self.err = werr.clone();
            }
            self.nbuf = 0;
        }
        self.err.clone()
    }
}

// `Encoder<W>` is itself an `io::Writer` — slot into pipelines.
impl<W: crate::io::Writer> crate::io::Writer for Encoder<W> {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        Encoder::Write(self, p)
    }
}

// Go: ascii85.go:88
//   func NewEncoder(w io.Writer) io.WriteCloser
//
// Goish takes the writer by move; the returned `Encoder<W>` exposes
// both `Write` and `Close`.
pub fn NewEncoder<W: crate::io::Writer>(w: W) -> Encoder<W> {
    Encoder {
        err: nil,
        w,
        buf: [0; 4],
        nbuf: 0,
        out: [0; 1024],
    }
}

// ─── Streaming Decoder (ascii85.go:243-307) ───────────────────────────
//
// Mirrors Go's `decoder` struct:
//
//   type decoder struct {
//       err     error
//       readErr error
//       r       io.Reader
//       buf     [1024]byte
//       nbuf    int
//       out     []byte
//       outbuf  [1024]byte
//   }
//
// `out` (a slice into `outbuf`) is represented as `out_start..out_end`
// indices to avoid self-referential borrows.

/// `ascii85` streaming decoder (ascii85.go:245). Wraps any `io::Reader`
/// and decodes ascii85 input on demand.
pub struct Decoder<R: crate::io::Reader> {
    err: error,
    read_err: error,
    r: R,
    buf: [byte; 1024],
    nbuf: usize,
    // Slice into outbuf — Go uses `out []byte`; goish uses index pair.
    out_start: usize,
    out_end: usize,
    outbuf: [byte; 1024],
}

impl<R: crate::io::Reader> Decoder<R> {
    // Go: ascii85.go:255
    //   func (d *decoder) Read(p []byte) (n int, err error)
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: if len(p) == 0 { return 0, nil }
        if p.Len() == 0 {
            return (0, nil);
        }
        // Go: if d.err != nil { return 0, d.err }
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }

        loop {
            // Go: copy leftover output from last decode.
            if self.out_end > self.out_start {
                let avail = self.out_end - self.out_start;
                let plen = p.Len() as usize;
                let n = if plen < avail { plen } else { avail };
                for i in 0..n {
                    p[i as int] = self.outbuf[self.out_start + i];
                }
                self.out_start += n;
                return (n as int, nil);
            }

            // Go: decode leftover input from last read.
            if self.nbuf > 0 {
                let nbuf = self.nbuf;
                let flush = !self.read_err.IsNil();
                let src_buf: alloc::vec::Vec<byte> = self.buf[..nbuf].to_vec();
                let (ndst, nsrc, derr) = decode_into(&mut self.outbuf[..], &src_buf, flush);
                self.err = derr;

                // Go: if ndst > 0 { d.out = d.outbuf[0:ndst]; d.nbuf = copy(d.buf[0:], d.buf[nsrc:d.nbuf]); continue }
                if ndst > 0 {
                    self.out_start = 0;
                    self.out_end = ndst as usize;
                    // Shift unconsumed input down to the front.
                    let nsrc_u = nsrc as usize;
                    let remaining = self.nbuf - nsrc_u;
                    for i in 0..remaining {
                        self.buf[i] = self.buf[nsrc_u + i];
                    }
                    self.nbuf = remaining;
                    continue;
                }
                // Go: special case — input mostly non-data; filter it out.
                if ndst == 0 && self.err.IsNil() {
                    let mut off = 0usize;
                    let mut i = 0usize;
                    while i < self.nbuf {
                        if self.buf[i] > b' ' {
                            self.buf[off] = self.buf[i];
                            off += 1;
                        }
                        i += 1;
                    }
                    self.nbuf = off;
                }
            }

            // Go: out of input, out of decoded output. Check errors.
            if !self.err.IsNil() {
                return (0, self.err.clone());
            }
            if !self.read_err.IsNil() {
                self.err = self.read_err.clone();
                return (0, self.err.clone());
            }

            // Go: read more data — d.r.Read(d.buf[d.nbuf:])
            let want = self.buf.len() - self.nbuf;
            let mut tmp = slice::__from_vec(alloc::vec![0u8; want]);
            let (nn, rerr) = self.r.Read(&mut tmp);
            self.read_err = rerr;
            let nn_u = nn as usize;
            let tmp_raw: &[byte] = &tmp;
            for i in 0..nn_u {
                self.buf[self.nbuf + i] = tmp_raw[i];
            }
            self.nbuf += nn_u;
        }
    }
}

// `Decoder<R>` is itself an `io::Reader` — slot into pipelines.
impl<R: crate::io::Reader> crate::io::Reader for Decoder<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Decoder::Read(self, p)
    }
}

// Go: ascii85.go:243
//   func NewDecoder(r io.Reader) io.Reader
//
// Goish takes the reader by move (or by `&mut R` via the io::Reader
// blanket impl on `&mut T`).
pub fn NewDecoder<R: crate::io::Reader>(r: R) -> Decoder<R> {
    Decoder {
        err: nil,
        read_err: nil,
        r,
        buf: [0; 1024],
        nbuf: 0,
        out_start: 0,
        out_end: 0,
        outbuf: [0; 1024],
    }
}
