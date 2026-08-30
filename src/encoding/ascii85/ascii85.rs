// go: file encoding/ascii85/ascii85.go decls: Encode, MaxEncodedLen, NewEncoder, encoder.Write, encoder.Close, CorruptInputError.Error, Decode, NewDecoder, decoder.Read
//
// The `decls:` manifest above lists ascii85.go's funcs and methods
// only. GOISH017 matches a manifest entry against Rust `fn` items, so
// naming the `encoder`, `decoder` or `CorruptInputError` types there
// would report them as dropped ports. They are not dropped — each
// carries its own `// go: sdk` anchor below.
//
// encoding/ascii85/ascii85.go — the ascii85 encoding used by btoa and
// PDF, without the <~ ~> framing (callers add it if they want it).
//
// Four bytes become five printable characters by writing the 32-bit
// big-endian value in base 85 starting at '!'. Two things fall out of
// that and are what a port gets wrong:
//
//   * A block of four zero bytes encodes as the single character 'z',
//     not as "!!!!!" — but only a *full* block, never a partial one at
//     the end of the input.
//   * The final partial block is padded with zeros to four bytes,
//     encoded, and then only `len+1` of the five characters are
//     emitted. Emitting all five would decode back to trailing zeros
//     that were never there.
//
// `Decode`'s `flush` argument is the other subtlety: without it the
// decoder cannot know whether a trailing partial block is the end of
// the input or just the end of what has been read so far, so it leaves
// those bytes unconsumed and the caller loops.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use crate::convert::{byte as tobyte, int as toint, uint32 as touint32};
use crate::errors::{error, nil, ErrorTrait, Wrap};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

// ─── MaxEncodedLen (ascii85.go:86) ────────────────────────────────────

// go: sdk 1.25.5 encoding/ascii85/ascii85.go:86-86 MaxEncodedLen
/// `ascii85.MaxEncodedLen(n)` — maximum encoded length for `n` source
/// bytes.
pub fn MaxEncodedLen(n: int) -> int {
    // Go: return (n + 3) / 4 * 5
    return (n + 3) / 4 * 5;
}

// ─── Encode (ascii85.go:27) ───────────────────────────────────────────

// go: sdk 1.25.5 encoding/ascii85/ascii85.go:27-83 Encode
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
    return (slice::__from_vec(dv), toint(n));
}

// go: none — goish idiom: the body of `Encode` over borrowed slices.
//     Go's `Encode(dst, src []byte) int` takes views; a goish
//     `slice<byte>` owns its buffer, so the public wrapper converts
//     and this does the work.
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
            v |= touint32(src[3]);
        }
        if l >= 3 {
            v |= touint32(src[2]) << 8;
        }
        if l >= 2 {
            v |= touint32(src[1]) << 16;
        }
        v |= touint32(src[0]) << 24;

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
            dst[di + i as usize] = b'!' + tobyte(vv % 85);
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
    return n;
}

// ─── Decode (ascii85.go:186) ──────────────────────────────────────────

// go: sdk 1.25.5 encoding/ascii85/ascii85.go:186-240 Decode
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
    return (slice::__from_vec(dv), ndst, nsrc, err);
}

// go: none — goish idiom: the body of `Decode`; see `encode_into`.
fn decode_into(dst: &mut [byte], src: &[byte], flush: bool) -> (int, int, error) {
    let mut v: u32 = 0;
    let mut nb: u32 = 0;
    let mut ndst: usize = 0;
    let mut nsrc: usize = 0;

    let mut i = 0;
    while i < src.len() {
        if dst.len() - ndst < 4 {
            return (toint(ndst), toint(nsrc), nil);
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
            v = v.wrapping_mul(85).wrapping_add(touint32(b - b'!'));
            nb += 1;
        } else {
            return (0, 0, Wrap(CorruptInputError { offset: toint(i) }));
        }
        if nb == 5 {
            nsrc = i + 1;
            dst[ndst] = tobyte(v >> 24);
            dst[ndst + 1] = tobyte(v >> 16);
            dst[ndst + 2] = tobyte(v >> 8);
            dst[ndst + 3] = tobyte(v);
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
                        offset: toint(src.len()),
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
                dst[ndst] = tobyte(v >> 24);
                v <<= 8;
                ndst += 1;
                k += 1;
            }
        }
    }

    return (toint(ndst), toint(nsrc), nil);
}

// ─── CorruptInputError (ascii85.go:166) ───────────────────────────────

/// `ascii85.CorruptInputError` (ascii85.go:166) — illegal ascii85 byte
/// at the given input offset.
pub struct CorruptInputError {
    pub offset: int,
}

impl ErrorTrait for CorruptInputError {
    // go: sdk 1.25.5 encoding/ascii85/ascii85.go:169-171 CorruptInputError.Error
    fn Error(&self) -> string {
        // Go: "illegal ascii85 data at input byte " + strconv.FormatInt(int64(e), 10)
        return string::from_static("illegal ascii85 data at input byte ")
            + crate::strconv::FormatInt(self.offset, 10);
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
    // go: sdk 1.25.5 encoding/ascii85/ascii85.go:103-149 Write
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
            n += toint(i);
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
            n += toint(nn);
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
        n += toint(p_len);
        return (n, nil);
    }

    // go: sdk 1.25.5 encoding/ascii85/ascii85.go:153-161 Close
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
        return self.err.clone();
    }
}

// `Encoder<W>` is itself an `io::Writer` — slot into pipelines.
impl<W: crate::io::Writer> crate::io::Writer for Encoder<W> {
    // go: sdk 1.25.5 encoding/ascii85/ascii85.go:103-149 Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return Encoder::Write(self, p);
    }
}

// go: sdk 1.25.5 encoding/ascii85/ascii85.go:93-93 NewEncoder
// Go: ascii85.go:88
//   func NewEncoder(w io.Writer) io.WriteCloser
//
// Goish takes the writer by move; the returned `Encoder<W>` exposes
// both `Write` and `Close`.
pub fn NewEncoder<W: crate::io::Writer>(w: W) -> Encoder<W> {
    return Encoder {
        err: nil,
        w,
        buf: [0; 4],
        nbuf: 0,
        out: [0; 1024],
    };
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
    // go: sdk 1.25.5 encoding/ascii85/ascii85.go:255-307 Read
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

        return loop {
            // Go: copy leftover output from last decode.
            if self.out_end > self.out_start {
                let avail = self.out_end - self.out_start;
                let plen = p.Len() as usize;
                let n = if plen < avail { plen } else { avail };
                for i in 0..n {
                    p[toint(i)] = self.outbuf[self.out_start + i];
                }
                self.out_start += n;
                return (toint(n), nil);
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
        };
    }
}

// `Decoder<R>` is itself an `io::Reader` — slot into pipelines.
impl<R: crate::io::Reader> crate::io::Reader for Decoder<R> {
    // go: sdk 1.25.5 encoding/ascii85/ascii85.go:255-307 Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Decoder::Read(self, p);
    }
}

// go: sdk 1.25.5 encoding/ascii85/ascii85.go:243-243 NewDecoder
// Go: ascii85.go:243
//   func NewDecoder(r io.Reader) io.Reader
//
// Goish takes the reader by move (or by `&mut R` via the io::Reader
// blanket impl on `&mut T`).
pub fn NewDecoder<R: crate::io::Reader>(r: R) -> Decoder<R> {
    return Decoder {
        err: nil,
        read_err: nil,
        r,
        buf: [0; 1024],
        nbuf: 0,
        out_start: 0,
        out_end: 0,
        outbuf: [0; 1024],
    };
}
