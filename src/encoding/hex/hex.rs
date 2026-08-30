// go: file encoding/hex/hex.go decls: EncodedLen, Encode, AppendEncode, InvalidByteError.Error, DecodedLen, Decode, AppendDecode, EncodeToString, DecodeString, Dump, NewEncoder, encoder.Write, NewDecoder, decoder.Read, Dumper, toChar, dumper.Write, dumper.Close
//
// goishlint:ignore GOISH021 reverseHexTable — Go's 256-byte lookup
//     string exists to make nibble decoding branchless. goish spells
//     the same decision as a `match` on three character ranges in
//     `from_hex_char`, so there is no table to declare.
//
// The `decls:` manifest above lists hex.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the file's consts, types and error vars there would report them as
// dropped ports. They are not dropped — each carries its own
// `// go: sdk` anchor below.
//
// encoding/hex/hex.go — hexadecimal encoding and decoding.
//
// `Decode` is the half with the contract worth stating: it decodes
// pairs, so it reports `ErrLength` only *after* consuming every
// complete pair, and an `InvalidByteError` names the offending byte
// rather than its position. Both are what a caller needs to resume or
// report, and both are easy to simplify away by mistake.
//
// `Dumper` writes the `hexdump -C` layout — offset, sixteen bytes in
// two eight-byte groups, then the printable rendering between pipes —
// which is why it buffers a whole line before writing anything.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use alloc::vec;
use alloc::vec::Vec;

use crate::convert::{byte as tobyte, int as toint};
use crate::errors::{error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int};

const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";

// go: sdk 1.25.5 encoding/hex/hex.go:39-39 EncodedLen
/// `hex.EncodedLen(n)` — bytes needed to encode `n` source bytes.
/// Mirrors `EncodedLen` (hex.go:39).
pub fn EncodedLen(n: int) -> int {
    return n * 2;
}

// go: sdk 1.25.5 encoding/hex/hex.go:78-78 DecodedLen
/// `hex.DecodedLen(n)` — bytes produced by decoding `n` source
/// bytes. Mirrors `DecodedLen` (hex.go:78).
pub fn DecodedLen(n: int) -> int {
    return n / 2;
}

// go: sdk 1.25.5 encoding/hex/hex.go:45-53 Encode
/// `hex.Encode(dst, src)` — write the hex encoding of `src` into
/// `dst`, returns the number of bytes written (always 2 * len(src)).
/// Mirrors `Encode` (hex.go:45).
pub fn Encode(dst: &mut [u8], src: &[u8]) -> int {
    let needed = src.len() * 2;
    assert!(dst.len() >= needed, "hex: Encode dst too short");
    let mut j = 0;
    for &b in src {
        dst[j] = HEX_TABLE[(b >> 4) as usize];
        dst[j + 1] = HEX_TABLE[(b & 0x0f) as usize];
        j += 2;
    }
    return toint(j);
}

// go: sdk 1.25.5 encoding/hex/hex.go:126-130 EncodeToString
/// `hex.EncodeToString(src)` — return the hex encoding as a string.
/// Mirrors `EncodeToString` (hex.go:126).
pub fn EncodeToString(src: &[u8]) -> string {
    let mut dst = vec![0u8; src.len() * 2];
    Encode(&mut dst, src);
    return string::from_bytes(&dst);
}

#[derive(Clone)]
pub struct InvalidByteError(pub u8);

impl ErrorTrait for InvalidByteError {
    // go: sdk 1.25.5 encoding/hex/hex.go:72-74 InvalidByteError.Error
    fn Error(&self) -> string {
        // Go: fmt.Sprintf("encoding/hex: invalid byte: %#U", rune(e))
        //
        // `%#U` is `U+XXXX` with at least four upper-case hex digits,
        // plus ` 'c'` when the rune is printable. goish's fmt has no
        // `%#U`, so the two halves are written out.
        let r = crate::convert::rune(self.0);
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        buf.extend_from_slice(b"encoding/hex: invalid byte: U+");
        let mut i: int = 3;
        while i >= 0 {
            let nib = ((r >> (i * 4)) & 0xf) as usize;
            buf.push(HEX_UPPER[nib]);
            i -= 1;
        }
        if crate::unicode::IsPrint(r) {
            buf.push(b' ');
            buf.push(b'\'');
            buf.extend_from_slice(crate::gostring::__crate_as_bytes(&crate::convert::string(
                r,
            )));
            buf.push(b'\'');
        }
        return string::from_bytes(&buf);
    }
}

// go: none — goish idiom: the upper-case digits `%#U` needs; the
//     package's own `HEX_TABLE` is lower-case, for encoding.
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

#[derive(Clone)]
pub struct ErrLength;

impl ErrorTrait for ErrLength {
    // go: sdk 1.25.5 encoding/hex/hex.go:72-74 Error
    fn Error(&self) -> string {
        return string::from_static("encoding/hex: odd length hex string");
    }
}

// go: none — goish idiom: Go decodes a nibble with a 256-byte
//     `reverseHexTable` string constant indexed by the byte. goish
//     matches on the character instead: the table's only purpose is to
//     make the lookup branchless, and a `match` on three ranges is the
//     same decision written out.
#[inline]
fn from_hex_char(c: u8) -> (u8, bool) {
    return match c {
        b'0'..=b'9' => (c - b'0', true),
        b'a'..=b'f' => (c - b'a' + 10, true),
        b'A'..=b'F' => (c - b'A' + 10, true),
        _ => (0, false),
    };
}

// go: sdk 1.25.5 encoding/hex/hex.go:87-113 Decode
/// `hex.Decode(dst, src)` — decode `src` into `dst`, returns
/// (bytesWritten, err). Mirrors `Decode` (hex.go:87).
pub fn Decode(dst: &mut [u8], src: &[u8]) -> (int, error) {
    let mut i = 0;
    let mut j = 0;
    while j + 1 < src.len() {
        let (hi, ok1) = from_hex_char(src[j]);
        if !ok1 {
            return (toint(i), crate::errors::Wrap(InvalidByteError(src[j])));
        }
        let (lo, ok2) = from_hex_char(src[j + 1]);
        if !ok2 {
            return (toint(i), crate::errors::Wrap(InvalidByteError(src[j + 1])));
        }
        if i >= dst.len() {
            break;
        }
        dst[i] = (hi << 4) | lo;
        i += 1;
        j += 2;
    }
    if src.len() % 2 == 1 {
        // Check whether the trailing byte is a valid hex char before
        // reporting odd-length (Go's behavior).
        let (_, ok) = from_hex_char(src[src.len() - 1]);
        if !ok {
            return (
                toint(i),
                crate::errors::Wrap(InvalidByteError(src[src.len() - 1])),
            );
        }
        return (toint(i), crate::errors::Wrap(ErrLength));
    }
    return (toint(i), crate::errors::nil);
}

// go: sdk 1.25.5 encoding/hex/hex.go:138-142 DecodeString
/// `hex.DecodeString(s)` — decode a hex string into bytes. Returns
/// `(slice<byte>, error)` — Go's `[]byte` shape. Mirrors
/// `DecodeString` (hex.go:138).
pub fn DecodeString(s: &str) -> (slice<byte>, error) {
    let src = s.as_bytes();
    let mut dst: Vec<u8> = vec![0u8; src.len() / 2];
    let (n, err) = Decode(&mut dst, src);
    dst.truncate(n as usize);
    return (slice::__from_vec(dst), err);
}

// go: sdk 1.25.5 encoding/hex/hex.go:57-62 AppendEncode
/// `hex.AppendEncode(dst, src)` (hex.go:57) — append the hex encoding
/// of `src` to `dst` and return the extended buffer.
///
/// Public API uses goish primitives (`slice<byte>`); the existing
/// `Encode(&mut [u8], &[u8])` is the low-level helper.
pub fn AppendEncode(dst: slice<byte>, src: slice<byte>) -> slice<byte> {
    // Go: n := EncodedLen(len(src)); dst = slices.Grow(dst, n)
    //     Encode(dst[len(dst):][:n], src); return dst[:len(dst)+n]
    let src_raw: &[byte] = &src;
    let n = src_raw.len() * 2;
    let mut out: Vec<byte> = dst.__into_vec();
    out.reserve(n);
    let start = out.len();
    out.resize(start + n, 0);
    Encode(&mut out[start..start + n], src_raw);
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 encoding/hex/hex.go:118-123 AppendDecode
/// `hex.AppendDecode(dst, src)` (hex.go:118) — append the decoded
/// bytes of `src` to `dst` and return the extended buffer plus any
/// decoding error. On error returns the partially decoded prefix.
pub fn AppendDecode(dst: slice<byte>, src: slice<byte>) -> (slice<byte>, error) {
    // Go: n := DecodedLen(len(src)); dst = slices.Grow(dst, n)
    //     n, err := Decode(dst[len(dst):][:n], src)
    //     return dst[:len(dst)+n], err
    let src_raw: &[byte] = &src;
    let cap_n = src_raw.len() / 2;
    let mut out: Vec<byte> = dst.__into_vec();
    out.reserve(cap_n);
    let start = out.len();
    out.resize(start + cap_n, 0);
    let (n, err) = Decode(&mut out[start..start + cap_n], src_raw);
    out.truncate(start + n as usize);
    return (slice::__from_vec(out), err);
}

// ─── NewEncoder / NewDecoder (hex.go:163-237) ────────────────────────────────

const BUFFER_SIZE: usize = 1024;

// go: sdk 1.25.5 encoding/hex/hex.go:173-175 NewEncoder
/// `hex.NewEncoder(w)` (hex.go:172) — `io.Writer` that lower-cases
/// hex-encodes its input as it streams into `w`.
pub fn NewEncoder<W: crate::io::Writer>(w: W) -> Encoder<W> {
    return Encoder {
        w,
        err: crate::errors::nil,
        out: [0u8; BUFFER_SIZE],
    };
}

/// `*encoder` (hex.go:166) — `io::Writer` that hex-encodes input.
pub struct Encoder<W: crate::io::Writer> {
    w: W,
    err: error,
    out: [byte; BUFFER_SIZE],
}

impl<W: crate::io::Writer> crate::io::Writer for Encoder<W> {
    // go: sdk 1.25.5 encoding/hex/hex.go:177-191 encoder.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: hex.go:177-191
        let raw: &[byte] = &p;
        let mut p = raw;
        let mut n: int = 0;
        while !p.is_empty() && self.err.IsNil() {
            let chunk_size = (BUFFER_SIZE / 2).min(p.len());
            let encoded = Encode(&mut self.out[..], &p[..chunk_size]);
            // Go: written, e.err = e.w.Write(e.out[:encoded])
            let chunk = slice::__from_vec(self.out[..encoded as usize].to_vec());
            let (written, err) = self.w.Write(chunk);
            self.err = err;
            n += written / 2;
            p = &p[chunk_size..];
        }
        return (n, self.err.clone());
    }
}

// go: sdk 1.25.5 encoding/hex/hex.go:202-204 NewDecoder
/// `hex.NewDecoder(r)` (hex.go:202) — `io.Reader` that hex-decodes
/// `r` on the fly. Expects an even number of hex chars in total.
pub fn NewDecoder<R: crate::io::Reader>(r: R) -> Decoder<R> {
    return Decoder {
        r,
        err: crate::errors::nil,
        in_buf: alloc::vec![],
        arr: [0u8; BUFFER_SIZE],
    };
}

/// `*decoder` (hex.go:193) — `io::Reader` that hex-decodes input.
pub struct Decoder<R: crate::io::Reader> {
    r: R,
    err: error,
    in_buf: Vec<byte>,
    arr: [byte; BUFFER_SIZE],
}

impl<R: crate::io::Reader> crate::io::Reader for Decoder<R> {
    // go: sdk 1.25.5 encoding/hex/hex.go:206-237 Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: hex.go:206-237
        // Refill internal buffer if we have <2 hex chars and no error.
        if self.in_buf.len() < 2 && self.err.IsNil() {
            let num_copy = self.in_buf.len();
            self.arr[..num_copy].copy_from_slice(&self.in_buf);
            // Read remaining bytes after the existing leftover.
            let mut tail_buf = slice::__from_vec(alloc::vec![0u8; BUFFER_SIZE - num_copy]);
            let (num_read, err) = self.r.Read(&mut tail_buf);
            let tail_raw: &[byte] = &tail_buf;
            self.arr[num_copy..num_copy + num_read as usize]
                .copy_from_slice(&tail_raw[..num_read as usize]);
            self.in_buf = self.arr[..num_copy + num_read as usize].to_vec();
            self.err = err;

            // Go: hex.go:213-220 — odd length at EOF check.
            if is_eof(&self.err) && self.in_buf.len() % 2 != 0 {
                let last = self.in_buf[self.in_buf.len() - 1];
                if !is_hex(last) {
                    self.err = invalid_byte_error(last);
                } else {
                    self.err = crate::errors::New("unexpected EOF");
                }
            }
        }

        // Decode internal buffer into output buffer.
        let p_raw: &mut [byte] = p;
        let max_decode = self.in_buf.len() / 2;
        let take = p_raw.len().min(max_decode);
        let (num_dec, err) = Decode(&mut p_raw[..take], &self.in_buf[..take * 2]);
        // Drop the consumed bytes.
        self.in_buf.drain(..(2 * num_dec as usize));
        if !err.IsNil() {
            // Decode error; discard input remainder and propagate.
            self.in_buf.clear();
            self.err = err;
        }

        if self.in_buf.len() < 2 {
            return (num_dec, self.err.clone());
        }
        return (num_dec, crate::errors::nil);
    }
}

// go: none — goish idiom: Go tests a nibble by looking it up in
//     `reverseHexTable` and comparing against the 0xff sentinel; this
//     is the same predicate spelled directly.
#[inline]
fn is_hex(b: byte) -> bool {
    return b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b);
}

// go: none — goish idiom: Go compares `err == io.EOF` by interface
//     identity; goish's decoder receives the error already wrapped, so
//     it matches on the message.
fn is_eof(e: &error) -> bool {
    if e.IsNil() {
        return false;
    }
    return e.Error() == "EOF";
}

// go: none — goish idiom: builds the `InvalidByteError` message. Go
//     constructs the typed error at the use site and lets `Error()`
//     format it; goish formats once here.
fn invalid_byte_error(b: byte) -> error {
    return crate::errors::Wrap(InvalidByteError(b));
}

// ─── Dumper / Dump (hex.go:144 + 242) ────────────────────────────────────────

// go: sdk 1.25.5 encoding/hex/hex.go:242-244 Dumper
/// `hex.Dumper(w)` (hex.go:242) — return a Dumper that writes a
/// `hexdump -C`-style hex dump of all input data to `w`.
///
/// Slim deviation: returns the concrete `Dumper<W>` rather than
/// `io.WriteCloser` (Goish doesn't ship trait-object Writers); callers
/// can still call `.Write` and `.Close` directly.
pub fn Dumper<W: crate::io::Writer>(w: W) -> Dumper<W> {
    return Dumper {
        w,
        right_chars: [0u8; 18],
        buf: [0u8; 14],
        used: 0,
        n: 0,
        closed: false,
    };
}

// go: sdk 1.25.5 encoding/hex/hex.go:146-161 Dump
/// `hex.Dump(data)` (hex.go:146) — return a hexdump string for `data`.
/// Empty input → empty string.
pub fn Dump(data: slice<byte>) -> string {
    use crate::io::{Closer, Writer};
    if data.len() == 0 {
        return string::from_static("");
    }
    let mut buf = crate::bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
    let mut d = Dumper(&mut buf);
    let _ = d.Write(data);
    let _ = d.Close();
    return buf.String();
}

/// `*dumper` (hex.go:246) — `hexdump -C` writer. Implements
/// `io::Writer` + `io::Closer`.
pub struct Dumper<W: crate::io::Writer> {
    w: W,
    right_chars: [byte; 18],
    buf: [byte; 14],
    used: int,
    n: u32,
    closed: bool,
}

// go: sdk 1.25.5 encoding/hex/hex.go:255-260 toChar
#[inline]
fn toChar(b: byte) -> byte {
    // Go: hex.go:255-260
    return if b < 32 || b > 126 { b'.' } else { b };
}

impl<W: crate::io::Writer> crate::io::Writer for Dumper<W> {
    // go: sdk 1.25.5 encoding/hex/hex.go:262-318 dumper.Write
    fn Write(&mut self, data: slice<byte>) -> (int, error) {
        // Go: hex.go:262-318
        if self.closed {
            return (0, crate::errors::New("encoding/hex: dumper closed"));
        }
        let raw: &[byte] = &data;
        let mut written: int = 0;

        for i in 0..raw.len() {
            // Go: hex.go:271 — at line start, emit offset.
            if self.used == 0 {
                self.buf[0] = tobyte(self.n >> 24);
                self.buf[1] = tobyte(self.n >> 16);
                self.buf[2] = tobyte(self.n >> 8);
                self.buf[3] = tobyte(self.n);
                let (left, right) = self.buf.split_at_mut(4);
                Encode(&mut right[..8], &left[..4]);
                self.buf[12] = b' ';
                self.buf[13] = b' ';
                let chunk = slice::__from_vec(self.buf[4..14].to_vec());
                let (_, err) = self.w.Write(chunk);
                if !err.IsNil() {
                    return (written, err);
                }
            }
            // Go: hex.go:286 — encode this byte and emit hex pair + spacer.
            let one = [raw[i]];
            Encode(&mut self.buf[..2], &one);
            self.buf[2] = b' ';
            let mut l: usize = 3;
            if self.used == 7 {
                self.buf[3] = b' ';
                l = 4;
            } else if self.used == 15 {
                self.buf[3] = b' ';
                self.buf[4] = b'|';
                l = 5;
            }
            let chunk = slice::__from_vec(self.buf[..l].to_vec());
            let (_, err) = self.w.Write(chunk);
            if !err.IsNil() {
                return (written, err);
            }
            written += 1;
            self.right_chars[self.used as usize] = toChar(raw[i]);
            self.used += 1;
            self.n += 1;
            if self.used == 16 {
                self.right_chars[16] = b'|';
                self.right_chars[17] = b'\n';
                let chunk = slice::__from_vec(self.right_chars[..18].to_vec());
                let (_, err) = self.w.Write(chunk);
                if !err.IsNil() {
                    return (written, err);
                }
                self.used = 0;
            }
        }
        return (written, crate::errors::nil);
    }
}

impl<W: crate::io::Writer> crate::io::Closer for Dumper<W> {
    // go: sdk 1.25.5 encoding/hex/hex.go:321-353 Close
    fn Close(&mut self) -> error {
        // Go: hex.go:321-353
        if self.closed {
            return crate::errors::nil;
        }
        self.closed = true;
        if self.used == 0 {
            return crate::errors::nil;
        }
        self.buf[0] = b' ';
        self.buf[1] = b' ';
        self.buf[2] = b' ';
        self.buf[3] = b' ';
        self.buf[4] = b'|';
        let n_bytes = self.used;
        while self.used < 16 {
            let mut l: usize = 3;
            if self.used == 7 {
                l = 4;
            } else if self.used == 15 {
                l = 5;
            }
            let chunk = slice::__from_vec(self.buf[..l].to_vec());
            let (_, err) = self.w.Write(chunk);
            if !err.IsNil() {
                return err;
            }
            self.used += 1;
        }
        self.right_chars[n_bytes as usize] = b'|';
        self.right_chars[(n_bytes + 1) as usize] = b'\n';
        let chunk = slice::__from_vec(self.right_chars[..(n_bytes + 2) as usize].to_vec());
        let (_, err) = self.w.Write(chunk);
        return err;
    }
}
