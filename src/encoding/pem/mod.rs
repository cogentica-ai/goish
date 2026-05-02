// encoding/pem — Privacy Enhanced Mail (RFC 1421) data encoding.
//
// Reference: /share/go/src/encoding/pem/pem.go.
//
// Public surface:
//
//   pub struct Block { Type, Headers, Bytes }
//   pub fn Decode(data: slice<byte>) -> (Option<Block>, slice<byte>)
//   pub fn Encode<W: io::Writer>(out: &mut W, b: &Block) -> error
//   pub fn EncodeToMemory(b: &Block) -> slice<byte>
//
// Slim deviations:
//   * Encode uses base64::EncodeToString to produce a complete
//     base64 string and then breaks it into 64-byte lines, rather
//     than wrapping a streaming `base64.NewEncoder` around an
//     `io::Writer`. Goish's base64 doesn't expose a streaming
//     encoder; the offline approach has identical output.
//   * `Headers` is `map<string, string>`. Iteration order matches
//     BTreeMap (sorted by key) — Go uses a `map` and explicitly
//     `slices.Sort`s before writing, so iteration order on the
//     wire is identical (with the Proc-Type RFC 1421 §4.6.1.1
//     exception preserved).

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::bytes;
use crate::encoding::base64;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int};

// ─── Block (pem.go:29) ───────────────────────────────────────────────────────

/// `pem.Block` (pem.go:29) — a PEM-encoded structure.
///
/// On the wire:
/// ```text
/// -----BEGIN Type-----
/// Headers
/// base64-encoded Bytes
/// -----END Type-----
/// ```
#[derive(Clone)]
pub struct Block {
    /// Type, e.g. "RSA PRIVATE KEY".
    pub Type: string,
    /// Optional headers (Key: Value lines).
    pub Headers: crate::gomap::map<string, string>,
    /// Decoded bytes (typically a DER ASN.1 structure).
    pub Bytes: slice<byte>,
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// `getLine` (pem.go:40) — return the first \r\n or \n delimited line and
/// the remainder of the input. The line excludes trailing whitespace and
/// the newline bytes; the remainder also excludes the newline bytes.
/// `consumed` is the number of bytes from `data` removed (line + newline).
fn getLine(data: &[byte]) -> (slice<byte>, slice<byte>, int) {
    // Go: pem.go:41 — i := bytes.IndexByte(data, '\n')
    let i_int = bytes::IndexByte(slice::__from_vec(data.to_vec()), b'\n');
    let mut i: usize;
    let j: usize;
    // Go: pem.go:42 — var j int
    if i_int < 0 {
        // Go: pem.go:43 — i = len(data); j = i
        i = data.len();
        j = i;
    } else {
        i = i_int as usize;
        j = i + 1;
        // Go: pem.go:48 — if i > 0 && data[i-1] == '\r' { i-- }
        if i > 0 && data[i - 1] == b'\r' {
            i -= 1;
        }
    }
    // Go: pem.go:52 — return bytes.TrimRight(data[0:i], " \t"), data[j:], j
    let line_v = bytes::TrimRight(
        slice::__from_vec(data[..i].to_vec()),
        slice::__from_vec(b" \t".to_vec()),
    );
    let rest_v = slice::__from_vec(data[j..].to_vec());
    (line_v, rest_v, j as int)
}

/// `removeSpacesAndTabs` (pem.go:60) — copy of input with all spaces and
/// tabs removed; if none are present, returns the input unchanged.
///
/// Slim deviation: Go's base64 decoder skips '\n' and '\r' itself, so this
/// helper only strips ' ' and '\t' upstream. Goish's base64 does NOT skip
/// newlines, so we strip those here as well to feed a clean stream to
/// `DecodeString`. Output bytes for valid PEM are identical either way.
fn removeSpacesAndTabs(data: &[byte]) -> slice<byte> {
    // Go: pem.go:61 — fast path. Extended to also detect \r\n.
    if !bytes::ContainsAny(
        slice::__from_vec(data.to_vec()),
        slice::__from_vec(b" \t\r\n".to_vec()),
    ) {
        return slice::__from_vec(data.to_vec());
    }
    // Go: pem.go:66 — result := make([]byte, len(data))
    let mut result: Vec<byte> = Vec::with_capacity(data.len());
    // Go: pem.go:69 — for _, b := range data { ... }
    for &b in data {
        if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
            continue;
        }
        result.push(b);
    }
    // Go: pem.go:77 — return result[0:n]
    slice::__from_vec(result)
}

// ─── PEM markers (pem.go:80-83) ──────────────────────────────────────────────

const PEM_START: &[byte] = b"\n-----BEGIN ";
const PEM_END: &[byte] = b"\n-----END ";
const PEM_END_OF_LINE: &[byte] = b"-----";
const COLON: byte = b':';

// ─── Decode (pem.go:89) ──────────────────────────────────────────────────────

/// `pem.Decode(data)` (pem.go:89) — find the next PEM-formatted block in the
/// input. Returns the block and the remainder. If no PEM data is found,
/// returns `None` and the whole input.
pub fn Decode(data: slice<byte>) -> (Option<Block>, slice<byte>) {
    // Go: pem.go:92 — rest = data
    let raw: Vec<byte> = data.__into_vec();
    let mut rest: Vec<byte> = raw.clone();

    // Go: pem.go:94 — endTrailerIndex := 0
    let mut end_trailer_index: int = 0;

    loop {
        // Go: pem.go:98 — if endTrailerIndex < 0 || endTrailerIndex > len(rest)
        if end_trailer_index < 0 || end_trailer_index > rest.len() as int {
            return (None, slice::__from_vec(raw));
        }
        // Go: pem.go:101 — rest = rest[endTrailerIndex:]
        rest = rest[end_trailer_index as usize..].to_vec();

        // Go: pem.go:106 — endIndex := bytes.Index(rest, pemEnd)
        let end_index_full = bytes::Index(
            slice::__from_vec(rest.clone()),
            slice::__from_vec(PEM_END.to_vec()),
        );
        if end_index_full < 0 {
            return (None, slice::__from_vec(raw));
        }
        let mut end_index = end_index_full;
        end_trailer_index = end_index + PEM_END.len() as int;

        // Go: pem.go:111 — beginIndex := bytes.LastIndex(rest[:endIndex], pemStart[1:])
        let begin_index_full = bytes::LastIndex(
            slice::__from_vec(rest[..end_index as usize].to_vec()),
            slice::__from_vec(PEM_START[1..].to_vec()),
        );
        // Go: pem.go:112 — must be at start, or preceded by \n
        if begin_index_full < 0
            || (begin_index_full > 0 && rest[(begin_index_full - 1) as usize] != b'\n')
        {
            continue;
        }

        // Go: pem.go:115 — rest = rest[beginIndex+len(pemStart)-1:]
        let shift = (begin_index_full + PEM_START.len() as int - 1) as usize;
        rest = rest[shift..].to_vec();
        end_index -= shift as int;
        end_trailer_index -= shift as int;

        // Go: pem.go:121 — typeLine, rest, consumed = getLine(rest)
        let (type_line_v, rest_after_type, consumed) = getLine(&rest);
        let mut type_line: Vec<byte> = type_line_v.__into_vec();
        rest = rest_after_type.__into_vec();
        end_index -= consumed;
        end_trailer_index -= consumed;

        // Go: pem.go:124 — if !bytes.HasSuffix(typeLine, pemEndOfLine) { continue }
        if !bytes::HasSuffix(
            slice::__from_vec(type_line.clone()),
            slice::__from_vec(PEM_END_OF_LINE.to_vec()),
        ) {
            continue;
        }
        // Go: pem.go:127 — typeLine = typeLine[0 : len(typeLine)-len(pemEndOfLine)]
        type_line.truncate(type_line.len() - PEM_END_OF_LINE.len());

        // Go: pem.go:129 — p = &Block{Headers: …, Type: …}
        let mut p = Block {
            Type: string::from_bytes(&type_line),
            Headers: crate::gomap::map::new(),
            Bytes: slice::__from_vec(alloc::vec![]),
        };

        // Go: pem.go:134-154 — header lines (Key: Value).
        loop {
            if rest.is_empty() {
                return (None, slice::__from_vec(raw));
            }
            let (line_v, next_v, consumed_h) = getLine(&rest);
            let line_bytes: Vec<byte> = line_v.__into_vec();

            let (key_v, val_v, ok) = bytes::Cut(
                slice::__from_vec(line_bytes.clone()),
                slice::__from_vec(alloc::vec![COLON]),
            );
            if !ok {
                break;
            }
            // Go: pem.go:148 — key = bytes.TrimSpace(key); val = bytes.TrimSpace(val)
            let key_bytes: Vec<byte> = bytes::TrimSpace(key_v).__into_vec();
            let val_bytes: Vec<byte> = bytes::TrimSpace(val_v).__into_vec();
            // Go: pem.go:150 — p.Headers[string(key)] = string(val)
            p.Headers.Set(
                string::from_bytes(&key_bytes),
                string::from_bytes(&val_bytes),
            );
            rest = next_v.__into_vec();
            end_index -= consumed_h;
            end_trailer_index -= consumed_h;
        }

        // Go: pem.go:158 — if len(p.Headers) > 0 && endIndex < 0 { continue }
        if p.Headers.Len() > 0 && end_index < 0 {
            continue;
        }

        // Go: pem.go:164 — endTrailer := rest[endTrailerIndex:]
        let end_trailer_full = &rest[end_trailer_index as usize..];
        // Go: pem.go:165 — endTrailerLen := len(typeLine) + len(pemEndOfLine)
        let end_trailer_len = type_line.len() + PEM_END_OF_LINE.len();
        if end_trailer_full.len() < end_trailer_len {
            continue;
        }

        let rest_of_end_line: Vec<byte> = end_trailer_full[end_trailer_len..].to_vec();
        let end_trailer: Vec<byte> = end_trailer_full[..end_trailer_len].to_vec();
        // Go: pem.go:172 — must HasPrefix(endTrailer, typeLine) && HasSuffix(endTrailer, pemEndOfLine)
        if !bytes::HasPrefix(
            slice::__from_vec(end_trailer.clone()),
            slice::__from_vec(type_line.clone()),
        ) || !bytes::HasSuffix(
            slice::__from_vec(end_trailer.clone()),
            slice::__from_vec(PEM_END_OF_LINE.to_vec()),
        ) {
            continue;
        }

        // Go: pem.go:178 — line must end with only whitespace.
        let (s_v, _, _) = getLine(&rest_of_end_line);
        if s_v.len() != 0 {
            continue;
        }

        // Go: pem.go:182 — p.Bytes = []byte{}
        if end_index > 0 {
            // Go: pem.go:184 — base64Data := removeSpacesAndTabs(rest[:endIndex])
            let base64_data = removeSpacesAndTabs(&rest[..end_index as usize]);
            // Go: pem.go:186 — base64.StdEncoding.Decode(...)
            // Slim: use DecodeString which takes &str and handles whitespace.
            let raw_b64: Vec<byte> = base64_data.__into_vec();
            let s = match core::str::from_utf8(&raw_b64) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let (decoded, derr) = base64::StdEncoding.DecodeString(s);
            if !derr.IsNil() {
                continue;
            }
            p.Bytes = decoded;
        }

        // Go: pem.go:195 — _, rest, _ = getLine(rest[endIndex+len(pemEnd)-1:])
        let advance = (end_index + PEM_END.len() as int - 1) as usize;
        let (_drop, rest_after, _) = getLine(&rest[advance..]);
        return (Some(p), rest_after);
    }
}

// ─── Encode (pem.go:255) ─────────────────────────────────────────────────────

const PEM_LINE_LENGTH: usize = 64; // pem.go:200

/// `pem.Encode(out, b)` (pem.go:255) — write the PEM encoding of `b` to `out`.
pub fn Encode<W: io::Writer>(out: &mut W, b: &Block) -> error {
    // Go: pem.go:257 — reject any header key containing ':'.
    let keys = b.Headers.Keys();
    for k in keys.iter() {
        if crate::strings::Contains(k.clone(), string::from_static(":")) {
            return errors::New("pem: cannot encode a header key that contains a colon");
        }
    }

    // Go: pem.go:266 — out.Write(pemStart[1:])  // "-----BEGIN "
    let (_, e1) = out.Write(slice::__from_vec(PEM_START[1..].to_vec()));
    if !e1.IsNil() {
        return e1;
    }
    // Go: pem.go:269 — out.Write([]byte(b.Type + "-----\n"))
    let mut head: Vec<byte> = Vec::new();
    head.extend_from_slice(crate::gostring::__crate_as_bytes(&b.Type));
    head.extend_from_slice(b"-----\n");
    let (_, e2) = out.Write(slice::__from_vec(head));
    if !e2.IsNil() {
        return e2;
    }

    // Go: pem.go:273 — write headers, Proc-Type first, rest sorted.
    if b.Headers.Len() > 0 {
        let proc_type = string::from_static("Proc-Type");
        let mut ordered: Vec<string> = Vec::new();
        let mut has_proc_type = false;
        for k in b.Headers.Keys().iter() {
            if *k == proc_type {
                has_proc_type = true;
                continue;
            }
            ordered.push(k.clone());
        }
        // Go: pem.go:286 — write Proc-Type first.
        if has_proc_type {
            let pt_v = b.Headers.Get(proc_type.clone()).0;
            let e = write_header(out, &proc_type, &pt_v);
            if !e.IsNil() {
                return e;
            }
        }
        // Go: pem.go:292 — slices.Sort(h)
        ordered.sort();
        for k in ordered.iter() {
            let v = b.Headers.Get(k.clone()).0;
            let e = write_header(out, k, &v);
            if !e.IsNil() {
                return e;
            }
        }
        // Go: pem.go:298 — out.Write(nl)
        let (_, e) = out.Write(slice::__from_vec(alloc::vec![b'\n']));
        if !e.IsNil() {
            return e;
        }
    }

    // Go: pem.go:303 — base64 encode b.Bytes through a 64-col line breaker.
    let raw: &[byte] = &b.Bytes;
    let encoded = base64::StdEncoding.EncodeToString(raw);
    // Slim: write encoded string in 64-byte chunks separated by '\n'.
    let s_bytes = crate::gostring::__crate_as_bytes(&encoded);
    let mut i = 0usize;
    while i < s_bytes.len() {
        let end = (i + PEM_LINE_LENGTH).min(s_bytes.len());
        let (_, e) = out.Write(slice::__from_vec(s_bytes[i..end].to_vec()));
        if !e.IsNil() {
            return e;
        }
        let (_, e2) = out.Write(slice::__from_vec(alloc::vec![b'\n']));
        if !e2.IsNil() {
            return e2;
        }
        i = end;
    }

    // Go: pem.go:313 — out.Write(pemEnd[1:])  // "-----END "
    let (_, e3) = out.Write(slice::__from_vec(PEM_END[1..].to_vec()));
    if !e3.IsNil() {
        return e3;
    }
    // Go: pem.go:316 — out.Write([]byte(b.Type + "-----\n"))
    let mut tail: Vec<byte> = Vec::new();
    tail.extend_from_slice(crate::gostring::__crate_as_bytes(&b.Type));
    tail.extend_from_slice(b"-----\n");
    let (_, e4) = out.Write(slice::__from_vec(tail));
    e4
}

fn write_header<W: io::Writer>(out: &mut W, k: &string, v: &string) -> error {
    // Go: pem.go:250 — out.Write([]byte(k + ": " + v + "\n"))
    let mut buf: Vec<byte> = Vec::new();
    buf.extend_from_slice(crate::gostring::__crate_as_bytes(k));
    buf.extend_from_slice(b": ");
    buf.extend_from_slice(crate::gostring::__crate_as_bytes(v));
    buf.push(b'\n');
    let (_, e) = out.Write(slice::__from_vec(buf));
    e
}

// ─── EncodeToMemory (pem.go:325) ─────────────────────────────────────────────

/// `pem.EncodeToMemory(b)` (pem.go:325) — return the PEM encoding of `b`.
/// Returns an empty slice if the block has invalid headers.
pub fn EncodeToMemory(b: &Block) -> slice<byte> {
    let mut buf = crate::bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
    let e = Encode(&mut buf, b);
    if !e.IsNil() {
        return slice::__from_vec(alloc::vec![]);
    }
    buf.Bytes()
}
