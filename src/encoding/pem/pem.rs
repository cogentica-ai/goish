// go: file encoding/pem/pem.go decls: getLine, removeSpacesAndTabs, Decode, lineBreaker.Write, lineBreaker.Close, writeHeader, Encode, EncodeToMemory
//
// The `decls:` manifest above lists pem.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the file's consts, types and vars there would report every one of
// them as a dropped port. They are not dropped — `Block`, `pemStart`,
// `pemEnd`, `pemEndOfLine`, `colon`, `pemLineLength`, `lineBreaker`
// and `nl` each carry their own `// go: sdk` anchor below.
//
// encoding/pem/pem.go — the PEM data encoding, which originated in
// Privacy Enhanced Mail (RFC 1421). Its most common use today is in
// TLS keys and certificates.
//
// `Decode` is the load-bearing half and reads oddly on purpose. It
// finds the first END line and then the *last* BEGIN before it, so a
// run of unterminated BEGIN lines cannot make it miss the block that
// does terminate; and it carries `endIndex` and `endTrailerIndex` as
// offsets that every `getLine` decrements, so a failed candidate can
// `continue` and resume past the END it already rejected rather than
// rescanning from the top. Both are Go's, and are reproduced rather
// than simplified.
//
// Deviations from Go:
//
//   * `Encode` base64-encodes `b.Bytes` in one shot and feeds the
//     result through `lineBreaker`, where Go wraps a streaming
//     `base64.NewEncoder` around the same breaker. goish's
//     encoding/base64 has no streaming encoder (it needs
//     `io.WriteCloser`, which is not ported), and the byte output is
//     identical either way — the breaker still does the 64-column
//     wrapping, so it is the same code path on the way out.
//   * `removeSpacesAndTabs` also strips CR and LF. Go leaves them for
//     its base64 decoder, which skips them; goish's does not.
//   * `Decode` returns `Option<Block>` where Go returns a nil `*Block`.
//   * `Encode` is generic over `W: io::Writer` rather than taking the
//     `io.Writer` interface, so `lineBreaker` can hold `&mut W` and
//     stay a three-field Go-shaped struct instead of boxing a trait
//     object (§5 rule 3).

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::bytes;
use crate::convert::int as toint;
use crate::encoding::base64;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int};

// ─── Block (pem.go:29) ───────────────────────────────────────────────────────

// go: sdk 1.25.5 encoding/pem/pem.go:29-33 Block
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

// go: sdk 1.25.5 encoding/pem/pem.go:40-53 getLine
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
    return (line_v, rest_v, toint(j));
}

// go: sdk 1.25.5 encoding/pem/pem.go:60-78 removeSpacesAndTabs
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
    return slice::__from_vec(result);
}

// ─── PEM markers ─────────────────────────────────────────────────────

// go: sdk 1.25.5 encoding/pem/pem.go:80-80 pemStart
const pemStart: &[byte] = b"\n-----BEGIN ";
// go: sdk 1.25.5 encoding/pem/pem.go:81-81 pemEnd
const pemEnd: &[byte] = b"\n-----END ";
// go: sdk 1.25.5 encoding/pem/pem.go:82-82 pemEndOfLine
const pemEndOfLine: &[byte] = b"-----";
// go: sdk 1.25.5 encoding/pem/pem.go:83-83 colon
//
// Go's is a one-byte `[]byte` for `bytes.Cut`; goish's `bytes::Cut`
// takes the separator as a slice built from this byte.
const colon: byte = b':';

// ─── Decode (pem.go:89) ──────────────────────────────────────────────────────

// go: sdk 1.25.5 encoding/pem/pem.go:89-197 Decode
/// `pem.Decode(data)` (pem.go:89) — find the next PEM-formatted block in the
/// input. Returns the block and the remainder. If no PEM data is found,
/// returns `None` and the whole input.
pub fn Decode(data: slice<byte>) -> (Option<Block>, slice<byte>) {
    // Go: pem.go:92 — rest = data
    let raw: Vec<byte> = data.__into_vec();
    let mut rest: Vec<byte> = raw.clone();

    // Go: pem.go:94 — endTrailerIndex := 0
    let mut end_trailer_index: int = 0;

    // Go writes `for { … return … }`; Rust's `loop` is an expression,
    // so the returns become labelled `break` values and the function
    // ends with one explicit `return`, per the house style (GOISH023).
    let out = 'decode: loop {
        // Go: pem.go:98 — if endTrailerIndex < 0 || endTrailerIndex > len(rest)
        if end_trailer_index < 0 || end_trailer_index > toint(rest.len()) {
            break 'decode (None, slice::__from_vec(raw));
        }
        // Go: pem.go:101 — rest = rest[endTrailerIndex:]
        rest = rest[end_trailer_index as usize..].to_vec();

        // Go: pem.go:106 — endIndex := bytes.Index(rest, pemEnd)
        let end_index_full = bytes::Index(
            slice::__from_vec(rest.clone()),
            slice::__from_vec(pemEnd.to_vec()),
        );
        if end_index_full < 0 {
            break 'decode (None, slice::__from_vec(raw));
        }
        let mut end_index = end_index_full;
        end_trailer_index = end_index + toint(pemEnd.len());

        // Go: pem.go:111 — beginIndex := bytes.LastIndex(rest[:endIndex], pemStart[1:])
        let begin_index_full = bytes::LastIndex(
            slice::__from_vec(rest[..end_index as usize].to_vec()),
            slice::__from_vec(pemStart[1..].to_vec()),
        );
        // Go: pem.go:112 — must be at start, or preceded by \n
        if begin_index_full < 0
            || (begin_index_full > 0 && rest[(begin_index_full - 1) as usize] != b'\n')
        {
            continue;
        }

        // Go: pem.go:115 — rest = rest[beginIndex+len(pemStart)-1:]
        let shift = usize::try_from(begin_index_full + toint(pemStart.len()) - 1).unwrap_or(0);
        rest = rest[shift..].to_vec();
        end_index -= toint(shift);
        end_trailer_index -= toint(shift);

        // Go: pem.go:121 — typeLine, rest, consumed = getLine(rest)
        let (type_line_v, rest_after_type, consumed) = getLine(&rest);
        let mut type_line: Vec<byte> = type_line_v.__into_vec();
        rest = rest_after_type.__into_vec();
        end_index -= consumed;
        end_trailer_index -= consumed;

        // Go: pem.go:124 — if !bytes.HasSuffix(typeLine, pemEndOfLine) { continue }
        if !bytes::HasSuffix(
            slice::__from_vec(type_line.clone()),
            slice::__from_vec(pemEndOfLine.to_vec()),
        ) {
            continue;
        }
        // Go: pem.go:127 — typeLine = typeLine[0 : len(typeLine)-len(pemEndOfLine)]
        type_line.truncate(type_line.len() - pemEndOfLine.len());

        // Go: pem.go:129 — p = &Block{Headers: …, Type: …}
        let mut p = Block {
            Type: string::from_bytes(&type_line),
            Headers: crate::gomap::map::new(),
            Bytes: slice::__from_vec(alloc::vec![]),
        };

        // Go: pem.go:134-154 — header lines (Key: Value).
        loop {
            if rest.is_empty() {
                break 'decode (None, slice::__from_vec(raw));
            }
            let (line_v, next_v, consumed_h) = getLine(&rest);
            let line_bytes: Vec<byte> = line_v.__into_vec();

            let (key_v, val_v, ok) = bytes::Cut(
                slice::__from_vec(line_bytes.clone()),
                slice::__from_vec(alloc::vec![colon]),
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
        let end_trailer_len = type_line.len() + pemEndOfLine.len();
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
            slice::__from_vec(pemEndOfLine.to_vec()),
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
        let advance = usize::try_from(end_index + toint(pemEnd.len()) - 1).unwrap_or(0);
        let (_drop, rest_after, _) = getLine(&rest[advance..]);
        break 'decode (Some(p), rest_after);
    };
    return out;
}

// ─── lineBreaker ─────────────────────────────────────────────────────

// go: sdk 1.25.5 encoding/pem/pem.go:200-200 pemLineLength
/// `pem.pemLineLength` — PEM wraps base64 at 64 columns.
const pemLineLength: usize = 64;

// go: sdk 1.25.5 encoding/pem/pem.go:202-206 lineBreaker
/// `pem.lineBreaker` — an `io.Writer` that inserts a newline every
/// [`pemLineLength`] bytes.
///
/// Go's `out` field is the `io.Writer` interface; goish holds `&mut W`
/// so the struct keeps Go's three fields without a boxed trait object.
struct lineBreaker<'a, W: io::Writer> {
    // Go: line [pemLineLength]byte
    line: [byte; pemLineLength],
    // Go: used int
    used: usize,
    // Go: out io.Writer
    out: &'a mut W,
}

// go: sdk 1.25.5 encoding/pem/pem.go:208-208 nl
const nl: &[byte] = b"\n";

impl<'a, W: io::Writer> lineBreaker<'a, W> {
    // go: sdk 1.25.5 encoding/pem/pem.go:210-235 lineBreaker.Write
    /// `(*lineBreaker).Write(b)` — buffer until a full line is
    /// available, then flush it followed by a newline, and recurse on
    /// what is left.
    fn Write(&mut self, b: &[byte]) -> (int, error) {
        // Go: if l.used+len(b) < pemLineLength
        if self.used + b.len() < pemLineLength {
            // Go: copy(l.line[l.used:], b); l.used += len(b)
            self.line[self.used..self.used + b.len()].copy_from_slice(b);
            self.used += b.len();
            return (int::try_from(b.len()).unwrap_or(0), errors::nil);
        }

        // Go: n, err = l.out.Write(l.line[0:l.used])
        let (mut n, err) = self
            .out
            .Write(slice::__from_vec(self.line[..self.used].to_vec()));
        if !err.IsNil() {
            return (n, err);
        }
        // Go: excess := pemLineLength - l.used; l.used = 0
        let excess = pemLineLength - self.used;
        self.used = 0;

        // Go: n, err = l.out.Write(b[0:excess])
        let (n2, err) = self.out.Write(slice::__from_vec(b[..excess].to_vec()));
        n = n2;
        if !err.IsNil() {
            return (n, err);
        }

        // Go: n, err = l.out.Write(nl)
        let (n3, err) = self.out.Write(slice::__from_vec(nl.to_vec()));
        n = n3;
        if !err.IsNil() {
            return (n, err);
        }
        let _ = n;

        // Go: return l.Write(b[excess:])
        return self.Write(&b[excess..]);
    }

    // go: sdk 1.25.5 encoding/pem/pem.go:237-247 lineBreaker.Close
    /// `(*lineBreaker).Close()` — flush the partial line, if any,
    /// followed by a newline.
    fn Close(&mut self) -> error {
        // Go: if l.used > 0
        if self.used > 0 {
            let (_, err) = self
                .out
                .Write(slice::__from_vec(self.line[..self.used].to_vec()));
            if !err.IsNil() {
                return err;
            }
            let (_, err) = self.out.Write(slice::__from_vec(nl.to_vec()));
            return err;
        }
        return errors::nil;
    }
}

// ─── Encode ──────────────────────────────────────────────────────────

// go: sdk 1.25.5 encoding/pem/pem.go:255-317 Encode
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
    let (_, e1) = out.Write(slice::__from_vec(pemStart[1..].to_vec()));
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
            let e = writeHeader(out, &proc_type, &pt_v);
            if !e.IsNil() {
                return e;
            }
        }
        // Go: pem.go:292 — slices.Sort(h)
        ordered.sort();
        for k in ordered.iter() {
            let v = b.Headers.Get(k.clone()).0;
            let e = writeHeader(out, k, &v);
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

    // Go: var breaker lineBreaker; breaker.out = out
    //     b64 := base64.NewEncoder(base64.StdEncoding, &breaker)
    //     b64.Write(b.Bytes); b64.Close(); breaker.Close()
    //
    // goish has no streaming base64 encoder, so the whole encoding is
    // produced first and handed to the same breaker. The bytes on the
    // wire are identical: `lineBreaker` does the wrapping either way.
    {
        let raw: &[byte] = &b.Bytes;
        let encoded = base64::StdEncoding.EncodeToString(raw);
        let mut breaker = lineBreaker {
            line: [0; pemLineLength],
            used: 0,
            out,
        };
        let (_, e) = breaker.Write(crate::gostring::__crate_as_bytes(&encoded));
        if !e.IsNil() {
            return e;
        }
        let e = breaker.Close();
        if !e.IsNil() {
            return e;
        }
    }

    // Go: pem.go:313 — out.Write(pemEnd[1:])  // "-----END "
    let (_, e3) = out.Write(slice::__from_vec(pemEnd[1..].to_vec()));
    if !e3.IsNil() {
        return e3;
    }
    // Go: pem.go:316 — out.Write([]byte(b.Type + "-----\n"))
    let mut tail: Vec<byte> = Vec::new();
    tail.extend_from_slice(crate::gostring::__crate_as_bytes(&b.Type));
    tail.extend_from_slice(b"-----\n");
    let (_, e4) = out.Write(slice::__from_vec(tail));
    return e4;
}

// go: sdk 1.25.5 encoding/pem/pem.go:249-252 writeHeader
/// `pem.writeHeader(out, k, v)` — write one `Key: Value` header line.
fn writeHeader<W: io::Writer>(out: &mut W, k: &string, v: &string) -> error {
    // Go: pem.go:250 — out.Write([]byte(k + ": " + v + "\n"))
    let mut buf: Vec<byte> = Vec::new();
    buf.extend_from_slice(crate::gostring::__crate_as_bytes(k));
    buf.extend_from_slice(b": ");
    buf.extend_from_slice(crate::gostring::__crate_as_bytes(v));
    buf.push(b'\n');
    let (_, e) = out.Write(slice::__from_vec(buf));
    return e;
}

// ─── EncodeToMemory (pem.go:325) ─────────────────────────────────────────────

// go: sdk 1.25.5 encoding/pem/pem.go:325-330 EncodeToMemory
/// `pem.EncodeToMemory(b)` (pem.go:325) — return the PEM encoding of `b`.
/// Returns an empty slice if the block has invalid headers.
pub fn EncodeToMemory(b: &Block) -> slice<byte> {
    let mut buf = crate::bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
    let e = Encode(&mut buf, b);
    if !e.IsNil() {
        return slice::__from_vec(alloc::vec![]);
    }
    return buf.Bytes();
}
