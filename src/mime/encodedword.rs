// go: file mime/encodedword.go decls: WordEncoder.Encode, needsEncoding, WordEncoder.encodeWord, maxBase64Len, WordEncoder.bEncode, WordEncoder.qEncode, writeQString, WordEncoder.openWord, closeWord, WordEncoder.splitWord, isUTF8, WordDecoder.Decode, WordDecoder.DecodeHeader, decode, WordDecoder.convert, hasNonWhitespace, qDecode, readHexByte, fromHex
//
// `errInvalidWord` is a package-level `var` in Go and `maxBase64Len`
// is one too; both are listed in the manifest because goish spells
// them as `fn`s — neither `errors::New` nor `base64::DecodedLen` is
// `const` — and GOISH017 matches a manifest entry against Rust `fn`
// items. The `WordEncoder`/`WordDecoder` types and the constants are
// deliberately absent for the same reason, in reverse: naming a
// non-`fn` there would report it as a dropped port. Each carries its
// own `// go: sdk` anchor below.
//
// mime/encodedword — RFC 2047 encoded-word encoder/decoder.
//
// Reference: mime/encodedword.go
//
// Slim deviations:
//   * bEncode buffers the to-be-encoded substring then calls
//     base64.StdEncoding.EncodeToString instead of streaming via
//     base64.NewEncoder. Output is identical because Close flushes.
//   * WordDecoder.CharsetReader is a function-pointer field carrying
//     `&[byte]` (vs Go's io.Reader). Decode/DecodeHeader still cover
//     utf-8, iso-8859-1, us-ascii without it.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::convert::{int as toint, rune as torune};
use crate::encoding::base64;
use crate::errors::{self, error};
use crate::gostring::string;
use crate::strings;
use crate::types::byte;
use crate::unicode::utf8;

// ─── WordEncoder (encodedword.go:18) ─────────────────────────────────

// go: sdk 1.25.5 mime/encodedword.go:19-19 WordEncoder
/// `mime.WordEncoder` — RFC 2047 encoded-word encoder.
///
/// Go: `type WordEncoder byte`. The byte is the encoding flag ('b' or
/// 'q'). We wrap it in a tuple struct so methods hang off a real type.
#[derive(Copy, Clone)]
pub struct WordEncoder(pub byte);

// go: sdk 1.25.5 mime/encodedword.go:21-26 BEncoding
/// `mime.BEncoding` — base64 encoding (RFC 2045).
pub const BEncoding: WordEncoder = WordEncoder(b'b');

// go: sdk 1.25.5 mime/encodedword.go:21-26 QEncoding
/// `mime.QEncoding` — Q encoding (RFC 2047).
pub const QEncoding: WordEncoder = WordEncoder(b'q');

// go: sdk 1.25.5 mime/encodedword.go:28-30 errInvalidWord
crate::var! {
    errInvalidWord: error = "mime: invalid RFC 2047 encoded-word";
}

impl WordEncoder {
    // go: sdk 1.25.5 mime/encodedword.go:35-40 WordEncoder.Encode
    /// `(WordEncoder).Encode(charset, s)` (encodedword.go:35).
    pub fn Encode<C: Into<string>, S: Into<string>>(self, charset: C, s: S) -> string {
        let charset: string = charset.into();
        let s: string = s.into();
        // Go: if !needsEncoding(s) { return s }
        if !needsEncoding(&s) {
            return s;
        }
        return self.encodeWord(charset, s);
    }

    // go: sdk 1.25.5 mime/encodedword.go:52-68 WordEncoder.encodeWord
    /// `(WordEncoder).encodeWord` (encodedword.go:52).
    fn encodeWord(self, charset: string, s: string) -> string {
        let mut buf = strings::Builder::new();
        // Go: buf.Grow(48)
        buf.Grow(48);

        self.openWord(&mut buf, &charset);
        if self.0 == BEncoding.0 {
            self.bEncode(&mut buf, &charset, &s);
        } else {
            self.qEncode(&mut buf, &charset, &s);
        }
        closeWord(&mut buf);

        return buf.String();
    }

    // go: sdk 1.25.5 mime/encodedword.go:82-112 WordEncoder.bEncode
    /// `(WordEncoder).bEncode` (encodedword.go:82).
    fn bEncode(self, buf: &mut strings::Builder, charset: &string, s: &string) {
        let raw = s.as_bytes();
        // Go: if !isUTF8(charset) || base64.StdEncoding.EncodedLen(len(s)) <= maxContentLen {
        let encoded_len = base64::StdEncoding.EncodedLen(toint(raw.len())) as usize;
        if !isUTF8(charset) || encoded_len <= maxContentLen {
            // Go: io.WriteString(w, s); w.Close()
            let enc = base64::StdEncoding.EncodeToString(raw);
            let _ = buf.WriteString(enc);
            return;
        }

        // Go: var currentLen, last, runeLen int
        let mut current_len: usize = 0;
        let mut last: usize = 0;
        let mut i: usize = 0;
        while i < raw.len() {
            // Go: _, runeLen = utf8.DecodeRuneInString(s[i:])
            let tail = string::from_bytes(&raw[i..]);
            let (_, rune_len) = utf8::DecodeRuneInString(&tail);
            let rune_len = rune_len as usize;

            // Go: if currentLen+runeLen <= maxBase64Len { currentLen += runeLen }
            if current_len + rune_len <= maxBase64Len() {
                current_len += rune_len;
            } else {
                // Go: io.WriteString(w, s[last:i]); w.Close(); e.splitWord(buf, charset)
                let chunk = &raw[last..i];
                let enc = base64::StdEncoding.EncodeToString(chunk);
                let _ = buf.WriteString(enc);
                self.splitWord(buf, charset);
                last = i;
                current_len = rune_len;
            }
            i += rune_len;
        }
        // Go: io.WriteString(w, s[last:]); w.Close()
        let chunk = &raw[last..];
        let enc = base64::StdEncoding.EncodeToString(chunk);
        let _ = buf.WriteString(enc);
    }

    // go: sdk 1.25.5 mime/encodedword.go:114-142 WordEncoder.qEncode
    /// `(WordEncoder).qEncode` (encodedword.go:114).
    fn qEncode(self, buf: &mut strings::Builder, charset: &string, s: &string) {
        // Go: if !isUTF8(charset) { writeQString(buf, s); return }
        if !isUTF8(charset) {
            writeQString(buf, s.as_bytes());
            return;
        }

        let raw = s.as_bytes();
        let mut current_len: usize = 0;
        let mut i: usize = 0;
        while i < raw.len() {
            let b = raw[i];
            // Go: var encLen int
            let rune_len: usize;
            let enc_len: usize;
            // Go: if b >= ' ' && b <= '~' && b != '=' && b != '?' && b != '_' {
            if b >= b' ' && b <= b'~' && b != b'=' && b != b'?' && b != b'_' {
                rune_len = 1;
                enc_len = 1;
            } else {
                let tail = string::from_bytes(&raw[i..]);
                let (_, rl) = utf8::DecodeRuneInString(&tail);
                rune_len = rl as usize;
                enc_len = 3 * rune_len;
            }

            // Go: if currentLen+encLen > maxContentLen { e.splitWord(buf, charset); currentLen = 0 }
            if current_len + enc_len > maxContentLen {
                self.splitWord(buf, charset);
                current_len = 0;
            }
            // Go: writeQString(buf, s[i:i+runeLen])
            writeQString(buf, &raw[i..i + rune_len]);
            current_len += enc_len;
            i += rune_len;
        }
    }

    // go: sdk 1.25.5 mime/encodedword.go:160-167 WordEncoder.openWord
    /// `(WordEncoder).openWord` (encodedword.go:160).
    fn openWord(self, buf: &mut strings::Builder, charset: &string) {
        let _ = buf.WriteString(string::from_static("=?"));
        let _ = buf.WriteString(charset.clone());
        let _ = buf.WriteByte(b'?');
        let _ = buf.WriteByte(self.0);
        let _ = buf.WriteByte(b'?');
    }

    // go: sdk 1.25.5 mime/encodedword.go:174-178 WordEncoder.splitWord
    /// `(WordEncoder).splitWord` (encodedword.go:174).
    fn splitWord(self, buf: &mut strings::Builder, charset: &string) {
        closeWord(buf);
        let _ = buf.WriteByte(b' ');
        self.openWord(buf, charset);
    }
}

// go: sdk 1.25.5 mime/encodedword.go:169-172 closeWord
/// `closeWord(buf)` (encodedword.go:169).
fn closeWord(buf: &mut strings::Builder) {
    let _ = buf.WriteString(string::from_static("?="));
}

// go: sdk 1.25.5 mime/encodedword.go:42-49 needsEncoding
/// `needsEncoding(s)` (encodedword.go:42).
fn needsEncoding(s: &string) -> bool {
    // Go: for _, b := range s {
    //         if (b < ' ' || b > '~') && b != '\t' { return true } }
    let raw = s.as_bytes();
    let mut i = 0usize;
    while i < raw.len() {
        let tail = string::from_bytes(&raw[i..]);
        let (r, sz) = utf8::DecodeRuneInString(&tail);
        if (r < torune(b' ') || r > torune(b'~')) && r != torune(b'\t') {
            return true;
        }
        i += sz as usize;
    }
    return false;
}

// go: sdk 1.25.5 mime/encodedword.go:144-158 writeQString
/// `writeQString(buf, s)` (encodedword.go:144).
fn writeQString(buf: &mut strings::Builder, s: &[byte]) {
    // Go: for i := 0; i < len(s); i++ { switch b := s[i]; { ... } }
    let mut i = 0usize;
    while i < s.len() {
        let b = s[i];
        if b == b' ' {
            let _ = buf.WriteByte(b'_');
        } else if b >= b'!' && b <= b'~' && b != b'=' && b != b'?' && b != b'_' {
            let _ = buf.WriteByte(b);
        } else {
            let _ = buf.WriteByte(b'=');
            let _ = buf.WriteByte(upperhex[(b >> 4) as usize]);
            let _ = buf.WriteByte(upperhex[(b & 0x0F) as usize]);
        }
        i += 1;
    }
}

// go: sdk 1.25.5 mime/encodedword.go:180-182 isUTF8
/// `isUTF8(charset)` (encodedword.go:180).
fn isUTF8(charset: &string) -> bool {
    return strings::EqualFold(charset.clone(), string::from_static("UTF-8"));
}

// go: sdk 1.25.5 mime/encodedword.go:184-184 upperhex
const upperhex: &[byte] = b"0123456789ABCDEF";

// go: sdk 1.25.5 mime/encodedword.go:70-77 maxEncodedWordLen
// Go: const maxEncodedWordLen = 75
const maxEncodedWordLen: usize = 75;
// go: sdk 1.25.5 mime/encodedword.go:70-77 maxContentLen
// Go: maxContentLen = maxEncodedWordLen - len("=?UTF-8?q?") - len("?=")
//                  = 75 - 10 - 2 = 63
const maxContentLen: usize = maxEncodedWordLen - 10 - 2;

// go: sdk 1.25.5 mime/encodedword.go:79-79 maxBase64Len
/// Go: `var maxBase64Len = base64.StdEncoding.DecodedLen(maxContentLen)`.
fn maxBase64Len() -> usize {
    return base64::StdEncoding.DecodedLen(toint(maxContentLen)) as usize;
}

// ─── WordDecoder (encodedword.go:187) ────────────────────────────────

// go: sdk 1.25.5 mime/encodedword.go:187-196 WordDecoder
/// `mime.WordDecoder` — RFC 2047 encoded-word decoder.
///
/// Slim: CharsetReader receives the raw decoded bytes (a `slice<byte>`)
/// and returns the converted UTF-8 string + error, instead of an
/// `io.Reader` factory. Default encodings (utf-8, iso-8859-1, us-ascii)
/// are still handled internally without a CharsetReader.
#[derive(Clone, Copy)]
pub struct WordDecoder {
    pub CharsetReader:
        Option<fn(charset: string, input: crate::goslice::slice<byte>) -> (string, error)>,
}

impl WordDecoder {
    // go: none — goish idiom: Go writes the zero value as
    //     `&mime.WordDecoder{}` at each use site; Rust has no struct
    //     literal shorthand for a private-field-free zero value across
    //     crates, so the constructor is spelled once here.
    /// An empty decoder — Go's `&mime.WordDecoder{}`.
    pub const fn new() -> Self {
        return WordDecoder {
            CharsetReader: None,
        };
    }

    // go: sdk 1.25.5 mime/encodedword.go:198-226 WordDecoder.Decode
    /// `(*WordDecoder).Decode(word)` (encodedword.go:198).
    pub fn Decode<W: Into<string>>(&self, word: W) -> (string, error) {
        let word: string = word.into();
        // Go: if len(word) < 8 || !strings.HasPrefix(word, "=?") ||
        //         !strings.HasSuffix(word, "?=") || strings.Count(word, "?") != 4 {
        if word.Len() < 8
            || !strings::HasPrefix(word.clone(), string::from_static("=?"))
            || !strings::HasSuffix(word.clone(), string::from_static("?="))
            || strings::Count(word.clone(), string::from_static("?")) != 4
        {
            return (string::new(), errInvalidWord.into());
        }
        // Go: word = word[2 : len(word)-2]
        let raw = word.as_bytes();
        let inner: Vec<byte> = raw[2..raw.len() - 2].to_vec();
        let inner = string::from_bytes(&inner);

        // Go: charset, text, _ := strings.Cut(word, "?")
        let (charset, text, _) = strings::Cut(inner, string::from_static("?"));
        if charset.Len() == 0 {
            return (string::new(), errInvalidWord.into());
        }
        // Go: encoding, text, _ := strings.Cut(text, "?")
        let (encoding, text, _) = strings::Cut(text, string::from_static("?"));
        if encoding.Len() != 1 {
            return (string::new(), errInvalidWord.into());
        }

        // Go: content, err := decode(encoding[0], text)
        let enc_byte = encoding.as_bytes()[0];
        let (content, err) = decode(enc_byte, &text);
        if !err.IsNil() {
            return (string::new(), err);
        }

        let mut buf = strings::Builder::new();
        let e = self.convert(&mut buf, &charset, &content);
        if !e.IsNil() {
            return (string::new(), e);
        }
        return (buf.String(), errors::nil);
    }

    // go: sdk 1.25.5 mime/encodedword.go:230-302 WordDecoder.DecodeHeader
    /// `(*WordDecoder).DecodeHeader(header)` (encodedword.go:230).
    pub fn DecodeHeader<H: Into<string>>(&self, header: H) -> (string, error) {
        let header: string = header.into();
        // Go: i := strings.Index(header, "=?"); if i == -1 { return header, nil }
        let i0 = strings::Index(header.clone(), string::from_static("=?"));
        if i0 == -1 {
            return (header, errors::nil);
        }

        let mut buf = strings::Builder::new();
        let raw = header.as_bytes();
        // Go: buf.WriteString(header[:i]); header = header[i:]
        let _ = buf.WriteString(string::from_bytes(&raw[..i0 as usize]));
        let mut head: Vec<byte> = raw[i0 as usize..].to_vec();

        let mut between_words = false;
        loop {
            let head_str = string::from_bytes(&head);
            // Go: start := strings.Index(header, "=?"); if start == -1 { break }
            let start = strings::Index(head_str.clone(), string::from_static("=?"));
            if start == -1 {
                break;
            }
            let start = start as usize;
            // Go: cur := start + len("=?")
            let mut cur = start + 2;

            // Go: i := strings.Index(header[cur:], "?"); if i == -1 { break }
            let tail_str = string::from_bytes(&head[cur..]);
            let i_q = strings::Index(tail_str, string::from_static("?"));
            if i_q == -1 {
                break;
            }
            let i_q = i_q as usize;
            // Go: charset := header[cur : cur+i]
            let charset_bytes: Vec<byte> = head[cur..cur + i_q].to_vec();
            cur += i_q + 1;

            // Go: if len(header) < cur+len("Q??=") { break }
            if head.len() < cur + 4 {
                break;
            }
            // Go: encoding := header[cur]; cur++
            let encoding_byte = head[cur];
            cur += 1;

            // Go: if header[cur] != '?' { break }
            if head[cur] != b'?' {
                break;
            }
            cur += 1;

            // Go: j := strings.Index(header[cur:], "?="); if j == -1 { break }
            let tail_str = string::from_bytes(&head[cur..]);
            let j = strings::Index(tail_str, string::from_static("?="));
            if j == -1 {
                break;
            }
            let j = j as usize;
            // Go: text := header[cur : cur+j]
            let text_bytes: Vec<byte> = head[cur..cur + j].to_vec();
            let text_str = string::from_bytes(&text_bytes);
            // Go: end := cur + j + len("?=")
            let end = cur + j + 2;

            // Go: content, err := decode(encoding, text)
            let (content, err) = decode(encoding_byte, &text_str);
            if !err.IsNil() {
                between_words = false;
                // Go: buf.WriteString(header[:start+2]); header = header[start+2:]
                let prefix = string::from_bytes(&head[..start + 2]);
                let _ = buf.WriteString(prefix);
                head = head[start + 2..].to_vec();
                continue;
            }

            // Go: if start > 0 && (!betweenWords || hasNonWhitespace(header[:start])) {
            //         buf.WriteString(header[:start]) }
            if start > 0 {
                let pre_bytes = &head[..start];
                let pre_str = string::from_bytes(pre_bytes);
                if !between_words || hasNonWhitespace(&pre_str) {
                    let _ = buf.WriteString(pre_str);
                }
            }

            let charset_str = string::from_bytes(&charset_bytes);
            let e = self.convert(&mut buf, &charset_str, &content);
            if !e.IsNil() {
                return (string::new(), e);
            }

            // Go: header = header[end:]
            head = head[end..].to_vec();
            between_words = true;
        }

        // Go: if len(header) > 0 { buf.WriteString(header) }
        if !head.is_empty() {
            let _ = buf.WriteString(string::from_bytes(&head));
        }

        return (buf.String(), errors::nil);
    }

    // go: sdk 1.25.5 mime/encodedword.go:315-346 WordDecoder.convert
    /// `(*WordDecoder).convert(buf, charset, content)` (encodedword.go:315).
    fn convert(&self, buf: &mut strings::Builder, charset: &string, content: &[byte]) -> error {
        return if strings::EqualFold(string::from_static("utf-8"), charset.clone()) {
            // Go: buf.Write(content)
            for &b in content {
                let _ = buf.WriteByte(b);
            }
            errors::nil
        } else if strings::EqualFold(string::from_static("iso-8859-1"), charset.clone()) {
            // Go: for _, c := range content { buf.WriteRune(rune(c)) }
            for &c in content {
                let _ = buf.WriteRune(torune(c));
            }
            errors::nil
        } else if strings::EqualFold(string::from_static("us-ascii"), charset.clone()) {
            // Go: for _, c := range content {
            //         if c >= utf8.RuneSelf { buf.WriteRune(unicode.ReplacementChar) }
            //         else { buf.WriteByte(c) } }
            for &c in content {
                if c >= utf8::RuneSelf {
                    let _ = buf.WriteRune(utf8::RuneError);
                } else {
                    let _ = buf.WriteByte(c);
                }
            }
            errors::nil
        } else {
            // Go: if d.CharsetReader == nil { return fmt.Errorf("mime: unhandled charset %q", charset) }
            match self.CharsetReader {
                None => {
                    let mut msg: Vec<byte> = Vec::with_capacity(40 + charset.Len() as usize);
                    msg.extend_from_slice(b"mime: unhandled charset \"");
                    msg.extend_from_slice(charset.as_bytes());
                    msg.push(b'"');
                    errors::New(string::from_bytes(&msg))
                }
                Some(f) => {
                    let lower = strings::ToLower(charset.clone());
                    let input = crate::goslice::slice::__from_vec(content.to_vec());
                    let (out, err) = f(lower, input);
                    if !err.IsNil() {
                        return err;
                    }
                    let _ = buf.WriteString(out);
                    errors::nil
                }
            }
        };
    }
}

// go: sdk 1.25.5 mime/encodedword.go:304-313 decode
/// `decode(encoding, text)` (encodedword.go:304).
fn decode(encoding: byte, text: &string) -> (Vec<byte>, error) {
    return match encoding {
        b'B' | b'b' => {
            // Go: return base64.StdEncoding.DecodeString(text)
            let raw = text.as_bytes();
            let s = core::str::from_utf8(raw).unwrap_or("");
            let (slc, err) = base64::StdEncoding.DecodeString(s);
            (slc.__into_vec(), err)
        }
        b'Q' | b'q' => qDecode(text),
        _ => (Vec::new(), errInvalidWord.into()),
    };
}

// go: sdk 1.25.5 mime/encodedword.go:348-360 hasNonWhitespace
/// `hasNonWhitespace(s)` (encodedword.go:348).
fn hasNonWhitespace(s: &string) -> bool {
    // Go: for _, b := range s {
    //         switch b { case ' ', '\t', '\n', '\r': default: return true } }
    let raw = s.as_bytes();
    let mut i = 0usize;
    while i < raw.len() {
        let tail = string::from_bytes(&raw[i..]);
        let (r, sz) = utf8::DecodeRuneInString(&tail);
        match r {
            r if r == torune(b' ')
                || r == torune(b'\t')
                || r == torune(b'\n')
                || r == torune(b'\r') => {}
            _ => return true,
        }
        i += sz as usize;
    }
    return false;
}

// go: sdk 1.25.5 mime/encodedword.go:362-389 qDecode
/// `qDecode(s)` (encodedword.go:362).
fn qDecode(s: &string) -> (Vec<byte>, error) {
    let raw = s.as_bytes();
    // Go: dec := make([]byte, len(s))
    let mut dec: Vec<byte> = alloc::vec![0u8; raw.len()];
    let mut n: usize = 0;
    let mut i: usize = 0;
    while i < raw.len() {
        let c = raw[i];
        if c == b'_' {
            dec[n] = b' ';
        } else if c == b'=' {
            // Go: if i+2 >= len(s) { return nil, errInvalidWord }
            if i + 2 >= raw.len() {
                return (Vec::new(), errInvalidWord.into());
            }
            let (b, err) = readHexByte(raw[i + 1], raw[i + 2]);
            if !err.IsNil() {
                return (Vec::new(), err);
            }
            dec[n] = b;
            i += 2;
        } else if (c <= b'~' && c >= b' ') || c == b'\n' || c == b'\r' || c == b'\t' {
            dec[n] = c;
        } else {
            return (Vec::new(), errInvalidWord.into());
        }
        n += 1;
        i += 1;
    }
    dec.truncate(n);
    return (dec, errors::nil);
}

// go: sdk 1.25.5 mime/encodedword.go:391-401 readHexByte
/// `readHexByte(a, b)` (encodedword.go:391).
fn readHexByte(a: byte, b: byte) -> (byte, error) {
    let (hb, err1) = fromHex(a);
    if !err1.IsNil() {
        return (0, err1);
    }
    let (lb, err2) = fromHex(b);
    if !err2.IsNil() {
        return (0, err2);
    }
    return (hb << 4 | lb, errors::nil);
}

// go: sdk 1.25.5 mime/encodedword.go:403-414 fromHex
/// `fromHex(b)` (encodedword.go:403).
fn fromHex(b: byte) -> (byte, error) {
    if b >= b'0' && b <= b'9' {
        return (b - b'0', errors::nil);
    }
    if b >= b'A' && b <= b'F' {
        return (b - b'A' + 10, errors::nil);
    }
    if b >= b'a' && b <= b'f' {
        return (b - b'a' + 10, errors::nil);
    }
    // Go: fmt.Errorf("mime: invalid hex byte %#02x", b) — LOWER-case
    // hex. This had been hand-rolled against an upper-case table, so
    // the message read "0x5A" where Go's reads "0x5a".
    return (0, crate::fmt::Errorf!("mime: invalid hex byte 0x%02x", b));
}
