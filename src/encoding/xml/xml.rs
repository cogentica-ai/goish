// goishlint:ignore GOISH018 EscapeString, InputOffset, InputPos, NewDecoder, NewTokenDecoder, RawToken, Token, attrval, autoClose, emitCDATA, getc, isName, isNameString, mustgetc, name, nsname, pop, popEOF, popElement, push, pushEOF, pushElement, pushNs, rawToken, readName, savedOffset, space, switchToReader, syntaxError, text, translate, ungetc — the Decoder state machine and the two name predicates, deliberately not in this first slice. The Decoder ones cannot be pinned a function at a time (they share a bufio reader, a name-space stack and an error latch), so they land together with their own ref smoke; isName/isNameString need Go's `first` and `second` unicode.RangeTables, 310 lines of xml.go that should be GENERATED from Go rather than transcribed, which is its own commit. emitCDATA and EscapeString are printer-side and belong with marshal.go. See the file header and ROADMAP §2.
// goishlint:ignore GOISH021 stkEOF, stkNs, stkStart, xmlPrefix, xmlURL, xmlnsPrefix, entity, errRawToken, HTMLEntity, HTMLAutoClose, first, second, Decoder, TokenReader, stack — the Decoder's own stack kinds, its name-space constants and its types; all of them exist only for the state machine waived above and would be dead declarations without it. `entity`, `HTMLEntity` and `HTMLAutoClose` are the decoder's entity tables and only `rawToken` reads them; `errRawToken` is the sentinel `Token()` returns when a TokenReader is in use; `first` and `second` are the 310-line name RangeTables that land with isName.
// go: file encoding/xml/xml.go decls: SyntaxError.Error, StartElement.Copy, StartElement.End, CharData.Copy, Comment.Copy, ProcInst.Copy, Directive.Copy, CopyToken, isInCharacterRange, isNameByte, EscapeText, escapeText, Escape, procInst
//
// encoding/xml/xml.rs — the pure half of Go's xml.go.
//
// PARTIAL, deliberately, and the split is by TESTABILITY. Go's xml.go
// is 2,076 lines, most of it the `Decoder` state machine: a
// bufio-backed reader, a name-space stack, and `rawToken`'s 300-line
// switch. None of that can be pinned one function at a time. What IS
// here is everything in the file that is a pure function of its
// arguments, so each row of `xml_ref_smoke` is a direct comparison
// against Go with no decoder to stand up.
//
// Here:   the token types and their Copy/End, SyntaxError.Error,
//         isInCharacterRange, isNameByte, EscapeText/escapeText/Escape,
//         procInst.
//
// NOT here, and why:
//   * Decoder and everything reachable from it — the state machine.
//   * isName / isNameString — they need Go's `first` and `second`
//     unicode.RangeTables (310 lines of xml.go). Those should be
//     GENERATED from Go rather than transcribed, which is its own
//     commit.
//   * emitCDATA, EscapeString — printer-side, and printer is marshal.go.
//   * HTMLEntity / HTMLAutoClose — tables, and only the Decoder reads
//     them.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int, rune};

// ─── SyntaxError ──────────────────────────────────────────────────────

// go: sdk 1.25.5 encoding/xml/xml.go:26-29 SyntaxError
/// Go: "A SyntaxError represents a syntax error in the XML input
/// stream."
#[derive(Clone, Default, PartialEq)]
pub struct SyntaxError {
    pub Msg: string,
    pub Line: int,
}

impl SyntaxError {
    // go: sdk 1.25.5 encoding/xml/xml.go:31-33 SyntaxError.Error
    /// Go: `"XML syntax error on line " + strconv.Itoa(e.Line) + ": " + e.Msg`
    pub fn Error(&self) -> string {
        return string::from_static("XML syntax error on line ")
            + crate::strconv::Itoa(self.Line)
            + string::from_static(": ")
            + self.Msg.clone();
    }
}

// ─── Name, Attr ───────────────────────────────────────────────────────

// go: sdk 1.25.5 encoding/xml/xml.go:40-42 Name
/// Go: "A Name represents an XML name (Local) annotated with a name
/// space identifier (Space)."
#[derive(Clone, Default, PartialEq)]
pub struct Name {
    pub Space: string,
    pub Local: string,
}

// go: sdk 1.25.5 encoding/xml/xml.go:45-48 Attr
/// Go: "An Attr represents an attribute in an XML element (Name=Value)."
#[derive(Clone, Default, PartialEq)]
pub struct Attr {
    pub Name: Name,
    pub Value: string,
}

// ─── the token types ──────────────────────────────────────────────────
//
// Go's `Token` is `any`, and the six concrete types are what it may
// hold. goish spells that as an enum: the set is closed in Go too (the
// doc lists exactly six), and a closed enum is what lets `CopyToken`
// below be total instead of falling through to `return t`.

// go: sdk 1.25.5 encoding/xml/xml.go:55-58 StartElement
/// Go: "A StartElement represents an XML start element."
#[derive(Clone, Default, PartialEq)]
pub struct StartElement {
    pub Name: Name,
    pub Attr: slice<Attr>,
}

impl StartElement {
    // go: sdk 1.25.5 encoding/xml/xml.go:61-66 StartElement.Copy
    /// Go: "Copy creates a new copy of StartElement." Go copies the
    /// Attr slice into a fresh backing array, because its slices alias;
    /// goish's `slice<T>` already owns its elements and `Clone` is
    /// deep, so this is the identity. Kept because it is Go's API, and
    /// because ROADMAP §2v1 may make slices alias — at which point
    /// this has to do the copy for real.
    pub fn Copy(&self) -> StartElement {
        return self.clone();
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:69-71 StartElement.End
    /// Go: "End returns the corresponding XML end element."
    pub fn End(&self) -> EndElement {
        return EndElement {
            Name: self.Name.clone(),
        };
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:74-76 EndElement
/// Go: "An EndElement represents an XML end element."
#[derive(Clone, Default, PartialEq)]
pub struct EndElement {
    pub Name: Name,
}

// go: sdk 1.25.5 encoding/xml/xml.go:81-81 CharData
/// Go: "A CharData represents XML character data (raw text), in which
/// XML escape sequences have been replaced by the characters they
/// represent."
#[derive(Clone, Default, PartialEq)]
pub struct CharData(pub slice<byte>);

impl CharData {
    // go: sdk 1.25.5 encoding/xml/xml.go:84-84 CharData.Copy
    /// Go: `CharData(bytes.Clone(c))`.
    pub fn Copy(&self) -> CharData {
        return CharData(self.0.clone());
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:88-88 Comment
/// Go: "A Comment represents an XML comment of the form
/// `<!--comment-->`. The bytes do not include the `<!--` and `-->`
/// comment markers."
#[derive(Clone, Default, PartialEq)]
pub struct Comment(pub slice<byte>);

impl Comment {
    // go: sdk 1.25.5 encoding/xml/xml.go:91-91 Comment.Copy
    /// Go: `Comment(bytes.Clone(c))`.
    pub fn Copy(&self) -> Comment {
        return Comment(self.0.clone());
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:94-97 ProcInst
/// Go: "A ProcInst represents an XML processing instruction of the form
/// `<?target inst?>`".
#[derive(Clone, Default, PartialEq)]
pub struct ProcInst {
    pub Target: string,
    pub Inst: slice<byte>,
}

impl ProcInst {
    // go: sdk 1.25.5 encoding/xml/xml.go:100-103 ProcInst.Copy
    /// Go: `p.Inst = bytes.Clone(p.Inst); return p`.
    pub fn Copy(&self) -> ProcInst {
        return self.clone();
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:107-107 Directive
/// Go: "A Directive represents an XML directive of the form `<!text>`.
/// The bytes do not include the `<!` and `>` markers."
#[derive(Clone, Default, PartialEq)]
pub struct Directive(pub slice<byte>);

impl Directive {
    // go: sdk 1.25.5 encoding/xml/xml.go:110-110 Directive.Copy
    /// Go: `Directive(bytes.Clone(d))`.
    pub fn Copy(&self) -> Directive {
        return Directive(self.0.clone());
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:52-52 Token
/// Go: "A Token is an interface holding one of the token types:
/// StartElement, EndElement, CharData, Comment, ProcInst, or
/// Directive."
#[derive(Clone, PartialEq)]
pub enum Token {
    StartElement(StartElement),
    EndElement(EndElement),
    CharData(CharData),
    Comment(Comment),
    ProcInst(ProcInst),
    Directive(Directive),
}

// go: sdk 1.25.5 encoding/xml/xml.go:113-127 CopyToken
/// Go: "CopyToken returns a copy of a Token."
///
/// Go's switch has no EndElement arm — an EndElement holds only a Name,
/// which is two strings, so `return t` already copies it. The enum
/// makes that arm explicit rather than a fallthrough, which is the
/// same answer with the six cases visible.
pub fn CopyToken(t: &Token) -> Token {
    return match t {
        Token::StartElement(v) => Token::StartElement(v.Copy()),
        Token::EndElement(v) => Token::EndElement(v.clone()),
        Token::CharData(v) => Token::CharData(v.Copy()),
        Token::Comment(v) => Token::Comment(v.Copy()),
        Token::ProcInst(v) => Token::ProcInst(v.Copy()),
        Token::Directive(v) => Token::Directive(v.Copy()),
    };
}

// ─── character predicates ─────────────────────────────────────────────

// go: sdk 1.25.5 encoding/xml/xml.go:1157-1165 isInCharacterRange
/// Go: the XML 1.0 §2.2 `Char` production — "any Unicode character,
/// excluding the surrogate blocks, FFFE, and FFFF".
///
/// Note what is EXCLUDED and is easy to get wrong: 0x0B and 0x0C are
/// not legal, so a vertical tab or form feed is not XML text; the
/// surrogate range D800-DFFF is not; and FFFE/FFFF are not, while FFFD
/// is.
pub fn isInCharacterRange(r: rune) -> bool {
    return r == 0x09
        || r == 0x0A
        || r == 0x0D
        || (r >= 0x20 && r <= 0xD7FF)
        || (r >= 0xE000 && r <= 0xFFFD)
        || (r >= 0x10000 && r <= 0x10FFFF);
}

// go: sdk 1.25.5 encoding/xml/xml.go:1229-1234 isNameByte
/// Go: the single-byte characters that may appear in an XML name.
/// Deliberately looser than the spec — Go's comment on `readName` says
/// "All multi-byte characters are accepted; the caller must check their
/// validity", and `isName` is that check.
pub fn isNameByte(c: byte) -> bool {
    return (c >= b'A' && c <= b'Z')
        || (c >= b'a' && c <= b'z')
        || (c >= b'0' && c <= b'9')
        || c == b'_'
        || c == b':'
        || c == b'.'
        || c == b'-';
}

// ─── escaping ─────────────────────────────────────────────────────────

// go: none — goish idiom: Go declares these as a `var (...)` block of
// []byte; goish spells them as byte literals. The choices are Go's and
// two are not the obvious ones: `"` becomes `&#34;` and `'` becomes
// `&#39;` because, as Go's own comment says, they are SHORTER than
// `&quot;` and `&apos;`.
const ESC_QUOT: &[u8] = b"&#34;";
const ESC_APOS: &[u8] = b"&#39;";
const ESC_AMP: &[u8] = b"&amp;";
const ESC_LT: &[u8] = b"&lt;";
const ESC_GT: &[u8] = b"&gt;";
const ESC_TAB: &[u8] = b"&#x9;";
const ESC_NL: &[u8] = b"&#xA;";
const ESC_CR: &[u8] = b"&#xD;";
/// U+FFFD REPLACEMENT CHARACTER, in UTF-8.
const ESC_FFFD: &[u8] = b"\xef\xbf\xbd";

// go: sdk 1.25.5 encoding/xml/xml.go:1910-1912 EscapeText
/// Go: "EscapeText writes to w the properly escaped XML equivalent of
/// the plain text data s."
pub fn EscapeText<W: crate::io::Writer + ?Sized>(w: &mut W, s: &[byte]) -> crate::error {
    return escapeText(w, s, true);
}

// go: sdk 1.25.5 encoding/xml/xml.go:1917-1962 escapeText
/// Go: "escapeText writes to w the properly escaped XML equivalent of
/// the plain text data s. If escapeNewline is true, newline characters
/// will be escaped."
///
/// The `escapeNewline` false case is the printer's: a newline inside
/// character data is legal and does not need escaping, and Go leaves it
/// alone there to keep generated XML readable.
///
/// The last branch is the one to read twice. Anything outside the
/// XML 1.0 character range becomes U+FFFD — and so does a literal
/// U+FFFD that arrived as ONE byte, which is how Go spells "this was
/// invalid UTF-8": `utf8.DecodeRune` returns (RuneError, 1) for a bad
/// byte, and (RuneError, 3) for a genuine encoded U+FFFD. Without the
/// width test an invalid byte would pass through as a valid rune.
pub fn escapeText<W: crate::io::Writer + ?Sized>(
    w: &mut W,
    s: &[byte],
    escapeNewline: bool,
) -> crate::error {
    let mut last: usize = 0;
    let mut i: usize = 0;
    while i < s.len() {
        let (r, w_) = crate::unicode::utf8::DecodeRune(&s[i..]);
        let width = w_ as usize;
        i += width;
        let esc: &[u8] = match r {
            0x22 => ESC_QUOT,
            0x27 => ESC_APOS,
            0x26 => ESC_AMP,
            0x3C => ESC_LT,
            0x3E => ESC_GT,
            0x09 => ESC_TAB,
            0x0A => {
                if !escapeNewline {
                    continue;
                }
                ESC_NL
            }
            0x0D => ESC_CR,
            _ => {
                if !isInCharacterRange(r) || (r == 0xFFFD && width == 1) {
                    ESC_FFFD
                } else {
                    continue;
                }
            }
        };
        let (_, err) = w.Write(slice::<byte>::__from_vec(s[last..i - width].to_vec()));
        if !err.IsNil() {
            return err;
        }
        let (_, err) = w.Write(slice::<byte>::__from_vec(esc.to_vec()));
        if !err.IsNil() {
            return err;
        }
        last = i;
    }
    let (_, err) = w.Write(slice::<byte>::__from_vec(s[last..].to_vec()));
    return err;
}

// go: sdk 1.25.5 encoding/xml/xml.go:2004-2006 Escape
/// Go: "Escape is like EscapeText but omits the error return value. It
/// is provided for backwards compatibility with Go 1.0. Code targeting
/// Go 1.1 or later should use EscapeText."
pub fn Escape<W: crate::io::Writer + ?Sized>(w: &mut W, s: &[byte]) {
    let _ = EscapeText(w, s);
}

// ─── procInst ─────────────────────────────────────────────────────────

// go: sdk 1.25.5 encoding/xml/xml.go:2049-2076 procInst
/// Go: "procInst parses the `param="..."` or `param='...'` value out of
/// the provided string, returning "" if not found."
///
/// Go's implementation is deliberately not a parser: it looks for the
/// parameter name followed by `=`, then takes the quoted run. A
/// parameter that appears as a SUFFIX of another would match, which is
/// why Go checks the preceding byte is a space.
pub fn procInst(param: &str, s: &str) -> string {
    // Go: if param == "encoding" { param = " encoding=" } else ...
    //     — Go builds `param + "="` and searches, requiring the match
    //     to be at the start or preceded by a space.
    // `alloc::format!` would pull in core::fmt's panic path and with it
    // `_Unwind_Resume`, which this no_std build does not link. Build the
    // needle by hand.
    let mut needle: Vec<byte> = Vec::with_capacity(param.len() + 1);
    needle.extend_from_slice(param.as_bytes());
    needle.push(b'=');
    let sb = s.as_bytes();
    let nb: &[byte] = &needle;
    let mut idx: Option<usize> = None;
    let mut j: usize = 0;
    while j + nb.len() <= sb.len() {
        if &sb[j..j + nb.len()] == nb && (j == 0 || sb[j - 1] == b' ') {
            idx = Some(j + nb.len());
            break;
        }
        j += 1;
    }
    let start = match idx {
        None => return string::from_static(""),
        Some(v) => v,
    };
    if start >= sb.len() {
        return string::from_static("");
    }
    let quote = sb[start];
    if quote != b'"' && quote != b'\'' {
        return string::from_static("");
    }
    let rest = &sb[start + 1..];
    let mut k: usize = 0;
    while k < rest.len() {
        if rest[k] == quote {
            return string::from_bytes(&rest[..k]);
        }
        k += 1;
    }
    return string::from_static("");
}
