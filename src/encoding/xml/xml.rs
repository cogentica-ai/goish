// goishlint:ignore GOISH018 EscapeString, NewTokenDecoder, RawToken, Token, attrval, autoClose, emitCDATA, name, nsname, rawToken, switchToReader,  — the Decoder state machine and the two name predicates, deliberately not in this first slice. The Decoder ones cannot be pinned a function at a time (they share a bufio reader, a name-space stack and an error latch), so they land together with their own ref smoke; isName/isNameString need Go's `first` and `second` unicode.RangeTables, 310 lines of xml.go that should be GENERATED from Go rather than transcribed, which is its own commit. emitCDATA and EscapeString are printer-side and belong with marshal.go. See the file header and ROADMAP §2.
// goishlint:ignore GOISH021 entity, errRawToken, HTMLEntity, HTMLAutoClose, TokenReader — the Decoder's own stack kinds, its name-space constants and its types; all of them exist only for the state machine waived above and would be dead declarations without it. `entity`, `HTMLEntity` and `HTMLAutoClose` are the decoder's entity tables and only `rawToken` reads them; `errRawToken` is the sentinel `Token()` returns when a TokenReader is in use.
// go: file encoding/xml/xml.go decls: SyntaxError.Error, StartElement.Copy, StartElement.End, CharData.Copy, Comment.Copy, ProcInst.Copy, Directive.Copy, CopyToken, isInCharacterRange, isNameByte, isName, isNameString, EscapeText, escapeText, Escape, procInst, Decoder.text, Decoder.readName, Decoder.push, Decoder.pop, Decoder.pushEOF, Decoder.popEOF, Decoder.pushElement, Decoder.pushNs, Decoder.popElement, Decoder.translate, Decoder.getc, Decoder.InputOffset, Decoder.InputPos, Decoder.savedOffset, Decoder.mustgetc, Decoder.ungetc, Decoder.space, Decoder.syntaxError, NewDecoder
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
use crate::unicode::{Range16, RangeTable};
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

// go: none — goish idiom: Go's *SyntaxError satisfies `error` by
// having an Error() method; goish needs the trait impl spelled out so
// `errors::Wrap` can carry it.
impl crate::errors::ErrorTrait for SyntaxError {
    // go: none — goish idiom: see the note above this impl.
    fn Error(&self) -> string {
        return SyntaxError::Error(self);
    }
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

// ─── Decoder: the byte layer ──────────────────────────────────────────
//
// The state machine lands in pieces, bottom-up, because that is the
// only way any of it is testable before `rawToken` exists. This is the
// bottom: the reader, the one-byte pushback, and the offset/line/column
// bookkeeping every error message and `InputPos` call depends on.
//
// Not here yet: the name-space and element stacks, `text`, `rawToken`,
// `Token` and everything reachable from them. They arrive together —
// see the GOISH018 waiver at the top of this file.

// goishlint:ignore GOISH019 Decoder — a PARTIAL port: this slice is the byte layer, so only the fields its methods touch are declared (r, saved, nextByte, err, line, linestart, offset) plus the exported knobs. AutoClose, Entity, CharsetReader, t, buf, stk, free, needClose, toClose, nextToken, ns and unmarshalDepth arrive with rawToken and the stacks — the same commit the GOISH018 waiver above describes. Declaring them now would be twelve dead fields.
// go: sdk 1.25.5 encoding/xml/xml.go:148-216 Decoder
/// Go: "A Decoder represents an XML parser reading a particular input
/// stream."
///
/// PARTIAL: the fields below are the ones this slice's methods touch,
/// plus the exported knobs, which are part of the API whether or not
/// anything reads them yet. `stk`/`free`/`ns`/`t`/`nextToken` and the
/// rest arrive with `rawToken`.
pub struct Decoder {
    /// Go: "Strict defaults to true, enforcing the requirements of the
    /// XML specification."
    pub Strict: bool,
    /// Go: "DefaultSpace sets the default name space used for
    /// unadorned tags, as if the entire XML stream were wrapped in an
    /// element containing the attribute xmlns='...'."
    pub DefaultSpace: string,

    /// Go: "Entity can be used to map non-standard entity names to
    /// string replacements. The parser behaves as if these standard
    /// mappings are present in the map, regardless of the actual map
    /// content: lt, gt, amp, apos, quot."
    pub Entity: Option<crate::gomap::map<string, string>>,

    r: alloc::boxed::Box<dyn crate::io::ByteReader>,
    /// Go: "AutoClose ... tells the parser to invent an end element
    /// for each of the named start elements."
    pub AutoClose: slice<string>,

    /// Go's `buf bytes.Buffer` — the scratch every token body is built
    /// in. Reused, so `text` and `readName` both start with a Reset.
    buf: crate::bytes::Buffer,
    /// Go's `stk *stack` linked list, bottom-first: the LAST element is
    /// Go's `d.stk`, the top. Go keeps a `free` list beside it to reuse
    /// nodes; a Vec does that job by construction, so `free` has no
    /// counterpart and is waived.
    stk: Vec<stack>,
    /// Go's `ns map[string]string` — prefix to URL, for the prefixes
    /// currently in scope.
    ns: crate::gomap::map<string, string>,
    needClose: bool,
    toClose: Name,
    /// Go's `saved *bytes.Buffer` — non-nil only while `rawToken` is
    /// recording raw input for a directive.
    saved: Option<crate::bytes::Buffer>,
    /// Go's `nextByte int`, -1 when empty. A one-byte pushback, not a
    /// buffer: `ungetc` overwrites whatever is there, which is safe
    /// only because every caller ungets at most one byte before the
    /// next `getc`.
    nextByte: int,
    err: crate::error,
    line: int,
    linestart: i64,
    offset: i64,
}

// go: sdk 1.25.5 encoding/xml/xml.go:221-231 NewDecoder
/// Go: "NewDecoder creates a new XML parser reading from r. If r does
/// not implement io.ByteReader, NewDecoder will do its own buffering."
///
/// goish always buffers: `io::ByteReader` is a separate trait here and
/// a generic `R: io::Reader` cannot be tested for it at runtime the way
/// Go's interface assertion can. Buffering a reader that was already
/// buffered costs one extra copy and changes no behaviour.
pub fn NewDecoder<R: crate::io::Reader + 'static>(r: R) -> Decoder {
    return Decoder {
        Strict: true,
        DefaultSpace: string::from_static(""),
        Entity: None,
        r: alloc::boxed::Box::new(crate::bufio::NewReader(r)),
        AutoClose: slice::<string>::new(),
        buf: crate::bytes::Buffer::new(),
        stk: Vec::new(),
        ns: crate::gomap::map::<string, string>::new(),
        needClose: false,
        toClose: Name::default(),
        saved: None,
        nextByte: -1,
        err: crate::errors::nil,
        line: 1,
        linestart: 0,
        offset: 0,
    };
}

impl Decoder {
    // go: sdk 1.25.5 encoding/xml/xml.go:907-929 Decoder.getc
    /// Read one byte, through the pushback slot if it is full.
    ///
    /// The line bookkeeping is the part worth reading: `line` counts
    /// newlines SEEN, and `linestart` is the offset just past the last
    /// one, so `InputPos`'s column is `offset - linestart + 1`.
    pub(crate) fn getc(&mut self) -> (byte, bool) {
        if !self.err.IsNil() {
            return (0, false);
        }
        let b: byte;
        if self.nextByte >= 0 {
            b = crate::byte(self.nextByte);
            self.nextByte = -1;
        } else {
            let (rb, e) = self.r.ReadByte();
            if !e.IsNil() {
                self.err = e;
                return (0, false);
            }
            b = rb;
            if let Some(sv) = self.saved.as_mut() {
                let _ = crate::io::Writer::Write(sv, slice::<byte>::__from_vec(alloc::vec![b]));
            }
        }
        if b == b'\n' {
            self.line += 1;
            self.linestart = self.offset + 1;
        }
        self.offset += 1;
        return (b, true);
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:934-936 Decoder.InputOffset
    /// Go: "InputOffset returns the input stream byte offset of the
    /// current decoder position."
    pub fn InputOffset(&self) -> i64 {
        return self.offset;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:941-943 Decoder.InputPos
    /// Go: "InputPos returns the line of the current decoder position
    /// and the 1 based input position of the line."
    ///
    /// It can return column 0, which is not a position any input has.
    /// `ungetc` decrements `offset` and `line` but does NOT restore
    /// `linestart`, so immediately after ungetting a newline the
    /// arithmetic gives `offset - linestart + 1` = 0. That is Go's
    /// behaviour, pinned in xml_decoder_bytes_ref_smoke rather than
    /// smoothed over — a port that "fixed" it would diverge.
    pub fn InputPos(&self) -> (int, int) {
        return (
            self.line,
            crate::int(crate::int64(self.offset - self.linestart)) + 1,
        );
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:947-953 Decoder.savedOffset
    /// Go: "Return saved offset. If we did ungetc (nextByte >= 0), have
    /// to back up one."
    pub(crate) fn savedOffset(&self) -> int {
        let mut n = match self.saved.as_ref() {
            Some(sv) => sv.Len(),
            None => 0,
        };
        if self.nextByte >= 0 {
            n -= 1;
        }
        return n;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:959-966 Decoder.mustgetc
    /// Go: "Must read a single byte. If there is no byte to read, set
    /// d.err to SyntaxError("unexpected EOF") and return ok==false."
    pub(crate) fn mustgetc(&mut self) -> (byte, bool) {
        let (b, ok) = self.getc();
        if !ok && crate::errors::Is(self.err.clone(), crate::io::EOF) {
            self.err = self.syntaxError("unexpected EOF");
        }
        return (b, ok);
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:969-975 Decoder.ungetc
    /// Go: "Unread a single byte."
    ///
    /// Note what it does NOT undo: `linestart`. See `InputPos`.
    pub(crate) fn ungetc(&mut self, b: byte) {
        if b == b'\n' {
            self.line -= 1;
        }
        self.nextByte = crate::int(crate::int64(b));
        self.offset -= 1;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:888-905 Decoder.space
    /// Skip spaces if any. Go's loop reads bytes until a non-space, and
    /// ungets the one it stopped on — so after `space()` the next
    /// `getc` returns that byte.
    pub(crate) fn space(&mut self) {
        loop {
            let (b, ok) = self.getc();
            if !ok {
                return;
            }
            match b {
                b' ' | b'\r' | b'\n' | b'\t' => {}
                _ => {
                    self.ungetc(b);
                    return;
                }
            }
        }
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:1205-1227 Decoder.readName
    /// Go: "Read a name and append its bytes to d.buf. The name is
    /// delimited by any single-byte character not valid in names. All
    /// multi-byte characters are accepted; the caller must check their
    /// validity."
    ///
    /// That last sentence is the contract `isName` exists to satisfy —
    /// this stops only at ASCII bytes it knows are not name bytes, so
    /// any non-ASCII byte is taken and validated later.
    pub(crate) fn readName(&mut self) -> bool {
        let (mut b, mut ok) = self.mustgetc();
        if !ok {
            return false;
        }
        if b < 0x80 && !isNameByte(b) {
            self.ungetc(b);
            return false;
        }
        let _ = self.buf.WriteByte(b);
        loop {
            let g = self.mustgetc();
            b = g.0;
            ok = g.1;
            if !ok {
                return false;
            }
            if b < 0x80 && !isNameByte(b) {
                self.ungetc(b);
                break;
            }
            let _ = self.buf.WriteByte(b);
        }
        return true;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:989-1151 Decoder.text
    /// Go: "Read plain text section (XML calls it character data). If
    /// quote >= 0, we are in a quoted string and need to find the
    /// matching quote. If cdata == true, we are in a `<![CDATA[`
    /// section and need to find `]]>`. On failure return nil and leave
    /// the error in d.err."
    ///
    /// Three things in here are worth knowing before changing it:
    ///
    ///   * `&#x` is hex, `&#X` is NOT — Go tests `b == 'x'` only, so
    ///     `&#X4a;` is read as a decimal entity with no digits and
    ///     fails with "(no semicolon)". Pinned.
    ///   * `\r` and `\r\n` both become a single `\n`, and the
    ///     two-byte history (`b0`, `b1`) exists for that and for
    ///     spotting `]]>`. An entity expansion RESETS that history, so
    ///     `]]` followed by `&gt;` is not a `]]>`.
    ///   * the character-range sweep happens at the END over the whole
    ///     buffer, not per byte, because an entity may have produced a
    ///     rune the input never contained.
    pub(crate) fn text(&mut self, quote: int, cdata: bool) -> Option<slice<byte>> {
        let mut b0: byte = 0;
        let mut b1: byte = 0;
        let mut trunc: int = 0;
        self.buf.Reset();
        'input: loop {
            let (b, ok) = self.getc();
            if !ok {
                if cdata {
                    if crate::errors::Is(self.err.clone(), crate::io::EOF) {
                        self.err = self.syntaxError("unexpected EOF in CDATA section");
                    }
                    return None;
                }
                break 'input;
            }

            // Go: "<![CDATA[ section ends with ]]>. It is an error for
            // ]]> to appear in ordinary text, but it is allowed in
            // quoted strings."
            if quote < 0 && b0 == b']' && b1 == b']' && b == b'>' {
                if cdata {
                    trunc = 2;
                    break 'input;
                }
                self.err = self.syntaxError("unescaped ]]> not in CDATA section");
                return None;
            }

            // Go: "Stop reading text if we see a <."
            if b == b'<' && !cdata {
                if quote >= 0 {
                    self.err = self.syntaxError("unescaped < inside quoted string");
                    return None;
                }
                self.ungetc(b'<');
                break 'input;
            }
            if quote >= 0 && b == crate::byte(quote) {
                break 'input;
            }
            if b == b'&' && !cdata {
                // Go: "Read escaped character expression up to
                // semicolon. ... Parsers are required to recognize lt,
                // gt, amp, apos, and quot even if they have not been
                // declared."
                let before = self.buf.Len();
                let _ = self.buf.WriteByte(b'&');
                let mut text = string::from_static("");
                let mut haveText = false;
                let (mut b, mut ok) = self.mustgetc();
                if !ok {
                    return None;
                }
                if b == b'#' {
                    let _ = self.buf.WriteByte(b);
                    let g = self.mustgetc();
                    b = g.0;
                    ok = g.1;
                    if !ok {
                        return None;
                    }
                    let mut base: int = 10;
                    // Go tests 'x' and not 'X'. `&#X41;` is therefore a
                    // DECIMAL entity with no digits.
                    if b == b'x' {
                        base = 16;
                        let _ = self.buf.WriteByte(b);
                        let g = self.mustgetc();
                        b = g.0;
                        ok = g.1;
                        if !ok {
                            return None;
                        }
                    }
                    let start = self.buf.Len();
                    while (b >= b'0' && b <= b'9')
                        || (base == 16 && b >= b'a' && b <= b'f')
                        || (base == 16 && b >= b'A' && b <= b'F')
                    {
                        let _ = self.buf.WriteByte(b);
                        let g = self.mustgetc();
                        b = g.0;
                        ok = g.1;
                        if !ok {
                            return None;
                        }
                    }
                    if b != b';' {
                        self.ungetc(b);
                    } else {
                        let all = self.buf.Bytes();
                        let raw: &[byte] = &all;
                        let sdigits = string::from_bytes(&raw[start as usize..]);
                        let _ = self.buf.WriteByte(b';');
                        let (n, err) = crate::strconv::ParseUint(sdigits, base, 64);
                        if err.IsNil() && n <= 0x10FFFF {
                            text = string::from_rune(crate::rune(n));
                            haveText = true;
                        }
                    }
                } else {
                    self.ungetc(b);
                    if !self.readName() && !self.err.IsNil() {
                        return None;
                    }
                    let g = self.mustgetc();
                    b = g.0;
                    ok = g.1;
                    if !ok {
                        return None;
                    }
                    if b != b';' {
                        self.ungetc(b);
                    } else {
                        let all = self.buf.Bytes();
                        let raw: &[byte] = &all;
                        let name: Vec<byte> = raw[(before + 1) as usize..].to_vec();
                        let _ = self.buf.WriteByte(b';');
                        if isName(&name) {
                            let key = string::from_bytes(&name);
                            let k: &str = key.as_ref();
                            // Go's `entity` map, the five XML requires.
                            let builtin = match k {
                                "lt" => Some('<'),
                                "gt" => Some('>'),
                                "amp" => Some('&'),
                                "apos" => Some('\''),
                                "quot" => Some('"'),
                                _ => None,
                            };
                            match builtin {
                                Some(r) => {
                                    text = string::from_rune(crate::rune(r));
                                    haveText = true;
                                }
                                None => {
                                    if let Some(m) = self.Entity.as_ref() {
                                        let (v, found) = m.Get(key.clone());
                                        if found {
                                            text = v;
                                            haveText = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if haveText {
                    self.buf.Truncate(before);
                    let _ = self.buf.WriteString(text);
                    b0 = 0;
                    b1 = 0;
                    continue 'input;
                }
                if !self.Strict {
                    b0 = 0;
                    b1 = 0;
                    continue 'input;
                }
                let all = self.buf.Bytes();
                let raw: &[byte] = &all;
                let mut ent = string::from_bytes(&raw[before as usize..]);
                let eb = ent.as_bytes();
                if eb.is_empty() || eb[eb.len() - 1] != b';' {
                    ent = ent + string::from_static(" (no semicolon)");
                }
                self.err = self.syntaxErrorString(
                    string::from_static("invalid character entity ") + ent,
                );
                return None;
            }

            // Go: "We must rewrite unescaped \r and \r\n into \n."
            if b == b'\r' {
                let _ = self.buf.WriteByte(b'\n');
            } else if b1 == b'\r' && b == b'\n' {
                // Skip \r\n — we already wrote \n.
            } else {
                let _ = self.buf.WriteByte(b);
            }

            b0 = b1;
            b1 = b;
        }
        // Go: `data := d.buf.Bytes()`. A bytes.Buffer that was never
        // written returns a NIL slice, and `rawToken` tests that nil to
        // decide whether a token was produced — so an empty result is
        // not the same as no result. goish's `slice` has no nil, so the
        // distinction is carried by Option, and the test has to be on
        // the buffer BEFORE trunc: Go's re-slice of a non-nil slice
        // stays non-nil even at length 0.
        if self.buf.Len() == 0 {
            return None;
        }
        let data = self.buf.Bytes();
        let dv: &[byte] = &data;
        let dv = &dv[..dv.len() - trunc as usize];

        // Go: "Inspect each rune for being a disallowed character."
        // Deliberately over the FINAL buffer: an entity may have
        // produced a rune the input never contained.
        let mut off: usize = 0;
        while off < dv.len() {
            let (r, size) = crate::unicode::utf8::DecodeRune(&dv[off..]);
            if r == crate::unicode::utf8::RuneError && size == 1 {
                self.err = self.syntaxError("invalid UTF-8");
                return None;
            }
            off += size as usize;
            if !isInCharacterRange(r) {
                // Go formats this with %U, which is "U+" followed by
                // AT LEAST four uppercase hex digits — U+0000, not
                // U+0. Getting that wrong makes every such message
                // differ from Go's on exactly the characters most
                // likely to appear in a bug report.
                let mut hex = crate::strings::ToUpper(crate::strconv::FormatInt(
                    crate::int64(r),
                    16,
                ));
                while hex.Len() < 4 {
                    hex = string::from_static("0") + hex;
                }
                self.err = self
                    .syntaxErrorString(string::from_static("illegal character code U+") + hex);
                return None;
            }
        }
        return Some(slice::<byte>::__from_vec(dv.to_vec()));
    }

    // go: none — goish-only: `syntaxError` takes a &str, and two call
    // sites in `text` build their message at runtime. Same struct.
    pub(crate) fn syntaxErrorString(&self, msg: string) -> crate::error {
        return crate::errors::Wrap(SyntaxError {
            Msg: msg,
            Line: self.line,
        });
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:468-476 Decoder.syntaxError
    /// Go: `&SyntaxError{Msg: msg, Line: d.line}`.
    pub(crate) fn syntaxError(&self, msg: &str) -> crate::error {
        return crate::errors::Wrap(SyntaxError {
            Msg: string::from_bytes(msg.as_bytes()),
            Line: self.line,
        });
    }
}

// go: none — goish-only: drive the byte layer from an example. `getc`,
// `ungetc` and `space` are crate-internal (Go's are unexported too), so
// the smoke scripts them through here — "g" getc, "u" ungetc the last
// byte read, "s" space — and reads back the observable state after each
// step. Exactly the shape of the reference generator run inside GOROOT.
#[doc(hidden)]
pub fn __byte_script(input: &[byte], script: &str) -> string {
    let mut d = NewDecoder(crate::bytes::NewReader(slice::<byte>::__from_vec(input.to_vec())));
    let mut out = string::from_static("");
    let mut last: byte = 0;
    let mut first = true;
    for op in script.chars() {
        if !first {
            out = out + string::from_static(" ");
        }
        first = false;
        match op {
            'g' => {
                let (b, ok) = d.getc();
                if ok {
                    last = b;
                }
                let (l, c) = d.InputPos();
                out = out
                    + crate::fmt::Sprintf!(
                        "g(%v,%v)@%v:%v:%v",
                        crate::int(b),
                        ok,
                        d.InputOffset(),
                        l,
                        c
                    );
            }
            'u' => {
                d.ungetc(last);
                let (l, c) = d.InputPos();
                out = out + crate::fmt::Sprintf!("u@%v:%v:%v", d.InputOffset(), l, c);
            }
            's' => {
                d.space();
                let (l, c) = d.InputPos();
                out = out + crate::fmt::Sprintf!("s@%v:%v:%v", d.InputOffset(), l, c);
            }
            _ => {}
        }
    }
    return out;
}

// go: none — goish-only: drive `text` from an example. Go's is
// unexported and takes the Decoder's whole state, so the smoke builds a
// decoder over `input`, sets Strict and any custom entities, calls
// text(quote, cdata) and reports what Go's reference generator reports:
// the bytes, the latched error, and the offset.
#[doc(hidden)]
pub fn __text_script(
    input: &[byte],
    quote: int,
    cdata: bool,
    strict: bool,
    entities: &[(&str, &str)],
) -> string {
    let mut d = NewDecoder(crate::bytes::NewReader(slice::<byte>::__from_vec(input.to_vec())));
    d.Strict = strict;
    if !entities.is_empty() {
        let mut m = crate::gomap::map::<string, string>::new();
        for (k, v) in entities.iter() {
            m.Set(
                string::from_bytes(k.as_bytes()),
                string::from_bytes(v.as_bytes()),
            );
        }
        d.Entity = Some(m);
    }
    let out = d.text(quote, cdata);
    let errs = if d.err.IsNil() {
        string::from_static("<nil>")
    } else {
        d.err.Error()
    };
    return match out {
        None => crate::fmt::Sprintf!("nil err=%s", errs),
        Some(b) => {
            let raw: &[byte] = &b;
            let mut hex = string::from_static("");
            for &x in raw.iter() {
                hex = hex + crate::fmt::Sprintf!("%02x", crate::int(x));
            }
            crate::fmt::Sprintf!("%s err=%s off=%v", hex, errs, d.InputOffset())
        }
    };
}

// ─── the parse stack ──────────────────────────────────────────────────

// go: sdk 1.25.5 encoding/xml/xml.go:379-384 stack
// goishlint:ignore GOISH019 stack — Go's `stack` is a linked-list node with a `next` pointer and a matching `free` list of recycled nodes. goish holds the stack as a Vec, so `next` is the index order and `free` has no counterpart; the remaining three fields are Go's.
/// Go: "Parsing state - stack holds old name space translations and the
/// current set of open elements. The translations to pop when ending a
/// given tag are *below* it on the stack, which is more work but forced
/// on us by XML."
#[derive(Clone, Default)]
struct stack {
    kind: int,
    name: Name,
    ok: bool,
}

// go: sdk 1.25.5 encoding/xml/xml.go:386-390 stkStart
/// An open element.
const stkStart: int = 0;
// go: none — see stkStart; Go declares the three in one `iota` block.
/// A saved name-space binding, to be restored when its element closes.
const stkNs: int = 1;
// go: none — see stkStart.
/// A marker that `Token` should report EOF until `popEOF`.
const stkEOF: int = 2;

impl Decoder {
    // go: sdk 1.25.5 encoding/xml/xml.go:392-403 Decoder.push
    /// Go recycles a node off `free` or allocates; the Vec just grows.
    fn push(&mut self, kind: int) -> usize {
        self.stk.push(stack {
            kind,
            name: Name::default(),
            ok: false,
        });
        return self.stk.len() - 1;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:405-412 Decoder.pop
    /// Go returns the popped node (and files it on `free`); goish
    /// returns it by value, which is the same information.
    fn pop(&mut self) -> Option<stack> {
        return self.stk.pop();
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:418-442 Decoder.pushEOF
    /// Go: "Record that after the current element is finished (that
    /// element is already pushed on the stack) Token should return EOF
    /// until popEOF is called."
    ///
    /// The insertion point is the fiddly part and the reason this is
    /// not a plain push: the marker goes BELOW the innermost open
    /// element AND below the stkNs entries that belong to it, so that
    /// closing that element pops down to the marker rather than past
    /// it. In Go's list that is "walk down to the first stkStart, then
    /// keep walking while the node below is stkNs, then splice in
    /// below"; in a Vec it is the same walk by index.
    fn pushEOF(&mut self) {
        // Go walks DOWN from the top to the first stkStart.
        let mut i = self.stk.len();
        while i > 0 && self.stk[i - 1].kind != stkStart {
            i -= 1;
        }
        // i-1 is now the start (Go's `start`). Go then moves `start`
        // down while the node BELOW it is stkNs.
        let mut at = i - 1;
        while at > 0 && self.stk[at - 1].kind == stkNs {
            at -= 1;
        }
        self.stk.insert(
            at,
            stack {
                kind: stkEOF,
                name: Name::default(),
                ok: false,
            },
        );
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:444-451 Decoder.popEOF
    /// Go: "Undo a pushEOF. The element must have been finished, so the
    /// EOF should be at the top of the stack."
    fn popEOF(&mut self) -> bool {
        if self.stk.is_empty() || self.stk[self.stk.len() - 1].kind != stkEOF {
            return false;
        }
        self.pop();
        return true;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:453-458 Decoder.pushElement
    /// Go: "Record that we are starting an element with the given name."
    fn pushElement(&mut self, name: Name) {
        let i = self.push(stkStart);
        self.stk[i].name = name;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:460-466 Decoder.pushNs
    /// Go: "Record that we are changing the value of ns[local]. The old
    /// value is url, ok." Note it saves the OLD binding, so `ok` false
    /// means "there was none, delete it again on the way out".
    fn pushNs(&mut self, local: string, url: string, ok: bool) {
        let i = self.push(stkNs);
        self.stk[i].name.Local = local;
        self.stk[i].name.Space = url;
        self.stk[i].ok = ok;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:478-517 Decoder.popElement
    /// Close the innermost open element, checking it matches `t`, then
    /// undo every name-space binding that element introduced.
    ///
    /// The non-Strict arm is not a relaxation of the check — it still
    /// REWRITES `t.Name` to the open element's name and records the
    /// mismatch in `needClose`/`toClose`, so the caller emits the tag
    /// the document should have had.
    fn popElement(&mut self, t: &mut EndElement) -> bool {
        let s = self.pop();
        let name = t.Name.clone();
        let s = match s {
            None => {
                self.err = self.syntaxErrorString(
                    string::from_static("unexpected end element </")
                        + name.Local.clone()
                        + string::from_static(">"),
                );
                return false;
            }
            Some(s) => {
                if s.kind != stkStart {
                    self.err = self.syntaxErrorString(
                        string::from_static("unexpected end element </")
                            + name.Local.clone()
                            + string::from_static(">"),
                    );
                    return false;
                }
                s
            }
        };
        if s.name.Local != name.Local {
            if !self.Strict {
                self.needClose = true;
                self.toClose = t.Name.clone();
                t.Name = s.name.clone();
                return true;
            }
            self.err = self.syntaxErrorString(
                string::from_static("element <")
                    + s.name.Local.clone()
                    + string::from_static("> closed by </")
                    + name.Local.clone()
                    + string::from_static(">"),
            );
            return false;
        }
        if s.name.Space != name.Space {
            let ns = if name.Space.Len() == 0 {
                string::from_static("\"\"")
            } else {
                name.Space.clone()
            };
            self.err = self.syntaxErrorString(
                string::from_static("element <")
                    + s.name.Local.clone()
                    + string::from_static("> in space ")
                    + s.name.Space.clone()
                    + string::from_static(" closed by </")
                    + name.Local.clone()
                    + string::from_static("> in space ")
                    + ns,
            );
            return false;
        }

        let mut n = t.Name.clone();
        self.translate(&mut n, true);
        t.Name = n;

        // Go: "Pop stack until a Start or EOF is on the top, undoing
        // the translations that were associated with the element we
        // just closed."
        while !self.stk.is_empty() {
            let k = self.stk[self.stk.len() - 1].kind;
            if k == stkStart || k == stkEOF {
                break;
            }
            let s = self.pop().unwrap();
            if s.ok {
                self.ns.Set(s.name.Local.clone(), s.name.Space.clone());
            } else {
                crate::delete!(self.ns, s.name.Local.clone());
            }
        }
        return true;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:345-361 Decoder.translate
    /// Resolve a name's prefix to its URL.
    ///
    /// The four early returns are each load-bearing and none is
    /// obvious: an `xmlns` prefix is left alone (it is not a namespace
    /// reference, it is the declaration syntax); an unprefixed
    /// ATTRIBUTE name is left alone, because unprefixed attributes are
    /// in no namespace even when the element is; the `xml` prefix is
    /// hardwired to its URL whether or not it was declared; and an
    /// unprefixed name that IS `xmlns` is the default-namespace
    /// declaration, also left alone.
    fn translate(&self, n: &mut Name, isElementName: bool) {
        if n.Space == string::from_static(xmlnsPrefix) {
            return;
        }
        if n.Space.Len() == 0 && !isElementName {
            return;
        }
        if n.Space == string::from_static(xmlPrefix) {
            n.Space = string::from_static(xmlURL);
        } else if n.Space.Len() == 0 && n.Local == string::from_static(xmlnsPrefix) {
            return;
        }
        let (v, ok) = self.ns.Get(n.Space.clone());
        if ok {
            n.Space = v;
        } else if n.Space.Len() == 0 {
            n.Space = self.DefaultSpace.clone();
        }
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:338 xmlnsPrefix
/// Go: the reserved prefixes, which never go through `ns`.
const xmlnsPrefix: &str = "xmlns";
// go: none — see xmlnsPrefix; Go declares both in one const block.
const xmlPrefix: &str = "xml";
// go: none — see xmlnsPrefix.
const xmlURL: &str = "http://www.w3.org/XML/1998/namespace";

// go: none — goish-only: drive the parse stack from an example. Go's
// stack ops are unexported and mutate the whole Decoder, so the smoke
// scripts them and reads back the same dump the reference generator
// prints inside GOROOT: the stack bottom-first and the ns map sorted.
#[doc(hidden)]
pub fn __stack_script(ops: &[&str], strict: bool, default_space: &str) -> string {
    let mut d = NewDecoder(crate::bytes::NewReader(slice::<byte>::new()));
    d.Strict = strict;
    d.DefaultSpace = string::from_bytes(default_space.as_bytes());

    // go: none — goish-only: the dump format the reference
    // generator prints, so the two are comparable.
    fn dump_stk(d: &Decoder) -> string {
        let mut out = string::from_static("[");
        // Go walks its list from the TOP down; the Vec is bottom-first.
        let mut i = d.stk.len();
        let mut first = true;
        while i > 0 {
            i -= 1;
            if !first {
                out = out + string::from_static(" ");
            }
            first = false;
            let e = &d.stk[i];
            let k = if e.kind == stkStart {
                "S"
            } else if e.kind == stkNs {
                "N"
            } else {
                "E"
            };
            out = out
                + crate::fmt::Sprintf!(
                    "%s(%s|%s|%v)",
                    k,
                    e.name.Space.clone(),
                    e.name.Local.clone(),
                    e.ok
                );
        }
        return out + string::from_static("]");
    }

    // go: none — goish-only: see dump_stk.
    fn dump_ns(d: &Decoder) -> string {
        let mut keys: Vec<string> = Vec::new();
        for (k, _) in crate::range!(&d.ns) {
            keys.push(k.clone());
        }
        keys.sort_by(|a, b| (a.as_ref() as &str).cmp(b.as_ref() as &str));
        let mut out = string::from_static("{");
        let mut first = true;
        for k in keys.iter() {
            if !first {
                out = out + string::from_static(",");
            }
            first = false;
            out = out + k.clone() + string::from_static("=") + d.ns.Get(k.clone()).0;
        }
        return out + string::from_static("}");
    }

    let mut out = string::from_static("");
    let mut first = true;
    for op in ops.iter() {
        if !first {
            out = out + string::from_static(" ");
        }
        first = false;
        let b = op.as_bytes();
        match b[0] {
            b'e' => {
                d.pushElement(Name {
                    Space: string::from_static(""),
                    Local: string::from_bytes(&b[1..]),
                });
                out = out + string::from_static("e:") + dump_stk(&d);
            }
            b'n' => {
                let mut rest = &b[1..];
                let mut ok = true;
                if !rest.is_empty() && rest[rest.len() - 1] == b'!' {
                    ok = false;
                    rest = &rest[..rest.len() - 1];
                }
                let eq = rest.iter().position(|&c| c == b'=').unwrap_or(rest.len());
                let l = string::from_bytes(&rest[..eq]);
                let u = string::from_bytes(if eq < rest.len() { &rest[eq + 1..] } else { &[] });
                if ok {
                    d.ns.Set(l.clone(), u.clone());
                }
                d.pushNs(l, u, ok);
                out = out + string::from_static("n:") + dump_stk(&d) + dump_ns(&d);
            }
            b'p' => {
                let mut t = EndElement {
                    Name: Name {
                        Space: string::from_static(""),
                        Local: string::from_bytes(&b[1..]),
                    },
                };
                let r = d.popElement(&mut t);
                let errs = if d.err.IsNil() {
                    string::from_static("<nil>")
                } else {
                    d.err.Error()
                };
                out = out
                    + crate::fmt::Sprintf!(
                        "p:%v %s %s err=%s",
                        r,
                        dump_stk(&d),
                        dump_ns(&d),
                        errs
                    );
            }
            b'F' => {
                d.pushEOF();
                out = out + string::from_static("F:") + dump_stk(&d);
            }
            b'f' => {
                let r = d.popEOF();
                out = out + crate::fmt::Sprintf!("f:%v %s", r, dump_stk(&d));
            }
            b't' => {
                let rest = &b[1..];
                let mut parts: Vec<&[byte]> = Vec::new();
                let mut start = 0usize;
                for i in 0..rest.len() {
                    if rest[i] == b'|' {
                        parts.push(&rest[start..i]);
                        start = i + 1;
                    }
                }
                parts.push(&rest[start..]);
                let mut n = Name {
                    Space: string::from_bytes(parts[0]),
                    Local: string::from_bytes(parts[1]),
                };
                d.translate(&mut n, parts[2] == b"1");
                out = out + crate::fmt::Sprintf!("t:%s|%s", n.Space, n.Local);
            }
            _ => {}
        }
    }
    return out;
}

// ─── the XML name character tables ────────────────────────────────────
//
// go: none — goish idiom: Go declares `first` and `second` as
// `*unicode.RangeTable` literals, 310 lines of xml.go. These were
// DUMPED from Go 1.25.5 (scripts/goref.sh encoding/xml, printing every
// R16 entry) rather than transcribed — 302 ranges is well past the
// point where retyping introduces a silent one-character error, and a
// wrong range here would accept or reject XML names for the rest of the
// package's life.
//
// Go's comment on them: "first" is the set of characters that may START
// an XML name (XML 1.0 §2.3 NameStartChar, roughly), "second" the extra
// ones legal in later positions — digits, combining marks, extenders.
// Neither table has any R32 entries, so no name character is above
// U+FFFF; that is Go's table, not an assumption, and the generator
// asserts it.

/// Generated from Go 1.25.5's `xml.first` — 190 R16 ranges, no R32,
/// LatinOffset 0. Dumped by scripts/goref.sh, not transcribed.
static FIRST_R16: [Range16; 190] = [
    Range16 { Lo: 0x003a, Hi: 0x003a, Stride: 1 },
    Range16 { Lo: 0x0041, Hi: 0x005a, Stride: 1 },
    Range16 { Lo: 0x005f, Hi: 0x005f, Stride: 1 },
    Range16 { Lo: 0x0061, Hi: 0x007a, Stride: 1 },
    Range16 { Lo: 0x00c0, Hi: 0x00d6, Stride: 1 },
    Range16 { Lo: 0x00d8, Hi: 0x00f6, Stride: 1 },
    Range16 { Lo: 0x00f8, Hi: 0x00ff, Stride: 1 },
    Range16 { Lo: 0x0100, Hi: 0x0131, Stride: 1 },
    Range16 { Lo: 0x0134, Hi: 0x013e, Stride: 1 },
    Range16 { Lo: 0x0141, Hi: 0x0148, Stride: 1 },
    Range16 { Lo: 0x014a, Hi: 0x017e, Stride: 1 },
    Range16 { Lo: 0x0180, Hi: 0x01c3, Stride: 1 },
    Range16 { Lo: 0x01cd, Hi: 0x01f0, Stride: 1 },
    Range16 { Lo: 0x01f4, Hi: 0x01f5, Stride: 1 },
    Range16 { Lo: 0x01fa, Hi: 0x0217, Stride: 1 },
    Range16 { Lo: 0x0250, Hi: 0x02a8, Stride: 1 },
    Range16 { Lo: 0x02bb, Hi: 0x02c1, Stride: 1 },
    Range16 { Lo: 0x0386, Hi: 0x0386, Stride: 1 },
    Range16 { Lo: 0x0388, Hi: 0x038a, Stride: 1 },
    Range16 { Lo: 0x038c, Hi: 0x038c, Stride: 1 },
    Range16 { Lo: 0x038e, Hi: 0x03a1, Stride: 1 },
    Range16 { Lo: 0x03a3, Hi: 0x03ce, Stride: 1 },
    Range16 { Lo: 0x03d0, Hi: 0x03d6, Stride: 1 },
    Range16 { Lo: 0x03da, Hi: 0x03e0, Stride: 2 },
    Range16 { Lo: 0x03e2, Hi: 0x03f3, Stride: 1 },
    Range16 { Lo: 0x0401, Hi: 0x040c, Stride: 1 },
    Range16 { Lo: 0x040e, Hi: 0x044f, Stride: 1 },
    Range16 { Lo: 0x0451, Hi: 0x045c, Stride: 1 },
    Range16 { Lo: 0x045e, Hi: 0x0481, Stride: 1 },
    Range16 { Lo: 0x0490, Hi: 0x04c4, Stride: 1 },
    Range16 { Lo: 0x04c7, Hi: 0x04c8, Stride: 1 },
    Range16 { Lo: 0x04cb, Hi: 0x04cc, Stride: 1 },
    Range16 { Lo: 0x04d0, Hi: 0x04eb, Stride: 1 },
    Range16 { Lo: 0x04ee, Hi: 0x04f5, Stride: 1 },
    Range16 { Lo: 0x04f8, Hi: 0x04f9, Stride: 1 },
    Range16 { Lo: 0x0531, Hi: 0x0556, Stride: 1 },
    Range16 { Lo: 0x0559, Hi: 0x0559, Stride: 1 },
    Range16 { Lo: 0x0561, Hi: 0x0586, Stride: 1 },
    Range16 { Lo: 0x05d0, Hi: 0x05ea, Stride: 1 },
    Range16 { Lo: 0x05f0, Hi: 0x05f2, Stride: 1 },
    Range16 { Lo: 0x0621, Hi: 0x063a, Stride: 1 },
    Range16 { Lo: 0x0641, Hi: 0x064a, Stride: 1 },
    Range16 { Lo: 0x0671, Hi: 0x06b7, Stride: 1 },
    Range16 { Lo: 0x06ba, Hi: 0x06be, Stride: 1 },
    Range16 { Lo: 0x06c0, Hi: 0x06ce, Stride: 1 },
    Range16 { Lo: 0x06d0, Hi: 0x06d3, Stride: 1 },
    Range16 { Lo: 0x06d5, Hi: 0x06d5, Stride: 1 },
    Range16 { Lo: 0x06e5, Hi: 0x06e6, Stride: 1 },
    Range16 { Lo: 0x0905, Hi: 0x0939, Stride: 1 },
    Range16 { Lo: 0x093d, Hi: 0x093d, Stride: 1 },
    Range16 { Lo: 0x0958, Hi: 0x0961, Stride: 1 },
    Range16 { Lo: 0x0985, Hi: 0x098c, Stride: 1 },
    Range16 { Lo: 0x098f, Hi: 0x0990, Stride: 1 },
    Range16 { Lo: 0x0993, Hi: 0x09a8, Stride: 1 },
    Range16 { Lo: 0x09aa, Hi: 0x09b0, Stride: 1 },
    Range16 { Lo: 0x09b2, Hi: 0x09b2, Stride: 1 },
    Range16 { Lo: 0x09b6, Hi: 0x09b9, Stride: 1 },
    Range16 { Lo: 0x09dc, Hi: 0x09dd, Stride: 1 },
    Range16 { Lo: 0x09df, Hi: 0x09e1, Stride: 1 },
    Range16 { Lo: 0x09f0, Hi: 0x09f1, Stride: 1 },
    Range16 { Lo: 0x0a05, Hi: 0x0a0a, Stride: 1 },
    Range16 { Lo: 0x0a0f, Hi: 0x0a10, Stride: 1 },
    Range16 { Lo: 0x0a13, Hi: 0x0a28, Stride: 1 },
    Range16 { Lo: 0x0a2a, Hi: 0x0a30, Stride: 1 },
    Range16 { Lo: 0x0a32, Hi: 0x0a33, Stride: 1 },
    Range16 { Lo: 0x0a35, Hi: 0x0a36, Stride: 1 },
    Range16 { Lo: 0x0a38, Hi: 0x0a39, Stride: 1 },
    Range16 { Lo: 0x0a59, Hi: 0x0a5c, Stride: 1 },
    Range16 { Lo: 0x0a5e, Hi: 0x0a5e, Stride: 1 },
    Range16 { Lo: 0x0a72, Hi: 0x0a74, Stride: 1 },
    Range16 { Lo: 0x0a85, Hi: 0x0a8b, Stride: 1 },
    Range16 { Lo: 0x0a8d, Hi: 0x0a8d, Stride: 1 },
    Range16 { Lo: 0x0a8f, Hi: 0x0a91, Stride: 1 },
    Range16 { Lo: 0x0a93, Hi: 0x0aa8, Stride: 1 },
    Range16 { Lo: 0x0aaa, Hi: 0x0ab0, Stride: 1 },
    Range16 { Lo: 0x0ab2, Hi: 0x0ab3, Stride: 1 },
    Range16 { Lo: 0x0ab5, Hi: 0x0ab9, Stride: 1 },
    Range16 { Lo: 0x0abd, Hi: 0x0ae0, Stride: 35 },
    Range16 { Lo: 0x0b05, Hi: 0x0b0c, Stride: 1 },
    Range16 { Lo: 0x0b0f, Hi: 0x0b10, Stride: 1 },
    Range16 { Lo: 0x0b13, Hi: 0x0b28, Stride: 1 },
    Range16 { Lo: 0x0b2a, Hi: 0x0b30, Stride: 1 },
    Range16 { Lo: 0x0b32, Hi: 0x0b33, Stride: 1 },
    Range16 { Lo: 0x0b36, Hi: 0x0b39, Stride: 1 },
    Range16 { Lo: 0x0b3d, Hi: 0x0b3d, Stride: 1 },
    Range16 { Lo: 0x0b5c, Hi: 0x0b5d, Stride: 1 },
    Range16 { Lo: 0x0b5f, Hi: 0x0b61, Stride: 1 },
    Range16 { Lo: 0x0b85, Hi: 0x0b8a, Stride: 1 },
    Range16 { Lo: 0x0b8e, Hi: 0x0b90, Stride: 1 },
    Range16 { Lo: 0x0b92, Hi: 0x0b95, Stride: 1 },
    Range16 { Lo: 0x0b99, Hi: 0x0b9a, Stride: 1 },
    Range16 { Lo: 0x0b9c, Hi: 0x0b9c, Stride: 1 },
    Range16 { Lo: 0x0b9e, Hi: 0x0b9f, Stride: 1 },
    Range16 { Lo: 0x0ba3, Hi: 0x0ba4, Stride: 1 },
    Range16 { Lo: 0x0ba8, Hi: 0x0baa, Stride: 1 },
    Range16 { Lo: 0x0bae, Hi: 0x0bb5, Stride: 1 },
    Range16 { Lo: 0x0bb7, Hi: 0x0bb9, Stride: 1 },
    Range16 { Lo: 0x0c05, Hi: 0x0c0c, Stride: 1 },
    Range16 { Lo: 0x0c0e, Hi: 0x0c10, Stride: 1 },
    Range16 { Lo: 0x0c12, Hi: 0x0c28, Stride: 1 },
    Range16 { Lo: 0x0c2a, Hi: 0x0c33, Stride: 1 },
    Range16 { Lo: 0x0c35, Hi: 0x0c39, Stride: 1 },
    Range16 { Lo: 0x0c60, Hi: 0x0c61, Stride: 1 },
    Range16 { Lo: 0x0c85, Hi: 0x0c8c, Stride: 1 },
    Range16 { Lo: 0x0c8e, Hi: 0x0c90, Stride: 1 },
    Range16 { Lo: 0x0c92, Hi: 0x0ca8, Stride: 1 },
    Range16 { Lo: 0x0caa, Hi: 0x0cb3, Stride: 1 },
    Range16 { Lo: 0x0cb5, Hi: 0x0cb9, Stride: 1 },
    Range16 { Lo: 0x0cde, Hi: 0x0cde, Stride: 1 },
    Range16 { Lo: 0x0ce0, Hi: 0x0ce1, Stride: 1 },
    Range16 { Lo: 0x0d05, Hi: 0x0d0c, Stride: 1 },
    Range16 { Lo: 0x0d0e, Hi: 0x0d10, Stride: 1 },
    Range16 { Lo: 0x0d12, Hi: 0x0d28, Stride: 1 },
    Range16 { Lo: 0x0d2a, Hi: 0x0d39, Stride: 1 },
    Range16 { Lo: 0x0d60, Hi: 0x0d61, Stride: 1 },
    Range16 { Lo: 0x0e01, Hi: 0x0e2e, Stride: 1 },
    Range16 { Lo: 0x0e30, Hi: 0x0e30, Stride: 1 },
    Range16 { Lo: 0x0e32, Hi: 0x0e33, Stride: 1 },
    Range16 { Lo: 0x0e40, Hi: 0x0e45, Stride: 1 },
    Range16 { Lo: 0x0e81, Hi: 0x0e82, Stride: 1 },
    Range16 { Lo: 0x0e84, Hi: 0x0e84, Stride: 1 },
    Range16 { Lo: 0x0e87, Hi: 0x0e88, Stride: 1 },
    Range16 { Lo: 0x0e8a, Hi: 0x0e8d, Stride: 3 },
    Range16 { Lo: 0x0e94, Hi: 0x0e97, Stride: 1 },
    Range16 { Lo: 0x0e99, Hi: 0x0e9f, Stride: 1 },
    Range16 { Lo: 0x0ea1, Hi: 0x0ea3, Stride: 1 },
    Range16 { Lo: 0x0ea5, Hi: 0x0ea7, Stride: 2 },
    Range16 { Lo: 0x0eaa, Hi: 0x0eab, Stride: 1 },
    Range16 { Lo: 0x0ead, Hi: 0x0eae, Stride: 1 },
    Range16 { Lo: 0x0eb0, Hi: 0x0eb0, Stride: 1 },
    Range16 { Lo: 0x0eb2, Hi: 0x0eb3, Stride: 1 },
    Range16 { Lo: 0x0ebd, Hi: 0x0ebd, Stride: 1 },
    Range16 { Lo: 0x0ec0, Hi: 0x0ec4, Stride: 1 },
    Range16 { Lo: 0x0f40, Hi: 0x0f47, Stride: 1 },
    Range16 { Lo: 0x0f49, Hi: 0x0f69, Stride: 1 },
    Range16 { Lo: 0x10a0, Hi: 0x10c5, Stride: 1 },
    Range16 { Lo: 0x10d0, Hi: 0x10f6, Stride: 1 },
    Range16 { Lo: 0x1100, Hi: 0x1100, Stride: 1 },
    Range16 { Lo: 0x1102, Hi: 0x1103, Stride: 1 },
    Range16 { Lo: 0x1105, Hi: 0x1107, Stride: 1 },
    Range16 { Lo: 0x1109, Hi: 0x1109, Stride: 1 },
    Range16 { Lo: 0x110b, Hi: 0x110c, Stride: 1 },
    Range16 { Lo: 0x110e, Hi: 0x1112, Stride: 1 },
    Range16 { Lo: 0x113c, Hi: 0x1140, Stride: 2 },
    Range16 { Lo: 0x114c, Hi: 0x1150, Stride: 2 },
    Range16 { Lo: 0x1154, Hi: 0x1155, Stride: 1 },
    Range16 { Lo: 0x1159, Hi: 0x1159, Stride: 1 },
    Range16 { Lo: 0x115f, Hi: 0x1161, Stride: 1 },
    Range16 { Lo: 0x1163, Hi: 0x1169, Stride: 2 },
    Range16 { Lo: 0x116d, Hi: 0x116e, Stride: 1 },
    Range16 { Lo: 0x1172, Hi: 0x1173, Stride: 1 },
    Range16 { Lo: 0x1175, Hi: 0x119e, Stride: 41 },
    Range16 { Lo: 0x11a8, Hi: 0x11ab, Stride: 3 },
    Range16 { Lo: 0x11ae, Hi: 0x11af, Stride: 1 },
    Range16 { Lo: 0x11b7, Hi: 0x11b8, Stride: 1 },
    Range16 { Lo: 0x11ba, Hi: 0x11ba, Stride: 1 },
    Range16 { Lo: 0x11bc, Hi: 0x11c2, Stride: 1 },
    Range16 { Lo: 0x11eb, Hi: 0x11f0, Stride: 5 },
    Range16 { Lo: 0x11f9, Hi: 0x11f9, Stride: 1 },
    Range16 { Lo: 0x1e00, Hi: 0x1e9b, Stride: 1 },
    Range16 { Lo: 0x1ea0, Hi: 0x1ef9, Stride: 1 },
    Range16 { Lo: 0x1f00, Hi: 0x1f15, Stride: 1 },
    Range16 { Lo: 0x1f18, Hi: 0x1f1d, Stride: 1 },
    Range16 { Lo: 0x1f20, Hi: 0x1f45, Stride: 1 },
    Range16 { Lo: 0x1f48, Hi: 0x1f4d, Stride: 1 },
    Range16 { Lo: 0x1f50, Hi: 0x1f57, Stride: 1 },
    Range16 { Lo: 0x1f59, Hi: 0x1f5b, Stride: 2 },
    Range16 { Lo: 0x1f5d, Hi: 0x1f5d, Stride: 1 },
    Range16 { Lo: 0x1f5f, Hi: 0x1f7d, Stride: 1 },
    Range16 { Lo: 0x1f80, Hi: 0x1fb4, Stride: 1 },
    Range16 { Lo: 0x1fb6, Hi: 0x1fbc, Stride: 1 },
    Range16 { Lo: 0x1fbe, Hi: 0x1fbe, Stride: 1 },
    Range16 { Lo: 0x1fc2, Hi: 0x1fc4, Stride: 1 },
    Range16 { Lo: 0x1fc6, Hi: 0x1fcc, Stride: 1 },
    Range16 { Lo: 0x1fd0, Hi: 0x1fd3, Stride: 1 },
    Range16 { Lo: 0x1fd6, Hi: 0x1fdb, Stride: 1 },
    Range16 { Lo: 0x1fe0, Hi: 0x1fec, Stride: 1 },
    Range16 { Lo: 0x1ff2, Hi: 0x1ff4, Stride: 1 },
    Range16 { Lo: 0x1ff6, Hi: 0x1ffc, Stride: 1 },
    Range16 { Lo: 0x2126, Hi: 0x2126, Stride: 1 },
    Range16 { Lo: 0x212a, Hi: 0x212b, Stride: 1 },
    Range16 { Lo: 0x212e, Hi: 0x212e, Stride: 1 },
    Range16 { Lo: 0x2180, Hi: 0x2182, Stride: 1 },
    Range16 { Lo: 0x3007, Hi: 0x3007, Stride: 1 },
    Range16 { Lo: 0x3021, Hi: 0x3029, Stride: 1 },
    Range16 { Lo: 0x3041, Hi: 0x3094, Stride: 1 },
    Range16 { Lo: 0x30a1, Hi: 0x30fa, Stride: 1 },
    Range16 { Lo: 0x3105, Hi: 0x312c, Stride: 1 },
    Range16 { Lo: 0x4e00, Hi: 0x9fa5, Stride: 1 },
    Range16 { Lo: 0xac00, Hi: 0xd7a3, Stride: 1 },
];

pub static FIRST: RangeTable = RangeTable {
    R16: &FIRST_R16,
    R32: &[],
    LatinOffset: 0,
};

/// Generated from Go 1.25.5's `xml.second` — 112 R16 ranges, no R32,
/// LatinOffset 0. Dumped by scripts/goref.sh, not transcribed.
static SECOND_R16: [Range16; 112] = [
    Range16 { Lo: 0x002d, Hi: 0x002e, Stride: 1 },
    Range16 { Lo: 0x0030, Hi: 0x0039, Stride: 1 },
    Range16 { Lo: 0x00b7, Hi: 0x00b7, Stride: 1 },
    Range16 { Lo: 0x02d0, Hi: 0x02d1, Stride: 1 },
    Range16 { Lo: 0x0300, Hi: 0x0345, Stride: 1 },
    Range16 { Lo: 0x0360, Hi: 0x0361, Stride: 1 },
    Range16 { Lo: 0x0387, Hi: 0x0387, Stride: 1 },
    Range16 { Lo: 0x0483, Hi: 0x0486, Stride: 1 },
    Range16 { Lo: 0x0591, Hi: 0x05a1, Stride: 1 },
    Range16 { Lo: 0x05a3, Hi: 0x05b9, Stride: 1 },
    Range16 { Lo: 0x05bb, Hi: 0x05bd, Stride: 1 },
    Range16 { Lo: 0x05bf, Hi: 0x05bf, Stride: 1 },
    Range16 { Lo: 0x05c1, Hi: 0x05c2, Stride: 1 },
    Range16 { Lo: 0x05c4, Hi: 0x0640, Stride: 124 },
    Range16 { Lo: 0x064b, Hi: 0x0652, Stride: 1 },
    Range16 { Lo: 0x0660, Hi: 0x0669, Stride: 1 },
    Range16 { Lo: 0x0670, Hi: 0x0670, Stride: 1 },
    Range16 { Lo: 0x06d6, Hi: 0x06dc, Stride: 1 },
    Range16 { Lo: 0x06dd, Hi: 0x06df, Stride: 1 },
    Range16 { Lo: 0x06e0, Hi: 0x06e4, Stride: 1 },
    Range16 { Lo: 0x06e7, Hi: 0x06e8, Stride: 1 },
    Range16 { Lo: 0x06ea, Hi: 0x06ed, Stride: 1 },
    Range16 { Lo: 0x06f0, Hi: 0x06f9, Stride: 1 },
    Range16 { Lo: 0x0901, Hi: 0x0903, Stride: 1 },
    Range16 { Lo: 0x093c, Hi: 0x093c, Stride: 1 },
    Range16 { Lo: 0x093e, Hi: 0x094c, Stride: 1 },
    Range16 { Lo: 0x094d, Hi: 0x094d, Stride: 1 },
    Range16 { Lo: 0x0951, Hi: 0x0954, Stride: 1 },
    Range16 { Lo: 0x0962, Hi: 0x0963, Stride: 1 },
    Range16 { Lo: 0x0966, Hi: 0x096f, Stride: 1 },
    Range16 { Lo: 0x0981, Hi: 0x0983, Stride: 1 },
    Range16 { Lo: 0x09bc, Hi: 0x09bc, Stride: 1 },
    Range16 { Lo: 0x09be, Hi: 0x09bf, Stride: 1 },
    Range16 { Lo: 0x09c0, Hi: 0x09c4, Stride: 1 },
    Range16 { Lo: 0x09c7, Hi: 0x09c8, Stride: 1 },
    Range16 { Lo: 0x09cb, Hi: 0x09cd, Stride: 1 },
    Range16 { Lo: 0x09d7, Hi: 0x09d7, Stride: 1 },
    Range16 { Lo: 0x09e2, Hi: 0x09e3, Stride: 1 },
    Range16 { Lo: 0x09e6, Hi: 0x09ef, Stride: 1 },
    Range16 { Lo: 0x0a02, Hi: 0x0a3c, Stride: 58 },
    Range16 { Lo: 0x0a3e, Hi: 0x0a3f, Stride: 1 },
    Range16 { Lo: 0x0a40, Hi: 0x0a42, Stride: 1 },
    Range16 { Lo: 0x0a47, Hi: 0x0a48, Stride: 1 },
    Range16 { Lo: 0x0a4b, Hi: 0x0a4d, Stride: 1 },
    Range16 { Lo: 0x0a66, Hi: 0x0a6f, Stride: 1 },
    Range16 { Lo: 0x0a70, Hi: 0x0a71, Stride: 1 },
    Range16 { Lo: 0x0a81, Hi: 0x0a83, Stride: 1 },
    Range16 { Lo: 0x0abc, Hi: 0x0abc, Stride: 1 },
    Range16 { Lo: 0x0abe, Hi: 0x0ac5, Stride: 1 },
    Range16 { Lo: 0x0ac7, Hi: 0x0ac9, Stride: 1 },
    Range16 { Lo: 0x0acb, Hi: 0x0acd, Stride: 1 },
    Range16 { Lo: 0x0ae6, Hi: 0x0aef, Stride: 1 },
    Range16 { Lo: 0x0b01, Hi: 0x0b03, Stride: 1 },
    Range16 { Lo: 0x0b3c, Hi: 0x0b3c, Stride: 1 },
    Range16 { Lo: 0x0b3e, Hi: 0x0b43, Stride: 1 },
    Range16 { Lo: 0x0b47, Hi: 0x0b48, Stride: 1 },
    Range16 { Lo: 0x0b4b, Hi: 0x0b4d, Stride: 1 },
    Range16 { Lo: 0x0b56, Hi: 0x0b57, Stride: 1 },
    Range16 { Lo: 0x0b66, Hi: 0x0b6f, Stride: 1 },
    Range16 { Lo: 0x0b82, Hi: 0x0b83, Stride: 1 },
    Range16 { Lo: 0x0bbe, Hi: 0x0bc2, Stride: 1 },
    Range16 { Lo: 0x0bc6, Hi: 0x0bc8, Stride: 1 },
    Range16 { Lo: 0x0bca, Hi: 0x0bcd, Stride: 1 },
    Range16 { Lo: 0x0bd7, Hi: 0x0bd7, Stride: 1 },
    Range16 { Lo: 0x0be7, Hi: 0x0bef, Stride: 1 },
    Range16 { Lo: 0x0c01, Hi: 0x0c03, Stride: 1 },
    Range16 { Lo: 0x0c3e, Hi: 0x0c44, Stride: 1 },
    Range16 { Lo: 0x0c46, Hi: 0x0c48, Stride: 1 },
    Range16 { Lo: 0x0c4a, Hi: 0x0c4d, Stride: 1 },
    Range16 { Lo: 0x0c55, Hi: 0x0c56, Stride: 1 },
    Range16 { Lo: 0x0c66, Hi: 0x0c6f, Stride: 1 },
    Range16 { Lo: 0x0c82, Hi: 0x0c83, Stride: 1 },
    Range16 { Lo: 0x0cbe, Hi: 0x0cc4, Stride: 1 },
    Range16 { Lo: 0x0cc6, Hi: 0x0cc8, Stride: 1 },
    Range16 { Lo: 0x0cca, Hi: 0x0ccd, Stride: 1 },
    Range16 { Lo: 0x0cd5, Hi: 0x0cd6, Stride: 1 },
    Range16 { Lo: 0x0ce6, Hi: 0x0cef, Stride: 1 },
    Range16 { Lo: 0x0d02, Hi: 0x0d03, Stride: 1 },
    Range16 { Lo: 0x0d3e, Hi: 0x0d43, Stride: 1 },
    Range16 { Lo: 0x0d46, Hi: 0x0d48, Stride: 1 },
    Range16 { Lo: 0x0d4a, Hi: 0x0d4d, Stride: 1 },
    Range16 { Lo: 0x0d57, Hi: 0x0d57, Stride: 1 },
    Range16 { Lo: 0x0d66, Hi: 0x0d6f, Stride: 1 },
    Range16 { Lo: 0x0e31, Hi: 0x0e31, Stride: 1 },
    Range16 { Lo: 0x0e34, Hi: 0x0e3a, Stride: 1 },
    Range16 { Lo: 0x0e46, Hi: 0x0e46, Stride: 1 },
    Range16 { Lo: 0x0e47, Hi: 0x0e4e, Stride: 1 },
    Range16 { Lo: 0x0e50, Hi: 0x0e59, Stride: 1 },
    Range16 { Lo: 0x0eb1, Hi: 0x0eb1, Stride: 1 },
    Range16 { Lo: 0x0eb4, Hi: 0x0eb9, Stride: 1 },
    Range16 { Lo: 0x0ebb, Hi: 0x0ebc, Stride: 1 },
    Range16 { Lo: 0x0ec6, Hi: 0x0ec6, Stride: 1 },
    Range16 { Lo: 0x0ec8, Hi: 0x0ecd, Stride: 1 },
    Range16 { Lo: 0x0ed0, Hi: 0x0ed9, Stride: 1 },
    Range16 { Lo: 0x0f18, Hi: 0x0f19, Stride: 1 },
    Range16 { Lo: 0x0f20, Hi: 0x0f29, Stride: 1 },
    Range16 { Lo: 0x0f35, Hi: 0x0f39, Stride: 2 },
    Range16 { Lo: 0x0f3e, Hi: 0x0f3f, Stride: 1 },
    Range16 { Lo: 0x0f71, Hi: 0x0f84, Stride: 1 },
    Range16 { Lo: 0x0f86, Hi: 0x0f8b, Stride: 1 },
    Range16 { Lo: 0x0f90, Hi: 0x0f95, Stride: 1 },
    Range16 { Lo: 0x0f97, Hi: 0x0f97, Stride: 1 },
    Range16 { Lo: 0x0f99, Hi: 0x0fad, Stride: 1 },
    Range16 { Lo: 0x0fb1, Hi: 0x0fb7, Stride: 1 },
    Range16 { Lo: 0x0fb9, Hi: 0x0fb9, Stride: 1 },
    Range16 { Lo: 0x20d0, Hi: 0x20dc, Stride: 1 },
    Range16 { Lo: 0x20e1, Hi: 0x3005, Stride: 3876 },
    Range16 { Lo: 0x302a, Hi: 0x302f, Stride: 1 },
    Range16 { Lo: 0x3031, Hi: 0x3035, Stride: 1 },
    Range16 { Lo: 0x3099, Hi: 0x309a, Stride: 1 },
    Range16 { Lo: 0x309d, Hi: 0x309e, Stride: 1 },
    Range16 { Lo: 0x30fc, Hi: 0x30fe, Stride: 1 },
];

pub static SECOND: RangeTable = RangeTable {
    R16: &SECOND_R16,
    R32: &[],
    LatinOffset: 0,
};

// go: sdk 1.25.5 encoding/xml/xml.go:1236-1258 isName
/// Go: whether `s` is a valid XML name — the first rune from `first`,
/// every later rune from `first` or `second`.
///
/// The invalid-UTF-8 rule is the same one `escapeText` uses and is easy
/// to miss: `DecodeRune` returning (RuneError, 1) means a bad byte, and
/// that is rejected, while a genuine encoded U+FFFD (width 3) is put to
/// the tables like any other rune — where it happens to fail anyway.
pub fn isName(s: &[byte]) -> bool {
    if s.is_empty() {
        return false;
    }
    let (c, n) = crate::unicode::utf8::DecodeRune(s);
    if c == crate::unicode::utf8::RuneError && n == 1 {
        return false;
    }
    if !crate::unicode::Is(&FIRST, c) {
        return false;
    }
    let mut off = n as usize;
    while off < s.len() {
        let (c, n) = crate::unicode::utf8::DecodeRune(&s[off..]);
        if c == crate::unicode::utf8::RuneError && n == 1 {
            return false;
        }
        if !crate::unicode::Is(&FIRST, c) && !crate::unicode::Is(&SECOND, c) {
            return false;
        }
        off += n as usize;
    }
    return true;
}

// go: sdk 1.25.5 encoding/xml/xml.go:1260-1282 isNameString
/// Go: `isName` over a string rather than a byte slice. Go keeps both
/// to avoid a conversion on each call; goish keeps both because Go's
/// API has both, and this one simply forwards.
pub fn isNameString(s: &str) -> bool {
    return isName(s.as_bytes());
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
