// go: file encoding/xml/xml.go decls: SyntaxError.Error, StartElement.Copy, StartElement.End, CharData.Copy, Comment.Copy, ProcInst.Copy, Directive.Copy, CopyToken, NewDecoder, NewTokenDecoder, Decoder.Token, Decoder.translate, Decoder.switchToReader, Decoder.push, Decoder.pop, Decoder.pushEOF, Decoder.popEOF, Decoder.pushElement, Decoder.pushNs, Decoder.syntaxError, Decoder.popElement, Decoder.autoClose, Decoder.RawToken, Decoder.rawToken, Decoder.attrval, Decoder.space, Decoder.getc, Decoder.InputOffset, Decoder.InputPos, Decoder.savedOffset, Decoder.mustgetc, Decoder.ungetc, Decoder.text, isInCharacterRange, Decoder.nsname, Decoder.name, Decoder.readName, isNameByte, isName, isNameString, EscapeText, escapeText, printer.EscapeString, Escape, emitCDATA, procInst
//
// encoding/xml/xml.go — the tokenizer: a byte-at-a-time XML 1.0 lexer
// with name-space translation, and the escaping helpers the encoder
// shares with it.
//
// The lexer is a direct port. What a plausible port gets wrong, and what
// this one keeps:
//
//   * `Token` and `RawToken` are different layers. RawToken is the lexer
//     alone; Token adds the element-balance check, name-space
//     translation (prefix -> URL, with the xmlns declarations in the same
//     start tag applying to that tag's own name), and — when
//     `Strict == false` — AutoClose. A self-closing `<a/>` is TWO tokens.
//   * Character data is normalised on the way in: `\r\n` and a lone `\r`
//     both become `\n`, entities are expanded, and every rune is checked
//     against the XML Char production. Only the five predefined entities
//     are known unless `Entity` adds more; in non-strict mode an unknown
//     one is left as written.
//   * A directive (`<!DOCTYPE …>`) nests on unquoted `<`/`>` and has any
//     embedded comment replaced by ONE space, so re-encoding it cannot
//     splice two markup fragments into a new one.
//
// ─── Deviations, all forced by the Rust shape ─────────────────────────
//
//   * `Token` is Go's `any` holding one of six types. goish spells it as
//     an enum with one variant per type plus `Nil`; a Go type switch is a
//     `match`. `CharData`, `Comment` and `Directive` are `[]byte`
//     newtypes whose `.0` is the slice.
//
//   * Token data does not alias the decoder's buffer. Go documents that
//     the bytes in a returned token are only valid until the next call;
//     goish slices never share backing, so every token owns its bytes
//     and `Copy`/`CopyToken` are plain clones. That is strictly safer
//     than Go and indistinguishable to a caller that follows Go's rule.
//
//   * `switchToReader` always wraps the reader in a `bufio.Reader`. Go
//     uses the reader directly when it already implements
//     `io.ByteReader`. The tokens, offsets and errors are identical
//     either way; what differs is that goish may read ahead of the
//     current token in the underlying reader.
//
//   * `CharsetReader` is `Option<fn(…)>`: Go's func-typed field with no
//     closure capture, `None` for nil. The reader it receives and returns
//     is boxed, since Go's is an interface value; a nil Reader cannot be
//     returned, so the panic Go raises for one has nothing to catch.
//
//   * The element stack is a `Vec<stack>` with the top at the end rather
//     than a linked list of `*stack` with a `free` list. `pushEOF` is an
//     insert below the top; `free` existed to recycle nodes, which the
//     Vec's retained capacity already does.
//
// goishlint:ignore GOISH021 free — the linked-list node cache; see the stack note above.
// goishlint:ignore GOISH021 Token — Go's `type Token any` is the `Token` enum below; there is no alias to declare.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::marshal::printer;
use crate::bufio;
use crate::bytes;
use crate::convert::{byte as tobyte, int as toint, rune as torune};
use crate::errors::{error, nil, ErrorTrait, Wrap};
use crate::fmt;
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::strconv;
use crate::strings;
use crate::types::{byte, int, int64, rune};
use crate::unicode;
use crate::unicode::utf8;

// go: sdk 1.25.5 encoding/xml/xml.go:26-29 SyntaxError
/// A SyntaxError represents a syntax error in the XML input stream.
#[derive(Clone, Debug, PartialEq)]
pub struct SyntaxError {
    pub Msg: string,
    pub Line: int,
}

impl ErrorTrait for SyntaxError {
    // go: sdk 1.25.5 encoding/xml/xml.go:31-33 SyntaxError.Error
    fn Error(&self) -> string {
        return string::from("XML syntax error on line ")
            + strconv::Itoa(self.Line)
            + ": "
            + self.Msg.clone();
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:40-42 Name
/// A Name represents an XML name (Local) annotated with a name space
/// identifier (Space). In tokens returned by [`Decoder::Token`], the
/// Space identifier is given as a canonical URL, not the short prefix
/// used in the document being parsed.
///
/// `#[goish::reflect]` so a user struct can carry an `XMLName: xml::Name`
/// field — which is how Go names an element — and still be reflected.
#[goish::reflect]
#[derive(PartialEq, Eq, Debug)]
pub struct Name {
    pub Space: string,
    pub Local: string,
}

// go: sdk 1.25.5 encoding/xml/xml.go:45-48 Attr
/// An Attr represents an attribute in an XML element (Name=Value).
#[goish::reflect]
#[derive(PartialEq, Eq, Debug)]
pub struct Attr {
    pub Name: Name,
    pub Value: string,
}

/// A Token holds one of the token types: [`StartElement`],
/// [`EndElement`], [`CharData`], [`Comment`], [`ProcInst`], or
/// [`Directive`] — or `Nil`, Go's nil `Token`.
#[derive(Clone, Default, PartialEq)]
pub enum Token {
    #[default]
    Nil,
    StartElement(StartElement),
    EndElement(EndElement),
    CharData(CharData),
    Comment(Comment),
    ProcInst(ProcInst),
    Directive(Directive),
}

impl From<crate::nilval::Nil> for Token {
    fn from(_: crate::nilval::Nil) -> Self {
        return Token::Nil;
    }
}

impl PartialEq<crate::nilval::Nil> for Token {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        return matches!(self, Token::Nil);
    }
}

impl PartialEq<Token> for crate::nilval::Nil {
    fn eq(&self, other: &Token) -> bool {
        return matches!(other, Token::Nil);
    }
}

impl From<StartElement> for Token {
    fn from(t: StartElement) -> Self {
        return Token::StartElement(t);
    }
}

impl From<EndElement> for Token {
    fn from(t: EndElement) -> Self {
        return Token::EndElement(t);
    }
}

impl From<CharData> for Token {
    fn from(t: CharData) -> Self {
        return Token::CharData(t);
    }
}

impl From<Comment> for Token {
    fn from(t: Comment) -> Self {
        return Token::Comment(t);
    }
}

impl From<ProcInst> for Token {
    fn from(t: ProcInst) -> Self {
        return Token::ProcInst(t);
    }
}

impl From<Directive> for Token {
    fn from(t: Directive) -> Self {
        return Token::Directive(t);
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:55-58 StartElement
/// A StartElement represents an XML start element.
#[derive(Clone, Default, PartialEq)]
pub struct StartElement {
    pub Name: Name,
    pub Attr: slice<Attr>,
}

impl StartElement {
    // go: sdk 1.25.5 encoding/xml/xml.go:61-66 StartElement.Copy
    /// Copy creates a new copy of StartElement.
    pub fn Copy(&self) -> StartElement {
        let mut e = self.clone();
        let mut attrs: Vec<Attr> = Vec::with_capacity(self.Attr.len());
        attrs.extend_from_slice(&self.Attr);
        e.Attr = slice::__from_vec(attrs);
        return e;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:69-71 StartElement.End
    /// End returns the corresponding XML end element.
    pub fn End(&self) -> EndElement {
        return EndElement {
            Name: self.Name.clone(),
        };
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:74-76 EndElement
/// An EndElement represents an XML end element.
#[derive(Clone, Default, PartialEq)]
pub struct EndElement {
    pub Name: Name,
}

// go: sdk 1.25.5 encoding/xml/xml.go:81-81 CharData
/// A CharData represents XML character data (raw text), in which XML
/// escape sequences have been replaced by the characters they represent.
#[derive(Clone, Default, PartialEq)]
pub struct CharData(pub slice<byte>);

impl CharData {
    // go: sdk 1.25.5 encoding/xml/xml.go:84-84 CharData.Copy
    /// Copy creates a new copy of CharData.
    pub fn Copy(&self) -> CharData {
        return CharData(bytes::Clone(self.0.clone()));
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:88-88 Comment
/// A Comment represents an XML comment of the form `<!--comment-->`.
/// The bytes do not include the `<!--` and `-->` comment markers.
#[derive(Clone, Default, PartialEq)]
pub struct Comment(pub slice<byte>);

impl Comment {
    // go: sdk 1.25.5 encoding/xml/xml.go:91-91 Comment.Copy
    /// Copy creates a new copy of Comment.
    pub fn Copy(&self) -> Comment {
        return Comment(bytes::Clone(self.0.clone()));
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:94-97 ProcInst
/// A ProcInst represents an XML processing instruction of the form
/// `<?target inst?>`.
#[derive(Clone, Default, PartialEq)]
pub struct ProcInst {
    pub Target: string,
    pub Inst: slice<byte>,
}

impl ProcInst {
    // go: sdk 1.25.5 encoding/xml/xml.go:100-103 ProcInst.Copy
    /// Copy creates a new copy of ProcInst.
    pub fn Copy(&self) -> ProcInst {
        let mut p = self.clone();
        p.Inst = bytes::Clone(self.Inst.clone());
        return p;
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:107-107 Directive
/// A Directive represents an XML directive of the form `<!text>`.
/// The bytes do not include the `<!` and `>` markers.
#[derive(Clone, Default, PartialEq)]
pub struct Directive(pub slice<byte>);

impl Directive {
    // go: sdk 1.25.5 encoding/xml/xml.go:110-110 Directive.Copy
    /// Copy creates a new copy of Directive.
    pub fn Copy(&self) -> Directive {
        return Directive(bytes::Clone(self.0.clone()));
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:113-127 CopyToken
/// CopyToken returns a copy of a Token.
pub fn CopyToken(t: Token) -> Token {
    return match t {
        Token::CharData(v) => Token::CharData(v.Copy()),
        Token::Comment(v) => Token::Comment(v.Copy()),
        Token::Directive(v) => Token::Directive(v.Copy()),
        Token::ProcInst(v) => Token::ProcInst(v.Copy()),
        Token::StartElement(v) => Token::StartElement(v.Copy()),
        other => other,
    };
}

// go: sdk 1.25.5 encoding/xml/xml.go:142-144 TokenReader
/// A TokenReader is anything that can decode a stream of XML tokens,
/// including a [`Decoder`].
///
/// When Token encounters an error or end-of-file condition after
/// successfully reading a token, it returns the token. It may return the
/// (non-nil) error from the same call or return the error (and a nil
/// token) from a subsequent call.
#[goish::interface]
pub trait TokenReader {
    fn Token(&mut self) -> (Token, error);
}

// go: sdk 1.25.5 encoding/xml/xml.go:148-216 Decoder
/// A Decoder represents an XML parser reading a particular input stream.
/// The parser assumes that its input is encoded in UTF-8.
pub struct Decoder {
    /// Strict defaults to true, enforcing the requirements of the XML
    /// specification. If set to false, the parser allows input containing
    /// common mistakes: missing end tags are invented, and unknown or
    /// malformed character entities are left alone.
    ///
    /// Setting `Strict = false`, `AutoClose = HTMLAutoClose` and
    /// `Entity = HTMLEntity` creates a parser that can handle typical HTML.
    pub Strict: bool,

    /// When Strict == false, AutoClose indicates a set of elements to
    /// consider closed immediately after they are opened, regardless of
    /// whether an end element is present.
    pub AutoClose: slice<string>,

    /// Entity can be used to map non-standard entity names to string
    /// replacements. `lt`, `gt`, `amp`, `apos` and `quot` are always
    /// recognised regardless of the map's contents.
    pub Entity: map<string, string>,

    /// CharsetReader, if set, generates charset-conversion readers,
    /// converting from the provided non-UTF-8 charset into UTF-8. If it
    /// is None or returns an error, parsing stops with an error.
    pub CharsetReader: Option<fn(string, Box<dyn io::Reader>) -> (Box<dyn io::Reader>, error)>,

    /// DefaultSpace sets the default name space used for unadorned tags,
    /// as if the entire XML stream were wrapped in an element containing
    /// the attribute `xmlns="DefaultSpace"`.
    pub DefaultSpace: string,

    r: Option<bufio::Reader<Box<dyn io::Reader>>>,
    t: Option<Box<dyn TokenReader>>,
    pub(super) buf: bytes::Buffer,
    pub(super) saved: Option<bytes::Buffer>,
    stk: Vec<stack>,
    needClose: bool,
    toClose: Name,
    nextToken: Token,
    nextByte: int,
    ns: map<string, string>,
    err: error,
    line: int,
    linestart: int64,
    offset: int64,
    pub(super) unmarshalDepth: int,
}

// go: none — goish idiom: the `&Decoder{ns: …, nextByte: -1, line: 1,
//     Strict: true}` literal both constructors start from; Go writes it
//     out twice.
fn newDecoderState() -> Decoder {
    return Decoder {
        Strict: true,
        AutoClose: slice::new(),
        Entity: map::new(),
        CharsetReader: None,
        DefaultSpace: string::new(),
        r: None,
        t: None,
        buf: bytes::Buffer::default(),
        saved: None,
        stk: Vec::new(),
        needClose: false,
        toClose: Name::default(),
        nextToken: Token::Nil,
        nextByte: -1,
        ns: map::new(),
        err: nil,
        line: 1,
        linestart: 0,
        offset: 0,
        unmarshalDepth: 0,
    };
}

// go: sdk 1.25.5 encoding/xml/xml.go:221-230 NewDecoder
/// NewDecoder creates a new XML parser reading from r.
pub fn NewDecoder<R: io::Reader + 'static>(r: R) -> Decoder {
    let mut d = newDecoderState();
    d.switchToReader(Box::new(r));
    return d;
}

// go: sdk 1.25.5 encoding/xml/xml.go:233-246 NewTokenDecoder
/// NewTokenDecoder creates a new XML parser using an underlying token
/// stream.
///
/// Go returns the argument itself when it is already a `*Decoder`; the
/// same holds here — a `Decoder` passed by value comes back unchanged
/// rather than wrapped.
pub fn NewTokenDecoder<T: TokenReader + 'static>(t: T) -> Decoder {
    // Is it already a Decoder?
    let mut slot: Option<T> = Some(t);
    if let Some(d) = (&mut slot as &mut dyn core::any::Any).downcast_mut::<Option<Decoder>>() {
        if let Some(d) = d.take() {
            return d;
        }
    }
    let mut d = newDecoderState();
    if let Some(t) = slot {
        d.t = Some(Box::new(t));
    }
    return d;
}

impl TokenReader for Decoder {
    // go: none — forwards to the inherent `Decoder::Token`, which is the
    //     one implementation.
    fn Token(&mut self) -> (Token, error) {
        return Decoder::Token(self);
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:336-340 xmlURL
pub(super) const xmlURL: &str = "http://www.w3.org/XML/1998/namespace";
// go: sdk 1.25.5 encoding/xml/xml.go:336-340 xmlnsPrefix
pub(super) const xmlnsPrefix: &str = "xmlns";
// go: sdk 1.25.5 encoding/xml/xml.go:336-340 xmlPrefix
pub(super) const xmlPrefix: &str = "xml";

// go: sdk 1.25.5 encoding/xml/xml.go:379-384 stack
/// Parsing state — the stack holds old name space translations and the
/// current set of open elements. `next` is implicit: it is the entry
/// below this one in `Decoder.stk`.
#[derive(Clone, Default)]
struct stack {
    kind: int,
    name: Name,
    ok: bool,
}

// go: sdk 1.25.5 encoding/xml/xml.go:386-390 stkStart
const stkStart: int = 0;
// go: sdk 1.25.5 encoding/xml/xml.go:386-390 stkNs
const stkNs: int = 1;
// go: sdk 1.25.5 encoding/xml/xml.go:386-390 stkEOF
const stkEOF: int = 2;

// go: sdk 1.25.5 encoding/xml/xml.go:539-539 errRawToken
crate::var! {
    errRawToken: error = "xml: cannot use RawToken from UnmarshalXML method";
}

// go: sdk 1.25.5 encoding/xml/xml.go:977-983 entity
static entity: [(&str, rune); 5] = [
    ("lt", 0x3C),   // '<'
    ("gt", 0x3E),   // '>'
    ("amp", 0x26),  // '&'
    ("apos", 0x27), // '\''
    ("quot", 0x22), // '"'
];

// go: none — goish idiom: `r, ok := entity[s]` over the five-entry
//     table above.
fn lookupEntity(s: &string) -> (rune, bool) {
    for (_, e) in crate::range!(entity) {
        if *s == e.0 {
            return (e.1, true);
        }
    }
    return (0, false);
}

impl Decoder {
    // go: sdk 1.25.5 encoding/xml/xml.go:274-334 Decoder.Token
    /// Token returns the next XML token in the input stream. At the end
    /// of the input stream, Token returns `Nil, io.EOF`.
    ///
    /// Token expands self-closing elements such as `<br/>` into separate
    /// start and end elements returned by successive calls, guarantees
    /// that the start and end elements it returns are properly nested and
    /// matched, and translates name space prefixes into their URLs. An
    /// unrecognized prefix is used as the Space rather than reported.
    pub fn Token(&mut self) -> (Token, error) {
        let mut t: Token;
        let mut err: error = nil;
        if let Some(top) = self.stk.last() {
            if top.kind == stkEOF {
                return (Token::Nil, io::EOF.into());
            }
        }
        if self.nextToken != Token::Nil {
            t = core::mem::take(&mut self.nextToken);
        } else {
            let (t0, e0) = self.rawToken();
            t = t0;
            err = e0;
            if t == Token::Nil && err != nil {
                if err == io::EOF {
                    if let Some(top) = self.stk.last() {
                        if top.kind != stkEOF {
                            err = self.syntaxError("unexpected EOF");
                        }
                    }
                }
                return (Token::Nil, err);
            }
            // We still have a token to process, so clear any
            // errors (e.g. EOF) and proceed.
            err = nil;
        }
        if !self.Strict {
            let (t1, ok) = self.autoClose(&t);
            if ok {
                self.nextToken = t;
                t = t1;
            }
        }
        match t {
            Token::StartElement(mut t1) => {
                // In XML name spaces, the translations listed in the
                // attributes apply to the element name and to the other
                // attribute names, so process the translations first.
                for (_, a) in crate::range!(t1.Attr) {
                    if a.Name.Space == xmlnsPrefix {
                        let (v, ok) = self.ns.Get(a.Name.Local.clone());
                        self.pushNs(a.Name.Local.clone(), v, ok);
                        self.ns.Set(a.Name.Local.clone(), a.Value.clone());
                    }
                    if a.Name.Space == "" && a.Name.Local == xmlnsPrefix {
                        // Default space for untagged names
                        let (v, ok) = self.ns.Get("");
                        self.pushNs(string::new(), v, ok);
                        self.ns.Set("", a.Value.clone());
                    }
                }

                self.pushElement(t1.Name.clone());
                self.translate(&mut t1.Name, true);
                let mut i: int = 0;
                while i < t1.Attr.Len() {
                    self.translate(&mut t1.Attr[i].Name, false);
                    i += 1;
                }
                t = Token::StartElement(t1);
            }
            Token::EndElement(mut t1) => {
                if !self.popElement(&mut t1) {
                    return (Token::Nil, self.err.clone());
                }
                t = Token::EndElement(t1);
            }
            other => {
                t = other;
            }
        }
        return (t, err);
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:345-361 Decoder.translate
    /// Apply name space translation to name n. The default name space
    /// (for Space=="") applies only to element names, not to attribute
    /// names.
    fn translate(&self, n: &mut Name, isElementName: bool) {
        if n.Space == xmlnsPrefix {
            return;
        } else if n.Space == "" && !isElementName {
            return;
        } else if n.Space == xmlPrefix {
            n.Space = string::from(xmlURL);
        } else if n.Space == "" && n.Local == xmlnsPrefix {
            return;
        }
        let (v, ok) = self.ns.Get(n.Space.clone());
        if ok {
            n.Space = v;
        } else if n.Space == "" {
            n.Space = self.DefaultSpace.clone();
        }
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:363-373 Decoder.switchToReader
    fn switchToReader(&mut self, r: Box<dyn io::Reader>) {
        // Get efficient byte at a time reader. Go uses r directly when it
        // implements io.ByteReader; goish always buffers (see the file
        // banner), which yields the same bytes in the same order.
        self.r = Some(bufio::NewReader(r));
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:392-403 Decoder.push
    fn push(&mut self, kind: int) -> &mut stack {
        self.stk.push(stack {
            kind,
            name: Name::default(),
            ok: false,
        });
        let n = self.stk.len();
        return &mut self.stk[n - 1];
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:405-413 Decoder.pop
    fn pop(&mut self) -> Option<stack> {
        return self.stk.pop();
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:418-440 Decoder.pushEOF
    /// Record that after the current element is finished (that element is
    /// already pushed on the stack) Token should return EOF until popEOF
    /// is called.
    pub(super) fn pushEOF(&mut self) {
        // Walk down stack to find Start. It might not be the top, because
        // there might be stkNs entries above it.
        let mut start = self.stk.len() - 1;
        while self.stk[start].kind != stkStart {
            start -= 1;
        }
        // The stkNs entries below a start are associated with that
        // element too; skip over them.
        while start > 0 && self.stk[start - 1].kind == stkNs {
            start -= 1;
        }
        self.stk.insert(
            start,
            stack {
                kind: stkEOF,
                name: Name::default(),
                ok: false,
            },
        );
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:444-450 Decoder.popEOF
    /// Undo a pushEOF. The element must have been finished, so the EOF
    /// should be at the top of the stack.
    pub(super) fn popEOF(&mut self) -> bool {
        match self.stk.last() {
            Some(top) if top.kind == stkEOF => {}
            _ => return false,
        }
        self.pop();
        return true;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:453-456 Decoder.pushElement
    /// Record that we are starting an element with the given name.
    fn pushElement(&mut self, name: Name) {
        let s = self.push(stkStart);
        s.name = name;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:460-465 Decoder.pushNs
    /// Record that we are changing the value of ns[local]. The old value
    /// is url, ok.
    fn pushNs(&mut self, local: string, url: string, ok: bool) {
        let s = self.push(stkNs);
        s.name.Local = local;
        s.name.Space = url;
        s.ok = ok;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:468-470 Decoder.syntaxError
    /// Creates a SyntaxError with the current line number.
    fn syntaxError<S: Into<string>>(&self, msg: S) -> error {
        return Wrap(SyntaxError {
            Msg: msg.into(),
            Line: self.line,
        });
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:478-518 Decoder.popElement
    /// Record that we are ending an element with the given name. The name
    /// must match the record at the top of the stack, which must be a
    /// pushElement record. After popping the element, apply any undo
    /// records from the stack to restore the name translations that
    /// existed before we saw this element.
    fn popElement(&mut self, t: &mut EndElement) -> bool {
        let s = self.pop();
        let name = t.Name.clone();
        match s {
            None => {
                self.err = self.syntaxError(string::from("unexpected end element </") + name.Local + ">");
                return false;
            }
            Some(ref s) if s.kind != stkStart => {
                self.err = self.syntaxError(string::from("unexpected end element </") + name.Local + ">");
                return false;
            }
            Some(ref s) if s.name.Local != name.Local => {
                if !self.Strict {
                    self.needClose = true;
                    self.toClose = t.Name.clone();
                    t.Name = s.name.clone();
                    return true;
                }
                self.err = self.syntaxError(
                    string::from("element <") + s.name.Local.clone() + "> closed by </" + name.Local + ">",
                );
                return false;
            }
            Some(ref s) if s.name.Space != name.Space => {
                let mut ns = name.Space.clone();
                if name.Space == "" {
                    ns = string::from("\"\"");
                }
                self.err = self.syntaxError(
                    string::from("element <")
                        + s.name.Local.clone()
                        + "> in space "
                        + s.name.Space.clone()
                        + " closed by </"
                        + name.Local
                        + "> in space "
                        + ns,
                );
                return false;
            }
            Some(_) => {}
        }

        self.translate(&mut t.Name, true);

        // Pop stack until a Start or EOF is on the top, undoing the
        // translations that were associated with the element we just
        // closed.
        loop {
            match self.stk.last() {
                Some(top) if top.kind != stkStart && top.kind != stkEOF => {}
                _ => break,
            }
            let s = self.pop().unwrap();
            if s.ok {
                self.ns.Set(s.name.Local, s.name.Space);
            } else {
                self.ns.Delete(s.name.Local);
            }
        }

        return true;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:522-537 Decoder.autoClose
    /// If the top element on the stack is autoclosing and t is not the
    /// end tag, invent the end tag.
    fn autoClose(&self, t: &Token) -> (Token, bool) {
        let top = match self.stk.last() {
            Some(top) if top.kind == stkStart => top,
            _ => return (Token::Nil, false),
        };
        for (_, s) in crate::range!(self.AutoClose) {
            if strings::EqualFold(s, &top.name.Local) {
                // This one should be auto closed if t doesn't close it.
                let closes = match t {
                    Token::EndElement(et) => strings::EqualFold(&et.Name.Local, &top.name.Local),
                    _ => false,
                };
                if !closes {
                    return (
                        Token::EndElement(EndElement {
                            Name: top.name.clone(),
                        }),
                        true,
                    );
                }
                break;
            }
        }
        return (Token::Nil, false);
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:544-549 Decoder.RawToken
    /// RawToken is like [`Decoder::Token`] but does not verify that start
    /// and end elements match and does not translate name space prefixes
    /// to their corresponding URLs.
    pub fn RawToken(&mut self) -> (Token, error) {
        if self.unmarshalDepth > 0 {
            return (Token::Nil, errRawToken.into());
        }
        return self.rawToken();
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:551-851 Decoder.rawToken
    fn rawToken(&mut self) -> (Token, error) {
        if let Some(t) = &mut self.t {
            return t.Token();
        }
        if self.err != nil {
            return (Token::Nil, self.err.clone());
        }
        if self.needClose {
            // The last element we read was self-closing and we returned
            // just the StartElement half. Return the EndElement half now.
            self.needClose = false;
            return (
                Token::EndElement(EndElement {
                    Name: self.toClose.clone(),
                }),
                nil,
            );
        }

        let (mut b, mut ok) = self.getc();
        if !ok {
            return (Token::Nil, self.err.clone());
        }

        if b != b'<' {
            // Text section.
            self.ungetc(b);
            return match self.text(-1, false) {
                None => (Token::Nil, self.err.clone()),
                Some(data) => (Token::CharData(CharData(data)), nil),
            };
        }

        (b, ok) = self.mustgetc();
        if !ok {
            return (Token::Nil, self.err.clone());
        }
        match b {
            b'/' => {
                // </: End element
                let name: Name;
                (name, ok) = self.nsname();
                if !ok {
                    if self.err == nil {
                        self.err = self.syntaxError("expected element name after </");
                    }
                    return (Token::Nil, self.err.clone());
                }
                self.space();
                (b, ok) = self.mustgetc();
                if !ok {
                    return (Token::Nil, self.err.clone());
                }
                if b != b'>' {
                    self.err = self.syntaxError(
                        string::from("invalid characters between </") + name.Local + " and >",
                    );
                    return (Token::Nil, self.err.clone());
                }
                return (Token::EndElement(EndElement { Name: name }), nil);
            }

            b'?' => {
                // <?: Processing instruction.
                let target: string;
                (target, ok) = self.name();
                if !ok {
                    if self.err == nil {
                        self.err = self.syntaxError("expected target name after <?");
                    }
                    return (Token::Nil, self.err.clone());
                }
                self.space();
                self.buf.Reset();
                let mut b0: byte = 0;
                loop {
                    (b, ok) = self.mustgetc();
                    if !ok {
                        return (Token::Nil, self.err.clone());
                    }
                    self.buf.WriteByte(b);
                    if b0 == b'?' && b == b'>' {
                        break;
                    }
                    b0 = b;
                }
                let mut data = self.buf.Bytes();
                data = data.slice(0, data.Len() - 2); // chop ?>

                if target == "xml" {
                    let content = string::from_bytes(&data);
                    let ver = procInst("version", content.clone());
                    if ver != "" && ver != "1.0" {
                        self.err = fmt::Errorf!(
                            "xml: unsupported version %q; only version 1.0 is supported",
                            ver
                        );
                        return (Token::Nil, self.err.clone());
                    }
                    let enc = procInst("encoding", content);
                    if enc != "" && enc != "utf-8" && enc != "UTF-8" && !strings::EqualFold(&enc, "utf-8") {
                        let charsetReader = match self.CharsetReader {
                            None => {
                                self.err = fmt::Errorf!(
                                    "xml: encoding %q declared but Decoder.CharsetReader is nil",
                                    enc
                                );
                                return (Token::Nil, self.err.clone());
                            }
                            Some(f) => f,
                        };
                        let cur: Box<dyn io::Reader> = match self.r.take() {
                            Some(r) => Box::new(r),
                            None => Box::new(bytes::NewReader(slice::new())),
                        };
                        let (newr, err) = charsetReader(enc.clone(), cur);
                        if err != nil {
                            self.err = fmt::Errorf!("xml: opening charset %q: %w", enc, err);
                            return (Token::Nil, self.err.clone());
                        }
                        self.switchToReader(newr);
                    }
                }
                return (
                    Token::ProcInst(ProcInst {
                        Target: target,
                        Inst: data,
                    }),
                    nil,
                );
            }

            b'!' => {
                // <!: Maybe comment, maybe CDATA.
                (b, ok) = self.mustgetc();
                if !ok {
                    return (Token::Nil, self.err.clone());
                }
                match b {
                    b'-' => {
                        // <!-
                        // Probably <!-- for a comment.
                        (b, ok) = self.mustgetc();
                        if !ok {
                            return (Token::Nil, self.err.clone());
                        }
                        if b != b'-' {
                            self.err = self.syntaxError("invalid sequence <!- not part of <!--");
                            return (Token::Nil, self.err.clone());
                        }
                        // Look for terminator.
                        self.buf.Reset();
                        let mut b0: byte = 0;
                        let mut b1: byte = 0;
                        loop {
                            (b, ok) = self.mustgetc();
                            if !ok {
                                return (Token::Nil, self.err.clone());
                            }
                            self.buf.WriteByte(b);
                            if b0 == b'-' && b1 == b'-' {
                                if b != b'>' {
                                    self.err = self.syntaxError(
                                        "invalid sequence \"--\" not allowed in comments",
                                    );
                                    return (Token::Nil, self.err.clone());
                                }
                                break;
                            }
                            (b0, b1) = (b1, b);
                        }
                        let mut data = self.buf.Bytes();
                        data = data.slice(0, data.Len() - 3); // chop -->
                        return (Token::Comment(Comment(data)), nil);
                    }

                    b'[' => {
                        // <![
                        // Probably <![CDATA[.
                        let cdata = b"CDATA[";
                        let mut i: int = 0;
                        while i < 6 {
                            (b, ok) = self.mustgetc();
                            if !ok {
                                return (Token::Nil, self.err.clone());
                            }
                            if b != cdata[i as usize] {
                                self.err = self.syntaxError("invalid <![ sequence");
                                return (Token::Nil, self.err.clone());
                            }
                            i += 1;
                        }
                        // Have <![CDATA[.  Read text until ]]>.
                        return match self.text(-1, true) {
                            None => (Token::Nil, self.err.clone()),
                            Some(data) => (Token::CharData(CharData(data)), nil),
                        };
                    }
                    _ => {}
                }

                // Probably a directive: <!DOCTYPE ...>, <!ENTITY ...>, etc.
                // We don't care, but accumulate for caller. Quoted angle
                // brackets do not count for nesting.
                self.buf.Reset();
                self.buf.WriteByte(b);
                let mut inquote: byte = 0;
                let mut depth: int = 0;
                loop {
                    (b, ok) = self.mustgetc();
                    if !ok {
                        return (Token::Nil, self.err.clone());
                    }
                    if inquote == 0 && b == b'>' && depth == 0 {
                        break;
                    }
                    // Go: the `HandleB:` label. A `goto HandleB` re-enters
                    // here with a new b, skipping the depth-0 `>` test
                    // above — which is exactly `continue 'HandleB`.
                    'HandleB: loop {
                        self.buf.WriteByte(b);
                        if b == inquote {
                            inquote = 0;
                        } else if inquote != 0 {
                            // in quotes, no special action
                        } else if b == b'\'' || b == b'"' {
                            inquote = b;
                        } else if b == b'>' && inquote == 0 {
                            depth -= 1;
                        } else if b == b'<' && inquote == 0 {
                            // Look for <!-- to begin comment.
                            let s = b"!--";
                            let mut i: int = 0;
                            while i < toint(s.len()) {
                                (b, ok) = self.mustgetc();
                                if !ok {
                                    return (Token::Nil, self.err.clone());
                                }
                                if b != s[i as usize] {
                                    let mut j: int = 0;
                                    while j < i {
                                        self.buf.WriteByte(s[j as usize]);
                                        j += 1;
                                    }
                                    depth += 1;
                                    continue 'HandleB;
                                }
                                i += 1;
                            }

                            // Remove < that was written above.
                            let n = self.buf.Len();
                            self.buf.Truncate(n - 1);

                            // Look for terminator.
                            let mut b0: byte = 0;
                            let mut b1: byte = 0;
                            loop {
                                (b, ok) = self.mustgetc();
                                if !ok {
                                    return (Token::Nil, self.err.clone());
                                }
                                if b0 == b'-' && b1 == b'-' && b == b'>' {
                                    break;
                                }
                                (b0, b1) = (b1, b);
                            }

                            // Replace the comment with a space in the
                            // returned Directive body, so that markup parts
                            // that were separated by the comment (like a
                            // "<" and a "!") don't get joined when
                            // re-encoding the Directive, taking new
                            // semantic meaning.
                            self.buf.WriteByte(b' ');
                        }
                        break 'HandleB;
                    }
                }
                return (Token::Directive(Directive(self.buf.Bytes())), nil);
            }
            _ => {}
        }

        // Must be an open element like <a href="foo">
        self.ungetc(b);

        let name: Name;
        let mut empty = false;
        let mut attr: Vec<Attr>;
        (name, ok) = self.nsname();
        if !ok {
            if self.err == nil {
                self.err = self.syntaxError("expected element name after <");
            }
            return (Token::Nil, self.err.clone());
        }

        attr = Vec::new();
        loop {
            self.space();
            (b, ok) = self.mustgetc();
            if !ok {
                return (Token::Nil, self.err.clone());
            }
            if b == b'/' {
                empty = true;
                (b, ok) = self.mustgetc();
                if !ok {
                    return (Token::Nil, self.err.clone());
                }
                if b != b'>' {
                    self.err = self.syntaxError("expected /> in element");
                    return (Token::Nil, self.err.clone());
                }
                break;
            }
            if b == b'>' {
                break;
            }
            self.ungetc(b);

            let mut a = Attr::default();
            (a.Name, ok) = self.nsname();
            if !ok {
                if self.err == nil {
                    self.err = self.syntaxError("expected attribute name in element");
                }
                return (Token::Nil, self.err.clone());
            }
            self.space();
            (b, ok) = self.mustgetc();
            if !ok {
                return (Token::Nil, self.err.clone());
            }
            if b != b'=' {
                if self.Strict {
                    self.err = self.syntaxError("attribute name without = in element");
                    return (Token::Nil, self.err.clone());
                }
                self.ungetc(b);
                a.Value = a.Name.Local.clone();
            } else {
                self.space();
                match self.attrval() {
                    None => return (Token::Nil, self.err.clone()),
                    Some(data) => a.Value = string::from_bytes(&data),
                }
            }
            attr.push(a);
        }
        if empty {
            self.needClose = true;
            self.toClose = name.clone();
        }
        return (
            Token::StartElement(StartElement {
                Name: name,
                Attr: slice::__from_vec(attr),
            }),
            nil,
        );
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:853-885 Decoder.attrval
    fn attrval(&mut self) -> Option<slice<byte>> {
        let (mut b, mut ok) = self.mustgetc();
        if !ok {
            return None;
        }
        // Handle quoted attribute values
        if b == b'"' || b == b'\'' {
            return self.text(toint(b), false);
        }
        // Handle unquoted attribute values for strict parsers
        if self.Strict {
            self.err = self.syntaxError("unquoted or missing attribute value in element");
            return None;
        }
        // Handle unquoted attribute values for unstrict parsers
        self.ungetc(b);
        self.buf.Reset();
        loop {
            (b, ok) = self.mustgetc();
            if !ok {
                return None;
            }
            // https://www.w3.org/TR/REC-html40/intro/sgmltut.html#h-3.2.2
            if b'a' <= b && b <= b'z'
                || b'A' <= b && b <= b'Z'
                || b'0' <= b && b <= b'9'
                || b == b'_'
                || b == b':'
                || b == b'-'
            {
                self.buf.WriteByte(b);
            } else {
                self.ungetc(b);
                break;
            }
        }
        return Some(self.buf.Bytes());
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:888-901 Decoder.space
    /// Skip spaces if any
    fn space(&mut self) {
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

    // go: sdk 1.25.5 encoding/xml/xml.go:907-929 Decoder.getc
    /// Read a single byte. If there is no byte to read, return ok==false
    /// and leave the error in d.err. Maintain line number.
    fn getc(&mut self) -> (byte, bool) {
        if self.err != nil {
            return (0, false);
        }
        let b: byte;
        if self.nextByte >= 0 {
            b = tobyte(self.nextByte);
            self.nextByte = -1;
        } else {
            let (c, err) = match &mut self.r {
                Some(r) => io::ByteReader::ReadByte(r),
                None => (0, io::EOF.into()),
            };
            self.err = err;
            if self.err != nil {
                return (0, false);
            }
            b = c;
            if let Some(saved) = &mut self.saved {
                saved.WriteByte(b);
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
    /// InputOffset returns the input stream byte offset of the current
    /// decoder position. The offset gives the location of the end of the
    /// most recently returned token and the beginning of the next token.
    pub fn InputOffset(&self) -> int64 {
        return self.offset;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:941-943 Decoder.InputPos
    /// InputPos returns the line of the current decoder position and the
    /// 1 based input position of the line. The position gives the
    /// location of the end of the most recently returned token.
    pub fn InputPos(&self) -> (int, int) {
        return (self.line, toint(self.offset - self.linestart) + 1);
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:947-953 Decoder.savedOffset
    /// Return saved offset. If we did ungetc (nextByte >= 0), have to
    /// back up one.
    pub(super) fn savedOffset(&self) -> int {
        let mut n = match &self.saved {
            Some(saved) => saved.Len(),
            None => 0,
        };
        if self.nextByte >= 0 {
            n -= 1;
        }
        return n;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:959-966 Decoder.mustgetc
    /// Must read a single byte. If there is no byte to read, set d.err to
    /// SyntaxError("unexpected EOF") and return ok==false
    fn mustgetc(&mut self) -> (byte, bool) {
        let (b, ok) = self.getc();
        if !ok {
            if self.err == io::EOF {
                self.err = self.syntaxError("unexpected EOF");
            }
        }
        return (b, ok);
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:969-975 Decoder.ungetc
    /// Unread a single byte.
    fn ungetc(&mut self, b: byte) {
        if b == b'\n' {
            self.line -= 1;
        }
        self.nextByte = toint(b);
        self.offset -= 1;
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:989-1152 Decoder.text
    /// Read plain text section (XML calls it character data). If
    /// quote >= 0, we are in a quoted string and need to find the matching
    /// quote. If cdata == true, we are in a <![CDATA[ section and need to
    /// find ]]>. On failure return None and leave the error in d.err.
    fn text(&mut self, quote: int, cdata: bool) -> Option<slice<byte>> {
        let mut b0: byte = 0;
        let mut b1: byte = 0;
        let mut trunc: int = 0;
        self.buf.Reset();
        'Input: loop {
            let (mut b, mut ok) = self.getc();
            if !ok {
                if cdata {
                    if self.err == io::EOF {
                        self.err = self.syntaxError("unexpected EOF in CDATA section");
                    }
                    return None;
                }
                break 'Input;
            }

            // <![CDATA[ section ends with ]]>. It is an error for ]]> to
            // appear in ordinary text, but it is allowed in quoted strings.
            if quote < 0 && b0 == b']' && b1 == b']' && b == b'>' {
                if cdata {
                    trunc = 2;
                    break 'Input;
                }
                self.err = self.syntaxError("unescaped ]]> not in CDATA section");
                return None;
            }

            // Stop reading text if we see a <.
            if b == b'<' && !cdata {
                if quote >= 0 {
                    self.err = self.syntaxError("unescaped < inside quoted string");
                    return None;
                }
                self.ungetc(b'<');
                break 'Input;
            }
            if quote >= 0 && b == tobyte(quote) {
                break 'Input;
            }
            if b == b'&' && !cdata {
                // Read escaped character expression up to semicolon. XML in
                // all its glory allows a document to define and use its own
                // character names with <!ENTITY ...> directives. Parsers are
                // required to recognize lt, gt, amp, apos, and quot even if
                // they have not been declared.
                let before = self.buf.Len();
                self.buf.WriteByte(b'&');
                let mut text = string::new();
                let mut haveText = false;
                (b, ok) = self.mustgetc();
                if !ok {
                    return None;
                }
                if b == b'#' {
                    self.buf.WriteByte(b);
                    (b, ok) = self.mustgetc();
                    if !ok {
                        return None;
                    }
                    let mut base: int = 10;
                    if b == b'x' {
                        base = 16;
                        self.buf.WriteByte(b);
                        (b, ok) = self.mustgetc();
                        if !ok {
                            return None;
                        }
                    }
                    let start = self.buf.Len();
                    while b'0' <= b && b <= b'9'
                        || base == 16 && b'a' <= b && b <= b'f'
                        || base == 16 && b'A' <= b && b <= b'F'
                    {
                        self.buf.WriteByte(b);
                        (b, ok) = self.mustgetc();
                        if !ok {
                            return None;
                        }
                    }
                    if b != b';' {
                        self.ungetc(b);
                    } else {
                        let all = self.buf.Bytes();
                        let s = string::from_bytes(&all.slice(start, all.Len()));
                        self.buf.WriteByte(b';');
                        let (n, err) = strconv::ParseUint(s, base, 64);
                        if err == nil && n <= crate::convert::uint64(unicode::MaxRune) {
                            text = string::from_rune(torune(n));
                            haveText = true;
                        }
                    }
                } else {
                    self.ungetc(b);
                    if !self.readName() {
                        if self.err != nil {
                            return None;
                        }
                    }
                    (b, ok) = self.mustgetc();
                    if !ok {
                        return None;
                    }
                    if b != b';' {
                        self.ungetc(b);
                    } else {
                        let all = self.buf.Bytes();
                        let name: &[byte] = &all;
                        let name = &name[(before + 1) as usize..];
                        self.buf.WriteByte(b';');
                        if isName(name) {
                            let s = string::from_bytes(name);
                            let (r, ok) = lookupEntity(&s);
                            if ok {
                                text = string::from_rune(r);
                                haveText = true;
                            } else {
                                (text, haveText) = self.Entity.Get(s);
                            }
                        }
                    }
                }

                if haveText {
                    self.buf.Truncate(before);
                    self.buf.WriteString(text);
                    b0 = 0;
                    b1 = 0;
                    continue 'Input;
                }
                if !self.Strict {
                    b0 = 0;
                    b1 = 0;
                    continue 'Input;
                }
                let all = self.buf.Bytes();
                let mut ent = string::from_bytes(&all.slice(before, all.Len()));
                if ent[ent.Len() - 1] != b';' {
                    ent += " (no semicolon)";
                }
                self.err = self.syntaxError(string::from("invalid character entity ") + ent);
                return None;
            }

            // We must rewrite unescaped \r and \r\n into \n.
            if b == b'\r' {
                self.buf.WriteByte(b'\n');
            } else if b1 == b'\r' && b == b'\n' {
                // Skip \r\n--we already wrote \n.
            } else {
                self.buf.WriteByte(b);
            }

            (b0, b1) = (b1, b);
        }
        let mut data = self.buf.Bytes();
        data = data.slice(0, data.Len() - trunc);

        // Inspect each rune for being a disallowed character.
        let mut buf: &[byte] = &data;
        while !buf.is_empty() {
            let (r, size) = utf8::DecodeRune(buf);
            if r == utf8::RuneError && size == 1 {
                self.err = self.syntaxError("invalid UTF-8");
                return None;
            }
            buf = &buf[size as usize..];
            if !isInCharacterRange(r) {
                self.err = self.syntaxError(fmt::Sprintf!("illegal character code %U", r));
                return None;
            }
        }

        return Some(data);
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:1168-1182 Decoder.nsname
    /// Get name space name: name with a : stuck in the middle. The part
    /// before the : is the name space identifier.
    fn nsname(&mut self) -> (Name, bool) {
        let mut name = Name::default();
        let (s, ok) = self.name();
        if !ok {
            return (name, ok);
        }
        if strings::Count(&s, ":") > 1 {
            return (name, false);
        }
        let (space, local, ok) = strings::Cut(&s, ":");
        if !ok || space == "" || local == "" {
            name.Local = s;
        } else {
            name.Space = space;
            name.Local = local;
        }
        return (name, true);
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:1187-1200 Decoder.name
    /// Get name: /first(first|second)*/ Do not set d.err if the name is
    /// missing (unless unexpected EOF is received): let the caller provide
    /// better context.
    fn name(&mut self) -> (string, bool) {
        self.buf.Reset();
        if !self.readName() {
            return (string::new(), false);
        }

        // Now we check the characters.
        let b = self.buf.Bytes();
        if !isName(&b) {
            self.err = self.syntaxError(string::from("invalid XML name: ") + string::from_bytes(&b));
            return (string::new(), false);
        }
        return (string::from_bytes(&b), true);
    }

    // go: sdk 1.25.5 encoding/xml/xml.go:1205-1227 Decoder.readName
    /// Read a name and append its bytes to d.buf. The name is delimited by
    /// any single-byte character not valid in names. All multi-byte
    /// characters are accepted; the caller must check their validity.
    fn readName(&mut self) -> bool {
        let (mut b, mut ok) = self.mustgetc();
        if !ok {
            return ok;
        }
        if b < utf8::RuneSelf && !isNameByte(b) {
            self.ungetc(b);
            return false;
        }
        self.buf.WriteByte(b);

        loop {
            (b, ok) = self.mustgetc();
            if !ok {
                return ok;
            }
            if b < utf8::RuneSelf && !isNameByte(b) {
                self.ungetc(b);
                break;
            }
            self.buf.WriteByte(b);
        }
        return true;
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:1157-1164 isInCharacterRange
/// Decide whether the given rune is in the XML Character Range, per the
/// Char production of https://www.xml.com/axml/testaxml.htm, Section 2.2
/// Characters.
pub(super) fn isInCharacterRange(r: rune) -> bool {
    return r == 0x09
        || r == 0x0A
        || r == 0x0D
        || r >= 0x20 && r <= 0xD7FF
        || r >= 0xE000 && r <= 0xFFFD
        || r >= 0x10000 && r <= 0x10FFFF;
}

// go: sdk 1.25.5 encoding/xml/xml.go:1229-1234 isNameByte
fn isNameByte(c: byte) -> bool {
    return b'A' <= c && c <= b'Z'
        || b'a' <= c && c <= b'z'
        || b'0' <= c && c <= b'9'
        || c == b'_'
        || c == b':'
        || c == b'.'
        || c == b'-';
}

// go: sdk 1.25.5 encoding/xml/xml.go:1236-1258 isName
pub(super) fn isName(s: &[byte]) -> bool {
    if s.is_empty() {
        return false;
    }
    let (mut c, mut n) = utf8::DecodeRune(s);
    if c == utf8::RuneError && n == 1 {
        return false;
    }
    if !unicode::Is(&first, c) {
        return false;
    }
    let mut s = s;
    while (n as usize) < s.len() {
        s = &s[n as usize..];
        (c, n) = utf8::DecodeRune(s);
        if c == utf8::RuneError && n == 1 {
            return false;
        }
        if !unicode::Is(&first, c) && !unicode::Is(&second, c) {
            return false;
        }
    }
    return true;
}

// go: sdk 1.25.5 encoding/xml/xml.go:1260-1282 isNameString
pub(super) fn isNameString(s: &string) -> bool {
    if s.Len() == 0 {
        return false;
    }
    let (mut c, mut n) = utf8::DecodeRuneInString(s);
    if c == utf8::RuneError && n == 1 {
        return false;
    }
    if !unicode::Is(&first, c) {
        return false;
    }
    let mut s: &[byte] = s.as_bytes();
    while (n as usize) < s.len() {
        s = &s[n as usize..];
        (c, n) = utf8::DecodeRuneInString(s);
        if c == utf8::RuneError && n == 1 {
            return false;
        }
        if !unicode::Is(&first, c) && !unicode::Is(&second, c) {
            return false;
        }
    }
    return true;
}

// go: none — goish idiom: `{lo, hi, stride}` composite literals of
//     `unicode.Range16`, spelled once.
const fn r16(Lo: u16, Hi: u16, Stride: u16) -> unicode::Range16 {
    return unicode::Range16 { Lo, Hi, Stride };
}

// These tables were generated by cut and paste from Appendix B of the XML
// spec at https://www.xml.com/axml/testaxml.htm and then reformatting.
// First corresponds to (Letter | '_' | ':') and second corresponds to
// NameChar. (The goish copy was generated from Go's xml.go, not retyped.)

// go: sdk 1.25.5 encoding/xml/xml.go:1289-1482 first
static first: unicode::RangeTable = unicode::RangeTable {
    R16: &FIRST_R16,
    R32: &[],
    LatinOffset: 0,
};

static FIRST_R16: [unicode::Range16; 190] = [
    r16(0x003A, 0x003A, 1),
    r16(0x0041, 0x005A, 1),
    r16(0x005F, 0x005F, 1),
    r16(0x0061, 0x007A, 1),
    r16(0x00C0, 0x00D6, 1),
    r16(0x00D8, 0x00F6, 1),
    r16(0x00F8, 0x00FF, 1),
    r16(0x0100, 0x0131, 1),
    r16(0x0134, 0x013E, 1),
    r16(0x0141, 0x0148, 1),
    r16(0x014A, 0x017E, 1),
    r16(0x0180, 0x01C3, 1),
    r16(0x01CD, 0x01F0, 1),
    r16(0x01F4, 0x01F5, 1),
    r16(0x01FA, 0x0217, 1),
    r16(0x0250, 0x02A8, 1),
    r16(0x02BB, 0x02C1, 1),
    r16(0x0386, 0x0386, 1),
    r16(0x0388, 0x038A, 1),
    r16(0x038C, 0x038C, 1),
    r16(0x038E, 0x03A1, 1),
    r16(0x03A3, 0x03CE, 1),
    r16(0x03D0, 0x03D6, 1),
    r16(0x03DA, 0x03E0, 0x2),
    r16(0x03E2, 0x03F3, 1),
    r16(0x0401, 0x040C, 1),
    r16(0x040E, 0x044F, 1),
    r16(0x0451, 0x045C, 1),
    r16(0x045E, 0x0481, 1),
    r16(0x0490, 0x04C4, 1),
    r16(0x04C7, 0x04C8, 1),
    r16(0x04CB, 0x04CC, 1),
    r16(0x04D0, 0x04EB, 1),
    r16(0x04EE, 0x04F5, 1),
    r16(0x04F8, 0x04F9, 1),
    r16(0x0531, 0x0556, 1),
    r16(0x0559, 0x0559, 1),
    r16(0x0561, 0x0586, 1),
    r16(0x05D0, 0x05EA, 1),
    r16(0x05F0, 0x05F2, 1),
    r16(0x0621, 0x063A, 1),
    r16(0x0641, 0x064A, 1),
    r16(0x0671, 0x06B7, 1),
    r16(0x06BA, 0x06BE, 1),
    r16(0x06C0, 0x06CE, 1),
    r16(0x06D0, 0x06D3, 1),
    r16(0x06D5, 0x06D5, 1),
    r16(0x06E5, 0x06E6, 1),
    r16(0x0905, 0x0939, 1),
    r16(0x093D, 0x093D, 1),
    r16(0x0958, 0x0961, 1),
    r16(0x0985, 0x098C, 1),
    r16(0x098F, 0x0990, 1),
    r16(0x0993, 0x09A8, 1),
    r16(0x09AA, 0x09B0, 1),
    r16(0x09B2, 0x09B2, 1),
    r16(0x09B6, 0x09B9, 1),
    r16(0x09DC, 0x09DD, 1),
    r16(0x09DF, 0x09E1, 1),
    r16(0x09F0, 0x09F1, 1),
    r16(0x0A05, 0x0A0A, 1),
    r16(0x0A0F, 0x0A10, 1),
    r16(0x0A13, 0x0A28, 1),
    r16(0x0A2A, 0x0A30, 1),
    r16(0x0A32, 0x0A33, 1),
    r16(0x0A35, 0x0A36, 1),
    r16(0x0A38, 0x0A39, 1),
    r16(0x0A59, 0x0A5C, 1),
    r16(0x0A5E, 0x0A5E, 1),
    r16(0x0A72, 0x0A74, 1),
    r16(0x0A85, 0x0A8B, 1),
    r16(0x0A8D, 0x0A8D, 1),
    r16(0x0A8F, 0x0A91, 1),
    r16(0x0A93, 0x0AA8, 1),
    r16(0x0AAA, 0x0AB0, 1),
    r16(0x0AB2, 0x0AB3, 1),
    r16(0x0AB5, 0x0AB9, 1),
    r16(0x0ABD, 0x0AE0, 0x23),
    r16(0x0B05, 0x0B0C, 1),
    r16(0x0B0F, 0x0B10, 1),
    r16(0x0B13, 0x0B28, 1),
    r16(0x0B2A, 0x0B30, 1),
    r16(0x0B32, 0x0B33, 1),
    r16(0x0B36, 0x0B39, 1),
    r16(0x0B3D, 0x0B3D, 1),
    r16(0x0B5C, 0x0B5D, 1),
    r16(0x0B5F, 0x0B61, 1),
    r16(0x0B85, 0x0B8A, 1),
    r16(0x0B8E, 0x0B90, 1),
    r16(0x0B92, 0x0B95, 1),
    r16(0x0B99, 0x0B9A, 1),
    r16(0x0B9C, 0x0B9C, 1),
    r16(0x0B9E, 0x0B9F, 1),
    r16(0x0BA3, 0x0BA4, 1),
    r16(0x0BA8, 0x0BAA, 1),
    r16(0x0BAE, 0x0BB5, 1),
    r16(0x0BB7, 0x0BB9, 1),
    r16(0x0C05, 0x0C0C, 1),
    r16(0x0C0E, 0x0C10, 1),
    r16(0x0C12, 0x0C28, 1),
    r16(0x0C2A, 0x0C33, 1),
    r16(0x0C35, 0x0C39, 1),
    r16(0x0C60, 0x0C61, 1),
    r16(0x0C85, 0x0C8C, 1),
    r16(0x0C8E, 0x0C90, 1),
    r16(0x0C92, 0x0CA8, 1),
    r16(0x0CAA, 0x0CB3, 1),
    r16(0x0CB5, 0x0CB9, 1),
    r16(0x0CDE, 0x0CDE, 1),
    r16(0x0CE0, 0x0CE1, 1),
    r16(0x0D05, 0x0D0C, 1),
    r16(0x0D0E, 0x0D10, 1),
    r16(0x0D12, 0x0D28, 1),
    r16(0x0D2A, 0x0D39, 1),
    r16(0x0D60, 0x0D61, 1),
    r16(0x0E01, 0x0E2E, 1),
    r16(0x0E30, 0x0E30, 1),
    r16(0x0E32, 0x0E33, 1),
    r16(0x0E40, 0x0E45, 1),
    r16(0x0E81, 0x0E82, 1),
    r16(0x0E84, 0x0E84, 1),
    r16(0x0E87, 0x0E88, 1),
    r16(0x0E8A, 0x0E8D, 0x3),
    r16(0x0E94, 0x0E97, 1),
    r16(0x0E99, 0x0E9F, 1),
    r16(0x0EA1, 0x0EA3, 1),
    r16(0x0EA5, 0x0EA7, 0x2),
    r16(0x0EAA, 0x0EAB, 1),
    r16(0x0EAD, 0x0EAE, 1),
    r16(0x0EB0, 0x0EB0, 1),
    r16(0x0EB2, 0x0EB3, 1),
    r16(0x0EBD, 0x0EBD, 1),
    r16(0x0EC0, 0x0EC4, 1),
    r16(0x0F40, 0x0F47, 1),
    r16(0x0F49, 0x0F69, 1),
    r16(0x10A0, 0x10C5, 1),
    r16(0x10D0, 0x10F6, 1),
    r16(0x1100, 0x1100, 1),
    r16(0x1102, 0x1103, 1),
    r16(0x1105, 0x1107, 1),
    r16(0x1109, 0x1109, 1),
    r16(0x110B, 0x110C, 1),
    r16(0x110E, 0x1112, 1),
    r16(0x113C, 0x1140, 0x2),
    r16(0x114C, 0x1150, 0x2),
    r16(0x1154, 0x1155, 1),
    r16(0x1159, 0x1159, 1),
    r16(0x115F, 0x1161, 1),
    r16(0x1163, 0x1169, 0x2),
    r16(0x116D, 0x116E, 1),
    r16(0x1172, 0x1173, 1),
    r16(0x1175, 0x119E, 0x119E - 0x1175),
    r16(0x11A8, 0x11AB, 0x11AB - 0x11A8),
    r16(0x11AE, 0x11AF, 1),
    r16(0x11B7, 0x11B8, 1),
    r16(0x11BA, 0x11BA, 1),
    r16(0x11BC, 0x11C2, 1),
    r16(0x11EB, 0x11F0, 0x11F0 - 0x11EB),
    r16(0x11F9, 0x11F9, 1),
    r16(0x1E00, 0x1E9B, 1),
    r16(0x1EA0, 0x1EF9, 1),
    r16(0x1F00, 0x1F15, 1),
    r16(0x1F18, 0x1F1D, 1),
    r16(0x1F20, 0x1F45, 1),
    r16(0x1F48, 0x1F4D, 1),
    r16(0x1F50, 0x1F57, 1),
    r16(0x1F59, 0x1F5B, 0x1F5B - 0x1F59),
    r16(0x1F5D, 0x1F5D, 1),
    r16(0x1F5F, 0x1F7D, 1),
    r16(0x1F80, 0x1FB4, 1),
    r16(0x1FB6, 0x1FBC, 1),
    r16(0x1FBE, 0x1FBE, 1),
    r16(0x1FC2, 0x1FC4, 1),
    r16(0x1FC6, 0x1FCC, 1),
    r16(0x1FD0, 0x1FD3, 1),
    r16(0x1FD6, 0x1FDB, 1),
    r16(0x1FE0, 0x1FEC, 1),
    r16(0x1FF2, 0x1FF4, 1),
    r16(0x1FF6, 0x1FFC, 1),
    r16(0x2126, 0x2126, 1),
    r16(0x212A, 0x212B, 1),
    r16(0x212E, 0x212E, 1),
    r16(0x2180, 0x2182, 1),
    r16(0x3007, 0x3007, 1),
    r16(0x3021, 0x3029, 1),
    r16(0x3041, 0x3094, 1),
    r16(0x30A1, 0x30FA, 1),
    r16(0x3105, 0x312C, 1),
    r16(0x4E00, 0x9FA5, 1),
    r16(0xAC00, 0xD7A3, 1),
];

// go: sdk 1.25.5 encoding/xml/xml.go:1484-1599 second
static second: unicode::RangeTable = unicode::RangeTable {
    R16: &SECOND_R16,
    R32: &[],
    LatinOffset: 0,
};

static SECOND_R16: [unicode::Range16; 112] = [
    r16(0x002D, 0x002E, 1),
    r16(0x0030, 0x0039, 1),
    r16(0x00B7, 0x00B7, 1),
    r16(0x02D0, 0x02D1, 1),
    r16(0x0300, 0x0345, 1),
    r16(0x0360, 0x0361, 1),
    r16(0x0387, 0x0387, 1),
    r16(0x0483, 0x0486, 1),
    r16(0x0591, 0x05A1, 1),
    r16(0x05A3, 0x05B9, 1),
    r16(0x05BB, 0x05BD, 1),
    r16(0x05BF, 0x05BF, 1),
    r16(0x05C1, 0x05C2, 1),
    r16(0x05C4, 0x0640, 0x0640 - 0x05C4),
    r16(0x064B, 0x0652, 1),
    r16(0x0660, 0x0669, 1),
    r16(0x0670, 0x0670, 1),
    r16(0x06D6, 0x06DC, 1),
    r16(0x06DD, 0x06DF, 1),
    r16(0x06E0, 0x06E4, 1),
    r16(0x06E7, 0x06E8, 1),
    r16(0x06EA, 0x06ED, 1),
    r16(0x06F0, 0x06F9, 1),
    r16(0x0901, 0x0903, 1),
    r16(0x093C, 0x093C, 1),
    r16(0x093E, 0x094C, 1),
    r16(0x094D, 0x094D, 1),
    r16(0x0951, 0x0954, 1),
    r16(0x0962, 0x0963, 1),
    r16(0x0966, 0x096F, 1),
    r16(0x0981, 0x0983, 1),
    r16(0x09BC, 0x09BC, 1),
    r16(0x09BE, 0x09BF, 1),
    r16(0x09C0, 0x09C4, 1),
    r16(0x09C7, 0x09C8, 1),
    r16(0x09CB, 0x09CD, 1),
    r16(0x09D7, 0x09D7, 1),
    r16(0x09E2, 0x09E3, 1),
    r16(0x09E6, 0x09EF, 1),
    r16(0x0A02, 0x0A3C, 0x3A),
    r16(0x0A3E, 0x0A3F, 1),
    r16(0x0A40, 0x0A42, 1),
    r16(0x0A47, 0x0A48, 1),
    r16(0x0A4B, 0x0A4D, 1),
    r16(0x0A66, 0x0A6F, 1),
    r16(0x0A70, 0x0A71, 1),
    r16(0x0A81, 0x0A83, 1),
    r16(0x0ABC, 0x0ABC, 1),
    r16(0x0ABE, 0x0AC5, 1),
    r16(0x0AC7, 0x0AC9, 1),
    r16(0x0ACB, 0x0ACD, 1),
    r16(0x0AE6, 0x0AEF, 1),
    r16(0x0B01, 0x0B03, 1),
    r16(0x0B3C, 0x0B3C, 1),
    r16(0x0B3E, 0x0B43, 1),
    r16(0x0B47, 0x0B48, 1),
    r16(0x0B4B, 0x0B4D, 1),
    r16(0x0B56, 0x0B57, 1),
    r16(0x0B66, 0x0B6F, 1),
    r16(0x0B82, 0x0B83, 1),
    r16(0x0BBE, 0x0BC2, 1),
    r16(0x0BC6, 0x0BC8, 1),
    r16(0x0BCA, 0x0BCD, 1),
    r16(0x0BD7, 0x0BD7, 1),
    r16(0x0BE7, 0x0BEF, 1),
    r16(0x0C01, 0x0C03, 1),
    r16(0x0C3E, 0x0C44, 1),
    r16(0x0C46, 0x0C48, 1),
    r16(0x0C4A, 0x0C4D, 1),
    r16(0x0C55, 0x0C56, 1),
    r16(0x0C66, 0x0C6F, 1),
    r16(0x0C82, 0x0C83, 1),
    r16(0x0CBE, 0x0CC4, 1),
    r16(0x0CC6, 0x0CC8, 1),
    r16(0x0CCA, 0x0CCD, 1),
    r16(0x0CD5, 0x0CD6, 1),
    r16(0x0CE6, 0x0CEF, 1),
    r16(0x0D02, 0x0D03, 1),
    r16(0x0D3E, 0x0D43, 1),
    r16(0x0D46, 0x0D48, 1),
    r16(0x0D4A, 0x0D4D, 1),
    r16(0x0D57, 0x0D57, 1),
    r16(0x0D66, 0x0D6F, 1),
    r16(0x0E31, 0x0E31, 1),
    r16(0x0E34, 0x0E3A, 1),
    r16(0x0E46, 0x0E46, 1),
    r16(0x0E47, 0x0E4E, 1),
    r16(0x0E50, 0x0E59, 1),
    r16(0x0EB1, 0x0EB1, 1),
    r16(0x0EB4, 0x0EB9, 1),
    r16(0x0EBB, 0x0EBC, 1),
    r16(0x0EC6, 0x0EC6, 1),
    r16(0x0EC8, 0x0ECD, 1),
    r16(0x0ED0, 0x0ED9, 1),
    r16(0x0F18, 0x0F19, 1),
    r16(0x0F20, 0x0F29, 1),
    r16(0x0F35, 0x0F39, 0x2),
    r16(0x0F3E, 0x0F3F, 1),
    r16(0x0F71, 0x0F84, 1),
    r16(0x0F86, 0x0F8B, 1),
    r16(0x0F90, 0x0F95, 1),
    r16(0x0F97, 0x0F97, 1),
    r16(0x0F99, 0x0FAD, 1),
    r16(0x0FB1, 0x0FB7, 1),
    r16(0x0FB9, 0x0FB9, 1),
    r16(0x20D0, 0x20DC, 1),
    r16(0x20E1, 0x3005, 0x3005 - 0x20E1),
    r16(0x302A, 0x302F, 1),
    r16(0x3031, 0x3035, 1),
    r16(0x3099, 0x309A, 1),
    r16(0x309D, 0x309E, 1),
    r16(0x30FC, 0x30FE, 1),
];

// go: sdk 1.25.5 encoding/xml/xml.go:1605-1605 HTMLEntity
/// HTMLEntity is an entity map containing translations for the standard
/// HTML entity characters.
///
/// See the [`Decoder`] `Strict` and `Entity` fields' documentation.
pub static HTMLEntity: crate::lazy::Lazy<map<string, string>> = crate::lazy::Lazy::new(|| {
    let mut m: map<string, string> = map::new();
    for (_, e) in crate::range!(htmlEntity) {
        m.Set(e.0, e.1);
    }
    return m;
});

// go: sdk 1.25.5 encoding/xml/xml.go:1607-1868 htmlEntity
static htmlEntity: [(&str, &str); 252] = [
    ("nbsp", "\u{00A0}"),
    ("iexcl", "\u{00A1}"),
    ("cent", "\u{00A2}"),
    ("pound", "\u{00A3}"),
    ("curren", "\u{00A4}"),
    ("yen", "\u{00A5}"),
    ("brvbar", "\u{00A6}"),
    ("sect", "\u{00A7}"),
    ("uml", "\u{00A8}"),
    ("copy", "\u{00A9}"),
    ("ordf", "\u{00AA}"),
    ("laquo", "\u{00AB}"),
    ("not", "\u{00AC}"),
    ("shy", "\u{00AD}"),
    ("reg", "\u{00AE}"),
    ("macr", "\u{00AF}"),
    ("deg", "\u{00B0}"),
    ("plusmn", "\u{00B1}"),
    ("sup2", "\u{00B2}"),
    ("sup3", "\u{00B3}"),
    ("acute", "\u{00B4}"),
    ("micro", "\u{00B5}"),
    ("para", "\u{00B6}"),
    ("middot", "\u{00B7}"),
    ("cedil", "\u{00B8}"),
    ("sup1", "\u{00B9}"),
    ("ordm", "\u{00BA}"),
    ("raquo", "\u{00BB}"),
    ("frac14", "\u{00BC}"),
    ("frac12", "\u{00BD}"),
    ("frac34", "\u{00BE}"),
    ("iquest", "\u{00BF}"),
    ("Agrave", "\u{00C0}"),
    ("Aacute", "\u{00C1}"),
    ("Acirc", "\u{00C2}"),
    ("Atilde", "\u{00C3}"),
    ("Auml", "\u{00C4}"),
    ("Aring", "\u{00C5}"),
    ("AElig", "\u{00C6}"),
    ("Ccedil", "\u{00C7}"),
    ("Egrave", "\u{00C8}"),
    ("Eacute", "\u{00C9}"),
    ("Ecirc", "\u{00CA}"),
    ("Euml", "\u{00CB}"),
    ("Igrave", "\u{00CC}"),
    ("Iacute", "\u{00CD}"),
    ("Icirc", "\u{00CE}"),
    ("Iuml", "\u{00CF}"),
    ("ETH", "\u{00D0}"),
    ("Ntilde", "\u{00D1}"),
    ("Ograve", "\u{00D2}"),
    ("Oacute", "\u{00D3}"),
    ("Ocirc", "\u{00D4}"),
    ("Otilde", "\u{00D5}"),
    ("Ouml", "\u{00D6}"),
    ("times", "\u{00D7}"),
    ("Oslash", "\u{00D8}"),
    ("Ugrave", "\u{00D9}"),
    ("Uacute", "\u{00DA}"),
    ("Ucirc", "\u{00DB}"),
    ("Uuml", "\u{00DC}"),
    ("Yacute", "\u{00DD}"),
    ("THORN", "\u{00DE}"),
    ("szlig", "\u{00DF}"),
    ("agrave", "\u{00E0}"),
    ("aacute", "\u{00E1}"),
    ("acirc", "\u{00E2}"),
    ("atilde", "\u{00E3}"),
    ("auml", "\u{00E4}"),
    ("aring", "\u{00E5}"),
    ("aelig", "\u{00E6}"),
    ("ccedil", "\u{00E7}"),
    ("egrave", "\u{00E8}"),
    ("eacute", "\u{00E9}"),
    ("ecirc", "\u{00EA}"),
    ("euml", "\u{00EB}"),
    ("igrave", "\u{00EC}"),
    ("iacute", "\u{00ED}"),
    ("icirc", "\u{00EE}"),
    ("iuml", "\u{00EF}"),
    ("eth", "\u{00F0}"),
    ("ntilde", "\u{00F1}"),
    ("ograve", "\u{00F2}"),
    ("oacute", "\u{00F3}"),
    ("ocirc", "\u{00F4}"),
    ("otilde", "\u{00F5}"),
    ("ouml", "\u{00F6}"),
    ("divide", "\u{00F7}"),
    ("oslash", "\u{00F8}"),
    ("ugrave", "\u{00F9}"),
    ("uacute", "\u{00FA}"),
    ("ucirc", "\u{00FB}"),
    ("uuml", "\u{00FC}"),
    ("yacute", "\u{00FD}"),
    ("thorn", "\u{00FE}"),
    ("yuml", "\u{00FF}"),
    ("fnof", "\u{0192}"),
    ("Alpha", "\u{0391}"),
    ("Beta", "\u{0392}"),
    ("Gamma", "\u{0393}"),
    ("Delta", "\u{0394}"),
    ("Epsilon", "\u{0395}"),
    ("Zeta", "\u{0396}"),
    ("Eta", "\u{0397}"),
    ("Theta", "\u{0398}"),
    ("Iota", "\u{0399}"),
    ("Kappa", "\u{039A}"),
    ("Lambda", "\u{039B}"),
    ("Mu", "\u{039C}"),
    ("Nu", "\u{039D}"),
    ("Xi", "\u{039E}"),
    ("Omicron", "\u{039F}"),
    ("Pi", "\u{03A0}"),
    ("Rho", "\u{03A1}"),
    ("Sigma", "\u{03A3}"),
    ("Tau", "\u{03A4}"),
    ("Upsilon", "\u{03A5}"),
    ("Phi", "\u{03A6}"),
    ("Chi", "\u{03A7}"),
    ("Psi", "\u{03A8}"),
    ("Omega", "\u{03A9}"),
    ("alpha", "\u{03B1}"),
    ("beta", "\u{03B2}"),
    ("gamma", "\u{03B3}"),
    ("delta", "\u{03B4}"),
    ("epsilon", "\u{03B5}"),
    ("zeta", "\u{03B6}"),
    ("eta", "\u{03B7}"),
    ("theta", "\u{03B8}"),
    ("iota", "\u{03B9}"),
    ("kappa", "\u{03BA}"),
    ("lambda", "\u{03BB}"),
    ("mu", "\u{03BC}"),
    ("nu", "\u{03BD}"),
    ("xi", "\u{03BE}"),
    ("omicron", "\u{03BF}"),
    ("pi", "\u{03C0}"),
    ("rho", "\u{03C1}"),
    ("sigmaf", "\u{03C2}"),
    ("sigma", "\u{03C3}"),
    ("tau", "\u{03C4}"),
    ("upsilon", "\u{03C5}"),
    ("phi", "\u{03C6}"),
    ("chi", "\u{03C7}"),
    ("psi", "\u{03C8}"),
    ("omega", "\u{03C9}"),
    ("thetasym", "\u{03D1}"),
    ("upsih", "\u{03D2}"),
    ("piv", "\u{03D6}"),
    ("bull", "\u{2022}"),
    ("hellip", "\u{2026}"),
    ("prime", "\u{2032}"),
    ("Prime", "\u{2033}"),
    ("oline", "\u{203E}"),
    ("frasl", "\u{2044}"),
    ("weierp", "\u{2118}"),
    ("image", "\u{2111}"),
    ("real", "\u{211C}"),
    ("trade", "\u{2122}"),
    ("alefsym", "\u{2135}"),
    ("larr", "\u{2190}"),
    ("uarr", "\u{2191}"),
    ("rarr", "\u{2192}"),
    ("darr", "\u{2193}"),
    ("harr", "\u{2194}"),
    ("crarr", "\u{21B5}"),
    ("lArr", "\u{21D0}"),
    ("uArr", "\u{21D1}"),
    ("rArr", "\u{21D2}"),
    ("dArr", "\u{21D3}"),
    ("hArr", "\u{21D4}"),
    ("forall", "\u{2200}"),
    ("part", "\u{2202}"),
    ("exist", "\u{2203}"),
    ("empty", "\u{2205}"),
    ("nabla", "\u{2207}"),
    ("isin", "\u{2208}"),
    ("notin", "\u{2209}"),
    ("ni", "\u{220B}"),
    ("prod", "\u{220F}"),
    ("sum", "\u{2211}"),
    ("minus", "\u{2212}"),
    ("lowast", "\u{2217}"),
    ("radic", "\u{221A}"),
    ("prop", "\u{221D}"),
    ("infin", "\u{221E}"),
    ("ang", "\u{2220}"),
    ("and", "\u{2227}"),
    ("or", "\u{2228}"),
    ("cap", "\u{2229}"),
    ("cup", "\u{222A}"),
    ("int", "\u{222B}"),
    ("there4", "\u{2234}"),
    ("sim", "\u{223C}"),
    ("cong", "\u{2245}"),
    ("asymp", "\u{2248}"),
    ("ne", "\u{2260}"),
    ("equiv", "\u{2261}"),
    ("le", "\u{2264}"),
    ("ge", "\u{2265}"),
    ("sub", "\u{2282}"),
    ("sup", "\u{2283}"),
    ("nsub", "\u{2284}"),
    ("sube", "\u{2286}"),
    ("supe", "\u{2287}"),
    ("oplus", "\u{2295}"),
    ("otimes", "\u{2297}"),
    ("perp", "\u{22A5}"),
    ("sdot", "\u{22C5}"),
    ("lceil", "\u{2308}"),
    ("rceil", "\u{2309}"),
    ("lfloor", "\u{230A}"),
    ("rfloor", "\u{230B}"),
    ("lang", "\u{2329}"),
    ("rang", "\u{232A}"),
    ("loz", "\u{25CA}"),
    ("spades", "\u{2660}"),
    ("clubs", "\u{2663}"),
    ("hearts", "\u{2665}"),
    ("diams", "\u{2666}"),
    ("quot", "\u{0022}"),
    ("amp", "\u{0026}"),
    ("lt", "\u{003C}"),
    ("gt", "\u{003E}"),
    ("OElig", "\u{0152}"),
    ("oelig", "\u{0153}"),
    ("Scaron", "\u{0160}"),
    ("scaron", "\u{0161}"),
    ("Yuml", "\u{0178}"),
    ("circ", "\u{02C6}"),
    ("tilde", "\u{02DC}"),
    ("ensp", "\u{2002}"),
    ("emsp", "\u{2003}"),
    ("thinsp", "\u{2009}"),
    ("zwnj", "\u{200C}"),
    ("zwj", "\u{200D}"),
    ("lrm", "\u{200E}"),
    ("rlm", "\u{200F}"),
    ("ndash", "\u{2013}"),
    ("mdash", "\u{2014}"),
    ("lsquo", "\u{2018}"),
    ("rsquo", "\u{2019}"),
    ("sbquo", "\u{201A}"),
    ("ldquo", "\u{201C}"),
    ("rdquo", "\u{201D}"),
    ("bdquo", "\u{201E}"),
    ("dagger", "\u{2020}"),
    ("Dagger", "\u{2021}"),
    ("permil", "\u{2030}"),
    ("lsaquo", "\u{2039}"),
    ("rsaquo", "\u{203A}"),
    ("euro", "\u{20AC}"),
];

// go: sdk 1.25.5 encoding/xml/xml.go:1874-1874 HTMLAutoClose
/// HTMLAutoClose is the set of HTML elements that should be considered
/// to close automatically.
///
/// See the [`Decoder`] `Strict` and `Entity` fields' documentation.
pub static HTMLAutoClose: crate::lazy::Lazy<slice<string>> = crate::lazy::Lazy::new(|| {
    let mut v: Vec<string> = Vec::with_capacity(htmlAutoClose.len());
    for (_, s) in crate::range!(htmlAutoClose) {
        v.push(string::from(*s));
    }
    return slice::__from_vec(v);
});

// go: sdk 1.25.5 encoding/xml/xml.go:1876-1894 htmlAutoClose
static htmlAutoClose: [&str; 13] = [
    "basefont", "br", "area", "link", "img", "param", "hr", "input", "col", "frame", "isindex",
    "base", "meta",
];

// go: sdk 1.25.5 encoding/xml/xml.go:1896-1906 escQuot
static escQuot: &[byte] = b"&#34;"; // shorter than "&quot;"
// go: sdk 1.25.5 encoding/xml/xml.go:1896-1906 escApos
static escApos: &[byte] = b"&#39;"; // shorter than "&apos;"
// go: sdk 1.25.5 encoding/xml/xml.go:1896-1906 escAmp
static escAmp: &[byte] = b"&amp;";
// go: sdk 1.25.5 encoding/xml/xml.go:1896-1906 escLT
static escLT: &[byte] = b"&lt;";
// go: sdk 1.25.5 encoding/xml/xml.go:1896-1906 escGT
static escGT: &[byte] = b"&gt;";
// go: sdk 1.25.5 encoding/xml/xml.go:1896-1906 escTab
static escTab: &[byte] = b"&#x9;";
// go: sdk 1.25.5 encoding/xml/xml.go:1896-1906 escNL
static escNL: &[byte] = b"&#xA;";
// go: sdk 1.25.5 encoding/xml/xml.go:1896-1906 escCR
static escCR: &[byte] = b"&#xD;";
// go: sdk 1.25.5 encoding/xml/xml.go:1896-1906 escFFFD
static escFFFD: &[byte] = "\u{FFFD}".as_bytes(); // Unicode replacement character

// go: none — goish idiom: Go's `w.Write(s[a:b])` with `s []byte`; a
//     goish `Write` takes an owned slice, so the sub-slice is copied out.
fn writeBytes(w: &mut dyn io::Writer, b: &[byte]) -> error {
    let (_, err) = w.Write(slice::__from_vec(b.to_vec()));
    return err;
}

// go: sdk 1.25.5 encoding/xml/xml.go:1910-1912 EscapeText
/// EscapeText writes to w the properly escaped XML equivalent of the
/// plain text data s.
pub fn EscapeText(w: &mut dyn io::Writer, s: slice<byte>) -> error {
    return escapeText(w, &s, true);
}

// go: sdk 1.25.5 encoding/xml/xml.go:1917-1960 escapeText
/// escapeText writes to w the properly escaped XML equivalent of the
/// plain text data s. If escapeNewline is true, newline characters will
/// be escaped.
pub(super) fn escapeText(w: &mut dyn io::Writer, s: &[byte], escapeNewline: bool) -> error {
    let mut esc: &[byte];
    let mut last: usize = 0;
    let mut i: usize = 0;
    while i < s.len() {
        let (r, width) = utf8::DecodeRune(&s[i..]);
        let width = width as usize;
        i += width;
        match r {
            0x22 => esc = escQuot,
            0x27 => esc = escApos,
            0x26 => esc = escAmp,
            0x3C => esc = escLT,
            0x3E => esc = escGT,
            0x09 => esc = escTab,
            0x0A => {
                if !escapeNewline {
                    continue;
                }
                esc = escNL;
            }
            0x0D => esc = escCR,
            _ => {
                if !isInCharacterRange(r) || (r == 0xFFFD && width == 1) {
                    esc = escFFFD;
                } else {
                    continue;
                }
            }
        }
        let err = writeBytes(w, &s[last..i - width]);
        if err != nil {
            return err;
        }
        let err = writeBytes(w, esc);
        if err != nil {
            return err;
        }
        last = i;
    }
    return writeBytes(w, &s[last..]);
}

impl printer {
    // go: sdk 1.25.5 encoding/xml/xml.go:1964-1999 printer.EscapeString
    /// EscapeString writes to p the properly escaped XML equivalent of the
    /// plain text data s.
    pub(super) fn EscapeString(&mut self, s: &string) {
        let s = s.as_bytes();
        let mut esc: &[byte];
        let mut last: usize = 0;
        let mut i: usize = 0;
        while i < s.len() {
            let (r, width) = utf8::DecodeRuneInString(&s[i..]);
            let width = width as usize;
            i += width;
            match r {
                0x22 => esc = escQuot,
                0x27 => esc = escApos,
                0x26 => esc = escAmp,
                0x3C => esc = escLT,
                0x3E => esc = escGT,
                0x09 => esc = escTab,
                0x0A => esc = escNL,
                0x0D => esc = escCR,
                _ => {
                    if !isInCharacterRange(r) || (r == 0xFFFD && width == 1) {
                        esc = escFFFD;
                    } else {
                        continue;
                    }
                }
            }
            self.WriteString(string::from_bytes(&s[last..i - width]));
            self.Write(slice::__from_vec(esc.to_vec()));
            last = i;
        }
        self.WriteString(string::from_bytes(&s[last..]));
    }
}

// go: sdk 1.25.5 encoding/xml/xml.go:2004-2006 Escape
/// Escape is like [`EscapeText`] but omits the error return value. It is
/// provided for backwards compatibility with Go 1.0. Code targeting Go
/// 1.1 or later should use [`EscapeText`].
pub fn Escape(w: &mut dyn io::Writer, s: slice<byte>) {
    let _ = EscapeText(w, s); // goishlint:ignore GOISH012 — Go discards the error: `EscapeText(w, s)` as a statement.
}

// go: sdk 1.25.5 encoding/xml/xml.go:2008-2012 cdataStart
static cdataStart: &[byte] = b"<![CDATA[";
// go: sdk 1.25.5 encoding/xml/xml.go:2008-2012 cdataEnd
static cdataEnd: &[byte] = b"]]>";
// go: sdk 1.25.5 encoding/xml/xml.go:2008-2012 cdataEscape
static cdataEscape: &[byte] = b"]]]]><![CDATA[>";

// go: sdk 1.25.5 encoding/xml/xml.go:2016-2045 emitCDATA
/// emitCDATA writes to w the CDATA-wrapped plain text data s. It escapes
/// CDATA directives nested in s.
pub(super) fn emitCDATA(w: &mut dyn io::Writer, s: &[byte]) -> error {
    if s.is_empty() {
        return nil;
    }
    let err = writeBytes(w, cdataStart);
    if err != nil {
        return err;
    }

    let mut s = s;
    loop {
        let i = bytes::Index(slice::__from_vec(s.to_vec()), slice::__from_vec(cdataEnd.to_vec()));
        if i < 0 {
            break;
        }
        let (before, after) = (&s[..i as usize], &s[i as usize + cdataEnd.len()..]);
        // Found a nested CDATA directive end.
        let err = writeBytes(w, before);
        if err != nil {
            return err;
        }
        let err = writeBytes(w, cdataEscape);
        if err != nil {
            return err;
        }
        s = after;
    }

    let err = writeBytes(w, s);
    if err != nil {
        return err;
    }

    return writeBytes(w, cdataEnd);
}

// go: sdk 1.25.5 encoding/xml/xml.go:2049-2076 procInst
/// procInst parses the `param="..."` or `param='...'` value out of the
/// provided string, returning "" if not found.
fn procInst<P: Into<string>>(param: P, s: string) -> string {
    // TODO: this parsing is somewhat lame and not exact.
    // It works for all actual cases, though.
    let param = param.into() + "=";
    let lenp = param.Len();
    let mut i: int = 0;
    let mut sep: byte = 0;
    while i < s.Len() {
        let sub = s.slice(i, s.Len());
        let k = strings::Index(&sub, &param);
        if k < 0 || lenp + k >= sub.Len() {
            return string::new();
        }
        i += lenp + k + 1;
        let c = sub[lenp + k];
        if c == b'\'' || c == b'"' {
            sep = c;
            break;
        }
    }
    if sep == 0 {
        return string::new();
    }
    let j = strings::IndexByte(s.slice(i, s.Len()), sep);
    if j < 0 {
        return string::new();
    }
    return s.slice(i, i + j);
}
