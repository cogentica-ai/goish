// goishlint:ignore GOISH018 Marshal, MarshalIndent, Encoder.Encode, Encoder.EncodeElement, printer.marshalValue, printer.marshalAttr, defaultStart, printer.marshalInterface, printer.marshalTextInterface, printer.marshalSimple, indirect, printer.marshalStruct, isEmptyValue, parentStack.trim, parentStack.push, UnsupportedTypeError.Error — the REFLECT half of marshal.go, deliberately not in this slice. Everything here writes tokens a caller already has; those walk a reflect.Value to produce them, need Marshaler/MarshalerAttr/TextMarshaler interface dispatch, and land together with read.go's matching half so the two can be pinned against Go on the same struct set.
// goishlint:ignore GOISH021 Marshaler, MarshalerAttr, UnsupportedTypeError, parentStack, marshalerType, marshalerAttrType, textMarshalerType, ddBytes — the types the absent reflect half needs and nothing in this slice references.
// goishlint:ignore GOISH019 printer — one field absent, `encoder`. Go sets `e.p.encoder = e` so the printer can call back into Encoder.EncodeElement when it meets a Marshaler; that is a self-referential pointer Rust will not form, and its only reader is marshalValue, which is absent above. It comes back as a parameter when the reflect half lands.
// go: file encoding/xml/marshal.go decls: NewEncoder, Encoder.Indent, Encoder.EncodeToken, isValidDirective, Encoder.Flush, Encoder.Close, printer.createAttrPrefix, printer.deleteAttrPrefix, printer.markPrefix, printer.popPrefix, printer.writeStart, printer.writeEnd, printer.Write, printer.WriteString, printer.WriteByte, printer.Close, printer.cachedWriteError, printer.writeIndent
//
// encoding/xml/marshal.go — the TOKEN PRINTER half.
//
// `EncodeToken` is the mirror of `Decoder.Token`: it takes tokens a
// caller already holds and writes well-formed XML, matching start and
// end tags, inventing `xmlns:` prefixes for attribute name spaces, and
// laying the output out according to `Indent`.
//
// The reflect-driven half of the file — Marshal, Encode, marshalValue
// and everything it reaches — is not here; see the GOISH018 waiver
// above for why it travels with read.go.
//
// PORT NOTES
//
// 1. `Encoder` and `printer` are generic over the writer, because
//    goish's `bufio.Writer<W>` owns its W rather than holding an
//    interface value. A caller who needs the written bytes back passes
//    a shared writer (`Arc<sync::Mutex<bytes::Buffer>>`), which is
//    goish's stand-in for Go's `&buf` as an io.Writer.
//
// 2. `attrNS` and `attrPrefix` are allocated by the constructor. Go
//    leaves them nil and makes them inside `createAttrPrefix`, because
//    a write to a nil map panics; reads of a nil map already return
//    the zero value, so the two are observationally identical.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use super::xml::{isName, isNameString, Attr, Name, StartElement, Token};
use crate::byte;
use crate::bytes;
use crate::errors;
use crate::fmt;
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::int;
use crate::io;

// go: sdk 1.25.5 encoding/xml/marshal.go:19-24 Header
/// Go: "Header is a generic XML header suitable for use with the output
/// of [Marshal]. This is not automatically added to any output of this
/// package, it is provided as a convenience."
pub const Header: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

// go: sdk 1.25.5 encoding/xml/marshal.go:194-198 begComment
/// Go's `var ( begComment; endComment; endProcInst )` block.
pub const begComment: &[byte] = b"<!--";
pub const endComment: &[byte] = b"-->";
pub const endProcInst: &[byte] = b"?>";

// go: sdk 1.25.5 encoding/xml/marshal.go:320-336 printer
/// Go: the marshaller's output state — the buffered writer, the indent
/// settings, the open-tag stack, and the attribute name-space prefixes
/// currently in scope.
pub struct printer<W: io::Writer> {
    pub w: crate::bufio::Writer<W>,
    pub seq: int,
    pub indent: string,
    pub prefix: string,
    pub depth: int,
    pub indentedIn: bool,
    pub putNewline: bool,
    /// Go: `map[string]string // map prefix -> name space`
    pub attrNS: map<string, string>,
    /// Go: `map[string]string // map name space -> prefix`
    pub attrPrefix: map<string, string>,
    pub prefixes: slice<string>,
    pub tags: slice<Name>,
    pub closed: bool,
    pub err: crate::error,
}

// go: sdk 1.25.5 encoding/xml/marshal.go:146-148 Encoder
/// Go: "An Encoder writes XML data to an output stream."
pub struct Encoder<W: io::Writer> {
    pub p: printer<W>,
}

// go: sdk 1.25.5 encoding/xml/marshal.go:150-155 NewEncoder
/// Go: "NewEncoder returns a new encoder that writes to w."
pub fn NewEncoder<W: io::Writer>(w: W) -> Encoder<W> {
    // Go also does `e.p.encoder = e`; see the GOISH019 waiver.
    return Encoder {
        p: printer {
            w: crate::bufio::NewWriter(w),
            seq: 0,
            indent: string::from_static(""),
            prefix: string::from_static(""),
            depth: 0,
            indentedIn: false,
            putNewline: false,
            attrNS: map::new(),
            attrPrefix: map::new(),
            prefixes: crate::slice!([]string{}),
            tags: crate::slice!([]Name{}),
            closed: false,
            err: errors::nil,
        },
    };
}

impl<W: io::Writer> Encoder<W> {
    // go: sdk 1.25.5 encoding/xml/marshal.go:157-164 Encoder.Indent
    /// Go: "Indent sets the encoder to generate XML in which each
    /// element begins on a new indented line that starts with prefix
    /// and is followed by one or more copies of indent according to the
    /// nesting depth."
    pub fn Indent<S1: Into<string>, S2: Into<string>>(&mut self, prefix: S1, indent: S2) {
        self.p.prefix = prefix.into();
        self.p.indent = indent.into();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:200-264 Encoder.EncodeToken
    /// Go: "EncodeToken writes the given XML token to the stream. It
    /// returns an error if [StartElement] and [EndElement] tokens are
    /// not properly matched. ... EncodeToken allows writing a
    /// [ProcInst] with Target set to "xml" only as the first token in
    /// the stream."
    ///
    /// EncodeToken does NOT flush — Go says so explicitly, and the
    /// reference rows call Flush before reading the bytes back.
    pub fn EncodeToken(&mut self, t: Token) -> crate::error {
        let p = &mut self.p;
        match t {
            Token::StartElement(t) => {
                let err = p.writeStart(&t);
                if err != errors::nil {
                    return err;
                }
            }
            Token::EndElement(t) => {
                let err = p.writeEnd(t.Name);
                if err != errors::nil {
                    return err;
                }
            }
            Token::CharData(t) => {
                let _ = super::xml::escapeText(p, &t.0, false);
            }
            Token::Comment(t) => {
                if bytes::Contains(t.0.clone(), slice::__from_vec(endComment.to_vec())) {
                    return fmt::Errorf!(
                        "xml: EncodeToken of Comment containing --> marker"
                    );
                }
                let _ = p.WriteString("<!--");
                let _ = p.Write(t.0.clone());
                let _ = p.WriteString("-->");
                return p.cachedWriteError();
            }
            Token::ProcInst(t) => {
                // Go: "First token to be encoded which is also a
                // ProcInst with target of xml is the xml declaration.
                // The only ProcInst where target of xml is allowed."
                if t.Target == string::from_static("xml") && p.w.Buffered() != 0 {
                    return fmt::Errorf!(
                        "xml: EncodeToken of ProcInst xml target only valid for xml declaration, first token encoded"
                    );
                }
                if !isNameString(t.Target.clone()) {
                    return fmt::Errorf!("xml: EncodeToken of ProcInst with invalid Target");
                }
                if bytes::Contains(t.Inst.clone(), slice::__from_vec(endProcInst.to_vec())) {
                    return fmt::Errorf!("xml: EncodeToken of ProcInst containing ?> marker");
                }
                let _ = p.WriteString("<?");
                let _ = p.WriteString(t.Target.clone());
                if t.Inst.Len() > 0 {
                    let _ = p.WriteByte(b' ');
                    let _ = p.Write(t.Inst.clone());
                }
                let _ = p.WriteString("?>");
            }
            Token::Directive(t) => {
                if !isValidDirective(&t) {
                    return fmt::Errorf!(
                        "xml: EncodeToken of Directive containing wrong < or > markers"
                    );
                }
                let _ = p.WriteString("<!");
                let _ = p.Write(t.0.clone());
                let _ = p.WriteString(">");
            }
        }
        return p.cachedWriteError();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:309-311 Encoder.Flush
    /// Go: "Flush flushes any buffered XML to the underlying writer."
    pub fn Flush(&mut self) -> crate::error {
        return self.p.w.Flush();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:316-318 Encoder.Close
    /// Go: "Close the Encoder, indicating that no more data will be
    /// written. It flushes any buffered XML to the underlying writer
    /// and returns an error if the written XML is invalid (e.g. by
    /// containing unclosed elements)."
    pub fn Close(&mut self) -> crate::error {
        return self.p.Close();
    }
}

// go: sdk 1.25.5 encoding/xml/marshal.go:266-306 isValidDirective
/// Go: "isValidDirective reports whether dir is a valid directive text,
/// meaning angle brackets are matched, ignoring comments and strings."
pub fn isValidDirective(dir: &super::xml::Directive) -> bool {
    let mut depth: int = 0;
    let mut inquote: byte = 0;
    let mut incomment = false;
    let d: &[byte] = &dir.0;
    // Go ranges over a []byte, so `i, c` are byte index and byte —
    // no UTF-8 decoding, which is why this can compare c to '<'.
    let mut i: usize = 0;
    while i < d.len() {
        let c = d[i];
        if incomment {
            if c == b'>' {
                let n = 1 + i as isize - endComment.len() as isize;
                if n >= 0 && &d[n as usize..i + 1] == endComment {
                    incomment = false;
                }
            }
            // Go: "Just ignore anything in comment"
        } else if inquote != 0 {
            if c == inquote {
                inquote = 0;
            }
            // Go: "Just ignore anything within quotes"
        } else if c == b'\'' || c == b'"' {
            inquote = c;
        } else if c == b'<' {
            if i + begComment.len() < d.len() && &d[i..i + begComment.len()] == begComment {
                incomment = true;
            } else {
                depth += 1;
            }
        } else if c == b'>' {
            if depth == 0 {
                return false;
            }
            depth -= 1;
        }
        i += 1;
    }
    return depth == 0 && inquote == 0 && !incomment;
}

impl<W: io::Writer> printer<W> {
    // go: sdk 1.25.5 encoding/xml/marshal.go:338-395 printer.createAttrPrefix
    /// Go: "createAttrPrefix finds the name space prefix attribute to
    /// use for the given name space, defining a new prefix if
    /// necessary. It returns the prefix."
    pub fn createAttrPrefix(&mut self, url: string) -> string {
        let (prefix, _) = self.attrPrefix.Get(url.clone());
        if prefix.Len() != 0 {
            return prefix;
        }

        // Go: "The "http://www.w3.org/XML/1998/namespace" name space is
        // predefined as "xml" and must be referred to that way."
        if url == string::from_static(super::xml::xmlURL) {
            return string::from_static(super::xml::xmlPrefix);
        }

        // Go makes attrPrefix/attrNS here; see port note 2.

        // Go: "Pick a name. We try to use the final element of the path
        // but fall back to _."
        let mut prefix = crate::strings::TrimRight(url.clone(), "/");
        let i = crate::strings::LastIndex(prefix.clone(), "/");
        if i >= 0 {
            prefix = prefix.slice(i + 1, prefix.Len());
        }
        if prefix.Len() == 0
            || !isName(prefix.as_bytes())
            || crate::strings::Contains(prefix.clone(), ":")
        {
            prefix = string::from_static("_");
        }
        // Go: "xmlanything is reserved and any variant of it regardless
        // of case should be matched, so: (('X'|'x') ('M'|'m')
        // ('L'|'l')). See Section 2.3 of
        // https://www.w3.org/TR/REC-xml/"
        if prefix.Len() >= 3 && crate::strings::EqualFold(prefix.slice(0, 3), "xml") {
            prefix = string::from_static("_") + prefix;
        }
        let (taken, _) = self.attrNS.Get(prefix.clone());
        if taken.Len() != 0 {
            // Go: "Name is taken. Find a better one."
            loop {
                self.seq += 1;
                let id = prefix.clone()
                    + string::from_static("_")
                    + crate::strconv::Itoa(self.seq);
                let (t, _) = self.attrNS.Get(id.clone());
                if t.Len() == 0 {
                    prefix = id;
                    break;
                }
            }
        }

        self.attrPrefix.Set(url.clone(), prefix.clone());
        self.attrNS.Set(prefix.clone(), url.clone());

        let _ = self.WriteString("xmlns:");
        let _ = self.WriteString(prefix.clone());
        let _ = self.WriteString("=\"");
        let _ = super::xml::EscapeText(self, url.as_bytes());
        let _ = self.WriteString("\" ");

        self.prefixes = crate::append!(self.prefixes.clone(), prefix.clone());

        return prefix;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:397-401 printer.deleteAttrPrefix
    /// Go: "deleteAttrPrefix removes an attribute name space prefix."
    pub fn deleteAttrPrefix(&mut self, prefix: string) {
        let (url, _) = self.attrNS.Get(prefix.clone());
        self.attrPrefix.Delete(url);
        self.attrNS.Delete(prefix);
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:403-405 printer.markPrefix
    /// Go: pushes the empty-string sentinel that `popPrefix` unwinds to.
    pub fn markPrefix(&mut self) {
        self.prefixes = crate::append!(self.prefixes.clone(), string::from_static(""));
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:407-416 printer.popPrefix
    /// Go: drops every prefix defined since the matching `markPrefix`.
    pub fn popPrefix(&mut self) {
        while self.prefixes.Len() > 0 {
            let prefix = self.prefixes[self.prefixes.Len() - 1].clone();
            self.prefixes = self.prefixes.slice(0, self.prefixes.Len() - 1);
            if prefix.Len() == 0 {
                break;
            }
            self.deleteAttrPrefix(prefix);
        }
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:721-757 printer.writeStart
    /// Go: writes `<name ...attrs>`, pushing the tag and a prefix mark.
    pub fn writeStart(&mut self, start: &StartElement) -> crate::error {
        if start.Name.Local.Len() == 0 {
            return fmt::Errorf!("xml: start tag with no name");
        }

        self.tags = crate::append!(self.tags.clone(), start.Name.clone());
        self.markPrefix();

        self.writeIndent(1);
        let _ = self.WriteByte(b'<');
        let _ = self.WriteString(start.Name.Local.clone());

        if start.Name.Space.Len() != 0 {
            let _ = self.WriteString(" xmlns=\"");
            self.EscapeString(start.Name.Space.clone());
            let _ = self.WriteByte(b'"');
        }

        // Go: "Attributes"
        let mut i: int = 0;
        while i < start.Attr.Len() {
            let attr: Attr = start.Attr[i].clone();
            i += 1;
            let name = attr.Name.clone();
            if name.Local.Len() == 0 {
                continue;
            }
            let _ = self.WriteByte(b' ');
            if name.Space.Len() != 0 {
                let p = self.createAttrPrefix(name.Space.clone());
                let _ = self.WriteString(p);
                let _ = self.WriteByte(b':');
            }
            let _ = self.WriteString(name.Local.clone());
            let _ = self.WriteString("=\"");
            self.EscapeString(attr.Value.clone());
            let _ = self.WriteByte(b'"');
        }
        let _ = self.WriteByte(b'>');
        return errors::nil;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:757-781 printer.writeEnd
    /// Go: writes `</name>` after checking it matches the open tag.
    pub fn writeEnd(&mut self, name: Name) -> crate::error {
        if name.Local.Len() == 0 {
            return fmt::Errorf!("xml: end tag with no name");
        }
        if self.tags.Len() == 0 || self.tags[self.tags.Len() - 1].Local.Len() == 0 {
            return fmt::Errorf!(
                "xml: end tag </%s> without start tag",
                name.Local.clone()
            );
        }
        let top = self.tags[self.tags.Len() - 1].clone();
        if top != name {
            if top.Local != name.Local {
                return fmt::Errorf!(
                    "xml: end tag </%s> does not match start tag <%s>",
                    name.Local.clone(),
                    top.Local.clone()
                );
            }
            return fmt::Errorf!(
                "xml: end tag </%s> in namespace %s does not match start tag <%s> in namespace %s",
                name.Local.clone(),
                name.Space.clone(),
                top.Local.clone(),
                top.Space.clone()
            );
        }
        self.tags = self.tags.slice(0, self.tags.Len() - 1);

        self.writeIndent(-1);
        let _ = self.WriteByte(b'<');
        let _ = self.WriteByte(b'/');
        let _ = self.WriteString(name.Local.clone());
        let _ = self.WriteByte(b'>');
        self.popPrefix();
        return errors::nil;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:990-998 printer.Write
    /// Go: the printer IS the io.Writer the escapers write through; it
    /// latches the first error and refuses writes after Close.
    pub fn Write(&mut self, b: slice<byte>) -> (int, crate::error) {
        if self.closed && self.err == errors::nil {
            self.err = errors::New("use of closed Encoder");
        }
        let mut n: int = 0;
        if self.err == errors::nil {
            let (wn, werr) = self.w.Write(b);
            n = wn;
            self.err = werr;
        }
        return (n, self.err.clone());
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:1001-1009 printer.WriteString
    /// Go: "WriteString implements io.StringWriter"
    pub fn WriteString<S: Into<string>>(&mut self, s: S) -> (int, crate::error) {
        if self.closed && self.err == errors::nil {
            self.err = errors::New("use of closed Encoder");
        }
        let mut n: int = 0;
        if self.err == errors::nil {
            let (wn, werr) = self.w.WriteString(s.into());
            n = wn;
            self.err = werr;
        }
        return (n, self.err.clone());
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:1012-1020 printer.WriteByte
    /// Go: "WriteByte implements io.ByteWriter"
    pub fn WriteByte(&mut self, c: byte) -> crate::error {
        if self.closed && self.err == errors::nil {
            self.err = errors::New("use of closed Encoder");
        }
        if self.err == errors::nil {
            self.err = self.w.WriteByte(c);
        }
        return self.err.clone();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:1025-1037 printer.Close
    /// Go: flushes, then reports any tag left open.
    pub fn Close(&mut self) -> crate::error {
        if self.closed {
            return errors::nil;
        }
        self.closed = true;
        let err = self.w.Flush();
        if err != errors::nil {
            return err;
        }
        if self.tags.Len() > 0 {
            return fmt::Errorf!(
                "unclosed tag <%s>",
                self.tags[self.tags.Len() - 1].Local.clone()
            );
        }
        return errors::nil;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:1040-1043 printer.cachedWriteError
    /// Go: "return the bufio Writer's cached write error"
    pub fn cachedWriteError(&mut self) -> crate::error {
        let (_, err) = self.Write(crate::slice!([]byte{}));
        return err;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:1045-1074 printer.writeIndent
    /// Go: emits the newline, prefix and depth-many indents that
    /// `Encoder.Indent` asked for — and does nothing at all when
    /// neither was set, which is why unindented output has no newlines.
    pub fn writeIndent(&mut self, depthDelta: int) {
        if self.prefix.Len() == 0 && self.indent.Len() == 0 {
            return;
        }
        if depthDelta < 0 {
            self.depth -= 1;
            if self.indentedIn {
                self.indentedIn = false;
                return;
            }
            self.indentedIn = false;
        }
        if self.putNewline {
            let _ = self.WriteByte(b'\n');
        } else {
            self.putNewline = true;
        }
        if self.prefix.Len() > 0 {
            let _ = self.WriteString(self.prefix.clone());
        }
        if self.indent.Len() > 0 {
            let mut i: int = 0;
            while i < self.depth {
                let _ = self.WriteString(self.indent.clone());
                i += 1;
            }
        }
        if depthDelta > 0 {
            self.depth += 1;
            self.indentedIn = true;
        }
    }
}

impl<W: io::Writer> io::Writer for printer<W> {
    // go: none — goish idiom: Go's *printer satisfies io.Writer by
    // having the method; Rust needs the trait impl spelled out so the
    // escapers (which take a W: io::Writer) can write through it.
    fn Write(&mut self, p: slice<byte>) -> (int, crate::error) {
        return printer::Write(self, p);
    }
}
