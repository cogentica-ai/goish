// go: file encoding/xml/marshal.go decls: Marshal, MarshalIndent, NewEncoder, Encoder.Indent, Encoder.Encode, Encoder.EncodeElement, Encoder.EncodeToken, isValidDirective, Encoder.Flush, Encoder.Close, printer.createAttrPrefix, printer.deleteAttrPrefix, printer.markPrefix, printer.popPrefix, printer.marshalValue, printer.marshalAttr, defaultStart, printer.marshalInterface, printer.marshalTextInterface, printer.writeStart, printer.writeEnd, printer.marshalSimple, indirect, printer.marshalStruct, printer.Write, printer.WriteString, printer.WriteByte, printer.Close, printer.cachedWriteError, printer.writeIndent, parentStack.trim, parentStack.push, UnsupportedTypeError.Error, isEmptyValue
//
// encoding/xml/marshal.go — the encoder: a token writer that enforces
// balance and name-space prefixes, and the reflective walk that turns a
// value into those tokens.
//
// What is kept, because a plausible port loses it without any test on
// well-formed input noticing:
//
//   * Element-name precedence: EncodeElement's start, then the struct's
//     XMLName tag, then the XMLName field's value, then the field tag or
//     name, then the type name. A nameless type is an
//     UnsupportedTypeError, not an empty tag.
//   * Attribute name spaces get a generated `xmlns:prefix` declaration,
//     derived from the URL's last path segment, `_`-prefixed when it
//     starts with any case of "xml", and suffixed `_N` on a clash.
//   * Fields that share an `a>b` parent chain share one parent element;
//     parents are opened lazily and closed on the first divergence.
//   * `,comment` refuses "--" and pads a trailing "-" with a space so the
//     closing marker cannot become "--->".
//   * Indent adds nothing before the first element and closes an element
//     that holds only text on the same line.
//
// ─── Deviations ───────────────────────────────────────────────────────
//
//   * `Marshal(v any)` is `Marshal(v: &T)` with `T: reflect::Reflect`,
//     the same shape as encoding/asn1 and encoding/json here. The walk
//     reads goish's owned `reflect::Value` tree.
//
//   * `Marshaler`, `MarshalerAttr` and `encoding.TextMarshaler` are not
//     discovered on nested values. Go asks each value whether it
//     implements them (`reflect.TypeAssert`); a goish `reflect::Value`
//     is a copy of the data with no route back to the concrete type, so
//     there is nothing to ask. The traits are declared and
//     `marshalInterface` is ported, so a caller that holds the concrete
//     value can still drive them through `EncodeToken`/`EncodeElement`.
//     The single exception is `time.Time`, recognised by its reflected
//     name — the same idiom encoding/asn1 uses — and marshaled through
//     its real `MarshalText`, which is by far the commonest
//     TextMarshaler in XML documents.
//
//   * The Encoder holds `bufio.Writer<Box<dyn io.Writer>>`; Go's printer
//     also holds a back-pointer `encoder *Encoder`, which Rust's
//     ownership rules do not allow. The one use, handing the Encoder to
//     `MarshalXML`, is served by making `marshalInterface` a method on
//     Encoder instead of on printer.
//
//   * `parentStack` does not hold its printer; `trim` and `push` take
//     it as an argument, for the same borrow reason.
//
//   * Type names in messages are goish's `reflect::Type.String()` —
//     `Person` where Go prints `main.Person`.
//
// goishlint:ignore GOISH021 encoder — the printer's back-pointer; see the Encoder deviation above.
// goishlint:ignore GOISH021 marshalerType, marshalerAttrType, textMarshalerType — Go caches these to call `Type.Implements`; see the Marshaler deviation above for why goish cannot ask.
// goishlint:ignore GOISH021 ddBytes — `strings.Contains(s, "--")` below reads the literal directly.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::typeinfo::{
    dontInitNilPointers, fAny, fAttr, fCDATA, fCharData, fComment, fElement, fInnerXML, fMode,
    fOmitEmpty, fieldInfo, getTypeInfo, typeInfo,
};
use super::xml::{
    emitCDATA, escapeText, isName, isNameString, xmlPrefix, xmlURL, xmlnsPrefix, Attr, Directive,
    EscapeText, Name, StartElement, Token,
};
use crate::bufio;
use crate::bytes;
use crate::errors::{self, error, nil, ErrorTrait, Wrap};
use crate::fmt;
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::reflect::{self, FromReflectValue, Kind, Type, Value};
use crate::strconv;
use crate::strings;
use crate::sync;
use crate::time;
use crate::types::{byte, int};

// go: sdk 1.25.5 encoding/xml/marshal.go:19-24 Header
/// Header is a generic XML header suitable for use with the output of
/// [`Marshal`]. This is not automatically added to any output of this
/// package, it is provided as a convenience.
pub const Header: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

// go: sdk 1.25.5 encoding/xml/marshal.go:82-92 Marshal
/// Marshal returns the XML encoding of v.
///
/// Marshal handles a slice by marshaling each of the elements, a pointer
/// by marshaling the value it points at or, if the pointer is nil, by
/// writing nothing, and all other data by writing one or more XML
/// elements containing the data. See the package documentation of Go's
/// encoding/xml for the full set of struct-tag rules; all of them apply.
pub fn Marshal<T: reflect::Reflect + ?Sized>(v: &T) -> (slice<byte>, error) {
    let b = Arc::new(sync::Mutex::new(bytes::Buffer::default()));
    let mut enc = NewEncoder(b.clone());
    let err = enc.Encode(v);
    if err != nil {
        return (slice::new(), err);
    }
    let err = enc.Close();
    if err != nil {
        return (slice::new(), err);
    }
    let out = b.Lock().Bytes();
    return (out, nil);
}

// go: sdk 1.25.5 encoding/xml/marshal.go:110-112 Marshaler
/// Marshaler is the interface implemented by objects that can marshal
/// themselves into valid XML elements.
///
/// MarshalXML encodes the receiver as zero or more XML elements. See the
/// file banner: the reflective [`Marshal`] cannot discover this on a
/// nested value in goish.
#[goish::interface]
pub trait Marshaler {
    fn MarshalXML(&self, e: &mut Encoder, start: StartElement) -> error;
}

// go: sdk 1.25.5 encoding/xml/marshal.go:125-127 MarshalerAttr
/// MarshalerAttr is the interface implemented by objects that can marshal
/// themselves into valid XML attributes. If MarshalXMLAttr returns the
/// zero attribute, no attribute will be generated in the output.
#[goish::interface]
pub trait MarshalerAttr {
    fn MarshalXMLAttr(&self, name: Name) -> (Attr, error);
}

// go: sdk 1.25.5 encoding/xml/marshal.go:132-143 MarshalIndent
/// MarshalIndent works like [`Marshal`], but each XML element begins on a
/// new indented line that starts with prefix and is followed by one or
/// more copies of indent according to the nesting depth.
pub fn MarshalIndent<T: reflect::Reflect + ?Sized, P: Into<string>, I: Into<string>>(
    v: &T,
    prefix: P,
    indent: I,
) -> (slice<byte>, error) {
    let b = Arc::new(sync::Mutex::new(bytes::Buffer::default()));
    let mut enc = NewEncoder(b.clone());
    enc.Indent(prefix, indent);
    let err = enc.Encode(v);
    if err != nil {
        return (slice::new(), err);
    }
    let err = enc.Close();
    if err != nil {
        return (slice::new(), err);
    }
    let out = b.Lock().Bytes();
    return (out, nil);
}

// go: sdk 1.25.5 encoding/xml/marshal.go:146-148 Encoder
/// An Encoder writes XML data to an output stream.
pub struct Encoder {
    p: printer,
}

// go: sdk 1.25.5 encoding/xml/marshal.go:151-155 NewEncoder
/// NewEncoder returns a new encoder that writes to w.
pub fn NewEncoder<W: io::Writer + 'static>(w: W) -> Encoder {
    let b: Box<dyn io::Writer> = Box::new(w);
    return Encoder {
        p: printer {
            w: bufio::NewWriter(b),
            seq: 0,
            indent: string::new(),
            prefix: string::new(),
            depth: 0,
            indentedIn: false,
            putNewline: false,
            attrNS: map::new(),
            attrPrefix: map::new(),
            prefixes: Vec::new(),
            tags: Vec::new(),
            closed: false,
            err: nil,
        },
    };
}

impl Encoder {
    // go: sdk 1.25.5 encoding/xml/marshal.go:160-163 Encoder.Indent
    /// Indent sets the encoder to generate XML in which each element
    /// begins on a new indented line that starts with prefix and is
    /// followed by one or more copies of indent according to the nesting
    /// depth.
    pub fn Indent<P: Into<string>, I: Into<string>>(&mut self, prefix: P, indent: I) {
        self.p.prefix = prefix.into();
        self.p.indent = indent.into();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:171-177 Encoder.Encode
    /// Encode writes the XML encoding of v to the stream. Encode calls
    /// [`Encoder::Flush`] before returning.
    pub fn Encode<T: reflect::Reflect + ?Sized>(&mut self, v: &T) -> error {
        let err = self.p.marshalValue(reflect::ValueOf(v), None, None);
        if err != nil {
            return err;
        }
        return self.p.w.Flush();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:186-192 Encoder.EncodeElement
    /// EncodeElement writes the XML encoding of v to the stream, using
    /// start as the outermost tag in the encoding. EncodeElement calls
    /// [`Encoder::Flush`] before returning.
    pub fn EncodeElement<T: reflect::Reflect + ?Sized>(&mut self, v: &T, start: StartElement) -> error {
        let err = self.p.marshalValue(reflect::ValueOf(v), None, Some(&start));
        if err != nil {
            return err;
        }
        return self.p.w.Flush();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:212-265 Encoder.EncodeToken
    /// EncodeToken writes the given XML token to the stream. It returns an
    /// error if StartElement and EndElement tokens are not properly
    /// matched.
    ///
    /// EncodeToken does not call [`Encoder::Flush`]; callers that invoke
    /// it directly need to call Flush when finished. It allows writing a
    /// ProcInst with Target set to "xml" only as the first token in the
    /// stream.
    pub fn EncodeToken<T: Into<Token>>(&mut self, t: T) -> error {
        let p = &mut self.p;
        match t.into() {
            Token::StartElement(t) => {
                let err = p.writeStart(&t);
                if err != nil {
                    return err;
                }
            }
            Token::EndElement(t) => {
                let err = p.writeEnd(&t.Name);
                if err != nil {
                    return err;
                }
            }
            Token::CharData(t) => {
                let _ = escapeText(p, &t.0, false); // goishlint:ignore GOISH012 — Go discards it too; the printer caches the write error.
            }
            Token::Comment(t) => {
                if bytes::Contains(t.0.clone(), slice::__from_vec(endComment.to_vec())) {
                    return fmt::Errorf!("xml: EncodeToken of Comment containing --> marker");
                }
                p.WriteString("<!--");
                p.Write(t.0);
                p.WriteString("-->");
                return p.cachedWriteError();
            }
            Token::ProcInst(t) => {
                // First token to be encoded which is also a ProcInst with
                // target of xml is the xml declaration. The only ProcInst
                // where target of xml is allowed.
                if t.Target == "xml" && p.w.Buffered() != 0 {
                    return fmt::Errorf!(
                        "xml: EncodeToken of ProcInst xml target only valid for xml declaration, first token encoded"
                    );
                }
                if !isNameString(&t.Target) {
                    return fmt::Errorf!("xml: EncodeToken of ProcInst with invalid Target");
                }
                if bytes::Contains(t.Inst.clone(), slice::__from_vec(endProcInst.to_vec())) {
                    return fmt::Errorf!("xml: EncodeToken of ProcInst containing ?> marker");
                }
                p.WriteString("<?");
                p.WriteString(t.Target);
                if t.Inst.len() > 0 {
                    p.WriteByte(b' ');
                    p.Write(t.Inst);
                }
                p.WriteString("?>");
            }
            Token::Directive(t) => {
                if !isValidDirective(&t) {
                    return fmt::Errorf!("xml: EncodeToken of Directive containing wrong < or > markers");
                }
                p.WriteString("<!");
                p.Write(t.0);
                p.WriteString(">");
            }
            Token::Nil => {
                return fmt::Errorf!("xml: EncodeToken of invalid token type");
            }
        }
        return p.cachedWriteError();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:309-311 Encoder.Flush
    /// Flush flushes any buffered XML to the underlying writer.
    pub fn Flush(&mut self) -> error {
        return self.p.w.Flush();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:316-318 Encoder.Close
    /// Close the Encoder, indicating that no more data will be written. It
    /// flushes any buffered XML to the underlying writer and returns an
    /// error if the written XML is invalid (e.g. by containing unclosed
    /// elements).
    pub fn Close(&mut self) -> error {
        return self.p.Close();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:688-705 printer.marshalInterface
    /// marshalInterface marshals a Marshaler interface value.
    ///
    /// A method on Encoder rather than printer: `MarshalXML` takes the
    /// Encoder, and the printer has no way back to it (see the banner).
    /// `typ` is the receiver's type, for the error message Go builds with
    /// `receiverType(val)`.
    #[allow(dead_code)] // goishlint:ignore GOISH025 — reachable once reflect can recover a Marshaler; see the banner.
    pub(super) fn marshalInterface(
        &mut self,
        val: &(dyn Marshaler + Send + Sync),
        typ: Type,
        start: StartElement,
    ) -> error {
        // Push a marker onto the tag stack so that MarshalXML cannot close
        // the XML tags that it did not open.
        self.p.tags.push(Name::default());
        let n = self.p.tags.len();

        let err = val.MarshalXML(self, start);
        if err != nil {
            return err;
        }

        // Make sure MarshalXML closed all its tags. p.tags[n-1] is the mark.
        if self.p.tags.len() > n {
            return fmt::Errorf!(
                "xml: %s.MarshalXML wrote invalid XML: <%s> not closed",
                super::read::receiverType(typ),
                self.p.tags[self.p.tags.len() - 1].Local
            );
        }
        self.p.tags.truncate(n - 1);
        return nil;
    }
}

// go: sdk 1.25.5 encoding/xml/marshal.go:194-198 begComment
static begComment: &[byte] = b"<!--";
// go: sdk 1.25.5 encoding/xml/marshal.go:194-198 endComment
static endComment: &[byte] = b"-->";
// go: sdk 1.25.5 encoding/xml/marshal.go:194-198 endProcInst
static endProcInst: &[byte] = b"?>";

// go: sdk 1.25.5 encoding/xml/marshal.go:269-305 isValidDirective
/// isValidDirective reports whether dir is a valid directive text,
/// meaning angle brackets are matched, ignoring comments and strings.
fn isValidDirective(dir: &Directive) -> bool {
    let dir: &[byte] = &dir.0;
    let mut depth: int = 0;
    let mut inquote: byte = 0;
    let mut incomment = false;
    for (i, c) in crate::range!(*dir) {
        let (i, c) = (i as usize, *c);
        if incomment {
            if c == b'>' {
                let n = 1 + i as isize - endComment.len() as isize;
                if n >= 0 && &dir[n as usize..i + 1] == endComment {
                    incomment = false;
                }
            }
            // Just ignore anything in comment
        } else if inquote != 0 {
            if c == inquote {
                inquote = 0;
            }
            // Just ignore anything within quotes
        } else if c == b'\'' || c == b'"' {
            inquote = c;
        } else if c == b'<' {
            if i + begComment.len() < dir.len() && &dir[i..i + begComment.len()] == begComment {
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
    }
    return depth == 0 && inquote == 0 && !incomment;
}

// go: sdk 1.25.5 encoding/xml/marshal.go:320-335 printer
pub(super) struct printer {
    w: bufio::Writer<Box<dyn io::Writer>>,
    seq: int,
    indent: string,
    prefix: string,
    depth: int,
    indentedIn: bool,
    putNewline: bool,
    attrNS: map<string, string>,     // map prefix -> name space
    attrPrefix: map<string, string>, // map name space -> prefix
    prefixes: Vec<string>,
    tags: Vec<Name>,
    closed: bool,
    err: error,
}

// go: none — goish idiom: the printer is Go's `io.Writer` by virtue of
//     its `Write` method, which `EscapeText(p, …)` relies on; Rust needs
//     the impl spelled out. It forwards to the inherent method.
impl io::Writer for printer {
    fn Write(&mut self, b: slice<byte>) -> (int, error) {
        return printer::Write(self, b);
    }
}

impl printer {
    // go: sdk 1.25.5 encoding/xml/marshal.go:339-396 printer.createAttrPrefix
    /// createAttrPrefix finds the name space prefix attribute to use for
    /// the given name space, defining a new prefix if necessary. It
    /// returns the prefix.
    fn createAttrPrefix(&mut self, url: &string) -> string {
        let (prefix, _) = self.attrPrefix.Get(url.clone());
        if prefix != "" {
            return prefix;
        }

        // The "http://www.w3.org/XML/1998/namespace" name space is
        // predefined as "xml" and must be referred to that way. (The
        // "http://www.w3.org/2000/xmlns/" name space is also predefined as
        // "xmlns", but users should not be trying to use that one
        // directly - that's our job.)
        if *url == xmlURL {
            return string::from(xmlPrefix);
        }

        // Pick a name. We try to use the final element of the path but
        // fall back to _.
        let mut prefix = strings::TrimRight(url, "/");
        let i = strings::LastIndex(&prefix, "/");
        if i >= 0 {
            prefix = prefix.slice(i + 1, prefix.Len());
        }
        if prefix == "" || !isName(prefix.as_bytes()) || strings::Contains(&prefix, ":") {
            prefix = string::from("_");
        }
        // xmlanything is reserved and any variant of it regardless of
        // case should be matched, so:
        //    (('X'|'x') ('M'|'m') ('L'|'l'))
        // See Section 2.3 of https://www.w3.org/TR/REC-xml/
        if prefix.Len() >= 3 && strings::EqualFold(prefix.slice(0, 3), "xml") {
            prefix = string::from("_") + prefix;
        }
        let (taken, _) = self.attrNS.Get(prefix.clone());
        if taken != "" {
            // Name is taken. Find a better one.
            self.seq += 1;
            loop {
                let id = prefix.clone() + "_" + strconv::Itoa(self.seq);
                let (used, _) = self.attrNS.Get(id.clone());
                if used == "" {
                    prefix = id;
                    break;
                }
                self.seq += 1;
            }
        }

        self.attrPrefix.Set(url.clone(), prefix.clone());
        self.attrNS.Set(prefix.clone(), url.clone());

        self.WriteString("xmlns:");
        self.WriteString(prefix.clone());
        self.WriteString("=\"");
        let _ = EscapeText(self, slice::__from_vec(url.as_bytes().to_vec())); // goishlint:ignore GOISH012 — Go discards it; the printer caches the write error.
        self.WriteString("\" ");

        self.prefixes.push(prefix.clone());

        return prefix;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:399-402 printer.deleteAttrPrefix
    /// deleteAttrPrefix removes an attribute name space prefix.
    fn deleteAttrPrefix(&mut self, prefix: &string) {
        let (url, _) = self.attrNS.Get(prefix.clone());
        self.attrPrefix.Delete(url);
        self.attrNS.Delete(prefix.clone());
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:404-406 printer.markPrefix
    fn markPrefix(&mut self) {
        self.prefixes.push(string::new());
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:408-417 printer.popPrefix
    fn popPrefix(&mut self) {
        while let Some(prefix) = self.prefixes.pop() {
            if prefix == "" {
                break;
            }
            self.deleteAttrPrefix(&prefix);
        }
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:427-579 printer.marshalValue
    /// marshalValue writes one or more XML elements representing val. If
    /// val was obtained from a struct field, finfo must have its details.
    fn marshalValue(
        &mut self,
        val: Value,
        finfo: Option<&fieldInfo>,
        startTemplate: Option<&StartElement>,
    ) -> error {
        if let Some(st) = startTemplate {
            if st.Name.Local == "" {
                return fmt::Errorf!("xml: EncodeElement of StartElement with missing name");
            }
        }

        if !val.IsValid() {
            return nil;
        }
        if let Some(fi) = finfo {
            if fi.flags & fOmitEmpty != 0 && isEmptyValue(&val) {
                return nil;
            }
        }

        // Drill into interfaces and pointers. This can turn into an
        // infinite loop given a cyclic chain, but it matches the Go 1
        // behavior.
        let mut val = val;
        while val.Kind() == Kind::Interface || val.Kind() == Kind::Pointer {
            if isNil(&val) {
                return nil;
            }
            val = elem(val);
        }

        let kind = val.Kind();
        let typ = val.Type();

        // Check for marshaler. goish can recover only time.Time's
        // TextMarshaler from a reflected value; see the file banner.
        if isTimeType(&typ) {
            let (t, _) = <time::Time as FromReflectValue>::from_reflect_value(val);
            return self.marshalTextInterface(t, defaultStart(&typ, finfo, startTemplate));
        }

        // Slices and arrays iterate over the elements. They do not have an
        // enclosing tag.
        if (kind == Kind::Slice || kind == Kind::Array) && !isByteSlice(&val) {
            let n = val.Len();
            let mut i: int = 0;
            while i < n {
                let err = self.marshalValue(val.Index(i), finfo, startTemplate);
                if err != nil {
                    return err;
                }
                i += 1;
            }
            return nil;
        }

        let (tinfo, err) = getTypeInfo(&typ);
        if err != nil {
            return err;
        }

        // Create start element.
        // Precedence for the XML element name is:
        // 0. startTemplate
        // 1. XMLName field in underlying struct;
        // 2. field name/tag in the struct field; and
        // 3. type name
        let mut start = StartElement::default();

        if let Some(st) = startTemplate {
            start.Name = st.Name.clone();
            start.Attr = st.Attr.clone();
        } else if let Some(xmlname) = &tinfo.xmlname {
            if xmlname.name != "" {
                (start.Name.Space, start.Name.Local) = (xmlname.xmlns.clone(), xmlname.name.clone());
            } else {
                let mut sv = val.clone();
                if let Some((fv, ft)) = xmlname.value(&mut sv, typ, dontInitNilPointers) {
                    if super::typeinfo::isNameType(&ft) {
                        let (v, _) = <Name as FromReflectValue>::from_reflect_value(fv.clone());
                        if v.Local != "" {
                            start.Name = v;
                        }
                    }
                }
            }
        }
        if start.Name.Local == "" {
            if let Some(fi) = finfo {
                (start.Name.Space, start.Name.Local) = (fi.xmlns.clone(), fi.name.clone());
            }
        }
        if start.Name.Local == "" {
            let mut name = typeName(&typ);
            let i = strings::IndexByte(&name, b'[');
            if i >= 0 {
                // Truncate generic instantiation name. See issue 48318.
                name = name.slice(0, i);
            }
            if name == "" {
                return Wrap(UnsupportedTypeError { Type: typ });
            }
            start.Name.Local = name;
        }

        // Attributes
        for (_, finfo) in crate::range!(tinfo.fields[..]) {
            if finfo.flags & fAttr == 0 {
                continue;
            }
            let mut sv = val.clone();
            let fv = match finfo.value(&mut sv, typ, dontInitNilPointers) {
                Some((fv, _)) => fv.clone(),
                None => Value::Invalid,
            };

            if finfo.flags & fOmitEmpty != 0 && (!fv.IsValid() || isEmptyValue(&fv)) {
                continue;
            }

            if fv.Kind() == Kind::Interface && isNil(&fv) {
                continue;
            }

            let name = Name {
                Space: finfo.xmlns.clone(),
                Local: finfo.name.clone(),
            };
            let err = self.marshalAttr(&mut start, name, fv);
            if err != nil {
                return err;
            }
        }

        // If an empty name was found, namespace is overridden with an
        // empty space
        if let Some(xmlname) = &tinfo.xmlname {
            if start.Name.Space == ""
                && xmlname.xmlns == ""
                && xmlname.name == ""
                && !self.tags.is_empty()
                && self.tags[self.tags.len() - 1].Space != ""
            {
                start.Attr = crate::append!(
                    start.Attr,
                    Attr {
                        Name: Name {
                            Space: string::new(),
                            Local: string::from(xmlnsPrefix),
                        },
                        Value: string::new(),
                    }
                );
            }
        }
        let err = self.writeStart(&start);
        if err != nil {
            return err;
        }

        let mut err: error = nil;
        if val.Kind() == Kind::Struct {
            err = self.marshalStruct(&tinfo, &val);
        } else {
            let (s, b, err1) = self.marshalSimple(&typ, &val);
            if err1 != nil {
                err = err1;
            } else if let Some(b) = b {
                let _ = EscapeText(self, b); // goishlint:ignore GOISH012 — Go discards it; the printer caches the write error.
            } else {
                self.EscapeString(&s);
            }
        }
        if err != nil {
            return err;
        }

        let err = self.writeEnd(&start.Name);
        if err != nil {
            return err;
        }

        return self.cachedWriteError();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:582-663 printer.marshalAttr
    /// marshalAttr marshals an attribute with the given name and value,
    /// adding to start.Attr.
    fn marshalAttr(&mut self, start: &mut StartElement, name: Name, val: Value) -> error {
        // MarshalerAttr / TextMarshaler: only time.Time is recoverable from
        // a reflected value (see the file banner).
        if isTimeType(&val.Type()) {
            let (t, _) = <time::Time as FromReflectValue>::from_reflect_value(val);
            let (text, err) = t.MarshalText();
            if err != nil {
                return err;
            }
            start.Attr = crate::append!(
                core::mem::take(&mut start.Attr),
                Attr {
                    Name: name,
                    Value: string::from_bytes(&text),
                }
            );
            return nil;
        }

        // Dereference or skip nil pointer, interface values.
        let mut val = val;
        match val.Kind() {
            Kind::Pointer | Kind::Interface => {
                if isNil(&val) {
                    return nil;
                }
                val = elem(val);
            }
            _ => {}
        }

        // Walk slices.
        if val.Kind() == Kind::Slice && !isByteSlice(&val) {
            let n = val.Len();
            let mut i: int = 0;
            while i < n {
                let err = self.marshalAttr(start, name.clone(), val.Index(i));
                if err != nil {
                    return err;
                }
                i += 1;
            }
            return nil;
        }

        if val.Type() == <Attr as reflect::Reflect>::__reflect_type() {
            let (attr, _) = <Attr as FromReflectValue>::from_reflect_value(val);
            start.Attr = crate::append!(core::mem::take(&mut start.Attr), attr);
            return nil;
        }

        let (mut s, b, err) = self.marshalSimple(&val.Type(), &val);
        if err != nil {
            return err;
        }
        if let Some(b) = b {
            s = string::from_bytes(&b);
        }
        start.Attr = crate::append!(core::mem::take(&mut start.Attr), Attr { Name: name, Value: s });
        return nil;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:708-718 printer.marshalTextInterface
    /// marshalTextInterface marshals a TextMarshaler interface value.
    ///
    /// Go takes an `encoding.TextMarshaler`; `time.Time` is the one goish
    /// can reach from a reflected value, so that is the parameter.
    fn marshalTextInterface(&mut self, val: time::Time, start: StartElement) -> error {
        let err = self.writeStart(&start);
        if err != nil {
            return err;
        }
        let (text, err) = val.MarshalText();
        if err != nil {
            return err;
        }
        let _ = EscapeText(self, text); // goishlint:ignore GOISH012 — Go discards it; the printer caches the write error.
        return self.writeEnd(&start.Name);
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:721-757 printer.writeStart
    /// writeStart writes the given start element.
    fn writeStart(&mut self, start: &StartElement) -> error {
        if start.Name.Local == "" {
            return fmt::Errorf!("xml: start tag with no name");
        }

        self.tags.push(start.Name.clone());
        self.markPrefix();

        self.writeIndent(1);
        self.WriteByte(b'<');
        self.WriteString(start.Name.Local.clone());

        if start.Name.Space != "" {
            self.WriteString(" xmlns=\"");
            self.EscapeString(&start.Name.Space);
            self.WriteByte(b'"');
        }

        // Attributes
        for (_, attr) in crate::range!(start.Attr) {
            let name = &attr.Name;
            if name.Local == "" {
                continue;
            }
            self.WriteByte(b' ');
            if name.Space != "" {
                let prefix = self.createAttrPrefix(&name.Space);
                self.WriteString(prefix);
                self.WriteByte(b':');
            }
            self.WriteString(name.Local.clone());
            self.WriteString("=\"");
            self.EscapeString(&attr.Value);
            self.WriteByte(b'"');
        }
        self.WriteByte(b'>');
        return nil;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:759-781 printer.writeEnd
    fn writeEnd(&mut self, name: &Name) -> error {
        if name.Local == "" {
            return fmt::Errorf!("xml: end tag with no name");
        }
        if self.tags.is_empty() || self.tags[self.tags.len() - 1].Local == "" {
            return fmt::Errorf!("xml: end tag </%s> without start tag", name.Local);
        }
        let top = &self.tags[self.tags.len() - 1];
        if top != name {
            if top.Local != name.Local {
                return fmt::Errorf!(
                    "xml: end tag </%s> does not match start tag <%s>",
                    name.Local,
                    top.Local
                );
            }
            return fmt::Errorf!(
                "xml: end tag </%s> in namespace %s does not match start tag <%s> in namespace %s",
                name.Local,
                name.Space,
                top.Local,
                top.Space
            );
        }
        self.tags.pop();

        self.writeIndent(-1);
        self.WriteByte(b'<');
        self.WriteByte(b'/');
        self.WriteString(name.Local.clone());
        self.WriteByte(b'>');
        self.popPrefix();
        return nil;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:783-816 printer.marshalSimple
    /// Returns the text of a simple value: as a string, or as bytes for a
    /// byte slice. Go returns a nil `[]byte` for "use the string"; goish
    /// returns None.
    fn marshalSimple(&mut self, typ: &Type, val: &Value) -> (string, Option<slice<byte>>, error) {
        match val.Kind() {
            Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
                return (strconv::FormatInt(val.Int(), 10), None, nil);
            }
            Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 | Kind::Uintptr => {
                return (strconv::FormatUint(val.Uint(), 10), None, nil);
            }
            Kind::Float32 | Kind::Float64 => {
                return (
                    strconv::FormatFloat(val.Float(), b'g', -1, val.Type().Bits()),
                    None,
                    nil,
                );
            }
            Kind::String => {
                return (val.String(), None, nil);
            }
            Kind::Bool => {
                return (strconv::FormatBool(val.Bool()), None, nil);
            }
            Kind::Array | Kind::Slice => {
                // [...]byte / []byte
                if isByteSlice(val) {
                    return (string::new(), Some(val.Bytes()), nil);
                }
            }
            _ => {}
        }
        return (
            string::new(),
            None,
            Wrap(UnsupportedTypeError { Type: *typ }),
        );
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:834-987 printer.marshalStruct
    fn marshalStruct(&mut self, tinfo: &typeInfo, val: &Value) -> error {
        let mut s = parentStack { stack: Vec::new() };
        let typ = val.Type();
        for (_, finfo) in crate::range!(tinfo.fields[..]) {
            if finfo.flags & fAttr != 0 {
                continue;
            }
            let mut sv = val.clone();
            let mut vf = match finfo.value(&mut sv, typ, dontInitNilPointers) {
                // The field is behind an anonymous struct field that's
                // nil. Skip it.
                None => continue,
                Some((fv, _)) => fv.clone(),
            };
            if !vf.IsValid() {
                continue;
            }

            let mode = finfo.flags & fMode;
            if mode == fCDATA || mode == fCharData {
                let cdata = mode == fCDATA;
                // Go: `emit := EscapeText` or `emitCDATA`.
                let emit = |p: &mut printer, b: &[byte]| -> error {
                    if cdata {
                        return emitCDATA(p, b);
                    }
                    return escapeText(p, b, true);
                };
                let err = s.trim(self, &finfo.parents);
                if err != nil {
                    return err;
                }
                if isTimeType(&vf.Type()) {
                    let (t, _) = <time::Time as FromReflectValue>::from_reflect_value(vf);
                    let (data, err) = t.MarshalText();
                    if err != nil {
                        return err;
                    }
                    let err = emit(self, &data);
                    if err != nil {
                        return err;
                    }
                    continue;
                }

                vf = indirect(vf);
                let err = match vf.Kind() {
                    Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
                        emit(self, strconv::FormatInt(vf.Int(), 10).as_bytes())
                    }
                    Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 | Kind::Uintptr => {
                        emit(self, strconv::FormatUint(vf.Uint(), 10).as_bytes())
                    }
                    Kind::Float32 | Kind::Float64 => emit(
                        self,
                        strconv::FormatFloat(vf.Float(), b'g', -1, vf.Type().Bits()).as_bytes(),
                    ),
                    Kind::Bool => emit(self, strconv::FormatBool(vf.Bool()).as_bytes()),
                    Kind::String => emit(self, vf.String().as_bytes()),
                    Kind::Slice => {
                        // Go: reflect.TypeAssert[[]byte] — an unnamed byte
                        // slice only.
                        if isUnnamedByteSlice(&vf) {
                            emit(self, &vf.Bytes())
                        } else {
                            nil
                        }
                    }
                    _ => nil,
                };
                if err != nil {
                    return err;
                }
                continue;
            } else if mode == fComment {
                let err = s.trim(self, &finfo.parents);
                if err != nil {
                    return err;
                }
                vf = indirect(vf);
                let k = vf.Kind();
                if !(k == Kind::String || k == Kind::Slice && isByteSlice(&vf)) {
                    return fmt::Errorf!("xml: bad type for comment field of %s", val.Type().String());
                }
                if vf.Len() == 0 {
                    continue;
                }
                self.writeIndent(0);
                self.WriteString("<!--");
                let dashDash: bool;
                let dashLast: bool;
                if k == Kind::String {
                    let s = vf.String();
                    dashDash = strings::Contains(&s, "--");
                    dashLast = s[s.Len() - 1] == b'-';
                    if !dashDash {
                        self.WriteString(s);
                    }
                } else {
                    let b = vf.Bytes();
                    dashDash = bytes::Contains(b.clone(), slice::__from_vec(b"--".to_vec()));
                    dashLast = b[b.len() - 1] == b'-';
                    if !dashDash {
                        self.Write(b);
                    }
                }
                if dashDash {
                    return fmt::Errorf!("xml: comments must not contain \"--\"");
                }
                if dashLast {
                    // "--->" is invalid grammar. Make it "- -->"
                    self.WriteByte(b' ');
                }
                self.WriteString("-->");
                continue;
            } else if mode == fInnerXML {
                vf = indirect(vf);
                // Go: `switch raw := vf.Interface().(type)` — only an
                // unnamed []byte or string matches; anything else falls
                // through to marshalValue.
                if isUnnamedByteSlice(&vf) {
                    self.Write(vf.Bytes());
                    continue;
                }
                if let Value::String(raw) = &vf {
                    self.WriteString(raw.clone());
                    continue;
                }
            } else if mode == fElement || mode == fElement | fAny {
                let err = s.trim(self, &finfo.parents);
                if err != nil {
                    return err;
                }
                if finfo.parents.len() > s.stack.len() {
                    if vf.Kind() != Kind::Pointer && vf.Kind() != Kind::Interface || !isNil(&vf) {
                        let err = s.push(self, &finfo.parents[s.stack.len()..]);
                        if err != nil {
                            return err;
                        }
                    }
                }
            }
            let err = self.marshalValue(vf, Some(finfo), None);
            if err != nil {
                return err;
            }
        }
        let _ = s.trim(self, &[]); // goishlint:ignore GOISH012 — Go writes `s.trim(nil)` as a statement.
        return self.cachedWriteError();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:990-998 printer.Write
    /// Write implements io.Writer
    pub(super) fn Write(&mut self, b: slice<byte>) -> (int, error) {
        let mut n: int = 0;
        if self.closed && self.err == nil {
            self.err = errors::New("use of closed Encoder");
        }
        if self.err == nil {
            (n, self.err) = self.w.Write(b);
        }
        return (n, self.err.clone());
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:1001-1009 printer.WriteString
    /// WriteString implements io.StringWriter
    pub(super) fn WriteString<S: Into<string>>(&mut self, s: S) -> (int, error) {
        let mut n: int = 0;
        if self.closed && self.err == nil {
            self.err = errors::New("use of closed Encoder");
        }
        if self.err == nil {
            (n, self.err) = self.w.WriteString(s);
        }
        return (n, self.err.clone());
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:1012-1020 printer.WriteByte
    /// WriteByte implements io.ByteWriter
    fn WriteByte(&mut self, c: byte) -> error {
        if self.closed && self.err == nil {
            self.err = errors::New("use of closed Encoder");
        }
        if self.err == nil {
            self.err = self.w.WriteByte(c);
        }
        return self.err.clone();
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:1025-1037 printer.Close
    /// Close the Encoder, indicating that no more data will be written. It
    /// flushes any buffered XML to the underlying writer and returns an
    /// error if the written XML is invalid (e.g. by containing unclosed
    /// elements).
    fn Close(&mut self) -> error {
        if self.closed {
            return nil;
        }
        self.closed = true;
        let err = self.w.Flush();
        if err != nil {
            return err;
        }
        if !self.tags.is_empty() {
            return fmt::Errorf!("unclosed tag <%s>", self.tags[self.tags.len() - 1].Local);
        }
        return nil;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:1040-1043 printer.cachedWriteError
    /// return the bufio Writer's cached write error
    fn cachedWriteError(&mut self) -> error {
        let (_, err) = self.Write(slice::new());
        return err;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:1045-1074 printer.writeIndent
    fn writeIndent(&mut self, depthDelta: int) {
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
            self.WriteByte(b'\n');
        } else {
            self.putNewline = true;
        }
        if self.prefix.Len() > 0 {
            self.WriteString(self.prefix.clone());
        }
        if self.indent.Len() > 0 {
            let mut i: int = 0;
            while i < self.depth {
                self.WriteString(self.indent.clone());
                i += 1;
            }
        }
        if depthDelta > 0 {
            self.depth += 1;
            self.indentedIn = true;
        }
    }
}

// go: sdk 1.25.5 encoding/xml/marshal.go:667-685 defaultStart
/// defaultStart returns the default start element to use, given the
/// reflect type, field info, and start template.
fn defaultStart(typ: &Type, finfo: Option<&fieldInfo>, startTemplate: Option<&StartElement>) -> StartElement {
    let mut start = StartElement::default();
    // Precedence for the XML element name is as above, except that we do
    // not look inside structs for the first field.
    if let Some(st) = startTemplate {
        start.Name = st.Name.clone();
        start.Attr = st.Attr.clone();
    } else if finfo.is_some() && finfo.unwrap().name != "" {
        let fi = finfo.unwrap();
        start.Name.Local = fi.name.clone();
        start.Name.Space = fi.xmlns.clone();
    } else if typeName(typ) != "" {
        start.Name.Local = typeName(typ);
    } else {
        // Must be a pointer to a named type, since it has the Marshaler
        // methods.
        start.Name.Local = typeName(&typ.Elem());
    }
    return start;
}

// go: sdk 1.25.5 encoding/xml/marshal.go:824-832 indirect
/// indirect drills into interfaces and pointers, returning the pointed-at
/// value. If it encounters a nil interface or pointer, indirect returns
/// that nil value. This can turn into an infinite loop given a cyclic
/// chain, but it matches the Go 1 behavior.
fn indirect(vf: Value) -> Value {
    let mut vf = vf;
    while vf.Kind() == Kind::Interface || vf.Kind() == Kind::Pointer {
        if isNil(&vf) {
            return vf;
        }
        vf = elem(vf);
    }
    return vf;
}

// go: sdk 1.25.5 encoding/xml/marshal.go:1076-1079 parentStack
struct parentStack {
    stack: Vec<string>,
}

impl parentStack {
    // go: sdk 1.25.5 encoding/xml/marshal.go:1084-1098 parentStack.trim
    /// trim updates the XML context to match the longest common prefix of
    /// the stack and the given parents. A closing tag will be written for
    /// every parent popped. Passing a zero slice or nil will close all the
    /// elements.
    fn trim(&mut self, p: &mut printer, parents: &[string]) -> error {
        let mut split: usize = 0;
        while split < parents.len() && split < self.stack.len() {
            if parents[split] != self.stack[split] {
                break;
            }
            split += 1;
        }
        let mut i = self.stack.len();
        while i > split {
            i -= 1;
            let err = p.writeEnd(&Name {
                Space: string::new(),
                Local: self.stack[i].clone(),
            });
            if err != nil {
                return err;
            }
        }
        self.stack.truncate(split);
        return nil;
    }

    // go: sdk 1.25.5 encoding/xml/marshal.go:1101-1109 parentStack.push
    /// push adds parent elements to the stack and writes open tags.
    fn push(&mut self, p: &mut printer, parents: &[string]) -> error {
        for (_, parent) in crate::range!(*parents) {
            let err = p.writeStart(&StartElement {
                Name: Name {
                    Space: string::new(),
                    Local: parent.clone(),
                },
                Attr: slice::new(),
            });
            if err != nil {
                return err;
            }
        }
        self.stack.extend_from_slice(parents);
        return nil;
    }
}

// go: sdk 1.25.5 encoding/xml/marshal.go:1113-1115 UnsupportedTypeError
/// UnsupportedTypeError is returned when [`Marshal`] encounters a type
/// that cannot be converted into XML.
#[derive(Clone)]
pub struct UnsupportedTypeError {
    pub Type: Type,
}

impl ErrorTrait for UnsupportedTypeError {
    // go: sdk 1.25.5 encoding/xml/marshal.go:1117-1119 UnsupportedTypeError.Error
    fn Error(&self) -> string {
        return string::from("xml: unsupported type: ") + self.Type.String();
    }
}

// go: sdk 1.25.5 encoding/xml/marshal.go:1121-1133 isEmptyValue
fn isEmptyValue(v: &Value) -> bool {
    return match v.Kind() {
        Kind::Array | Kind::Map | Kind::Slice | Kind::String => v.Len() == 0,
        Kind::Bool
        | Kind::Int
        | Kind::Int8
        | Kind::Int16
        | Kind::Int32
        | Kind::Int64
        | Kind::Uint
        | Kind::Uint8
        | Kind::Uint16
        | Kind::Uint32
        | Kind::Uint64
        | Kind::Uintptr
        | Kind::Float32
        | Kind::Float64 => v.IsZero(),
        // Go: v.IsZero(), which for a pointer or interface is "is nil".
        // goish's `Value::IsZero` answers false for every pointer, so ask
        // the question directly.
        Kind::Interface | Kind::Pointer => isNil(v),
        _ => false,
    };
}

// ─── goish helpers over the owned reflect::Value ───────────────────────

// go: none — goish idiom: `v.IsNil()` for pointers AND interfaces. An
//     `any` reflects as `Value::Named { Interface, Invalid }` when nil,
//     which `Value::IsNil` does not treat as nil.
pub(super) fn isNil(v: &Value) -> bool {
    return match v {
        Value::Named { ty, inner } if ty.Kind() == Kind::Interface => !inner.IsValid(),
        Value::Invalid => true,
        other => other.IsNil(),
    };
}

// go: none — goish idiom: `v.Elem()` for a pointer or an interface. Go's
//     `Value.Elem` handles both; goish's handles pointers only.
pub(super) fn elem(v: Value) -> Value {
    return match v {
        Value::Pointer(inner) => *inner,
        Value::Named { ty, inner } if ty.Kind() == Kind::Interface => *inner,
        Value::Named { inner, .. } => elem(*inner),
        other => other,
    };
}

// go: none — goish idiom: Go's `typ.Elem().Kind() == reflect.Uint8` on a
//     slice or array Value.
pub(super) fn isByteSlice(v: &Value) -> bool {
    return match v {
        Value::Named { inner, .. } => isByteSlice(inner),
        Value::Slice { elem_type, .. } => elem_type().Kind() == Kind::Uint8,
        _ => false,
    };
}

// go: none — goish idiom: `v.([]byte)` — an UNNAMED byte slice, which a
//     named `type B []byte` does not satisfy.
pub(super) fn isUnnamedByteSlice(v: &Value) -> bool {
    return matches!(v, Value::Slice { .. }) && isByteSlice(v);
}

// go: none — goish idiom: `t == reflect.TypeFor[time.Time]()`, by the
//     reflected name — see the Marshaler note in the banner.
pub(super) fn isTimeType(t: &Type) -> bool {
    return t.Kind() == Kind::Struct && t.Name() == "time.Time";
}

// go: none — goish idiom: Go's `Type.Name()` is unqualified ("Time");
//     goish's descriptors for library types carry the package
//     ("time.Time"), user structs do not. Strip the qualifier.
pub(super) fn typeName(t: &Type) -> string {
    let name = t.Name();
    let i = strings::LastIndex(&name, ".");
    if i >= 0 {
        return name.slice(i + 1, name.Len());
    }
    return name;
}
