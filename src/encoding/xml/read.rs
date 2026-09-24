// go: file encoding/xml/read.go decls: Unmarshal, Decoder.Decode, Decoder.DecodeElement, UnmarshalError.Error, receiverType, Decoder.unmarshalInterface, Decoder.unmarshalTextInterface, Decoder.unmarshalAttr, Decoder.unmarshal, copyValue, Decoder.unmarshalPath, Decoder.Skip
//
// encoding/xml/read.go — the reflective decoder: XML elements into
// struct fields, following the same tag table marshal.go writes from.
//
// The rules are order-sensitive, and a port that reorders them still
// passes every test whose document has one obvious home per element:
//
//   * An attribute goes to the field that names it; an attribute nobody
//     names goes to the FIRST `,any,attr` field.
//   * Character data and comments accumulate into the FIRST `,chardata`
//     (or `,cdata`) and `,comment` field; `,innerxml` receives the raw
//     bytes between the tags.
//   * A sub-element goes to the field whose path matches exactly; a
//     partial path match descends; only then does `,any` take it; only
//     then is it skipped. An XMLName tag is a REQUIREMENT on the element
//     name, not a default.
//   * A slice field grows by one per matching element, and shrinks back
//     if decoding that element fails.
//   * Numbers and booleans are whitespace-trimmed; an empty element
//     yields the zero value, and an empty `[]byte` is still non-nil.
//
// ─── Deviations ───────────────────────────────────────────────────────
//
//   * `Unmarshal(data, v any)` is `Unmarshal(data, v: &mut T)` with
//     `T: reflect::Reflect + reflect::FromReflectValue` — encoding/asn1's
//     shape here. goish's `reflect::Value` is an owned copy, so the
//     decoder fills a Value tree taken from `*v` and converts it back
//     with `FromReflectValue`. The copy is taken from the existing value,
//     so Go's merge semantics hold: fields the document does not mention
//     keep their values, and slices are appended to. It is written back
//     even when decoding fails part-way, as Go leaves the partial result
//     in place. Go's "non-pointer passed to Unmarshal" and "nil pointer
//     passed to Unmarshal" cannot happen with a `&mut T`.
//
//   * `Unmarshaler`, `UnmarshalerAttr` and `encoding.TextUnmarshaler`
//     are not discovered on nested values, for the reason marshal.rs
//     gives. `time.Time` is the exception, recognised by name and parsed
//     with its real `UnmarshalText`. The traits are declared and
//     `unmarshalInterface` is ported.
//
//   * The "save" targets (`saveData`, `saveComment`, `saveXML`,
//     `saveAny`) are field indices resolved when written, not live
//     `reflect.Value`s held across the token loop: Rust will not keep
//     several `&mut` into one struct while also recursing into it. Go
//     resolves them with `initNilPointers` at the same point; since
//     goish reflects no embedded fields, that call never allocates, so
//     resolving late is the same operation.
//
//   * Recursion depth is counted as in Go 1.25.5 (the `depth` argument),
//     including the wasm-only 5000 limit being inapplicable here.
//
// goishlint:ignore GOISH021 attrType, unmarshalerType, unmarshalerAttrType, textUnmarshalerType — Go caches `reflect.TypeFor[T]()` to compare type identity; goish compares descriptors directly (`Attr::__reflect_type()`), and the three interface types have no reflect descriptor to cache (see the Unmarshaler deviation above).
// goishlint:ignore GOISH021 maxUnmarshalDepthWasm — goish builds for no wasm target.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use super::marshal::{isByteSlice, isNil, isTimeType, typeName};
use super::typeinfo::{
    fAny, fAttr, fCDATA, fCharData, fComment, fElement, fInnerXML, fMode, getTypeInfo, initNilPointers,
    isNameType, typeInfo, underlying,
};
use super::xml::{Attr, Decoder, NewDecoder, StartElement, Token};
use crate::bytes;
use crate::errors::{self, error, nil, ErrorTrait};
use crate::fmt;
use crate::goslice::slice;
use crate::gostring::string;
use crate::reflect::{self, FromReflectValue, Kind, Reflect, Type, Value};
use crate::strconv;
use crate::strings;
use crate::time;
use crate::types::{byte, int, int64};

// go: sdk 1.25.5 encoding/xml/read.go:133-135 Unmarshal
/// Unmarshal parses the XML-encoded data and stores the result in the
/// value v, which must be a struct, slice, or string (or a type built
/// from them). Well-formed data that does not fit into v is discarded.
///
/// The mapping rules are Go's; see the file banner for the order they
/// apply in and for what differs.
pub fn Unmarshal<T: Reflect + FromReflectValue>(data: slice<byte>, v: &mut T) -> error {
    return NewDecoder(bytes::NewReader(data)).Decode(v);
}

impl Decoder {
    // go: sdk 1.25.5 encoding/xml/read.go:139-141 Decoder.Decode
    /// Decode works like [`Unmarshal`], except it reads the decoder stream
    /// to find the start element.
    pub fn Decode<T: Reflect + FromReflectValue>(&mut self, v: &mut T) -> error {
        return self.DecodeElement(v, None);
    }

    // go: sdk 1.25.5 encoding/xml/read.go:147-157 Decoder.DecodeElement
    /// DecodeElement works like [`Unmarshal`] except that it takes the
    /// start XML element to decode into v. It is useful when a client
    /// reads some raw XML tokens itself but also wants to defer to
    /// Unmarshal for some elements.
    pub fn DecodeElement<T: Reflect + FromReflectValue>(
        &mut self,
        v: &mut T,
        start: Option<&StartElement>,
    ) -> error {
        // Go rejects a non-pointer or nil pointer here; `&mut T` is
        // neither, so decoding starts at `*v` directly.
        let mut val = v.__reflect_value();
        let err = self.unmarshal(&mut val, T::__reflect_type(), start, 0);
        let (nv, werr) = T::from_reflect_value(val);
        if werr == nil {
            *v = nv;
        } else if err == nil {
            return werr;
        }
        return err;
    }
}

// go: sdk 1.25.5 encoding/xml/read.go:160-160 UnmarshalError
/// An UnmarshalError represents an error in the unmarshaling process.
#[derive(Clone, Debug, PartialEq)]
pub struct UnmarshalError(pub string);

impl ErrorTrait for UnmarshalError {
    // go: sdk 1.25.5 encoding/xml/read.go:162-162 UnmarshalError.Error
    fn Error(&self) -> string {
        return self.0.clone();
    }
}

// go: sdk 1.25.5 encoding/xml/read.go:179-181 Unmarshaler
/// Unmarshaler is the interface implemented by objects that can unmarshal
/// an XML element description of themselves. UnmarshalXML must consume
/// exactly one XML element, and may not use `d.RawToken`.
#[goish::interface]
pub trait Unmarshaler {
    fn UnmarshalXML(&mut self, d: &mut Decoder, start: StartElement) -> error;
}

// go: sdk 1.25.5 encoding/xml/read.go:191-193 UnmarshalerAttr
/// UnmarshalerAttr is the interface implemented by objects that can
/// unmarshal an XML attribute description of themselves.
#[goish::interface]
pub trait UnmarshalerAttr {
    fn UnmarshalXMLAttr(&mut self, attr: Attr) -> error;
}

// go: sdk 1.25.5 encoding/xml/read.go:196-202 receiverType
/// receiverType returns the receiver type to use in an expression like
/// "%s.MethodName". Go takes the value; goish takes its type.
pub(super) fn receiverType(t: Type) -> string {
    if typeName(&t) != "" {
        return t.String();
    }
    return string::from("(") + t.String() + ")";
}

// go: sdk 1.25.5 encoding/xml/read.go:314-314 maxUnmarshalDepth
const maxUnmarshalDepth: int = 10000;

// go: sdk 1.25.5 encoding/xml/read.go:318-318 errUnmarshalDepth
crate::var! {
    errUnmarshalDepth: error = "exceeded max depth";
}

// go: none — goish idiom: where a `saveData`/`saveComment`/`saveXML`/
//     `saveAny` points. Go holds a `reflect.Value`; see the banner for
//     why goish holds the address instead.
#[derive(Clone, Copy, PartialEq)]
enum saveSlot {
    none,
    this,
    field(usize),
}

// go: none — goish idiom: resolve a `saveSlot` to the Value it names.
fn slotValue<'a>(val: &'a mut Value, typ: Type, tinfo: &typeInfo, s: saveSlot) -> Option<(&'a mut Value, Type)> {
    return match s {
        saveSlot::none => None,
        saveSlot::this => Some((val, typ)),
        saveSlot::field(i) => tinfo.fields[i].value(val, typ, initNilPointers),
    };
}

impl Decoder {
    // go: sdk 1.25.5 encoding/xml/read.go:206-223 Decoder.unmarshalInterface
    /// unmarshalInterface unmarshals a single XML element into val. start
    /// is the opening tag of the element. `typ` names the receiver in the
    /// error Go builds with `receiverType(val)`.
    #[allow(dead_code)] // goishlint:ignore GOISH025 — reachable once reflect can recover an Unmarshaler; see the banner.
    pub(super) fn unmarshalInterface(
        &mut self,
        val: &mut (dyn Unmarshaler + Send + Sync),
        typ: Type,
        start: &StartElement,
    ) -> error {
        // Record that decoder must stop at end tag corresponding to start.
        self.pushEOF();

        self.unmarshalDepth += 1;
        let err = val.UnmarshalXML(self, start.clone());
        self.unmarshalDepth -= 1;
        if err != nil {
            self.popEOF();
            return err;
        }

        if !self.popEOF() {
            return fmt::Errorf!(
                "xml: %s.UnmarshalXML did not consume entire <%s> element",
                receiverType(typ),
                start.Name.Local
            );
        }

        return nil;
    }

    // go: sdk 1.25.5 encoding/xml/read.go:228-248 Decoder.unmarshalTextInterface
    /// unmarshalTextInterface unmarshals a single XML element into val.
    /// The chardata contained in the element (but not its children) is
    /// passed to the text unmarshaler — here `time.Time`'s, the one goish
    /// recovers from a reflected value.
    fn unmarshalTextInterface(&mut self, val: &mut time::Time) -> error {
        let mut buf: Vec<byte> = Vec::new();
        let mut depth: int = 1;
        while depth > 0 {
            let (t, err) = self.Token();
            if err != nil {
                return err;
            }
            match t {
                Token::CharData(t) => {
                    if depth == 1 {
                        buf.extend_from_slice(&t.0);
                    }
                }
                Token::StartElement(_) => depth += 1,
                Token::EndElement(_) => depth -= 1,
                _ => {}
            }
        }
        return val.UnmarshalText(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 encoding/xml/read.go:251-304 Decoder.unmarshalAttr
    /// unmarshalAttr unmarshals a single XML attribute into val.
    fn unmarshalAttr(&mut self, val: &mut Value, typ: Type, attr: &Attr) -> error {
        let mut val = val;
        let mut typ = typ;
        if typ.Kind() == Kind::Pointer {
            if val.IsNil() {
                val.Set(reflect::New(typ.Elem()));
            }
            typ = typ.Elem();
            val = match val {
                Value::Pointer(inner) => &mut **inner,
                other => other,
            };
        }

        // UnmarshalerAttr / TextUnmarshaler: only time.Time is recoverable
        // from a reflected value (see the banner).
        if isTimeType(&typ) {
            let (mut t, _) = <time::Time as FromReflectValue>::from_reflect_value(val.clone());
            let err = t.UnmarshalText(slice::__from_vec(attr.Value.as_bytes().to_vec()));
            val.Set(t.__reflect_value());
            return err;
        }

        if typ.Kind() == Kind::Slice && !isByteSlice(val) {
            // Slice of element values.
            // Grow slice.
            return match underlying(val) {
                Value::Slice { elem_type, items } => {
                    let et = elem_type();
                    items.push(reflect::Zero(et));
                    let n = items.len() - 1;

                    // Recur to read element into slice.
                    let err = self.unmarshalAttr(&mut items[n], et, attr);
                    if err != nil {
                        items.truncate(n);
                        return err;
                    }
                    nil
                }
                _ => nil,
            };
        }

        if typ == <Attr as Reflect>::__reflect_type() {
            val.Set(attr.__reflect_value());
            return nil;
        }

        return copyValue(Some((val, typ)), attr.Value.as_bytes());
    }

    // go: sdk 1.25.5 encoding/xml/read.go:321-619 Decoder.unmarshal
    /// Unmarshal a single XML element into val, whose static type is typ.
    pub(super) fn unmarshal(
        &mut self,
        val: &mut Value,
        typ: Type,
        start: Option<&StartElement>,
        depth: int,
    ) -> error {
        if depth >= maxUnmarshalDepth {
            return errUnmarshalDepth.into();
        }
        // Find start element if we need it.
        let found: StartElement;
        let start: &StartElement = match start {
            Some(s) => s,
            None => {
                loop {
                    let (tok, err) = self.Token();
                    if err != nil {
                        return err;
                    }
                    if let Token::StartElement(t) = tok {
                        found = t;
                        break;
                    }
                }
                &found
            }
        };

        let mut val = val;
        let mut typ = typ;

        // Load value from interface, but only if the result will be
        // usefully addressable.
        if val.Kind() == Kind::Interface && !isNil(val) {
            let usable = match &*val {
                Value::Named { inner, .. } => inner.Kind() == Kind::Pointer && !inner.IsNil(),
                _ => false,
            };
            if usable {
                val = match val {
                    Value::Named { inner, .. } => &mut **inner,
                    other => other,
                };
                typ = val.Type();
            }
        }

        if typ.Kind() == Kind::Pointer {
            if val.IsNil() {
                val.Set(reflect::New(typ.Elem()));
            }
            typ = typ.Elem();
            val = match val {
                Value::Pointer(inner) => &mut **inner,
                other => other,
            };
        }

        // Unmarshaler / TextUnmarshaler: only time.Time is recoverable
        // from a reflected value (see the banner).
        if isTimeType(&typ) {
            let (mut t, _) = <time::Time as FromReflectValue>::from_reflect_value(val.clone());
            let err = self.unmarshalTextInterface(&mut t);
            val.Set(t.__reflect_value());
            return err;
        }

        let mut data: Vec<byte> = Vec::new();
        let mut saveData = saveSlot::none;
        let mut comment: Vec<byte> = Vec::new();
        let mut saveComment = saveSlot::none;
        let mut saveXML = saveSlot::none;
        let mut saveXMLIndex: int = 0;
        let mut saveXMLData: slice<byte> = slice::new();
        let mut saveAny = saveSlot::none;
        let mut sv = false;
        let mut tinfo = typeInfo::default();

        match typ.Kind() {
            Kind::Interface => {
                // TODO: For now, simply ignore the field. In the near
                //       future we may choose to unmarshal the start
                //       element on it, if not nil.
                return self.Skip();
            }

            Kind::Slice => {
                if isByteSlice(val) {
                    // []byte
                    saveData = saveSlot::this;
                } else {
                    // Slice of element values.
                    // Grow slice.
                    return match underlying(val) {
                        Value::Slice { elem_type, items } => {
                            let et = elem_type();
                            items.push(reflect::Zero(et));
                            let n = items.len() - 1;

                            // Recur to read element into slice.
                            let err = self.unmarshal(&mut items[n], et, Some(start), depth + 1);
                            if err != nil {
                                items.truncate(n);
                                return err;
                            }
                            nil
                        }
                        _ => errors::New(string::from("unknown type ") + typ.String()),
                    };
                }
            }

            Kind::Bool
            | Kind::Float32
            | Kind::Float64
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
            | Kind::String => {
                saveData = saveSlot::this;
            }

            Kind::Struct => {
                if isNameType(&typ) {
                    val.Set(start.Name.__reflect_value());
                } else {
                    sv = true;
                    let err: error;
                    (tinfo, err) = getTypeInfo(&typ);
                    if err != nil {
                        return err;
                    }

                    // Validate and assign element name.
                    if let Some(finfo) = &tinfo.xmlname {
                        if finfo.name != "" && finfo.name != start.Name.Local {
                            return errors::Wrap(UnmarshalError(
                                string::from("expected element type <")
                                    + finfo.name.clone()
                                    + "> but have <"
                                    + start.Name.Local.clone()
                                    + ">",
                            ));
                        }
                        if finfo.xmlns != "" && finfo.xmlns != start.Name.Space {
                            let mut e = string::from("expected element <")
                                + finfo.name.clone()
                                + "> in name space "
                                + finfo.xmlns.clone()
                                + " but have ";
                            if start.Name.Space == "" {
                                e += "no name space";
                            } else {
                                e += start.Name.Space.clone();
                            }
                            return errors::Wrap(UnmarshalError(e));
                        }
                        if let Some((fv, ft)) = finfo.value(val, typ, initNilPointers) {
                            if isNameType(&ft) {
                                fv.Set(start.Name.__reflect_value());
                            }
                        }
                    }

                    // Assign attributes.
                    for (_, a) in crate::range!(start.Attr) {
                        let mut handled = false;
                        let mut any: isize = -1;
                        for (i, finfo) in crate::range!(tinfo.fields[..]) {
                            let mode = finfo.flags & fMode;
                            if mode == fAttr {
                                if a.Name.Local == finfo.name && (finfo.xmlns == "" || finfo.xmlns == a.Name.Space) {
                                    if let Some((strv, st)) = finfo.value(val, typ, initNilPointers) {
                                        let err = self.unmarshalAttr(strv, st, a);
                                        if err != nil {
                                            return err;
                                        }
                                    }
                                    handled = true;
                                }
                            } else if mode == fAny | fAttr {
                                if any == -1 {
                                    any = i as isize;
                                }
                            }
                        }
                        if !handled && any >= 0 {
                            let finfo = &tinfo.fields[any as usize];
                            if let Some((strv, st)) = finfo.value(val, typ, initNilPointers) {
                                let err = self.unmarshalAttr(strv, st, a);
                                if err != nil {
                                    return err;
                                }
                            }
                        }
                    }

                    // Determine whether we need to save character data or
                    // comments.
                    for (i, finfo) in crate::range!(tinfo.fields[..]) {
                        let i = i as usize;
                        let mode = finfo.flags & fMode;
                        if mode == fCDATA || mode == fCharData {
                            if saveData == saveSlot::none {
                                saveData = saveSlot::field(i);
                            }
                        } else if mode == fComment {
                            if saveComment == saveSlot::none {
                                saveComment = saveSlot::field(i);
                            }
                        } else if mode == fAny || mode == fAny | fElement {
                            if saveAny == saveSlot::none {
                                saveAny = saveSlot::field(i);
                            }
                        } else if mode == fInnerXML {
                            if saveXML == saveSlot::none {
                                saveXML = saveSlot::field(i);
                                if self.saved.is_none() {
                                    saveXMLIndex = 0;
                                    self.saved = Some(bytes::Buffer::default());
                                } else {
                                    saveXMLIndex = self.savedOffset();
                                }
                            }
                        }
                    }
                }
            }

            _ => {
                return errors::New(string::from("unknown type ") + typ.String());
            }
        }

        // Find end element.
        // Process sub-elements along the way.
        loop {
            let mut savedOffset: int = 0;
            if saveXML != saveSlot::none {
                savedOffset = self.savedOffset();
            }
            let (tok, err) = self.Token();
            if err != nil {
                return err;
            }
            match tok {
                Token::StartElement(t) => {
                    let mut consumed = false;
                    if sv {
                        let err: error;
                        (consumed, err) = self.unmarshalPath(&tinfo, val, typ, &[], &t, depth);
                        if err != nil {
                            return err;
                        }
                        if !consumed && saveAny != saveSlot::none {
                            consumed = true;
                            if let Some((av, at)) = slotValue(val, typ, &tinfo, saveAny) {
                                let err = self.unmarshal(av, at, Some(&t), depth + 1);
                                if err != nil {
                                    return err;
                                }
                            }
                        }
                    }
                    if !consumed {
                        let err = self.Skip();
                        if err != nil {
                            return err;
                        }
                    }
                }

                Token::EndElement(_) => {
                    if saveXML != saveSlot::none {
                        if let Some(saved) = &self.saved {
                            let all = saved.Bytes();
                            saveXMLData = all.slice(saveXMLIndex, savedOffset);
                        }
                        if saveXMLIndex == 0 {
                            self.saved = None;
                        }
                    }
                    break;
                }

                Token::CharData(t) => {
                    if saveData != saveSlot::none {
                        data.extend_from_slice(&t.0);
                    }
                }

                Token::Comment(t) => {
                    if saveComment != saveSlot::none {
                        comment.extend_from_slice(&t.0);
                    }
                }

                _ => {}
            }
        }

        if let Some((dv, dt)) = slotValue(val, typ, &tinfo, saveData) {
            if isTimeType(&dt) {
                let (mut t, _) = <time::Time as FromReflectValue>::from_reflect_value(dv.clone());
                let err = t.UnmarshalText(slice::__from_vec(data.clone()));
                dv.Set(t.__reflect_value());
                if err != nil {
                    return err;
                }
                saveData = saveSlot::none;
            }
        }

        let err = copyValue(slotValue(val, typ, &tinfo, saveData), &data);
        if err != nil {
            return err;
        }

        if let Some((t, _)) = slotValue(val, typ, &tinfo, saveComment) {
            match t.Kind() {
                Kind::String => t.SetString(string::__from_vec(comment)),
                Kind::Slice => t.SetBytes(slice::__from_vec(comment)),
                _ => {}
            }
        }

        if let Some((t, _)) = slotValue(val, typ, &tinfo, saveXML) {
            match t.Kind() {
                Kind::String => t.SetString(string::from_bytes(&saveXMLData)),
                Kind::Slice => {
                    if isByteSlice(t) {
                        t.SetBytes(saveXMLData);
                    }
                }
                _ => {}
            }
        }

        return nil;
    }

    // go: sdk 1.25.5 encoding/xml/read.go:694-753 Decoder.unmarshalPath
    /// unmarshalPath walks down an XML structure looking for wanted
    /// paths, and calls unmarshal on them. The consumed result tells
    /// whether XML elements have been consumed from the Decoder until
    /// start's matching end element, or if it's still untouched because
    /// start is uninteresting for sv's fields.
    fn unmarshalPath(
        &mut self,
        tinfo: &typeInfo,
        sv: &mut Value,
        svType: Type,
        parents: &[string],
        start: &StartElement,
        depth: int,
    ) -> (bool, error) {
        let mut recurse = false;
        let mut parents: Vec<string> = parents.to_vec();
        'Loop: for (_, finfo) in crate::range!(tinfo.fields[..]) {
            if finfo.flags & fElement == 0
                || finfo.parents.len() < parents.len()
                || finfo.xmlns != "" && finfo.xmlns != start.Name.Space
            {
                continue;
            }
            for (j, p) in crate::range!(parents[..]) {
                if *p != finfo.parents[j as usize] {
                    continue 'Loop;
                }
            }
            if finfo.parents.len() == parents.len() && finfo.name == start.Name.Local {
                // It's a perfect match, unmarshal the field.
                return match finfo.value(sv, svType, initNilPointers) {
                    Some((fv, ft)) => (true, self.unmarshal(fv, ft, Some(start), depth + 1)),
                    None => (true, nil),
                };
            }
            if finfo.parents.len() > parents.len() && finfo.parents[parents.len()] == start.Name.Local {
                // It's a prefix for the field. Break and recurse since it's
                // not ok for one field path to be itself the prefix for
                // another field path.
                recurse = true;

                // We can reuse the same slice as long as we don't try to
                // append to it.
                parents = finfo.parents[..parents.len() + 1].to_vec();
                break;
            }
        }
        if !recurse {
            // We have no business with this element.
            return (false, nil);
        }
        // The element is not a perfect match for any field, but one or
        // more fields have the path to this element as a parent prefix.
        // Recurse and attempt to match these.
        loop {
            let (tok, err) = self.Token();
            if err != nil {
                return (true, err);
            }
            match tok {
                Token::StartElement(t) => {
                    // the recursion depth of unmarshalPath is limited to the
                    // path length specified by the struct field tag, so we
                    // don't increment the depth here.
                    let (consumed2, err) = self.unmarshalPath(tinfo, sv, svType, &parents, &t, depth);
                    if err != nil {
                        return (true, err);
                    }
                    if !consumed2 {
                        let err = self.Skip();
                        if err != nil {
                            return (true, err);
                        }
                    }
                }
                Token::EndElement(_) => {
                    return (true, nil);
                }
                _ => {}
            }
        }
    }

    // go: sdk 1.25.5 encoding/xml/read.go:760-777 Decoder.Skip
    /// Skip reads tokens until it has consumed the end element matching
    /// the most recent start element already consumed, skipping nested
    /// structures. It returns nil if it finds an end element matching the
    /// start element; otherwise it returns an error describing the
    /// problem.
    pub fn Skip(&mut self) -> error {
        let mut depth: int64 = 0;
        loop {
            let (tok, err) = self.Token();
            if err != nil {
                return err;
            }
            match tok {
                Token::StartElement(_) => depth += 1,
                Token::EndElement(_) => {
                    if depth == 0 {
                        return nil;
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
    }
}

// go: sdk 1.25.5 encoding/xml/read.go:621-687 copyValue
/// Store src, the accumulated text of an element or the value of an
/// attribute, into dst. Go passes an invalid `reflect.Value` for "nowhere
/// to store it"; goish passes None.
fn copyValue(dst: Option<(&mut Value, Type)>, src: &[byte]) -> error {
    let (dst, typ0) = match dst {
        // Probably a comment.
        None => return nil,
        Some(d) => d,
    };
    let mut dst = dst;
    let mut typ = typ0;

    if typ.Kind() == Kind::Pointer {
        if dst.IsNil() {
            dst.Set(reflect::New(typ.Elem()));
        }
        typ = typ.Elem();
        dst = match dst {
            Value::Pointer(inner) => &mut **inner,
            other => other,
        };
    }

    // Save accumulated data.
    match dst.Kind() {
        Kind::Invalid => {
            // Probably a comment.
        }
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
            if src.is_empty() {
                dst.SetInt(0);
                return nil;
            }
            let (itmp, err) = strconv::ParseInt(strings::TrimSpace(string::from_bytes(src)), 10, typ.Bits());
            if err != nil {
                return err;
            }
            dst.SetInt(itmp);
        }
        Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 | Kind::Uintptr => {
            if src.is_empty() {
                dst.SetUint(0);
                return nil;
            }
            let (utmp, err) = strconv::ParseUint(strings::TrimSpace(string::from_bytes(src)), 10, typ.Bits());
            if err != nil {
                return err;
            }
            dst.SetUint(utmp);
        }
        Kind::Float32 | Kind::Float64 => {
            if src.is_empty() {
                dst.SetFloat(0.0);
                return nil;
            }
            let (ftmp, err) = strconv::ParseFloat(strings::TrimSpace(string::from_bytes(src)), typ.Bits());
            if err != nil {
                return err;
            }
            dst.SetFloat(ftmp);
        }
        Kind::Bool => {
            if src.is_empty() {
                dst.SetBool(false);
                return nil;
            }
            let (value, err) = strconv::ParseBool(strings::TrimSpace(string::from_bytes(src)));
            if err != nil {
                return err;
            }
            dst.SetBool(value);
        }
        Kind::String => {
            dst.SetString(string::from_bytes(src));
        }
        Kind::Slice => {
            // An empty src is still non-nil in Go, to flag presence; goish
            // has no nil/empty distinction for slices.
            dst.SetBytes(slice::__from_vec(src.to_vec()));
        }
        _ => {
            return errors::New(string::from("cannot unmarshal into ") + typ0.String());
        }
    }
    return nil;
}
