// go: file encoding/xml/typeinfo.go decls: getTypeInfo, structFieldInfo, lookupXMLName, addFieldInfo, TagPathError.Error, fieldInfo.value
//
// encoding/xml/typeinfo.go — the `xml:"…"` struct-tag grammar, compiled
// once per struct type into the field table both Marshal and Unmarshal
// walk.
//
// The grammar is small and full of refusals, and the refusals are the
// contract: `a>b,attr` (a parent chain on a non-element), `,chardata`
// with a name, two modes at once, `omitempty` on character data, a
// namespace with no name, a trailing `>`, and a field name that
// disagrees with the XMLName of the field's own type are all errors, not
// guesses.
//
// ─── Deviations ───────────────────────────────────────────────────────
//
//   * No `tinfoMap` cache. Go keys it on `reflect.Type`, which is unique
//     per type. goish's `reflect::Type` compares by (kind, name), so two
//     same-named structs in different modules would share one entry and
//     one of them would be walked with the other's field table. The
//     table is rebuilt per call instead; that costs time, never
//     correctness.
//
//   * `fieldInfo.value` walks goish's owned `reflect::Value` tree and
//     hands back `&mut` into it, together with the field's static
//     `reflect::Type`. Go reads the static type off the Value itself;
//     goish cannot for a nil pointer (`Value::Pointer(Invalid)` carries
//     no element type), and allocating one is exactly what
//     `initNilPointers` is for — so the type rides alongside.
//
//   * Embedded structs are ported but unreachable: goish's reflect
//     descriptor marks no field `Anonymous` (reflect/mod.rs), so every
//     `idx` here has length one.
//
// goishlint:ignore GOISH021 tinfoMap — see the cache note above.
// goishlint:ignore GOISH021 nameType — `isNameType` below; Go caches `reflect.TypeFor[Name]()`, goish compares against the descriptor directly.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use super::xml::Name;
use crate::errors::{error, nil, ErrorTrait, Wrap};
use crate::fmt;
use crate::goslice::slice;
use crate::gostring::string;
use crate::reflect::{self, Kind, Reflect, StructField, Type, Value};
use crate::strings;
use crate::types::int;

// go: sdk 1.25.5 encoding/xml/typeinfo.go:15-18 typeInfo
/// typeInfo holds details for the xml representation of a type.
#[derive(Clone, Default)]
pub(super) struct typeInfo {
    pub(super) xmlname: Option<fieldInfo>,
    pub(super) fields: Vec<fieldInfo>,
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:21-27 fieldInfo
/// fieldInfo holds details for the xml representation of a single field.
#[derive(Clone, Default)]
pub(super) struct fieldInfo {
    pub(super) idx: Vec<int>,
    pub(super) name: string,
    pub(super) xmlns: string,
    pub(super) flags: fieldFlags,
    pub(super) parents: Vec<string>,
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:29-29 fieldFlags
pub(super) type fieldFlags = int;

// go: sdk 1.25.5 encoding/xml/typeinfo.go:31-45 fElement
pub(super) const fElement: fieldFlags = 1 << 0;
// go: sdk 1.25.5 encoding/xml/typeinfo.go:31-45 fAttr
pub(super) const fAttr: fieldFlags = 1 << 1;
// go: sdk 1.25.5 encoding/xml/typeinfo.go:31-45 fCDATA
pub(super) const fCDATA: fieldFlags = 1 << 2;
// go: sdk 1.25.5 encoding/xml/typeinfo.go:31-45 fCharData
pub(super) const fCharData: fieldFlags = 1 << 3;
// go: sdk 1.25.5 encoding/xml/typeinfo.go:31-45 fInnerXML
pub(super) const fInnerXML: fieldFlags = 1 << 4;
// go: sdk 1.25.5 encoding/xml/typeinfo.go:31-45 fComment
pub(super) const fComment: fieldFlags = 1 << 5;
// go: sdk 1.25.5 encoding/xml/typeinfo.go:31-45 fAny
pub(super) const fAny: fieldFlags = 1 << 6;
// go: sdk 1.25.5 encoding/xml/typeinfo.go:31-45 fOmitEmpty
pub(super) const fOmitEmpty: fieldFlags = 1 << 7;
// go: sdk 1.25.5 encoding/xml/typeinfo.go:31-45 fMode
pub(super) const fMode: fieldFlags = fElement | fAttr | fCDATA | fCharData | fInnerXML | fComment | fAny;
// go: sdk 1.25.5 encoding/xml/typeinfo.go:31-45 xmlName
pub(super) const xmlName: &str = "XMLName";

// go: none — goish idiom: Go's `typ == nameType` with
//     `nameType = reflect.TypeFor[Name]()`. The descriptor comparison is
//     (kind, name), which a user struct also called `Name` would pass, so
//     the field layout is checked too: only a struct shaped exactly like
//     `xml.Name` is treated as one — and such a struct behaves the same.
pub(super) fn isNameType(typ: &Type) -> bool {
    let nameType = <Name as Reflect>::__reflect_type();
    if *typ != nameType || typ.NumField() != 2 {
        return false;
    }
    let (f0, f1) = (typ.Field(0), typ.Field(1));
    return f0.Name == "Space"
        && (f0.Type)().Kind() == Kind::String
        && f1.Name == "Local"
        && (f1.Type)().Kind() == Kind::String;
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:53-110 getTypeInfo
/// getTypeInfo returns the typeInfo structure with details necessary for
/// marshaling and unmarshaling typ.
pub(super) fn getTypeInfo(typ: &Type) -> (typeInfo, error) {
    let mut tinfo = typeInfo::default();
    if typ.Kind() == Kind::Struct && !isNameType(typ) {
        let n = typ.NumField();
        let mut i: int = 0;
        while i < n {
            let f = typ.Field(i);
            i += 1;
            if (f.PkgPath != "" && !f.Anonymous) || f.Tag.Get("xml") == "-" {
                continue; // Private field
            }

            // For embedded structs, embed its fields.
            if f.Anonymous {
                let mut t = (f.Type)();
                if t.Kind() == Kind::Pointer {
                    t = t.Elem();
                }
                if t.Kind() == Kind::Struct {
                    let (inner, err) = getTypeInfo(&t);
                    if err != nil {
                        return (typeInfo::default(), err);
                    }
                    if tinfo.xmlname.is_none() {
                        tinfo.xmlname = inner.xmlname.clone();
                    }
                    for (_, finfo) in crate::range!(inner.fields[..]) {
                        let mut finfo = finfo.clone();
                        finfo.idx.insert(0, i - 1);
                        let err = addFieldInfo(typ, &mut tinfo, &finfo);
                        if err != nil {
                            return (typeInfo::default(), err);
                        }
                    }
                    continue;
                }
            }

            let (finfo, err) = structFieldInfo(typ, &f, i - 1);
            if err != nil {
                return (typeInfo::default(), err);
            }

            if f.Name == xmlName {
                tinfo.xmlname = Some(finfo);
                continue;
            }

            // Add the field if it doesn't conflict with other fields.
            let err = addFieldInfo(typ, &mut tinfo, &finfo);
            if err != nil {
                return (typeInfo::default(), err);
            }
        }
    }
    return (tinfo, nil);
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:113-226 structFieldInfo
/// structFieldInfo builds and returns a fieldInfo for f.
///
/// Go reads the index off `f.Index`; goish's `StructField` has no
/// `Index`, so the caller passes the position it found `f` at.
pub(super) fn structFieldInfo(typ: &Type, f: &StructField, index: int) -> (fieldInfo, error) {
    let mut finfo = fieldInfo {
        idx: alloc::vec![index],
        ..fieldInfo::default()
    };

    // Split the tag from the xml namespace if necessary.
    let mut tag = f.Tag.Get("xml");
    let (ns, t, ok) = strings::Cut(&tag, " ");
    if ok {
        (finfo.xmlns, tag) = (ns, t);
    }

    // Parse flags.
    let tokens: Vec<string> = strings::Split(&tag, ",").__into_vec();
    if tokens.len() == 1 {
        finfo.flags = fElement;
    } else {
        tag = tokens[0].clone();
        for (_, flag) in crate::range!(tokens[1..]) {
            if *flag == "attr" {
                finfo.flags |= fAttr;
            } else if *flag == "cdata" {
                finfo.flags |= fCDATA;
            } else if *flag == "chardata" {
                finfo.flags |= fCharData;
            } else if *flag == "innerxml" {
                finfo.flags |= fInnerXML;
            } else if *flag == "comment" {
                finfo.flags |= fComment;
            } else if *flag == "any" {
                finfo.flags |= fAny;
            } else if *flag == "omitempty" {
                finfo.flags |= fOmitEmpty;
            }
        }

        // Validate the flags used.
        let mut valid = true;
        let mode = finfo.flags & fMode;
        if mode == 0 {
            finfo.flags |= fElement;
        } else if mode == fAttr
            || mode == fCDATA
            || mode == fCharData
            || mode == fInnerXML
            || mode == fComment
            || mode == fAny
            || mode == fAny | fAttr
        {
            if f.Name == xmlName || tag != "" && mode != fAttr {
                valid = false;
            }
        } else {
            // This will also catch multiple modes in a single field.
            valid = false;
        }
        if finfo.flags & fMode == fAny {
            finfo.flags |= fElement;
        }
        if finfo.flags & fOmitEmpty != 0 && finfo.flags & (fElement | fAttr) == 0 {
            valid = false;
        }
        if !valid {
            return (
                fieldInfo::default(),
                fmt::Errorf!(
                    "xml: invalid tag in field %s of type %s: %q",
                    f.Name,
                    typ.String(),
                    f.Tag.Get("xml")
                ),
            );
        }
    }

    // Use of xmlns without a name is not allowed.
    if finfo.xmlns != "" && tag == "" {
        return (
            fieldInfo::default(),
            fmt::Errorf!(
                "xml: namespace without name in field %s of type %s: %q",
                f.Name,
                typ.String(),
                f.Tag.Get("xml")
            ),
        );
    }

    if f.Name == xmlName {
        // The XMLName field records the XML element name. Don't process
        // it as usual because its name should default to empty rather
        // than to the field name.
        finfo.name = tag;
        return (finfo, nil);
    }

    if tag == "" {
        // If the name part of the tag is completely empty, get default
        // from XMLName of underlying struct if feasible, or field name
        // otherwise.
        match lookupXMLName(&(f.Type)()) {
            Some(xmlname) => {
                (finfo.xmlns, finfo.name) = (xmlname.xmlns, xmlname.name);
            }
            None => {
                finfo.name = string::from(f.Name);
            }
        }
        return (finfo, nil);
    }

    // Prepare field name and parents.
    let mut parents: Vec<string> = strings::Split(&tag, ">").__into_vec();
    if parents[0] == "" {
        parents[0] = string::from(f.Name);
    }
    if parents[parents.len() - 1] == "" {
        return (
            fieldInfo::default(),
            fmt::Errorf!("xml: trailing '>' in field %s of type %s", f.Name, typ.String()),
        );
    }
    finfo.name = parents[parents.len() - 1].clone();
    if parents.len() > 1 {
        if (finfo.flags & fElement) == 0 {
            return (
                fieldInfo::default(),
                fmt::Errorf!(
                    "xml: %s chain not valid with %s flag",
                    tag,
                    strings::Join(slice::__from_vec(tokens[1..].to_vec()), ",")
                ),
            );
        }
        parents.truncate(parents.len() - 1);
        finfo.parents = parents;
    }

    // If the field type has an XMLName field, the names must match so
    // that the behavior of both marshaling and unmarshaling is
    // straightforward and unambiguous.
    if finfo.flags & fElement != 0 {
        let ftyp = (f.Type)();
        if let Some(xmlname) = lookupXMLName(&ftyp) {
            if xmlname.name != finfo.name {
                return (
                    fieldInfo::default(),
                    fmt::Errorf!(
                        "xml: name %q in tag of %s.%s conflicts with name %q in %s.XMLName",
                        finfo.name,
                        typ.String(),
                        f.Name,
                        xmlname.name,
                        ftyp.String()
                    ),
                );
            }
        }
    }
    return (finfo, nil);
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:231-252 lookupXMLName
/// lookupXMLName returns the fieldInfo for typ's XMLName field in case it
/// exists and has a valid xml field tag, otherwise it returns None.
pub(super) fn lookupXMLName(typ: &Type) -> Option<fieldInfo> {
    let mut typ = *typ;
    while typ.Kind() == Kind::Pointer {
        typ = typ.Elem();
    }
    if typ.Kind() != Kind::Struct {
        return None;
    }
    let n = typ.NumField();
    let mut i: int = 0;
    while i < n {
        let f = typ.Field(i);
        if f.Name != xmlName {
            i += 1;
            continue;
        }
        let (finfo, err) = structFieldInfo(&typ, &f, i);
        if err == nil && finfo.name != "" {
            return Some(finfo);
        }
        // Also consider errors as a non-existent field tag and let
        // getTypeInfo itself report the error.
        break;
    }
    return None;
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:261-326 addFieldInfo
/// addFieldInfo adds finfo to tinfo.fields if there are no conflicts, or
/// if conflicts arise from previous fields that were obtained from deeper
/// embedded structures than finfo. In the latter case, the conflicting
/// entries are dropped. A conflict occurs when the path (parent + name)
/// to a field is itself a prefix of another path, or when two paths match
/// exactly. It is okay for field paths to share a common, shorter prefix.
pub(super) fn addFieldInfo(typ: &Type, tinfo: &mut typeInfo, newf: &fieldInfo) -> error {
    let mut conflicts: Vec<usize> = Vec::new();
    // First, figure all conflicts. Most working code will have none.
    'Loop: for (i, oldf) in crate::range!(tinfo.fields[..]) {
        let i = i as usize;
        if oldf.flags & fMode != newf.flags & fMode {
            continue;
        }
        if oldf.xmlns != "" && newf.xmlns != "" && oldf.xmlns != newf.xmlns {
            continue;
        }
        let minl = core::cmp::min(newf.parents.len(), oldf.parents.len());
        let mut p: usize = 0;
        while p < minl {
            if oldf.parents[p] != newf.parents[p] {
                continue 'Loop;
            }
            p += 1;
        }
        if oldf.parents.len() > newf.parents.len() {
            if oldf.parents[newf.parents.len()] == newf.name {
                conflicts.push(i);
            }
        } else if oldf.parents.len() < newf.parents.len() {
            if newf.parents[oldf.parents.len()] == oldf.name {
                conflicts.push(i);
            }
        } else {
            if newf.name == oldf.name && newf.xmlns == oldf.xmlns {
                conflicts.push(i);
            }
        }
    }
    // Without conflicts, add the new field and return.
    if conflicts.is_empty() {
        tinfo.fields.push(newf.clone());
        return nil;
    }

    // If any conflict is shallower, ignore the new field. This matches
    // the Go field resolution on embedding.
    for (_, i) in crate::range!(conflicts[..]) {
        if tinfo.fields[*i].idx.len() < newf.idx.len() {
            return nil;
        }
    }

    // Otherwise, if any of them is at the same depth level, it's an error.
    for (_, i) in crate::range!(conflicts[..]) {
        let oldf = &tinfo.fields[*i];
        if oldf.idx.len() == newf.idx.len() {
            let f1 = typ.FieldByIndex(&oldf.idx);
            let f2 = typ.FieldByIndex(&newf.idx);
            return Wrap(TagPathError {
                Struct: *typ,
                Field1: string::from(f1.Name),
                Tag1: f1.Tag.Get("xml"),
                Field2: string::from(f2.Name),
                Tag2: f2.Tag.Get("xml"),
            });
        }
    }

    // Otherwise, the new field is shallower, and thus takes precedence,
    // so drop the conflicting fields from tinfo and append the new one.
    let mut c = conflicts.len();
    while c > 0 {
        c -= 1;
        tinfo.fields.remove(conflicts[c]);
    }
    tinfo.fields.push(newf.clone());
    return nil;
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:330-334 TagPathError
/// A TagPathError represents an error in the unmarshaling process caused
/// by the use of field tags with conflicting paths.
#[derive(Clone)]
pub struct TagPathError {
    pub Struct: Type,
    pub Field1: string,
    pub Tag1: string,
    pub Field2: string,
    pub Tag2: string,
}

// SAFETY-free: `reflect::Type` is a descriptor of `&'static` data and fn
// pointers, so a TagPathError is as shareable as the error handle needs.
impl ErrorTrait for TagPathError {
    // go: sdk 1.25.5 encoding/xml/typeinfo.go:336-338 TagPathError.Error
    fn Error(&self) -> string {
        return fmt::Sprintf!(
            "%s field %q with tag %q conflicts with field %q with tag %q",
            self.Struct.String(),
            self.Field1,
            self.Tag1,
            self.Field2,
            self.Tag2
        );
    }
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:340-343 initNilPointers
pub(super) const initNilPointers: bool = true;
// go: sdk 1.25.5 encoding/xml/typeinfo.go:340-343 dontInitNilPointers
pub(super) const dontInitNilPointers: bool = false;

impl fieldInfo {
    // go: sdk 1.25.5 encoding/xml/typeinfo.go:350-367 fieldInfo.value
    /// value returns v's field value corresponding to finfo, with the
    /// field's static type. It's equivalent to v.FieldByIndex(finfo.idx),
    /// but when passed initNilPointers, it initializes and dereferences
    /// pointers as necessary. When passed dontInitNilPointers and a nil
    /// pointer is reached, the function returns None (Go: a zero
    /// reflect.Value).
    pub(super) fn value<'a>(
        &self,
        v: &'a mut Value,
        typ: Type,
        shouldInitNilPointers: bool,
    ) -> Option<(&'a mut Value, Type)> {
        let mut v = v;
        let mut t = typ;
        for (i, x) in crate::range!(self.idx[..]) {
            if i > 0 {
                if t.Kind() == Kind::Pointer && t.Elem().Kind() == Kind::Struct {
                    if v.IsNil() {
                        if !shouldInitNilPointers {
                            return None;
                        }
                        v.Set(reflect::New(t.Elem()));
                    }
                    t = t.Elem();
                    v = match v {
                        Value::Pointer(inner) => &mut **inner,
                        _ => return None,
                    };
                }
            }
            let ft = (t.Field(*x).Type)();
            v = match underlying(v) {
                Value::Struct { fields, .. } => &mut fields[*x as usize],
                _ => return None,
            };
            t = ft;
        }
        return Some((v, t));
    }
}

// go: none — goish idiom: `Value::Named` wraps a declared non-struct type
//     and is transparent for everything but `Type()`; a write into the
//     payload goes through the wrapper.
pub(super) fn underlying(v: &mut Value) -> &mut Value {
    return match v {
        Value::Named { inner, .. } => underlying(&mut **inner),
        other => other,
    };
}
