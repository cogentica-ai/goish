// goishlint:ignore GOISH018 fieldInfo.value — the field-walk half, which needs reflect.Value mutation (v.Set, reflect.New for nil-pointer init) that goish's read-only Value enum does not offer; its only callers are marshal.go and read.go, both unported, so it lands with them.
// goishlint:ignore GOISH021 initNilPointers, dontInitNilPointers — the two bool constants exist solely as named arguments to fieldInfo.value, which is absent above.
// goishlint:ignore GOISH020 structFieldInfo — one extra parameter, `idx`: Go reads the field's position from reflect.StructField.Index, which goish's StructField does not carry, so the caller passes the loop variable Go would have found there. See port note 1 in the file banner.
// goishlint:ignore GOISH021 tinfoMap — DELIBERATELY not ported; it is a memo whose key would be unsound here. Go keys it on reflect.Type identity, which is exact; goish's Type compares (kind, name), so two distinct descriptors sharing a name would share a cache entry and the second caller would get the first one's field table. Nothing downstream needs the cache — Go's value is the shared *typeInfo pointer, and goish returns typeInfo by value — so recomputing is the cheap half of the trade. Reinstate it the day Type identity becomes exact.
// go: file encoding/xml/typeinfo.go decls: TagPathError.Error, nameType, getTypeInfo, structFieldInfo, lookupXMLName, addFieldInfo
//
// encoding/xml/typeinfo.go — the struct-tag interpreter. Given a
// reflect.Type it answers "which XML name does each field carry, in
// which name space, in which mode (element / attribute / chardata /
// …), under which parent chain" — the table both the marshaller and
// the unmarshaller walk.
//
// PORT NOTES
//
// 1. `structFieldInfo` takes an extra `idx` parameter. Go reads the
//    field's position out of `reflect.StructField.Index`, which the
//    runtime fills in; goish's `StructField` carries no Index, so the
//    caller passes the loop variable Go would have found there. Every
//    other use of `idx` is identical.
//
// 2. Go's `reflect.Type` identity is the type itself. goish's compares
//    `(kind, name)`, so two distinct structs sharing a name would share
//    a cache entry. Descriptors in this tree are hand-written and
//    uniquely named, so this has no effect today — but it is why the
//    cache key is worth remembering if that ever changes.
//
// 3. Error text interpolates the type with `%s`, which in Go is the
//    package-qualified name (`xml.tiOmit`). goish's `Type::String()`
//    returns the descriptor's `name` verbatim, so a descriptor that
//    wants Go's error text spells its name qualified.
//
// 4. `f.Anonymous` is always false in goish's reflect descriptor (see
//    reflect/mod.rs), so `getTypeInfo`'s embedded-struct branch is
//    unreachable today. It is ported anyway — it is the behaviour the
//    descriptor will need the moment embedding is modelled, and
//    leaving it out would silently change field resolution then.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use crate::fmt;
use crate::goslice::slice;
use crate::gostring::string;
use crate::int;
use crate::reflect;

// go: sdk 1.25.5 encoding/xml/typeinfo.go:14-18 typeInfo
/// Go: "typeInfo holds details for the xml representation of a type."
#[derive(Clone, Default)]
pub struct typeInfo {
    pub xmlname: Option<fieldInfo>,
    pub fields: slice<fieldInfo>,
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:20-27 fieldInfo
/// Go: "fieldInfo holds details for the xml representation of a single
/// field."
#[derive(Clone, Default)]
pub struct fieldInfo {
    pub idx: slice<int>,
    pub name: string,
    pub xmlns: string,
    pub flags: fieldFlags,
    pub parents: slice<string>,
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:29-29 fieldFlags
/// Go: `type fieldFlags int`
pub type fieldFlags = int;

// go: sdk 1.25.5 encoding/xml/typeinfo.go:31-45 fElement
/// Go's `1 << iota` block. `fMode` masks the mutually exclusive modes;
/// `fOmitEmpty` sits outside it, which is why a field can be both an
/// element and omit-empty but never both an attribute and chardata.
pub const fElement: fieldFlags = 1;
pub const fAttr: fieldFlags = 2;
pub const fCDATA: fieldFlags = 4;
pub const fCharData: fieldFlags = 8;
pub const fInnerXML: fieldFlags = 16;
pub const fComment: fieldFlags = 32;
pub const fAny: fieldFlags = 64;
pub const fOmitEmpty: fieldFlags = 128;
pub const fMode: fieldFlags =
    fElement | fAttr | fCDATA | fCharData | fInnerXML | fComment | fAny;
pub const xmlName: &str = "XMLName";

// go: sdk 1.25.5 encoding/xml/typeinfo.go:49-49 nameType
/// Go: `var nameType = reflect.TypeFor[Name]()`
///
/// A function rather than a static because goish's descriptors are
/// built by a `fn() -> Type`, not a const.
pub fn nameType() -> reflect::Type {
    return reflect::TypeOfDyn::<super::xml::Name>();
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:53-110 getTypeInfo
/// Go: "getTypeInfo returns the typeInfo structure with details
/// necessary for marshaling and unmarshaling typ."
pub fn getTypeInfo(typ: reflect::Type) -> (typeInfo, crate::error) {
    let mut tinfo = typeInfo::default();
    if typ.Kind() == reflect::Kind::Struct && typ != nameType() {
        let n = typ.NumField();
        let mut i: int = 0;
        while i < n {
            let f = typ.Field(i);
            // Go: `!f.IsExported()`, which is defined as
            // `f.PkgPath == ""`. goish's descriptor exposes only
            // exported fields, so PkgPath is always empty and this
            // half of the test never fires.
            if (!f.PkgPath.is_empty() && !f.Anonymous)
                || f.Tag.Get("xml") == string::from_static("-")
            {
                i += 1;
                continue; // Go: "Private field"
            }

            // Go: "For embedded structs, embed its fields."
            if f.Anonymous {
                let mut t = (f.Type)();
                if t.Kind() == reflect::Kind::Pointer {
                    t = t.Elem();
                }
                if t.Kind() == reflect::Kind::Struct {
                    let (inner, err) = getTypeInfo(t);
                    if err != crate::errors::nil {
                        return (typeInfo::default(), err);
                    }
                    if tinfo.xmlname.is_none() {
                        tinfo.xmlname = inner.xmlname.clone();
                    }
                    let mut k: int = 0;
                    while k < inner.fields.Len() {
                        let mut finfo = inner.fields[k as usize].clone();
                        finfo.idx = crate::append!(crate::slice!([]int{i}), finfo.idx...);
                        let err = addFieldInfo(typ, &mut tinfo, &finfo);
                        if err != crate::errors::nil {
                            return (typeInfo::default(), err);
                        }
                        k += 1;
                    }
                    i += 1;
                    continue;
                }
            }

            let (finfo, err) = structFieldInfo(typ, i, &f);
            if err != crate::errors::nil {
                return (typeInfo::default(), err);
            }
            let finfo = match finfo {
                Some(fi) => fi,
                // Go has no such case: `structFieldInfo` returns a
                // non-nil *fieldInfo whenever it returns a nil error,
                // and Go would nil-dereference here if it did not. The
                // Option is the Rust shape of "pointer or error", so
                // the arm exists; reaching it means structFieldInfo
                // broke its contract.
                None => {
                    i += 1;
                    continue;
                }
            };

            if f.Name == xmlName {
                tinfo.xmlname = Some(finfo);
                i += 1;
                continue;
            }

            // Go: "Add the field if it doesn't conflict with other fields."
            let err = addFieldInfo(typ, &mut tinfo, &finfo);
            if err != crate::errors::nil {
                return (typeInfo::default(), err);
            }
            i += 1;
        }
    }

    return (tinfo, crate::errors::nil);
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:113-226 structFieldInfo
/// Go: "structFieldInfo builds and returns a fieldInfo for f."
pub fn structFieldInfo(
    typ: reflect::Type,
    idx: int,
    f: &reflect::StructField,
) -> (Option<fieldInfo>, crate::error) {
    let mut finfo = fieldInfo {
        idx: crate::slice!([]int{idx}),
        ..Default::default()
    };

    // Go: "Split the tag from the xml namespace if necessary."
    let mut tag = f.Tag.Get("xml");
    let (ns, t, ok) = crate::strings::Cut(tag.clone(), " ");
    if ok {
        finfo.xmlns = ns;
        tag = t;
    }

    // Go: "Parse flags."
    let tokens = crate::strings::Split(tag.clone(), ",");
    if tokens.Len() == 1 {
        finfo.flags = fElement;
    } else {
        tag = tokens[0].clone();
        let mut i: int = 1;
        while i < tokens.Len() {
            let flag = tokens[i as usize].clone();
            let s: &str = flag.as_ref();
            match s {
                "attr" => finfo.flags |= fAttr,
                "cdata" => finfo.flags |= fCDATA,
                "chardata" => finfo.flags |= fCharData,
                "innerxml" => finfo.flags |= fInnerXML,
                "comment" => finfo.flags |= fComment,
                "any" => finfo.flags |= fAny,
                "omitempty" => finfo.flags |= fOmitEmpty,
                _ => {}
            }
            i += 1;
        }

        // Go: "Validate the flags used."
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
            || mode == (fAny | fAttr)
        {
            if f.Name == xmlName || (tag.Len() != 0 && mode != fAttr) {
                valid = false;
            }
        } else {
            // Go: "This will also catch multiple modes in a single field."
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
                None,
                fmt::Errorf!(
                    "xml: invalid tag in field %s of type %s: %q",
                    string::from_static(f.Name),
                    typ.String(),
                    f.Tag.Get("xml")
                ),
            );
        }
    }

    // Go: "Use of xmlns without a name is not allowed."
    if finfo.xmlns.Len() != 0 && tag.Len() == 0 {
        return (
            None,
            fmt::Errorf!(
                "xml: namespace without name in field %s of type %s: %q",
                string::from_static(f.Name),
                typ.String(),
                f.Tag.Get("xml")
            ),
        );
    }

    if f.Name == xmlName {
        // Go: "The XMLName field records the XML element name. Don't
        // process it as usual because its name should default to
        // empty rather than to the field name."
        finfo.name = tag;
        return (Some(finfo), crate::errors::nil);
    }

    if tag.Len() == 0 {
        // Go: "If the name part of the tag is completely empty, get
        // default from XMLName of underlying struct if feasible, or
        // field name otherwise."
        match lookupXMLName((f.Type)()) {
            Some(xmlname) => {
                finfo.xmlns = xmlname.xmlns;
                finfo.name = xmlname.name;
            }
            None => {
                finfo.name = string::from_static(f.Name);
            }
        }
        return (Some(finfo), crate::errors::nil);
    }

    // Go: "Prepare field name and parents."
    let mut parents = crate::strings::Split(tag.clone(), ">");
    if parents[0].Len() == 0 {
        parents[0] = string::from_static(f.Name);
    }
    if parents[(parents.Len() - 1) as usize].Len() == 0 {
        return (
            None,
            fmt::Errorf!(
                "xml: trailing '>' in field %s of type %s",
                string::from_static(f.Name),
                typ.String()
            ),
        );
    }
    finfo.name = parents[(parents.Len() - 1) as usize].clone();
    if parents.Len() > 1 {
        if finfo.flags & fElement == 0 {
            return (
                None,
                fmt::Errorf!(
                    "xml: %s chain not valid with %s flag",
                    tag,
                    crate::strings::Join(tokens.slice(1, tokens.Len()), ",")
                ),
            );
        }
        finfo.parents = parents.slice(0, parents.Len() - 1);
    }

    // Go: "If the field type has an XMLName field, the names must match
    // so that the behavior of both marshaling and unmarshaling is
    // straightforward and unambiguous."
    if finfo.flags & fElement != 0 {
        let ftyp = (f.Type)();
        if let Some(xmlname) = lookupXMLName(ftyp) {
            if xmlname.name != finfo.name {
                return (
                    None,
                    fmt::Errorf!(
                        "xml: name %q in tag of %s.%s conflicts with name %q in %s.XMLName",
                        finfo.name,
                        typ.String(),
                        string::from_static(f.Name),
                        xmlname.name,
                        ftyp.String()
                    ),
                );
            }
        }
    }
    return (Some(finfo), crate::errors::nil);
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:226-251 lookupXMLName
/// Go: "lookupXMLName returns the fieldInfo for typ's XMLName field in
/// case it exists and has a valid xml field tag, otherwise it returns
/// nil."
pub fn lookupXMLName(typ: reflect::Type) -> Option<fieldInfo> {
    let mut typ = typ;
    while typ.Kind() == reflect::Kind::Pointer {
        typ = typ.Elem();
    }
    if typ.Kind() != reflect::Kind::Struct {
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
        let (finfo, err) = structFieldInfo(typ, i, &f);
        if err == crate::errors::nil {
            if let Some(fi) = finfo {
                if fi.name.Len() != 0 {
                    return Some(fi);
                }
            }
        }
        // Go: "Also consider errors as a non-existent field tag and let
        // getTypeInfo itself report the error."
        break;
    }
    return None;
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:253-325 addFieldInfo
/// Go: "addFieldInfo adds finfo to tinfo.fields if there are no
/// conflicts, or if conflicts arise from previous fields that were
/// obtained from deeper embedded structures than finfo. ... A conflict
/// occurs when the path (parent + name) to a field is itself a prefix
/// of another path, or when two paths match exactly."
pub fn addFieldInfo(
    typ: reflect::Type,
    tinfo: &mut typeInfo,
    newf: &fieldInfo,
) -> crate::error {
    let mut conflicts: slice<int> = crate::slice!([]int{});
    // Go: "First, figure all conflicts. Most working code will have none."
    let mut i: int = 0;
    'Loop: while i < tinfo.fields.Len() {
        let oldf = tinfo.fields[i as usize].clone();
        if oldf.flags & fMode != newf.flags & fMode {
            i += 1;
            continue;
        }
        if oldf.xmlns.Len() != 0 && newf.xmlns.Len() != 0 && oldf.xmlns != newf.xmlns {
            i += 1;
            continue;
        }
        let minl = if newf.parents.Len() < oldf.parents.Len() {
            newf.parents.Len()
        } else {
            oldf.parents.Len()
        };
        let mut p: int = 0;
        while p < minl {
            if oldf.parents[p as usize] != newf.parents[p as usize] {
                i += 1;
                continue 'Loop;
            }
            p += 1;
        }
        if oldf.parents.Len() > newf.parents.Len() {
            if oldf.parents[newf.parents.Len() as usize] == newf.name {
                conflicts = crate::append!(conflicts, i);
            }
        } else if oldf.parents.Len() < newf.parents.Len() {
            if newf.parents[oldf.parents.Len() as usize] == oldf.name {
                conflicts = crate::append!(conflicts, i);
            }
        } else {
            if newf.name == oldf.name && newf.xmlns == oldf.xmlns {
                conflicts = crate::append!(conflicts, i);
            }
        }
        i += 1;
    }
    // Go: "Without conflicts, add the new field and return."
    if conflicts.Len() == 0 {
        tinfo.fields = crate::append!(tinfo.fields.clone(), newf.clone());
        return crate::errors::nil;
    }

    // Go: "If any conflict is shallower, ignore the new field. This
    // matches the Go field resolution on embedding."
    let mut c: int = 0;
    while c < conflicts.Len() {
        let i = conflicts[c as usize];
        if tinfo.fields[i as usize].idx.Len() < newf.idx.Len() {
            return crate::errors::nil;
        }
        c += 1;
    }

    // Go: "Otherwise, if any of them is at the same depth level, it's
    // an error."
    let mut c: int = 0;
    while c < conflicts.Len() {
        let i = conflicts[c as usize];
        let oldf = tinfo.fields[i as usize].clone();
        if oldf.idx.Len() == newf.idx.Len() {
            let i1 = oldf.idx.clone().__into_vec();
            let i2 = newf.idx.clone().__into_vec();
            let f1 = typ.FieldByIndex(&i1);
            let f2 = typ.FieldByIndex(&i2);
            return crate::errors::Wrap(TagPathError {
                Struct: typ,
                Field1: string::from_static(f1.Name),
                Tag1: f1.Tag.Get("xml"),
                Field2: string::from_static(f2.Name),
                Tag2: f2.Tag.Get("xml"),
            });
        }
        c += 1;
    }

    // Go: "Otherwise, the new field is shallower, and thus takes
    // precedence, so drop the conflicting fields from tinfo and append
    // the new one."
    let mut c: int = conflicts.Len() - 1;
    while c >= 0 {
        let i = conflicts[c as usize];
        // Go's `copy(fields[i:], fields[i+1:]); fields = fields[:len-1]`
        // — a shift-left delete, which Vec::remove is exactly.
        let mut v = tinfo.fields.clone().__into_vec();
        v.remove(i as usize);
        tinfo.fields = slice::__from_vec(v);
        c -= 1;
    }
    tinfo.fields = crate::append!(tinfo.fields.clone(), newf.clone());
    return crate::errors::nil;
}

// go: sdk 1.25.5 encoding/xml/typeinfo.go:327-333 TagPathError
/// Go: "A TagPathError represents an error in the unmarshaling process
/// caused by the use of field tags with conflicting paths."
#[derive(Clone)]
pub struct TagPathError {
    pub Struct: reflect::Type,
    pub Field1: string,
    pub Tag1: string,
    pub Field2: string,
    pub Tag2: string,
}

impl TagPathError {
    // go: sdk 1.25.5 encoding/xml/typeinfo.go:335-337 TagPathError.Error
    /// Go: `fmt.Sprintf("%s field %q with tag %q conflicts with field
    /// %q with tag %q", e.Struct, e.Field1, e.Tag1, e.Field2, e.Tag2)`
    pub fn Error(&self) -> string {
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

impl crate::errors::ErrorTrait for TagPathError {
    // go: none — goish idiom: Go satisfies `error` by having the method;
    // Rust needs the trait impl to forward to it.
    fn Error(&self) -> string {
        return TagPathError::Error(self);
    }
}

// ─── ref-smoke hooks ──────────────────────────────────────────────────

// go: none — goish-only: the hook examples/xml_typeinfo_ref_smoke.rs
// calls. It renders a `typeInfo` in exactly the layout the Go side
// prints (see the generator in the smoke's header), so the two dumps
// compare as strings. `getTypeInfo` and `typeInfo` are package-private
// in Go, so the hook is the only way an example can reach them.
#[doc(hidden)]
pub fn __typeinfo_script(typ: reflect::Type) -> string {
    // go: none — goish-only: the per-fieldInfo row.
    fn fi(tag: &'static str, f: &fieldInfo) -> string {
        let mut idx = string::from_static("");
        let mut i: int = 0;
        while i < f.idx.Len() {
            if i > 0 {
                idx = idx + string::from_static(".");
            }
            idx = idx + crate::strconv::Itoa(f.idx[i as usize]);
            i += 1;
        }
        return fmt::Sprintf!(
            "%s %s|%s|%d|%s|%s",
            string::from_static(tag),
            f.name.clone(),
            f.xmlns.clone(),
            f.flags,
            idx,
            crate::strings::Join(f.parents.clone(), ",")
        );
    }

    let (ti, err) = getTypeInfo(typ);
    if err != crate::errors::nil {
        return string::from_static("E ") + err.Error();
    }
    let mut rows: slice<string> = crate::slice!([]string{});
    if let Some(x) = &ti.xmlname {
        rows = crate::append!(rows, fi("X", x));
    }
    let mut i: int = 0;
    while i < ti.fields.Len() {
        rows = crate::append!(rows, fi("F", &ti.fields[i as usize]));
        i += 1;
    }
    return crate::strings::Join(rows, " ");
}
