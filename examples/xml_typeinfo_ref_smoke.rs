// encoding/xml: typeinfo.go — the struct-tag interpreter.
//
// `getTypeInfo` turns a struct's reflect descriptor into the table both
// the marshaller and the unmarshaller walk: for each field, the XML
// name, the name space, the mode (element / attribute / chardata /
// cdata / innerxml / comment / any), the omit-empty bit and the parent
// chain from an `a>b>c` tag. It is also where every tag-validation
// error in encoding/xml is raised.
//
// 29 types from Go 1.25.5 via `scripts/goref.sh encoding/xml`, dumped
// in the same layout both sides:
//
//   E <error text>                      — getTypeInfo returned an error
//   X <name>|<xmlns>|<flags>|<idx>|<parents>   — tinfo.xmlname
//   F <name>|<xmlns>|<flags>|<idx>|<parents>   — one tinfo.fields entry
//
// WHERE THE DESCRIPTORS COME FROM. Go builds these from real struct
// types; goish's reflect has no runtime registry, so the arrays below
// are the SAME field tables, generated from the Go generator's own
// SPEC dump rather than retyped. The type names are package-qualified
// ("xml.tiOmitBad") because Go interpolates the type into its error
// text with `%s`, which is the qualified form, and goish's `Type` has
// one name field where Go has Name() and String().
//
// WHAT THE TYPES ARE FOR. The rows are not a sample of plausible tags;
// they are the branches:
//
//   * every mode flag on its own, and the flag VALUES (fAny sets
//     fElement too, so `,any` is 65 and not 64; `,any,attr` is 66).
//   * the invalid combinations — two modes at once, a NAME with a
//     non-attr mode, `,chardata,omitempty` (omitempty needs element or
//     attr), and `XMLName` carrying a mode.
//   * `xml:"-"` skipped, a namespace with no name rejected, a trailing
//     `>` rejected, a `a>b` chain rejected under a non-element flag,
//     and `>b` taking its head from the FIELD name.
//   * the XMLName interactions: a tag that agrees with the inner
//     struct's XMLName, one that contradicts it, and a field with no
//     tag at all inheriting the inner XMLName.
//   * addFieldInfo's conflict rules: same name same mode (error),
//     same name different NAME SPACE (fine), same name different MODE
//     (fine), and a name that is a PREFIX of another field's path
//     (error).
//
// LIMIT. goish's reflect descriptor does not model embedding —
// `StructField.Anonymous` is always false — so `getTypeInfo`'s
// embedded-struct branch cannot be reached from here and no row
// exercises it. It is ported, and it is untested; see the port notes
// at the head of src/encoding/xml/typeinfo.rs.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
extern crate alloc;
extern crate goish;

use goish::encoding::xml;
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

static mut PASS: int = 0;
static mut FAIL: int = 0;

// go: none
fn ty_slice() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Slice, "", &[]);
}

static F_tiPlain: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "B",
        Tag: goish::reflect::StructTag::__new("xml:\"\""),
        Type: <int as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiPlain() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiPlain", &F_tiPlain)
        .__with_pkg("xml");
}

static F_tiAttr: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"a,attr\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "B",
        Tag: goish::reflect::StructTag::__new("xml:\"b\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiAttr() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiAttr", &F_tiAttr)
        .__with_pkg("xml");
}

static F_tiNS: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"http://ns/one a\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "B",
        Tag: goish::reflect::StructTag::__new("xml:\"http://ns/two b,attr\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiNS() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiNS", &F_tiNS)
        .__with_pkg("xml");
}

static F_tiModes: [goish::reflect::StructField; 5] = [
    goish::reflect::StructField {
        Name: "C",
        Tag: goish::reflect::StructTag::__new("xml:\",chardata\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "D",
        Tag: goish::reflect::StructTag::__new("xml:\",cdata\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "I",
        Tag: goish::reflect::StructTag::__new("xml:\",innerxml\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "M",
        Tag: goish::reflect::StructTag::__new("xml:\",comment\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "N",
        Tag: goish::reflect::StructTag::__new("xml:\",any\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiModes() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiModes", &F_tiModes)
        .__with_pkg("xml");
}

static F_tiOmit: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"a,omitempty\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "B",
        Tag: goish::reflect::StructTag::__new("xml:\"b,attr,omitempty\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiOmit() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiOmit", &F_tiOmit)
        .__with_pkg("xml");
}

static F_tiOmitBad: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "C",
        Tag: goish::reflect::StructTag::__new("xml:\",chardata,omitempty\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiOmitBad() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiOmitBad", &F_tiOmitBad)
        .__with_pkg("xml");
}

static F_tiTwoModes: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"a,attr,chardata\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiTwoModes() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiTwoModes", &F_tiTwoModes)
        .__with_pkg("xml");
}

static F_tiAnyAttr: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\",any,attr\""),
        Type: ty_slice,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiAnyAttr() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiAnyAttr", &F_tiAnyAttr)
        .__with_pkg("xml");
}

static F_tiNamedMode: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"a,chardata\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiNamedMode() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiNamedMode", &F_tiNamedMode)
        .__with_pkg("xml");
}

static F_tiNamedAttr: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"a,attr\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiNamedAttr() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiNamedAttr", &F_tiNamedAttr)
        .__with_pkg("xml");
}

static F_tiSkip: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"-\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "B",
        Tag: goish::reflect::StructTag::__new("xml:\"b\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiSkip() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiSkip", &F_tiSkip)
        .__with_pkg("xml");
}

static F_tiPath: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"a>b>c\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "D",
        Tag: goish::reflect::StructTag::__new("xml:\"a>b>d\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiPath() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiPath", &F_tiPath)
        .__with_pkg("xml");
}

static F_tiTrailing: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"a>\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiTrailing() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiTrailing", &F_tiTrailing)
        .__with_pkg("xml");
}

static F_tiPathMode: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"a>b,attr\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiPathMode() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiPathMode", &F_tiPathMode)
        .__with_pkg("xml");
}

static F_tiEmptyHead: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\">b\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiEmptyHead() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiEmptyHead", &F_tiEmptyHead)
        .__with_pkg("xml");
}

static F_tiNsNoName: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"http://ns/one \""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiNsNoName() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiNsNoName", &F_tiNsNoName)
        .__with_pkg("xml");
}

static F_tiXMLName: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "XMLName",
        Tag: goish::reflect::StructTag::__new("xml:\"root\""),
        Type: <xml::Name as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"a\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiXMLName() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiXMLName", &F_tiXMLName)
        .__with_pkg("xml");
}

static F_tiXMLNameNS: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "XMLName",
        Tag: goish::reflect::StructTag::__new("xml:\"http://ns/one root\""),
        Type: <xml::Name as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"a\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiXMLNameNS() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiXMLNameNS", &F_tiXMLNameNS)
        .__with_pkg("xml");
}

static F_tiXMLNameBad: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "XMLName",
        Tag: goish::reflect::StructTag::__new("xml:\"root,attr\""),
        Type: <xml::Name as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiXMLNameBad() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiXMLNameBad", &F_tiXMLNameBad)
        .__with_pkg("xml");
}

static F_tiInner: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "XMLName",
        Tag: goish::reflect::StructTag::__new("xml:\"inner\""),
        Type: <xml::Name as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "V",
        Tag: goish::reflect::StructTag::__new("xml:\",chardata\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiInner() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiInner", &F_tiInner)
        .__with_pkg("xml");
}

static F_tiHasInner: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "F",
        Tag: goish::reflect::StructTag::__new("xml:\"inner\""),
        Type: ty_tiInner,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiHasInner() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiHasInner", &F_tiHasInner)
        .__with_pkg("xml");
}

static F_tiHasInnerBad: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "F",
        Tag: goish::reflect::StructTag::__new("xml:\"other\""),
        Type: ty_tiInner,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiHasInnerBad() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiHasInnerBad", &F_tiHasInnerBad)
        .__with_pkg("xml");
}

static F_tiHasInnerDefault: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "F",
        Tag: goish::reflect::StructTag::__new("xml:\"\""),
        Type: ty_tiInner,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiHasInnerDefault() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiHasInnerDefault", &F_tiHasInnerDefault)
        .__with_pkg("xml");
}

static F_tiConflict: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"x\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "B",
        Tag: goish::reflect::StructTag::__new("xml:\"x\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiConflict() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiConflict", &F_tiConflict)
        .__with_pkg("xml");
}

static F_tiConflictNS: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"http://a x\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "B",
        Tag: goish::reflect::StructTag::__new("xml:\"http://b x\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiConflictNS() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiConflictNS", &F_tiConflictNS)
        .__with_pkg("xml");
}

static F_tiPrefixConflict: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"x\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "B",
        Tag: goish::reflect::StructTag::__new("xml:\"x>y\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiPrefixConflict() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiPrefixConflict", &F_tiPrefixConflict)
        .__with_pkg("xml");
}

static F_tiNoConflictMode: [goish::reflect::StructField; 2] = [
    goish::reflect::StructField {
        Name: "A",
        Tag: goish::reflect::StructTag::__new("xml:\"x\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    goish::reflect::StructField {
        Name: "B",
        Tag: goish::reflect::StructTag::__new("xml:\"x,attr\""),
        Type: <string as goish::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiNoConflictMode() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiNoConflictMode", &F_tiNoConflictMode)
        .__with_pkg("xml");
}

static F_tiPtr: [goish::reflect::StructField; 1] = [
    goish::reflect::StructField {
        Name: "F",
        Tag: goish::reflect::StructTag::__new("xml:\"inner\""),
        Type: ty_ptr_tiInner,
        PkgPath: "",
        Anonymous: false,
    },
];
// go: none
fn ty_tiPtr() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Struct, "tiPtr", &F_tiPtr)
        .__with_pkg("xml");
}

// go: none
fn ty_ptr_tiInner() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Pointer, "", &[])
        .__with_elem(ty_tiInner);
}
// go: none
fn trow(idx: int, name: &'static str, typ: goish::reflect::Type, want: &'static str) {
    let got = xml::typeinfo::__typeinfo_script(typ);
    let ok = got == string::from_bytes(want.as_bytes());
    unsafe {
        if ok {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %v %s\n     got  %s\n     want %s\n",
                idx,
                name,
                got.clone(),
                want
            );
        }
    }
}

#[goish::main]
fn main() {
    trow(0, "tiPlain", ty_tiPlain(), "F A||1|0| F B||1|1|");
    trow(1, "tiAttr", ty_tiAttr(), "F a||2|0| F b||1|1|");
    trow(2, "tiNS", ty_tiNS(), "F a|http://ns/one|1|0| F b|http://ns/two|2|1|");
    trow(3, "tiModes", ty_tiModes(), "F C||8|0| F D||4|1| F I||16|2| F M||32|3| F N||65|4|");
    trow(4, "tiOmit", ty_tiOmit(), "F a||129|0| F b||130|1|");
    trow(5, "tiOmitBad", ty_tiOmitBad(), "E xml: invalid tag in field C of type xml.tiOmitBad: \",chardata,omitempty\"");
    trow(6, "tiTwoModes", ty_tiTwoModes(), "E xml: invalid tag in field A of type xml.tiTwoModes: \"a,attr,chardata\"");
    trow(7, "tiAnyAttr", ty_tiAnyAttr(), "F A||66|0|");
    trow(8, "tiNamedMode", ty_tiNamedMode(), "E xml: invalid tag in field A of type xml.tiNamedMode: \"a,chardata\"");
    trow(9, "tiNamedAttr", ty_tiNamedAttr(), "F a||2|0|");
    trow(10, "tiSkip", ty_tiSkip(), "F b||1|1|");
    trow(11, "tiPath", ty_tiPath(), "F c||1|0|a,b F d||1|1|a,b");
    trow(12, "tiTrailing", ty_tiTrailing(), "E xml: trailing '>' in field A of type xml.tiTrailing");
    trow(13, "tiPathMode", ty_tiPathMode(), "E xml: a>b chain not valid with attr flag");
    trow(14, "tiEmptyHead", ty_tiEmptyHead(), "F b||1|0|A");
    trow(15, "tiNsNoName", ty_tiNsNoName(), "E xml: namespace without name in field A of type xml.tiNsNoName: \"http://ns/one \"");
    trow(16, "tiXMLName", ty_tiXMLName(), "X root||1|0| F a||1|1|");
    trow(17, "tiXMLNameNS", ty_tiXMLNameNS(), "X root|http://ns/one|1|0| F a||1|1|");
    trow(18, "tiXMLNameBad", ty_tiXMLNameBad(), "E xml: invalid tag in field XMLName of type xml.tiXMLNameBad: \"root,attr\"");
    trow(19, "tiInner", ty_tiInner(), "X inner||1|0| F V||8|1|");
    trow(20, "tiHasInner", ty_tiHasInner(), "F inner||1|0|");
    trow(21, "tiHasInnerBad", ty_tiHasInnerBad(), "E xml: name \"other\" in tag of xml.tiHasInnerBad.F conflicts with name \"inner\" in xml.tiInner.XMLName");
    trow(22, "tiHasInnerDefault", ty_tiHasInnerDefault(), "F inner||1|0|");
    trow(23, "tiConflict", ty_tiConflict(), "E xml.tiConflict field \"A\" with tag \"x\" conflicts with field \"B\" with tag \"x\"");
    trow(24, "tiConflictNS", ty_tiConflictNS(), "F x|http://a|1|0| F x|http://b|1|1|");
    trow(25, "tiPrefixConflict", ty_tiPrefixConflict(), "E xml.tiPrefixConflict field \"A\" with tag \"x\" conflicts with field \"B\" with tag \"x>y\"");
    trow(26, "tiNoConflictMode", ty_tiNoConflictMode(), "F x||1|0| F x||2|1|");
    trow(27, "tiPtr", ty_tiPtr(), "F inner||1|0|");
    trow(28, "Name", <xml::Name as goish::reflect::Reflect>::__reflect_type(), "");
    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 29 {
            fmt::Printf!("FAIL ran %v rows, expected 29\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("xml_typeinfo_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
