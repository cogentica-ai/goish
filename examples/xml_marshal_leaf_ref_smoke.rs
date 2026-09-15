// encoding/xml: the LEAF half of marshal.go's reflect side.
//
// `marshalSimple`, `isEmptyValue`, `indirect`, `defaultStart`,
// `parentStack.trim`/`push`, `marshalTextInterface` and
// `UnsupportedTypeError` — the functions `marshalValue` reaches that do
// NOT need the reflect capabilities goish does not have.
//
// WHAT IS STILL MISSING, stated rather than implied. `marshalValue`,
// `marshalStruct`, `marshalAttr` and `marshalInterface` are NOT ported
// and nothing here calls these seven from a Marshal(). Go's
// marshalValue dispatches on `typ.Implements(marshalerType)` and
// `val.CanAddr()` / `val.Addr()`, and goish's reflect has none of
// `Implements`, `CanAddr`, `Addr`, `NumMethod` or `Method` — so the
// MarshalXML / MarshalText dispatch cannot be expressed at all, and a
// Marshal built without it would silently ignore every type that
// implements them. That is the blocker, it is in reflect and not in
// encoding/xml, and it is written up in ROADMAP §2. These seven are
// the part that can be pinned today, and the traversal will sit on
// them unchanged.
//
// 71 rows from Go 1.25.5 (`scripts/goref.sh encoding/xml`), values and
// error text dumped as hex.
//
// WHAT THE ROWS ARE FOR:
//
//   * marshalSimple's float formatting is Go's `FormatFloat(f, 'g', -1,
//     bits)`, and the rows are where 'g' switches to exponent form:
//     1e20 prints in full, 1e21 as `1e+21`, 1e-7 as `1e-07`. float32
//     and float64 take DIFFERENT bit widths, so 0.1 as a float32 must
//     still print `0.1` and not the float64 expansion of the same bits.
//   * every integer width at its extreme, including uint's full range,
//     because Go formats through Int()/Uint() and a wrong accessor is
//     invisible at small values.
//   * the three UnsupportedTypeError cases, which is where Marshal's
//     "unsupported type" text is decided — and it renders the TYPE, so
//     `[]int` and `map[string]int` and a named struct each read
//     differently.
//   * isEmptyValue's non-obvious half: a STRUCT is never empty whatever
//     it holds, a non-nil pointer to a zero value is not empty, and a
//     nil slice and an allocated-empty slice are BOTH empty (Len, not
//     IsZero). Negative zero is empty.
//   * defaultStart's three precedences plus the pointer fallthrough to
//     `typ.Elem().Name()`.
//   * parentStack against the real printer: trim writes an end tag per
//     popped parent, a diverging chain pops to the common prefix, and
//     a LONGER parents list trims nothing.
//   * marshalTextInterface escapes with EscapeText, so `\n` becomes
//     `&#xA;` here where the same bytes through EncodeToken's CharData
//     path stay literal.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::encoding::xml;
use goish::fmt;
use goish::gostring::string;
use goish::reflect::Value as RV;
use goish::sync;
use goish::types::int;

static mut PASS: int = 0;
static mut FAIL: int = 0;

// go: none
fn unhex(h: &str) -> alloc::vec::Vec<u8> {
    let b = h.as_bytes();
    let mut out = alloc::vec::Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        // go: none
        fn nib(c: u8) -> u8 {
            if c >= b'0' && c <= b'9' {
                return c - b'0';
            }
            return c - b'a' + 10;
        }
        out.push(nib(b[i]) * 16 + nib(b[i + 1]));
        i += 2;
    }
    return out;
}

// go: none
fn ck(idx: int, name: &'static str, got: string, want: string) {
    unsafe {
        if got == want {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %v %s\n     got  %s\n     want %s\n",
                idx,
                name,
                got.clone(),
                want.clone()
            );
        }
    }
}

// ── the reflect descriptors the rows need ────────────────────────────

static MS_FIELDS: [goish::reflect::StructField; 1] = [goish::reflect::StructField {
    Name: "A",
    Tag: goish::reflect::StructTag::__new(""),
    Type: <int as goish::reflect::Reflect>::__reflect_type,
    PkgPath: "",
    Anonymous: false,
}];

// go: none
fn ty_struct() -> goish::reflect::Type {
    return goish::reflect::Type::__new(
        goish::reflect::Kind::Struct,
        "msStruct",
        &MS_FIELDS,
    )
    .__with_pkg("xml");
}

// go: none
fn ty_ptr_struct() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Pointer, "", &[])
        .__with_elem(ty_struct);
}

// go: none
fn ty_int() -> goish::reflect::Type {
    return <int as goish::reflect::Reflect>::__reflect_type();
}

// go: none
fn ty_u8() -> goish::reflect::Type {
    return <goish::byte as goish::reflect::Reflect>::__reflect_type();
}

// go: none
fn ty_str() -> goish::reflect::Type {
    return <string as goish::reflect::Reflect>::__reflect_type();
}

// go: none
fn ty_slice_int() -> goish::reflect::Type {
    return goish::reflect::Type::__new(goish::reflect::Kind::Slice, "", &[])
        .__with_elem(ty_int);
}

// go: none
fn vbytes(b: &[u8]) -> RV {
    let mut items = alloc::vec::Vec::new();
    for x in b.iter() {
        items.push(RV::Uint8(*x));
    }
    return RV::Slice {
        elem_type: ty_u8,
        items,
        is_nil: false,
    };
}

// go: none
fn vslice_int() -> RV {
    return RV::Slice {
        elem_type: ty_int,
        items: alloc::vec![RV::Int(1), RV::Int(2)],
        is_nil: false,
    };
}

// go: none
fn vslice_int_empty() -> RV {
    return RV::Slice {
        elem_type: ty_int,
        items: alloc::vec::Vec::new(),
        is_nil: false,
    };
}

// go: none
fn vslice_nil() -> RV {
    return RV::Slice {
        elem_type: ty_int,
        items: alloc::vec::Vec::new(),
        is_nil: true,
    };
}

// go: none
fn vslice_one() -> RV {
    return RV::Slice {
        elem_type: ty_int,
        items: alloc::vec![RV::Int(1)],
        is_nil: false,
    };
}

// go: none
fn vmap() -> RV {
    return RV::Map {
        key_type: ty_str,
        value_type: ty_int,
        entries: alloc::vec::Vec::new(),
        is_nil: false,
    };
}

// go: none
fn vmap_nil() -> RV {
    return RV::Map {
        key_type: ty_str,
        value_type: ty_int,
        entries: alloc::vec::Vec::new(),
        is_nil: true,
    };
}

// go: none
fn vmap_one() -> RV {
    return RV::Map {
        key_type: ty_str,
        value_type: ty_int,
        entries: alloc::vec![(RV::String(string::from_static("a")), RV::Int(1))],
        is_nil: false,
    };
}

// go: none
fn vstruct() -> RV {
    return RV::Struct {
        ty: ty_struct(),
        fields: alloc::vec![RV::Int(0)],
    };
}

// go: none
fn vstruct_set() -> RV {
    return RV::Struct {
        ty: ty_struct(),
        fields: alloc::vec![RV::Int(1)],
    };
}

// go: none
fn se(
    space: &'static str,
    local: &'static str,
    attrs: &[(&'static str, &'static str, &'static str)],
) -> xml::StartElement {
    let mut a = goish::slice!([]xml::Attr{});
    for (s, l, v) in attrs.iter() {
        a = goish::append!(
            a,
            xml::Attr {
                Name: xml::Name {
                    Space: string::from_static(s),
                    Local: string::from_static(l),
                },
                Value: string::from_static(v),
            }
        );
    }
    return xml::StartElement {
        Name: xml::Name {
            Space: string::from_static(space),
            Local: string::from_static(local),
        },
        Attr: a,
    };
}

// go: none
fn fi(name: &'static str, xmlns: &'static str) -> xml::typeinfo::fieldInfo {
    let mut f = xml::typeinfo::fieldInfo::default();
    f.name = string::from_static(name);
    f.xmlns = string::from_static(xmlns);
    return f;
}

// go: none — a TextMarshaler for marshalTextInterface to call.
struct TM(string);

impl goish::encoding::TextMarshaler for TM {
    // go: none
    fn MarshalText(&self) -> (goish::slice<goish::byte>, goish::error) {
        return (
            goish::slice::__from_vec(self.0.as_bytes().to_vec()),
            goish::errors::nil,
        );
    }
}

// go: none
fn newp() -> (
    xml::marshal::Encoder<Arc<sync::Mutex<goish::bytes::Buffer>>>,
    Arc<sync::Mutex<goish::bytes::Buffer>>,
) {
    let buf = Arc::new(sync::Mutex::new(goish::bytes::Buffer::new()));
    let enc = xml::NewEncoder(buf.clone());
    return (enc, buf);
}

// ── the rows ─────────────────────────────────────────────────────────

// go: none
fn msrow(idx: int, name: &'static str, v: RV, ws: &'static str, wb: &'static str, we: &'static str) {
    let (enc, _buf) = newp();
    let (s, b, err) = enc.p.marshalSimple(v.Type(), &v);
    let goterr = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    let got = goish::encoding::hex::EncodeToString(s.as_bytes())
        + string::from_static("|")
        + goish::encoding::hex::EncodeToString(&b)
        + string::from_static("|")
        + goterr;
    let want = string::from_static(ws)
        + string::from_static("|")
        + string::from_static(wb)
        + string::from_static("|")
        + string::from_bytes(we.as_bytes());
    ck(idx, name, got, want);
}

// go: none
fn ievrow(idx: int, name: &'static str, v: RV, want: bool) {
    let got = xml::marshal::isEmptyValue(&v);
    ck(
        idx,
        name,
        fmt::Sprintf!("%v", got),
        fmt::Sprintf!("%v", want),
    );
}

// go: none
fn indrow(idx: int, name: &'static str, v: RV, wkind: &'static str, wvalid: bool) {
    let r = xml::marshal::indirect(v);
    ck(
        idx,
        name,
        fmt::Sprintf!("%s|%v", r.Kind().String(), r.IsValid()),
        fmt::Sprintf!("%s|%v", string::from_static(wkind), wvalid),
    );
}

// go: none
fn dsrow(
    idx: int,
    name: &'static str,
    typ: goish::reflect::Type,
    finfo: Option<&xml::typeinfo::fieldInfo>,
    tmpl: Option<&xml::StartElement>,
    wspace: &'static str,
    wlocal: &'static str,
    wattr: int,
) {
    let s = xml::marshal::defaultStart(typ, finfo, tmpl);
    ck(
        idx,
        name,
        goish::encoding::hex::EncodeToString(s.Name.Space.as_bytes())
            + string::from_static("|")
            + goish::encoding::hex::EncodeToString(s.Name.Local.as_bytes())
            + string::from_static("|")
            + goish::strconv::Itoa(s.Attr.Len()),
        string::from_static(wspace)
            + string::from_static("|")
            + string::from_static(wlocal)
            + string::from_static("|")
            + goish::strconv::Itoa(wattr),
    );
}

// go: none
fn psrow(
    idx: int,
    name: &'static str,
    seq: &[&[&'static str]],
    wout: &'static str,
    werr: &'static str,
) {
    let (mut enc, buf) = newp();
    let mut st = xml::marshal::parentStack::default();
    let mut errs = string::from_static("");
    let mut i: int = 0;
    for parents in seq.iter() {
        let mut ps = goish::slice!([]string{});
        for p in parents.iter() {
            ps = goish::append!(ps, string::from_static(p));
        }
        let err = if i % 2 == 0 {
            st.push(&mut enc.p, &ps)
        } else {
            st.trim(&mut enc.p, &ps)
        };
        if err != goish::errors::nil {
            errs = fmt::Sprintf!("step%v:%s", i, err.Error());
            break;
        }
        i += 1;
    }
    if errs.Len() == 0 {
        let err = enc.Flush();
        if err != goish::errors::nil {
            errs = string::from_static("flush:") + err.Error();
        }
    }
    ck(
        idx,
        name,
        goish::encoding::hex::EncodeToString(&buf.Lock().Bytes()) + string::from_static("|") + errs,
        string::from_static(wout) + string::from_static("|") + string::from_bytes(werr.as_bytes()),
    );
}

// go: none
fn mtirow(
    idx: int,
    name: &'static str,
    text: &'static str,
    start: xml::StartElement,
    wout: &'static str,
    werr: &'static str,
) {
    let (mut enc, buf) = newp();
    let tm = TM(string::from_bytes(text.as_bytes()));
    let err = enc.p.marshalTextInterface(&tm, start);
    let mut errs = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    if errs.Len() == 0 {
        let e = enc.Flush();
        if e != goish::errors::nil {
            errs = string::from_static("flush:") + e.Error();
        }
    }
    ck(
        idx,
        name,
        goish::encoding::hex::EncodeToString(&buf.Lock().Bytes()) + string::from_static("|") + errs,
        string::from_static(wout) + string::from_static("|") + string::from_bytes(werr.as_bytes()),
    );
}

// go: none
fn uterow(idx: int, typ: goish::reflect::Type, want: &'static str) {
    let e = xml::marshal::UnsupportedTypeError { Type: typ };
    ck(
        idx,
        "UnsupportedTypeError",
        e.Error(),
        string::from_bytes(want.as_bytes()),
    );
}

#[goish::main]
fn main() {
    msrow(0, "int0", RV::Int(0), "30", "", "");
    msrow(1, "int", RV::Int(-42), "2d3432", "", "");
    msrow(2, "int8", RV::Int8(-128), "2d313238", "", "");
    msrow(3, "int16", RV::Int16(32767), "3332373637", "", "");
    msrow(4, "int32", RV::Int32(-2147483648), "2d32313437343833363438", "", "");
    msrow(5, "uint", RV::Uint(18446744073709551615), "3138343436373434303733373039353531363135", "", "");
    msrow(6, "uint8", RV::Uint8(255), "323535", "", "");
    msrow(7, "uint16", RV::Uint16(65535), "3635353335", "", "");
    msrow(8, "uint32", RV::Uint32(4294967295), "34323934393637323935", "", "");
    msrow(9, "f64-0", RV::Float64(0.0), "30", "", "");
    msrow(10, "f64-half", RV::Float64(0.5), "302e35", "", "");
    msrow(11, "f64-tenth", RV::Float64(0.1), "302e31", "", "");
    msrow(12, "f64-1e21", RV::Float64(1e21), "31652b3231", "", "");
    msrow(13, "f64-1e20", RV::Float64(1e20), "31652b3230", "", "");
    msrow(14, "f64-1e-7", RV::Float64(1e-7), "31652d3037", "", "");
    msrow(15, "f64-neg", RV::Float64(-2.5), "2d322e35", "", "");
    msrow(16, "f64-big", RV::Float64(1.7976931348623157e308), "312e37393736393331333438363233313537652b333038", "", "");
    msrow(17, "f32-tenth", RV::Float32(0.1), "302e31", "", "");
    msrow(18, "f32-1e21", RV::Float32(1e21), "31652b3231", "", "");
    msrow(19, "f32-max", RV::Float32(3.4028235e38), "332e34303238323335652b3338", "", "");
    msrow(20, "str", RV::String(string::from_static("hi<&>")), "68693c263e", "", "");
    msrow(21, "str-empty", RV::String(string::from_static("")), "", "", "");
    msrow(22, "bool-t", RV::Bool(true), "74727565", "", "");
    msrow(23, "bool-f", RV::Bool(false), "66616c7365", "", "");
    msrow(24, "bytes", vbytes(&[0, 1, 255]), "", "0001ff", "");
    msrow(25, "bytes-empty", vbytes(&[]), "", "", "");
    msrow(26, "slice-int", vslice_int(), "", "", "xml: unsupported type: []int");
    msrow(27, "map", vmap(), "", "", "xml: unsupported type: map[string]int");
    msrow(28, "struct", vstruct(), "", "", "xml: unsupported type: xml.msStruct");
    ievrow(29, "int0", RV::Int(0), true);
    ievrow(30, "int1", RV::Int(1), false);
    ievrow(31, "f0", RV::Float64(0.0), true);
    ievrow(32, "f-neg0", RV::Float64(-0.0), true);
    ievrow(33, "f1", RV::Float64(1.0), false);
    ievrow(34, "bool-f", RV::Bool(false), true);
    ievrow(35, "bool-t", RV::Bool(true), false);
    ievrow(36, "str-empty", RV::String(string::from_static("")), true);
    ievrow(37, "str", RV::String(string::from_static("x")), false);
    ievrow(38, "slice-nil", vslice_nil(), true);
    ievrow(39, "slice-empty", vslice_int_empty(), true);
    ievrow(40, "slice-one", vslice_one(), false);
    ievrow(41, "map-nil", vmap_nil(), true);
    ievrow(42, "map-empty", vmap(), true);
    ievrow(43, "map-one", vmap_one(), false);
    ievrow(44, "ptr-nil", RV::Pointer(alloc::boxed::Box::new(RV::Invalid)), true);
    ievrow(45, "ptr", RV::Pointer(alloc::boxed::Box::new(RV::Int(0))), false);
    ievrow(46, "struct", vstruct(), false);
    ievrow(47, "struct-set", vstruct_set(), false);
    indrow(48, "int", RV::Int(1), "int", true);
    indrow(49, "ptr", RV::Pointer(alloc::boxed::Box::new(RV::Int(0))), "int", true);
    indrow(50, "ptr-nil", RV::Pointer(alloc::boxed::Box::new(RV::Invalid)), "ptr", true);
    indrow(51, "ptrptr", RV::Pointer(alloc::boxed::Box::new(RV::Pointer(alloc::boxed::Box::new(RV::Int(0))))), "int", true);
    indrow(52, "str", RV::String(string::from_static("x")), "string", true);
    dsrow(53, "tmpl", ty_struct(), None, Some(&se("ns", "tmpl", &[("", "k", "v")])), "6e73", "746d706c", 1);
    dsrow(54, "finfo", ty_struct(), Some(&fi("fn", "fns")), None, "666e73", "666e", 0);
    dsrow(55, "finfo-empty", ty_struct(), Some(&fi("", "")), None, "", "6d73537472756374", 0);
    dsrow(56, "typename", ty_struct(), None, None, "", "6d73537472756374", 0);
    dsrow(57, "ptr-typename", ty_ptr_struct(), None, None, "", "6d73537472756374", 0);
    psrow(58, "push-trim", &[&["a","b"][..], &["a"][..]], "3c613e3c623e3c2f623e", "");
    psrow(59, "push-empty", &[&[][..], &[][..]], "", "");
    psrow(60, "push-trim-all", &[&["a","b","c"][..], &[][..]], "3c613e3c623e3c633e3c2f633e3c2f623e3c2f613e", "");
    psrow(61, "push-trim-diverge", &[&["a","b"][..], &["a","x"][..]], "3c613e3c623e3c2f623e", "");
    psrow(62, "push-trim-longer", &[&["a"][..], &["a","b"][..]], "3c613e", "");
    psrow(63, "push-push", &[&["a"][..], &["a"][..], &["b"][..]], "3c613e3c623e", "");
    mtirow(64, "plain", "hi", se("", "a", &[]), "3c613e68693c2f613e", "");
    mtirow(65, "escape", "x<&>\"'\t\n\r", se("", "a", &[]), "3c613e78266c743b26616d703b2667743b262333343b262333393b262378393b262378413b262378443b3c2f613e", "");
    mtirow(66, "ns", "v", se("http://d", "a", &[]), "3c6120786d6c6e733d22687474703a2f2f64223e763c2f613e", "");
    mtirow(67, "attr", "v", se("", "a", &[("", "k", "1")]), "3c61206b3d2231223e763c2f613e", "");
    mtirow(68, "noname", "v", se("", "", &[]), "", "xml: start tag with no name");
    uterow(69, ty_struct(), "xml: unsupported type: xml.msStruct");
    uterow(70, ty_slice_int(), "xml: unsupported type: []int");
    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 71 {
            fmt::Printf!("FAIL ran %v rows, expected 71\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("xml_marshal_leaf_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
