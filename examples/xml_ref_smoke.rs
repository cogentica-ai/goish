// xml_ref_smoke — encoding/xml against a running Go.
// (encoding/xml/xml.go, marshal.go, read.go, typeinfo.go)
//
// Every expectation below is what a real Go prints: the lines in GO are
// the verbatim output of `go run tools/gen_xml_ref.go`. The generator and
// this file walk the same cases in the same order, so a case added to one
// is a mismatch in the other, never a silent pass.
//
// What is pinned, because a plausible port gets it wrong while ordinary
// documents still parse and print:
//
//   * Token vs RawToken: name-space translation (with the xmlns
//     declarations in a start tag applying to that tag's own name and to
//     its attributes, but the default space NOT applying to attributes),
//     and the `xml` prefix mapping to its fixed URL.
//   * Text normalisation: `\r\n` and lone `\r` become `\n`, entities and
//     character references expand, a DOCTYPE's embedded comment becomes
//     one space, and each refusal (bad entity, out-of-range reference,
//     control character, invalid UTF-8, `--` in a comment, `]]>` in text,
//     `<` in an attribute) has its own message and line number.
//   * Non-strict HTML mode: AutoClose, HTMLEntity, unquoted and
//     value-less attributes.
//   * InputOffset/InputPos after the last token or error.
//   * The encoder's attribute-prefix generation (`x`, `x_1`, `_XMLthing`,
//     `_`, the predefined `xml`), its escaping, Indent's layout, and every
//     EncodeToken refusal.
//   * Marshal's tag grammar — parent chains, omitempty, attr, chardata,
//     cdata (with a nested `]]>`), comment (with the trailing-dash pad),
//     `-`, XMLName by tag and by value — and its refusals.
//   * Unmarshal's merge semantics, the order that attributes, character
//     data, comments, `,any` and `,innerxml` are filled in, whitespace
//     trimming of numbers, overflow errors, and the XMLName checks.
//
// The one textual difference is removed at the source: Go prints user
// types package-qualified ("main.Conflict"), goish's reflect.Type has no
// package for a user struct, so the generator strips "main.".
//
// Not covered, because goish's reflection cannot express it (see
// src/encoding/xml/marshal.rs): user Marshaler/Unmarshaler methods on
// nested values, and Unmarshal into a time.Time field — the
// `#[goish::reflect]` service layer needs a JSON codec on every field
// type, which time.Time does not have. Marshal of time.Time is covered.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;

use goish::bytes;
use goish::encoding::xml;
use goish::errors::{self, error};
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::strconv;
use goish::sync;
use goish::syscall;
use goish::time;
use goish::types::{byte, float32, float64, int, uint};

const GO: [&str; 79] = [
    "tok full -> P xml \"version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"\" ; C \"\\n\" ; D \"DOCTYPE doc [<!ENTITY e \\\"v\\\">   ]\" ; C \"\\n\" ; S {urn:d}doc {}xmlns=\"urn:d\" {xmlns}p=\"urn:p\" {urn:p}a=\"1\" {}b=\"2\" ; C \"\\n text & <>\\\"' AB \" ; S {urn:p}x ; E {urn:p}x ; C \"<raw>\" ; M \" note \" ; S {urn:d}y {http://www.w3.org/XML/1998/namespace}lang=\"en\" ; C \"z\" ; E {urn:d}y ; E {urn:d}doc ; EOF | off=244 pos=4:110",
    "tok full-raw -> P xml \"version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"\" ; C \"\\n\" ; D \"DOCTYPE doc [<!ENTITY e \\\"v\\\">   ]\" ; C \"\\n\" ; S {}doc {}xmlns=\"urn:d\" {xmlns}p=\"urn:p\" {p}a=\"1\" {}b=\"2\" ; C \"\\n text & <>\\\"' AB \" ; S {p}x ; E {p}x ; C \"<raw>\" ; M \" note \" ; S {}y {xml}lang=\"en\" ; C \"z\" ; E {}y ; E {}doc ; EOF | off=244 pos=4:110",
    "tok empty -> EOF | off=0 pos=1:1",
    "tok eof -> S {}a ; S {}b ; E {}b ; err=XML syntax error on line 1: unexpected EOF | off=10 pos=1:11",
    "tok mismatch -> S {}a ; err=XML syntax error on line 1: element <a> closed by </b> | off=7 pos=1:8",
    "tok stray-end -> err=XML syntax error on line 1: unexpected end element </a> | off=4 pos=1:5",
    "tok entity -> S {}a ; err=XML syntax error on line 1: invalid character entity &foo; | off=8 pos=1:9",
    "tok entity-nosemi -> S {}a ; err=XML syntax error on line 1: invalid character entity &amp (no semicolon) | off=7 pos=1:8",
    "tok charref-big -> S {}a ; err=XML syntax error on line 1: invalid character entity &#x110000; | off=13 pos=1:14",
    "tok badchar -> S {}a ; err=XML syntax error on line 1: illegal character code U+0001 | off=4 pos=1:5",
    "tok badutf8 -> S {}a ; err=XML syntax error on line 1: invalid UTF-8 | off=4 pos=1:5",
    "tok comment-dashes -> err=XML syntax error on line 1: invalid sequence \"--\" not allowed in comments | off=10 pos=1:11",
    "tok unquoted -> err=XML syntax error on line 1: unquoted or missing attribute value in element | off=6 pos=1:7",
    "tok noeq -> err=XML syntax error on line 1: attribute name without = in element | off=5 pos=1:6",
    "tok badname -> err=XML syntax error on line 1: invalid XML name: 1a | off=3 pos=1:4",
    "tok cdata-end-in-text -> S {}a ; err=XML syntax error on line 1: unescaped ]]> not in CDATA section | off=6 pos=1:7",
    "tok bad-cdata-seq -> err=XML syntax error on line 1: invalid <![ sequence | off=7 pos=1:8",
    "tok cdata-eof -> S {}a ; err=XML syntax error on line 1: unexpected EOF in CDATA section | off=15 pos=1:16",
    "tok version -> err=xml: unsupported version \"1.1\"; only version 1.0 is supported | off=21 pos=1:22",
    "tok encoding -> err=xml: encoding \"latin1\" declared but Decoder.CharsetReader is nil | off=39 pos=1:40",
    "tok lt-in-attr -> err=XML syntax error on line 1: unescaped < inside quoted string | off=7 pos=1:8",
    "tok space-mismatch -> S {x}a ; err=XML syntax error on line 1: element <a> in space x closed by </a> in space y | off=11 pos=1:12",
    "tok end-junk -> S {}a ; err=XML syntax error on line 1: invalid characters between </a and > | off=8 pos=1:9",
    "tok two-colons -> err=XML syntax error on line 1: expected element name after < | off=6 pos=1:7",
    "tok crlf -> S {}a ; C \"1\\n2\\n3\" ; E {}a ; EOF | off=13 pos=2:8",
    "tok line -> S {}a ; C \"\\n\\n\" ; S {}b ; err=XML syntax error on line 3: element <b> closed by </a> | off=12 pos=3:8",
    "tok pi-noname -> err=XML syntax error on line 1: expected target name after <? | off=2 pos=1:3",
    "tok directive-quoted -> D \"DOCTYPE a '>' \\\"<\\\" <![x]>\" ; EOF | off=27 pos=1:28",
    "tok attr-dup-ns -> S {}a {xmlns}p=\"u1\" ; S {u2}b {xmlns}p=\"u2\" {u2}c=\"1\" ; E {u2}b ; S {u1}d ; E {u1}d ; E {}a ; EOF | off=53 pos=1:54",
    "tok html -> S {}html ; S {}p ; C \"a\\u00a0b &bogus; c\" ; S {}br ; E {}br ; C \"d\" ; S {}img {}src=\"x\" {}alt=\"alt\" ; E {}img ; C \"e\" ; E {}p ; E {}html ; EOF | off=59 pos=1:60",
    "tok defaultspace -> S {urn:def}a ; S {urn:x}b {}xmlns=\"urn:x\" ; E {urn:x}b ; S {urn:def}c ; E {urn:def}c ; E {urn:def}a ; EOF | off=29 pos=1:30",
    "skip first=S {}a then=S {}b skip=<nil> next=S {}b",
    "escape -> \"a&lt;b&gt;&amp;&#34;&#39;&#x9;&#xA;&#xD;\u{fffd}\u{fffd}\u{fffd}\" err=<nil>",
    "encode -> \"<?xml version=\\\"1.0\\\"?><root xmlns=\\\"urn:a\\\" xmlns:ns=\\\"http://ex.com/ns/\\\" ns:k=\\\"v\\\" xmlns:x=\\\"http://a/x\\\" x:k1=\\\"1\\\" xmlns:x_1=\\\"http://b/x\\\" x_1:k2=\\\"2\\\" xmlns:_XMLthing=\\\"http://q/XMLthing\\\" _XMLthing:k3=\\\"3\\\" xmlns:_=\\\"urn:q\\\" _:k4=\\\"4\\\" xml:lang=\\\"en\\\" plain=\\\"a&lt;&amp;&#34;&#39;&#x9;&#xA;&#xD;\\\">x&lt;y\\n<!-- hi -->\\n  <child></child><!DOCTYPE a [<!-- c --> ]>\\n</root>\" errs=<nil>,<nil>,<nil>,<nil>,<nil>,<nil>,<nil>,<nil>,<nil>",
    "encerr end-without-start -> xml: end tag </a> without start tag",
    "encerr end-mismatch -> xml: end tag </b> does not match start tag <a>",
    "encerr end-ns-mismatch -> xml: end tag </a> in namespace u2 does not match start tag <a> in namespace u1",
    "encerr comment-marker -> xml: EncodeToken of Comment containing --> marker",
    "encerr procinst-late -> xml: EncodeToken of ProcInst xml target only valid for xml declaration, first token encoded",
    "encerr procinst-target -> xml: EncodeToken of ProcInst with invalid Target",
    "encerr procinst-marker -> xml: EncodeToken of ProcInst containing ?> marker",
    "encerr directive -> xml: EncodeToken of Directive containing wrong < or > markers",
    "encerr unclosed -> unclosed tag <a>",
    "encerr noname -> xml: start tag with no name",
    "encerr after-close -> use of closed Encoder",
    "marshal person -> \"<person xmlns=\\\"urn:p\\\" id=\\\"13\\\"><name><first>John</first><last>Doe</last></name><age>42</age><height>1.75</height><Married>true</Married><email>a@x</email><email>b@x</email><home zip=\\\"0\\\"><city>Hanga Roa</city></home><!-- Need more details. -->t&amp;t<raw>r&lt;</raw></person>\" err=<nil>",
    "indent person -> \"><person xmlns=\\\"urn:p\\\" id=\\\"13\\\">\\n>  <name>\\n>    <first>John</first>\\n>    <last>Doe</last>\\n>  </name>\\n>  <age>42</age>\\n>  <height>1.75</height>\\n>  <Married>true</Married>\\n>  <email>a@x</email>\\n>  <email>b@x</email>\\n>  <home zip=\\\"0\\\">\\n>    <city>Hanga Roa</city>\\n>  </home>\\n>  <!-- Need more details. -->t&amp;t\\n>  <raw>r&lt;</raw>\\n></person>\" err=<nil>",
    "marshal person-zero -> \"<person xmlns=\\\"urn:p\\\" id=\\\"0\\\"><name><first></first><last></last></name><age>0</age><Married>false</Married><raw></raw></person>\" err=<nil>",
    "marshal int -> \"<int>5</int>\" err=<nil>",
    "marshal string -> \"<string>hi</string>\" err=<nil>",
    "marshal ints -> \"<int>1</int><int>2</int>\" err=<nil>",
    "marshal map -> \"\" err=xml: unsupported type: map[string]int",
    "marshal dyn -> \"<dyn xmlns=\\\"urn:x\\\"><v>1</v></dyn>\" err=<nil>",
    "marshal dyn-noname -> \"<Dyn><v>2</v></Dyn>\" err=<nil>",
    "marshal cdata -> \"<cd><![CDATA[a]]]]><![CDATA[>b]]></cd>\" err=<nil>",
    "marshal comment-dash -> \"<c><!--x- --></c>\" err=<nil>",
    "marshal comment-dashdash -> \"\" err=xml: comments must not contain \"--\"",
    "marshal badtag -> \"\" err=xml: invalid tag in field A of type BadTag: \"a,chardata\"",
    "marshal conflict -> \"\" err=Conflict field \"A\" with tag \"x\" conflicts with field \"B\" with tag \"x\"",
    "marshal chain-attr -> \"\" err=xml: a>b chain not valid with attr flag",
    "marshal nums -> \"<n u16=\\\"255\\\"><i8>-5</i8><f32>0.1</f32><b>true</b></n>\" err=<nil>",
    "marshal time -> \"<ts t=\\\"1999-12-31T23:59:59Z\\\"><at>2024-01-02T03:04:05.5Z</at></ts>\" err=<nil>",
    "unmarshal roundtrip -> xmlname={urn:p}person id=13 kind=\"\" first=\"John\" last=\"Doe\" age=42 height=1.75 married=true emails=[\"a@x\" \"b@x\"] home={city=\"Hanga Roa\" zip=\"0\"} note=\" Need more details. \" text=\"t&t\" raw=\"r<\" err=<nil>",
    "unmarshal doc -> xmlname={urn:p}person id=7 kind=\"k\" first=\"A\" last=\"B\" age=9 height=0 married=true emails=[\"e1\" \"e2\"] home={city=\"C\" zip=\"z\"} note=\"c1c2\" text=\"txt\" raw=\"\" err=<nil>",
    "unmarshal merge -> xmlname={urn:p}person id=0 kind=\"\" first=\"keep\" last=\"\" age=0 height=0 married=false emails=[\"old\" \"new\"] home=nil note=\"\" text=\"\" raw=\"\" err=<nil>",
    "unmarshal wrong-name -> xmlname={} id=0 kind=\"\" first=\"\" last=\"\" age=0 height=0 married=false emails=[] home=nil note=\"\" text=\"\" raw=\"\" err=expected element type <person> but have <human>",
    "unmarshal no-ns -> xmlname={} id=0 kind=\"\" first=\"\" last=\"\" age=0 height=0 married=false emails=[] home=nil note=\"\" text=\"\" raw=\"\" err=expected element <person> in name space urn:p but have no name space",
    "unmarshal bad-int -> xmlname={urn:p}person id=0 kind=\"\" first=\"\" last=\"\" age=0 height=0 married=false emails=[] home=nil note=\"\" text=\"\" raw=\"\" err=strconv.ParseInt: parsing \"x\": invalid syntax",
    "unmarshal bad-bool -> xmlname={urn:p}person id=0 kind=\"\" first=\"\" last=\"\" age=0 height=0 married=false emails=[] home=nil note=\"\" text=\"\" raw=\"\" err=strconv.ParseBool: parsing \"maybe\": invalid syntax",
    "unmarshal syntax -> xmlname={urn:p}person id=0 kind=\"\" first=\"\" last=\"\" age=0 height=0 married=false emails=[] home=nil note=\"\" text=\"\" raw=\"\" err=XML syntax error on line 1: element <age> closed by </person>",
    "unmarshal empty-age -> xmlname={urn:p}person id=0 kind=\"\" first=\"\" last=\"\" age=0 height=0 married=false emails=[] home=nil note=\"\" text=\"\" raw=\"\" err=<nil>",
    "unmarshal innerxml -> inner=\"<a>1</a><b>2&amp;</b>\" a=\"1\" name=wrap err=<nil>",
    "unmarshal any -> a=\"A\" other=[\"B\" \"C\"] extra=\"2\" err=<nil>",
    "unmarshal overflow -> i8=0 u16=0 err=strconv.ParseUint: parsing \"700\": value out of range",
    "unmarshal nums -> i8=-5 u16=7 f32=2.5 b=true err=<nil>",
    "unmarshal slice -> [\"one\"] err=<nil>",
    "unmarshal string -> \"ac\" err=<nil>",
    "unmarshal conflict -> err=Conflict field \"A\" with tag \"x\" conflicts with field \"B\" with tag \"x\"",
    "unmarshal empty -> err=EOF",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from(x);
}

fn b(x: &[u8]) -> slice<byte> {
    return slice::__from_vec(x.to_vec());
}

fn errs(err: &error) -> string {
    if *err == errors::nil {
        return s("<nil>");
    }
    return err.Error();
}

fn tok(t: &xml::Token) -> string {
    return match t {
        xml::Token::StartElement(v) => {
            let mut out = fmt::Sprintf!("S {%s}%s", v.Name.Space, v.Name.Local);
            for (_, a) in goish::range!(v.Attr) {
                out = out + fmt::Sprintf!(" {%s}%s=%q", a.Name.Space, a.Name.Local, a.Value);
            }
            out
        }
        xml::Token::EndElement(v) => fmt::Sprintf!("E {%s}%s", v.Name.Space, v.Name.Local),
        xml::Token::CharData(v) => fmt::Sprintf!("C %q", string::from_bytes(&v.0)),
        xml::Token::Comment(v) => fmt::Sprintf!("M %q", string::from_bytes(&v.0)),
        xml::Token::ProcInst(v) => fmt::Sprintf!("P %s %q", v.Target, string::from_bytes(&v.Inst)),
        xml::Token::Directive(v) => fmt::Sprintf!("D %q", string::from_bytes(&v.0)),
        xml::Token::Nil => s("nil"),
    };
}

fn dump(name: &str, d: &mut xml::Decoder, raw: bool) -> string {
    let mut parts: Vec<string> = Vec::new();
    let mut i = 0;
    while i < 200 {
        i += 1;
        let (t, err) = if raw { d.RawToken() } else { d.Token() };
        if t != xml::Token::Nil {
            parts.push(tok(&t));
        }
        if err != errors::nil {
            if err == io::EOF {
                parts.push(s("EOF"));
            } else {
                parts.push(s("err=") + errs(&err));
            }
            break;
        }
    }
    let (line, col) = d.InputPos();
    let mut joined = s("");
    for (j, p) in goish::range!(parts[..]) {
        if j > 0 {
            joined = joined + " ; ";
        }
        joined = joined + p.clone();
    }
    return fmt::Sprintf!(
        "tok %s -> %s | off=%d pos=%d:%d",
        s(name),
        joined,
        d.InputOffset(),
        line,
        col
    );
}

fn q(ss: &slice<string>) -> string {
    let mut out = s("[");
    for (i, x) in goish::range!(ss) {
        if i > 0 {
            out = out + " ";
        }
        out = out + strconv::Quote(x.clone());
    }
    return out + "]";
}

#[goish::reflect]
pub struct Addr {
    #[tag(r#"xml:"city""#)]
    pub City: string,
    #[tag(r#"xml:"zip,attr""#)]
    pub Zip: string,
}

#[goish::reflect]
pub struct Person {
    #[tag(r#"xml:"urn:p person""#)]
    pub XMLName: xml::Name,
    #[tag(r#"xml:"id,attr""#)]
    pub Id: int,
    #[tag(r#"xml:"kind,attr,omitempty""#)]
    pub Kind: string,
    #[tag(r#"xml:"name>first""#)]
    pub First: string,
    #[tag(r#"xml:"name>last""#)]
    pub Last: string,
    #[tag(r#"xml:"age""#)]
    pub Age: int,
    #[tag(r#"xml:"height,omitempty""#)]
    pub Height: float64,
    pub Married: bool,
    #[tag(r#"xml:"email""#)]
    pub Emails: slice<string>,
    #[tag(r#"xml:"home""#)]
    pub Home: Option<Addr>,
    #[tag(r#"xml:",comment""#)]
    pub Note: string,
    #[tag(r#"xml:",chardata""#)]
    pub Text: string,
    #[tag(r#"xml:"-""#)]
    pub Skip: string,
    #[tag(r#"xml:"raw""#)]
    pub Raw: slice<byte>,
}

fn person(p: &Person) -> string {
    let home = match &p.Home {
        None => s("nil"),
        Some(h) => fmt::Sprintf!("{city=%q zip=%q}", h.City, h.Zip),
    };
    return fmt::Sprintf!(
        "xmlname={%s}%s id=%d kind=%q first=%q last=%q age=%d height=%s married=%t emails=%s home=%s note=%q text=%q raw=%q",
        p.XMLName.Space,
        p.XMLName.Local,
        p.Id,
        p.Kind,
        p.First,
        p.Last,
        p.Age,
        strconv::FormatFloat(p.Height, b'g', -1, 64),
        p.Married,
        q(&p.Emails),
        home,
        p.Note,
        p.Text,
        string::from_bytes(&p.Raw)
    );
}

#[goish::reflect]
pub struct Dyn {
    pub XMLName: xml::Name,
    #[tag(r#"xml:"v""#)]
    pub V: int,
}

#[goish::reflect]
pub struct Wrap {
    #[tag(r#"xml:"wrap""#)]
    pub XMLName: xml::Name,
    #[tag(r#"xml:",innerxml""#)]
    pub Inner: string,
    #[tag(r#"xml:"a""#)]
    pub A: string,
}

#[goish::reflect]
pub struct AnyS {
    #[tag(r#"xml:"a""#)]
    pub A: string,
    #[tag(r#"xml:",any""#)]
    pub Other: slice<string>,
    #[tag(r#"xml:",any,attr""#)]
    pub Extra: string,
}

#[goish::reflect]
pub struct CD {
    #[tag(r#"xml:"cd""#)]
    pub XMLName: xml::Name,
    #[tag(r#"xml:",cdata""#)]
    pub Body: string,
}

#[goish::reflect]
pub struct Cmt {
    #[tag(r#"xml:"c""#)]
    pub XMLName: xml::Name,
    #[tag(r#"xml:",comment""#)]
    pub Note: string,
}

#[goish::reflect]
pub struct BadTag {
    #[tag(r#"xml:"a,chardata""#)]
    pub A: string,
}

#[goish::reflect]
pub struct Conflict {
    #[tag(r#"xml:"x""#)]
    pub A: string,
    #[tag(r#"xml:"x""#)]
    pub B: string,
}

#[goish::reflect]
pub struct Chain {
    #[tag(r#"xml:"a>b,attr""#)]
    pub A: string,
}

#[goish::reflect]
pub struct Nums {
    #[tag(r#"xml:"n""#)]
    pub XMLName: xml::Name,
    #[tag(r#"xml:"i8""#)]
    pub I8: i32,
    #[tag(r#"xml:"u16,attr""#)]
    pub U16: u8,
    #[tag(r#"xml:"f32""#)]
    pub F32: float32,
    #[tag(r#"xml:"b""#)]
    pub B: bool,
}

// reflect_only: time.Time has no JSON codec, which the full service layer
// demands of every field; Marshal needs only Reflect.
#[goish::reflect(reflect_only)]
pub struct TS {
    #[tag(r#"xml:"ts""#)]
    pub XMLName: xml::Name,
    #[tag(r#"xml:"at""#)]
    pub At: time::Time,
    #[tag(r#"xml:"t,attr""#)]
    pub AtAttr: time::Time,
}

fn marshal<T: goish::reflect::Reflect + ?Sized>(name: &str, v: &T) -> string {
    let (out, err) = xml::Marshal(v);
    return fmt::Sprintf!("marshal %s -> %q err=%s", s(name), string::from_bytes(&out), errs(&err));
}

fn newBuf() -> Arc<sync::Mutex<bytes::Buffer>> {
    return Arc::new(sync::Mutex::new(bytes::Buffer::default()));
}

fn nm(space: &str, local: &str) -> xml::Name {
    return xml::Name {
        Space: s(space),
        Local: s(local),
    };
}

fn start(space: &str, local: &str) -> xml::StartElement {
    return xml::StartElement {
        Name: nm(space, local),
        Attr: slice::new(),
    };
}

fn end(space: &str, local: &str) -> xml::EndElement {
    return xml::EndElement { Name: nm(space, local) };
}

fn encErr(name: &str, f: fn(&mut xml::Encoder) -> error) -> string {
    let mut e = xml::NewEncoder(newBuf());
    let err = f(&mut e);
    return fmt::Sprintf!("encerr %s -> %s", s(name), errs(&err));
}

const FULL: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE doc [<!ENTITY e \"v\"> <!-- c --> ]>\n<doc xmlns=\"urn:d\" xmlns:p=\"urn:p\" p:a=\"1\" b='2'>\r\n text &amp; &lt;&gt;&quot;&apos; &#65;&#x42; <p:x/><![CDATA[<raw>]]><!-- note --><y xml:lang=\"en\">z</y></doc>";

fn dec(input: &[u8]) -> xml::Decoder {
    return xml::NewDecoder(bytes::NewReader(b(input)));
}

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let f = &mut failed;
    let l = &mut ln;

    // ── tokenizer ─────────────────────────────────────────────────────
    chk(f, l, dump("full", &mut dec(FULL.as_bytes()), false));
    chk(f, l, dump("full-raw", &mut dec(FULL.as_bytes()), true));
    let cases: [(&str, &[u8]); 27] = [
        ("empty", b""),
        ("eof", b"<a><b></b>"),
        ("mismatch", b"<a></b>"),
        ("stray-end", b"</a>"),
        ("entity", b"<a>&foo;</a>"),
        ("entity-nosemi", b"<a>&amp</a>"),
        ("charref-big", b"<a>&#x110000;</a>"),
        ("badchar", b"<a>\x01</a>"),
        ("badutf8", b"<a>\xff</a>"),
        ("comment-dashes", b"<!-- a -- b -->"),
        ("unquoted", b"<a b=c></a>"),
        ("noeq", b"<a b></a>"),
        ("badname", b"<1a/>"),
        ("cdata-end-in-text", b"<a>]]></a>"),
        ("bad-cdata-seq", b"<![CDAX[x]]>"),
        ("cdata-eof", b"<a><![CDATA[abc"),
        ("version", b"<?xml version=\"1.1\"?><a/>"),
        ("encoding", b"<?xml version=\"1.0\" encoding=\"latin1\"?><a/>"),
        ("lt-in-attr", b"<a b=\"<\"/>"),
        ("space-mismatch", b"<x:a></y:a>"),
        ("end-junk", b"<a></a b>"),
        ("two-colons", b"<a:b:c/>"),
        ("crlf", b"<a>1\r\n2\r3</a>"),
        ("line", b"<a>\n\n<b></a>"),
        ("pi-noname", b"<? x?>"),
        ("directive-quoted", b"<!DOCTYPE a '>' \"<\" <![x]>>"),
        (
            "attr-dup-ns",
            b"<a xmlns:p=\"u1\"><p:b xmlns:p=\"u2\" p:c=\"1\"/><p:d/></a>",
        ),
    ];
    for (_, c) in goish::range!(cases) {
        chk(f, l, dump(c.0, &mut dec(c.1), false));
    }
    {
        let mut d = dec(b"<html><p>a&nbsp;b &bogus; c<br>d<img src=x alt>e</p></html>");
        d.Strict = false;
        d.AutoClose = (*xml::HTMLAutoClose).clone();
        d.Entity = (*xml::HTMLEntity).clone();
        chk(f, l, dump("html", &mut d, false));
    }
    {
        let mut d = dec(b"<a><b xmlns=\"urn:x\"/><c/></a>");
        d.DefaultSpace = s("urn:def");
        chk(f, l, dump("defaultspace", &mut d, false));
    }
    {
        let mut d = dec(b"<a><b>1</b><b>2</b></a>");
        let (t1, _) = d.Token();
        let (t2, _) = d.Token();
        let err = d.Skip();
        let (t3, _) = d.Token();
        chk(
            f,
            l,
            fmt::Sprintf!("skip first=%s then=%s skip=%s next=%s", tok(&t1), tok(&t2), errs(&err), tok(&t3)),
        );
    }

    // ── escaping ──────────────────────────────────────────────────────
    {
        let mut buf = bytes::Buffer::default();
        let mut raw: Vec<byte> = "a<b>&\"'\t\n\r\x01\u{FFFD}".as_bytes().to_vec();
        raw.push(0xff);
        let err = xml::EscapeText(&mut buf, slice::__from_vec(raw));
        chk(f, l, fmt::Sprintf!("escape -> %q err=%s", buf.String(), errs(&err)));
    }

    // ── encoder ───────────────────────────────────────────────────────
    {
        let out = newBuf();
        let mut e = xml::NewEncoder(out.clone());
        e.Indent("", "  ");
        let mut seen: Vec<string> = Vec::new();
        seen.push(errs(&e.EncodeToken(xml::ProcInst {
            Target: s("xml"),
            Inst: b(b"version=\"1.0\""),
        })));
        let attr = |sp: &str, lo: &str, v: &str| xml::Attr {
            Name: nm(sp, lo),
            Value: s(v),
        };
        seen.push(errs(&e.EncodeToken(xml::StartElement {
            Name: nm("urn:a", "root"),
            Attr: slice::__from_vec(alloc::vec![
                attr("http://ex.com/ns/", "k", "v"),
                attr("http://a/x", "k1", "1"),
                attr("http://b/x", "k2", "2"),
                attr("http://q/XMLthing", "k3", "3"),
                attr("urn:q", "k4", "4"),
                attr("http://www.w3.org/XML/1998/namespace", "lang", "en"),
                attr("", "plain", "a<&\"'\t\n\r"),
            ]),
        })));
        seen.push(errs(&e.EncodeToken(xml::CharData(b(b"x<y\n")))));
        seen.push(errs(&e.EncodeToken(xml::Comment(b(b" hi ")))));
        seen.push(errs(&e.EncodeToken(start("", "child"))));
        seen.push(errs(&e.EncodeToken(end("", "child"))));
        seen.push(errs(&e.EncodeToken(xml::Directive(b(b"DOCTYPE a [<!-- c --> ]")))));
        seen.push(errs(&e.EncodeToken(end("urn:a", "root"))));
        seen.push(errs(&e.Close()));
        let mut joined = s("");
        for (i, x) in goish::range!(seen[..]) {
            if i > 0 {
                joined = joined + ",";
            }
            joined = joined + x.clone();
        }
        let text = out.Lock().String();
        chk(f, l, fmt::Sprintf!("encode -> %q errs=%s", text, joined));
    }
    chk(f, l, encErr("end-without-start", |e| e.EncodeToken(end("", "a"))));
    chk(f, l, encErr("end-mismatch", |e| {
        let _ = e.EncodeToken(start("", "a"));
        e.EncodeToken(end("", "b"))
    }));
    chk(f, l, encErr("end-ns-mismatch", |e| {
        let _ = e.EncodeToken(start("u1", "a"));
        e.EncodeToken(end("u2", "a"))
    }));
    chk(f, l, encErr("comment-marker", |e| e.EncodeToken(xml::Comment(b(b"a-->b")))));
    chk(f, l, encErr("procinst-late", |e| {
        let _ = e.EncodeToken(start("", "a"));
        e.EncodeToken(xml::ProcInst {
            Target: s("xml"),
            Inst: slice::new(),
        })
    }));
    chk(f, l, encErr("procinst-target", |e| {
        e.EncodeToken(xml::ProcInst {
            Target: s("1x"),
            Inst: slice::new(),
        })
    }));
    chk(f, l, encErr("procinst-marker", |e| {
        e.EncodeToken(xml::ProcInst {
            Target: s("x"),
            Inst: b(b"a?>b"),
        })
    }));
    chk(f, l, encErr("directive", |e| e.EncodeToken(xml::Directive(b(b"a<b")))));
    chk(f, l, encErr("unclosed", |e| {
        let _ = e.EncodeToken(start("", "a"));
        e.Close()
    }));
    chk(f, l, encErr("noname", |e| e.EncodeToken(xml::StartElement::default())));
    chk(f, l, encErr("after-close", |e| {
        let _ = e.Close();
        e.EncodeToken(xml::CharData(b(b"x")))
    }));

    // ── Marshal ───────────────────────────────────────────────────────
    let p = Person {
        Id: 13,
        First: s("John"),
        Last: s("Doe"),
        Age: 42,
        Height: 1.75,
        Married: true,
        Emails: slice::__from_vec(alloc::vec![s("a@x"), s("b@x")]),
        Home: Some(Addr {
            City: s("Hanga Roa"),
            Zip: s("0"),
        }),
        Note: s(" Need more details. "),
        Text: s("t&t"),
        Skip: s("no"),
        Raw: b(b"r<"),
        ..Person::default()
    };
    chk(f, l, marshal("person", &p));
    {
        let (out, err) = xml::MarshalIndent(&p, ">", "  ");
        chk(f, l, fmt::Sprintf!("indent person -> %q err=%s", string::from_bytes(&out), errs(&err)));
    }
    chk(f, l, marshal("person-zero", &Person::default()));
    chk(f, l, marshal("int", &(5 as int)));
    chk(f, l, marshal("string", &s("hi")));
    chk(f, l, marshal("ints", &slice::__from_vec(alloc::vec![1 as int, 2])));
    chk(f, l, marshal("map", &goish::gomap::map::<string, int>::new()));
    chk(f, l, marshal("dyn", &Dyn { XMLName: nm("urn:x", "dyn"), V: 1 }));
    chk(f, l, marshal("dyn-noname", &Dyn { V: 2, ..Dyn::default() }));
    chk(f, l, marshal("cdata", &CD { Body: s("a]]>b"), ..CD::default() }));
    chk(f, l, marshal("comment-dash", &Cmt { Note: s("x-"), ..Cmt::default() }));
    chk(f, l, marshal("comment-dashdash", &Cmt { Note: s("a--b"), ..Cmt::default() }));
    chk(f, l, marshal("badtag", &BadTag::default()));
    chk(f, l, marshal("conflict", &Conflict::default()));
    chk(f, l, marshal("chain-attr", &Chain::default()));
    chk(
        f,
        l,
        marshal(
            "nums",
            &Nums {
                I8: -5,
                U16: 255,
                F32: 0.1,
                B: true,
                ..Nums::default()
            },
        ),
    );
    chk(
        f,
        l,
        marshal(
            "time",
            &TS {
                XMLName: xml::Name::default(),
                At: time::Date(2024, time::January, 2, 3, 4, 5, 500000000, time::UTC),
                AtAttr: time::Date(1999, time::December, 31, 23, 59, 59, 0, time::UTC),
            },
        ),
    );

    // ── Unmarshal ─────────────────────────────────────────────────────
    let unmarshal = |name: &str, input: &[u8], mut v: Person| -> string {
        let err = xml::Unmarshal(b(input), &mut v);
        return fmt::Sprintf!("unmarshal %s -> %s err=%s", s(name), person(&v), errs(&err));
    };
    let (out, _) = xml::Marshal(&p);
    chk(f, l, unmarshal("roundtrip", &out, Person::default()));
    chk(f, l, unmarshal(
        "doc",
        b"<person xmlns=\"urn:p\" id=\" 7 \" kind=\"k\"><name><first>A</first><last>B</last></name><age> 9 </age><Married>1</Married><email>e1</email><!--c1--><email>e2</email>txt<!--c2--><home zip=\"z\"><city>C</city></home><raw></raw><unknown><x/></unknown></person>",
        Person::default(),
    ));
    chk(f, l, unmarshal(
        "merge",
        b"<person xmlns=\"urn:p\"><email>new</email></person>",
        Person {
            Emails: slice::__from_vec(alloc::vec![s("old")]),
            First: s("keep"),
            ..Person::default()
        },
    ));
    chk(f, l, unmarshal("wrong-name", b"<human xmlns=\"urn:p\"/>", Person::default()));
    chk(f, l, unmarshal("no-ns", b"<person/>", Person::default()));
    chk(f, l, unmarshal("bad-int", b"<person xmlns=\"urn:p\"><age>x</age></person>", Person::default()));
    chk(f, l, unmarshal(
        "bad-bool",
        b"<person xmlns=\"urn:p\"><Married>maybe</Married></person>",
        Person::default(),
    ));
    chk(f, l, unmarshal("syntax", b"<person xmlns=\"urn:p\"><age>1</person>", Person::default()));
    chk(f, l, unmarshal(
        "empty-age",
        b"<person xmlns=\"urn:p\"><age/></person>",
        Person { Age: 3, ..Person::default() },
    ));
    {
        let mut w = Wrap::default();
        let err = xml::Unmarshal(b(b"<wrap><a>1</a><b>2&amp;</b></wrap>"), &mut w);
        chk(
            f,
            l,
            fmt::Sprintf!("unmarshal innerxml -> inner=%q a=%q name=%s err=%s", w.Inner, w.A, w.XMLName.Local, errs(&err)),
        );
    }
    {
        let mut a = AnyS::default();
        let err = xml::Unmarshal(b(b"<r x=\"1\" y=\"2\"><a>A</a><b>B</b><c>C</c></r>"), &mut a);
        chk(
            f,
            l,
            fmt::Sprintf!("unmarshal any -> a=%q other=%s extra=%q err=%s", a.A, q(&a.Other), a.Extra, errs(&err)),
        );
    }
    {
        let mut n = Nums::default();
        let err = xml::Unmarshal(b(b"<n u16=\"700\"><i8>-5</i8></n>"), &mut n);
        chk(
            f,
            l,
            fmt::Sprintf!("unmarshal overflow -> i8=%d u16=%d err=%s", n.I8 as int, n.U16 as uint, errs(&err)),
        );
        n = Nums::default();
        let err = xml::Unmarshal(b(b"<n u16=\"7\"><i8>-5</i8><f32> 2.5 </f32><b>true</b></n>"), &mut n);
        chk(
            f,
            l,
            fmt::Sprintf!(
                "unmarshal nums -> i8=%d u16=%d f32=%s b=%t err=%s",
                n.I8 as int,
                n.U16 as uint,
                strconv::FormatFloat(n.F32 as float64, b'g', -1, 32),
                n.B,
                errs(&err)
            ),
        );
    }
    {
        let mut sl: slice<string> = slice::new();
        let err = xml::Unmarshal(b(b"<x>one</x>"), &mut sl);
        chk(f, l, fmt::Sprintf!("unmarshal slice -> %s err=%s", q(&sl), errs(&err)));
        let mut st = s("");
        let err = xml::Unmarshal(b(b"<x>a<y>b</y>c</x>"), &mut st);
        chk(f, l, fmt::Sprintf!("unmarshal string -> %q err=%s", st, errs(&err)));
        let mut c = Conflict::default();
        let err = xml::Unmarshal(b(b"<c/>"), &mut c);
        chk(f, l, fmt::Sprintf!("unmarshal conflict -> err=%s", errs(&err)));
        let mut e = s("");
        let err = xml::Unmarshal(b(b""), &mut e);
        chk(f, l, fmt::Sprintf!("unmarshal empty -> err=%s", errs(&err)));
    }

    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
