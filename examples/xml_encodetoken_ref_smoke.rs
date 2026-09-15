// encoding/xml: Encoder.EncodeToken — the token printer.
//
// The mirror of `Decoder.Token`: tokens in, well-formed XML out. It
// matches start and end tags, invents `xmlns:` prefixes for attribute
// name spaces, escapes attribute values and character data, and lays
// the result out according to `Indent`.
//
// 47 cases from Go 1.25.5 (`scripts/goref.sh encoding/xml`). Both the
// expected output AND the input token streams come from the Go
// generator's own dump — the tokens are hex in the source below
// because that is what the generator printed, which is also why a row
// carrying a `\r` or a `<` needs no quoting decisions on this side.
//
// WHAT THE CASES ARE FOR. The prefix allocator in `createAttrPrefix`
// is the part where a plausible implementation drifts from Go:
//
//   * the prefix is the LAST PATH ELEMENT of the name-space URL, after
//     a trailing `/` is trimmed — "http://x/foo" and "http://x/foo/"
//     both give `foo`.
//   * it falls back to `_` when that element is empty, is not a valid
//     XML name, or contains a colon.
//   * anything case-insensitively starting "xml" is RESERVED, so
//     `xmlfoo` and `XMLfoo` both become `_xmlfoo` / `_XMLfoo`.
//   * the XML name space itself is hardwired to the `xml` prefix and
//     never declared.
//   * two different URLs whose last element agrees collide, and the
//     second gets `foo_1` from the sequence counter.
//   * a prefix goes out of scope with the element that declared it —
//     the `attr-ns-scoped` row reuses `foo` for a different URL in a
//     sibling element.
//
// And `isValidDirective` is a small state machine with three states:
// a quote swallows `<` and `>`, a `<!--` comment swallows them too and
// only a real `-->` closes it, and an unterminated quote or comment is
// an error even though the brackets balanced.
//
// The indent rows are the other half: `writeIndent` does NOTHING when
// neither prefix nor indent is set, which is why unindented output has
// no newlines at all, and `indentedIn` is what stops `<c></c>` from
// getting a newline between the tags.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::encoding::xml;
use goish::fmt;
use goish::gostring::string;
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
fn HS(h: &str) -> string {
    return string::from_bytes(&unhex(h));
}

// go: none
fn HB(h: &str) -> goish::slice<goish::byte> {
    return goish::slice::__from_vec(unhex(h));
}

// go: none
fn NM(space: &str, local: &str) -> xml::Name {
    return xml::Name {
        Space: HS(space),
        Local: HS(local),
    };
}

// go: none
fn erow(
    idx: int,
    name: &'static str,
    prefix: string,
    indent: string,
    toks: &[xml::Token],
    close: bool,
    want: &'static str,
) {
    let buf = Arc::new(sync::Mutex::new(goish::bytes::Buffer::new()));
    let mut enc = xml::NewEncoder(buf.clone());
    enc.Indent(prefix, indent);
    let mut errs = string::from_static("");
    let mut i: int = 0;
    for t in toks.iter() {
        let err = enc.EncodeToken(t.clone());
        if err != goish::errors::nil {
            errs = fmt::Sprintf!("tok%v:%s", i, err.Error());
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
    if close && errs.Len() == 0 {
        let err = enc.Close();
        if err != goish::errors::nil {
            errs = string::from_static("close:") + err.Error();
        } else if name == "closed-then-write" {
            let err = enc.EncodeToken(xml::Token::StartElement(xml::StartElement {
                Name: NM("", "7a"),
                Attr: goish::slice!([]xml::Attr{}),
            }));
            if err != goish::errors::nil {
                errs = string::from_static("afterclose:") + err.Error();
            }
        }
    }
    let got = goish::encoding::hex::EncodeToString(&buf.Lock().Bytes())
        + string::from_static("|")
        + errs;
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
    erow(
        0,
        "plain",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c613e3c2f613e|",
    );
    erow(
        1,
        "nested",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "62"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "62") }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c613e3c623e3c2f623e3c2f613e|",
    );
    erow(
        2,
        "chardata",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::CharData(xml::CharData(HB("783c79267a"))),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c613e78266c743b7926616d703b7a3c2f613e|",
    );
    erow(
        3,
        "chardata-nl",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::CharData(xml::CharData(HB("780a790d097a"))),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c613e780a79262378443b262378393b7a3c2f613e|",
    );
    erow(
        4,
        "elem-space",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("687474703a2f2f64", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("687474703a2f2f64", "61") })
        ],
        false,
        "3c6120786d6c6e733d22687474703a2f2f64223e3c2f613e|",
    );
    erow(
        5,
        "attr-plain",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("", "6b"), Value: HS("763c22") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c61206b3d2276266c743b262333343b223e3c2f613e|",
    );
    erow(
        6,
        "attr-empty-name",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("", ""), Value: HS("76") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c613e3c2f613e|",
    );
    erow(
        7,
        "attr-ns",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("687474703a2f2f782f666f6f", "6b"), Value: HS("76") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c6120786d6c6e733a666f6f3d22687474703a2f2f782f666f6f2220666f6f3a6b3d2276223e3c2f613e|",
    );
    erow(
        8,
        "attr-ns-xml",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("687474703a2f2f7777772e77332e6f72672f584d4c2f313939382f6e616d657370616365", "6c616e67"), Value: HS("656e") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c6120786d6c3a6c616e673d22656e223e3c2f613e|",
    );
    erow(
        9,
        "attr-ns-trailing-slash",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("687474703a2f2f782f666f6f2f", "6b"), Value: HS("76") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c6120786d6c6e733a666f6f3d22687474703a2f2f782f666f6f2f2220666f6f3a6b3d2276223e3c2f613e|",
    );
    erow(
        10,
        "attr-ns-bad-name",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("687474703a2f2f782f31666f6f", "6b"), Value: HS("76") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c6120786d6c6e733a5f3d22687474703a2f2f782f31666f6f22205f3a6b3d2276223e3c2f613e|",
    );
    erow(
        11,
        "attr-ns-colon",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("687474703a2f2f782f663a6f6f", "6b"), Value: HS("76") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c6120786d6c6e733a5f3d22687474703a2f2f782f663a6f6f22205f3a6b3d2276223e3c2f613e|",
    );
    erow(
        12,
        "attr-ns-xmlish",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("687474703a2f2f782f786d6c666f6f", "6b"), Value: HS("76") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c6120786d6c6e733a5f786d6c666f6f3d22687474703a2f2f782f786d6c666f6f22205f786d6c666f6f3a6b3d2276223e3c2f613e|",
    );
    erow(
        13,
        "attr-ns-XMLish",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("687474703a2f2f782f584d4c666f6f", "6b"), Value: HS("76") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c6120786d6c6e733a5f584d4c666f6f3d22687474703a2f2f782f584d4c666f6f22205f584d4c666f6f3a6b3d2276223e3c2f613e|",
    );
    erow(
        14,
        "attr-ns-noslash",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("666f6f", "6b"), Value: HS("76") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c6120786d6c6e733a666f6f3d22666f6f2220666f6f3a6b3d2276223e3c2f613e|",
    );
    erow(
        15,
        "attr-ns-empty",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("2f", "6b"), Value: HS("76") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c6120786d6c6e733a5f3d222f22205f3a6b3d2276223e3c2f613e|",
    );
    erow(
        16,
        "attr-ns-two-same-tail",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("687474703a2f2f782f666f6f", "6b"), Value: HS("31") }, xml::Attr { Name: NM("687474703a2f2f792f666f6f", "6a"), Value: HS("32") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c6120786d6c6e733a666f6f3d22687474703a2f2f782f666f6f2220666f6f3a6b3d22312220786d6c6e733a666f6f5f313d22687474703a2f2f792f666f6f2220666f6f5f313a6a3d2232223e3c2f613e|",
    );
    erow(
        17,
        "attr-ns-reuse",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("687474703a2f2f782f666f6f", "6b"), Value: HS("31") }, xml::Attr { Name: NM("687474703a2f2f782f666f6f", "6a"), Value: HS("32") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c6120786d6c6e733a666f6f3d22687474703a2f2f782f666f6f2220666f6f3a6b3d22312220666f6f3a6a3d2232223e3c2f613e|",
    );
    erow(
        18,
        "attr-ns-scoped",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "62"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("687474703a2f2f782f666f6f", "6b"), Value: HS("31") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "62") }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "63"), Attr: goish::slice!([]xml::Attr{xml::Attr { Name: NM("687474703a2f2f792f666f6f", "6a"), Value: HS("32") }}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "63") }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c613e3c6220786d6c6e733a666f6f3d22687474703a2f2f782f666f6f2220666f6f3a6b3d2231223e3c2f623e3c6320786d6c6e733a666f6f3d22687474703a2f2f792f666f6f2220666f6f3a6a3d2232223e3c2f633e3c2f613e|",
    );
    erow(
        19,
        "comment",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::Comment(xml::Comment(HB("6869"))),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c613e3c212d2d68692d2d3e3c2f613e|",
    );
    erow(
        20,
        "comment-bad",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::Comment(xml::Comment(HB("612d2d3e62"))),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "|tok1:xml: EncodeToken of Comment containing --> marker",
    );
    erow(
        21,
        "procinst-xml-first",
        HS(""),
        HS(""),
        &[
            xml::Token::ProcInst(xml::ProcInst { Target: HS("786d6c"), Inst: HB("76657273696f6e3d22312e3022") }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c3f786d6c2076657273696f6e3d22312e30223f3e3c613e3c2f613e|",
    );
    erow(
        22,
        "procinst-xml-late",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::ProcInst(xml::ProcInst { Target: HS("786d6c"), Inst: HB("78") }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "|tok1:xml: EncodeToken of ProcInst xml target only valid for xml declaration, first token encoded",
    );
    erow(
        23,
        "procinst-other",
        HS(""),
        HS(""),
        &[
            xml::Token::ProcInst(xml::ProcInst { Target: HS("706870"), Inst: HB("6563686f") }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c3f706870206563686f3f3e3c613e3c2f613e|",
    );
    erow(
        24,
        "procinst-no-inst",
        HS(""),
        HS(""),
        &[
            xml::Token::ProcInst(xml::ProcInst { Target: HS("706870"), Inst: HB("") }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c3f7068703f3e3c613e3c2f613e|",
    );
    erow(
        25,
        "procinst-bad-target",
        HS(""),
        HS(""),
        &[
            xml::Token::ProcInst(xml::ProcInst { Target: HS("3178"), Inst: HB("79") }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "|tok0:xml: EncodeToken of ProcInst with invalid Target",
    );
    erow(
        26,
        "procinst-bad-inst",
        HS(""),
        HS(""),
        &[
            xml::Token::ProcInst(xml::ProcInst { Target: HS("706870"), Inst: HB("613f3e62") }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "|tok0:xml: EncodeToken of ProcInst containing ?> marker",
    );
    erow(
        27,
        "directive",
        HS(""),
        HS(""),
        &[
            xml::Token::Directive(xml::Directive(HB("444f43545950452061"))),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c21444f435459504520613e3c613e3c2f613e|",
    );
    erow(
        28,
        "directive-nested",
        HS(""),
        HS(""),
        &[
            xml::Token::Directive(xml::Directive(HB("444f43545950452061205b3c21454c454d454e5420613e5d"))),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c21444f43545950452061205b3c21454c454d454e5420613e5d3e3c613e3c2f613e|",
    );
    erow(
        29,
        "directive-unmatched-gt",
        HS(""),
        HS(""),
        &[
            xml::Token::Directive(xml::Directive(HB("613e62"))),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "|tok0:xml: EncodeToken of Directive containing wrong < or > markers",
    );
    erow(
        30,
        "directive-unmatched-lt",
        HS(""),
        HS(""),
        &[
            xml::Token::Directive(xml::Directive(HB("613c62"))),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "|tok0:xml: EncodeToken of Directive containing wrong < or > markers",
    );
    erow(
        31,
        "directive-quote",
        HS(""),
        HS(""),
        &[
            xml::Token::Directive(xml::Directive(HB("6120223c3e222062"))),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c216120223c3e2220623e3c613e3c2f613e|",
    );
    erow(
        32,
        "directive-apos",
        HS(""),
        HS(""),
        &[
            xml::Token::Directive(xml::Directive(HB("6120273c3e272062"))),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c216120273c3e2720623e3c613e3c2f613e|",
    );
    erow(
        33,
        "directive-comment",
        HS(""),
        HS(""),
        &[
            xml::Token::Directive(xml::Directive(HB("61203c212d2d203c203e202d2d3e2062"))),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c2161203c212d2d203c203e202d2d3e20623e3c613e3c2f613e|",
    );
    erow(
        34,
        "directive-open-comment",
        HS(""),
        HS(""),
        &[
            xml::Token::Directive(xml::Directive(HB("61203c212d2d203c203e2062"))),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "|tok0:xml: EncodeToken of Directive containing wrong < or > markers",
    );
    erow(
        35,
        "directive-open-quote",
        HS(""),
        HS(""),
        &[
            xml::Token::Directive(xml::Directive(HB("61202278"))),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "|tok0:xml: EncodeToken of Directive containing wrong < or > markers",
    );
    erow(
        36,
        "start-no-name",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", ""), Attr: goish::slice!([]xml::Attr{}) })
        ],
        false,
        "|tok0:xml: start tag with no name",
    );
    erow(
        37,
        "end-no-name",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "") })
        ],
        false,
        "|tok1:xml: end tag with no name",
    );
    erow(
        38,
        "end-no-start",
        HS(""),
        HS(""),
        &[
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "|tok0:xml: end tag </a> without start tag",
    );
    erow(
        39,
        "end-mismatch-local",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "62") })
        ],
        false,
        "|tok1:xml: end tag </b> does not match start tag <a>",
    );
    erow(
        40,
        "end-mismatch-space",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("687474703a2f2f64", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("687474703a2f2f65", "61") })
        ],
        false,
        "|tok1:xml: end tag </a> in namespace http://e does not match start tag <a> in namespace http://d",
    );
    erow(
        41,
        "unclosed",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) })
        ],
        true,
        "3c613e|close:unclosed tag <a>",
    );
    erow(
        42,
        "closed-then-write",
        HS(""),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        true,
        "3c613e3c2f613e|afterclose:use of closed Encoder",
    );
    erow(
        43,
        "indent",
        HS(""),
        HS("2020"),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "62"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::CharData(xml::CharData(HB("78"))),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "62") }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "63"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "63") }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c613e0a20203c623e783c2f623e0a20203c633e3c2f633e0a3c2f613e|",
    );
    erow(
        44,
        "indent-prefix",
        HS("7c"),
        HS("2e2e"),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "62"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "62") }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "7c3c613e0a7c2e2e3c623e3c2f623e0a7c3c2f613e|",
    );
    erow(
        45,
        "prefix-only",
        HS("3e"),
        HS(""),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "62"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "62") }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3e3c613e0a3e3c623e3c2f623e0a3e3c2f613e|",
    );
    erow(
        46,
        "indent-deep",
        HS(""),
        HS("20"),
        &[
            xml::Token::StartElement(xml::StartElement { Name: NM("", "61"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "62"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::StartElement(xml::StartElement { Name: NM("", "63"), Attr: goish::slice!([]xml::Attr{}) }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "63") }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "62") }),
            xml::Token::EndElement(xml::EndElement { Name: NM("", "61") })
        ],
        false,
        "3c613e0a203c623e0a20203c633e3c2f633e0a203c2f623e0a3c2f613e|",
    );
    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 47 {
            fmt::Printf!("FAIL ran %v rows, expected 47\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("xml_encodetoken_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
