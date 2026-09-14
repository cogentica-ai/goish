// encoding/xml: Decoder.rawToken — whole documents in, tokens out.
//
// Sixth slice, and the last of xml.go's Decoder. rawToken is Go's
// ~300-line switch over `<`-prefixed input: end elements, processing
// instructions, comments, CDATA, directives, and start elements with
// their attributes. Plus nsname, name, attrval and RawToken.
//
// FIRST PIECE OF THIS PORT TESTABLE END TO END. The four slices before
// it had to script internals — getc/ungetc, text(quote, cdata), the
// stack ops — because nothing turned bytes into an observable result.
// Here a document goes in and a token stream comes out, so the rows are
// just documents. All 31 came from Go 1.25.5 (`scripts/goref.sh
// encoding/xml`), dumped in the same format on both sides, with token
// bodies as HEX so a difference in an invisible byte still reads as a
// diff.
//
// The documents are chosen per branch, including the ones that are
// easy to get wrong:
//
//   * `<a/>` must yield TWO tokens — Go returns the StartElement, sets
//     needClose, and hands back the EndElement on the next call.
//   * `<!--a--b-->` is an ERROR: "--" is not allowed inside a comment,
//     and the check fires on the byte AFTER the second dash.
//   * a directive tracks quote state and nesting depth, so
//     `<!DOCTYPE a "quoted > here">` does not end at the quoted `>`.
//   * a comment INSIDE a directive is replaced by a single space, so
//     that markup either side of it is not joined on re-encoding.
//   * `<a b/>` is an error under Strict and an attribute whose value is
//     its own name when not.
//   * `<a>]]></a>` is an error — `]]>` is only legal in CDATA or a
//     quoted string.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use goish::encoding::xml;
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

static mut PASS: int = 0;
static mut FAIL: int = 0;

fn rrow(idx: int, name: &'static str, doc: &[u8], strict: bool, want: &'static str) {
    let got = xml::xml::__raw_script(doc, strict);
    let ok = got == string::from_bytes(want.as_bytes());
    unsafe {
        if ok {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %v %s strict=%v\n     got  %s\n     want %s\n",
                idx,
                name,
                strict,
                got.clone(),
                want
            );
        }
    }
}

#[goish::main]
fn main() {
    rrow(0, "<a/>", &[0x3c, 0x61, 0x2f, 0x3e], true, "S(|a)[] E(|a) err=EOF");
    rrow(1, "<a></a>", &[0x3c, 0x61, 0x3e, 0x3c, 0x2f, 0x61, 0x3e], true, "S(|a)[] E(|a) err=EOF");
    rrow(2, "<a>hi</a>", &[0x3c, 0x61, 0x3e, 0x68, 0x69, 0x3c, 0x2f, 0x61, 0x3e], true, "S(|a)[] C(6869) E(|a) err=EOF");
    rrow(3, "<a b=<U+0022>c<U+0022>/>", &[0x3c, 0x61, 0x20, 0x62, 0x3d, 0x22, 0x63, 0x22, 0x2f, 0x3e], true, "S(|a)[|b=c] E(|a) err=EOF");
    rrow(4, "<a b=<U+0022>c<U+0022> d='e'/>", &[0x3c, 0x61, 0x20, 0x62, 0x3d, 0x22, 0x63, 0x22, 0x20, 0x64, 0x3d, 0x27, 0x65, 0x27, 0x2f, 0x3e], true, "S(|a)[|b=c,|d=e] E(|a) err=EOF");
    rrow(5, "<a xmlns:x=<U+0022>http://x<U+0022>><x:b/></a>", &[0x3c, 0x61, 0x20, 0x78, 0x6d, 0x6c, 0x6e, 0x73, 0x3a, 0x78, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x78, 0x22, 0x3e, 0x3c, 0x78, 0x3a, 0x62, 0x2f, 0x3e, 0x3c, 0x2f, 0x61, 0x3e], true, "S(|a)[xmlns|x=http://x] S(x|b)[] E(x|b) E(|a) err=EOF");
    rrow(6, "<a>&lt;&amp;</a>", &[0x3c, 0x61, 0x3e, 0x26, 0x6c, 0x74, 0x3b, 0x26, 0x61, 0x6d, 0x70, 0x3b, 0x3c, 0x2f, 0x61, 0x3e], true, "S(|a)[] C(3c26) E(|a) err=EOF");
    rrow(7, "<!--c-->", &[0x3c, 0x21, 0x2d, 0x2d, 0x63, 0x2d, 0x2d, 0x3e], true, "M(63) err=EOF");
    rrow(8, "<!---->", &[0x3c, 0x21, 0x2d, 0x2d, 0x2d, 0x2d, 0x3e], true, "M() err=EOF");
    rrow(9, "<!--a--b-->", &[0x3c, 0x21, 0x2d, 0x2d, 0x61, 0x2d, 0x2d, 0x62, 0x2d, 0x2d, 0x3e], true, "err=XML syntax error on line 1: invalid sequence \"--\" not allowed in comments");
    rrow(10, "<?xml version=<U+0022>1.0<U+0022>?><a/>", &[0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3f, 0x3e, 0x3c, 0x61, 0x2f, 0x3e], true, "P(xml|76657273696f6e3d22312e3022) S(|a)[] E(|a) err=EOF");
    rrow(11, "<?php echo ?><a/>", &[0x3c, 0x3f, 0x70, 0x68, 0x70, 0x20, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x3f, 0x3e, 0x3c, 0x61, 0x2f, 0x3e], true, "P(php|6563686f20) S(|a)[] E(|a) err=EOF");
    rrow(12, "<![CDATA[x<y]]>", &[0x3c, 0x21, 0x5b, 0x43, 0x44, 0x41, 0x54, 0x41, 0x5b, 0x78, 0x3c, 0x79, 0x5d, 0x5d, 0x3e], true, "C(783c79) err=EOF");
    rrow(13, "<![CDATA[]]>", &[0x3c, 0x21, 0x5b, 0x43, 0x44, 0x41, 0x54, 0x41, 0x5b, 0x5d, 0x5d, 0x3e], true, "C() err=EOF");
    rrow(14, "<!DOCTYPE a>", &[0x3c, 0x21, 0x44, 0x4f, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x61, 0x3e], true, "D(444f43545950452061) err=EOF");
    rrow(15, "<!DOCTYPE a [<!ENTITY b <U+0022>c<U+0022>>]>", &[0x3c, 0x21, 0x44, 0x4f, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x61, 0x20, 0x5b, 0x3c, 0x21, 0x45, 0x4e, 0x54, 0x49, 0x54, 0x59, 0x20, 0x62, 0x20, 0x22, 0x63, 0x22, 0x3e, 0x5d, 0x3e], true, "D(444f43545950452061205b3c21454e544954592062202263223e5d) err=EOF");
    rrow(16, "<!DOCTYPE a [<!-- c -->]>", &[0x3c, 0x21, 0x44, 0x4f, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x61, 0x20, 0x5b, 0x3c, 0x21, 0x2d, 0x2d, 0x20, 0x63, 0x20, 0x2d, 0x2d, 0x3e, 0x5d, 0x3e], true, "D(444f43545950452061205b205d) err=EOF");
    rrow(17, "<!DOCTYPE a <U+0022>quoted > here<U+0022>>", &[0x3c, 0x21, 0x44, 0x4f, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x61, 0x20, 0x22, 0x71, 0x75, 0x6f, 0x74, 0x65, 0x64, 0x20, 0x3e, 0x20, 0x68, 0x65, 0x72, 0x65, 0x22, 0x3e], true, "D(444f43545950452061202271756f746564203e206865726522) err=EOF");
    rrow(18, "<a/><b/>", &[0x3c, 0x61, 0x2f, 0x3e, 0x3c, 0x62, 0x2f, 0x3e], true, "S(|a)[] E(|a) S(|b)[] E(|b) err=EOF");
    rrow(19, " <a/> ", &[0x20, 0x3c, 0x61, 0x2f, 0x3e, 0x20], true, "C(20) S(|a)[] E(|a) C(20) err=EOF");
    rrow(20, "<a", &[0x3c, 0x61], true, "err=XML syntax error on line 1: unexpected EOF");
    rrow(21, "</", &[0x3c, 0x2f], true, "err=XML syntax error on line 1: unexpected EOF");
    rrow(22, "<a b/>", &[0x3c, 0x61, 0x20, 0x62, 0x2f, 0x3e], true, "err=XML syntax error on line 1: attribute name without = in element");
    rrow(23, "<a b/>", &[0x3c, 0x61, 0x20, 0x62, 0x2f, 0x3e], false, "S(|a)[|b=b] E(|a) err=EOF");
    rrow(24, "<a b=c/>", &[0x3c, 0x61, 0x20, 0x62, 0x3d, 0x63, 0x2f, 0x3e], true, "err=XML syntax error on line 1: unquoted or missing attribute value in element");
    rrow(25, "<!-", &[0x3c, 0x21, 0x2d], true, "err=XML syntax error on line 1: unexpected EOF");
    rrow(26, "<![x", &[0x3c, 0x21, 0x5b, 0x78], true, "err=XML syntax error on line 1: invalid <![ sequence");
    rrow(27, "<a></b>", &[0x3c, 0x61, 0x3e, 0x3c, 0x2f, 0x62, 0x3e], true, "S(|a)[] E(|b) err=EOF");
    rrow(28, "<?xml version=<U+0022>9.9<U+0022>?>", &[0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x39, 0x2e, 0x39, 0x22, 0x3f, 0x3e], true, "err=xml: unsupported version \"9.9\"; only version 1.0 is supported");
    rrow(29, "<?xml encoding=<U+0022>EBCDIC<U+0022>?>", &[0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3d, 0x22, 0x45, 0x42, 0x43, 0x44, 0x49, 0x43, 0x22, 0x3f, 0x3e], true, "err=xml: encoding \"EBCDIC\" declared but Decoder.CharsetReader is nil");
    rrow(30, "<a>]]></a>", &[0x3c, 0x61, 0x3e, 0x5d, 0x5d, 0x3e, 0x3c, 0x2f, 0x61, 0x3e], true, "S(|a)[] err=XML syntax error on line 1: unescaped ]]> not in CDATA section");

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 31 {
            fmt::Printf!("FAIL ran %v rows, expected 31\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("xml_rawtoken_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
