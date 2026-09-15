// encoding/xml: Decoder.Token — name-space resolution and matching.
//
// Seventh slice, and this COMPLETES xml.go's Decoder. `Token` is the
// layer over `rawToken`: it matches start and end elements, resolves
// name-space prefixes to URLs, and — outside Strict mode — invents end
// tags for AutoClose elements.
//
// 17 documents from Go 1.25.5 (`scripts/goref.sh encoding/xml`), same
// dump format both sides.
//
// WHAT THE DOCUMENTS ARE FOR. Name-space scoping is the part where a
// plausible implementation differs from Go in ways only a nested
// document reveals:
//
//   * a prefix declared on an element is IN SCOPE FOR THAT ELEMENT —
//     `<a xmlns:x="http://x" x:c="1"/>` resolves its own attribute. Go
//     processes the xmlns attributes before translating anything, and
//     the order is the reason.
//   * the default name space applies to ELEMENT names only. Row 8,
//     with DefaultSpace set, has `a` in the default space and its
//     attribute `b` in none.
//   * an inner `xmlns` SHADOWS an outer one and the outer must come
//     back when the inner element closes — row 9 has `<b>` in
//     http://e between two elements in http://d.
//   * `xml:lang` resolves to the hardwired XML URL without any
//     declaration.
//   * a prefix goes out of scope at its element's end tag: row 10
//     uses `x:` after `</a>` and must fail to resolve.
//
// And the AutoClose rows are worth reading for the ORDER they produce:
// `<p>one<p>two` yields S(p) E(p) C(one) S(p) E(p) C(two), because
// autoClose stashes the token the caller was about to get and returns
// the invented end tag first.
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

fn trow(
    idx: int,
    name: &'static str,
    doc: &[u8],
    strict: bool,
    def: &'static str,
    ac: &[&str],
    want: &'static str,
) {
    let got = xml::xml::__tok_script(doc, strict, def, ac);
    let ok = got == string::from_bytes(want.as_bytes());
    unsafe {
        if ok {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %v %s strict=%v def=%s\n     got  %s\n     want %s\n",
                idx,
                name,
                strict,
                def,
                got.clone(),
                want
            );
        }
    }
}

#[goish::main]
fn main() {
    trow(0, "<a/>", &[0x3c, 0x61, 0x2f, 0x3e], true, "", &[], "S(|a)[] E(|a) err=EOF");
    trow(1, "<a></a>", &[0x3c, 0x61, 0x3e, 0x3c, 0x2f, 0x61, 0x3e], true, "", &[], "S(|a)[] E(|a) err=EOF");
    trow(2, "<a></b>", &[0x3c, 0x61, 0x3e, 0x3c, 0x2f, 0x62, 0x3e], true, "", &[], "S(|a)[] err=XML syntax error on line 1: element <a> closed by </b>");
    trow(3, "<a>", &[0x3c, 0x61, 0x3e], true, "", &[], "S(|a)[] err=XML syntax error on line 1: unexpected EOF");
    trow(4, "</a>", &[0x3c, 0x2f, 0x61, 0x3e], true, "", &[], "err=XML syntax error on line 1: unexpected end element </a>");
    trow(5, "<a xmlns=<U+0022>http://d<U+0022>><b/></a>", &[0x3c, 0x61, 0x20, 0x78, 0x6d, 0x6c, 0x6e, 0x73, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x64, 0x22, 0x3e, 0x3c, 0x62, 0x2f, 0x3e, 0x3c, 0x2f, 0x61, 0x3e], true, "", &[], "S(http://d|a)[|xmlns=http://d] S(http://d|b)[] E(http://d|b) E(http://d|a) err=EOF");
    trow(6, "<a xmlns:x=<U+0022>http://x<U+0022>><x:b x:c=<U+0022>1<U+0022>/></a>", &[0x3c, 0x61, 0x20, 0x78, 0x6d, 0x6c, 0x6e, 0x73, 0x3a, 0x78, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x78, 0x22, 0x3e, 0x3c, 0x78, 0x3a, 0x62, 0x20, 0x78, 0x3a, 0x63, 0x3d, 0x22, 0x31, 0x22, 0x2f, 0x3e, 0x3c, 0x2f, 0x61, 0x3e], true, "", &[], "S(|a)[xmlns|x=http://x] S(http://x|b)[http://x|c=1] E(http://x|b) E(|a) err=EOF");
    trow(7, "<a xmlns:x=<U+0022>http://x<U+0022> x:c=<U+0022>1<U+0022>/>", &[0x3c, 0x61, 0x20, 0x78, 0x6d, 0x6c, 0x6e, 0x73, 0x3a, 0x78, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x78, 0x22, 0x20, 0x78, 0x3a, 0x63, 0x3d, 0x22, 0x31, 0x22, 0x2f, 0x3e], true, "", &[], "S(|a)[xmlns|x=http://x,http://x|c=1] E(|a) err=EOF");
    trow(8, "<a b=<U+0022>1<U+0022>/>", &[0x3c, 0x61, 0x20, 0x62, 0x3d, 0x22, 0x31, 0x22, 0x2f, 0x3e], true, "http://def", &[], "S(http://def|a)[|b=1] E(http://def|a) err=EOF");
    trow(9, "<a xmlns=<U+0022>http://d<U+0022>><b xmlns=<U+0022>http://e<U+0022>/><c/></a>", &[0x3c, 0x61, 0x20, 0x78, 0x6d, 0x6c, 0x6e, 0x73, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x64, 0x22, 0x3e, 0x3c, 0x62, 0x20, 0x78, 0x6d, 0x6c, 0x6e, 0x73, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x65, 0x22, 0x2f, 0x3e, 0x3c, 0x63, 0x2f, 0x3e, 0x3c, 0x2f, 0x61, 0x3e], true, "", &[], "S(http://d|a)[|xmlns=http://d] S(http://e|b)[|xmlns=http://e] E(http://e|b) S(http://d|c)[] E(http://d|c) E(http://d|a) err=EOF");
    trow(10, "<a xmlns:x=<U+0022>http://x<U+0022>><x:b/></a><x:c/>", &[0x3c, 0x61, 0x20, 0x78, 0x6d, 0x6c, 0x6e, 0x73, 0x3a, 0x78, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x78, 0x22, 0x3e, 0x3c, 0x78, 0x3a, 0x62, 0x2f, 0x3e, 0x3c, 0x2f, 0x61, 0x3e, 0x3c, 0x78, 0x3a, 0x63, 0x2f, 0x3e], true, "", &[], "S(|a)[xmlns|x=http://x] S(http://x|b)[] E(http://x|b) E(|a) S(x|c)[] E(x|c) err=EOF");
    trow(11, "<a xml:lang=<U+0022>en<U+0022>/>", &[0x3c, 0x61, 0x20, 0x78, 0x6d, 0x6c, 0x3a, 0x6c, 0x61, 0x6e, 0x67, 0x3d, 0x22, 0x65, 0x6e, 0x22, 0x2f, 0x3e], true, "", &[], "S(|a)[http://www.w3.org/XML/1998/namespace|lang=en] E(|a) err=EOF");
    trow(12, "<a xmlns:x=<U+0022>http://x<U+0022>><b><x:c/></b></a>", &[0x3c, 0x61, 0x20, 0x78, 0x6d, 0x6c, 0x6e, 0x73, 0x3a, 0x78, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x78, 0x22, 0x3e, 0x3c, 0x62, 0x3e, 0x3c, 0x78, 0x3a, 0x63, 0x2f, 0x3e, 0x3c, 0x2f, 0x62, 0x3e, 0x3c, 0x2f, 0x61, 0x3e], true, "", &[], "S(|a)[xmlns|x=http://x] S(|b)[] S(http://x|c)[] E(http://x|c) E(|b) E(|a) err=EOF");
    trow(13, "<p>one<p>two", &[0x3c, 0x70, 0x3e, 0x6f, 0x6e, 0x65, 0x3c, 0x70, 0x3e, 0x74, 0x77, 0x6f], false, "", &["p"], "S(|p)[] E(|p) C(6f6e65) S(|p)[] E(|p) C(74776f) err=EOF");
    trow(14, "<p>one</p>", &[0x3c, 0x70, 0x3e, 0x6f, 0x6e, 0x65, 0x3c, 0x2f, 0x70, 0x3e], false, "", &["p"], "S(|p)[] E(|p) C(6f6e65) err=XML syntax error on line 1: unexpected end element </p>");
    trow(15, "<a><b></a>", &[0x3c, 0x61, 0x3e, 0x3c, 0x62, 0x3e, 0x3c, 0x2f, 0x61, 0x3e], false, "", &[], "S(|a)[] S(|b)[] E(|b) E(|a) err=EOF");
    trow(16, "<a>x</a>trailing", &[0x3c, 0x61, 0x3e, 0x78, 0x3c, 0x2f, 0x61, 0x3e, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x69, 0x6e, 0x67], true, "", &[], "S(|a)[] C(78) E(|a) C(747261696c696e67) err=EOF");

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 17 {
            fmt::Printf!("FAIL ran %v rows, expected 17\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("xml_token_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
