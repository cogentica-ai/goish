// encoding/xml: the parse stack, name-space scoping, and translate.
//
// Fifth slice. Go holds this as a linked list of `stack` nodes with a
// `free` list of recycled ones; goish holds a Vec, so `next` is index
// order and `free` has no counterpart. That is a data-structure change
// in the middle of a parser, which is exactly the kind of substitution
// that looks equivalent and is not — hence a row for every operation
// and a dump of the WHOLE stack after each one, bottom-first, plus the
// ns map sorted.
//
// All 19 scripts came from Go 1.25.5 driving its real Decoder inside a
// writable GOROOT copy (`scripts/goref.sh encoding/xml`); the stack
// ops are unexported and mutate the decoder wholesale, so there is no
// other way to see them. Committed as
// examples/testdata/xml_stack_ref.txt.
//
// The script letters: e=pushElement, n=pushNs (trailing ! means the
// prefix had NO previous binding), p=popElement, F=pushEOF, f=popEOF,
// t=translate.
//
// WHAT THE ROWS ARE REALLY FOR:
//
//   * pushEOF does not push. The marker goes BELOW the innermost open
//     element and below the stkNs entries belonging to it, so that
//     closing the element pops down TO the marker instead of past it.
//     Rows 9-11 are the ones that see it, and a plain push passes
//     everything else.
//   * popElement undoes name-space bindings by walking down to the
//     next Start or EOF, restoring each saved binding or DELETING it
//     when `ok` was false. Row 8 is the delete case — get it wrong and
//     a prefix leaks out of its element's scope.
//   * translate's four early returns are each load-bearing: `xmlns` is
//     declaration syntax rather than a reference; an unprefixed
//     ATTRIBUTE is in no namespace even when its element is; the `xml`
//     prefix is hardwired whether or not it was declared.
//   * non-Strict popElement does not merely tolerate a mismatch — it
//     REWRITES the end element's name to the open element's. Row 2.
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

fn srow(idx: int, ops: &[&str], strict: bool, def: &'static str, want: &'static str) {
    let got = xml::xml::__stack_script(ops, strict, def);
    let ok = got == string::from_bytes(want.as_bytes());
    unsafe {
        if ok {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL case %v strict=%v def=%s\n     got  %s\n     want %s\n",
                idx,
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
    srow(0, &["ea", "pa"], true, "", "e:[S(|a|false)] p:true [] {} err=<nil>");
    srow(1, &["ea", "pb"], true, "", "e:[S(|a|false)] p:false [] {} err=XML syntax error on line 1: element <a> closed by </b>");
    srow(2, &["ea", "pb"], false, "", "e:[S(|a|false)] p:true [] {} err=<nil>");
    srow(3, &["pa"], true, "", "p:false [] {} err=XML syntax error on line 1: unexpected end element </a>");
    srow(4, &["ea", "eb", "pb", "pa"], true, "", "e:[S(|a|false)] e:[S(|b|false) S(|a|false)] p:true [S(|a|false)] {} err=<nil> p:true [] {} err=<nil>");
    srow(5, &["nx=http://x", "ea", "pa"], true, "", "n:[N(http://x|x|true)]{x=http://x} e:[S(|a|false) N(http://x|x|true)] p:true [] {x=http://x} err=<nil>");
    srow(6, &["ea", "nx=http://x", "pa"], true, "", "e:[S(|a|false)] n:[N(http://x|x|true) S(|a|false)]{x=http://x} p:false [S(|a|false)] {x=http://x} err=XML syntax error on line 1: unexpected end element </a>");
    srow(7, &["ea", "nx=http://x", "nx=http://y", "pa"], true, "", "e:[S(|a|false)] n:[N(http://x|x|true) S(|a|false)]{x=http://x} n:[N(http://y|x|true) N(http://x|x|true) S(|a|false)]{x=http://y} p:false [N(http://x|x|true) S(|a|false)] {x=http://y} err=XML syntax error on line 1: unexpected end element </a>");
    srow(8, &["nx=old!", "ea", "pa"], true, "", "n:[N(old|x|false)]{} e:[S(|a|false) N(old|x|false)] p:true [] {} err=<nil>");
    srow(9, &["ea", "F", "pa", "f", "f"], true, "", "e:[S(|a|false)] F:[S(|a|false) E(||false)] p:true [E(||false)] {} err=<nil> f:true [] f:false []");
    srow(10, &["ea", "nx=http://x", "F", "pa", "f"], true, "", "e:[S(|a|false)] n:[N(http://x|x|true) S(|a|false)]{x=http://x} F:[N(http://x|x|true) S(|a|false) E(||false)] p:false [S(|a|false) E(||false)] {x=http://x} err=XML syntax error on line 1: unexpected end element </a> f:false [S(|a|false) E(||false)]");
    srow(11, &["ea", "eb", "F", "pb", "f", "pa"], true, "", "e:[S(|a|false)] e:[S(|b|false) S(|a|false)] F:[S(|b|false) E(||false) S(|a|false)] p:true [E(||false) S(|a|false)] {} err=<nil> f:true [S(|a|false)] p:true [] {} err=<nil>");
    srow(12, &["tx|a|1"], true, "", "t:x|a");
    srow(13, &["nx=http://x", "tx|a|1"], true, "", "n:[N(http://x|x|true)]{x=http://x} t:http://x|a");
    srow(14, &["t|a|1"], true, "http://def", "t:http://def|a");
    srow(15, &["t|a|0"], true, "http://def", "t:|a");
    srow(16, &["txml|a|1"], true, "", "t:http://www.w3.org/XML/1998/namespace|a");
    srow(17, &["txmlns|a|1"], true, "", "t:xmlns|a");
    srow(18, &["t|xmlns|1"], true, "http://def", "t:|xmlns");

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 19 {
            fmt::Printf!("FAIL ran %v rows, expected 19\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("xml_stack_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
