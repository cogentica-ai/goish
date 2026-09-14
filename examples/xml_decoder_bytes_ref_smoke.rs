// encoding/xml: the Decoder's byte layer, pinned against Go.
//
// Third slice of the port. The Decoder state machine only becomes
// testable bottom-up, and this is the bottom: the reader, the one-byte
// pushback, and the offset/line/column bookkeeping that every error
// message and every `InputPos` call is built on.
//
// The rows are SCRIPTS — "g" getc, "u" ungetc the last byte, "s" space
// — run over an input, reporting (byte, ok) and offset:line:column
// after each step. Scripting the internals is the only way to see this
// layer at all; `Token` does not exist yet, and when it does it will
// not expose the intermediate states where the bugs live.
//
// All of it came from Go 1.25.5 via `scripts/goref.sh encoding/xml`,
// running the same script through the real Decoder inside a writable
// GOROOT copy. Committed as examples/testdata/xml_bytes_ref.txt.
//
// THE ROW TO READ IS `u@1:1:0` — column ZERO, which no input position
// can be. `ungetc` decrements `offset` and `line` but does NOT restore
// `linestart`, so immediately after ungetting a newline the arithmetic
// gives `offset - linestart + 1` = 0. That is Go's behaviour. It is
// pinned here rather than smoothed over, because a port that "fixed"
// it would diverge from Go on every error message that reports a
// column after a pushback.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use goish::encoding::xml;
use goish::fmt;
use goish::gostring::string;
use goish::types::{byte, int};

static mut PASS: int = 0;
static mut FAIL: int = 0;

fn brow(name: &'static str, input: &[byte], script: &'static str, want: &'static str) {
    let got = xml::xml::__byte_script(input, script);
    let ok = got == string::from_bytes(want.as_bytes());
    unsafe {
        if ok {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %s [%s]\n     got  %s\n     want %s\n",
                name,
                script,
                got.clone(),
                want
            );
        }
    }
}

#[goish::main]
fn main() {
    brow("abc", &[0x61, 0x62, 0x63], "ggg", "g(97,true)@1:1:2 g(98,true)@2:1:3 g(99,true)@3:1:4");
    brow("abc", &[0x61, 0x62, 0x63], "gggg", "g(97,true)@1:1:2 g(98,true)@2:1:3 g(99,true)@3:1:4 g(0,false)@3:1:4");
    brow("", &[], "g", "g(0,false)@0:1:1");
    brow("a\\nb", &[0x61, 0x0a, 0x62], "gggg", "g(97,true)@1:1:2 g(10,true)@2:2:1 g(98,true)@3:2:2 g(0,false)@3:2:2");
    brow("a\\nb", &[0x61, 0x0a, 0x62], "ggug", "g(97,true)@1:1:2 g(10,true)@2:2:1 u@1:1:0 g(10,true)@2:2:1");
    brow("\\n\\n\\n", &[0x0a, 0x0a, 0x0a], "ggg", "g(10,true)@1:2:1 g(10,true)@2:3:1 g(10,true)@3:4:1");
    brow("a\\nbc", &[0x61, 0x0a, 0x62, 0x63], "ggugg", "g(97,true)@1:1:2 g(10,true)@2:2:1 u@1:1:0 g(10,true)@2:2:1 g(98,true)@3:2:2");
    brow("ab", &[0x61, 0x62], "gugu", "g(97,true)@1:1:2 u@0:1:1 g(97,true)@1:1:2 u@0:1:1");
    brow("a", &[0x61], "gug", "g(97,true)@1:1:2 u@0:1:1 g(97,true)@1:1:2");
    brow("  \\t\\n x", &[0x20, 0x20, 0x09, 0x0a, 0x20, 0x78], "s", "s@5:2:2");
    brow("   ", &[0x20, 0x20, 0x20], "s", "s@3:1:4");
    brow("x", &[0x78], "s", "s@0:1:1");
    brow("\\n\\n  y", &[0x0a, 0x0a, 0x20, 0x20, 0x79], "sg", "s@4:3:3 g(121,true)@5:3:4");
    brow("a  b", &[0x61, 0x20, 0x20, 0x62], "gsg", "g(97,true)@1:1:2 s@3:1:4 g(98,true)@4:1:5");
    brow("a\\r\\nb", &[0x61, 0x0d, 0x0a, 0x62], "gggg", "g(97,true)@1:1:2 g(13,true)@2:1:3 g(10,true)@3:2:1 g(98,true)@4:2:2");

    // A fresh Decoder: offset 0, line 1, column 1. Go's NewDecoder
    // seeds line=1, so the first byte of the input is at 1:1 — an
    // off-by-one here would shift every error message in the package.
    {
        let got = xml::xml::__byte_script(b"x", "");
        unsafe {
            if got == string::from_static("") {
                PASS += 1;
            } else {
                FAIL += 1;
                fmt::Printf!("FAIL empty script produced output: %s\n", got);
            }
        }
        // and one getc off a fresh decoder lands at 1:2
        brow("fresh", b"x", "g", "g(120,true)@1:1:2");
    }

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 17 {
            fmt::Printf!("FAIL ran %v checks, expected 17\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!(
            "xml_decoder_bytes_ref_smoke: %v checks, %v failed\n",
            pass + fail,
            fail
        );
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
