// json_indent_html_escape_smoke — exercise json.Indent + json.HTMLEscape.
// (encoding/json/indent.go:16, 120)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::encoding::json;
use goish::fmt;
use goish::goslice::slice;
use goish::syscall;
use goish::types::{byte, int};

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

fn equal_bytes(a: slice<byte>, b: slice<byte>) -> bool {
    let aa: &[byte] = &a;
    let bb: &[byte] = &b;
    aa == bb
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Indent — empty array.
    {
        let (out, err) = json::Indent(empty_buf(), to_bytes("[]"), "", "  ");
        if err.IsNil() && equal_bytes(out, to_bytes("[]")) {
            fmt::Println!("[ 1] Indent empty arr          PASS");
        } else {
            fmt::Println!("[ 1] Indent empty arr          FAIL");
            failed += 1;
        }
    }

    // 2. Indent — flat array.
    {
        let (out, err) = json::Indent(empty_buf(), to_bytes("[1,2,3]"), "", "  ");
        let expect = to_bytes("[\n  1,\n  2,\n  3\n]");
        if err.IsNil() && equal_bytes(out, expect) {
            fmt::Println!("[ 2] Indent flat arr           PASS");
        } else {
            fmt::Println!("[ 2] Indent flat arr           FAIL");
            failed += 1;
        }
    }

    // 3. Indent — empty object.
    {
        let (out, err) = json::Indent(empty_buf(), to_bytes("{}"), "", "  ");
        if err.IsNil() && equal_bytes(out, to_bytes("{}")) {
            fmt::Println!("[ 3] Indent empty obj          PASS");
        } else {
            fmt::Println!("[ 3] Indent empty obj          FAIL");
            failed += 1;
        }
    }

    // 4. Indent — nested object/array.
    {
        let (out, err) = json::Indent(empty_buf(), to_bytes("{\"a\":[1,2]}"), "", "  ");
        let expect = to_bytes("{\n  \"a\": [\n    1,\n    2\n  ]\n}");
        if err.IsNil() && equal_bytes(out, expect) {
            fmt::Println!("[ 4] Indent nested             PASS");
        } else {
            fmt::Println!("[ 4] Indent nested             FAIL");
            failed += 1;
        }
    }

    // 5. Indent — preserves dst prefix bytes.
    {
        let dst = to_bytes("PRE:");
        let (out, err) = json::Indent(dst, to_bytes("[1]"), "", "  ");
        let expect = to_bytes("PRE:[\n  1\n]");
        if err.IsNil() && equal_bytes(out, expect) {
            fmt::Println!("[ 5] Indent dst prefix         PASS");
        } else {
            fmt::Println!("[ 5] Indent dst prefix         FAIL");
            failed += 1;
        }
    }

    // 6. Indent — invalid JSON returns error.
    {
        let (_, err) = json::Indent(empty_buf(), to_bytes("not-json"), "", "  ");
        if !err.IsNil() {
            fmt::Println!("[ 6] Indent invalid            PASS");
        } else {
            fmt::Println!("[ 6] Indent invalid            FAIL");
            failed += 1;
        }
    }

    // 7. Indent — custom prefix.
    {
        let (out, err) = json::Indent(empty_buf(), to_bytes("[1,2]"), ">>", "..");
        let expect = to_bytes("[\n>>..1,\n>>..2\n>>]");
        if err.IsNil() && equal_bytes(out, expect) {
            fmt::Println!("[ 7] Indent prefix             PASS");
        } else {
            fmt::Println!("[ 7] Indent prefix             FAIL");
            failed += 1;
        }
    }

    // 8. HTMLEscape — escapes <, >, &.
    {
        let out = json::HTMLEscape(empty_buf(), to_bytes("<a&b>"));
        let expect = to_bytes("\\u003ca\\u0026b\\u003e");
        if equal_bytes(out, expect) {
            fmt::Println!("[ 8] HTMLEscape angle/amp      PASS");
        } else {
            fmt::Println!("[ 8] HTMLEscape angle/amp      FAIL");
            failed += 1;
        }
    }

    // 9. HTMLEscape — empty input is empty output.
    {
        let out = json::HTMLEscape(empty_buf(), to_bytes(""));
        if equal_bytes(out, to_bytes("")) {
            fmt::Println!("[ 9] HTMLEscape empty          PASS");
        } else {
            fmt::Println!("[ 9] HTMLEscape empty          FAIL");
            failed += 1;
        }
    }

    // 10. HTMLEscape — preserves benign bytes.
    {
        let out = json::HTMLEscape(empty_buf(), to_bytes("hello world 123"));
        if equal_bytes(out, to_bytes("hello world 123")) {
            fmt::Println!("[10] HTMLEscape benign         PASS");
        } else {
            fmt::Println!("[10] HTMLEscape benign         FAIL");
            failed += 1;
        }
    }

    // 11. HTMLEscape — preserves dst prefix bytes.
    {
        let dst = to_bytes("KEEP:");
        let out = json::HTMLEscape(dst, to_bytes("<x>"));
        let expect = to_bytes("KEEP:\\u003cx\\u003e");
        if equal_bytes(out, expect) {
            fmt::Println!("[11] HTMLEscape dst prefix     PASS");
        } else {
            fmt::Println!("[11] HTMLEscape dst prefix     FAIL");
            failed += 1;
        }
    }

    // 12. HTMLEscape — U+2028 (E2 80 A8) →  .
    {
        // Build raw bytes [0xE2, 0x80, 0xA8] explicitly.
        let mut v: Vec<byte> = Vec::new();
        v.push(0xE2);
        v.push(0x80);
        v.push(0xA8);
        let raw = slice::<byte>::__from_vec(v);
        let out = json::HTMLEscape(empty_buf(), raw);
        let expect = to_bytes("\\u2028");
        if equal_bytes(out, expect) {
            fmt::Println!("[12] HTMLEscape U+2028         PASS");
        } else {
            fmt::Println!("[12] HTMLEscape U+2028         FAIL");
            failed += 1;
        }
    }

    // 13. HTMLEscape — U+2029 (E2 80 A9) →  .
    {
        let mut v: Vec<byte> = Vec::new();
        v.push(0xE2);
        v.push(0x80);
        v.push(0xA9);
        let raw = slice::<byte>::__from_vec(v);
        let out = json::HTMLEscape(empty_buf(), raw);
        let expect = to_bytes("\\u2029");
        if equal_bytes(out, expect) {
            fmt::Println!("[13] HTMLEscape U+2029         PASS");
        } else {
            fmt::Println!("[13] HTMLEscape U+2029         FAIL");
            failed += 1;
        }
    }

    let total: int = 13;
    if failed == 0 {
        fmt::Println!("ok 13/13");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of", total);
        syscall::Exit(1);
    }
}
