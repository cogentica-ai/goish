// json_escape_ref_smoke — json.Marshal's string escaping vs Go.
// (encoding/json/encode.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_jsonesc_ref.go` run in `package
// json_test` by `scripts/goref.sh`.
//
// goish's encoding/json is 1885 lines carrying ONE provenance anchor,
// so none of this had been diffed. Its string encoder escaped the seven
// characters JSON itself requires and nothing else, which left three
// silent problems:
//
//   * `<`, `>` and `&` went through RAW. Go escapes them as \u003c,
//     \u003e and \u0026 for one documented reason — "so that the JSON
//     will be safe to embed inside HTML <script> tags". A marshalled
//     string containing "</script>" CLOSED the enclosing script block.
//     goish already had a correctly-ported HTMLEscape; Marshal simply
//     never called it.
//   * U+2028 and U+2029 went through raw. They are valid JSON and are
//     LINE TERMINATORS in JavaScript, so a string carrying one changes
//     how the surrounding script parses.
//   * Invalid UTF-8 went through raw, producing output that is not
//     valid JSON and that a conformant parser rejects. Go replaces each
//     bad byte with U+FFFD and succeeds.
//
// The first two are why this file exists: an encoder that is correct
// for every ASCII string in a test suite can still hand an attacker the
// end of your script tag.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::encoding::json;
use goish::gostring::string;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn eq(failed: &mut int, got: string, want: &str, what: &str) {
    if got == s(want) {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %s want %s\n", s(what), got, s(want));
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The escaping table, verbatim from Go.
    {
        let cases: [(&str, &str); 16] = [
            ("plain", "\"plain\""),
            ("", "\"\""),
            ("a\"b", "\"a\\\"b\""),
            ("a\\b", "\"a\\\\b\""),
            ("a\nb", "\"a\\nb\""),
            ("a\tb", "\"a\\tb\""),
            ("a\rb", "\"a\\rb\""),
            ("a\u{8}b", "\"a\\bb\""),
            ("a\u{c}b", "\"a\\fb\""),
            ("\u{0}", "\"\\u0000\""),
            ("\u{1f}", "\"\\u001f\""),
            // DEL is NOT escaped — it is above the control range Go
            // escapes and is not one of the three HTML characters.
            ("\u{7f}", "\"\u{7f}\""),
            ("héllo", "\"héllo\""),
            ("日本語", "\"日本語\""),
            ("\u{1F600}", "\"\u{1F600}\""),
            // '/' is NOT escaped, though many encoders do.
            ("a/b", "\"a/b\""),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, want) = cases[i];
            let (b, e) = json::Marshal(&s(inp));
            if !e.IsNil() {
                fmt::Printf!("[!!] Marshal(%q) err %q\n", s(inp), e.Error());
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    string::from_bytes(&b.clone().__into_vec()),
                    want,
                    inp,
                );
            }
            i += 1;
        }
        fmt::Println!("[  1 ] the escaping table");
    }

    // 2. The HTML three. This is the security-relevant half: without it
    //    a string value can close the script tag it is embedded in.
    {
        let cases: [(&str, &str); 4] = [
            ("<script>", "\"\\u003cscript\\u003e\""),
            ("a&b", "\"a\\u0026b\""),
            ("a>b", "\"a\\u003eb\""),
            ("a<b", "\"a\\u003cb\""),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, want) = cases[i];
            let (b, _) = json::Marshal(&s(inp));
            eq(
                &mut failed,
                string::from_bytes(&b.clone().__into_vec()),
                want,
                inp,
            );
            i += 1;
        }
        // The case that motivates it: a closing tag inside a value must
        // not survive into the output intact.
        let (b, _) = json::Marshal(&s("</script><script>alert(1)</script>"));
        let got = string::from_bytes(&b.clone().__into_vec());
        if goish::strings::Contains(got.clone(), "</script>") {
            fmt::Printf!(
                "[!!] a marshalled value still closes the script tag: %s\n",
                got
            );
            failed += 1;
        }
        fmt::Println!("[  2 ] <, > and & are escaped");
    }

    // 3. U+2028 and U+2029 — valid JSON, JavaScript line terminators.
    {
        let (b1, _) = json::Marshal(&s("\u{2028}"));
        eq(
            &mut failed,
            string::from_bytes(&b1.clone().__into_vec()),
            "\"\\u2028\"",
            "U+2028",
        );
        let (b2, _) = json::Marshal(&s("\u{2029}"));
        eq(
            &mut failed,
            string::from_bytes(&b2.clone().__into_vec()),
            "\"\\u2029\"",
            "U+2029",
        );
        // A neighbouring non-ASCII character is NOT escaped, so the
        // check is on those two code points and not on "anything wide".
        let (b3, _) = json::Marshal(&s("\u{a0}"));
        eq(
            &mut failed,
            string::from_bytes(&b3.clone().__into_vec()),
            "\"\u{a0}\"",
            "U+00A0",
        );
        fmt::Println!("[  3 ] U+2028 and U+2029 are escaped");
    }

    // 4. Invalid UTF-8 becomes U+FFFD and Marshal SUCCEEDS. Go:
    //    badutf8 -> "f\ufffdo" err=<nil>.
    {
        let bad = string::from_bytes(&[0x66, 0xff, 0x6f]);
        let (b, e) = json::Marshal(&bad);
        if !e.IsNil() {
            fmt::Printf!("[!!] Marshal of invalid UTF-8 errored: %q\n", e.Error());
            failed += 1;
        }
        eq(
            &mut failed,
            string::from_bytes(&b.clone().__into_vec()),
            "\"f\\ufffdo\"",
            "invalid UTF-8",
        );
        fmt::Println!("[  4 ] invalid UTF-8 becomes U+FFFD");
    }

    // 5. The DECODE side of the same question: an unpaired surrogate.
    //
    //    Go's unquoteBytes never fails on one. An unpaired surrogate
    //    becomes U+FFFD and the lookahead is NOT consumed, so whatever
    //    follows is read as itself — "\uD800\u0041" is U+FFFD then 'A'.
    //    goish used to require the pair and reject the string, so a
    //    document carrying one lone surrogate — and real-world JSON
    //    does — was rejected whole where Go accepts it.
    {
        let cases: [(&str, &[u8]); 10] = [
            ("\"\\uD800\"", &[239, 191, 189]),
            ("\"\\uDC00\"", &[239, 191, 189]),
            ("\"\\uD800\\uD800\"", &[239, 191, 189, 239, 191, 189]),
            ("\"\\uD83D\\uDE00\"", &[240, 159, 152, 128]),
            ("\"a\\uD800b\"", &[97, 239, 191, 189, 98]),
            ("\"\\uD800x\"", &[239, 191, 189, 120]),
            ("\"\\u0041\"", &[65]),
            ("\"\\u00e9\"", &[195, 169]),
            ("\"\\uDC00\\uD800\"", &[239, 191, 189, 239, 191, 189]),
            ("\"\\uD800\\u0041\"", &[239, 191, 189, 65]),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, want) = cases[i];
            let mut v = json::Value::default();
            let e = json::Unmarshal(inp.as_bytes(), &mut v);
            if !e.IsNil() {
                fmt::Printf!("[!!] Unmarshal(%s) err %q\n", s(inp), e.Error());
                failed += 1;
            } else {
                match v.AsString() {
                    None => {
                        fmt::Printf!("[!!] Unmarshal(%s) is not a string\n", s(inp));
                        failed += 1;
                    }
                    Some(got) => {
                        if got.as_bytes() != want {
                            fmt::Printf!("[!!] Unmarshal(%s) wrong bytes\n", s(inp));
                            failed += 1;
                        }
                    }
                }
            }
            i += 1;
        }
        fmt::Println!("[  5 ] an unpaired surrogate decodes to U+FFFD");
    }

    if failed == 0 {
        fmt::Println!("ok - json string escaping matches Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
