// html_ref_smoke — html.EscapeString/UnescapeString against Go.
// (html/escape.go, html/entity.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_html_ref.go` run in `package html_test`
// by `scripts/goref.sh`.
//
// src/html carried ZERO provenance anchors for all three of its
// functions. Diffing found the escape direction — the one that matters
// for XSS — already correct, and the unescape direction shipping five
// named entities where Go has 2231.
//
// EscapeString escapes exactly FIVE characters and uses the NUMERIC
// forms for quote and apostrophe: &#34; and &#39;, not &quot; and
// &apos;. That distinction is not cosmetic — &apos; is not in the
// HTML4 entity set, so an old parser renders it literally.
//
// UnescapeString is far more permissive, and its oddities are real
// browser behaviour rather than sloppiness:
//
//   * A reference does NOT need its semicolon: "&amp" decodes.
//   * Which is why "&notreal;" decodes to "\u{ac}real;" — `&not` is an
//     entity, it matches the longest valid prefix, and the rest is left
//     as text. That single vector is what proves the prefix walk is
//     there rather than a plain table hit.
//   * The names are case sensitive PER ENTRY: "&AMP;" and "&amp;" are
//     both in the table, "&Amp;" is not.
//   * An out-of-range or zero numeric reference becomes U+FFFD rather
//     than failing.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::html;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn eq(failed: &mut int, got: string, want: &str, what: &str) {
    if got == s(want) {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %q want %q\n", s(what), got, s(want));
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. EscapeString: exactly five characters, numeric quote forms.
    {
        let cases: [(&str, &str); 18] = [
            ("", ""),
            ("plain", "plain"),
            ("<", "&lt;"),
            (">", "&gt;"),
            ("&", "&amp;"),
            ("'", "&#39;"),
            ("\"", "&#34;"),
            (
                "<script>alert('x')</script>",
                "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;",
            ),
            ("a & b", "a &amp; b"),
            ("a &amp; b", "a &amp;amp; b"),
            ("<>&'\"", "&lt;&gt;&amp;&#39;&#34;"),
            ("héllo", "héllo"),
            ("日本語", "日本語"),
            ("a\nb", "a\nb"),
            ("a\tb", "a\tb"),
            ("&lt;", "&amp;lt;"),
            ("&&", "&amp;&amp;"),
            ("<<>>", "&lt;&lt;&gt;&gt;"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, want) = cases[i];
            eq(&mut failed, html::EscapeString(s(inp)), want, inp);
            i += 1;
        }
        fmt::Println!("[  1 ] EscapeString escapes exactly five characters");
    }

    // 2. UnescapeString over the full HTML5 table.
    {
        let cases: [(&str, &str); 28] = [
            ("", ""),
            ("plain", "plain"),
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&amp;", "&"),
            ("&#39;", "'"),
            ("&#34;", "\""),
            ("&quot;", "\""),
            ("&apos;", "'"),
            ("&nbsp;", "\u{a0}"),
            ("&copy;", "©"),
            ("&#65;", "A"),
            ("&#x41;", "A"),
            ("&#X41;", "A"),
            ("&lt", "<"),
            ("&amp", "&"),
            ("&notreal;", "¬real;"),
            ("&", "&"),
            ("&;", "&;"),
            ("&#;", "&#;"),
            ("&#xZZ;", "&#xZZ;"),
            ("a&lt;b&gt;c", "a<b>c"),
            ("&amp;lt;", "&lt;"),
            ("&#0;", "�"),
            ("&#x110000;", "�"),
            ("&#128512;", "😀"),
            ("&AMP;", "&"),
            ("&Amp;", "&Amp;"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, want) = cases[i];
            eq(&mut failed, html::UnescapeString(s(inp)), want, inp);
            i += 1;
        }
        fmt::Println!("[  2 ] UnescapeString knows the whole table");
    }

    // 3. Escape then unescape is the identity — which is the property
    //    anything round-tripping user text through HTML depends on.
    {
        eq(
            &mut failed,
            html::UnescapeString(html::EscapeString(s("<>&'\""))),
            "<>&'\"",
            "round <>&'\\",
        );
        eq(
            &mut failed,
            html::UnescapeString(html::EscapeString(s("a & b"))),
            "a & b",
            "round a & b",
        );
        eq(
            &mut failed,
            html::UnescapeString(html::EscapeString(s("<script>"))),
            "<script>",
            "round <script>",
        );
        fmt::Println!("[  3 ] escape then unescape is the identity");
    }

    if failed == 0 {
        fmt::Println!("ok - html escaping matches Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
