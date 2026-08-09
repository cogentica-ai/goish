// strconv_unquote_char_smoke — exercise UnquoteChar, QuotedPrefix,
// QuoteToGraphic family, and the upgraded Unquote (which now handles
// `\u`, `\U`, octal, single-quote literals, and backquoted strings).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::strconv;
use goish::types::{byte, rune};
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. UnquoteChar — plain ASCII byte ('a'), no escape.
    {
        let (v, mb, tail, err) = strconv::UnquoteChar(string("abc"), b'"');
        if err.IsNil() && v == b'a' as rune && !mb && tail == "bc" {
            fmt::Println!("[ 1] UnquoteChar plain         PASS");
        } else {
            fmt::Println!("[ 1] UnquoteChar plain         FAIL");
            failed += 1;
        }
    }

    // 2. UnquoteChar — \n escape.
    {
        let (v, mb, tail, err) = strconv::UnquoteChar(string("\\nrest"), b'"');
        if err.IsNil() && v == 0x0A && !mb && tail == "rest" {
            fmt::Println!("[ 2] UnquoteChar \\n            PASS");
        } else {
            fmt::Println!("[ 2] UnquoteChar \\n            FAIL");
            failed += 1;
        }
    }

    // 3. UnquoteChar — \xHH hex.
    {
        let (v, mb, tail, err) = strconv::UnquoteChar(string("\\xFFtail"), b'"');
        if err.IsNil() && v == 0xFF && !mb && tail == "tail" {
            fmt::Println!("[ 3] UnquoteChar \\xHH          PASS");
        } else {
            fmt::Println!("[ 3] UnquoteChar \\xHH          FAIL");
            failed += 1;
        }
    }

    // 4. UnquoteChar — Ǵ (Unicode 4-hex).
    {
        let (v, mb, tail, err) = strconv::UnquoteChar(string("\\u00e9z"), b'"');
        if err.IsNil() && v == 0xE9 && mb && tail == "z" {
            fmt::Println!("[ 4] UnquoteChar \\uXXXX         PASS");
        } else {
            fmt::Println!("[ 4] UnquoteChar \\uXXXX         FAIL");
            failed += 1;
        }
    }

    // 5. UnquoteChar — \U00010348 (Unicode 8-hex, multibyte).
    {
        let (v, mb, _tail, err) = strconv::UnquoteChar(string("\\U00010348"), b'"');
        if err.IsNil() && v == 0x10348 && mb {
            fmt::Println!("[ 5] UnquoteChar \\UXXXXXXXX     PASS");
        } else {
            fmt::Println!("[ 5] UnquoteChar \\UXXXXXXXX     FAIL");
            failed += 1;
        }
    }

    // 6. UnquoteChar — octal \101 → 'A'.
    {
        let (v, mb, tail, err) = strconv::UnquoteChar(string("\\101bc"), b'"');
        if err.IsNil() && v == 0x41 && !mb && tail == "bc" {
            fmt::Println!("[ 6] UnquoteChar octal         PASS");
        } else {
            fmt::Println!("[ 6] UnquoteChar octal         FAIL");
            failed += 1;
        }
    }

    // 7. UnquoteChar — \\ and \' (single-quote literal).
    {
        let (v1, _, _, e1) = strconv::UnquoteChar(string("\\\\"), b'"');
        let (v2, _, _, e2) = strconv::UnquoteChar(string("\\'"), b'\'');
        if e1.IsNil() && v1 == b'\\' as rune && e2.IsNil() && v2 == b'\'' as rune {
            fmt::Println!("[ 7] UnquoteChar \\\\ + \\'       PASS");
        } else {
            fmt::Println!("[ 7] UnquoteChar \\\\ + \\'       FAIL");
            failed += 1;
        }
    }

    // 8. UnquoteChar — error: bare backslash at end.
    {
        let (_, _, _, err) = strconv::UnquoteChar(string("\\"), b'"');
        // Error: ErrSyntax (incomplete escape).
        if !err.IsNil() {
            fmt::Println!("[ 8] UnquoteChar trailing\\     PASS");
        } else {
            fmt::Println!("[ 8] UnquoteChar trailing\\     FAIL");
            failed += 1;
        }
    }

    // 9. UnquoteChar — error: unescaped quote-byte.
    {
        let (_, _, _, err) = strconv::UnquoteChar(string("\"abc"), b'"');
        if !err.IsNil() {
            fmt::Println!("[ 9] UnquoteChar bare quote    PASS");
        } else {
            fmt::Println!("[ 9] UnquoteChar bare quote    FAIL");
            failed += 1;
        }
    }

    // 10. UnquoteChar — multibyte UTF-8 passes through.
    {
        // 'é' = 0xC3 0xA9 → rune 0xE9
        let (v, mb, _tail, err) = strconv::UnquoteChar(string("\u{00e9}rest"), b'"');
        if err.IsNil() && v == 0xE9 && mb {
            fmt::Println!("[10] UnquoteChar UTF-8         PASS");
        } else {
            fmt::Println!("[10] UnquoteChar UTF-8         FAIL");
            failed += 1;
        }
    }

    // 11. Unquote — single-quote rune literal '\n' → "\n".
    {
        let (s, err) = strconv::Unquote(string("'\\n'"));
        if err.IsNil() && s == "\n" {
            fmt::Println!("[11] Unquote rune literal      PASS");
        } else {
            fmt::Println!("[11] Unquote rune literal      FAIL");
            failed += 1;
        }
    }

    // 12. Unquote — backquoted raw string `abc`.
    {
        let (s, err) = strconv::Unquote(string("`abc`"));
        if err.IsNil() && s == "abc" {
            fmt::Println!("[12] Unquote backquote         PASS");
        } else {
            fmt::Println!("[12] Unquote backquote         FAIL");
            failed += 1;
        }
    }

    // 13. Unquote — backquoted raw string strips \r.
    {
        let (s, err) = strconv::Unquote(string("`a\rb`"));
        if err.IsNil() && s == "ab" {
            fmt::Println!("[13] Unquote bq strip CR       PASS");
        } else {
            fmt::Println!("[13] Unquote bq strip CR       FAIL");
            failed += 1;
        }
    }

    // 14. Unquote — \u escape inside double-quoted string.
    {
        let (s, err) = strconv::Unquote(string("\"x\\u00e9y\""));
        if err.IsNil() && s == "x\u{00e9}y" {
            fmt::Println!("[14] Unquote \\u inside \"      PASS");
        } else {
            fmt::Println!("[14] Unquote \\u inside \"      FAIL");
            failed += 1;
        }
    }

    // 15. Unquote — error: unterminated.
    {
        let (_, err) = strconv::Unquote(string("\"abc"));
        if !err.IsNil() {
            fmt::Println!("[15] Unquote unterminated      PASS");
        } else {
            fmt::Println!("[15] Unquote unterminated      FAIL");
            failed += 1;
        }
    }

    // 16. Unquote — error: trailing garbage after close quote.
    {
        let (_, err) = strconv::Unquote(string("\"abc\"x"));
        if !err.IsNil() {
            fmt::Println!("[16] Unquote trailing junk     PASS");
        } else {
            fmt::Println!("[16] Unquote trailing junk     FAIL");
            failed += 1;
        }
    }

    // 17. QuotedPrefix — strips one quoted token, returns it raw.
    {
        let (out, err) = strconv::QuotedPrefix(string("\"hi\"rest"));
        if err.IsNil() && out == "\"hi\"" {
            fmt::Println!("[17] QuotedPrefix              PASS");
        } else {
            fmt::Println!("[17] QuotedPrefix              FAIL");
            failed += 1;
        }
    }

    // 18. QuotedPrefix — backquoted token followed by other text.
    {
        let (out, err) = strconv::QuotedPrefix(string("`hello`world"));
        if err.IsNil() && out == "`hello`" {
            fmt::Println!("[18] QuotedPrefix backquote    PASS");
        } else {
            fmt::Println!("[18] QuotedPrefix backquote    FAIL");
            failed += 1;
        }
    }

    // 19. QuotedPrefix — error on no quote.
    {
        let (_, err) = strconv::QuotedPrefix(string("nope"));
        if !err.IsNil() {
            fmt::Println!("[19] QuotedPrefix no quote     PASS");
        } else {
            fmt::Println!("[19] QuotedPrefix no quote     FAIL");
            failed += 1;
        }
    }

    // 20. QuoteToGraphic — alias of Quote in slim build.
    {
        let q = strconv::QuoteToGraphic(string("hi"));
        if q == "\"hi\"" {
            fmt::Println!("[20] QuoteToGraphic            PASS");
        } else {
            fmt::Println!("[20] QuoteToGraphic            FAIL");
            failed += 1;
        }
    }

    // 21. QuoteRuneToGraphic — alias of QuoteRune in slim build.
    {
        let q = strconv::QuoteRuneToGraphic(b'A' as rune);
        if q == "'A'" {
            fmt::Println!("[21] QuoteRuneToGraphic        PASS");
        } else {
            fmt::Println!("[21] QuoteRuneToGraphic        FAIL");
            failed += 1;
        }
    }

    // 22. AppendQuoteToGraphic / AppendQuoteRuneToGraphic.
    {
        use goish::slice;
        let dst: goish::slice<byte> = slice::__from_vec(alloc::vec::Vec::new());
        let dst = strconv::AppendQuoteToGraphic(dst, string("hi"));
        let dst = strconv::AppendQuoteRuneToGraphic(dst, b'!' as rune);
        let s = string::from_bytes(&dst);
        if s == "\"hi\"'!'" {
            fmt::Println!("[22] AppendQuote*ToGraphic     PASS");
        } else {
            fmt::Println!("[22] AppendQuote*ToGraphic     FAIL");
            failed += 1;
        }
    }

    // 23. Round-trip: Quote + Unquote with multibyte content.
    {
        let original = string("héllo \\ \"x\" \tend");
        let q = strconv::Quote(original.clone());
        let (uq, err) = strconv::Unquote(q);
        if err.IsNil() && uq == original {
            fmt::Println!("[23] Round-trip multibyte      PASS");
        } else {
            fmt::Println!("[23] Round-trip multibyte      FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 23/23");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 23");
        syscall::Exit(1);
    }
}
