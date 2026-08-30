// scanner_smoke — exercise text/scanner.
// (text/scanner/scanner.go)
//
// Every check replays a token stream printed by a running Go 1.25.5
// (tools/gen_scanner_ref.go, run through scripts/goref.sh). For each
// source the scanner is driven to EOF and each token is rendered as
// `TokenString(tok)|TokenText()|Line:Column`, so a wrong token *kind*,
// a wrong token *text* and a wrong *position* are all separate
// failures rather than one blurred one. The error count is compared
// too, because several of the number cases are only interesting for
// the diagnostics they produce.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::string::String as RString;
use goish::fmt;
use goish::strings;
use goish::syscall;
use goish::text::scanner;
use goish::types::int;

fn noop_error(_s: &mut scanner::Scanner<strings::Reader>, _msg: goish::string) {}

// Render one source's whole token stream the way the Go reference does.
fn render(src: &str, mode: goish::types::uint) -> (RString, int) {
    let mut s = scanner::NewScanner(strings::NewReader(src));
    s.Mode = mode;
    s.Error = Some(noop_error);
    let mut out = RString::new();
    let mut n = 0;
    while n < 60 {
        let tok = s.Scan();
        if tok == scanner::EOF {
            break;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(core::str::from_utf8(scanner::TokenString(tok).as_bytes()).unwrap_or("?"));
        out.push('|');
        let tt = s.TokenText();
        out.push_str(core::str::from_utf8(tt.as_bytes()).unwrap_or("?"));
        out.push('|');
        let ln = goish::strconv::Itoa(s.Position.Line);
        out.push_str(core::str::from_utf8(ln.as_bytes()).unwrap_or("?"));
        out.push(':');
        let cl = goish::strconv::Itoa(s.Position.Column);
        out.push_str(core::str::from_utf8(cl.as_bytes()).unwrap_or("?"));
        n += 1;
    }
    (out, s.ErrorCount)
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let cases: [(&str, goish::types::uint, int, &str); 6] = [
        (
            "package main\n// line comment\nfunc f(x int) { y := 0x1f_2a; z := 1.5e3; s := \"hi\\n\"; c := \'a\'; r := `raw` }\n",
            scanner::GoTokens,
            0,
            "Ident|package|1:1\nIdent|main|1:9\nIdent|func|3:1\nIdent|f|3:6\n\"(\"|(|3:7\nIdent|x|3:8\nIdent|int|3:10\n\")\"|)|3:13\n\"{\"|{|3:15\nIdent|y|3:17\n\":\"|:|3:19\n\"=\"|=|3:20\nInt|0x1f_2a|3:22\n\";\"|;|3:29\nIdent|z|3:31\n\":\"|:|3:33\n\"=\"|=|3:34\nFloat|1.5e3|3:36\n\";\"|;|3:41\nIdent|s|3:43\n\":\"|:|3:45\n\"=\"|=|3:46\nString|\"hi\\n\"|3:48\n\";\"|;|3:54\nIdent|c|3:56\n\":\"|:|3:58\n\"=\"|=|3:59\nChar|'a'|3:61\n\";\"|;|3:64\nIdent|r|3:66\n\":\"|:|3:68\n\"=\"|=|3:69\nRawString|`raw`|3:71\n\"}\"|}|3:77",
        ),
        (
            "abc 123 \"str\" x_1",
            scanner::ScanIdents,
            0,
            "Ident|abc|1:1\n\"1\"|1|1:5\n\"2\"|2|1:6\n\"3\"|3|1:7\n\"\\\"\"|\"|1:9\nIdent|str|1:10\n\"\\\"\"|\"|1:13\nIdent|x_1|1:15",
        ),
        (
            "a /*b*/ c // d\ne",
            scanner::ScanIdents | scanner::ScanComments,
            0,
            "Ident|a|1:1\nComment|/*b*/|1:3\nIdent|c|1:9\nComment|// d|1:11\nIdent|e|2:1",
        ),
        (
            "0 00 0x 0b101 0o17 1_000 1__0 08 1.5 .5 1e3 0x1p-2 1e 0b1.2",
            scanner::ScanInts | scanner::ScanFloats,
            5,
            "Int|0|1:1\nInt|00|1:3\nInt|0x|1:6\nInt|0b101|1:9\nInt|0o17|1:15\nInt|1_000|1:20\nInt|1__0|1:26\nInt|08|1:31\nFloat|1.5|1:34\nFloat|.5|1:38\nFloat|1e3|1:41\nFloat|0x1p-2|1:45\nFloat|1e|1:52\nFloat|0b1.2|1:55",
        ),
        (
            "\"unterminated\n \'ab\' `x",
            scanner::GoTokens,
            3,
            "String|\"unterminated\n|1:1\nChar|'ab'|2:2\nRawString|`x|2:7",
        ),
        (
            "\u{3c0} := \"h\u{e9}llo\" // \u{fc}n\u{ef}code\n\u{3a3}",
            scanner::GoTokens,
            0,
            "Ident|\u{3c0}|1:1\n\":\"|:|1:3\n\"=\"|=|1:4\nString|\"h\u{e9}llo\"|1:6\nIdent|\u{3a3}|2:1",
        ),
    ];

    let mut k: usize = 0;
    while k < cases.len() {
        let (src, mode, want_errs, want) = cases[k];
        let (got, errs) = render(src, mode);
        if got.as_str() == want && errs == want_errs {
            fmt::Println!("[", (k + 1) as i64, "] token stream vs Go     PASS");
        } else {
            fmt::Println!("[", (k + 1) as i64, "] token stream vs Go     FAIL");
            fmt::Println!("  got :", goish::string::from(got.as_str()));
            fmt::Println!("  want:", goish::string::from(want));
            failed += 1;
        }
        k += 1;
    }

    // Peek/Next walk the source character by character without
    // disturbing the token machinery, and Pos tracks them.
    {
        let mut s = scanner::NewScanner(strings::NewReader("ab\ncd"));
        s.Error = Some(noop_error);
        let mut chars = RString::new();
        loop {
            let c = s.Peek();
            if c == scanner::EOF {
                break;
            }
            let g = s.Next();
            chars.push(char::from_u32(g as u32).unwrap_or('?'));
        }
        let p = s.Pos();
        // Go prints line=2 col=3 off=5 for this source.
        if chars.as_str() == "ab\ncd" && p.Line == 2 && p.Column == 3 && p.Offset == 5 {
            fmt::Println!("[ 7] Next/Peek/Pos            PASS");
        } else {
            fmt::Println!("[ 7] Next/Peek/Pos            FAIL");
            failed += 1;
        }
    }

    // Position rendering, including the <input> default filename.
    {
        let p = scanner::Position {
            Filename: goish::string::new(),
            Offset: 0,
            Line: 3,
            Column: 7,
        };
        let mut q = p.clone();
        q.Filename = "a.go".into();
        let invalid = scanner::Position {
            Filename: "b.go".into(),
            Offset: 0,
            Line: 0,
            Column: 0,
        };
        if p.String() == "<input>:3:7"
            && q.String() == "a.go:3:7"
            && invalid.String() == "b.go"
            && p.IsValid()
            && !invalid.IsValid()
        {
            fmt::Println!("[ 8] Position.String          PASS");
        } else {
            fmt::Println!("[ 8] Position.String          FAIL");
            failed += 1;
        }
    }

    // TokenString names the eight token constants and quotes anything
    // else, which is what makes a scanner error message readable.
    {
        if scanner::TokenString(scanner::EOF) == "EOF"
            && scanner::TokenString(scanner::Ident) == "Ident"
            && scanner::TokenString(scanner::RawString) == "RawString"
            && scanner::TokenString(43) == "\"+\""
        {
            fmt::Println!("[ 9] TokenString              PASS");
        } else {
            fmt::Println!("[ 9] TokenString              FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 9/9");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 9");
        syscall::Exit(1);
    }
}
