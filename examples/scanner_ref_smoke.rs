// scanner_ref_smoke — text/scanner against a running Go.
// (text/scanner/scanner.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_scanner_ref.go` run in
// `package scanner_test` by `scripts/goref.sh`.
//
// A tokenizer's bugs are all at the boundaries: the last character of a
// token, the first of the next, and what happens when a token runs off
// the end of the input. Every one of those is invisible in ordinary
// source and obvious against a reference — five modes crossed with
// sixteen inputs here, and goish matched all 97 lines on the first run.
//
// What is pinned:
//
//   * The Mode is a set of bits saying which token KINDS to recognise,
//     and an unrecognised token degrades to individual RUNES rather
//     than erroring: with ScanInts off, "123" comes back as '1', '2',
//     '3'. Mode 0 turns every input into its characters.
//   * Position is 1-based for Line and Column and counts RUNES, so a
//     token after 日本 reports the column a human would count — and
//     Offset stays in bytes, which is the pair a caller needs to slice
//     the source and to point at it.
//   * A malformed token reports through the Error hook and still
//     returns something, so the scan continues: an unterminated string,
//     an unterminated comment, a multi-rune char literal and an unknown
//     escape each produce their message AND their token.
//   * Comments are skipped by default (SkipComments is inside GoTokens)
//     and returned as tokens when ScanComments is set without it.
//   * Peek does not consume and Next is the raw rune reader that
//     bypasses tokenisation, including across a multi-byte rune and
//     past the end.
//
// One harness difference: Go's Error hook is a closure appending to a
// local slice, where goish's is a plain fn pointer with no captures, so
// the messages are collected through a static. The messages themselves
// are compared unchanged.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string;
use goish::strings;
use goish::sync::Mutex;
use goish::syscall;
use goish::text::scanner;
use goish::types::{int, rune, uint};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// Go's Error hook is a closure that appends to a local slice; goish's
// is a plain fn pointer with no captures, so the messages are collected
// through a static instead.
static ERRS: Mutex<alloc::vec::Vec<string>> = Mutex::new(alloc::vec::Vec::new());

fn on_err(_s: &mut scanner::Scanner<strings::Reader>, msg: string) {
    ERRS.Lock().push(msg);
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 97] = [
    "scan gotokens     idents             -> [Ident:\"abc\"@1:4 Ident:\"_x9\"@1:8 Ident:\"Δx\"@1:11] errs=[]",
    "scan gotokens     ints               -> [Int:\"0\"@1:2 Int:\"42\"@1:5 Int:\"0x1f\"@1:10 Int:\"0b101\"@1:16 Int:\"0o17\"@1:21 Int:\"1_000\"@1:27] errs=[]",
    "scan gotokens     floats             -> [Float:\"1.5\"@1:4 Float:\"1e10\"@1:9 Float:\".5\"@1:12 Float:\"1.\"@1:15 Float:\"0x1p4\"@1:21] errs=[]",
    "scan gotokens     strings            -> [String:\"\\\"a\\\"\"@1:4 String:\"\\\"b\\\\nc\\\"\"@1:11 String:\"\\\"é\\\"\"@1:15] errs=[]",
    "scan gotokens     rawstring          -> [RawString:\"`raw\\nstring`\"@2:8] errs=[]",
    "scan gotokens     chars              -> [Char:\"'a'\"@1:4 Char:\"'\\\\n'\"@1:9 Char:\"'é'\"@1:13] errs=[]",
    "scan gotokens     comments           -> [Ident:\"a\"@1:2 Ident:\"b\"@2:2 Ident:\"c\"@2:16] errs=[]",
    "scan gotokens     operators          -> [Ident:\"a\"@1:2 \"+\":\"+\"@1:3 Ident:\"b\"@1:4 \"*\":\"*\"@1:5 Ident:\"c\"@1:6 \"=\":\"=\"@1:8 \"=\":\"=\"@1:9 Ident:\"d\"@1:11] errs=[]",
    "scan gotokens     mixed              -> [Ident:\"x\"@1:2 \":\":\":\"@1:4 \"=\":\"=\"@1:5 Int:\"1\"@1:7 \"+\":\"+\"@1:9 Float:\"2.5\"@1:13] errs=[]",
    "scan gotokens     empty              -> [] errs=[]",
    "scan gotokens     whitespace         -> [] errs=[]",
    "scan gotokens     cjk                -> [Ident:\"日本\"@1:3 Ident:\"x\"@1:5] errs=[]",
    "scan gotokens     unterminated-str   -> [String:\"\\\"abc\"@1:5] errs=[literal not terminated]",
    "scan gotokens     unterminated-cmt   -> [] errs=[comment not terminated]",
    "scan gotokens     bad-char           -> [Char:\"'ab'\"@1:5] errs=[invalid char literal]",
    "scan gotokens     lone-backslash     -> [String:\"\\\"a\\\\qb\\\"\"@1:7] errs=[invalid char escape]",
    "scan no-ints      idents             -> [Ident:\"abc\"@1:4 Ident:\"_x9\"@1:8 Ident:\"Δx\"@1:11] errs=[]",
    "scan no-ints      ints               -> [Int:\"0\"@1:2 Int:\"42\"@1:5 Int:\"0x1f\"@1:10 Int:\"0b101\"@1:16 Int:\"0o17\"@1:21 Int:\"1_000\"@1:27] errs=[]",
    "scan no-ints      floats             -> [Float:\"1.5\"@1:4 Float:\"1e10\"@1:9 Float:\".5\"@1:12 Float:\"1.\"@1:15 Float:\"0x1p4\"@1:21] errs=[]",
    "scan no-ints      strings            -> [String:\"\\\"a\\\"\"@1:4 String:\"\\\"b\\\\nc\\\"\"@1:11 String:\"\\\"é\\\"\"@1:15] errs=[]",
    "scan no-ints      rawstring          -> [RawString:\"`raw\\nstring`\"@2:8] errs=[]",
    "scan no-ints      chars              -> [Char:\"'a'\"@1:4 Char:\"'\\\\n'\"@1:9 Char:\"'é'\"@1:13] errs=[]",
    "scan no-ints      comments           -> [Ident:\"a\"@1:2 Ident:\"b\"@2:2 Ident:\"c\"@2:16] errs=[]",
    "scan no-ints      operators          -> [Ident:\"a\"@1:2 \"+\":\"+\"@1:3 Ident:\"b\"@1:4 \"*\":\"*\"@1:5 Ident:\"c\"@1:6 \"=\":\"=\"@1:8 \"=\":\"=\"@1:9 Ident:\"d\"@1:11] errs=[]",
    "scan no-ints      mixed              -> [Ident:\"x\"@1:2 \":\":\":\"@1:4 \"=\":\"=\"@1:5 Int:\"1\"@1:7 \"+\":\"+\"@1:9 Float:\"2.5\"@1:13] errs=[]",
    "scan no-ints      empty              -> [] errs=[]",
    "scan no-ints      whitespace         -> [] errs=[]",
    "scan no-ints      cjk                -> [Ident:\"日本\"@1:3 Ident:\"x\"@1:5] errs=[]",
    "scan no-ints      unterminated-str   -> [String:\"\\\"abc\"@1:5] errs=[literal not terminated]",
    "scan no-ints      unterminated-cmt   -> [] errs=[comment not terminated]",
    "scan no-ints      bad-char           -> [Char:\"'ab'\"@1:5] errs=[invalid char literal]",
    "scan no-ints      lone-backslash     -> [String:\"\\\"a\\\\qb\\\"\"@1:7] errs=[invalid char escape]",
    "scan comments     idents             -> [Ident:\"abc\"@1:4 Ident:\"_x9\"@1:8 Ident:\"Δx\"@1:11] errs=[]",
    "scan comments     ints               -> [Int:\"0\"@1:2 Int:\"42\"@1:5 Int:\"0x1f\"@1:10 Int:\"0b101\"@1:16 Int:\"0o17\"@1:21 Int:\"1_000\"@1:27] errs=[]",
    "scan comments     floats             -> [Float:\"1.5\"@1:4 Float:\"1e10\"@1:9 Float:\".5\"@1:12 Float:\"1.\"@1:15 Float:\"0x1p4\"@1:21] errs=[]",
    "scan comments     strings            -> [String:\"\\\"a\\\"\"@1:4 String:\"\\\"b\\\\nc\\\"\"@1:11 String:\"\\\"é\\\"\"@1:15] errs=[]",
    "scan comments     rawstring          -> [RawString:\"`raw\\nstring`\"@2:8] errs=[]",
    "scan comments     chars              -> [Char:\"'a'\"@1:4 Char:\"'\\\\n'\"@1:9 Char:\"'é'\"@1:13] errs=[]",
    "scan comments     comments           -> [Ident:\"a\"@1:2 Comment:\"// line\"@1:10 Ident:\"b\"@2:2 Comment:\"/* block */\"@2:14 Ident:\"c\"@2:16] errs=[]",
    "scan comments     operators          -> [Ident:\"a\"@1:2 \"+\":\"+\"@1:3 Ident:\"b\"@1:4 \"*\":\"*\"@1:5 Ident:\"c\"@1:6 \"=\":\"=\"@1:8 \"=\":\"=\"@1:9 Ident:\"d\"@1:11] errs=[]",
    "scan comments     mixed              -> [Ident:\"x\"@1:2 \":\":\":\"@1:4 \"=\":\"=\"@1:5 Int:\"1\"@1:7 \"+\":\"+\"@1:9 Float:\"2.5\"@1:13 Comment:\"// sum\"@1:20] errs=[]",
    "scan comments     empty              -> [] errs=[]",
    "scan comments     whitespace         -> [] errs=[]",
    "scan comments     cjk                -> [Ident:\"日本\"@1:3 Ident:\"x\"@1:5] errs=[]",
    "scan comments     unterminated-str   -> [String:\"\\\"abc\"@1:5] errs=[literal not terminated]",
    "scan comments     unterminated-cmt   -> [Comment:\"/* abc\"@1:7] errs=[comment not terminated]",
    "scan comments     bad-char           -> [Char:\"'ab'\"@1:5] errs=[invalid char literal]",
    "scan comments     lone-backslash     -> [String:\"\\\"a\\\\qb\\\"\"@1:7] errs=[invalid char escape]",
    "scan idents-only  idents             -> [Ident:\"abc\"@1:4 Ident:\"_x9\"@1:8 Ident:\"Δx\"@1:11] errs=[]",
    "scan idents-only  ints               -> [\"0\":\"0\"@1:2 \"4\":\"4\"@1:4 \"2\":\"2\"@1:5 \"0\":\"0\"@1:7 Ident:\"x1f\"@1:10 \"0\":\"0\"@1:12 Ident:\"b101\"@1:16 \"0\":\"0\"@1:18 Ident:\"o17\"@1:21 \"1\":\"1\"@1:23 Ident:\"_000\"@1:27] errs=[]",
    "scan idents-only  floats             -> [\"1\":\"1\"@1:2 \".\":\".\"@1:3 \"5\":\"5\"@1:4 \"1\":\"1\"@1:6 Ident:\"e10\"@1:9 \".\":\".\"@1:11 \"5\":\"5\"@1:12 \"1\":\"1\"@1:14 \".\":\".\"@1:15 \"0\":\"0\"@1:17 Ident:\"x1p4\"@1:21] errs=[]",
    "scan idents-only  strings            -> [\"\\\"\":\"\\\"\"@1:2 Ident:\"a\"@1:3 \"\\\"\":\"\\\"\"@1:4 \"\\\"\":\"\\\"\"@1:6 Ident:\"b\"@1:7 \"\\\\\":\"\\\\\"@1:8 Ident:\"nc\"@1:10 \"\\\"\":\"\\\"\"@1:11 \"\\\"\":\"\\\"\"@1:13 Ident:\"é\"@1:14 \"\\\"\":\"\\\"\"@1:15] errs=[]",
    "scan idents-only  rawstring          -> [\"`\":\"`\"@1:2 Ident:\"raw\"@1:5 Ident:\"string\"@2:7 \"`\":\"`\"@2:8] errs=[]",
    "scan idents-only  chars              -> [\"'\":\"'\"@1:2 Ident:\"a\"@1:3 \"'\":\"'\"@1:4 \"'\":\"'\"@1:6 \"\\\\\":\"\\\\\"@1:7 Ident:\"n\"@1:8 \"'\":\"'\"@1:9 \"'\":\"'\"@1:11 Ident:\"é\"@1:12 \"'\":\"'\"@1:13] errs=[]",
    "scan idents-only  comments           -> [Ident:\"a\"@1:2 \"/\":\"/\"@1:4 \"/\":\"/\"@1:5 Ident:\"line\"@1:10 Ident:\"b\"@2:2 \"/\":\"/\"@2:4 \"*\":\"*\"@2:5 Ident:\"block\"@2:11 \"*\":\"*\"@2:13 \"/\":\"/\"@2:14 Ident:\"c\"@2:16] errs=[]",
    "scan idents-only  operators          -> [Ident:\"a\"@1:2 \"+\":\"+\"@1:3 Ident:\"b\"@1:4 \"*\":\"*\"@1:5 Ident:\"c\"@1:6 \"=\":\"=\"@1:8 \"=\":\"=\"@1:9 Ident:\"d\"@1:11] errs=[]",
    "scan idents-only  mixed              -> [Ident:\"x\"@1:2 \":\":\":\"@1:4 \"=\":\"=\"@1:5 \"1\":\"1\"@1:7 \"+\":\"+\"@1:9 \"2\":\"2\"@1:11 \".\":\".\"@1:12 \"5\":\"5\"@1:13 \"/\":\"/\"@1:15 \"/\":\"/\"@1:16 Ident:\"sum\"@1:20] errs=[]",
    "scan idents-only  empty              -> [] errs=[]",
    "scan idents-only  whitespace         -> [] errs=[]",
    "scan idents-only  cjk                -> [Ident:\"日本\"@1:3 Ident:\"x\"@1:5] errs=[]",
    "scan idents-only  unterminated-str   -> [\"\\\"\":\"\\\"\"@1:2 Ident:\"abc\"@1:5] errs=[]",
    "scan idents-only  unterminated-cmt   -> [\"/\":\"/\"@1:2 \"*\":\"*\"@1:3 Ident:\"abc\"@1:7] errs=[]",
    "scan idents-only  bad-char           -> [\"'\":\"'\"@1:2 Ident:\"ab\"@1:4 \"'\":\"'\"@1:5] errs=[]",
    "scan idents-only  lone-backslash     -> [\"\\\"\":\"\\\"\"@1:2 Ident:\"a\"@1:3 \"\\\\\":\"\\\\\"@1:4 Ident:\"qb\"@1:6 \"\\\"\":\"\\\"\"@1:7] errs=[]",
    "scan zero         idents             -> [\"a\":\"a\"@1:2 \"b\":\"b\"@1:3 \"c\":\"c\"@1:4 \"_\":\"_\"@1:6 \"x\":\"x\"@1:7 \"9\":\"9\"@1:8 \"Δ\":\"Δ\"@1:10 \"x\":\"x\"@1:11] errs=[]",
    "scan zero         ints               -> [\"0\":\"0\"@1:2 \"4\":\"4\"@1:4 \"2\":\"2\"@1:5 \"0\":\"0\"@1:7 \"x\":\"x\"@1:8 \"1\":\"1\"@1:9 \"f\":\"f\"@1:10 \"0\":\"0\"@1:12 \"b\":\"b\"@1:13 \"1\":\"1\"@1:14 \"0\":\"0\"@1:15 \"1\":\"1\"@1:16 \"0\":\"0\"@1:18 \"o\":\"o\"@1:19 \"1\":\"1\"@1:20 \"7\":\"7\"@1:21 \"1\":\"1\"@1:23 \"_\":\"_\"@1:24 \"0\":\"0\"@1:25 \"0\":\"0\"@1:26 \"0\":\"0\"@1:27] errs=[]",
    "scan zero         floats             -> [\"1\":\"1\"@1:2 \".\":\".\"@1:3 \"5\":\"5\"@1:4 \"1\":\"1\"@1:6 \"e\":\"e\"@1:7 \"1\":\"1\"@1:8 \"0\":\"0\"@1:9 \".\":\".\"@1:11 \"5\":\"5\"@1:12 \"1\":\"1\"@1:14 \".\":\".\"@1:15 \"0\":\"0\"@1:17 \"x\":\"x\"@1:18 \"1\":\"1\"@1:19 \"p\":\"p\"@1:20 \"4\":\"4\"@1:21] errs=[]",
    "scan zero         strings            -> [\"\\\"\":\"\\\"\"@1:2 \"a\":\"a\"@1:3 \"\\\"\":\"\\\"\"@1:4 \"\\\"\":\"\\\"\"@1:6 \"b\":\"b\"@1:7 \"\\\\\":\"\\\\\"@1:8 \"n\":\"n\"@1:9 \"c\":\"c\"@1:10 \"\\\"\":\"\\\"\"@1:11 \"\\\"\":\"\\\"\"@1:13 \"é\":\"é\"@1:14 \"\\\"\":\"\\\"\"@1:15] errs=[]",
    "scan zero         rawstring          -> [\"`\":\"`\"@1:2 \"r\":\"r\"@1:3 \"a\":\"a\"@1:4 \"w\":\"w\"@1:5 \"s\":\"s\"@2:2 \"t\":\"t\"@2:3 \"r\":\"r\"@2:4 \"i\":\"i\"@2:5 \"n\":\"n\"@2:6 \"g\":\"g\"@2:7 \"`\":\"`\"@2:8] errs=[]",
    "scan zero         chars              -> [\"'\":\"'\"@1:2 \"a\":\"a\"@1:3 \"'\":\"'\"@1:4 \"'\":\"'\"@1:6 \"\\\\\":\"\\\\\"@1:7 \"n\":\"n\"@1:8 \"'\":\"'\"@1:9 \"'\":\"'\"@1:11 \"é\":\"é\"@1:12 \"'\":\"'\"@1:13] errs=[]",
    "scan zero         comments           -> [\"a\":\"a\"@1:2 \"/\":\"/\"@1:4 \"/\":\"/\"@1:5 \"l\":\"l\"@1:7 \"i\":\"i\"@1:8 \"n\":\"n\"@1:9 \"e\":\"e\"@1:10 \"b\":\"b\"@2:2 \"/\":\"/\"@2:4 \"*\":\"*\"@2:5 \"b\":\"b\"@2:7 \"l\":\"l\"@2:8 \"o\":\"o\"@2:9 \"c\":\"c\"@2:10 \"k\":\"k\"@2:11 \"*\":\"*\"@2:13 \"/\":\"/\"@2:14 \"c\":\"c\"@2:16] errs=[]",
    "scan zero         operators          -> [\"a\":\"a\"@1:2 \"+\":\"+\"@1:3 \"b\":\"b\"@1:4 \"*\":\"*\"@1:5 \"c\":\"c\"@1:6 \"=\":\"=\"@1:8 \"=\":\"=\"@1:9 \"d\":\"d\"@1:11] errs=[]",
    "scan zero         mixed              -> [\"x\":\"x\"@1:2 \":\":\":\"@1:4 \"=\":\"=\"@1:5 \"1\":\"1\"@1:7 \"+\":\"+\"@1:9 \"2\":\"2\"@1:11 \".\":\".\"@1:12 \"5\":\"5\"@1:13 \"/\":\"/\"@1:15 \"/\":\"/\"@1:16 \"s\":\"s\"@1:18 \"u\":\"u\"@1:19 \"m\":\"m\"@1:20] errs=[]",
    "scan zero         empty              -> [] errs=[]",
    "scan zero         whitespace         -> [] errs=[]",
    "scan zero         cjk                -> [\"日\":\"日\"@1:2 \"本\":\"本\"@1:3 \"x\":\"x\"@1:5] errs=[]",
    "scan zero         unterminated-str   -> [\"\\\"\":\"\\\"\"@1:2 \"a\":\"a\"@1:3 \"b\":\"b\"@1:4 \"c\":\"c\"@1:5] errs=[]",
    "scan zero         unterminated-cmt   -> [\"/\":\"/\"@1:2 \"*\":\"*\"@1:3 \"a\":\"a\"@1:5 \"b\":\"b\"@1:6 \"c\":\"c\"@1:7] errs=[]",
    "scan zero         bad-char           -> [\"'\":\"'\"@1:2 \"a\":\"a\"@1:3 \"b\":\"b\"@1:4 \"'\":\"'\"@1:5] errs=[]",
    "scan zero         lone-backslash     -> [\"\\\"\":\"\\\"\"@1:2 \"a\":\"a\"@1:3 \"\\\\\":\"\\\\\"@1:4 \"q\":\"q\"@1:5 \"b\":\"b\"@1:6 \"\\\"\":\"\\\"\"@1:7] errs=[]",
    "peek1='a' next1='a' peek2='b' next2='b' next3='日' next4='�'",
    "pos \"a\"  offset=1   line=1 col=2",
    "pos \"bb\" offset=4   line=2 col=3",
    "pos \"ccc\" offset=9   line=4 col=4",
    "tokname EOF         ",
    "tokname Ident       ",
    "tokname Int         ",
    "tokname Float       ",
    "tokname Char        ",
    "tokname String      ",
    "tokname RawString   ",
    "tokname Comment     ",
    "tokname \"+\"         ",
    "tokname \"x\"         ",
    "pos-valid zero=false set=true",
    "pos-string zero=\"<input>\"",
    "pos-string set=\"f:2:3\"",
];

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;

    let configs: [(&str, uint); 5] = [
        ("gotokens", scanner::GoTokens),
        ("no-ints", scanner::GoTokens & !scanner::ScanInts),
        (
            "comments",
            (scanner::GoTokens & !scanner::SkipComments) | scanner::ScanComments,
        ),
        ("idents-only", scanner::ScanIdents),
        ("zero", 0),
    ];
    let inputs: [(&str, &str); 16] = [
        ("idents", "abc _x9 Δx"),
        ("ints", "0 42 0x1f 0b101 0o17 1_000"),
        ("floats", "1.5 1e10 .5 1. 0x1p4"),
        ("strings", "\"a\" \"b\\nc\" \"é\""),
        ("rawstring", "`raw\nstring`"),
        ("chars", "'a' '\\n' 'é'"),
        ("comments", "a // line\nb /* block */ c"),
        ("operators", "a+b*c == d"),
        ("mixed", "x := 1 + 2.5 // sum"),
        ("empty", ""),
        ("whitespace", "   \t\n  "),
        ("cjk", "日本 x"),
        ("unterminated-str", "\"abc"),
        ("unterminated-cmt", "/* abc"),
        ("bad-char", "'ab'"),
        ("lone-backslash", "\"a\\qb\""),
    ];
    for (cname, mode) in configs.iter() {
        for (iname, src) in inputs.iter() {
            ERRS.Lock().clear();
            let mut sc = scanner::NewScanner(strings::NewReader(s(src)));
            sc.Init();
            sc.Mode = *mode;
            sc.Error = Some(on_err);
            let mut toks: alloc::vec::Vec<string> = alloc::vec::Vec::new();
            for _ in 0..30 {
                let tok = sc.Scan();
                if tok == scanner::EOF {
                    break;
                }
                let p = sc.Pos();
                toks.push(fmt::Sprintf!(
                    "%s:%q@%d:%d",
                    scanner::TokenString(tok),
                    sc.TokenText(),
                    p.Line,
                    p.Column
                ));
            }
            let mut tl = s("[");
            for (i, t) in toks.iter().enumerate() {
                if i > 0 {
                    tl = tl + s(" ");
                }
                tl = tl + t.clone();
            }
            tl = tl + s("]");
            let mut el = s("[");
            {
                let e = ERRS.Lock();
                for (i, m) in e.iter().enumerate() {
                    if i > 0 {
                        el = el + s(" ");
                    }
                    el = el + m.clone();
                }
            }
            el = el + s("]");
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("scan %-12s %-18s -> %s errs=%s", s(cname), s(iname), tl, el),
            );
        }
    }
    // Peek and Next.
    {
        let mut sc = scanner::NewScanner(strings::NewReader(s("ab日")));
        sc.Init();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "peek1=%q next1=%q peek2=%q next2=%q next3=%q next4=%q",
                sc.Peek(),
                sc.Next(),
                sc.Peek(),
                sc.Next(),
                sc.Next(),
                sc.Next()
            ),
        );
    }
    // Position after each token.
    {
        let mut sc = scanner::NewScanner(strings::NewReader(s("a\nbb\n\nccc")));
        sc.Init();
        sc.Mode = scanner::GoTokens;
        loop {
            let tok = sc.Scan();
            if tok == scanner::EOF {
                break;
            }
            let p = sc.Pos();
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "pos %-4q offset=%-3d line=%d col=%d",
                    sc.TokenText(),
                    p.Offset,
                    p.Line,
                    p.Column
                ),
            );
        }
    }
    // Token names.
    for tok in [
        scanner::EOF,
        scanner::Ident,
        scanner::Int,
        scanner::Float,
        scanner::Char,
        scanner::String,
        scanner::RawString,
        scanner::Comment,
        b'+' as rune,
        b'x' as rune,
    ] {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("tokname %-12s", scanner::TokenString(tok)),
        );
    }
    {
        let p = scanner::Position::default();
        let mut q = scanner::Position::default();
        q.Line = 1;
        let mut r = scanner::Position::default();
        r.Filename = s("f");
        r.Line = 2;
        r.Column = 3;
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("pos-valid zero=%v set=%v", p.IsValid(), q.IsValid()),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("pos-string zero=%q", p.String()),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("pos-string set=%q", r.String()),
        );
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
