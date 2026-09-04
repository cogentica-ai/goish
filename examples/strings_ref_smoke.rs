// strings_ref_smoke — the strings package against a running Go.
// (strings/strings.go, strings/builder.go, strings/replace.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_strings_ref.go` run in
// `package strings_test` by `scripts/goref.sh`.
//
// strings is the package every Go program uses, and goish had 2847
// lines of it with NO reference test at all. Its edge cases are not
// exotic — they are the empty string, the empty separator, the cutset
// that is a set of runes and not a prefix, and the count that is a cap
// and not a switch — and each has a rule that is easy to get backwards
// while every ordinary input still works.
//
// Measuring it found four defects, three of them silent:
//
//   * fmt's field width counted BYTES where Go counts RUNES
//     (format.go:98, `f.wid - utf8.RuneCount(b)`). Every padded column
//     containing non-ASCII came out short, everywhere in the library —
//     which is why this smoke pads so many of its own lines.
//   * IndexAny and LastIndexAny compared raw BYTES against the cutset
//     where Go compares RUNES. "日本語" against the cutset "本語"
//     answered 0, because 日 and 本 both begin 0xE6 — an index that is
//     not even a rune boundary, so a caller slicing there splits a
//     character in half.
//   * IndexRune(s, utf8.RuneError) searched for the ENCODED U+FFFD
//     bytes. Go has a separate case that ranges over s, which yields
//     RuneError for a genuine U+FFFD *and* for any invalid byte — so
//     this is how a caller asks "where does this stop being valid
//     UTF-8?", and goish answered -1, "it is all fine", for every
//     malformed input.
//   * SplitAfterN(s, sep, 0) returned every piece. Go's genSplit opens
//     with `if n == 0 { return nil }`; n is a cap on the result, and
//     zero is a cap of zero, not "unlimited". The guards read `n > 0`,
//     so zero fell through to the unlimited path.
//
// Builder.String also took `self` and consumed the builder, which made
// Go's ordinary `if b.Len() > 0 { log(b.String()) }` followed by more
// writing impossible. It now takes `&self` like Go's pointer receiver
// and copies, which removes the alias hazard the consuming form was
// chosen to prevent.
//
// One KNOWN GAP is asserted at the end so it cannot drift silently: Go
// applies a field width to EACH ELEMENT of a compound value, and goish
// applies it to the whole rendering. Fixing it means threading the fmt
// state through every element renderer, which is a larger change than
// this one.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::gostring::string;
use goish::types::{int, rune};
use goish::{fmt, slices, strings, syscall, unicode};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn sl(v: &[&str]) -> slice<string> {
    let mut out: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    for x in v {
        out.push(s(x));
    }
    return slice::__from_vec(out);
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 156] = [
    "split \"a,b,c\"  \",\"  -> [\"a\" \"b\" \"c\"]",
    "splitafter \"a,b,c\"  \",\"  -> [\"a,\" \"b,\" \"c\"]",
    "split \"a,b,c\"  \"\"   -> [\"a\" \",\" \"b\" \",\" \"c\"]",
    "splitafter \"a,b,c\"  \"\"   -> [\"a\" \",\" \"b\" \",\" \"c\"]",
    "split \"\"       \",\"  -> [\"\"]",
    "splitafter \"\"       \",\"  -> [\"\"]",
    "split \"\"       \"\"   -> []",
    "splitafter \"\"       \"\"   -> []",
    "split \"abc\"    \"\"   -> [\"a\" \"b\" \"c\"]",
    "splitafter \"abc\"    \"\"   -> [\"a\" \"b\" \"c\"]",
    "split \"a\"      \",\"  -> [\"a\"]",
    "splitafter \"a\"      \",\"  -> [\"a\"]",
    "split \",\"      \",\"  -> [\"\" \"\"]",
    "splitafter \",\"      \",\"  -> [\",\" \"\"]",
    "split \",,\"     \",\"  -> [\"\" \"\" \"\"]",
    "splitafter \",,\"     \",\"  -> [\",\" \",\" \"\"]",
    "split \"a,,b\"   \",\"  -> [\"a\" \"\" \"b\"]",
    "splitafter \"a,,b\"   \",\"  -> [\"a,\" \",\" \"b\"]",
    "split \"日本語\"    \"\"   -> [\"日\" \"本\" \"語\"]",
    "splitafter \"日本語\"    \"\"   -> [\"日\" \"本\" \"語\"]",
    "split \"a→b\"    \"→\"  -> [\"a\" \"b\"]",
    "splitafter \"a→b\"    \"→\"  -> [\"a→\" \"b\"]",
    "split \"banana\" \"an\" -> [\"b\" \"\" \"a\"]",
    "splitafter \"banana\" \"an\" -> [\"ban\" \"an\" \"a\"]",
    "split \"banana\" \"na\" -> [\"ba\" \"\" \"\"]",
    "splitafter \"banana\" \"na\" -> [\"bana\" \"na\" \"\"]",
    "split \"aaa\"    \"aa\" -> [\"\" \"a\"]",
    "splitafter \"aaa\"    \"aa\" -> [\"aa\" \"a\"]",
    "split \"x\"      \"xx\" -> [\"x\"]",
    "splitafter \"x\"      \"xx\" -> [\"x\"]",
    "splitn n=-1  -> [\"a\" \"b\" \"c\" \"d\"]  after=[\"a,\" \"b,\" \"c,\" \"d\"]",
    "splitn n=0   -> []  after=[]",
    "splitn n=1   -> [\"a,b,c,d\"]  after=[\"a,b,c,d\"]",
    "splitn n=2   -> [\"a\" \"b,c,d\"]  after=[\"a,\" \"b,c,d\"]",
    "splitn n=3   -> [\"a\" \"b\" \"c,d\"]  after=[\"a,\" \"b,\" \"c,d\"]",
    "splitn n=10  -> [\"a\" \"b\" \"c\" \"d\"]  after=[\"a,\" \"b,\" \"c,\" \"d\"]",
    "index \"chicken\"  \"ken\" -> idx=4   last=4   count=1 contains=true",
    "index \"chicken\"  \"\"    -> idx=0   last=7   count=8 contains=true",
    "index \"\"         \"\"    -> idx=0   last=0   count=1 contains=true",
    "index \"\"         \"a\"   -> idx=-1  last=-1  count=0 contains=false",
    "index \"chicken\"  \"xyz\" -> idx=-1  last=-1  count=0 contains=false",
    "index \"go gopher\" \"go\"  -> idx=0   last=3   count=2 contains=true",
    "index \"aaa\"      \"aa\"  -> idx=0   last=1   count=1 contains=true",
    "index \"日本語\"      \"本\"   -> idx=3   last=3   count=1 contains=true",
    "index \"日本語\"      \"語\"   -> idx=6   last=6   count=1 contains=true",
    "indexany \"chicken\" \"aeiouy\" -> any=2   lastany=5",
    "indexany \"crwth\"  \"aeiouy\" -> any=-1  lastany=-1",
    "indexany \"\"       \"abc\"    -> any=-1  lastany=-1",
    "indexany \"abc\"    \"\"       -> any=-1  lastany=-1",
    "indexany \"日本語\"    \"本語\"     -> any=3   lastany=6",
    "indexany \"abc\"    \"cba\"    -> any=0   lastany=2",
    "indexrune \"chicken\" 'k'       -> 4",
    "indexrune \"chicken\" 'z'       -> -1",
    "indexrune \"日本語\"    '本'       -> 3",
    "indexrune \"\"       'a'       -> -1",
    "indexrune \"abc\"    '�'       -> -1",
    "indexrune \"a\\xffb\" '�'       -> 1",
    "indexfunc \"chicken\" upper=-1  lastupper=-1",
    "indexfunc \"\"       upper=-1  lastupper=-1",
    "indexfunc \"日本語\"    upper=-1  lastupper=-1",
    "indexfunc \"ABC\"    upper=0   lastupper=2",
    "trim \"¡¡¡Hello!!!\"  \"!¡\"  -> t=\"Hello\"      l=\"Hello!!!\"   r=\"¡¡¡Hello\"   space=\"¡¡¡Hello!!!\"",
    "trim \"xxhixx\"       \"x\"   -> t=\"hi\"         l=\"hixx\"       r=\"xxhi\"       space=\"xxhixx\"",
    "trim \"xxhixx\"       \"xh\"  -> t=\"i\"          l=\"ixx\"        r=\"xxhi\"       space=\"xxhixx\"",
    "trim \"\"             \"abc\" -> t=\"\"           l=\"\"           r=\"\"           space=\"\"",
    "trim \"abc\"          \"\"    -> t=\"abc\"        l=\"abc\"        r=\"abc\"        space=\"abc\"",
    "trim \"aaa\"          \"a\"   -> t=\"\"           l=\"\"           r=\"\"           space=\"aaa\"",
    "trim \"  hi  \"       \" \"   -> t=\"hi\"         l=\"hi  \"       r=\"  hi\"       space=\"hi\"",
    "trim \"\\t\\n hi \\r\\n\" \"\"    -> t=\"\\t\\n hi \\r\\n\" l=\"\\t\\n hi \\r\\n\" r=\"\\t\\n hi \\r\\n\" space=\"hi\"",
    "trim \"日本語\"          \"日語\"  -> t=\"本\"          l=\"本語\"         r=\"日本\"         space=\"日本語\"",
    "trimfix \"hello\"  \"he\"     -> prefix=\"llo\"    suffix=\"hello\"  cutp=(\"llo\",true) cuts=(\"hello\",false)",
    "trimfix \"hello\"  \"x\"      -> prefix=\"hello\"  suffix=\"hello\"  cutp=(\"hello\",false) cuts=(\"hello\",false)",
    "trimfix \"hello\"  \"\"       -> prefix=\"hello\"  suffix=\"hello\"  cutp=(\"hello\",true) cuts=(\"hello\",true)",
    "trimfix \"hello\"  \"hello\"  -> prefix=\"\"       suffix=\"\"       cutp=(\"\",true) cuts=(\"\",true)",
    "trimfix \"hello\"  \"hellox\" -> prefix=\"hello\"  suffix=\"hello\"  cutp=(\"hello\",false) cuts=(\"hello\",false)",
    "trimfix \"hello\"  \"lo\"     -> prefix=\"hello\"  suffix=\"hel\"    cutp=(\"hello\",false) cuts=(\"hel\",true)",
    "cut \"a=b\"    \"=\" -> before=\"a\"    after=\"b\"    found=true",
    "cut \"a=b=c\"  \"=\" -> before=\"a\"    after=\"b=c\"  found=true",
    "cut \"abc\"    \"=\" -> before=\"abc\"  after=\"\"     found=false",
    "cut \"\"       \"=\" -> before=\"\"     after=\"\"     found=false",
    "cut \"a=b\"    \"\"  -> before=\"\"     after=\"a=b\"  found=true",
    "cut \"=b\"     \"=\" -> before=\"\"     after=\"b\"    found=true",
    "cut \"a=\"     \"=\" -> before=\"a\"    after=\"\"     found=true",
    "fields \"  foo bar  baz   \"  -> [\"foo\" \"bar\" \"baz\"]",
    "fields \"\"                   -> []",
    "fields \"   \"                -> []",
    "fields \"a\"                  -> [\"a\"]",
    "fields \"a\\tb\\nc\\vd\\fe\\rf\"   -> [\"a\" \"b\" \"c\" \"d\" \"e\" \"f\"]",
    "fields \"日 本 語\"              -> [\"日\" \"本\" \"語\"]",
    "fields \"\\u00a0x\"            -> [\"x\"]",
    "fields \"x\\u2028y\"           -> [\"x\" \"y\"]",
    "fieldsfunc \"a1b2c3\" -> [\"a\" \"b\" \"c\"]",
    "case \"hello\"    -> lower=\"hello\"      upper=\"HELLO\"        title=\"Hello\"      totitle=\"HELLO\"",
    "case \"HELLO\"    -> lower=\"hello\"      upper=\"HELLO\"        title=\"HELLO\"      totitle=\"HELLO\"",
    "case \"HeLlO\"    -> lower=\"hello\"      upper=\"HELLO\"        title=\"HeLlO\"      totitle=\"HELLO\"",
    "case \"\"         -> lower=\"\"           upper=\"\"             title=\"\"           totitle=\"\"",
    "case \"日本語\"      -> lower=\"日本語\"        upper=\"日本語\"          title=\"日本語\"        totitle=\"日本語\"",
    "case \"ǅungla\"   -> lower=\"ǆungla\"     upper=\"ǄUNGLA\"       title=\"ǅungla\"     totitle=\"ǅUNGLA\"",
    "case \"ß\"        -> lower=\"ß\"          upper=\"ß\"            title=\"ß\"          totitle=\"ß\"",
    "case \"İ\"        -> lower=\"i\"          upper=\"İ\"            title=\"İ\"          totitle=\"İ\"",
    "case \"ﬁ\"        -> lower=\"ﬁ\"          upper=\"ﬁ\"            title=\"ﬁ\"          totitle=\"ﬁ\"",
    "case \"ΣΣΣ\"      -> lower=\"σσσ\"        upper=\"ΣΣΣ\"          title=\"ΣΣΣ\"        totitle=\"ΣΣΣ\"",
    "case \"kelvin K\" -> lower=\"kelvin k\"   upper=\"KELVIN K\"     title=\"Kelvin K\"   totitle=\"KELVIN K\"",
    "equalfold \"Go\"     \"go\"     -> true",
    "equalfold \"K\"      \"k\"      -> true",
    "equalfold \"K\"      \"K\"      -> true",
    "equalfold \"ß\"      \"ss\"     -> false",
    "equalfold \"ß\"      \"SS\"     -> false",
    "equalfold \"ſ\"      \"s\"      -> true",
    "equalfold \"ſ\"      \"S\"      -> true",
    "equalfold \"\"       \"\"       -> true",
    "equalfold \"\"       \"x\"      -> false",
    "equalfold \"日本\"     \"日本\"     -> true",
    "equalfold \"ǅ\"      \"ǆ\"      -> true",
    "equalfold \"ǅ\"      \"Ǆ\"      -> true",
    "repeat \"ab\" 0  -> \"\"",
    "repeat \"ab\" 1  -> \"ab\"",
    "repeat \"ab\" 3  -> \"ababab\"",
    "repeat \"\"   5  -> \"\"",
    "repeat \"日\"  2  -> \"日日\"",
    "join [] \",\" -> \"\"",
    "join [] \",\" -> \"\"",
    "join [\"a\"] \",\" -> \"a\"",
    "join [\"a\" \"b\"] \",\" -> \"a,b\"",
    "join [\"a\" \"b\"] \"\"  -> \"ab\"",
    "join [\"\" \"\"] \"-\" -> \"-\"",
    "replace \"oink oink oink\" \"k\"   \"ky\" n=2   -> \"oinky oinky oink\"",
    "replace \"oink oink oink\" \"oink\" \"moo\" n=-1  -> \"moo moo moo\"",
    "replace \"banana\"         \"a\"   \"o\"  n=0   -> \"banana\"",
    "replace \"banana\"         \"a\"   \"o\"  n=1   -> \"bonana\"",
    "replace \"banana\"         \"a\"   \"o\"  n=-1  -> \"bonono\"",
    "replace \"abc\"            \"\"    \"-\"  n=-1  -> \"-a-b-c-\"",
    "replace \"abc\"            \"\"    \"-\"  n=2   -> \"-a-bc\"",
    "replace \"\"               \"\"    \"-\"  n=-1  -> \"-\"",
    "replace \"aaa\"            \"aa\"  \"b\"  n=-1  -> \"ba\"",
    "map drop-vowels \"hll wrld\"",
    "tovalid \"abc\"      \"?\"      -> \"abc\"",
    "tovalid \"a\\xffb\"   \"?\"      -> \"a?b\"",
    "tovalid \"a\\xffb\"   \"\"       -> \"ab\"",
    "tovalid \"\\xff\\xfe\" \"!\"      -> \"!\"",
    "tovalid \"\"         \"?\"      -> \"\"",
    "tovalid \"日本\\xff語\"  \"�\"      -> \"日本�語\"",
    "prefix \"Gopher\" \"Go\" -> has=true  suffix=false cmp=1",
    "prefix \"Gopher\" \"C\"  -> has=false suffix=false cmp=1",
    "prefix \"Gopher\" \"\"   -> has=true  suffix=true  cmp=1",
    "prefix \"\"       \"\"   -> has=true  suffix=true  cmp=0",
    "prefix \"\"       \"x\"  -> has=false suffix=false cmp=-1",
    "prefix \"Gopher\" \"her\" -> has=false suffix=true  cmp=-1",
    "prefix \"a\"      \"ab\" -> has=false suffix=false cmp=-1",
    "builder \"0-1-2-end!日\" len=13",
    "builder-reset \"\" len=0",
    "replacer \"&lt;Xb&gt;XhXi&lt;X/Xb&gt;X\"",
    "replacer-swap \"baba\"",
    "lines [\"a\\n\" \"b\\n\" \"\\n\" \"c\"]",
    "lines-empty []",
    "splitseq [\"a\" \"b\" \"c\"]",
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

    // 1
    let sp: [(&str, &str); 15] = [
        ("a,b,c", ","),
        ("a,b,c", ""),
        ("", ","),
        ("", ""),
        ("abc", ""),
        ("a", ","),
        (",", ","),
        (",,", ","),
        ("a,,b", ","),
        ("日本語", ""),
        ("a→b", "→"),
        ("banana", "an"),
        ("banana", "na"),
        ("aaa", "aa"),
        ("x", "xx"),
    ];
    for (a, sep) in sp.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "split %-8q %-4q -> %q",
                s(a),
                s(sep),
                strings::Split(s(a), s(sep))
            ),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "splitafter %-8q %-4q -> %q",
                s(a),
                s(sep),
                strings::SplitAfter(s(a), s(sep))
            ),
        );
    }
    for n in [-1 as int, 0, 1, 2, 3, 10] {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "splitn n=%-3d -> %q  after=%q",
                n,
                strings::SplitN(s("a,b,c,d"), s(","), n),
                strings::SplitAfterN(s("a,b,c,d"), s(","), n)
            ),
        );
    }
    // 2
    let ix: [(&str, &str); 9] = [
        ("chicken", "ken"),
        ("chicken", ""),
        ("", ""),
        ("", "a"),
        ("chicken", "xyz"),
        ("go gopher", "go"),
        ("aaa", "aa"),
        ("日本語", "本"),
        ("日本語", "語"),
    ];
    for (a, sub) in ix.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "index %-10q %-5q -> idx=%-3d last=%-3d count=%d contains=%v",
                s(a),
                s(sub),
                strings::Index(s(a), s(sub)),
                strings::LastIndex(s(a), s(sub)),
                strings::Count(s(a), s(sub)),
                strings::Contains(s(a), s(sub))
            ),
        );
    }
    for (a, ch) in [
        ("chicken", "aeiouy"),
        ("crwth", "aeiouy"),
        ("", "abc"),
        ("abc", ""),
        ("日本語", "本語"),
        ("abc", "cba"),
    ]
    .iter()
    {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "indexany %-8q %-8q -> any=%-3d lastany=%d",
                s(a),
                s(ch),
                strings::IndexAny(s(a), s(ch)),
                strings::LastIndexAny(s(a), s(ch))
            ),
        );
    }
    for (a, r) in [
        ("chicken", 'k' as rune),
        ("chicken", 'z' as rune),
        ("日本語", '本' as rune),
        ("", 'a' as rune),
        ("abc", 0x110000 as rune),
    ]
    .iter()
    {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "indexrune %-8q %-9q -> %d",
                s(a),
                *r,
                strings::IndexRune(s(a), *r)
            ),
        );
    }
    {
        // Go's input here is a RAW invalid byte, which a Rust &str
        // cannot hold; build the string from bytes instead.
        let bad = string::from_bytes(&[b'a', 0xff, b'b']);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "indexrune %-8q %-9q -> %d",
                bad.clone(),
                0xFFFD as rune,
                strings::IndexRune(bad, 0xFFFD as rune)
            ),
        );
    }
    for a in ["chicken", "", "日本語", "ABC"] {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "indexfunc %-8q upper=%-3d lastupper=%d",
                s(a),
                strings::IndexFunc(s(a), unicode::IsUpper),
                strings::LastIndexFunc(s(a), unicode::IsUpper)
            ),
        );
    }
    // 3
    for (a, cut) in [
        ("¡¡¡Hello!!!", "!¡"),
        ("xxhixx", "x"),
        ("xxhixx", "xh"),
        ("", "abc"),
        ("abc", ""),
        ("aaa", "a"),
        ("  hi  ", " "),
        ("\t\n hi \r\n", ""),
        ("日本語", "日語"),
    ]
    .iter()
    {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "trim %-14q %-5q -> t=%-12q l=%-12q r=%-12q space=%q",
                s(a),
                s(cut),
                strings::Trim(s(a), s(cut)),
                strings::TrimLeft(s(a), s(cut)),
                strings::TrimRight(s(a), s(cut)),
                strings::TrimSpace(s(a))
            ),
        );
    }
    for (a, p) in [
        ("hello", "he"),
        ("hello", "x"),
        ("hello", ""),
        ("hello", "hello"),
        ("hello", "hellox"),
        ("hello", "lo"),
    ]
    .iter()
    {
        let (cp, cpok) = strings::CutPrefix(s(a), s(p));
        let (cs, csok) = strings::CutSuffix(s(a), s(p));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "trimfix %-8q %-8q -> prefix=%-8q suffix=%-8q cutp=(%q,%v) cuts=(%q,%v)",
                s(a),
                s(p),
                strings::TrimPrefix(s(a), s(p)),
                strings::TrimSuffix(s(a), s(p)),
                cp,
                cpok,
                cs,
                csok
            ),
        );
    }
    // 4
    for (a, sep) in [
        ("a=b", "="),
        ("a=b=c", "="),
        ("abc", "="),
        ("", "="),
        ("a=b", ""),
        ("=b", "="),
        ("a=", "="),
    ]
    .iter()
    {
        let (before, after, found) = strings::Cut(s(a), s(sep));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "cut %-8q %-3q -> before=%-6q after=%-6q found=%v",
                s(a),
                s(sep),
                before,
                after,
                found
            ),
        );
    }
    // 5
    for a in [
        "  foo bar  baz   ",
        "",
        "   ",
        "a",
        "a\tb\nc\u{b}d\u{c}e\rf",
        "日 本 語",
        "\u{a0}x",
        "x\u{2028}y",
    ] {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("fields %-20q -> %q", s(a), strings::Fields(s(a))),
        );
    }
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "fieldsfunc %q -> %q",
            s("a1b2c3"),
            strings::FieldsFunc(s("a1b2c3"), unicode::IsDigit)
        ),
    );
    // 6
    for a in [
        "hello",
        "HELLO",
        "HeLlO",
        "",
        "日本語",
        "ǅungla",
        "ß",
        "İ",
        "ﬁ",
        "ΣΣΣ",
        "kelvin K",
    ] {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "case %-10q -> lower=%-12q upper=%-14q title=%-12q totitle=%q",
                s(a),
                strings::ToLower(s(a)),
                strings::ToUpper(s(a)),
                strings::Title(s(a)),
                strings::ToTitle(s(a))
            ),
        );
    }
    // 7
    for (a, b) in [
        ("Go", "go"),
        ("\u{212a}", "k"),
        ("K", "\u{212a}"),
        ("ß", "ss"),
        ("ß", "SS"),
        ("ſ", "s"),
        ("ſ", "S"),
        ("", ""),
        ("", "x"),
        ("日本", "日本"),
        ("ǅ", "ǆ"),
        ("ǅ", "Ǆ"),
    ]
    .iter()
    {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "equalfold %-8q %-8q -> %v",
                s(a),
                s(b),
                strings::EqualFold(s(a), s(b))
            ),
        );
    }
    // 8
    for (a, n) in [("ab", 0 as int), ("ab", 1), ("ab", 3), ("", 5), ("日", 2)].iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "repeat %-4q %-2d -> %q",
                s(a),
                *n,
                strings::Repeat(s(a), *n)
            ),
        );
    }
    let joins: [(&[&str], &str); 6] = [
        (&[], ","),
        (&[], ","),
        (&["a"], ","),
        (&["a", "b"], ","),
        (&["a", "b"], ""),
        (&["", ""], "-"),
    ];
    for (elems, sep) in joins.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "join %q %-3q -> %q",
                sl(elems),
                s(sep),
                strings::Join(sl(elems), s(sep))
            ),
        );
    }
    let reps: [(&str, &str, &str, int); 9] = [
        ("oink oink oink", "k", "ky", 2),
        ("oink oink oink", "oink", "moo", -1),
        ("banana", "a", "o", 0),
        ("banana", "a", "o", 1),
        ("banana", "a", "o", -1),
        ("abc", "", "-", -1),
        ("abc", "", "-", 2),
        ("", "", "-", -1),
        ("aaa", "aa", "b", -1),
    ];
    for (a, old, new_, n) in reps.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "replace %-16q %-5q %-4q n=%-3d -> %q",
                s(a),
                s(old),
                s(new_),
                *n,
                strings::Replace(s(a), s(old), s(new_), *n)
            ),
        );
    }
    // 9
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "map drop-vowels %q",
            strings::Map(
                |r: rune| -> rune {
                    if strings::ContainsRune(s("aeiou"), r) {
                        return -1;
                    }
                    return r;
                },
                s("hello world")
            )
        ),
    );
    let bads: [(&[u8], &str); 6] = [
        (b"abc", "?"),
        (&[b'a', 0xff, b'b'], "?"),
        (&[b'a', 0xff, b'b'], ""),
        (&[0xff, 0xfe], "!"),
        (b"", "?"),
        (
            &[0xe6, 0x97, 0xa5, 0xe6, 0x9c, 0xac, 0xff, 0xe8, 0xaa, 0x9e],
            "\u{fffd}",
        ),
    ];
    for (a, repl) in bads.iter() {
        let sa = string::from_bytes(a);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "tovalid %-10q %-8q -> %q",
                sa.clone(),
                s(repl),
                strings::ToValidUTF8(sa, s(repl))
            ),
        );
    }
    // 10
    for (a, b) in [
        ("Gopher", "Go"),
        ("Gopher", "C"),
        ("Gopher", ""),
        ("", ""),
        ("", "x"),
        ("Gopher", "her"),
        ("a", "ab"),
    ]
    .iter()
    {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "prefix %-8q %-4q -> has=%-5v suffix=%-5v cmp=%d",
                s(a),
                s(b),
                strings::HasPrefix(s(a), s(b)),
                strings::HasSuffix(s(a), s(b)),
                strings::Compare(s(a), s(b))
            ),
        );
    }
    // 11
    {
        let mut b = strings::Builder::new();
        for i in 0..3i64 {
            b.WriteString(fmt::Sprintf!("%d-", i));
        }
        b.WriteString(s("end"));
        b.WriteByte(b'!');
        b.WriteRune('日' as rune);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("builder %q len=%d", b.String(), b.Len()),
        );
        b.Reset();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("builder-reset %q len=%d", b.String(), b.Len()),
        );
    }
    {
        let r = strings::NewReplacer(sl(&["<", "&lt;", ">", "&gt;", "", "X"]));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("replacer %q", r.Replace(s("<b>hi</b>"))),
        );
        let r2 = strings::NewReplacer(sl(&["a", "b", "b", "a"]));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("replacer-swap %q", r2.Replace(s("abab"))),
        );
    }
    // 12
    {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("lines %q", slices::Collect(strings::Lines(s("a\nb\n\nc")))),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("lines-empty %q", slices::Collect(strings::Lines(s("")))),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "splitseq %q",
                slices::Collect(strings::SplitSeq(s("a,b,c"), s(",")))
            ),
        );
    }
    // This was a KNOWN GAP when this smoke was written: Go applies a
    // field width to EACH ELEMENT of a compound value and goish applied
    // it to the whole rendering. It is closed now — the width is
    // threaded into the compound renderers — so the assertion is Go's
    // answer rather than goish's, and it stays here because a
    // regression would be invisible everywhere else.
    {
        let v: slice<string> = slice::__from_vec(alloc::vec![s("a"), s("b")]);
        let got = fmt::Sprintf!("[%-16q]", v);
        if got != s("[[\"a\"              \"b\"             ]]") {
            fmt::Printf!("[!!] compound-width FAIL: %q\n", got);
            failed += 1;
        }
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
