// tabwriter_ref_smoke — text/tabwriter against a running Go.
// (text/tabwriter/tabwriter.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_tabwriter_ref.go` run in
// `package tabwriter_test` by `scripts/goref.sh`.
//
// tabwriter aligns columns, and every one of its rules is about where a
// COLUMN ENDS rather than about spacing. That is what makes it easy to
// get subtly wrong while the common case still looks aligned — the
// output is always plausible, so nothing short of a reference catches
// it. goish matched Go on all 106 lines, across nine configurations
// crossed with eleven inputs.
//
// The rules that are pinned:
//
//   * A "column block" is a run of ADJACENT lines that all have a cell
//     in that position, and a line with FEWER cells terminates the
//     block — so the lines above and below it are widened
//     independently. `short-line-splits` is the case: a port that
//     widens the whole output to one global width looks right until a
//     short line appears in the middle.
//   * The LAST cell of a line has no trailing tab, so it is not part of
//     any column and never contributes to a width.
//   * Widths count RUNES, not bytes, so a CJK column lines up with an
//     ASCII one by character count. (goish already routed this through
//     utf8::RuneCount — unlike fmt's field width, which counted bytes
//     until 765ea47.)
//   * The width of a column is max(minwidth, widest cell + padding),
//     and a padchar of '\t' makes the output tab-TERMINATED rather
//     than space-padded, which changes the unit to tabwidth.
//   * AlignRight, DiscardEmptyColumns, TabIndent, FilterHTML,
//     StripEscape and Debug each change the answer, and each is crossed
//     with every input here.
//   * Text between two Escape bytes is one cell whatever it contains,
//     including tabs and newlines; StripEscape removes the markers from
//     the output but not the grouping.
//   * Writing one byte at a time gives the same output as one Write,
//     and Flush is idempotent with more writing allowed after it.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::syscall;
use goish::text::tabwriter;
use goish::types::{byte, int, uint};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn bs(x: &str) -> slice<byte> {
    return slice::__from_vec(x.as_bytes().to_vec());
}
fn et(e: &error) -> string {
    if e.IsNil() {
        return s("<nil>");
    }
    return e.Error();
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 106] = [
    "tw default       simple             -> \"a bb ccc\\n1 2  3\\n\" err=<nil>",
    "tw default       ragged             -> \"a      bb ccc\\nlonger x\\n1      2 3\\n\" err=<nil>",
    "tw default       short-line-splits  -> \"aaa b\\nx\\nccccc d\\n\" err=<nil>",
    "tw default       trailing-tab       -> \"a b \\nc d \\n\" err=<nil>",
    "tw default       empty-cells        -> \"a  c\\nd  f\\n\" err=<nil>",
    "tw default       one-column         -> \"a\\nbb\\nccc\\n\" err=<nil>",
    "tw default       no-newline         -> \"a b\" err=<nil>",
    "tw default       empty              -> \"\" err=<nil>",
    "tw default       blank-line         -> \"a b\\n\\nc d\\n\" err=<nil>",
    "tw default       cjk                -> \"日本 x\\nab y\\n\" err=<nil>",
    "tw default       wide-first         -> \"aaaaaaaa b\\nc        d\\n\" err=<nil>",
    "tw min5          simple             -> \"a    bb   ccc\\n1    2    3\\n\" err=<nil>",
    "tw min5          ragged             -> \"a      bb   ccc\\nlonger x\\n1      2    3\\n\" err=<nil>",
    "tw min5          short-line-splits  -> \"aaa  b\\nx\\nccccc d\\n\" err=<nil>",
    "tw min5          trailing-tab       -> \"a    b    \\nc    d    \\n\" err=<nil>",
    "tw min5          empty-cells        -> \"a         c\\nd         f\\n\" err=<nil>",
    "tw min5          one-column         -> \"a\\nbb\\nccc\\n\" err=<nil>",
    "tw min5          no-newline         -> \"a    b\" err=<nil>",
    "tw min5          empty              -> \"\" err=<nil>",
    "tw min5          blank-line         -> \"a    b\\n\\nc    d\\n\" err=<nil>",
    "tw min5          cjk                -> \"日本   x\\nab   y\\n\" err=<nil>",
    "tw min5          wide-first         -> \"aaaaaaaa b\\nc        d\\n\" err=<nil>",
    "tw pad3          simple             -> \"a   bb   ccc\\n1   2    3\\n\" err=<nil>",
    "tw pad3          ragged             -> \"a        bb   ccc\\nlonger   x\\n1        2   3\\n\" err=<nil>",
    "tw pad3          short-line-splits  -> \"aaa   b\\nx\\nccccc   d\\n\" err=<nil>",
    "tw pad3          trailing-tab       -> \"a   b   \\nc   d   \\n\" err=<nil>",
    "tw pad3          empty-cells        -> \"a      c\\nd      f\\n\" err=<nil>",
    "tw pad3          one-column         -> \"a\\nbb\\nccc\\n\" err=<nil>",
    "tw pad3          no-newline         -> \"a   b\" err=<nil>",
    "tw pad3          empty              -> \"\" err=<nil>",
    "tw pad3          blank-line         -> \"a   b\\n\\nc   d\\n\" err=<nil>",
    "tw pad3          cjk                -> \"日本   x\\nab   y\\n\" err=<nil>",
    "tw pad3          wide-first         -> \"aaaaaaaa   b\\nc          d\\n\" err=<nil>",
    "tw dots          simple             -> \"a.bb.ccc\\n1.2..3\\n\" err=<nil>",
    "tw dots          ragged             -> \"a......bb.ccc\\nlonger.x\\n1......2.3\\n\" err=<nil>",
    "tw dots          short-line-splits  -> \"aaa.b\\nx\\nccccc.d\\n\" err=<nil>",
    "tw dots          trailing-tab       -> \"a.b.\\nc.d.\\n\" err=<nil>",
    "tw dots          empty-cells        -> \"a..c\\nd..f\\n\" err=<nil>",
    "tw dots          one-column         -> \"a\\nbb\\nccc\\n\" err=<nil>",
    "tw dots          no-newline         -> \"a.b\" err=<nil>",
    "tw dots          empty              -> \"\" err=<nil>",
    "tw dots          blank-line         -> \"a.b\\n\\nc.d\\n\" err=<nil>",
    "tw dots          cjk                -> \"日本.x\\nab.y\\n\" err=<nil>",
    "tw dots          wide-first         -> \"aaaaaaaa.b\\nc........d\\n\" err=<nil>",
    "tw tabpad        simple             -> \"a\\tbb\\tccc\\n1\\t2\\t3\\n\" err=<nil>",
    "tw tabpad        ragged             -> \"a\\t\\tbb\\tccc\\nlonger\\tx\\n1\\t\\t2\\t3\\n\" err=<nil>",
    "tw tabpad        short-line-splits  -> \"aaa\\tb\\nx\\nccccc\\td\\n\" err=<nil>",
    "tw tabpad        trailing-tab       -> \"a\\tb\\t\\nc\\td\\t\\n\" err=<nil>",
    "tw tabpad        empty-cells        -> \"a\\t\\tc\\nd\\t\\tf\\n\" err=<nil>",
    "tw tabpad        one-column         -> \"a\\nbb\\nccc\\n\" err=<nil>",
    "tw tabpad        no-newline         -> \"a\\tb\" err=<nil>",
    "tw tabpad        empty              -> \"\" err=<nil>",
    "tw tabpad        blank-line         -> \"a\\tb\\n\\nc\\td\\n\" err=<nil>",
    "tw tabpad        cjk                -> \"日本\\tx\\nab\\ty\\n\" err=<nil>",
    "tw tabpad        wide-first         -> \"aaaaaaaa\\tb\\nc\\t\\t\\td\\n\" err=<nil>",
    "tw alignright    simple             -> \" a bbccc\\n 1  23\\n\" err=<nil>",
    "tw alignright    ragged             -> \"      a bbccc\\n longerx\\n      1 23\\n\" err=<nil>",
    "tw alignright    short-line-splits  -> \" aaab\\nx\\n cccccd\\n\" err=<nil>",
    "tw alignright    trailing-tab       -> \" a b\\n c d\\n\" err=<nil>",
    "tw alignright    empty-cells        -> \" a c\\n d f\\n\" err=<nil>",
    "tw alignright    one-column         -> \"a\\nbb\\nccc\\n\" err=<nil>",
    "tw alignright    no-newline         -> \" ab\" err=<nil>",
    "tw alignright    empty              -> \"\" err=<nil>",
    "tw alignright    blank-line         -> \" ab\\n\\n cd\\n\" err=<nil>",
    "tw alignright    cjk                -> \" 日本x\\n aby\\n\" err=<nil>",
    "tw alignright    wide-first         -> \" aaaaaaaab\\n        cd\\n\" err=<nil>",
    "tw debug         simple             -> \"a |bb |ccc\\n1 |2  |3\\n\" err=<nil>",
    "tw debug         ragged             -> \"a      |bb |ccc\\nlonger |x\\n1      |2 |3\\n\" err=<nil>",
    "tw debug         short-line-splits  -> \"aaa |b\\nx\\nccccc |d\\n\" err=<nil>",
    "tw debug         trailing-tab       -> \"a |b |\\nc |d |\\n\" err=<nil>",
    "tw debug         empty-cells        -> \"a | |c\\nd | |f\\n\" err=<nil>",
    "tw debug         one-column         -> \"a\\nbb\\nccc\\n\" err=<nil>",
    "tw debug         no-newline         -> \"a |b\" err=<nil>",
    "tw debug         empty              -> \"\" err=<nil>",
    "tw debug         blank-line         -> \"a |b\\n\\nc |d\\n\" err=<nil>",
    "tw debug         cjk                -> \"日本 |x\\nab |y\\n\" err=<nil>",
    "tw debug         wide-first         -> \"aaaaaaaa |b\\nc        |d\\n\" err=<nil>",
    "tw tabindent     simple             -> \"a\\tbb\\tccc\\n1\\t2\\t3\\n\" err=<nil>",
    "tw tabindent     ragged             -> \"a\\t\\tbb\\tccc\\nlonger\\tx\\n1\\t\\t2\\t3\\n\" err=<nil>",
    "tw tabindent     short-line-splits  -> \"aaa\\tb\\nx\\nccccc\\td\\n\" err=<nil>",
    "tw tabindent     trailing-tab       -> \"a\\tb\\t\\nc\\td\\t\\n\" err=<nil>",
    "tw tabindent     empty-cells        -> \"a\\t\\tc\\nd\\t\\tf\\n\" err=<nil>",
    "tw tabindent     one-column         -> \"a\\nbb\\nccc\\n\" err=<nil>",
    "tw tabindent     no-newline         -> \"a\\tb\" err=<nil>",
    "tw tabindent     empty              -> \"\" err=<nil>",
    "tw tabindent     blank-line         -> \"a\\tb\\n\\nc\\td\\n\" err=<nil>",
    "tw tabindent     cjk                -> \"日本\\tx\\nab\\ty\\n\" err=<nil>",
    "tw tabindent     wide-first         -> \"aaaaaaaa\\tb\\nc\\t\\t\\td\\n\" err=<nil>",
    "tw discardempty  simple             -> \"a bb ccc\\n1 2  3\\n\" err=<nil>",
    "tw discardempty  ragged             -> \"a      bb ccc\\nlonger x\\n1      2 3\\n\" err=<nil>",
    "tw discardempty  short-line-splits  -> \"aaa b\\nx\\nccccc d\\n\" err=<nil>",
    "tw discardempty  trailing-tab       -> \"a b \\nc d \\n\" err=<nil>",
    "tw discardempty  empty-cells        -> \"a  c\\nd  f\\n\" err=<nil>",
    "tw discardempty  one-column         -> \"a\\nbb\\nccc\\n\" err=<nil>",
    "tw discardempty  no-newline         -> \"a b\" err=<nil>",
    "tw discardempty  empty              -> \"\" err=<nil>",
    "tw discardempty  blank-line         -> \"a b\\n\\nc d\\n\" err=<nil>",
    "tw discardempty  cjk                -> \"日本 x\\nab y\\n\" err=<nil>",
    "tw discardempty  wide-first         -> \"aaaaaaaa b\\nc        d\\n\" err=<nil>",
    "esc html-off       -> \"a<b>c x\\ndd    y\\n\" err=<nil>",
    "esc html-on        -> \"a<b>c x\\ndd y\\n\" err=<nil>",
    "esc entity-on      -> \"a&amp;b x\\ndd  y\\n\" err=<nil>",
    "esc escaped        -> \"\\xffa\\tb\\xff x\\ncc  y\\n\" err=<nil>",
    "esc escaped-strip  -> \"a\\tb x\\ncc  y\\n\" err=<nil>",
    "incremental same=true out=\"aaa b\\nc   ddd\\n\"",
    "reflush out=\"a b\\ncc dd\\n\"",
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

    let inputs: [(&str, &str); 11] = [
        ("simple", "a\tbb\tccc\n1\t2\t3\n"),
        ("ragged", "a\tbb\tccc\nlonger\tx\n1\t2\t3\n"),
        ("short-line-splits", "aaa\tb\nx\nccccc\td\n"),
        ("trailing-tab", "a\tb\t\nc\td\t\n"),
        ("empty-cells", "a\t\tc\nd\t\tf\n"),
        ("one-column", "a\nbb\nccc\n"),
        ("no-newline", "a\tb"),
        ("empty", ""),
        ("blank-line", "a\tb\n\nc\td\n"),
        ("cjk", "日本\tx\nab\ty\n"),
        ("wide-first", "aaaaaaaa\tb\nc\td\n"),
    ];
    let configs: [(&str, int, int, int, u8, uint); 9] = [
        ("default", 0, 8, 1, b' ', 0),
        ("min5", 5, 8, 1, b' ', 0),
        ("pad3", 0, 8, 3, b' ', 0),
        ("dots", 0, 8, 1, b'.', 0),
        ("tabpad", 0, 4, 1, b'\t', 0),
        ("alignright", 0, 8, 1, b' ', tabwriter::AlignRight),
        ("debug", 0, 8, 1, b' ', tabwriter::Debug),
        ("tabindent", 0, 4, 1, b'\t', tabwriter::TabIndent),
        (
            "discardempty",
            0,
            8,
            1,
            b' ',
            tabwriter::DiscardEmptyColumns,
        ),
    ];
    for (cname, minw, tabw, pad, padc, flags) in configs.iter() {
        for (iname, inp) in inputs.iter() {
            let mut buf = bytes::Buffer::new();
            let err = {
                let mut w = tabwriter::NewWriter(&mut buf, *minw, *tabw, *pad, *padc, *flags);
                let _ = w.Write(bs(inp));
                w.Flush()
            };
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "tw %-13s %-18s -> %q err=%v",
                    s(cname),
                    s(iname),
                    buf.String(),
                    et(&err)
                ),
            );
        }
    }
    // Escape and FilterHTML.
    // tabwriter::Escape is 0xff, which is not valid UTF-8, so the
    // escaped input is built from raw bytes rather than a &str.
    let mut escaped: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    escaped.push(tabwriter::Escape);
    escaped.extend_from_slice(b"a\tb");
    escaped.push(tabwriter::Escape);
    escaped.extend_from_slice(b"\tx\ncc\ty\n");
    let cases: [(&str, &[u8], uint); 5] = [
        ("html-off", b"a<b>c\tx\ndd\ty\n", 0),
        ("html-on", b"a<b>c\tx\ndd\ty\n", tabwriter::FilterHTML),
        ("entity-on", b"a&amp;b\tx\ndd\ty\n", tabwriter::FilterHTML),
        ("escaped", &escaped, 0),
        ("escaped-strip", &escaped, tabwriter::StripEscape),
    ];
    for (name, inp, flags) in cases.iter() {
        let mut buf = bytes::Buffer::new();
        let err = {
            let mut w = tabwriter::NewWriter(&mut buf, 0, 8, 1, b' ', *flags);
            let _ = w.Write(slice::__from_vec(inp.to_vec()));
            w.Flush()
        };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("esc %-14s -> %q err=%v", s(name), buf.String(), et(&err)),
        );
    }
    // Incremental writes must equal one write.
    {
        let full = "aaa\tb\nc\tddd\n";
        let mut one = bytes::Buffer::new();
        {
            let mut w1 = tabwriter::NewWriter(&mut one, 0, 8, 1, b' ', 0);
            let _ = w1.Write(bs(full));
            let _ = w1.Flush();
        }
        let mut many = bytes::Buffer::new();
        {
            let mut w2 = tabwriter::NewWriter(&mut many, 0, 8, 1, b' ', 0);
            for b in full.as_bytes() {
                let _ = w2.Write(slice::__from_vec(alloc::vec![*b]));
            }
            let _ = w2.Flush();
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "incremental same=%v out=%q",
                one.String() == many.String(),
                many.String()
            ),
        );
    }
    // Flush twice, and write after a flush.
    {
        let mut buf = bytes::Buffer::new();
        {
            let mut w = tabwriter::NewWriter(&mut buf, 0, 8, 1, b' ', 0);
            let _ = w.Write(bs("a\tb\n"));
            let _ = w.Flush();
            let _ = w.Flush();
            let _ = w.Write(bs("cc\tdd\n"));
            let _ = w.Flush();
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reflush out=%q", buf.String()),
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
