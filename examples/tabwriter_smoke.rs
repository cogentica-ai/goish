// tabwriter_smoke — exercise the text/tabwriter package.
// (text/tabwriter/tabwriter.go)
//
// Checks 1-10 mirror Go's example_test.go (Init, elastic, trailingTab)
// plus edge cases. Check 11 replays sixteen formatted outputs printed
// by a running Go 1.25.5 (tools/gen_tabwriter_ref.go, run through
// scripts/goref.sh) — every flag, both escape modes, a ragged table, a
// form feed, and non-ASCII cells — comparing the bytes exactly.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::fmt;
use goish::string;
use goish::syscall;
use goish::text::tabwriter;
use goish::types::byte;

// Format `body` through a fresh tabwriter and return the resulting string.
fn run(
    body: &str,
    minwidth: goish::int,
    tabwidth: goish::int,
    padding: goish::int,
    padchar: byte,
    flags: goish::types::uint,
) -> goish::string {
    let mut buf = bytes::Buffer::new();
    {
        let mut w = tabwriter::NewWriter(&mut buf, minwidth, tabwidth, padding, padchar, flags);
        let s: goish::string = body.into();
        let bytes_slice = goish::bytes(s);
        let _ = w.Write(bytes_slice);
        let _ = w.Flush();
    }
    buf.String()
}

// Byte-level variant. Go string literals can hold a lone 0xFF (the
// tabwriter Escape byte); a Rust `&str` cannot, so the escape cases
// have to go in as bytes.
fn run_bytes(
    body: &[u8],
    minwidth: goish::int,
    tabwidth: goish::int,
    padding: goish::int,
    padchar: byte,
    flags: goish::types::uint,
) -> alloc::vec::Vec<byte> {
    let mut buf = bytes::Buffer::new();
    {
        let mut w = tabwriter::NewWriter(&mut buf, minwidth, tabwidth, padding, padchar, flags);
        let _ = w.Write(goish::goslice::slice::<byte>::__from_vec(body.to_vec()));
        let _ = w.Flush();
    }
    let out = buf.Bytes();
    let raw: &[byte] = &out;
    raw.to_vec()
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Tab-padded, minwidth=0 tabwidth=8 padding=0 padchar='\t'.
    {
        // Mirror of ExampleWriter_Init first half. Column widths:
        //   col 0 max=3 (123)         → cellw rounded to 8 → 1 tab pads "a" or "123".
        //   col 1 max=5 (12345)       → cellw=8 → 1 tab pads "b" or "12345".
        //   col 2 max=7 (1234567)     → cellw=8 → 1 tab pads "c" or "1234567".
        //   col 3 max=9 (123456789)   → cellw=16 → "d" needs 2 tabs to reach 16
        //                                          "123456789" needs 1 tab.
        let got = run(
            "a\tb\tc\td\t.\n123\t12345\t1234567\t123456789\t.\n\n",
            0,
            8,
            0,
            b'\t',
            0,
        );
        let want: goish::string = "a\tb\tc\td\t\t.\n123\t12345\t1234567\t123456789\t.\n\n".into();
        if got == want {
            fmt::Println!("[ 1] tab-padded minwidth=0      PASS");
        } else {
            fmt::Println!("[ 1] tab-padded minwidth=0      FAIL");
            failed += 1;
        }
    }

    // 2. Right-aligned, minwidth=5 padding=1 padchar=' '.
    {
        // Mirror of ExampleWriter_Init second half.
        let got = run(
            "a\tb\tc\td\t.\n123\t12345\t1234567\t123456789\t.\n\n",
            5,
            0,
            1,
            b' ',
            tabwriter::AlignRight,
        );
        let want = string("    a     b       c         d.\n  123 12345 1234567 123456789.\n\n");
        if got == want {
            fmt::Println!("[ 2] right-aligned minwidth=5   PASS");
        } else {
            fmt::Println!("[ 2] right-aligned minwidth=5   FAIL");
            failed += 1;
        }
    }

    // 3. Elastic-tabstops with debug bars (Go Example_elastic).
    {
        let got = run(
            "a\tb\tc\naa\tbb\tcc\naaa\t\naaaa\tdddd\teeee\n",
            0,
            0,
            1,
            b'.',
            tabwriter::AlignRight | tabwriter::Debug,
        );
        let want = string("....a|..b|c\n...aa|.bb|cc\n..aaa|\n.aaaa|.dddd|eeee\n");
        if got == want {
            fmt::Println!("[ 3] elastic + debug bars       PASS");
        } else {
            fmt::Println!("[ 3] elastic + debug bars       FAIL");
            failed += 1;
        }
    }

    // 4. Trailing-tab vs. no-trailing-tab (Go Example_trailingTab).
    {
        let got = run(
            "a\tb\taligned\t\naa\tbb\taligned\t\naaa\tbbb\tunaligned\naaaa\tbbbb\taligned\t\n",
            0,
            0,
            3,
            b'-',
            tabwriter::AlignRight | tabwriter::Debug,
        );
        let want = string(
            "------a|------b|---aligned|\n-----aa|-----bb|---aligned|\n----aaa|----bbb|unaligned\n---aaaa|---bbbb|---aligned|\n",
        );
        if got == want {
            fmt::Println!("[ 4] trailing-tab discipline    PASS");
        } else {
            fmt::Println!("[ 4] trailing-tab discipline    FAIL");
            failed += 1;
        }
    }

    // 5. Empty input flushes to empty output.
    {
        let got = run("", 0, 8, 0, b' ', 0);
        if got == "" {
            fmt::Println!("[ 5] empty input                PASS");
        } else {
            fmt::Println!("[ 5] empty input                FAIL");
            failed += 1;
        }
    }

    // 6. Single line, no tabs — passed through verbatim.
    {
        let got = run("hello world\n", 0, 8, 0, b' ', 0);
        if got == "hello world\n" {
            fmt::Println!("[ 6] no-tabs passthrough        PASS");
        } else {
            fmt::Println!("[ 6] no-tabs passthrough        FAIL");
            failed += 1;
        }
    }

    // 7. Left-align, space-padded, minwidth=4 padding=2.
    {
        let got = run("a\tb\nccc\tdd\n", 4, 0, 2, b' ', 0);
        // Column 0 widths: max(1+2, 3+2) = 5 → first col padded to 5.
        // "a" → 1 byte text + 4 spaces; "ccc" → 3 bytes + 2 spaces.
        let want: goish::string = "a    b\nccc  dd\n".into();
        if got == want {
            fmt::Println!("[ 7] left-align padding=2       PASS");
        } else {
            fmt::Println!("[ 7] left-align padding=2       FAIL");
            failed += 1;
        }
    }

    // 8. DiscardEmptyColumns drops a soft-tab-only column.
    {
        // Vertical tab '\v' is "soft" — discardable when DiscardEmptyColumns set.
        // Each line: cell0 \t cell1 \v cell2 \n. cell1 is empty everywhere,
        // separated by '\v', so column 1 is discardable.
        let got = run(
            "a\t\u{000b}c\nbb\t\u{000b}dd\n",
            0,
            0,
            1,
            b' ',
            tabwriter::DiscardEmptyColumns,
        );
        // Column 0: max("a"=1, "bb"=2)+padding=3, so first col width = 3.
        // Column 1: discarded (width=0).
        // Column 2: last (not aligned).
        let want = string("a  c\nbb dd\n");
        if got == want {
            fmt::Println!("[ 8] DiscardEmptyColumns        PASS");
        } else {
            fmt::Println!("[ 8] DiscardEmptyColumns        FAIL");
            failed += 1;
        }
    }

    // 9. Multi-byte (UTF-8) width counted in runes.
    {
        // 'é' = 0xC3 0xA9 (2 bytes, 1 rune).
        let got = run("é\tx\néé\tyy\n", 0, 0, 1, b' ', 0);
        // Column 0 widths: 1+1=2 vs 2+1=3 → 3 runes.
        // Output uses spaces for padding so width-by-rune controls layout.
        let want = string("é  x\néé yy\n");
        if got == want {
            fmt::Println!("[ 9] UTF-8 rune-width padding   PASS");
        } else {
            fmt::Println!("[ 9] UTF-8 rune-width padding   FAIL");
            failed += 1;
        }
    }

    // 10. Formfeed forces flush. The two columns before \f must size
    //     independently from those after — without \f they would share
    //     column-0 width. Note: the formfeed also terminates a line, so
    //     a blank line appears between the two sections in the output
    //     (matching Go's tabwriter behavior).
    {
        let got = run("aaa\tx\n\u{000c}y\tzzzz\n", 0, 0, 1, b'.', 0);
        // Section 1: "aaa\tx\n" + blank line from \f → "aaa.x\n\n".
        // Section 2: "y\tzzzz\n" → col 0 width=1+padding=2 → "y.zzzz\n".
        let want: goish::string = "aaa.x\n\ny.zzzz\n".into();
        if got == want {
            fmt::Println!("[10] formfeed forces re-align   PASS");
        } else {
            fmt::Println!("[10] formfeed forces re-align   FAIL");
            failed += 1;
        }
    }

    // 11. Sixteen Go-printed outputs, byte for byte. Column widths are
    //     the whole product of this package, so a table that merely
    //     "looks aligned" is not evidence; these are Go's bytes.
    {
        let cases: [(
            &str,
            goish::int,
            goish::int,
            goish::int,
            byte,
            goish::types::uint,
            &str,
            &str,
        ); 14] = [
            (
                "default",
                0,
                8,
                1,
                b' ',
                0,
                "a\tbbb\tcc\nddddd\te\tfff\n",
                "a     bbb cc\nddddd e   fff\n",
            ),
            (
                "minwidth5",
                5,
                8,
                1,
                b' ',
                0,
                "a\tbbb\tcc\nddddd\te\tfff\n",
                "a     bbb  cc\nddddd e    fff\n",
            ),
            (
                "padding3",
                0,
                8,
                3,
                b' ',
                0,
                "a\tbbb\tcc\nddddd\te\tfff\n",
                "a       bbb   cc\nddddd   e     fff\n",
            ),
            (
                "alignright",
                0,
                8,
                1,
                b' ',
                tabwriter::AlignRight,
                "a\tbbb\tcc\nddddd\te\tfff\n",
                "     a bbbcc\n ddddd   efff\n",
            ),
            (
                "tabindent",
                0,
                8,
                1,
                b'\t',
                tabwriter::TabIndent,
                "a\tbbb\tcc\nddddd\te\tfff\n",
                "a\tbbb\tcc\nddddd\te\tfff\n",
            ),
            (
                "debug",
                0,
                8,
                1,
                b' ',
                tabwriter::Debug,
                "a\tbbb\tcc\nddddd\te\tfff\n",
                "a     |bbb |cc\nddddd |e   |fff\n",
            ),
            (
                "discardempty",
                0,
                8,
                1,
                b' ',
                tabwriter::DiscardEmptyColumns,
                "a\t\tb\nc\t\td\n",
                "a  b\nc  d\n",
            ),
            (
                "ragged",
                0,
                8,
                1,
                b' ',
                0,
                "a\tb\tc\nd\te\n f\n",
                "a b c\nd e\n f\n",
            ),
            ("trailing-nonl", 0, 8, 1, b' ', 0, "a\tb\tc", "a b c"),
            ("empty", 0, 8, 1, b' ', 0, "", ""),
            ("vertical-tab", 0, 8, 1, b' ', 0, "a\x0bb\tc\n", "a b c\n"),
            (
                "formfeed",
                0,
                8,
                1,
                b' ',
                0,
                "a\tb\n\x0ccc\tdd\n",
                "a b\n\ncc dd\n",
            ),
            (
                "html",
                0,
                8,
                1,
                b' ',
                tabwriter::FilterHTML,
                "a\t<b>bb</b>\tc\nddd\te\tf\n",
                "a   <b>bb</b> c\nddd e  f\n",
            ),
            (
                "unicode",
                0,
                8,
                1,
                b' ',
                0,
                "é\tab\ncdé\tx\n",
                "é   ab\ncdé x\n",
            ),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < cases.len() {
            let (_name, mw, tw, pad, pc, fl, input, want) = cases[k];
            let got = run(input, mw, tw, pad, pc, fl);
            if got != want {
                bad += 1;
                fmt::Println!("     mismatch:", _name);
            }
            k += 1;
        }
        if bad == 0 {
            fmt::Println!("[11] 14 layouts vs Go        PASS");
        } else {
            fmt::Println!("[11] 14 layouts vs Go        FAIL");
            failed += 1;
        }
    }

    // 12. The Escape byte (0xFF) brackets a segment so the tab inside
    //     it does not terminate a cell. Go string literals can hold a
    //     lone 0xFF; Rust `&str` cannot, so these go in as bytes —
    //     which is also the only way to see that StripEscape removes
    //     the brackets while keeping the segment one cell wide.
    {
        let input: &[u8] = b"a\t\xffb\tb\xff\tc\n1\t2\t3\n";
        let got = run_bytes(input, 0, 8, 1, b' ', 0);
        let want: &[u8] = b"a \xffb\tb\xff c\n1 2   3\n";
        let got2 = run_bytes(input, 0, 8, 1, b' ', tabwriter::StripEscape);
        let want2: &[u8] = b"a b\tb c\n1 2   3\n";
        if got.as_slice() == want && got2.as_slice() == want2 {
            fmt::Println!("[12] Escape/StripEscape vs Go PASS");
        } else {
            fmt::Println!("[12] Escape/StripEscape vs Go FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
