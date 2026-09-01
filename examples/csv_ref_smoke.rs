// csv_ref_smoke — encoding/csv against a running Go.
// (encoding/csv/{reader,writer}.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_csv_ref.go` run in `package csv_test` by
// `scripts/goref.sh`. The tables are GENERATED from that output rather
// than typed.
//
// A CSV reader is a parser with a long tail, and every wrong answer in
// it still yields records: a quote inside a quoted field, a bare quote
// in a bare field, a record whose field count changes, CRLF versus LF,
// a comment line, and leading space that is significant unless
// TrimLeadingSpace says otherwise.
//
// All 53 reference lines agree. What is pinned, beyond the ordinary
// rows: the three parse errors with their exact line and column —
// `bare " in non-quoted-field` at column 4 of `a,b"c`, and
// `extraneous or missing " in quoted-field` at column 5 of both
// `a,"b` and `a,"b"c` — the three inputs LazyQuotes turns from an
// error into a record, the wrong-field-count error and the
// FieldsPerRecord = -1 that switches it off, `a, "b"` being an error
// WITHOUT TrimLeadingSpace and a clean record with it, the leading BOM
// being kept as part of the first field rather than stripped, a lone
// `\r` surviving inside a field while `\r\n` is a terminator, and
// FieldPos/InputOffset after two reads.
//
// On the writing side: which values force quoting (a comma, a quote, a
// newline, a bare `\r`, a LEADING space — but not a trailing one, and
// not a tab), the doubled quote, UseCRLF, a non-default Comma, and the
// invalid-delimiter error that a `"` as Comma produces.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::encoding::csv;
use goish::gostring::string;
use goish::types::{int, rune};
use goish::{fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// go: none — goish idiom: render the records the way Go's `%q` of a
//     [][]string does, so the generated table compares directly.
fn render(v: &slice<slice<string>>) -> string {
    let mut out = s("[");
    let mut i = 0usize;
    while i < v.len() {
        if i > 0 {
            out = out + s(" ");
        }
        out = out + s("[");
        let mut j = 0usize;
        while j < v[i].len() {
            if j > 0 {
                out = out + s(" ");
            }
            out = out + fmt::Sprintf!("%q", v[i][j].clone());
            j += 1;
        }
        out = out + s("]");
        i += 1;
    }
    return out + s("]");
}

// (records rendered as Go prints them, error text or "") for each
// case in the smoke's table, in order.
const READ: [(&str, &str); 36] = [
    ("[[\"a\" \"b\" \"c\"]]", ""),
    ("[[\"a\" \"b\" \"c\"]]", ""),
    ("[[\"a\" \"b\" \"c\"]]", ""),
    ("[[\"a\" \"b\" \"c\"] [\"d\" \"e\" \"f\"]]", ""),
    ("[]", ""),
    ("[]", ""),
    ("[]", ""),
    ("[[\"a\"] [\"b\"]]", ""),
    ("[[\"a\" \"b\"]]", ""),
    ("[[\"a\\\"b\"]]", ""),
    ("[[\"a\\nb\"]]", ""),
    ("[[\"a,b\" \"c\"]]", ""),
    (
        "[]",
        "parse error on line 1, column 5: extraneous or missing \" in quoted-field",
    ),
    (
        "[]",
        "parse error on line 1, column 4: bare \" in non-quoted-field",
    ),
    (
        "[]",
        "parse error on line 1, column 5: extraneous or missing \" in quoted-field",
    ),
    ("[[\"a\" \"b\\\"c\"]]", ""),
    ("[[\"a\" \"b\\\"c\"]]", ""),
    ("[[\"a\" \"b\"]]", ""),
    ("[]", "record on line 2: wrong number of fields"),
    ("[[\"a\" \"b\"] [\"c\"]]", ""),
    ("[]", "record on line 2: wrong number of fields"),
    ("[[\"a\" \"b\" \"c\"]]", ""),
    ("[[\"a\" \"b\"]]", ""),
    ("[[\"a\" \"b\"]]", ""),
    ("[[\"a\" \"b\"] [\"c\" \"d\"]]", ""),
    ("[[\" a\" \" b\"]]", ""),
    ("[[\"a\" \"b\"]]", ""),
    (
        "[]",
        "parse error on line 1, column 4: bare \" in non-quoted-field",
    ),
    ("[[\"a\" \"b\"]]", ""),
    ("[[\"a\" \"\" \"b\"]]", ""),
    ("[[\"\" \"\"]]", ""),
    ("[[\"a\" \"b\" \"\"]]", ""),
    ("[[\"\"]]", ""),
    ("[[\"a\\r\\rb\"]]", ""),
    ("[[\"a\" \"b\"] [\"c\" \"d\"]]", ""),
    ("[[\"\\ufeffa\" \"b\"]]", ""),
];

const WRITE: [(&str, &str); 12] = [
    ("a,b\n", ""),
    ("\"a,b\",c\n", ""),
    ("\"a\"\"b\"\n", ""),
    ("\"a\nb\"\n", ""),
    ("\"a\rb\"\n", ""),
    ("\" a\"\n", ""),
    ("a \n", ""),
    ("\n", ""),
    (",\n", ""),
    ("\"\\.\"\n", ""),
    ("a\tb\n", ""),
    ("héllo\n", ""),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ReadAll over 36 inputs, each with its own Comma, Comment,
    //    FieldsPerRecord, LazyQuotes and TrimLeadingSpace, compared
    //    against Go's records AND its exact error text.
    {
        let mut ok = true;
        // (input, comma, comment, fieldsPerRecord, lazy, trim)
        let cases: [(&str, rune, rune, int, bool, bool); 36] = [
            ("a,b,c\n", 0, 0, 0, false, false),
            ("a,b,c", 0, 0, 0, false, false),
            ("a,b,c\r\n", 0, 0, 0, false, false),
            ("a,b,c\nd,e,f\n", 0, 0, 0, false, false),
            ("", 0, 0, 0, false, false),
            ("\n", 0, 0, 0, false, false),
            ("\n\n", 0, 0, 0, false, false),
            ("a\n\nb\n", 0, 0, 0, false, false),
            ("\"a\",\"b\"", 0, 0, 0, false, false),
            ("\"a\"\"b\"", 0, 0, 0, false, false),
            ("\"a\nb\"", 0, 0, 0, false, false),
            ("\"a,b\",c", 0, 0, 0, false, false),
            ("a,\"b", 0, 0, 0, false, false),
            ("a,b\"c", 0, 0, 0, false, false),
            ("a,\"b\"c", 0, 0, 0, false, false),
            ("a,\"b\"c", 0, 0, 0, true, false),
            ("a,b\"c", 0, 0, 0, true, false),
            ("a,\"b", 0, 0, 0, true, false),
            ("a,b\nc\n", 0, 0, 0, false, false),
            ("a,b\nc\n", 0, 0, -1, false, false),
            ("a,b\nc,d,e\n", 0, 0, 0, false, false),
            ("a;b;c\n", 59, 0, 0, false, false),
            ("a\tb\n", 9, 0, 0, false, false),
            ("#x\na,b\n", 0, 35, 0, false, false),
            ("a,b\n#x\nc,d\n", 0, 35, 0, false, false),
            (" a, b\n", 0, 0, 0, false, false),
            (" a, b\n", 0, 0, 0, false, true),
            ("a, \"b\"", 0, 0, 0, false, false),
            ("a, \"b\"", 0, 0, 0, false, true),
            ("a,,b\n", 0, 0, 0, false, false),
            (",\n", 0, 0, 0, false, false),
            ("a,b,\n", 0, 0, 0, false, false),
            ("\"\"\n", 0, 0, 0, false, false),
            ("a\r\rb\n", 0, 0, 0, false, false),
            ("a,b\r\nc,d\r\n", 0, 0, 0, false, false),
            ("\u{feff}a,b\n", 0, 0, 0, false, false),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (inp, comma, comment, fpr, lazy, trim) = cases[i];
            let (wrecs, werr) = READ[i];
            let mut r = csv::NewReader(bytes::NewReader(goish::bytes(inp)));
            if comma != 0 {
                r.Comma = comma;
            }
            if comment != 0 {
                r.Comment = comment;
            }
            if fpr != 0 {
                r.FieldsPerRecord = fpr;
            }
            r.LazyQuotes = lazy;
            r.TrimLeadingSpace = trim;
            let (recs, err) = r.ReadAll();
            let got = render(&recs);
            if got != s(wrecs) {
                fmt::Println!(
                    "   ",
                    fmt::Sprintf!("%q", s(inp)),
                    fmt::Sprintf!("got %v want %v", got, s(wrecs))
                );
                ok = false;
            }
            if werr.len() == 0 {
                if !err.IsNil() {
                    fmt::Println!(
                        "   ",
                        fmt::Sprintf!("%q", s(inp)),
                        "unexpected",
                        err.Error()
                    );
                    ok = false;
                }
            } else if err.IsNil() || err.Error() != s(werr) {
                fmt::Println!(
                    "   ",
                    fmt::Sprintf!("%q", s(inp)),
                    "err got",
                    if err.IsNil() { s("<nil>") } else { err.Error() },
                    "want",
                    s(werr)
                );
                ok = false;
            }
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 1",
            "ReadAll, with every option and every error",
        );
    }

    // 2. FieldPos and InputOffset, which is what a caller needs to point
    //    at the field that failed validation. Go: after the first Read
    //    of "a,b\nccc,d\n", field 0 is at (1,1), field 1 at (1,3), and
    //    the offset is 4.
    {
        let mut ok = true;
        let mut r = csv::NewReader(bytes::NewReader(goish::bytes("a,b\nccc,d\n")));
        let (_, e1) = r.Read();
        if !e1.IsNil() {
            ok = false;
        }
        let (l0, c0) = r.FieldPos(0);
        let (l1, c1) = r.FieldPos(1);
        if l0 != 1 || c0 != 1 || l1 != 1 || c1 != 3 || r.InputOffset() != 4 {
            fmt::Println!(
                "    first",
                fmt::Sprintf!("(%d,%d) (%d,%d) off=%d", l0, c0, l1, c1, r.InputOffset())
            );
            ok = false;
        }
        let (_, e2) = r.Read();
        if !e2.IsNil() {
            ok = false;
        }
        let (l2, c2) = r.FieldPos(0);
        if l2 != 2 || c2 != 1 || r.InputOffset() != 10 {
            fmt::Println!(
                "    second",
                fmt::Sprintf!("(%d,%d) off=%d", l2, c2, r.InputOffset())
            );
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 2",
            "FieldPos and InputOffset track the input",
        );
    }

    // 3. The writer's quoting rules. A LEADING space forces quotes and a
    //    trailing one does not; a tab does not; `\r` alone does.
    {
        let mut ok = true;
        let recs: [alloc::vec::Vec<&str>; 12] = [
            alloc::vec!["a", "b"],
            alloc::vec!["a,b", "c"],
            alloc::vec!["a\"b"],
            alloc::vec!["a\nb"],
            alloc::vec!["a\rb"],
            alloc::vec![" a"],
            alloc::vec!["a "],
            alloc::vec![""],
            alloc::vec!["", ""],
            alloc::vec!["\\."],
            alloc::vec!["a\tb"],
            alloc::vec!["h\u{e9}llo"],
        ];
        let mut i = 0usize;
        while i < recs.len() {
            let (want, werr) = WRITE[i];
            let mut buf = bytes::Buffer::new();
            let mut w = csv::NewWriter(&mut buf);
            let fields: alloc::vec::Vec<string> = recs[i].iter().map(|x| s(x)).collect();
            let e = w.Write(&fields);
            w.Flush();
            let got = buf.String();
            if got != s(want) {
                fmt::Println!(
                    "    write",
                    i as int,
                    fmt::Sprintf!("got %q want %q", got, s(want))
                );
                ok = false;
            }
            if (werr.len() == 0) != e.IsNil() {
                ok = false;
            }
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 3",
            "the writer quotes exactly what Go quotes",
        );
    }

    // 4. A non-default Comma, UseCRLF, and the invalid-delimiter error.
    //    Go: a `"` as Comma is "csv: invalid field or comment delimiter",
    //    and the record already written is unaffected.
    {
        let mut ok = true;
        {
            let mut buf = bytes::Buffer::new();
            let mut w = csv::NewWriter(&mut buf);
            w.Comma = 59;
            let _ = w.Write(&[s("a"), s("b;c")]);
            w.Flush();
            if buf.String() != s("a;\"b;c\"\n") {
                fmt::Println!("    semi got", fmt::Sprintf!("%q", buf.String()));
                ok = false;
            }
        }
        {
            let mut buf = bytes::Buffer::new();
            let mut w = csv::NewWriter(&mut buf);
            w.UseCRLF = true;
            let rows = [
                slice::__from_vec(alloc::vec![s("a"), s("b")]),
                slice::__from_vec(alloc::vec![s("c"), s("d")]),
            ];
            let _ = w.WriteAll(&rows);
            if buf.String() != s("a,b\r\nc,d\r\n") {
                fmt::Println!("    crlf got", fmt::Sprintf!("%q", buf.String()));
                ok = false;
            }
        }
        {
            let mut buf = bytes::Buffer::new();
            let mut w = csv::NewWriter(&mut buf);
            let e1 = w.Write(&[s("a\nb")]);
            w.Comma = 34;
            let e2 = w.Write(&[s("x")]);
            w.Flush();
            if !e1.IsNil() {
                ok = false;
            }
            if e2.IsNil() || e2.Error() != s("csv: invalid field or comment delimiter") {
                fmt::Println!(
                    "    delim err",
                    if e2.IsNil() { s("<nil>") } else { e2.Error() }
                );
                ok = false;
            }
            if buf.String() != s("\"a\nb\"\n") {
                ok = false;
            }
        }
        report(
            &mut failed,
            ok,
            " 4",
            "Comma, UseCRLF, and the bad delimiter",
        );
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
