// mail_ref_smoke — net/mail's address and date parsing against a
// running Go. (net/mail/message.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_mail_ref.go` run in `package mail` by
// `scripts/goref.sh`.
//
// net/mail is an RFC 5322 lexer wearing a four-function API, and goish
// had the wrapper without the lexer: `Message`, `ReadMessage`,
// `readHeader` and `Header` were ported, and `ParseAddress`,
// `ParseAddressList`, `Address.String`, `AddressParser`, `ParseDate`,
// `Header.Date` and `Header.AddressList` were not — four of
// thirty-eight functions, and none of the ones a caller reaches for.
//
// `ParseDate` could not have worked before this release either: it
// hands `time.Parse` a layout ending in "-0700" and expects the offset
// back, which a `time.Location` carrying no offset could not do. The
// zone rows below are the proof that it now does.
//
// The vectors are deliberately the awkward cases, because that is
// where a parser that merely looks right answers differently: quoted
// display names, nested comments, group syntax, RFC 2047 encoded
// words, domain literals, and the exact error TEXT for each refusal.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::net::mail;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
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

    // 1. ParseAddress over the whole awkward surface. Each row is
    //    (input, want_err, want_name, want_addr, want_string) — an
    //    empty want_err means it must parse, and the error TEXT is
    //    compared too, because a parser that refuses the right inputs
    //    for the wrong stated reason is still telling the caller
    //    something false.
    {
        let cases: [(&str, &str, &str, &str, &str); 28] = [
            (
                "John Doe <jdoe@machine.example>",
                "",
                "John Doe",
                "jdoe@machine.example",
                "\"John Doe\" <jdoe@machine.example>",
            ),
            (
                "jdoe@machine.example",
                "",
                "",
                "jdoe@machine.example",
                "<jdoe@machine.example>",
            ),
            (
                "<jdoe@machine.example>",
                "",
                "",
                "jdoe@machine.example",
                "<jdoe@machine.example>",
            ),
            (
                "\"John Doe\" <jdoe@machine.example>",
                "",
                "John Doe",
                "jdoe@machine.example",
                "\"John Doe\" <jdoe@machine.example>",
            ),
            (
                "\"Mary Smith: Personal Account\" <smith@home.example>",
                "",
                "Mary Smith: Personal Account",
                "smith@home.example",
                "\"Mary Smith: Personal Account\" <smith@home.example>",
            ),
            (
                "Mary Smith <mary@x.test>",
                "",
                "Mary Smith",
                "mary@x.test",
                "\"Mary Smith\" <mary@x.test>",
            ),
            (
                "  John  Doe  <jdoe@machine.example>  ",
                "",
                "John Doe",
                "jdoe@machine.example",
                "\"John Doe\" <jdoe@machine.example>",
            ),
            (
                "John (comment) Doe <jdoe@machine.example>",
                "",
                "John Doe",
                "jdoe@machine.example",
                "\"John Doe\" <jdoe@machine.example>",
            ),
            (
                "(comment)<jdoe@machine.example>",
                "mail: missing word in phrase: mail: invalid string",
                "",
                "",
                "",
            ),
            (
                "jdoe@machine.example (John Doe)",
                "",
                "John Doe",
                "jdoe@machine.example",
                "\"John Doe\" <jdoe@machine.example>",
            ),
            (
                "=?utf-8?q?J=C3=B6rg_Doe?= <joerg@example.com>",
                "",
                "Jörg Doe",
                "joerg@example.com",
                "=?utf-8?q?J=C3=B6rg_Doe?= <joerg@example.com>",
            ),
            (
                "=?ISO-8859-1?Q?Andr=E9?= Pirard <PIRARD@vm1.ulg.ac.be>",
                "",
                "André Pirard",
                "PIRARD@vm1.ulg.ac.be",
                "=?utf-8?q?Andr=C3=A9_Pirard?= <PIRARD@vm1.ulg.ac.be>",
            ),
            (
                "\"Joe Q. Public\" <john.q.public@example.com>",
                "",
                "Joe Q. Public",
                "john.q.public@example.com",
                "\"Joe Q. Public\" <john.q.public@example.com>",
            ),
            (
                "user@[192.168.0.1]",
                "",
                "",
                "user@[192.168.0.1]",
                "<user@[192.168.0.1]>",
            ),
            (
                "user@[IPv6:2001:db8::1]",
                "mail: missing '@' or angle-addr",
                "",
                "",
                "",
            ),
            (
                "\"quoted@local\"@example.com",
                "",
                "",
                "quoted@local@example.com",
                "<\"quoted@local\"@example.com>",
            ),
            ("a@b", "", "", "a@b", "<a@b>"),
            (
                "Group: a@b, c@d;",
                "mail: group with multiple addresses",
                "",
                "",
                "",
            ),
            ("undisclosed-recipients:;", "mail: empty group", "", "", ""),
            ("", "mail: no address", "", "", ""),
            (
                "@example.com",
                "mail: missing word in phrase: mail: invalid string",
                "",
                "",
                "",
            ),
            (
                "missing-at-sign",
                "mail: missing '@' or angle-addr",
                "",
                "",
                "",
            ),
            ("a@", "mail: missing '@' or angle-addr", "", "", ""),
            (
                "<a@b>, <c@d>",
                "mail: expected single address, got \", <c@d>\"",
                "",
                "",
                "",
            ),
            (
                "John Doe <jdoe@machine.example>, Mary Smith <mary@x.test>",
                "mail: expected single address, got \", Mary Smith <mary@x.test>\"",
                "",
                "",
                "",
            ),
            (
                "\"Sender\\\\Name\" <s@x.test>",
                "",
                "Sender\\Name",
                "s@x.test",
                "\"Sender\\\\Name\" <s@x.test>",
            ),
            (
                "\"has \\\" quote\" <q@x.test>",
                "",
                "has \" quote",
                "q@x.test",
                "\"has \\\" quote\" <q@x.test>",
            ),
            (
                "Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>",
                "mail: expected single address, got \",joe@where.test,John <jdoe@one.test>\"",
                "",
                "",
                "",
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, want_err, want_name, want_addr, want_str) = cases[i];
            let (a, err) = mail::ParseAddress(inp);
            if want_err.len() > 0 {
                if err.IsNil() {
                    fmt::Printf!(
                        "[!!] %q FAIL expected error %q, parsed\n",
                        s(inp),
                        s(want_err)
                    );
                    failed += 1;
                } else {
                    eq(&mut failed, err.Error(), want_err, inp);
                }
            } else if !err.IsNil() {
                fmt::Printf!("[!!] %q FAIL unexpected error %q\n", s(inp), err.Error());
                failed += 1;
            } else {
                eq(&mut failed, a.Name.clone(), want_name, inp);
                eq(&mut failed, a.Address.clone(), want_addr, inp);
                eq(&mut failed, a.String(), want_str, inp);
            }
            i += 1;
        }
        fmt::Println!("[  1 ] ParseAddress over 28 RFC 5322 forms done");
    }

    // 2. ParseAddressList, including the group forms — a group with
    //    several members flattens into the list, and an empty group
    //    ("undisclosed-recipients:;") yields NO addresses and no
    //    error, which is easy to turn into an error by accident.
    {
        {
            let (as_, err) =
                mail::ParseAddressList("John Doe <jdoe@machine.example>, Mary Smith <mary@x.test>");
            if !err.IsNil() {
                fmt::Printf!("[!!] list FAIL %%q\n", err.Error());
                failed += 1;
            } else if as_.len() != 2 {
                fmt::Printf!("[!!] list FAIL n=%d want 2\n", as_.len() as i64);
                failed += 1;
            } else {
                eq(&mut failed, as_[0].Name.clone(), "John Doe", "list name");
                eq(
                    &mut failed,
                    as_[0].Address.clone(),
                    "jdoe@machine.example",
                    "list addr",
                );
                eq(&mut failed, as_[1].Name.clone(), "Mary Smith", "list name");
                eq(
                    &mut failed,
                    as_[1].Address.clone(),
                    "mary@x.test",
                    "list addr",
                );
            }
        }
        {
            let (as_, err) =
                mail::ParseAddressList("Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>");
            if !err.IsNil() {
                fmt::Printf!("[!!] list FAIL %%q\n", err.Error());
                failed += 1;
            } else if as_.len() != 3 {
                fmt::Printf!("[!!] list FAIL n=%d want 3\n", as_.len() as i64);
                failed += 1;
            } else {
                eq(&mut failed, as_[0].Name.clone(), "Ed Jones", "list name");
                eq(&mut failed, as_[0].Address.clone(), "c@a.test", "list addr");
                eq(&mut failed, as_[1].Name.clone(), "", "list name");
                eq(
                    &mut failed,
                    as_[1].Address.clone(),
                    "joe@where.test",
                    "list addr",
                );
                eq(&mut failed, as_[2].Name.clone(), "John", "list name");
                eq(
                    &mut failed,
                    as_[2].Address.clone(),
                    "jdoe@one.test",
                    "list addr",
                );
            }
        }
        {
            let (as_, err) = mail::ParseAddressList("Group: a@b, c@d;");
            if !err.IsNil() {
                fmt::Printf!("[!!] list FAIL %%q\n", err.Error());
                failed += 1;
            } else if as_.len() != 2 {
                fmt::Printf!("[!!] list FAIL n=%d want 2\n", as_.len() as i64);
                failed += 1;
            } else {
                eq(&mut failed, as_[0].Name.clone(), "", "list name");
                eq(&mut failed, as_[0].Address.clone(), "a@b", "list addr");
                eq(&mut failed, as_[1].Name.clone(), "", "list name");
                eq(&mut failed, as_[1].Address.clone(), "c@d", "list addr");
            }
        }
        {
            let (as_, err) = mail::ParseAddressList("undisclosed-recipients:;");
            if !err.IsNil() {
                fmt::Printf!("[!!] list FAIL %%q\n", err.Error());
                failed += 1;
            } else if as_.len() != 0 {
                fmt::Printf!("[!!] list FAIL n=%d want 0\n", as_.len() as i64);
                failed += 1;
            }
        }
        {
            let (as_, err) = mail::ParseAddressList("a@b,");
            if !err.IsNil() {
                fmt::Printf!("[!!] list FAIL %%q\n", err.Error());
                failed += 1;
            } else if as_.len() != 1 {
                fmt::Printf!("[!!] list FAIL n=%d want 1\n", as_.len() as i64);
                failed += 1;
            } else {
                eq(&mut failed, as_[0].Name.clone(), "", "list name");
                eq(&mut failed, as_[0].Address.clone(), "a@b", "list addr");
            }
        }
        {
            let (_as_, err) = mail::ParseAddressList("");
            if err.IsNil() {
                fmt::Println!("[!!] list FAIL expected error");
                failed += 1;
            } else {
                eq(&mut failed, err.Error(), "mail: no address", "list err");
            }
        }
        {
            let (as_, err) = mail::ParseAddressList(
                "A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;",
            );
            if !err.IsNil() {
                fmt::Printf!("[!!] list FAIL %%q\n", err.Error());
                failed += 1;
            } else if as_.len() != 3 {
                fmt::Printf!("[!!] list FAIL n=%d want 3\n", as_.len() as i64);
                failed += 1;
            } else {
                eq(&mut failed, as_[0].Name.clone(), "Ed Jones", "list name");
                eq(&mut failed, as_[0].Address.clone(), "c@a.test", "list addr");
                eq(&mut failed, as_[1].Name.clone(), "", "list name");
                eq(
                    &mut failed,
                    as_[1].Address.clone(),
                    "joe@where.test",
                    "list addr",
                );
                eq(&mut failed, as_[2].Name.clone(), "John", "list name");
                eq(
                    &mut failed,
                    as_[2].Address.clone(),
                    "jdoe@one.test",
                    "list addr",
                );
            }
        }
        fmt::Println!("[  2 ] ParseAddressList incl. group syntax done");
    }

    // 3. Address.String is a RE-encoder, not a formatter: it quotes a
    //    display name that needs quoting, escapes what must be escaped,
    //    RFC 2047-encodes a non-ASCII name, and switches from Q to B
    //    encoding when the name contains characters an encoded-word may
    //    not carry. It also re-quotes a local-part that needs it, and
    //    appends a bare "@" to an address with no domain.
    {
        let cases: [(&str, &str, &str); 11] = [
            ("", "a@b.com", "<a@b.com>"),
            ("Plain Name", "a@b.com", "\"Plain Name\" <a@b.com>"),
            ("Needs, Quote", "a@b.com", "\"Needs, Quote\" <a@b.com>"),
            (
                "Has \"quote\"",
                "a@b.com",
                "\"Has \\\"quote\\\"\" <a@b.com>",
            ),
            (
                "Has\\backslash",
                "a@b.com",
                "\"Has\\\\backslash\" <a@b.com>",
            ),
            ("Jörg", "a@b.com", "=?utf-8?q?J=C3=B6rg?= <a@b.com>"),
            (
                "日本語",
                "a@b.com",
                "=?utf-8?q?=E6=97=A5=E6=9C=AC=E8=AA=9E?= <a@b.com>",
            ),
            (
                "Joe Q. Public",
                "john.q.public@example.com",
                "\"Joe Q. Public\" <john.q.public@example.com>",
            ),
            (
                "trailing space ",
                "a@b.com",
                "\"trailing space \" <a@b.com>",
            ),
            (
                "x",
                "quoted@local\"@example.com",
                "\"x\" <\"quoted@local\\\"\"@example.com>",
            ),
            ("x", "no-at-sign", "\"x\" <no-at-sign@>"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (name, addr, want) = cases[i];
            let a = mail::Address {
                Name: s(name),
                Address: s(addr),
            };
            eq(&mut failed, a.String(), want, name);
            i += 1;
        }
        fmt::Println!("[  3 ] Address::String re-encodes like Go");
    }

    // 4. ParseDate. The zone columns are the point: Go returns the
    //    real numeric offset, and an anonymous zone for a numeric one
    //    versus a NAMED zone for "GMT". Every one of these rows was
    //    unreachable in this tree until time.Location gained a name and
    //    an offset — a Time that cannot carry -0600 cannot report it.
    {
        let cases: [(&str, &str, i64, &str, i64, &str); 11] = [
            (
                "Fri, 21 Nov 1997 09:55:06 -0600",
                "",
                880127706,
                "",
                -21600,
                "1997-11-21T09:55:06-06:00",
            ),
            (
                "Thu, 13 Feb 1969 23:32:54 -0330",
                "",
                -27723426,
                "",
                -12600,
                "1969-02-13T23:32:54-03:30",
            ),
            (
                "Mon, 24 Nov 1997 14:22:01 -0800",
                "",
                880410121,
                "",
                -28800,
                "1997-11-24T14:22:01-08:00",
            ),
            (
                "21 Nov 97 09:55:06 GMT",
                "",
                880106106,
                "GMT",
                0,
                "1997-11-21T09:55:06Z",
            ),
            (
                "Fri, 21 Nov 1997 09:55:06 +0000",
                "",
                880106106,
                "UTC",
                0,
                "1997-11-21T09:55:06Z",
            ),
            (
                "Fri, 21 Nov 1997 09:55:06 GMT",
                "",
                880106106,
                "GMT",
                0,
                "1997-11-21T09:55:06Z",
            ),
            (
                "Fri, 21 Nov 1997 09:55:06 -0600 (MDT)",
                "",
                880127706,
                "",
                -21600,
                "1997-11-21T09:55:06-06:00",
            ),
            (
                "Thu, 20 Nov 1997 09:55:06 -0600 (MDT and some more)",
                "",
                880041306,
                "",
                -21600,
                "1997-11-20T09:55:06-06:00",
            ),
            (
                "Fri,21 Nov 1997 09:55:06 -0600",
                "mail: header could not be parsed",
                0,
                "",
                0,
                "",
            ),
            (
                "Fri, 21 Nov 1997 09:55 -0600",
                "",
                880127700,
                "",
                -21600,
                "1997-11-21T09:55:00-06:00",
            ),
            ("garbage", "mail: header could not be parsed", 0, "", 0, ""),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, want_err, want_unix, want_zn, want_zo, want_fmt) = cases[i];
            let (t, err) = mail::ParseDate(inp);
            if want_err.len() > 0 {
                if err.IsNil() {
                    fmt::Printf!("[!!] date %q FAIL expected error\n", s(inp));
                    failed += 1;
                } else {
                    eq(&mut failed, err.Error(), want_err, inp);
                }
            } else if !err.IsNil() {
                fmt::Printf!("[!!] date %q FAIL %q\n", s(inp), err.Error());
                failed += 1;
            } else {
                if t.Unix() != want_unix {
                    fmt::Printf!(
                        "[!!] date %q FAIL unix=%d want %d\n",
                        s(inp),
                        t.Unix(),
                        want_unix
                    );
                    failed += 1;
                }
                let (zn, zo) = t.Zone();
                eq(&mut failed, zn, want_zn, inp);
                if zo != want_zo {
                    fmt::Printf!("[!!] date %q FAIL off=%d want %d\n", s(inp), zo, want_zo);
                    failed += 1;
                }
                eq(&mut failed, t.Format(goish::time::RFC3339), want_fmt, inp);
            }
            i += 1;
        }
        fmt::Println!("[  4 ] ParseDate incl. real zone offsets");
    }

    if failed == 0 {
        fmt::Println!("ok - net/mail matches Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
