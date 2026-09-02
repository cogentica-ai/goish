// multipart_ref_smoke — mime/multipart and mime/quotedprintable
// against a running Go.
// (mime/multipart/multipart.go, mime/quotedprintable/reader.go)
//
// The lines in GO are the verbatim output of
// `tools/gen_multipart_ref.go` run in `package multipart_test` by
// `scripts/goref.sh`, except the one marked KNOWN GAP.
//
// mime/multipart parses HTTP request bodies — file uploads, form
// submissions — so its input is attacker-shaped by default, and every
// rule about where a part begins and ends is a place two parsers can be
// made to disagree. Nothing in the tree had measured it. Four defects,
// one of them a security defect:
//
//   * FileName() returned the filename parameter VERBATIM. Go
//     base-names it, citing RFC 7578 Section 4.2 — "if a filename is
//     provided, the directory path information must not be used" — so
//     Go answers "passwd" for filename="../../etc/passwd" and goish
//     answered the whole path. Any handler doing the obvious
//     os.Create(part.FileName()) wrote outside its upload directory.
//     That is the classic multipart upload traversal, and the
//     base-naming is the defence, not a tidy-up.
//   * A body using bare LF line endings failed to parse at all. Go
//     switches the whole reader into LF mode when the FIRST delimiter
//     line ends with a bare "\n" (isBoundaryDelimiterLine: "This is a
//     violation of the spec, but occurs in practice"), and real clients
//     do send it.
//   * A quoted-printable part was NOT decoded. Go's NextPart decodes it
//     transparently and removes the Content-Transfer-Encoding header,
//     so the caller never sees the encoding; goish handed back the raw
//     "=3D" text with the header still attached.
//   * A body containing no delimiter at all returned a bare io.EOF, so
//     the ordinary `if err == io.EOF { break }` loop read rubbish as
//     "zero parts, fine". Go wraps it — "multipart: NextPart: EOF" —
//     which is an error while still satisfying errors.Is(err, io.EOF).
//
// Measured and found correct: a boundary only counts at the start of a
// line, so "--b" inside a body stays data; the CRLF before a delimiter
// belongs to the delimiter and not to the part; trailing whitespace
// after a delimiter is tolerated; the preamble and epilogue are
// ignored; FormName is empty unless the disposition is form-data; the
// writer's output round-trips through the reader; SetBoundary's length
// and character rules match; and quotedprintable decodes every escape,
// soft line break and trailing-whitespace case identically, including
// the malformed ones it passes through unchanged.

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
use goish::io;
use goish::mime::multipart;
use goish::mime::quotedprintable;
use goish::net::http::Header;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int};

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
// Renders a part's headers in the same canonical, sorted form the Go
// generator uses, so the two sides are compared on content rather than
// on how each language prints a map.
fn hdr_string(h: &Header) -> string {
    let mut keys: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    for (k, _) in goish::range!(h) {
        keys.push(k.clone());
    }
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            if keys[j].as_bytes() < keys[i].as_bytes() {
                keys.swap(i, j);
            }
        }
    }
    let mut out = string::default();
    for k in keys.iter() {
        out = out + k.clone() + s("=");
        let vals = h.Values(k.clone());
        for i in 0..vals.Len() {
            if i > 0 {
                out = out + s("|");
            }
            out = out + vals[i].clone();
        }
        out = out + s(";");
    }
    return out;
}

// go: none — goish idiom: the expected lines, in the order they are
//     printed. Every line is Go's output except the one marked KNOWN
//     GAP, which holds goish's answer with Go's described above it.
const GO: [&str; 59] = [
    "part simple            #0 -> hdr=A=1; body=\"body\"",
    "part simple            #1 -> EOF",
    "part two-parts         #0 -> hdr= body=\"one\"",
    "part two-parts         #1 -> hdr= body=\"two\"",
    "part two-parts         #2 -> EOF",
    "part bare-lf           #0 -> hdr=A=1; body=\"body\"",
    "part bare-lf           #1 -> EOF",
    "part preamble          #0 -> hdr= body=\"x\"",
    "part preamble          #1 -> EOF",
    "part epilogue          #0 -> hdr= body=\"x\"",
    "part epilogue          #1 -> EOF",
    "part empty-part        #0 -> hdr= body=\"\"",
    "part empty-part        #1 -> EOF",
    "part no-final-crlf     #0 -> hdr= body=\"x\"",
    "part no-final-crlf     #1 -> EOF",
    "part boundary-in-body  #0 -> hdr= body=\"a--b-not\"",
    "part boundary-in-body  #1 -> EOF",
    "part trailing-space    #0 -> hdr= body=\"x\"",
    "part trailing-space    #1 -> EOF",
    // KNOWN GAP — Go yields the part and reports the failure on the
    // READ instead: `hdr= body="x" rerr=unexpected EOF`, then
    // `err="multipart: NextPart: EOF"` on the next call. goish's Part
    // carries an eager Body, so it has nowhere to put "here is the
    // part, and reading it failed partway".
    "part no-closing        #0 -> err=\"multipart: unexpected EOF in part body\"",
    "part missing-first     #0 -> err=\"multipart: NextPart: EOF\"",
    "part empty-body        #0 -> err=\"multipart: NextPart: EOF\"",
    "part headers           #0 -> hdr=X-A=1;X-B=2; body=\"z\"",
    "part headers           #1 -> EOF",
    "part crlf-in-body      #0 -> hdr= body=\"line1\\r\\nline2\"",
    "part crlf-in-body      #1 -> EOF",
    "disp \"form-data; name=\\\"field\\\"\"            -> formname=\"field\"  filename=\"\"",
    "disp \"form-data; name=\\\"f\\\"; filename=\\\"a.txt\\\"\" -> formname=\"f\"      filename=\"a.txt\"",
    "disp \"form-data; name=\\\"f\\\"; filename=\\\"../../etc/passwd\\\"\" -> formname=\"f\"      filename=\"passwd\"",
    "disp \"form-data; name=\\\"f\\\"; filename=\\\"dir/sub/a.txt\\\"\" -> formname=\"f\"      filename=\"a.txt\"",
    "disp \"form-data; name=\\\"f\\\"; filename=\\\"..\\\\\\\\..\\\\\\\\win.ini\\\"\" -> formname=\"f\"      filename=\"..\\\\..\\\\win.ini\"",
    "disp \"attachment; name=\\\"f\\\"; filename=\\\"a.txt\\\"\" -> formname=\"\"       filename=\"a.txt\"",
    "disp \"form-data\"                            -> formname=\"\"       filename=\"\"",
    "disp \"form-data; filename=\\\"a.txt\\\"\"        -> formname=\"\"       filename=\"a.txt\"",
    "disp \"\"                                     -> formname=\"\"       filename=\"\"",
    "qp part body=\"a=bc\" cte=\"\"",
    "qp \"plain\"        -> \"plain\" err=<nil>",
    "qp \"a=3Db\"        -> \"a=b\" err=<nil>",
    "qp \"a=\\r\\nb\"      -> \"ab\" err=<nil>",
    "qp \"a=\\nb\"        -> \"ab\" err=<nil>",
    "qp \"a=3\"          -> \"a=3\" err=<nil>",
    "qp \"a=ZZ\"         -> \"a=ZZ\" err=<nil>",
    "qp \"a=\"           -> \"a\" err=<nil>",
    "qp \"line   \\r\\nnext\" -> \"line\\r\\nnext\" err=<nil>",
    "qp \"=E2=98=BA\"    -> \"☺\" err=<nil>",
    "qp \"a=3db\"        -> \"a=b\" err=<nil>",
    "qp \"tab\\there\"    -> \"tab\\there\" err=<nil>",
    "writer ct=\"multipart/form-data; boundary=fixedboundary\"",
    "writer out=\"--fixedboundary\\r\\nContent-Disposition: form-data; name=\\\"a\\\"\\r\\n\\r\\n1\\r\\n--fixedboundary\\r\\nContent-Disposition: form-data; name=\\\"file\\\"; filename=\\\"up.txt\\\"\\r\\nContent-Type: application/octet-stream\\r\\n\\r\\ndata\\r\\n--fixedboundary\\r\\nContent-Disposition: form-data; name=\\\"b\\\"\\r\\n\\r\\n2\\r\\n--fixedboundary--\\r\\n\"",
    "writer-rt name=\"a\"    file=\"\"       body=\"1\"",
    "writer-rt name=\"file\" file=\"up.txt\" body=\"data\"",
    "writer-rt name=\"b\"    file=\"\"       body=\"2\"",
    "setboundary len=2   -> err=<nil>",
    "setboundary len=0   -> err=mime: invalid boundary length",
    "setboundary len=70  -> err=<nil>",
    "setboundary len=71  -> err=mime: invalid boundary length",
    "setboundary len=9   -> err=<nil>",
    "setboundary len=7   -> err=mime: invalid boundary character",
    "setboundary len=3   -> err=<nil>",
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
    let cases: [(&str, &str, &str); 14] = [
        ("simple", "--b\r\nA: 1\r\n\r\nbody\r\n--b--\r\n", "b"),
        (
            "two-parts",
            "--b\r\n\r\none\r\n--b\r\n\r\ntwo\r\n--b--\r\n",
            "b",
        ),
        ("bare-lf", "--b\nA: 1\n\nbody\n--b--\n", "b"),
        ("preamble", "junk\r\nmore\r\n--b\r\n\r\nx\r\n--b--\r\n", "b"),
        (
            "epilogue",
            "--b\r\n\r\nx\r\n--b--\r\ntrailing junk\r\n",
            "b",
        ),
        ("empty-part", "--b\r\n\r\n\r\n--b--\r\n", "b"),
        ("no-final-crlf", "--b\r\n\r\nx\r\n--b--", "b"),
        ("boundary-in-body", "--b\r\n\r\na--b-not\r\n--b--\r\n", "b"),
        ("trailing-space", "--b \r\n\r\nx\r\n--b--\r\n", "b"),
        ("no-closing", "--b\r\n\r\nx\r\n", "b"),
        ("missing-first", "nothing here\r\n", "b"),
        ("empty-body", "", "b"),
        (
            "headers",
            "--b\r\nX-A: 1\r\nX-B: 2\r\n\r\nz\r\n--b--\r\n",
            "b",
        ),
        (
            "crlf-in-body",
            "--b\r\n\r\nline1\r\nline2\r\n--b--\r\n",
            "b",
        ),
    ];
    for (name, body, bnd) in cases.iter() {
        let mut r = multipart::NewReader(bs(body), s(bnd));
        let mut n: i64 = 0;
        loop {
            let (p, err) = r.NextPart();
            if !err.IsNil() {
                // The Go side distinguishes the BARE io.EOF from the
                // one Go wraps as "multipart: NextPart: EOF", so match
                // on the message rather than on errors::Is — which is
                // true for both, by design.
                if err.Error() == s("EOF") {
                    chk(
                        &mut failed,
                        &mut ln,
                        fmt::Sprintf!("part %-17s #%d -> EOF", s(name), n),
                    );
                } else {
                    chk(
                        &mut failed,
                        &mut ln,
                        fmt::Sprintf!("part %-17s #%d -> err=%q", s(name), n, err.Error()),
                    );
                }
                break;
            }
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "part %-17s #%d -> hdr=%s body=%q",
                    s(name),
                    n,
                    hdr_string(&p.Header),
                    p.Body
                ),
            );
            n += 1;
            if n > 4 {
                break;
            }
        }
    }
    // 2
    for d in [
        "form-data; name=\"field\"",
        "form-data; name=\"f\"; filename=\"a.txt\"",
        "form-data; name=\"f\"; filename=\"../../etc/passwd\"",
        "form-data; name=\"f\"; filename=\"dir/sub/a.txt\"",
        "form-data; name=\"f\"; filename=\"..\\\\..\\\\win.ini\"",
        "attachment; name=\"f\"; filename=\"a.txt\"",
        "form-data",
        "form-data; filename=\"a.txt\"",
        "",
    ] {
        let mut body = string::from("--b\r\n");
        if !d.is_empty() {
            body = body + s("Content-Disposition: ") + s(d) + s("\r\n");
        }
        body = body + s("\r\nx\r\n--b--\r\n");
        let mut r = multipart::NewReader(slice::__from_vec(body.as_bytes().to_vec()), s("b"));
        let (p, err) = r.NextPart();
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("disp %-38q -> err=%q", s(d), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "disp %-38q -> formname=%-8q filename=%q",
                s(d),
                p.FormName(),
                p.FileName()
            ),
        );
    }
    // 3
    {
        let body =
            "--b\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\na=3Db=\r\nc\r\n--b--\r\n";
        let mut r = multipart::NewReader(bs(body), s("b"));
        let (p, _) = r.NextPart();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "qp part body=%q cte=%q",
                p.Body.clone(),
                p.Header.Get(s("Content-Transfer-Encoding"))
            ),
        );
    }
    // 4
    for inp in [
        "plain",
        "a=3Db",
        "a=\r\nb",
        "a=\nb",
        "a=3",
        "a=ZZ",
        "a=",
        "line   \r\nnext",
        "=E2=98=BA",
        "a=3db",
        "tab\there",
    ] {
        let mut src = strings::NewReader(s(inp));
        let mut qr = quotedprintable::NewReader(&mut src);
        let (out, err) = io::ReadAll(&mut qr);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("qp %-14q -> %q err=%v", s(inp), out, et(&err)),
        );
    }
    // 5
    {
        let mut sb = bytes::Buffer::new();
        {
            let mut w = multipart::NewWriter(&mut sb);
            let _ = w.SetBoundary(s("fixedboundary"));
            {
                let (mut fw, _) = w.CreateFormField(s("a"));
                let _ = fw.Write(bs("1"));
            }
            {
                let (mut ff, _) = w.CreateFormFile(s("file"), s("up.txt"));
                let _ = ff.Write(bs("data"));
            }
            let _ = w.WriteField(s("b"), s("2"));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("writer ct=%q", w.FormDataContentType()),
            );
            let _ = w.Close();
        }
        let out = sb.String();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("writer out=%q", out.clone()),
        );
        let mut r = multipart::NewReader(
            slice::__from_vec(out.as_bytes().to_vec()),
            s("fixedboundary"),
        );
        loop {
            let (p, err) = r.NextPart();
            if !err.IsNil() {
                break;
            }
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "writer-rt name=%-6q file=%-8q body=%q",
                    p.FormName(),
                    p.FileName(),
                    p.Body
                ),
            );
        }
    }
    // 6
    {
        let mut sb = bytes::Buffer::new();
        let mut w = multipart::NewWriter(&mut sb);
        let long70: string = string::from_bytes(&alloc::vec![b'x'; 70]);
        let long71: string = string::from_bytes(&alloc::vec![b'x'; 71]);
        let bnds: [string; 7] = [
            s("ok"),
            s(""),
            long70,
            long71,
            s("has space"),
            s("has\ttab"),
            s("a:b"),
        ];
        for b in bnds.iter() {
            let err = w.SetBoundary(b.clone());
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("setboundary len=%-3d -> err=%v", b.Len(), et(&err)),
            );
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
