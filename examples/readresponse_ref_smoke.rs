// readresponse_ref_smoke — http.ReadResponse and header writing
// against a running Go. (net/http/response.go, net/http/header.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_readresponse_ref.go` run in
// `package http_test` by `scripts/goref.sh`.
//
// ReadResponse is the client-side twin of ReadRequest, with the same
// problem from the other direction: a client and an intermediary that
// disagree about where a response ends can be made to desync, so the
// next response the client reads is attacker-chosen. Its framing rules
// are subtler than the request side's, because the STATUS CODE decides
// whether a body is allowed at all.
//
// goish's framing was correct on every case, which for this surface is
// the result worth recording:
//
//   * 1xx, 204 and 304 carry NO body regardless of their headers, so a
//     Content-Length on a 304 does not make the client swallow the next
//     response's bytes. Both 204-with-cl and 304-with-cl are pinned.
//   * A HEAD response carries the Content-Length a GET would and no
//     body, which requires knowing the request it answers.
//   * An HTTP/1.0 response with neither Content-Length nor chunked is
//     close-delimited: ContentLength -1, Close true, body read to EOF.
//   * Content-Length and Transfer-Encoding conflicts, duplicate
//     Content-Length headers, and non-numeric or negative values are
//     refused exactly as on the request side.
//   * Header.Write replaces CR and LF in a value with spaces rather
//     than emitting them, which is the response-splitting defence, and
//     goish already did.
//
// Two defects, both about telling a truncated response from a finished
// one:
//
//   * A response that is not there at all, and one whose headers stop
//     partway, both reported io.EOF. Go converts each to
//     io.ErrUnexpectedEOF at exactly those two points ("if err ==
//     io.EOF { err = io.ErrUnexpectedEOF }"), because a response that
//     stops mid-message was CUT OFF, not finished — and that is the
//     distinction a client uses to decide whether to retry.
//   * The malformed-status-line errors named no offending text. Go's
//     badStringError is `fmt.Errorf("%s %q", what, val)`, so it says
//     `malformed HTTP status code "2000"` where goish said only
//     "http: malformed HTTP status code". With a status line, the
//     value IS the diagnosis.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bufio;
use goish::bytes;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::net::http;
use goish::net::http::Header;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn et(e: &error) -> string {
    if e.IsNil() {
        return s("<nil>");
    }
    return e.Error();
}
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
fn te_string(te: &slice<string>) -> string {
    let mut out = s("[");
    for i in 0..te.Len() {
        if i > 0 {
            out = out + s(" ");
        }
        out = out + te[i].clone();
    }
    return out + s("]");
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 38] = [
    "res simple         -> code=200  status=\"200 OK\"         proto=\"HTTP/1.1\" cl=5   te=[] close=false hdr=Content-Length=5; body=\"hello\" berr=<nil>",
    "res no-reason      -> code=200  status=\"200\"            proto=\"HTTP/1.1\" cl=0   te=[] close=false hdr=Content-Length=0; body=\"\" berr=<nil>",
    "res reason-spaces  -> code=404  status=\"404 Not Found\"  proto=\"HTTP/1.1\" cl=0   te=[] close=false hdr=Content-Length=0; body=\"\" berr=<nil>",
    "res http10-close   -> code=200  status=\"200 OK\"         proto=\"HTTP/1.0\" cl=-1  te=[] close=true  hdr= body=\"body-to-eof\" berr=<nil>",
    "res chunked        -> code=200  status=\"200 OK\"         proto=\"HTTP/1.1\" cl=-1  te=[chunked] close=false hdr= body=\"hello\" berr=<nil>",
    "res 204            -> code=204  status=\"204 No Content\" proto=\"HTTP/1.1\" cl=0   te=[] close=false hdr= body=\"\" berr=<nil>",
    "res 204-with-cl    -> code=204  status=\"204 No Content\" proto=\"HTTP/1.1\" cl=0   te=[] close=false hdr=Content-Length=5; body=\"\" berr=<nil>",
    "res 304            -> code=304  status=\"304 Not Modified\" proto=\"HTTP/1.1\" cl=0   te=[] close=false hdr= body=\"\" berr=<nil>",
    "res 304-with-cl    -> code=304  status=\"304 Not Modified\" proto=\"HTTP/1.1\" cl=0   te=[] close=false hdr=Content-Length=5; body=\"\" berr=<nil>",
    "res 100            -> code=100  status=\"100 Continue\"   proto=\"HTTP/1.1\" cl=0   te=[] close=false hdr= body=\"\" berr=<nil>",
    "res head           -> code=200  status=\"200 OK\"         proto=\"HTTP/1.1\" cl=5   te=[] close=false hdr=Content-Length=5; body=\"\" berr=<nil>",
    "res head-chunked   -> code=200  status=\"200 OK\"         proto=\"HTTP/1.1\" cl=-1  te=[chunked] close=false hdr= body=\"\" berr=<nil>",
    "res cl-neg         -> err=\"bad Content-Length \\\"-1\\\"\"",
    "res cl-junk        -> err=\"bad Content-Length \\\"x\\\"\"",
    "res cl-dup-diff    -> err=\"http: message cannot contain multiple Content-Length headers; got [\\\"1\\\" \\\"2\\\"]\"",
    "res cl-dup-same    -> code=200  status=\"200 OK\"         proto=\"HTTP/1.1\" cl=1   te=[] close=false hdr=Content-Length=1; body=\"x\" berr=<nil>",
    "res te-and-cl      -> code=200  status=\"200 OK\"         proto=\"HTTP/1.1\" cl=-1  te=[chunked] close=false hdr= body=\"\" berr=<nil>",
    "res te-gzip        -> err=\"unsupported transfer encoding: \\\"gzip\\\"\"",
    "res bad-code       -> err=\"malformed HTTP status code \\\"20\\\"\"",
    "res code-4digit    -> err=\"malformed HTTP status code \\\"2000\\\"\"",
    "res code-nonnum    -> err=\"malformed HTTP status code \\\"abc\\\"\"",
    "res bad-proto      -> err=\"malformed HTTP version \\\"ICY\\\"\"",
    "res empty          -> err=\"unexpected EOF\"",
    "res only-status    -> err=\"unexpected EOF\"",
    "res conn-close     -> code=200  status=\"200 OK\"         proto=\"HTTP/1.1\" cl=1   te=[] close=true  hdr=Content-Length=1; body=\"x\" berr=<nil>",
    "res multi-header   -> code=200  status=\"200 OK\"         proto=\"HTTP/1.1\" cl=0   te=[] close=false hdr=Content-Length=0;X-A=1|2; body=\"\" berr=<nil>",
    "hdrwrite \"plain\"      -> out=\"X-Test: plain\\r\\n\"            err=<nil>",
    "hdrwrite \"with\\rcr\"   -> out=\"X-Test: with cr\\r\\n\"          err=<nil>",
    "hdrwrite \"with\\nlf\"   -> out=\"X-Test: with lf\\r\\n\"          err=<nil>",
    "hdrwrite \"with\\r\\ncrlf\" -> out=\"X-Test: with  crlf\\r\\n\"       err=<nil>",
    "hdrwrite \"with\\x00nul\" -> out=\"X-Test: with\\x00nul\\r\\n\"      err=<nil>",
    "hdrwrite \"trailing \"  -> out=\"X-Test: trailing\\r\\n\"         err=<nil>",
    "hdrwrite \" leading\"   -> out=\"X-Test: leading\\r\\n\"          err=<nil>",
    "hdrwrite \"tab\\there\"  -> out=\"X-Test: tab\\there\\r\\n\"        err=<nil>",
    "hdrkey \"X-Ok\"               -> out=\"X-Ok: v\\r\\n\"              err=<nil>",
    "hdrkey \"X-Bad\\r\\nInjected\"  -> out=\"\"                         err=<nil>",
    "hdrkey \"X Bad\"              -> out=\"\"                         err=<nil>",
    "hdrkey \"\"                   -> out=\"\"                         err=<nil>",
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

    let cases: [(&str, &str, &str); 26] = [
        (
            "simple",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            "GET",
        ),
        (
            "no-reason",
            "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n",
            "GET",
        ),
        (
            "reason-spaces",
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
            "GET",
        ),
        ("http10-close", "HTTP/1.0 200 OK\r\n\r\nbody-to-eof", "GET"),
        (
            "chunked",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            "GET",
        ),
        ("204", "HTTP/1.1 204 No Content\r\n\r\n", "GET"),
        (
            "204-with-cl",
            "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello",
            "GET",
        ),
        ("304", "HTTP/1.1 304 Not Modified\r\n\r\n", "GET"),
        (
            "304-with-cl",
            "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\nhello",
            "GET",
        ),
        ("100", "HTTP/1.1 100 Continue\r\n\r\n", "GET"),
        (
            "head",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            "HEAD",
        ),
        (
            "head-chunked",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HEAD",
        ),
        (
            "cl-neg",
            "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            "GET",
        ),
        (
            "cl-junk",
            "HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
            "GET",
        ),
        (
            "cl-dup-diff",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
            "GET",
        ),
        (
            "cl-dup-same",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            "GET",
        ),
        (
            "te-and-cl",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
            "GET",
        ),
        (
            "te-gzip",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            "GET",
        ),
        ("bad-code", "HTTP/1.1 20 OK\r\n\r\n", "GET"),
        ("code-4digit", "HTTP/1.1 2000 OK\r\n\r\n", "GET"),
        ("code-nonnum", "HTTP/1.1 abc OK\r\n\r\n", "GET"),
        ("bad-proto", "ICY 200 OK\r\n\r\n", "GET"),
        ("empty", "", "GET"),
        ("only-status", "HTTP/1.1 200 OK\r\n", "GET"),
        (
            "conn-close",
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 1\r\n\r\nx",
            "GET",
        ),
        (
            "multi-header",
            "HTTP/1.1 200 OK\r\nX-A: 1\r\nX-A: 2\r\nContent-Length: 0\r\n\r\n",
            "GET",
        ),
    ];
    for (name, raw, method) in cases.iter() {
        let (req, _) = http::NewRequest(s(method), s("http://x/"), ());
        let mut src = strings::NewReader(s(raw));
        let mut br = bufio::NewReader(&mut src);
        let (mut res, err) = http::ReadResponse(&mut br, Some(req));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("res %-14s -> err=%q", s(name), err.Error()),
            );
            continue;
        }
        let (body, berr) = io::ReadAll(&mut res.Body);
        chk(&mut failed, &mut ln, fmt::Sprintf!(
            "res %-14s -> code=%-4d status=%-16q proto=%-9q cl=%-3d te=%v close=%-5v hdr=%s body=%q berr=%v",
            s(name),
            res.StatusCode,
            res.Status.clone(),
            res.Proto.clone(),
            res.ContentLength,
            te_string(&res.TransferEncoding),
            res.Close,
            hdr_string(&res.Header),
            body,
            et(&berr)
        ));
    }
    // Header writing: the CRLF injection a value must never carry.
    for v in [
        "plain",
        "with\rcr",
        "with\nlf",
        "with\r\ncrlf",
        "with\u{0}nul",
        "trailing ",
        " leading",
        "tab\there",
    ] {
        let mut h = Header::new();
        h.Set(s("X-Test"), s(v));
        let mut sb = bytes::Buffer::new();
        let err = h.Write(&mut sb);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "hdrwrite %-12q -> out=%-30q err=%v",
                s(v),
                sb.String(),
                et(&err)
            ),
        );
    }
    for k in ["X-Ok", "X-Bad\r\nInjected", "X Bad", ""] {
        let mut h = Header::new();
        h.Set(s(k), s("v"));
        let mut sb = bytes::Buffer::new();
        let err = h.Write(&mut sb);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "hdrkey %-20q -> out=%-26q err=%v",
                s(k),
                sb.String(),
                et(&err)
            ),
        );
    }
    let _: byte = 0;
    let _: int = 0;
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
