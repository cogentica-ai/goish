// gzip_transport_ref_smoke — the transport's transparent gzip against a running Go.
// (net/http/transport.go persistConn.readLoop + Transport.roundTrip)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_gzip_transport_ref.go` run in
// `package http_test` by `scripts/goref.sh`. The backend reports the
// Accept-Encoding it SAW, because "did the transport ask for gzip" is
// not observable from the client side at all — and a port that decodes
// without asking, or asks without decoding, is broken in a way the
// response alone cannot show.
//
// goish had `Transport.DisableCompression` and `Response.Uncompressed`
// as fields that did nothing: the client never asked for gzip and never
// decoded one. Two API surfaces that lie, and an origin that gzips —
// which is most of them — answering every goish request uncompressed.
// The whole feature is implemented here and every line of the reference
// matched on the first run.
//
// The rule, in the shape a port has to reproduce:
//
//   * Ask only when the caller has expressed no preference: no
//     Accept-Encoding, no Range, not HEAD, DisableCompression false.
//     Each clause earns its place. A caller who set Accept-Encoding
//     wants the ENCODED bytes — a reverse proxy depends on that, since
//     it must relay what the origin sent rather than a decoded copy
//     whose headers no longer describe it. A Range request must not be
//     answered with a gzip stream of the whole resource. A HEAD has no
//     body.
//   * On the way back, delete Content-Encoding AND Content-Length, set
//     ContentLength to -1 and Uncompressed to true. The deletions are
//     not tidiness: a decoded body with a Content-Length describing the
//     COMPRESSED bytes is a response whose framing lies about itself,
//     and anything that re-serializes it — a proxy, a cache, a dump —
//     would write a length that does not match what it writes.
//
// The cases that no reasonable person would guess, all pinned:
//
//   * caller-ae="" — an EXPLICITLY empty Accept-Encoding. Go puts its
//     own "Accept-Encoding: gzip" in `extraHeaders`, which does not
//     displace a header the caller set, so the wire carries the
//     caller's empty value AND the response is still decoded. The
//     header sent and the decision taken disagree, deliberately.
//   * gzip-empty — a "Content-Encoding: gzip" with nothing after it is
//     passed through untouched, header and all, because Go reaches the
//     gzip arm only on the branch that has a body to stream.
//   * gzip-corrupt — the decoder is LAZY. A bad gzip header surfaces
//     from the first Read as "gzip: invalid header", not from the call
//     that returned the response, and Uncompressed is already true.
//   * gzip-truncated — the decoder STREAMS. Ten bytes come back and
//     then "unexpected EOF", rather than the whole read failing. A
//     port that buffered the body to decode it would return zero bytes
//     and an error, losing what had already arrived.
//   * identity and deflate are NOT decoded, and keep their
//     Content-Encoding. Only gzip is transparent.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::bytes;
use goish::compress::gzip;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::{Handler, ResponseWriter};
use goish::strings;
use goish::sync;
use goish::syscall;
use goish::types::int;
const GO: [&str; 18] = [
    "default/gzip                       -> code=200 saw-ae=\"gzip\" ce=\"\" clen-hdr=\"\" ContentLength=-1 Uncompressed=true n=128 same=true err=<nil> out=\"gzip round trip gzip rou…\"",
    "default/gzip-always                -> code=200 saw-ae=\"gzip\" ce=\"\" clen-hdr=\"\" ContentLength=-1 Uncompressed=true n=128 same=true err=<nil> out=\"gzip round trip gzip rou…\"",
    "default/plain                      -> code=200 saw-ae=\"gzip\" ce=\"\" clen-hdr=\"128\" ContentLength=128 Uncompressed=false n=128 same=true err=<nil> out=\"gzip round trip gzip rou…\"",
    "default/identity                   -> code=200 saw-ae=\"gzip\" ce=\"identity\" clen-hdr=\"128\" ContentLength=128 Uncompressed=false n=128 same=true err=<nil> out=\"gzip round trip gzip rou…\"",
    "default/deflate                    -> code=200 saw-ae=\"gzip\" ce=\"deflate\" clen-hdr=\"128\" ContentLength=128 Uncompressed=false n=128 same=true err=<nil> out=\"gzip round trip gzip rou…\"",
    "default/gzip-corrupt               -> code=200 saw-ae=\"gzip\" ce=\"\" clen-hdr=\"\" ContentLength=-1 Uncompressed=true n=0 same=false err=gzip: invalid header out=\"\"",
    "default/gzip-truncated             -> code=200 saw-ae=\"gzip\" ce=\"\" clen-hdr=\"\" ContentLength=-1 Uncompressed=true n=10 same=false err=unexpected EOF out=\"gzip round\"",
    "default/gzip-empty                 -> code=200 saw-ae=\"gzip\" ce=\"gzip\" clen-hdr=\"0\" ContentLength=0 Uncompressed=false n=0 same=false err=<nil> out=\"\"",
    "caller-ae=\"gzip\"                   -> code=200 saw-ae=\"gzip\" ce=\"gzip\" clen-hdr=\"42\" ContentLength=42 Uncompressed=false n=42 same=false err=<nil> out=\"\\x1f\\x8b\\b\\x00\\x00\\x00\\x00\\x00\\x00\\xffJ\\xaf\\xca,P(\\xca/\\xcdKQ()\\xca…\"",
    "caller-ae=\"gzip, deflate\"          -> code=200 saw-ae=\"gzip, deflate\" ce=\"gzip\" clen-hdr=\"42\" ContentLength=42 Uncompressed=false n=42 same=false err=<nil> out=\"\\x1f\\x8b\\b\\x00\\x00\\x00\\x00\\x00\\x00\\xffJ\\xaf\\xca,P(\\xca/\\xcdKQ()\\xca…\"",
    "caller-ae=\"identity\"               -> code=200 saw-ae=\"identity\" ce=\"gzip\" clen-hdr=\"42\" ContentLength=42 Uncompressed=false n=42 same=false err=<nil> out=\"\\x1f\\x8b\\b\\x00\\x00\\x00\\x00\\x00\\x00\\xffJ\\xaf\\xca,P(\\xca/\\xcdKQ()\\xca…\"",
    "caller-ae=\"*\"                      -> code=200 saw-ae=\"*\" ce=\"gzip\" clen-hdr=\"42\" ContentLength=42 Uncompressed=false n=42 same=false err=<nil> out=\"\\x1f\\x8b\\b\\x00\\x00\\x00\\x00\\x00\\x00\\xffJ\\xaf\\xca,P(\\xca/\\xcdKQ()\\xca…\"",
    "caller-ae=\"\"                       -> code=200 saw-ae=\"\" ce=\"\" clen-hdr=\"\" ContentLength=-1 Uncompressed=true n=128 same=true err=<nil> out=\"gzip round trip gzip rou…\"",
    "disabled/gzip                      -> code=200 saw-ae=\"\" ce=\"gzip\" clen-hdr=\"42\" ContentLength=42 Uncompressed=false n=42 same=false err=<nil> out=\"\\x1f\\x8b\\b\\x00\\x00\\x00\\x00\\x00\\x00\\xffJ\\xaf\\xca,P(\\xca/\\xcdKQ()\\xca…\"",
    "disabled/plain                     -> code=200 saw-ae=\"\" ce=\"\" clen-hdr=\"128\" ContentLength=128 Uncompressed=false n=128 same=true err=<nil> out=\"gzip round trip gzip rou…\"",
    "range-request                      -> code=200 saw-ae=\"\" ce=\"\" clen-hdr=\"128\" ContentLength=128 Uncompressed=false n=128 same=true err=<nil> out=\"gzip round trip gzip rou…\"",
    "head-request                       -> code=200 saw-ae=\"\" ce=\"\" clen-hdr=\"128\" ContentLength=128 Uncompressed=false n=0 same=false err=<nil> out=\"\"",
    "manual-decode -> same=true n=128 err=<nil>",
];

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

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn errText(err: error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    return err.Error();
}
static PAYLOAD: sync::Mutex<Option<string>> = sync::Mutex::new(None);
static GZBYTES: sync::Mutex<Option<slice<goish::types::byte>>> = sync::Mutex::new(None);
struct Backend;
impl Handler for Backend {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &http::Request) {
        let payload = PAYLOAD.Lock().clone().unwrap();
        let gz = GZBYTES.Lock().clone().unwrap();
        let ae = r.Header.Get(s("Accept-Encoding"));
        w.Header()
            .Set(s("X-Saw-Accept-Encoding"), fmt::Sprintf!("%q", ae));
        let p = r.URL.Path.clone();
        if p == "/gzip" {
            w.Header().Set(s("Content-Encoding"), s("gzip"));
            w.Header()
                .Set(s("Content-Length"), fmt::Sprintf!("%d", gz.Len()));
            let _ = w.Write(gz);
        } else if p == "/gzip-always" {
            w.Header().Set(s("Content-Encoding"), s("gzip"));
            let _ = w.Write(gz);
        } else if p == "/gzip-corrupt" {
            w.Header().Set(s("Content-Encoding"), s("gzip"));
            let _ = w.Write(slice::__from_vec(
                b"not actually gzip at all, not even close".to_vec(),
            ));
        } else if p == "/gzip-truncated" {
            w.Header().Set(s("Content-Encoding"), s("gzip"));
            let _ = w.Write(gz.slice(0, gz.Len() / 2));
        } else if p == "/gzip-empty" {
            w.Header().Set(s("Content-Encoding"), s("gzip"));
        } else if p == "/identity" {
            w.Header().Set(s("Content-Encoding"), s("identity"));
            let _ = w.Write(slice::__from_vec(payload.as_bytes().to_vec()));
        } else if p == "/deflate" {
            w.Header().Set(s("Content-Encoding"), s("deflate"));
            let _ = w.Write(slice::__from_vec(payload.as_bytes().to_vec()));
        } else {
            let _ = w.Write(slice::__from_vec(payload.as_bytes().to_vec()));
        }
    }
}
fn show(
    failed: &mut int,
    ln: &mut int,
    label: string,
    resp: &mut http::Response,
    err: error,
    payload: &string,
) {
    if err != goish::nil {
        chk(
            failed,
            ln,
            fmt::Sprintf!("%-34s -> err=%s", label, err.Error()),
        );
        return;
    }
    let (body, rerr) = io::ReadAll(&mut resp.Body);
    let _ = io::Closer::Close(&mut resp.Body);
    let out = string::from_bytes(&body.to_vec());
    let same = out == *payload;
    let shown = if out.Len() > 24 {
        string::from_bytes(&out.as_bytes()[..24]) + "…"
    } else {
        out
    };
    chk(failed, ln, fmt::Sprintf!(
        "%-34s -> code=%d saw-ae=%s ce=%q clen-hdr=%q ContentLength=%d Uncompressed=%v n=%d same=%v err=%s out=%q",
        label, resp.StatusCode,
        resp.Header.Get(s("X-Saw-Accept-Encoding")),
        resp.Header.Get(s("Content-Encoding")),
        resp.Header.Get(s("Content-Length")),
        resp.ContentLength, resp.Uncompressed, body.Len(), same,
        errText(rerr), shown
    ));
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let payload = strings::Repeat(s("gzip round trip "), 8);
    {
        let mut buf = bytes::Buffer::new();
        let mut zw = gzip::NewWriter(&mut buf);
        let _ = zw.Write(slice::__from_vec(payload.as_bytes().to_vec()));
        let _ = zw.Close();
        *GZBYTES.Lock() = Some(buf.Bytes());
    }
    *PAYLOAD.Lock() = Some(payload.clone());
    let srv = httptest::NewServer(Arc::new(Backend) as Arc<dyn Handler>);
    let base = srv.URL();
    let paths = [
        "/gzip",
        "/gzip-always",
        "/plain",
        "/identity",
        "/deflate",
        "/gzip-corrupt",
        "/gzip-truncated",
        "/gzip-empty",
    ];
    for p in paths {
        let mut c = http::Client::default();
        c.Transport = Arc::new(http::Transport::default());
        let (mut resp, err) = c.Get(base.clone() + s(p));
        show(
            &mut failed,
            &mut ln,
            string::from("default") + s(p),
            &mut resp,
            err,
            &payload,
        );
    }
    for ae in ["gzip", "gzip, deflate", "identity", "*", ""] {
        let (mut req, _) = http::NewRequest(s("GET"), base.clone() + s("/gzip"), ());
        if ae != "" {
            req.Header.Set(s("Accept-Encoding"), s(ae));
        } else {
            req.Header.Set(s("Accept-Encoding"), string::new());
        }
        let mut c = http::Client::default();
        c.Transport = Arc::new(http::Transport::default());
        let (mut resp, err) = c.Do(&req);
        show(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("caller-ae=%-14q", s(ae)),
            &mut resp,
            err,
            &payload,
        );
    }
    for p in ["/gzip", "/plain"] {
        let mut tr = http::Transport::default();
        tr.DisableCompression = true;
        let mut c = http::Client::default();
        c.Transport = Arc::new(tr);
        let (mut resp, err) = c.Get(base.clone() + s(p));
        show(
            &mut failed,
            &mut ln,
            string::from("disabled") + s(p),
            &mut resp,
            err,
            &payload,
        );
    }
    {
        let (mut req, _) = http::NewRequest(s("GET"), base.clone() + s("/plain"), ());
        req.Header.Set(s("Range"), s("bytes=0-3"));
        let mut c = http::Client::default();
        c.Transport = Arc::new(http::Transport::default());
        let (mut resp, err) = c.Do(&req);
        show(
            &mut failed,
            &mut ln,
            s("range-request"),
            &mut resp,
            err,
            &payload,
        );
    }
    {
        let mut c = http::Client::default();
        c.Transport = Arc::new(http::Transport::default());
        let (mut resp, err) = c.Head(base.clone() + s("/plain"));
        show(
            &mut failed,
            &mut ln,
            s("head-request"),
            &mut resp,
            err,
            &payload,
        );
    }
    {
        let (mut req, _) = http::NewRequest(s("GET"), base.clone() + s("/gzip"), ());
        req.Header.Set(s("Accept-Encoding"), s("gzip"));
        let mut c = http::Client::default();
        c.Transport = Arc::new(http::Transport::default());
        let (mut resp, err) = c.Do(&req);
        if err != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("manual-decode -> err=%s", err.Error()),
            );
        } else {
            let (raw, _) = io::ReadAll(&mut resp.Body);
            let _ = io::Closer::Close(&mut resp.Body);
            let mut rd = bytes::NewReader(raw);
            let (mut zr, zerr) = gzip::NewReader(&mut rd);
            if zerr != goish::nil {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!("manual-decode -> newreader-err=%s", zerr.Error()),
                );
            } else {
                let (out, rerr) = io::ReadAll(&mut zr);
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!(
                        "manual-decode -> same=%v n=%d err=%s",
                        string::from_bytes(&out.to_vec()) == payload.clone(),
                        out.Len(),
                        errText(rerr)
                    ),
                );
            }
        }
    }
    Arc::clone(&srv).Close();
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
