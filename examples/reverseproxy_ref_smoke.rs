// reverseproxy_ref_smoke — httputil's ReverseProxy against a running Go.
// (net/http/httputil/reverseproxy.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_revproxy_ref.go` run in
// `package httputil` by `scripts/goref.sh`. The backend ECHOES what it
// received, so this measures what crossed the proxy rather than what
// the proxy meant to send.
//
// A reverse proxy sits between a client and a backend, which makes
// every header it forwards a statement the backend will believe, and
// every header it relays back a statement the client will believe. Six
// things were wrong with goish's, and four of them changed what one end
// could tell the other.
//
//   * HOP-BY-HOP STRIPPING WAS HALF DONE, IN BOTH DIRECTIONS. RFC 7230
//     §6.1 says the Connection header itself NAMES further hop-by-hop
//     headers, and those must go too. goish stripped only the fixed
//     RFC 2616 list, so a client sending `Connection: X-Secret` with
//     `X-Secret: …` had X-Secret forwarded where Go deletes it — and a
//     backend answering `Connection: X-Internal` had X-Internal
//     relayed to the client. A connection-option header that survives
//     an intermediary is the raw material of request smuggling: the
//     two ends disagree about which headers belong to the hop and
//     which to the message. `removeHopByHopHeaders` was already
//     written, already documented with the two-pass order that makes
//     it work, and called from nowhere.
//   * THE PROXY FOLLOWED THE BACKEND'S REDIRECTS. Go calls
//     Transport.RoundTrip, exactly one exchange. goish went through
//     Client::Do, which follows up to ten — so a 302 never reached the
//     client and the proxy fetched the target itself, including hosts
//     it was never pointed at. Now CheckRedirect returns
//     ErrUseLastResponse, which is the documented way to say "hand me
//     the redirect, do not chase it".
//   * THE INBOUND HOST WAS DISCARDED. Go leaves req.Host alone, which
//     is what lets a backend do name-based virtual hosting behind a
//     proxy. goish cleared it, because its client dialled and
//     addressed from the same value; the client now separates the two
//     (Request.Host overrides the Host header, as documented) and the
//     inbound Host survives.
//   * `Te: trailers` WAS NOT RE-ADDED after the strip. Te is
//     hop-by-hop but trailers are negotiated end-to-end, so Go puts it
//     back. Without it no request could negotiate trailers across the
//     proxy.
//   * THE RESPONSE'S TRAILER ANNOUNCEMENT WAS LOST. Go rebuilds it
//     from res.Trailer after the strip. goish had nothing to rebuild
//     from, because its response writer derived a Content-Length even
//     when the handler had declared trailers — and a Content-Length
//     response has nowhere to put them. Trailers require chunked
//     framing; the writer now promotes, as Go's `!trailers` guard
//     does.
//   * THE PROXY STAMPED ITS OWN User-Agent on a request that carried
//     none, which the backend then attributes to the client. Go sets
//     it empty instead, the documented way to send none. The error
//     body on an unreachable backend is empty in Go, too.
//
// What is pinned beyond the fixes:
//
//   * X-Forwarded-For is APPENDED to, never replaced, so a backend
//     that trusts the whole list is trusting the client — every entry
//     but the LAST is client-supplied. "xff/spoofed-private" is the
//     shape of that: "127.0.0.1, 192.0.2.9" reaches the backend, and
//     only the second half means anything.
//   * X-Forwarded-Proto and X-Forwarded-Host are NOT touched by this
//     constructor, so a client's claim to have arrived over https, or
//     from evil.example, passes straight through. That is Go's
//     behaviour and it is the reason the Rewrite API exists.
//   * Path joining across the slash boundaries, and query merging with
//     the target's own query first.
//
// One KNOWN GAP, and it is deliberate: Accept-Encoding is excluded
// from the header dump on both sides. Go's TRANSPORT adds
// "Accept-Encoding: gzip" and transparently decodes the result;
// goish's client does neither, which is self-consistent but different.
// Excluding it lets the other thirty lines pin the PROXY exactly
// instead of drowning in one transport-level difference repeated
// everywhere. That gap belongs to net/http's transport, not to this
// file, and it is not fixed here.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::httputil;
use goish::net::http::{Handler, ResponseWriter};
use goish::net::url;
use goish::sort;
use goish::strings;
use goish::syscall;
use goish::types::int;
const GO: [&str; 31] = [
    "hop/plain                    code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "hop/connection-close         code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\" X-Keep=\"yes\"]",
    "hop/connection-names         code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\" X-Keep=\"yes\"]",
    "hop/connection-multi         code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-C=\"3\" X-Forwarded-For=\"192.0.2.9\"]",
    "hop/connection-empty-item    code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "hop/connection-spaces        code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "hop/all-hop-headers          code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[Te=\"trailers\" X-Forwarded-For=\"192.0.2.9\" X-Survives=\"yes\"]",
    "hop/te-not-trailers          code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\" X-Keep=\"yes\"]",
    "hop/connection-names-xff     code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "xff/absent                   code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "xff/present                  code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"1.2.3.4, 192.0.2.9\"]",
    "xff/chain                    code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"1.2.3.4, 5.6.7.8, 192.0.2.9\"]",
    "xff/multi-header             code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"1.2.3.4, 5.6.7.8, 192.0.2.9\"]",
    "xff/spoofed-private          code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"127.0.0.1, 192.0.2.9\"]",
    "xff/client-sets-proto        code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\" X-Forwarded-Host=\"evil.example\" X-Forwarded-Proto=\"https\"]",
    "xff/connection-names-xff     code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/root->root              code=200 method=GET uri=\"/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/prefix                  code=200 method=GET uri=\"/api/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/prefix-slash            code=200 method=GET uri=\"/api/x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/prefix+slash-req        code=200 method=GET uri=\"/api//x\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/req-root                code=200 method=GET uri=\"/api/\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/req-empty               code=200 method=GET uri=\"/api/\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/escaped-req             code=200 method=GET uri=\"/api/a%2Fb\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/dots-req                code=200 method=GET uri=\"/api/a/../b\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/query-req               code=200 method=GET uri=\"/api/x?a=1\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/query-both              code=200 method=GET uri=\"/api/x?t=9&a=1\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/query-target-only       code=200 method=GET uri=\"/api/x?t=9\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/semicolon-query         code=200 method=GET uri=\"/api/x?a=1;b=2\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "path/unicode                 code=200 method=GET uri=\"/api/%E2%98%83\" proto=HTTP/1.1 host=\"front\" hdr=[X-Forwarded-For=\"192.0.2.9\"]",
    "error/unreachable            code=502 body=\"\"",
    "resp/hop-stripped            code=203 hdr=[Content-Type=\"text/plain; charset=utf-8\" Trailer=\"X-T\" X-Ok=\"fine\"] body=\"body\"",
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
fn hdrDump(h: &http::Header) -> string {
    let mut keys: Vec<string> = Vec::new();
    for (k, _) in h.__inner().__iter() {
        keys.push(k.clone());
    }
    let mut ks = slice::<string>::__from_vec(keys);
    sort::Strings(&mut ks);
    let mut parts: Vec<string> = Vec::new();
    for i in 0..ks.Len() {
        let k = ks[i].clone();
        let vs = h.Values(k.clone());
        let mut joined = string::new();
        for j in 0..vs.Len() {
            if j > 0 {
                joined = joined + "|";
            }
            joined = joined + vs[j].clone();
        }
        parts.push(fmt::Sprintf!("%s=%q", k, joined));
    }
    return strings::Join(slice::<string>::__from_vec(parts), s(" "));
}
struct EchoReq;
impl Handler for EchoReq {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &http::Request) {
        let out = fmt::Sprintf!(
            "method=%s uri=%q proto=%s host=%q hdr=[%s]",
            r.Method.clone(),
            r.RequestURI.clone(),
            r.Proto.clone(),
            r.Host.clone(),
            hdrDump(&r.Header)
        );
        let _ = w.Write(slice::__from_vec(out.as_bytes().to_vec()));
    }
}

struct HopBackend;
impl Handler for HopBackend {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &http::Request) {
        w.Header().Set(s("Connection"), s("X-Backend-Secret"));
        w.Header().Set(s("X-Backend-Secret"), s("leaked"));
        w.Header().Set(s("Keep-Alive"), s("timeout=5"));
        w.Header().Set(s("X-Ok"), s("fine"));
        w.Header().Set(s("Trailer"), s("X-T"));
        w.WriteHeader(203);
        let _ = w.Write(slice::__from_vec(b"body".to_vec()));
    }
}

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    // A bare Handler, NOT a ServeMux: a mux would clean "/api//x" and
    // "/api/a/../b" and answer a redirect, measuring the mux instead
    // of the proxy.
    let backend = httptest::NewServer(Arc::new(EchoReq) as Arc<dyn Handler>);
    let backurl = backend.URL();
    let (burl, _) = url::Parse(backurl.clone());
    let bhost = burl.Host.clone();
    let norm = |x: string| -> string {
        return strings::ReplaceAll(x, bhost.clone(), s("BACKEND"));
    };
    let mkreq = |target: &str, hdrs: &[(&str, &str)]| -> http::Request {
        let mut r = httptest::NewRequest(s("GET"), s(target), ());
        r.RemoteAddr = s("192.0.2.9:1234");
        for (k, v) in hdrs.iter() {
            r.Header.Add(s(k), s(v));
        }
        return r;
    };
    let mut run =
        |failed: &mut int, ln: &mut int, label: &str, target: &url::URL, r: &http::Request| {
            let p = httputil::NewSingleHostReverseProxy(target.clone());
            let w = httptest::NewRecorder();
            p.ServeHTTP(&w, r);
            let body = string::from_bytes(&w.Body().to_vec());
            chk(
                failed,
                ln,
                fmt::Sprintf!("%-28s code=%d %s", s(label), w.Code(), norm(body)),
            );
        };
    run(
        &mut failed,
        &mut ln,
        "hop/plain",
        &burl,
        &mkreq("http://front/x", &[]),
    );
    run(
        &mut failed,
        &mut ln,
        "hop/connection-close",
        &burl,
        &mkreq(
            "http://front/x",
            &[("Connection", "close"), ("X-Keep", "yes")],
        ),
    );
    run(
        &mut failed,
        &mut ln,
        "hop/connection-names",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("Connection", "X-Secret"),
                ("X-Secret", "sensitive"),
                ("X-Keep", "yes"),
            ],
        ),
    );
    run(
        &mut failed,
        &mut ln,
        "hop/connection-multi",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("Connection", "X-A, X-B"),
                ("X-A", "1"),
                ("X-B", "2"),
                ("X-C", "3"),
            ],
        ),
    );
    run(
        &mut failed,
        &mut ln,
        "hop/connection-empty-item",
        &burl,
        &mkreq(
            "http://front/x",
            &[("Connection", "X-A,,X-B"), ("X-A", "1"), ("X-B", "2")],
        ),
    );
    run(
        &mut failed,
        &mut ln,
        "hop/connection-spaces",
        &burl,
        &mkreq("http://front/x", &[("Connection", "  X-A  "), ("X-A", "1")]),
    );
    run(
        &mut failed,
        &mut ln,
        "hop/all-hop-headers",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("Keep-Alive", "timeout=5"),
                ("Proxy-Connection", "keep-alive"),
                ("Proxy-Authenticate", "Basic"),
                ("Proxy-Authorization", "Basic x"),
                ("Te", "trailers"),
                ("Trailer", "X-T"),
                ("Upgrade", "websocket"),
                ("X-Survives", "yes"),
            ],
        ),
    );
    run(
        &mut failed,
        &mut ln,
        "hop/te-not-trailers",
        &burl,
        &mkreq("http://front/x", &[("Te", "gzip"), ("X-Keep", "yes")]),
    );
    run(
        &mut failed,
        &mut ln,
        "hop/connection-names-xff",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("Connection", "X-Forwarded-For"),
                ("X-Forwarded-For", "1.2.3.4"),
            ],
        ),
    );
    run(
        &mut failed,
        &mut ln,
        "xff/absent",
        &burl,
        &mkreq("http://front/x", &[]),
    );
    run(
        &mut failed,
        &mut ln,
        "xff/present",
        &burl,
        &mkreq("http://front/x", &[("X-Forwarded-For", "1.2.3.4")]),
    );
    run(
        &mut failed,
        &mut ln,
        "xff/chain",
        &burl,
        &mkreq("http://front/x", &[("X-Forwarded-For", "1.2.3.4, 5.6.7.8")]),
    );
    run(
        &mut failed,
        &mut ln,
        "xff/multi-header",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("X-Forwarded-For", "1.2.3.4"),
                ("X-Forwarded-For", "5.6.7.8"),
            ],
        ),
    );
    run(
        &mut failed,
        &mut ln,
        "xff/spoofed-private",
        &burl,
        &mkreq("http://front/x", &[("X-Forwarded-For", "127.0.0.1")]),
    );
    run(
        &mut failed,
        &mut ln,
        "xff/client-sets-proto",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "evil.example"),
            ],
        ),
    );
    run(
        &mut failed,
        &mut ln,
        "xff/connection-names-xff",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("Connection", "X-Forwarded-For"),
                ("X-Forwarded-For", "1.2.3.4"),
            ],
        ),
    );
    let paths: [(&str, &str, &str); 13] = [
        ("root->root", "", "http://front/x"),
        ("prefix", "/api", "http://front/x"),
        ("prefix-slash", "/api/", "http://front/x"),
        ("prefix+slash-req", "/api/", "http://front//x"),
        ("req-root", "/api", "http://front/"),
        ("req-empty", "/api", "http://front"),
        ("escaped-req", "/api", "http://front/a%2Fb"),
        ("dots-req", "/api", "http://front/a/../b"),
        ("query-req", "/api", "http://front/x?a=1"),
        ("query-both", "/api?t=9", "http://front/x?a=1"),
        ("query-target-only", "/api?t=9", "http://front/x"),
        ("semicolon-query", "/api", "http://front/x?a=1;b=2"),
        ("unicode", "/api", "http://front/%E2%98%83"),
    ];
    for (name, target, req) in paths.iter() {
        let u = if *target == "" {
            burl.clone()
        } else {
            let (tu, _) = url::Parse(backurl.clone() + s(target));
            tu
        };
        let label = string::from("path/") + s(name);
        let p = httputil::NewSingleHostReverseProxy(u);
        let w = httptest::NewRecorder();
        let r = mkreq(req, &[]);
        p.ServeHTTP(&w, &r);
        let body = string::from_bytes(&w.Body().to_vec());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("%-28s code=%d %s", label, w.Code(), norm(body)),
        );
    }
    {
        let (dead, _) = url::Parse(s("http://127.0.0.1:1"));
        let p = httputil::NewSingleHostReverseProxy(dead);
        let w = httptest::NewRecorder();
        let r = mkreq("http://front/x", &[]);
        p.ServeHTTP(&w, &r);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s code=%d body=%q",
                s("error/unreachable"),
                w.Code(),
                string::from_bytes(&w.Body().to_vec())
            ),
        );
    }
    {
        let b2 = httptest::NewServer(Arc::new(HopBackend) as Arc<dyn Handler>);
        let (u2, _) = url::Parse(b2.URL());
        let p = httputil::NewSingleHostReverseProxy(u2);
        let w = httptest::NewRecorder();
        let r = mkreq("http://front/x", &[]);
        p.ServeHTTP(&w, &r);
        let hm = w.HeaderMap();
        let mut keys: Vec<string> = Vec::new();
        for (k, _) in hm.__inner().__iter() {
            if k == "Date" || k == "Content-Length" {
                continue;
            }
            keys.push(k.clone());
        }
        let mut ks = slice::<string>::__from_vec(keys);
        sort::Strings(&mut ks);
        let mut parts: Vec<string> = Vec::new();
        for i in 0..ks.Len() {
            let k = ks[i].clone();
            let vs = hm.Values(k.clone());
            let mut joined = string::new();
            for j in 0..vs.Len() {
                if j > 0 {
                    joined = joined + "|";
                }
                joined = joined + vs[j].clone();
            }
            parts.push(fmt::Sprintf!("%s=%q", k, joined));
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s code=%d hdr=[%s] body=%q",
                s("resp/hop-stripped"),
                w.Code(),
                strings::Join(slice::<string>::__from_vec(parts), s(" ")),
                string::from_bytes(&w.Body().to_vec())
            ),
        );
        Arc::clone(&b2).Close();
    }
    Arc::clone(&backend).Close();
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
