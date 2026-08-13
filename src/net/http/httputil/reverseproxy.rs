// net/http/httputil/reverseproxy.go — the reverse proxy handler.

#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::types::byte;
use crate::string;
use crate::strings;


// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:275-280 NewSingleHostReverseProxy
/// Returns a Handler that forwards every request to `target`.
/// Returns a Handler that forwards every incoming request to `target`,
/// rewriting the URL's Scheme/Host/Path and stripping hop-by-hop
/// headers in both directions.
///
/// Slim deviations from Go:
///   - No Director, ModifyResponse, ErrorHandler, or Transport hooks
///     (the proxy uses a default `http::Client`).
///   - No streaming Body — request body is `slice<byte>` already.
///   - No X-Forwarded-For / X-Forwarded-Host injection (slim).
///   - No connection upgrade (websocket) handling.
///
/// Sufficient for in-process reverse-proxy demos and basic load
/// balancers; not a drop-in for Go's hardened `httputil.ReverseProxy`.
pub fn NewSingleHostReverseProxy(
    target: super::super::url::URL,
) -> alloc::sync::Arc<dyn super::super::server::Handler> {
    return alloc::sync::Arc::new(reverseProxyHandler {
        target,
        client: alloc::sync::Arc::new(super::super::client::Client::default()),
    });
}

#[allow(non_camel_case_types)]
// go: none — goish-only. Go's ReverseProxy is a struct with Director
// / Rewrite / Transport fields that IS the Handler; this is the slim
// single-host form NewSingleHostReverseProxy returns.
struct reverseProxyHandler {
    target: super::super::url::URL,
    client: alloc::sync::Arc<super::super::client::Client>,
}

/// Hop-by-hop headers (RFC 7230). Stripped before forwarding the
/// request and before relaying the response back to the original
/// client. Mirrors Go's `hopHeaders` (reverseproxy.go:307).
// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:307-317 hopHeaders
//
// Go: "Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility."
const hopHeaders: &[&str] = &[
    "Connection",
    "Proxy-Connection",
    "Keep-Alive",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "Te",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
];

// go: none — goish-only helper. Go tests membership inline against
// the `hopHeaders` slice at each call site; this names the check.
fn isHopHeader(name: &string) -> bool {
    for h in hopHeaders.iter() {
        if crate::strings::EqualFold(name.clone(), string(*h)) {
            return true;
        }
    }
    return false;
}

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:234-253 joinURLPath
/// Appends
/// req's path to target's, gluing with a single '/'.
fn join_url_path(target_path: &string, req_path: &string) -> string {
    let a = target_path.clone();
    let b = req_path.clone();
    let a_slash = crate::strings::HasSuffix(a.clone(), string("/"));
    let b_slash = crate::strings::HasPrefix(b.clone(), string("/"));
    let mut out = strings::Builder::new();
    if a_slash && b_slash {
        let _ = out.WriteString(a.clone());
        let trimmed = crate::strings::TrimPrefix(b, string("/"));
        let _ = out.WriteString(trimmed);
    } else if !a_slash && !b_slash {
        let _ = out.WriteString(a.clone());
        if a.Len() > 0 && b.Len() > 0 {
            let _ = out.WriteByte(b'/');
        }
        let _ = out.WriteString(b);
    } else {
        let _ = out.WriteString(a);
        let _ = out.WriteString(b);
    }
    return out.String();
}

impl super::super::server::Handler for reverseProxyHandler {
    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:345-565 ReverseProxy.ServeHTTP
    fn ServeHTTP(
        &self,
        w: &(dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static),
        r: &super::super::request::Request,
    ) {
        // Go: outreq := req.Clone(req.Context())
        let mut outreq = r.clone();

        // Go: rewriteRequestURL(req, target)
        outreq.URL.Scheme = self.target.Scheme.clone();
        outreq.URL.Host = self.target.Host.clone();
        outreq.URL.Path = join_url_path(&self.target.Path, &r.URL.Path);
        outreq.URL.RawPath = outreq.URL.Path.clone();
        // Combine target query with request query, preferring incoming.
        if self.target.RawQuery.Len() > 0 || r.URL.RawQuery.Len() > 0 {
            if self.target.RawQuery.Len() == 0 || r.URL.RawQuery.Len() == 0 {
                let mut q = strings::Builder::new();
                let _ = q.WriteString(self.target.RawQuery.clone());
                let _ = q.WriteString(r.URL.RawQuery.clone());
                outreq.URL.RawQuery = q.String();
            } else {
                let mut q = strings::Builder::new();
                let _ = q.WriteString(self.target.RawQuery.clone());
                let _ = q.WriteByte(b'&');
                let _ = q.WriteString(r.URL.RawQuery.clone());
                outreq.URL.RawQuery = q.String();
            }
        }
        // Drop the original Host so URL.Host wins on serialization.
        outreq.Host = string::new();

        // Go: removeHopByHopHeaders(outreq.Header)
        let inner = outreq.Header.__inner().clone();
        for (k, _) in inner.__iter() {
            if isHopHeader(k) {
                outreq.Header.Del(k.clone());
            }
        }

        // Go: roundTrip via Transport / our Client.
        let (mut resp, err) = self.client.Do(&outreq);
        if !err.IsNil() {
            super::super::server::Error(
                w,
                string("Bad Gateway"),
                super::super::status::StatusBadGateway,
            );
            return;
        }

        // Go: copyHeader(rw.Header(), res.Header) minus hop-by-hop.
        let r_inner = resp.Header.__inner();
        for (k, vs) in r_inner.__iter() {
            if isHopHeader(k) {
                continue;
            }
            for i in 0..vs.Len() {
                w.Header().Add(k.clone(), vs[i].clone());
            }
        }

        // Go: rw.WriteHeader(res.StatusCode)
        w.WriteHeader(resp.StatusCode);

        // Go: io.Copy(rw, res.Body) — streamed chunk-by-chunk, with a
        // Flush after each write so flushed upstream chunks (SSE, LLM
        // token streams) pass through the proxy live instead of
        // buffering until upstream EOF. (Go gets the same effect via
        // ReverseProxy.FlushInterval / the periodicFlusher.)
        let (fl, has_fl) = crate::cast!(w, super::super::responsewriter::Flusher);
        loop {
            let mut buf = crate::make!([]byte, 32 * 1024);
            let (n, rerr) = crate::io::Reader::Read(&mut resp.Body, &mut buf);
            if n > 0 {
                let _ = w.Write(buf.slice(0, n));
                if has_fl {
                    fl.Flush();
                }
            }
            if !rerr.IsNil() {
                break;
            }
        }
        let _ = crate::io::Closer::Close(&mut resp.Body);
    }
}

// go: none — goish idiom: `reverseProxyHandler` is unexported, so only
// this module can register it. See AGENTS.md §9b.
pub(crate) fn register_httputil_impls() {
    super::super::server::__goish_register_Handler_impl::<reverseProxyHandler>();
}

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:222-232 singleJoiningSlash
//
/// Join two path halves with exactly one '/' between them: a trailing
/// slash on `a` and a leading one on `b` collapse to one, and neither
/// having one inserts one.
pub fn singleJoiningSlash<A: Into<string>, B: Into<string>>(a: A, b: B) -> string {
    let a: string = a.into();
    let b: string = b.into();
    let aslash = strings::HasSuffix(a.clone(), string("/"));
    let bslash = strings::HasPrefix(b.clone(), string("/"));
    if aslash && bslash {
        return a + b.slice(1, b.Len());
    }
    if !aslash && !bslash {
        return a + "/" + b;
    }
    return a + b;
}

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:294-300 copyHeader
//
/// Append every value of `src` onto `dst`, key by key. Go uses `Add`,
/// not `Set`, so a key present in both ends up with BOTH sets of
/// values rather than dst's being replaced.
pub fn copyHeader(dst: &mut super::super::header::Header, src: &super::super::header::Header) {
    for (k, vv) in src.__inner().__iter() {
        let n = crate::len(vv);
        let mut i: crate::types::int = 0;
        while i < n {
            dst.Add(k.clone(), vv[i].clone());
            i += 1;
        }
    }
}

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:877-887 ishex
pub fn ishex(c: crate::types::byte) -> bool {
    if b'0' <= c && c <= b'9' {
        return true;
    }
    if b'a' <= c && c <= b'f' {
        return true;
    }
    if b'A' <= c && c <= b'F' {
        return true;
    }
    return false;
}

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:588-605 removeHopByHopHeaders
//
/// Strip hop-by-hop headers before forwarding to a backend.
///
/// Two passes, and the ORDER matters: RFC 7230 §6.1 says the
/// Connection header itself lists the hop-by-hop names, so those are
/// removed first — while the Connection header is still present to be
/// read. Only then is the fixed RFC 2616 §13.5.1 list removed, which
/// includes Connection itself. Doing it the other way round would
/// delete Connection before reading it and leak whatever it named.
pub fn removeHopByHopHeaders(h: &mut super::super::header::Header) {
    // Go: remove headers listed in the "Connection" header.
    let conn = h.Values(string("Connection"));
    let cn = crate::len(&conn);
    let mut ci: crate::types::int = 0;
    let mut doomed: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    while ci < cn {
        let parts = strings::Split(conn[ci].clone(), string(","));
        ci += 1;
        let pn = crate::len(&parts);
        let mut pi: crate::types::int = 0;
        while pi < pn {
            let sf = crate::net::textproto::TrimString(parts[pi].clone());
            pi += 1;
            if sf != "" {
                doomed.push(sf);
            }
        }
    }
    for k in doomed.iter() {
        h.Del(k.clone());
    }
    // Go: remove the known hop-by-hop set, for backwards compatibility.
    for f in hopHeaders.iter() {
        h.Del(string(*f));
    }
}

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:743-748 upgradeType
//
/// The protocol named in an `Upgrade:` header, but ONLY when
/// `Connection:` actually lists the `Upgrade` token. Both conditions
/// are required — an `Upgrade: websocket` with no matching
/// `Connection` is not an upgrade request, and treating it as one is
/// how a proxy gets talked into hijacking a plain HTTP connection.
///
/// Go calls `httpguts.HeaderValuesContainsToken(h["Connection"],
/// "Upgrade")`, which scans EVERY value of the Connection header;
/// goish's `hasToken` takes a single value, so this loops.
pub fn upgradeType(h: &super::super::header::Header) -> string {
    let conn = h.Values(string("Connection"));
    let mut found = false;
    for i in 0..conn.len() {
        // Lowercase token required; see the note in response.rs's
        // isProtocolSwitchHeader. "Upgrade" here missed
        // `Connection: upgrade` entirely.
        if super::super::header::hasToken(conn[i].clone(), string("upgrade")) {
            found = true;
            break;
        }
    }
    if !found {
        return string::new();
    }
    return h.Get(string("Upgrade"));
}

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:856-874 cleanQueryParams
//
/// Passes a raw query through untouched when it is already safe, and
/// otherwise re-encodes it by round-tripping through ParseQuery.
///
/// "Unsafe" means either a semicolon — which Go stopped treating as a
/// separator in 1.17, so forwarding it verbatim would let the proxy
/// and the backend disagree about the parameters — or a malformed
/// percent escape. Both are exactly the ambiguities a request-
/// smuggling attempt relies on, which is why the fix is to normalise
/// rather than to reject.
pub fn cleanQueryParams<S: Into<string>>(s: S) -> string {
    let s: string = s.into();
    let b = s.as_bytes();
    let reencode = |q: &string| -> string {
        let (v, _) = super::super::url::ParseQuery(q.clone());
        return super::super::url::ValuesEncode(v);
    };
    let mut i: usize = 0;
    while i < b.len() {
        match b[i] {
            b';' => return reencode(&s),
            b'%' => {
                if i + 2 >= b.len() || !ishex(b[i + 1]) || !ishex(b[i + 2]) {
                    return reencode(&s);
                }
                i += 3;
            }
            _ => i += 1,
        }
    }
    return s;
}
