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
const HOP_HEADERS: &[&str] = &[
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
    for h in HOP_HEADERS.iter() {
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
        w: &(dyn super::super::response::ResponseWriter + Send + Sync + 'static),
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
        let (fl, has_fl) = crate::cast!(w, super::super::response::Flusher);
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
