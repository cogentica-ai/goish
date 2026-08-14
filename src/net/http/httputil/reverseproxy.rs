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
///   - X-Forwarded-For IS appended (Go's Director-path
///     behaviour); X-Forwarded-Host / -Proto are not set, since
///     those come from SetXForwarded, which needs the ProxyRequest
///     type goish does not have.
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
        rewriteRequestURL(&mut outreq, &self.target);
        // Drop the original Host so URL.Host wins on serialization.
        outreq.Host = string::new();

        // Go: removeHopByHopHeaders(outreq.Header)
        let inner = outreq.Header.__inner().clone();
        for (k, _) in inner.__iter() {
            if isHopHeader(k) {
                outreq.Header.Del(k.clone());
            }
        }

        // Go: append the client IP to X-Forwarded-For
        // (reverseproxy.go, ServeHTTP's Director path).
        //
        // This was MISSING, and the file's header comment called it a
        // deliberate "slim" omission. It is not a safe omission for a
        // proxy: the inbound header was copied to the outbound request
        // VERBATIM, so a client could send any X-Forwarded-For it
        // liked and the backend would see it unchanged. Go always
        // appends the real peer address, which is what makes the LAST
        // entry trustworthy no matter what the client claimed.
        //
        // Go folds multiple prior headers into one comma+space list
        // before appending. It also honours Issue 38079 — an explicit
        // nil entry means "do not populate" — which goish cannot
        // express, since its Header maps a key to a value list with no
        // nil-versus-absent distinction; a caller wanting the header
        // suppressed must Del it after the proxy runs.
        {
            let (clientIP, _, sperr) = crate::net::SplitHostPort(outreq.RemoteAddr.clone());
            if sperr.IsNil() {
                let prior = outreq.Header.Values(string("X-Forwarded-For"));
                let mut v = clientIP;
                if prior.len() > 0 {
                    let mut joined = string::new();
                    for i in 0..prior.len() {
                        if i > 0 {
                            joined = joined + string(", ");
                        }
                        joined = joined + prior[i].clone();
                    }
                    v = joined + string(", ") + v;
                }
                outreq.Header.Set(string("X-Forwarded-For"), v);
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


// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:234-252 joinURLPath
//
/// Joins the target's path with the incoming request's, returning
/// both the decoded path and the raw (escaped) one.
///
/// When NEITHER url carries a RawPath this is just
/// `singleJoiningSlash` on the decoded paths. Otherwise Go decides
/// where the slash goes using the ESCAPED paths, while still building
/// the decoded result from the decoded ones — the two answers can
/// differ when a segment contains an encoded slash, and getting it
/// from the decoded path alone would let "%2F" change which target
/// path a request lands on.
pub fn joinURLPath(
    a: &super::super::url::URL,
    b: &super::super::url::URL,
) -> (string, string) {
    if a.RawPath.Len() == 0 && b.RawPath.Len() == 0 {
        return (singleJoiningSlash(a.Path.clone(), b.Path.clone()), string::new());
    }
    let apath = a.EscapedPath();
    let bpath = b.EscapedPath();
    let aslash = crate::strings::HasSuffix(apath.clone(), string("/"));
    let bslash = crate::strings::HasPrefix(bpath.clone(), string("/"));
    if aslash && bslash {
        return (
            a.Path.clone() + b.Path.slice(1, b.Path.Len()),
            apath.clone() + bpath.slice(1, bpath.Len()),
        );
    }
    if !aslash && !bslash {
        return (
            a.Path.clone() + string("/") + b.Path.clone(),
            apath + string("/") + bpath,
        );
    }
    return (a.Path.clone() + b.Path.clone(), apath + bpath);
}

// goishlint:ignore GOISH019 ReverseProxy — Go's struct also carries
// BufferPool (an io buffer recycler, which would sit on the open
// sync::Pool fault) and the httptrace/h2 plumbing. What lands are the
// fields the methods below actually read.
// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:112-213 ReverseProxy
/// Go: "ReverseProxy is an HTTP Handler that takes an incoming request
/// and sends it to another server, proxying the response back to the
/// client."
///
/// STAGED: `ServeHTTP` is not ported — it needs the streaming response
/// copy, which needs Body as io.ReadCloser. goish's working proxy is
/// still `NewSingleHostReverseProxy`. What lands here is the POLICY
/// that handler consults, which is testable on its own.
#[derive(Default)]
pub struct ReverseProxy {
    /// Go: "Rewrite must be a function which modifies the request into
    /// a new request to be sent using Transport." Preferred over
    /// Director — it cannot accidentally forward the inbound
    /// X-Forwarded-For.
    pub Rewrite: Option<alloc::sync::Arc<dyn Fn(&mut ProxyRequest) + Send + Sync>>,
    /// Go: "Deprecated: Use Rewrite instead."
    pub Director:
        Option<alloc::sync::Arc<dyn Fn(&mut super::super::request::Request) + Send + Sync>>,
    /// Go: "the flush interval to flush to the client while copying
    /// the response body. If zero, no periodic flushing is done. A
    /// negative value means to flush immediately."
    pub FlushInterval: crate::time::Duration,
    /// Go: "an optional logger for errors […] If nil, logging is done
    /// via the log package's standard logger."
    pub ErrorLog: Option<alloc::sync::Arc<crate::log::Logger>>,
    /// Go: "an optional function that modifies the Response from the
    /// backend. […] If it returns an error, ErrorHandler is called."
    pub ModifyResponse: Option<
        alloc::sync::Arc<dyn Fn(&mut super::super::response::Response) -> crate::errors::error + Send + Sync>,
    >,
    /// Go: "an optional function that handles errors reaching the
    /// backend or errors from ModifyResponse."
    pub ErrorHandler: Option<
        alloc::sync::Arc<
            dyn Fn(
                    &(dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static),
                    &super::super::request::Request,
                    crate::errors::error,
                ) + Send
                + Sync,
        >,
    >,
}

impl ReverseProxy {
    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:684-692 ReverseProxy.logf
    /// Go's signature is `logf(format string, args ...any)`; goish has
    /// no variadic `any`, so callers format with `fmt::Sprintf!` and
    /// pass the finished string. `args` is kept as an empty slice so
    /// the arity matches and a future variadic form has somewhere to
    /// land — the same shape `Server.logf` uses.
    pub fn logf(
        &self,
        format: crate::string,
        args: crate::goslice::slice<crate::string>,
    ) {
        // goish's Sprintv takes `slice<Arc<dyn Any>>`; the only caller
        // today passes no args, so the formatted string arrives ready.
        let _ = &args;
        let msg = format;
        match self.ErrorLog.as_ref() {
            Some(l) => {
                let _ = l.Output(2, msg);
            }
            None => {
                crate::log::Printf!("%s", msg);
            }
        }
        return;
    }

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:319-322 ReverseProxy.defaultErrorHandler
    /// Go: log the error and answer 502. The STATUS is the contract —
    /// a backend failure must not surface as a 500, which blames the
    /// proxy, nor as the backend's own code, which it never sent.
    pub fn defaultErrorHandler(
        &self,
        rw: &(dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static),
        _req: &super::super::request::Request,
        err: crate::errors::error,
    ) {
        self.logf(
            crate::fmt::Sprintf!("http: proxy error: %v", err),
            crate::goslice::slice::<crate::string>::new(),
        );
        rw.WriteHeader(super::super::status::StatusBadGateway);
        return;
    }

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:324-329 ReverseProxy.getErrorHandler
    /// Go returns `p.ErrorHandler` when set, else the bound
    /// `p.defaultErrorHandler`. goish cannot return a bound method as
    /// a value, so this reports WHICH to use and `handleError` below
    /// dispatches — same two outcomes, one indirection fewer.
    pub fn getErrorHandler(
        &self,
    ) -> Option<
        alloc::sync::Arc<
            dyn Fn(
                    &(dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static),
                    &super::super::request::Request,
                    crate::errors::error,
                ) + Send
                + Sync,
        >,
    > {
        return self.ErrorHandler.clone();
    }

    // go: none — goish-only: the call half of getErrorHandler. Go
    // writes `p.getErrorHandler()(rw, req, err)`; a bound method value
    // has no Rust equivalent, so the fallback lives here.
    pub fn handleError(
        &self,
        rw: &(dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static),
        req: &super::super::request::Request,
        err: crate::errors::error,
    ) {
        match self.getErrorHandler() {
            Some(h) => {
                h(rw, req, err);
            }
            None => {
                self.defaultErrorHandler(rw, req, err);
            }
        }
        return;
    }

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:333-344 ReverseProxy.modifyResponse
    /// Run the caller's ModifyResponse hook. Reports whether to
    /// CONTINUE proxying.
    ///
    /// On error Go closes the response body BEFORE invoking the error
    /// handler — the backend conn is finished with either way, and
    /// skipping the close leaks it on every rejected response.
    pub fn modifyResponse(
        &self,
        rw: &(dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static),
        res: &mut super::super::response::Response,
        req: &super::super::request::Request,
    ) -> bool {
        let f = match self.ModifyResponse.as_ref() {
            None => {
                return true;
            }
            Some(f) => f.clone(),
        };
        let err = f(res);
        if !err.IsNil() {
            let _ = res.Body.__close_shared();
            self.handleError(rw, req, err);
            return false;
        }
        return true;
    }

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:607-624 ReverseProxy.flushInterval
    /// Two cases force IMMEDIATE flushing regardless of the configured
    /// interval, and both are streams that never end: a
    /// `text/event-stream` response, and one with an unknown
    /// ContentLength. Buffering either means the client sees nothing
    /// until the backend closes — which for SSE is never.
    pub fn flushInterval(
        &self,
        res: &super::super::response::Response,
    ) -> crate::time::Duration {
        let resCT = res.Header.Get(crate::string("Content-Type"));
        let (baseCT, _, _) = crate::mime::ParseMediaType(resCT);
        if baseCT == "text/event-stream" {
            return crate::time::Duration(-1);
        }
        if res.ContentLength == -1 {
            return crate::time::Duration(-1);
        }
        return self.FlushInterval;
    }
}

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:30-40 ProxyRequest
/// Go: "A ProxyRequest contains a request to be rewritten by a
/// ReverseProxy." `In` is the inbound request as received; `Out` is
/// the one that will be sent upstream, and is the only one a Rewrite
/// func may mutate.
pub struct ProxyRequest<'a> {
    /// Go: "the request received by the proxy. The Rewrite function
    /// must not modify In."
    pub In: &'a super::super::request::Request,
    /// Go: "the request which will be sent by the proxy."
    pub Out: &'a mut super::super::request::Request,
}

impl<'a> ProxyRequest<'a> {
    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:56-59 ProxyRequest.SetURL
    /// Go: rewrite the outbound URL to route to `target`, then CLEAR
    /// `Out.Host`.
    ///
    /// That clearing is the load-bearing half. Leaving Host set sends
    /// the client's Host header to the backend, so a backend that
    /// routes by Host — a vhost, or anything doing name-based TLS —
    /// sees the wrong site. Go's own doc says SetURL "rewrites the
    /// outbound Host header to match the target's host".
    pub fn SetURL(&mut self, target: &super::super::url::URL) {
        rewriteRequestURL(self.Out, target);
        self.Out.Host = crate::string::new();
        return;
    }

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:80-97 ProxyRequest.SetXForwarded
    /// Go: "sets the X-Forwarded-For, X-Forwarded-Host, and
    /// X-Forwarded-Proto headers of the outbound request."
    ///
    /// It appends to the OUTBOUND header, not the inbound one — so a
    /// Rewrite that has not copied the client's X-Forwarded-For across
    /// gets a chain containing only addresses this proxy observed,
    /// which is what makes the value trustworthy. And when RemoteAddr
    /// cannot be split, the header is DELETED rather than left alone:
    /// a stale value is worse than none.
    pub fn SetXForwarded(&mut self) {
        let (clientIP, _, err) = crate::net::SplitHostPort(self.In.RemoteAddr.clone());
        if err.IsNil() {
            let prior = self.Out.Header.Values(crate::string("X-Forwarded-For"));
            let mut v = clientIP;
            if prior.Len() > 0 {
                let mut joined = crate::string::new();
                for i in 0..prior.Len() {
                    if i > 0 {
                        joined = crate::fmt::Sprintf!("%s, %s", joined, prior[i].clone());
                    } else {
                        joined = prior[i].clone();
                    }
                }
                v = crate::fmt::Sprintf!("%s, %s", joined, v);
            }
            self.Out.Header.Set(crate::string("X-Forwarded-For"), v);
        } else {
            self.Out.Header.Del(crate::string("X-Forwarded-For"));
        }
        self.Out
            .Header
            .Set(crate::string("X-Forwarded-Host"), self.In.Host.clone());
        if self.In.TLS.is_none() {
            self.Out
                .Header
                .Set(crate::string("X-Forwarded-Proto"), crate::string("http"));
        } else {
            self.Out
                .Header
                .Set(crate::string("X-Forwarded-Proto"), crate::string("https"));
        }
        return;
    }
}

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:282-291 rewriteRequestURL
//
/// Points `req` at `target`: target scheme and host, the two paths
/// joined, and the two queries concatenated with `&` only when BOTH
/// are non-empty.
pub fn rewriteRequestURL(
    req: &mut super::super::request::Request,
    target: &super::super::url::URL,
) {
    let targetQuery = target.RawQuery.clone();
    req.URL.Scheme = target.Scheme.clone();
    req.URL.Host = target.Host.clone();
    let (p, rp) = joinURLPath(target, &req.URL);
    req.URL.Path = p;
    req.URL.RawPath = rp;
    if targetQuery.Len() == 0 || req.URL.RawQuery.Len() == 0 {
        req.URL.RawQuery = targetQuery + req.URL.RawQuery.clone();
    } else {
        req.URL.RawQuery = targetQuery + string("&") + req.URL.RawQuery.clone();
    }
}
