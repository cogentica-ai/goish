// net/http/httputil/reverseproxy.go — the reverse proxy handler.

#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::string;
use crate::strings;
use crate::types::byte;

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:275-280 NewSingleHostReverseProxy
/// Returns a Handler that forwards every request to `target`.
/// Returns a Handler that forwards every incoming request to `target`,
/// rewriting the URL's Scheme/Host/Path and stripping hop-by-hop
/// headers in both directions.
///
/// This block listed, until 2026-09-06: no Director, ModifyResponse,
/// ErrorHandler or Transport hooks; no connection upgrade handling; and
/// X-Forwarded-Host / -Proto unset "since those come from
/// SetXForwarded, which needs the ProxyRequest type goish does not
/// have". Every one of those has since landed in this file — Director
/// and Rewrite, ModifyResponse, ErrorHandler, Transport, the 101
/// upgrade path, and ProxyRequest::SetXForwarded at line 1534.
///
/// The list went stale the same day it was corrected, because the work
/// that landed those hooks did not touch this paragraph. That is the
/// failure mode being catalogued elsewhere in this tree — a note
/// understating what exists — arriving from the other direction.
///
/// What is still true:
///   - The request body is a `slice<byte>`, so nothing streams; a
///     proxied upload is held whole (ROADMAP section 0 A).
///   - `FlushInterval` is a field and is INERT — see the note above the
///     struct, which explains why and what it is blocked on.
pub fn NewSingleHostReverseProxy(
    target: super::super::url::URL,
) -> alloc::sync::Arc<dyn super::super::server::Handler> {
    let mut c = super::super::client::Client::default();
    // See ServeHTTP: a proxy RELAYS a redirect, it does not chase it.
    c.CheckRedirect = Some(alloc::sync::Arc::new(
        |_req: &super::super::request::Request,
         _via: &[super::super::request::Request]|
         -> crate::errors::error {
            return super::super::client::ErrUseLastResponse.into();
        },
    ));
    return alloc::sync::Arc::new(reverseProxyHandler {
        target,
        client: alloc::sync::Arc::new(c),
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

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:307-317 hopHeaders
/// Hop-by-hop headers (RFC 7230). Stripped before forwarding the
/// request and before relaying the response back to the original
/// client. Mirrors Go's `hopHeaders` (reverseproxy.go:307).
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

// `joinURLPath` lives at its full form further down this file, taking
// two *url.URL and returning (path, rawpath) as Go does. A second,
// string-only port stood here until 2026-09-06: it implemented the
// slash-gluing half and nothing else, had no caller, and carried its
// own anchor for the same Go range — so the file claimed one Go
// declaration twice, with the incomplete copy indistinguishable from
// the real one to every check. Deleted rather than wired up: it drops
// the RawPath branch, which is what keeps an encoded slash in the
// inbound path from being glued into a different upstream path.
// Found by scripts/dead_port_check.py's PRIVATE_DEAD list.

impl super::super::server::Handler for reverseProxyHandler {
    // go: none — goish-only: the slim single-host proxy behind
    // NewSingleHostReverseProxy. It used to carry the anchor for
    // ReverseProxy.ServeHTTP, which is why nothing reported that the
    // real one was missing; the anchor now sits on the port above,
    // and this stays as the hookless handler its own doc describes.
    fn ServeHTTP(
        &self,
        w: &(dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static),
        r: &super::super::request::Request,
    ) {
        // Go: outreq := req.Clone(req.Context())
        let mut outreq = r.clone();
        // The inbound request carries the server-stamped RequestURI;
        // an OUTGOING request must not (client.go `send` refuses it —
        // Go's proxy dodges the guard by calling Transport.RoundTrip
        // directly, goish's routes through the Client).
        outreq.RequestURI = string::new();

        // Go: rewriteRequestURL(req, target)
        rewriteRequestURL(&mut outreq, &self.target);
        // Go leaves req.Host ALONE: "If the Director/Rewrite does not
        // set Host, the outbound request keeps the inbound one", which
        // is what lets a backend do name-based virtual hosting behind
        // a proxy. goish used to clear it, because the client dialled
        // and addressed from the same value and this was the only way
        // to make the URL host win; the client now separates the two,
        // so the inbound Host survives as Go intends.

        // Go (reverseproxy.go:369-372): capture the upgrade type BEFORE
        // the hop-by-hop strip removes Connection/Upgrade, then add
        // both back — "necessary for protocol negotiation". Without
        // the re-add, no upgrade request can traverse the proxy.
        let reqUpType = upgradeType(&outreq.Header);
        // Go: removeHopByHopHeaders(outreq.Header)
        //
        // This used to be an inline loop over `hopHeaders` alone, which
        // is only HALF the rule. RFC 7230 §6.1 says the Connection
        // header itself names further hop-by-hop headers, and those
        // must be removed too — `removeHopByHopHeaders` below does both
        // passes in the order that matters, and was already written,
        // documented and never called.
        //
        // With only the fixed list stripped, a client sending
        // `Connection: X-Secret` alongside `X-Secret: …` had the
        // X-Secret forwarded to the backend, where Go deletes it. A
        // connection-option header that survives an intermediary is
        // the raw material of request smuggling: the two ends disagree
        // about which headers belong to the hop and which to the
        // message.
        //
        // Go re-adds `Te: trailers` after the strip
        // (`httpguts.HeaderValuesContainsToken(req.Header["Te"],
        // "trailers")`), because trailers are negotiated end-to-end
        // even though Te itself is hop-by-hop. That was missing too, so
        // no request could negotiate trailers across the proxy.
        let teTrailers = headerValuesContainToken(&outreq.Header, "Te", "trailers");
        removeHopByHopHeaders(&mut outreq.Header);
        if teTrailers {
            outreq.Header.Set(string("Te"), string("trailers"));
        }
        if reqUpType.Len() != 0 {
            outreq.Header.Set(string("Connection"), string("Upgrade"));
            outreq.Header.Set(string("Upgrade"), reqUpType);
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

        // Go: "If the outbound request doesn't have a User-Agent header
        // set, don't send the default Go HTTP client User-Agent."
        // Setting it EMPTY is the documented way to send none — the
        // serializer tests `has`, not the value. Without this the proxy
        // stamps its own agent on a request that deliberately carried
        // none, which the backend then attributes to the client.
        if !outreq.Header.has(string("User-Agent")) {
            outreq.Header.Set(string("User-Agent"), string::new());
        }

        // Go: roundTrip via Transport / our Client.
        //
        // Go calls Transport.RoundTrip, which performs exactly ONE
        // exchange. goish routes through Client::Do, which by default
        // follows up to ten redirects — so a 302 from the backend never
        // reached the client; the proxy went and fetched the target
        // itself. That is wrong twice over: the client loses a response
        // it was entitled to see, and the proxy is turned into a
        // fetcher for whatever URL the backend names, including hosts
        // it was never pointed at. `ErrUseLastResponse` is the
        // documented way to say "hand me the redirect, do not follow
        // it", which is what a proxy wants.
        let (mut resp, err) = self.client.Do(&outreq);
        if !err.IsNil() {
            // Go's defaultErrorHandler writes the status and NO body.
            w.WriteHeader(super::super::status::StatusBadGateway);
            return;
        }

        // Go: "Deal with 101 Switching Protocols responses: (WebSocket,
        // h2c, etc)" (reverseproxy.go:479) — the conn is handed over,
        // nothing below (header copy / body pump) applies.
        if resp.StatusCode == super::super::status::StatusSwitchingProtocols {
            upgrade_response_impl(w, &outreq, &mut resp, &|e| {
                super::super::server::Error(w, e.Error(), super::super::status::StatusBadGateway);
            });
            return;
        }

        // Go: removeHopByHopHeaders(res.Header), then
        // copyHeader(rw.Header(), res.Header).
        //
        // Same half-rule as the request side, and the leak runs the
        // other way: a backend answering `Connection: X-Internal`
        // alongside `X-Internal: …` expects the proxy to delete
        // X-Internal before the client sees it. goish relayed it.
        removeHopByHopHeaders(&mut resp.Header);
        // Go announces the trailers the response declared, which the
        // strip above has just removed along with the rest of the
        // hop-by-hop set. Without this a client is never told which
        // trailers to expect.
        let announced = resp.Trailer.__inner().Len();
        if announced > 0 {
            let mut keys: alloc::vec::Vec<string> = alloc::vec::Vec::new();
            for (k, _) in resp.Trailer.__inner().__iter() {
                keys.push(k.clone());
            }
            keys.sort_by(|a, b| crate::strings::Compare(a.clone(), b.clone()).cmp(&0));
            let mut joined = string::new();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    joined = joined + ", ";
                }
                joined = joined + k.clone();
            }
            w.Header().Add(string("Trailer"), joined);
        }
        let r_inner = resp.Header.__inner();
        for (k, vs) in r_inner.__iter() {
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

impl super::super::server::Handler for ReverseProxy {
    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:345-565 ReverseProxy.ServeHTTP
    /// Go's proxy request path, assembled from the pieces this file
    /// already had. Deviations, all stated:
    ///
    ///   - `FlushInterval`/`copyResponse` are not used; the body is
    ///     flushed after every write. See ROADMAP 2m — copyResponse
    ///     wants an owned writer and a Handler is handed a borrowed
    ///     one.
    ///   - Go installs an httptrace `Got1xxResponse` hook to relay
    ///     informational responses. goish's httptrace fires no hooks
    ///     (ROADMAP 2j), so there is nothing to install.
    ///   - Go consults `CloseNotifier` when the request context has no
    ///     Done channel; goish's requests always carry a context.
    fn ServeHTTP(
        &self,
        rw: &(dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static),
        req: &super::super::request::Request,
    ) {
        // Go: transport := p.Transport; if nil { http.DefaultTransport }
        let transport: alloc::sync::Arc<dyn super::super::client::RoundTripper> =
            match self.Transport.as_ref() {
                Some(t) => t.clone(),
                None => super::super::transport::DefaultTransport(),
            };

        // Go: outreq := req.Clone(ctx). The inbound request carries the
        // server-stamped RequestURI; an outgoing one must not.
        let mut outreq = req.clone();
        outreq.RequestURI = string::new();

        // Go: if (p.Director != nil) == (p.Rewrite != nil) { error }
        if self.Director.is_some() == self.Rewrite.is_some() {
            self.handleError(
                rw,
                req,
                crate::errors::New("ReverseProxy must have exactly one of Director or Rewrite set"),
            );
            return;
        }

        if let Some(d) = self.Director.as_ref() {
            d(&mut outreq);
        }
        // Go: outreq.Close = false
        outreq.Close = false;

        // Go captures the upgrade type BEFORE the hop-by-hop strip
        // removes Connection/Upgrade, then adds both back.
        let reqUpType = upgradeType(&outreq.Header);
        let teTrailers = headerValuesContainToken(&outreq.Header, "Te", "trailers");
        removeHopByHopHeaders(&mut outreq.Header);
        // Go: trailers are negotiated end-to-end even though Te is
        // hop-by-hop.
        if teTrailers {
            outreq.Header.Set(string("Te"), string("trailers"));
        }
        if reqUpType.Len() != 0 {
            outreq.Header.Set(string("Connection"), string("Upgrade"));
            outreq.Header.Set(string("Upgrade"), reqUpType);
        }

        if let Some(rwf) = self.Rewrite.as_ref() {
            // Go: "Strip client-provided forwarding headers. The
            // Rewrite func may use SetXForwarded to set new values."
            outreq.Header.Del(string("Forwarded"));
            outreq.Header.Del(string("X-Forwarded-For"));
            outreq.Header.Del(string("X-Forwarded-Host"));
            outreq.Header.Del(string("X-Forwarded-Proto"));
            outreq.URL.RawQuery = cleanQueryParams(outreq.URL.RawQuery.clone());
            {
                let mut pr = ProxyRequest {
                    In: req,
                    Out: &mut outreq,
                };
                rwf(&mut pr);
            }
        } else {
            // Go's Director path appends the real peer address, which
            // is what makes the LAST entry trustworthy no matter what
            // the client claimed.
            let (clientIP, _, sperr) = crate::net::SplitHostPort(req.RemoteAddr.clone());
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

        // Go: "If the outbound request doesn't have a User-Agent header
        // set, don't send the default Go HTTP client User-Agent."
        if !outreq.Header.has(string("User-Agent")) {
            outreq.Header.Set(string("User-Agent"), string::new());
        }

        // Go: res, err := transport.RoundTrip(outreq) — exactly ONE
        // exchange, so a 3xx is relayed rather than followed.
        let (mut res, err) = transport.RoundTrip(&outreq);
        if !err.IsNil() {
            self.handleError(rw, &outreq, err);
            return;
        }

        // Go: "Deal with 101 Switching Protocols responses."
        if res.StatusCode == super::super::status::StatusSwitchingProtocols {
            if !self.modifyResponse(rw, &mut res, &outreq) {
                return;
            }
            self.handleUpgradeResponse(rw, &outreq, &mut res);
            return;
        }

        removeHopByHopHeaders(&mut res.Header);

        if !self.modifyResponse(rw, &mut res, &outreq) {
            return;
        }

        // Go: copyHeader(rw.Header(), res.Header). `rw.Header()` hands
        // back a handle rather than a `&mut Header`, so the loop is
        // inline; the rule it implements is copyHeader's — Add, not
        // Set, so a key present in both keeps BOTH sets of values.
        {
            let inner = res.Header.__inner();
            for (k, vs) in inner.__iter() {
                for i in 0..vs.Len() {
                    rw.Header().Add(k.clone(), vs[i].clone());
                }
            }
        }

        // Go: "The Trailer header isn't included in the Transport's
        // response […] Build it up from Trailer."
        let announced = res.Trailer.__inner().Len();
        if announced > 0 {
            let mut keys: alloc::vec::Vec<string> = alloc::vec::Vec::new();
            for (k, _) in res.Trailer.__inner().__iter() {
                keys.push(k.clone());
            }
            keys.sort_by(|a, b| crate::strings::Compare(a.clone(), b.clone()).cmp(&0));
            let mut joined = string::new();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    joined = joined + string(", ");
                }
                joined = joined + k.clone();
            }
            rw.Header().Add(string("Trailer"), joined);
        }

        rw.WriteHeader(res.StatusCode);

        // Go: p.copyResponse(rw, res.Body, p.flushInterval(res)). See
        // the deviation note on the struct: flush every write.
        let (fl, has_fl) = crate::cast!(rw, super::super::responsewriter::Flusher);
        loop {
            let mut buf = crate::make!([]byte, 32 * 1024);
            let (n, rerr) = crate::io::Reader::Read(&mut res.Body, &mut buf);
            if n > 0 {
                let _ = rw.Write(buf.slice(0, n));
                if has_fl {
                    fl.Flush();
                }
            }
            if !rerr.IsNil() {
                break;
            }
        }
        let _ = crate::io::Closer::Close(&mut res.Body);
    }

    // go: none — goish-only interface-registry hook.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: the `&mut` twin of the hook above.
    // Overriding only the immutable one is what hook_pair_check calls
    // MUT_MISSING: `cast!(&mut x, Iface)` then misses silently.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: `reverseProxyHandler` is unexported, so only
// this module can register it. See AGENTS.md §9b.
pub(crate) fn register_httputil_impls() {
    super::super::server::__goish_register_Handler_impl::<reverseProxyHandler>();
    super::super::server::__goish_register_Handler_impl::<ReverseProxy>();
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

// go: none — goish-only. Go reaches for
// `httpguts.HeaderValuesContainsToken(h[key], token)`, which scans
// every value of a multi-valued header; goish's `header::hasToken`
// takes one value at a time, so this loops over them.
fn headerValuesContainToken(h: &super::super::header::Header, key: &str, token: &str) -> bool {
    let vs = h.Values(string::from_bytes(key.as_bytes()));
    for i in 0..vs.Len() {
        if super::super::header::hasToken(vs[i].clone(), string::from_bytes(token.as_bytes())) {
            return true;
        }
    }
    return false;
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

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:820-823 switchProtocolCopier
//
/// Go: "switchProtocolCopier exists so goroutines proxying data back
/// and forth have nice names in stacks." Go's two fields are shared
/// io.ReadWriter interface values, one struct copy per goroutine;
/// Rust ownership splits each conn into a read half and a dup(2)'d
/// write half (see `TCPConn::__dup_handle` / `ConnSrc::
/// split_for_upgrade`), and each copier method takes the pair it
/// owns.
struct switchProtocolCopier {
    /// The hijacked user conn (read half; its dup'd write half rides
    /// beside it into the opposite copier).
    user: crate::net::TCPConn,
    /// The upgraded backend carrier (read half).
    backend: super::super::client::ConnSrc,
}

impl switchProtocolCopier {
    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:825-838 switchProtocolCopier.copyFromBackend
    // goishlint:ignore GOISH020 copyFromBackend — Go's receiver carries
    // the shared conns; goish passes each goroutine its owned halves.
    //
    /// backend → user. On clean backend EOF, Go propagates a
    /// CloseWrite to the user conn (the FIN is how the switched
    /// protocol's peer learns the stream is over) and reports the
    /// half-close's error; otherwise errCopyDone.
    fn copyFromBackend(
        mut backend_r: super::super::client::ConnSrc,
        user_w: crate::net::TCPConn,
        errc: crate::gochan::chan<crate::errors::error>,
    ) {
        let mut user_w = user_w;
        loop {
            let mut buf = crate::make!([]byte, 32 * 1024);
            let (n, rerr) = crate::io::Reader::Read(&mut backend_r, &mut buf);
            if n > 0 {
                let (_, werr) = crate::io::Writer::Write(&mut user_w, buf.slice(0, n));
                if !werr.IsNil() {
                    errc.Send(werr);
                    return;
                }
            }
            if !rerr.IsNil() {
                if !crate::errors::Is(rerr.clone(), crate::io::EOF) {
                    errc.Send(rerr);
                    return;
                }
                // Go: c.user.(interface{ CloseWrite() error })
                errc.Send(user_w.CloseWrite());
                return;
            }
            if n == 0 {
                errc.Send(user_w.CloseWrite());
                return;
            }
        }
    }

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:840-853 switchProtocolCopier.copyToBackend
    // goishlint:ignore GOISH020 copyToBackend — same owned-halves
    // adaptation as copyFromBackend above.
    //
    /// user → backend, with the mirror-image CloseWrite propagation.
    fn copyToBackend(
        user_r: crate::net::TCPConn,
        backend_w: crate::net::TCPConn,
        errc: crate::gochan::chan<crate::errors::error>,
    ) {
        let mut user_r = user_r;
        let mut backend_w = backend_w;
        loop {
            let mut buf = crate::make!([]byte, 32 * 1024);
            let (n, rerr) = crate::io::Reader::Read(&mut user_r, &mut buf);
            if n > 0 {
                let (_, werr) = crate::io::Writer::Write(&mut backend_w, buf.slice(0, n));
                if !werr.IsNil() {
                    errc.Send(werr);
                    return;
                }
            }
            if !rerr.IsNil() {
                if !crate::errors::Is(rerr.clone(), crate::io::EOF) {
                    errc.Send(rerr);
                    return;
                }
                errc.Send(backend_w.CloseWrite());
                return;
            }
            if n == 0 {
                errc.Send(backend_w.CloseWrite());
                return;
            }
        }
    }
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
        return super::super::url::ValuesEncode(&v);
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
pub fn joinURLPath(a: &super::super::url::URL, b: &super::super::url::URL) -> (string, string) {
    if a.RawPath.Len() == 0 && b.RawPath.Len() == 0 {
        return (
            singleJoiningSlash(a.Path.clone(), b.Path.clone()),
            string::new(),
        );
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

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:215-219 BufferPool
/// Go: "A BufferPool is an interface for getting and returning
/// temporary byte slices for use by [io.CopyBuffer]."
///
/// The pool is the caller's to implement; goish does not ship one,
/// because `sync::Pool` still faults under many-goroutine teardown.
/// A plain per-proxy `Mutex<Vec<slice<byte>>>` is a fine stand-in.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait BufferPool {
    fn Get(&self) -> crate::goslice::slice<byte>;
    fn Put(&self, b: crate::goslice::slice<byte>);
}

// goishlint:ignore GOISH019 maxLatencyWriter — Go's six fields
// (dst, flush, latency, mu, t, flushPending) live behind one Arc here,
// because `time::AfterFunc` needs a `Send + 'static` callback and the
// callback is this same writer. The field set is preserved on
// `mlwInner` / `mlwState`, one level down.
// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:694-702 maxLatencyWriter
/// The writer `copyResponse` interposes when a flush interval is set:
/// every Write goes straight through, but a flush is scheduled rather
/// than performed, and at most one is ever pending.
///
/// Go keeps `dst`, `flush` and the mutex in one struct with a pointer
/// receiver. goish shares it through an `Arc` instead, because
/// `time::AfterFunc` needs a `Send + 'static` closure and the timer
/// callback and the writer are the same object.
#[derive(Clone)]
pub struct maxLatencyWriter {
    inner: alloc::sync::Arc<mlwInner>,
}

// go: none — goish-only: the fields behind maxLatencyWriter's Arc.
// `latency` and `dst` are immutable after construction, so only the
// timer and the pending flag sit under the mutex — same partition as
// Go's comment "protects t, flushPending, and dst.Flush".
struct mlwInner {
    dst: alloc::sync::Arc<dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static>,
    /// Go: "non-zero; negative means to flush immediately".
    latency: crate::time::Duration,
    mu: crate::sync::Mutex<mlwState>,
}

// go: none — goish-only: the mutex-guarded half of mlwInner.
struct mlwState {
    t: Option<crate::time::Timer>,
    flushPending: bool,
}

// go: none — goish-only: Go builds the struct literal inline in
// copyResponse, including `flush: http.NewResponseController(dst).Flush`
// — a bound method value, which Rust has no spelling for. The
// controller is rebuilt per flush instead; it holds nothing but the
// writer, so this is the same work.
pub fn __newMaxLatencyWriter(
    dst: alloc::sync::Arc<dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static>,
    latency: crate::time::Duration,
) -> maxLatencyWriter {
    return maxLatencyWriter {
        inner: alloc::sync::Arc::new(mlwInner {
            dst,
            latency,
            mu: crate::sync::Mutex::new(mlwState {
                t: None,
                flushPending: false,
            }),
        }),
    };
}

impl maxLatencyWriter {
    // go: none — goish-only: Go's `flush` field, resolved per call.
    fn flush(&self) -> crate::errors::error {
        return super::super::responsecontroller::NewResponseController(self.inner.dst.clone())
            .Flush();
    }

    // go: none — goish-only: copyResponse's "set up initial timer so
    // headers get flushed even if body writes are delayed" pair, which
    // reaches into the struct's unexported fields from outside any
    // method. goish keeps the fields private, so the pair is named.
    fn __arm_initial(&self) {
        let me = self.clone();
        let mut st = self.inner.mu.Lock();
        st.flushPending = true;
        st.t = Some(crate::time::AfterFunc(self.inner.latency, move || {
            me.delayedFlush();
        }));
        return;
    }

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:704-722 maxLatencyWriter.Write
    /// The write itself is never delayed — only the flush is. A
    /// NEGATIVE latency flushes inline, which is how `flushInterval`
    /// spells "this is a stream, never buffer it".
    pub fn Write(
        &self,
        p: crate::goslice::slice<byte>,
    ) -> (crate::types::int, crate::errors::error) {
        let mut st = self.inner.mu.Lock();
        let (n, err) = self.inner.dst.Write(p);
        if self.inner.latency.0 < 0 {
            let _ = self.flush();
            return (n, err);
        }
        if st.flushPending {
            return (n, err);
        }
        // Go: `m.t.Reset(m.latency)` when a timer already exists.
        // goish's Timer has no Reset, so the spent timer is stopped
        // and a fresh one armed — single-shot either way, and nothing
        // observes the timer but this struct.
        if let Some(t) = st.t.take() {
            t.Stop();
        }
        let me = self.clone();
        st.t = Some(crate::time::AfterFunc(self.inner.latency, move || {
            me.delayedFlush();
        }));
        st.flushPending = true;
        return (n, err);
    }

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:724-732 maxLatencyWriter.delayedFlush
    /// The `flushPending` re-check is not redundant: `stop` may have
    /// run after `AfterFunc` already released this callback, and
    /// flushing then would touch a response the handler is done with.
    pub fn delayedFlush(&self) {
        let mut st = self.inner.mu.Lock();
        if !st.flushPending {
            return;
        }
        let _ = self.flush();
        st.flushPending = false;
        return;
    }

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:734-741 maxLatencyWriter.stop
    pub fn stop(&self) {
        let mut st = self.inner.mu.Lock();
        st.flushPending = false;
        if let Some(t) = st.t.take() {
            t.Stop();
        }
        return;
    }
}

impl crate::io::Writer for maxLatencyWriter {
    // go: none — goish-only: Go's maxLatencyWriter IS an io.Writer
    // because its Write has the io.Writer signature. goish's method
    // takes `&self` (the value is shared with the timer callback), so
    // the `&mut self` trait method forwards to it.
    fn Write(
        &mut self,
        p: crate::goslice::slice<byte>,
    ) -> (crate::types::int, crate::errors::error) {
        return maxLatencyWriter::Write(self, p);
    }
}

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:567-567 inOurTests
/// Go: "whether we're in our own tests". Only the package's own tests
/// set it; it exists so `shouldPanicOnCopyError` can panic there
/// without breaking third-party tests written before Go 1.11.
pub static inOurTests: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:574-587 shouldPanicOnCopyError
/// Go: "reports whether the reverse proxy should panic with
/// http.ErrAbortHandler. This is the right thing to do by default, but
/// Go 1.10 and earlier did not, so existing unit tests weren't
/// expecting panics. Only panic in our own tests, or when running
/// under the HTTP server."
///
/// The server branch is the one that matters: under a Server the
/// panic is recovered and the connection is torn down, which is how a
/// half-copied body stops looking like a complete one. Outside a
/// Server there is nobody to recover it, so the copy error is
/// returned instead.
pub fn shouldPanicOnCopyError(req: &super::super::request::Request) -> bool {
    if inOurTests.load(core::sync::atomic::Ordering::Relaxed) {
        // Go: "Our tests know to handle this panic."
        return true;
    }
    if req
        .Context()
        .Value(super::super::server::ServerContextKey)
        .is_some()
    {
        // Go: "We seem to be running under an HTTP server, so it'll
        // recover the panic."
        return true;
    }
    // Go: "Otherwise act like Go 1.10 and earlier to not break
    // existing tests."
    return false;
}

// go: sdk 1.25.5 net/http/httputil/reverseproxy.go:818-818 errCopyDone
crate::var! {
    /// Go: "hijacked connection copy complete" — the sentinel the two
    /// switchProtocolCopier goroutines send when their direction of an
    /// upgraded connection finishes.
    pub errCopyDone: error = "hijacked connection copy complete";
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
/// `ServeHTTP` is ported below, and this type is a Handler. It used to
/// carry a note saying ServeHTTP was staged because it "needs the
/// streaming response copy, which needs Body as io.ReadCloser" — that
/// reason had gone stale: `Response.Body` is an `io::Reader` and the
/// slim `reverseProxyHandler` had been streaming through it for some
/// time. Until this landed, every hook on this struct was unreachable,
/// because nothing could invoke the type at all.
///
/// One deviation remains, stated rather than silent: `FlushInterval`
/// is NOT honoured. Go applies it through `copyResponse`, which takes
/// an `Arc<dyn ResponseWriter>` while `Handler::ServeHTTP` is handed a
/// `&dyn` — see ROADMAP 2m. The body is instead flushed after every
/// write, which is what `reverseProxyHandler` does and the only thing
/// a borrowed writer can do.
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
        alloc::sync::Arc<
            dyn Fn(&mut super::super::response::Response) -> crate::errors::error + Send + Sync,
        >,
    >,
    /// Go: "optionally specifies a buffer pool to get byte slices for
    /// use by [io.CopyBuffer] when copying HTTP response bodies."
    pub BufferPool: Option<alloc::sync::Arc<dyn BufferPool + Send + Sync + 'static>>,
    /// Go: "The transport used to perform proxy requests. If nil,
    /// http.DefaultTransport is used."
    ///
    /// Go calls `Transport.RoundTrip` directly rather than going
    /// through a Client, which is what makes a proxy perform exactly
    /// ONE exchange: a 3xx from the backend is relayed to the client
    /// instead of being followed by the proxy.
    pub Transport: Option<alloc::sync::Arc<dyn super::super::client::RoundTripper>>,
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

// go: none — goish-only: the shared body of
// ReverseProxy.handleUpgradeResponse, split out so the slim
// `reverseProxyHandler` (the wired serve path) speaks the same
// upgrade protocol with its own error reporting.
fn upgrade_response_impl(
    rw: &(dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static),
    req: &super::super::request::Request,
    res: &mut super::super::response::Response,
    report: &dyn Fn(crate::errors::error),
) {
    let reqUpType = upgradeType(&req.Header);
    let resUpType = upgradeType(&res.Header);
    // Go: !ascii.IsPrint(resUpType) → invalid protocol error.
    if !super::super::internal::ascii::IsPrint(resUpType.clone()) {
        report(crate::errors::New(crate::fmt::Sprintf!(
            "backend tried to switch to invalid protocol %q",
            resUpType
        )));
        return;
    }
    // Go: !ascii.EqualFold(reqUpType, resUpType) → mismatch error.
    if !super::super::internal::ascii::EqualFold(reqUpType.clone(), resUpType.clone()) {
        report(crate::errors::New(crate::fmt::Sprintf!(
            "backend tried to switch protocol %q when %q was requested",
            resUpType,
            reqUpType
        )));
        return;
    }

    // Go: backConn, ok := res.Body.(io.ReadWriteCloser)
    let back = match res.Body.__take_upgraded() {
        Some(b) => b,
        None => {
            report(crate::errors::New(string(
                "internal error: 101 switching protocols response with non-writable body",
            )));
            return;
        }
    };
    let (split, splerr) = back.split_for_upgrade();
    if !splerr.IsNil() {
        report(splerr);
        return;
    }
    let (backend_r, backend_w) = split.unwrap();

    // Go: rc := http.NewResponseController(rw); conn, brw, err := rc.Hijack()
    // goish: the controller is Arc-shaped and a borrowed handler
    // writer cannot become one; the cast IS what rc.Hijack does.
    let (hj, can_hijack) = crate::cast!(rw, super::super::responsewriter::Hijacker);
    if !can_hijack {
        report(crate::errors::New(string(
            "can't switch protocols using non-Hijacker ResponseWriter",
        )));
        return;
    }
    let (conn, hijackErr) = hj.Hijack();
    if !hijackErr.IsNil() {
        report(crate::errors::New(crate::fmt::Sprintf!(
            "Hijack failed on protocol switch: %v",
            hijackErr
        )));
        return;
    }
    let (user_w, duperr) = conn.__dup_handle();
    if !duperr.IsNil() {
        report(duperr);
        return;
    }
    let user_r = conn;

    // Go: res.Body = nil; res.Write(brw) — replay the 101 head to
    // the user verbatim (status line + the backend's headers).
    {
        let mut head: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        head.extend_from_slice(b"HTTP/1.1 101 ");
        let text = super::super::status::StatusText(res.StatusCode);
        if text.Len() != 0 {
            head.extend_from_slice(text.as_bytes());
        } else {
            head.extend_from_slice(b"Switching Protocols");
        }
        head.extend_from_slice(b"\r\n");
        let mut hb = crate::bytes::Buffer::new();
        let _ = res
            .Header
            .WriteSubset(&mut hb, &crate::gomap::map::<string, bool>::new());
        head.extend_from_slice(&hb.Bytes());
        head.extend_from_slice(b"\r\n");
        let mut uw = user_w;
        let (_, werr) =
            crate::io::Writer::Write(&mut uw, crate::goslice::slice::<byte>::__from_vec(head));
        if !werr.IsNil() {
            report(crate::errors::New(crate::fmt::Sprintf!(
                "response write: %v",
                werr
            )));
            return;
        }
        // Go: errc := make(chan error, 1)
        //     spc := switchProtocolCopier{user: conn, backend: backConn}
        //     go spc.copyToBackend(errc); go spc.copyFromBackend(errc)
        // Go copies the interface-holding struct into both
        // goroutines; goish destructures it and sends each copier
        // the halves it owns.
        let spc = switchProtocolCopier {
            user: user_r,
            backend: backend_r,
        };
        let switchProtocolCopier { user, backend } = spc;
        let errc: crate::gochan::chan<crate::errors::error> =
            crate::make!(chan crate::errors::error, 1);
        let e1 = errc.clone();
        let e2 = errc.clone();
        crate::go!(stack(256 * crate::KB), move || {
            switchProtocolCopier::copyToBackend(user, backend_w, e1);
        });
        crate::go!(stack(256 * crate::KB), move || {
            switchProtocolCopier::copyFromBackend(backend, uw, e2);
        });
        // Go: <-errc — first finisher decides; both conns drop
        // (and close) when this frame and the copiers unwind.
        let _ = errc.Recv();
    }
    return;
}

impl ReverseProxy {
    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:684-692 ReverseProxy.logf
    /// Go's signature is `logf(format string, args ...any)`; goish has
    /// no variadic `any`, so callers format with `fmt::Sprintf!` and
    /// pass the finished string. `args` is kept as an empty slice so
    /// the arity matches and a future variadic form has somewhere to
    /// land — the same shape `Server.logf` uses.
    pub fn logf(&self, format: crate::string, args: crate::goslice::slice<crate::string>) {
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

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:750-816 ReverseProxy.handleUpgradeResponse
    //
    /// The 101 Switching Protocols path: verify the backend switched
    /// to the protocol the client asked for, hijack the user side,
    /// replay the 101 head, then pump bytes both ways until either
    /// side finishes. Adaptations, stated:
    ///  * Go type-asserts `res.Body.(io.ReadWriteCloser)`; goish's
    ///    comma-ok is `Body::__take_upgraded` (the client attaches the
    ///    conn on 101 via newReadWriteCloserBody).
    ///  * Go's req.Context-cancel watcher goroutine closes the backend
    ///    (issue 35559); goish's request context carries no Done chan
    ///    on this path — teardown rides the copier errc instead, and
    ///    both conns close when this function returns.
    ///  * A TLS backend refuses the split (see split_for_upgrade).
    pub fn handleUpgradeResponse(
        &self,
        rw: &(dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static),
        req: &super::super::request::Request,
        res: &mut super::super::response::Response,
    ) {
        upgrade_response_impl(rw, req, res, &|e| self.handleError(rw, req, e));
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
    pub fn flushInterval(&self, res: &super::super::response::Response) -> crate::time::Duration {
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

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:626-651 ReverseProxy.copyResponse
    /// Stream the backend body to the client, flushing at most every
    /// `flushInterval`.
    ///
    /// The initial timer is armed BEFORE the first body byte is read,
    /// which is what makes an SSE response usable: the head reaches
    /// the client even when the backend then goes quiet for minutes.
    /// A zero interval opts out entirely and writes straight through.
    pub fn copyResponse(
        &self,
        dst: alloc::sync::Arc<
            dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static,
        >,
        src: &mut dyn crate::io::Reader,
        flushInterval: crate::time::Duration,
    ) -> crate::errors::error {
        // Go: `var w io.Writer = dst`, then replaces it with the
        // latency writer. goish keeps the two apart because the
        // ResponseWriter is not itself an io::Writer.
        if flushInterval.0 != 0 {
            let mlw = __newMaxLatencyWriter(dst, flushInterval);
            let stopper = mlw.clone();
            crate::defer! { stopper.stop(); }
            // Go: "set up initial timer so headers get flushed even if
            // body writes are delayed".
            mlw.__arm_initial();
            let mut w = mlw.clone();
            let buf = self.__poolGet();
            let (_, err) = self.copyBuffer(&mut w, src, buf.clone());
            self.__poolPut(buf);
            return err;
        }
        let mut w = responseWriterWriter { rw: dst };
        let buf = self.__poolGet();
        let (_, err) = self.copyBuffer(&mut w, src, buf.clone());
        self.__poolPut(buf);
        return err;
    }

    // go: none — goish-only: Go writes the pool pair as
    // `buf = p.BufferPool.Get(); defer p.BufferPool.Put(buf)` inside
    // copyResponse, and the deferred Put must run on every exit path.
    // goish's `defer!` moves what it captures, so the pair is two
    // named halves around the copy instead.
    fn __poolGet(&self) -> crate::goslice::slice<byte> {
        if let Some(p) = self.BufferPool.as_ref() {
            return p.Get();
        }
        return crate::goslice::slice::<byte>::new();
    }

    // go: none — goish-only: the Put half of __poolGet. A nil pool
    // never had a buffer to return, so this is a no-op there — Go's
    // `defer` is registered only inside the same `!= nil` branch.
    fn __poolPut(&self, buf: crate::goslice::slice<byte>) {
        if let Some(p) = self.BufferPool.as_ref() {
            p.Put(buf);
        }
        return;
    }

    // go: sdk 1.25.5 net/http/httputil/reverseproxy.go:653-684 ReverseProxy.copyBuffer
    /// Go: "copyBuffer returns any write errors or non-EOF read
    /// errors, and the amount of bytes written."
    ///
    /// Three details carry weight. A read error that is neither EOF
    /// nor `context.Canceled` is LOGGED but does not stop the loop
    /// early — the bytes already read still get written. A short write
    /// is `io.ErrShortWrite`, not silence. And EOF is normalised to
    /// nil, so a clean end of body is not an error.
    pub fn copyBuffer(
        &self,
        dst: &mut dyn crate::io::Writer,
        src: &mut dyn crate::io::Reader,
        buf: crate::goslice::slice<byte>,
    ) -> (crate::types::int64, crate::errors::error) {
        let mut buf = buf;
        if crate::len(&buf) == 0 {
            buf = crate::make!([]byte, 32 * 1024);
        }
        let mut written: crate::types::int64 = 0;
        // Go's `for { … }` only leaves through a return; Rust needs
        // the value to come out of the loop, so each exit breaks with
        // the pair Go would have returned.
        let out = loop {
            let (nr, rerr) = src.Read(&mut buf);
            if !rerr.IsNil()
                && !crate::errors::Is(rerr.clone(), crate::io::EOF)
                && !crate::errors::Is(rerr.clone(), crate::context::Canceled)
            {
                self.logf(
                    crate::fmt::Sprintf!(
                        "httputil: ReverseProxy read error during body copy: %v",
                        rerr
                    ),
                    crate::goslice::slice::<crate::string>::new(),
                );
            }
            if nr > 0 {
                let (nw, werr) = dst.Write(buf.slice(0, nr));
                if nw > 0 {
                    written += crate::types::int64::from(nw);
                }
                if !werr.IsNil() {
                    break (written, werr);
                }
                if nr != nw {
                    break (written, crate::io::ErrShortWrite.into());
                }
            }
            if !rerr.IsNil() {
                if crate::errors::Is(rerr.clone(), crate::io::EOF) {
                    break (written, crate::errors::nil);
                }
                break (written, rerr);
            }
        };
        return out;
    }
}

// go: none — goish-only: Go writes `var w io.Writer = dst` because its
// ResponseWriter embeds io.Writer. goish's ResponseWriter has
// `Write(&self, …)` and is not an io::Writer, so the adapter is
// explicit.
struct responseWriterWriter {
    rw: alloc::sync::Arc<dyn super::super::responsewriter::ResponseWriter + Send + Sync + 'static>,
}

impl crate::io::Writer for responseWriterWriter {
    // go: none — goish-only: see responseWriterWriter above.
    fn Write(
        &mut self,
        p: crate::goslice::slice<byte>,
    ) -> (crate::types::int, crate::errors::error) {
        return self.rw.Write(p);
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
