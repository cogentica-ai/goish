// net/http/request — Request type + ReadRequest parser.
//
// Slim port of Go's net/http.Request and ReadRequest
// (Go 1.25 src/net/http/request.go:1058).
//
// Subset implemented:
//   - HTTP/1.0 and HTTP/1.1 origin-form / absolute-form request-target.
//   - Header parsing per RFC 7230, with continuation-line folding NOT
//     supported (deprecated in HTTP/1.1).
//   - Body: read fully into a slice<byte> before the handler runs.
//     Bounded by Content-Length; zero bytes if absent.
//
// Out of scope (v1):
//   - Chunked transfer-encoding on incoming bodies.
//   - Trailers.
//   - Multipart parsing (handled at higher layers in user code).

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::bufio;
use crate::bytes;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::{self, Reader};
use crate::string;
use crate::types::{byte, int};

use super::header::{hasToken, Header};
use super::url::{parse_request_uri, URL};

/// `net/http.Request`. Slim — only fields a handler typically reads.
#[derive(Clone)]
pub struct Request {
    pub Method: string,
    pub URL: URL,
    pub Proto: string,    // "HTTP/1.1"
    pub ProtoMajor: int,
    pub ProtoMinor: int,
    pub Header: Header,
    pub Host: string,
    pub ContentLength: int, // -1 if unknown
    /// Fully-buffered request body. Bounded by `Content-Length`.
    /// Empty for GET/HEAD/no-body methods.
    ///
    /// **Deviation from Go**: Go exposes `Body io.ReadCloser` for
    /// streaming. Goish v1 reads the body upfront — callers wrap it
    /// in `bytes::NewReader` if they want a `Reader`. For the
    /// sub-MB requests typical of REST APIs this is the same
    /// observable behavior with simpler lifetimes.
    pub Body: slice<byte>,
    pub RemoteAddr: string,
    /// Wildcard pattern bindings (Go 1.22). Populated by `ServeMux`
    /// when a `/users/{id}`-style pattern matches; queried via
    /// `r.PathValue(name)`. Empty otherwise.
    pub(crate) path_values: crate::gomap::map<string, string>,
    /// Lazy form-parse state. Wrapped in `Arc<Mutex<…>>` so
    /// `ParseForm`/`FormValue`/`PostFormValue` can be called from
    /// `&Request` (handlers receive `&Request`, not `&mut Request`,
    /// because `Handler::ServeHTTP` takes `&self`). Mirrors Go's
    /// `(r *Request).ParseForm()` mutation through a shared pointer.
    ///
    /// Cloning a Request shares this state via `Arc::clone` — slight
    /// divergence from Go where `r.Clone(ctx)` deep-copies Form. In
    /// practice handlers don't clone-then-parse; the shared-state
    /// model matches "all `&Request` views see the same parsed
    /// values" which is what Go's pointer-aliasing already provides.
    pub(crate) form_state: alloc::sync::Arc<crate::sync::Mutex<FormCell>>,
    /// Request-scoped context (Go's unexported `ctx` field,
    /// request.go:319). `None` means "no context attached" —
    /// `Context()` then reports `context.Background()`. Set via
    /// `WithContext` / `Clone`; middleware uses this to hand values
    /// (request IDs, auth principals) down the handler chain.
    pub(crate) ctx: Option<alloc::sync::Arc<dyn crate::context::Context>>,

    /// `Request.Close` (request.go:224) — whether to close the
    /// connection after replying to this request (servers) or after
    /// sending it and reading its response (clients).
    ///
    /// Go: "For server requests, the HTTP server handles this
    /// automatically and this field is not needed by Handlers. For
    /// client requests, setting this field prevents re-use of TCP
    /// connections between requests to the same hosts, as if
    /// Transport.DisableKeepAlives were set."
    pub Close: bool,

    /// `Request.Trailer` (request.go:283) — trailer keys and values.
    ///
    /// Go: "For client requests, Trailer must be initialized to a map
    /// containing the trailer keys to later send. The values may be
    /// nil or their final values. The ContentLength must be 0 or -1,
    /// to send a chunked request."
    pub Trailer: Header,

    /// `Request.RequestURI` (request.go:294) — Go: "the unmodified
    /// request-target of the Request-Line (RFC 7230, Section 3.1.1) as
    /// sent by the client to a server. Usually the URL field should be
    /// used instead. It is an error to set this field in an HTTP
    /// client request."
    ///
    /// Kept alongside URL because the two differ: `OPTIONS *` has a
    /// request-target of "*", which is not a path and does not survive
    /// URL parsing — serverHandler tests RequestURI, not URL.Path.
    pub RequestURI: string,

    /// `Request.TLS` (request.go:307) — the TLS connection state for a
    /// request received over TLS, or `None` for plaintext.
    ///
    /// Go's field is a `*tls.ConnectionState` where nil means "not
    /// TLS"; `Option` is that pointer's nil-ness spelled out.
    pub TLS: Option<alloc::sync::Arc<crate::crypto::tls::ConnectionState>>,
}

/// Internal form-parse cell — the four fields that ParseForm
/// populates, bundled under one Mutex. Mirrors the four Go
/// `Request.Form` / `Request.PostForm` fields plus their nil-test
/// booleans.
#[derive(Default, Clone)]
pub(crate) struct FormCell {
    pub parsed: bool,
    pub post_parsed: bool,
    pub form: crate::gomap::map<string, slice<string>>,
    pub post_form: crate::gomap::map<string, slice<string>>,
}

impl Request {
    /// Convenience: `bytes::Reader` over `Body` so handler code that
    /// expects an `io::Reader` (`json::NewDecoder(req.body_reader())`)
    /// keeps working. Mirrors what `Request.Body io.Reader` would
    /// return in Go.
    pub fn body_reader(&self) -> bytes::Reader {
        bytes::NewReader(self.Body.clone())
    }

    // go: sdk 1.25.5 net/http/request.go:352-357 Request.Context
    /// `r.Context()` (request.go:352). Returns the request's context,
    /// or `context.Background()` if none was attached — exactly Go's
    /// `if r.ctx != nil { return r.ctx }; return context.Background()`.
    pub fn Context(&self) -> alloc::sync::Arc<dyn crate::context::Context> {
        match &self.ctx {
            Some(c) => c.clone(),
            None => crate::context::Background(),
        }
    }

    // go: sdk 1.25.5 net/http/request.go:368-376 Request.WithContext
    /// `r.WithContext(ctx)` (request.go:368) — shallow copy of the
    /// request with its context replaced.
    pub fn WithContext(
        &self,
        ctx: alloc::sync::Arc<dyn crate::context::Context>,
    ) -> Request {
        // Go: r2 := new(Request); *r2 = *r; r2.ctx = ctx
        let mut r2 = self.clone();
        r2.ctx = Some(ctx);
        r2
    }

    // go: sdk 1.25.5 net/http/request.go:386-413 Request.Clone
    /// `r.Clone(ctx)` (request.go:386) — deep copy with its context
    /// replaced. Goish container types (string / slice / gomap) all
    /// deep-clone via #[derive(Clone)], so the explicit per-field
    /// clones in Go's source are unnecessary here.
    pub fn Clone(
        &self,
        ctx: alloc::sync::Arc<dyn crate::context::Context>,
    ) -> Request {
        // Go: cloneURL(r.URL); r.Header.Clone(); r.Trailer.Clone(); etc.
        let mut r2 = self.clone();
        r2.ctx = Some(ctx);
        r2
    }

    // go: sdk 1.25.5 net/http/request.go:428-430 Request.Cookies
    /// `r.Cookies()` — parse all `Cookie:` request headers. Mirrors
    /// `(*Request).Cookies()` (request.go:404).
    pub fn Cookies(&self) -> slice<super::cookie::Cookie> {
        super::cookie::readCookies(&self.Header, &string::new())
    }

    // go: sdk 1.25.5 net/http/request.go:434-439 Request.CookiesNamed
    /// `r.CookiesNamed(name)` (request.go:434) — return all request
    /// cookies with the given name. Empty `name` yields an empty slice.
    pub fn CookiesNamed<S: Into<string>>(&self, name: S) -> slice<super::cookie::Cookie> {
        let name = name.into();
        // Go: if name == "" { return []*Cookie{} }
        if name.Len() == 0 {
            return slice::<super::cookie::Cookie>::__from_vec(Vec::new());
        }
        // Go: return readCookies(r.Header, name)
        super::cookie::readCookies(&self.Header, &name)
    }

    // go: sdk 1.25.5 net/http/request.go:448-456 Request.Cookie
    /// `r.Cookie(name)` — return the named cookie, or
    /// `(Cookie::default(), ErrNoCookie)` if absent. Mirrors
    /// `(*Request).Cookie(name)` (request.go:418).
    pub fn Cookie<S: Into<string>>(&self, name: S) -> (super::cookie::Cookie, error) {
        let matches = super::cookie::readCookies(&self.Header, &name.into());
        if matches.Len() > 0 {
            return (matches[0].clone(), errors::nil);
        }
        (super::cookie::Cookie::default(), ErrNoCookie.into())
    }

    // go: sdk 1.25.5 net/http/request.go:1469-1474 Request.PathValue
    /// `r.PathValue(name)` — look up a wildcard binding from a Go 1.22
    /// pattern match (e.g. `/users/{id}` → `r.PathValue("id")`).
    /// Returns the empty string if no such binding exists. Mirrors
    /// `(*Request).PathValue(name)` (request.go:472 in Go's source).
    // NOTE — `patIndex` has no counterpart HERE by design, not by
    // omission. Deliberately NOT suppressed with a
    // `goishlint:ignore GOISH018`: that directive is FILE-scoped for
    // this rule, so adding one here silently masked all 22 of
    // request.rs's GOISH018 findings, not just this one. The other 21
    // are real gaps and must stay visible; patIndex being listed is
    // the acceptable cost. Go resolves a wildcard name by keeping
    // the matched `pat *pattern` plus a positional `matches []string`
    // and linear-scanning the pattern's segments (request.go:1491);
    // goish stores the bindings directly in a `map<string,string>`, so
    // the lookup below IS patIndex's job. Porting it would produce a
    // function nothing can call — the same trap that made `exactMatch`
    // an orphan earlier in this port.
    //
    // The divergence is data-structure-only: verified against goref
    // via a real ServeMux that the observable behaviour is identical,
    // including the cases where the two designs could plausibly differ
    // — an unknown name and the empty name both give "", `{rest...}`
    // yields the whole remaining path with slashes intact, and `{$}`
    // is NOT addressable (PathValue("$") is ""). See
    // examples/http_pathvalue_smoke.rs.
    pub fn PathValue<S: Into<string>>(&self, name: S) -> string {
        let (v, ok) = self.path_values.Get(name.into());
        if ok {
            v
        } else {
            string::new()
        }
    }

    // go: sdk 1.25.5 net/http/request.go:1478-1487 Request.SetPathValue
    /// `r.SetPathValue(name, value)` — set a wildcard binding for
    /// testing or middleware use. Mirrors `(*Request).SetPathValue`.
    pub fn SetPathValue<K: Into<string>, V: Into<string>>(&mut self, name: K, value: V) {
        self.path_values.Set(name.into(), value.into());
    }

    /// Internal: bulk-install path bindings from a successful pattern
    /// match. Used by `ServeMux::ServeHTTP`; not part of the public
    /// API since users would set bindings via `SetPathValue` instead.
    #[doc(hidden)]
    pub fn __set_path_values(&mut self, m: crate::gomap::map<string, string>) {
        self.path_values = m;
    }

    // go: sdk 1.25.5 net/http/request.go:1327-1360 Request.ParseForm
    //
    /// `r.ParseForm()` — populate `r.Form` and `r.PostForm`.
    ///
    /// Line-by-line port of `(*Request).ParseForm()` (request.go:1327).
    /// For all requests, parses the URL's RawQuery into `r.Form`. For
    /// POST/PUT/PATCH with `Content-Type: application/x-www-form-urlencoded`,
    /// also parses the body and merges into both `r.PostForm` and
    /// `r.Form`. Idempotent.
    ///
    /// Takes `&self` (not `&mut self`) so handlers — which receive
    /// `&Request` from the `Handler` trait — can call it directly,
    /// matching Go's `func (r *Request) ParseForm()` ergonomics.
    /// State lives behind an internal `Mutex<FormCell>`.
    pub fn ParseForm(&self) -> error {
        let mut s = self.form_state.Lock();
        // Go: var err error
        let mut err: error = errors::nil;
        // Go: if r.PostForm == nil { … }
        if !s.post_parsed {
            s.post_parsed = true;
            // Go: if r.Method == "POST" || "PUT" || "PATCH" { r.PostForm, err = parsePostForm(r) }
            if self.Method == "POST" || self.Method == "PUT" || self.Method == "PATCH" {
                let (pf, e) = parsePostForm(self);
                s.post_form = pf;
                err = e;
            }
            // Go: if r.PostForm == nil { r.PostForm = make(url.Values) }
            // (already initialized to empty map by default; nothing to do)
        }
        // Go: if r.Form == nil { … }
        if !s.parsed {
            s.parsed = true;
            // Go: if len(r.PostForm) > 0 { copyValues(r.Form, r.PostForm) }
            if s.post_form.Len() > 0 {
                let post_form = s.post_form.clone();
                copyValues(&mut s.form, &post_form);
            }
            // Go: newValues, e := url.ParseQuery(r.URL.RawQuery)
            let (new_values, e) = super::url::ParseQuery(self.URL.RawQuery.clone());
            if err.IsNil() {
                err = e;
            }
            // Go: copyValues(r.Form, newValues)
            copyValues(&mut s.form, &new_values);
        }
        err
    }

    /// `r.FormValue(key)` — first form value for `key`, or empty.
    /// Mirrors `(*Request).FormValue(key)` (request.go:1419).
    // go: none — goish-only accessor for Go's `Request.Form` FIELD
    // (request.go:80). goish keeps the parsed values in a
    // mutex-guarded cell so ParseForm can populate them through a
    // `&self` receiver, and a Rust field cannot be handed out from
    // behind a lock — so the field becomes a method returning a
    // snapshot, exactly as `httptest::Server::URL` does.
    //
    // Without this, only the SCALAR `FormValue` was reachable and
    // Go's multi-value semantics — `Form["a"] == ["9","1"]` when a
    // query and a POST body both set `a` — could not be observed at
    // all, let alone tested.
    pub fn Form(&self) -> crate::gomap::map<string, slice<string>> {
        return self.form_state.Lock().form.clone();
    }

    // go: none — goish-only accessor for Go's `Request.PostForm`
    // FIELD (request.go:88); see `Form` above.
    pub fn PostForm(&self) -> crate::gomap::map<string, slice<string>> {
        return self.form_state.Lock().post_form.clone();
    }

    // go: sdk 1.25.5 net/http/request.go:1419-1427 Request.FormValue
    //
    /// First value for `key` across query and POST body, or empty.
    ///
    /// Verified against goref: with `?a=1` and a POST body `a=9`, Go
    /// merges POST FIRST, so this returns "9", not "1".
    pub fn FormValue<S: Into<string>>(&self, key: S) -> string {
        // Go: if r.Form == nil { r.ParseMultipartForm(defaultMaxMemory) }
        if !self.form_state.Lock().parsed {
            let _ = self.ParseForm();
        }
        // Go: if vs := r.Form[key]; len(vs) > 0 { return vs[0] }
        let s = self.form_state.Lock();
        let (vs, ok) = s.form.Get(key.into());
        if ok && vs.Len() > 0 {
            return vs[0].clone();
        }
        string::new()
    }

    // go: sdk 1.25.5 net/http/request.go:1434-1442 Request.PostFormValue
    //
    /// `r.PostFormValue(key)` — first POST form value for `key`, or
    /// empty.
    pub fn PostFormValue<S: Into<string>>(&self, key: S) -> string {
        if !self.form_state.Lock().post_parsed {
            let _ = self.ParseForm();
        }
        let s = self.form_state.Lock();
        let (vs, ok) = s.post_form.Get(key.into());
        if ok && vs.Len() > 0 {
            return vs[0].clone();
        }
        string::new()
    }

    /// `r.MultipartReader()` (request.go:497) — return a
    /// `mime/multipart::Reader` over the request body, if this is a
    /// multipart/form-data POST. Slim port: drops the
    /// "MultipartReader called twice" guard (we don't track
    /// MultipartForm state) and the multipart/mixed support.
    pub fn MultipartReader(&self) -> (super::super::super::mime::multipart::Reader, error) {
        let v = self.Header.Get(string("Content-Type"));
        if v.Len() == 0 {
            return (
                empty_multipart_reader(),
                ErrNotMultipart.into(),
            );
        }
        if self.Body.Len() == 0 {
            return (
                empty_multipart_reader(),
                errors::New(string("missing form body")),
            );
        }
        let (d, params, perr) = crate::mime::ParseMediaType(v);
        if !perr.IsNil() || d != "multipart/form-data" {
            return (empty_multipart_reader(), ErrNotMultipart.into());
        }
        let (boundary, ok) = params.Get(string("boundary"));
        if !ok {
            return (empty_multipart_reader(), ErrMissingBoundary.into());
        }
        (
            crate::mime::multipart::NewReader(self.Body.clone(), boundary),
            errors::nil,
        )
    }

    /// `r.Write(w)` (request.go:561) — serialize the request onto `w`
    /// in HTTP/1.1 wire format. Slim port: delegates to the same
    /// `serialize_request` helper used by Client::Do, which already
    /// implements (*Request).write internally.
    pub fn Write<W: io::Writer>(&self, w: &mut W) -> error {
        // Go: return r.write(w, false, nil, nil)
        self.write_to(w, false)
    }

    /// `r.WriteProxy(w)` (request.go:571) — like Write but emits an
    /// absolute Request-URI line (scheme://host/path?query) per RFC
    /// 7230 §5.3. Used when the request is being sent through an HTTP
    /// proxy.
    pub fn WriteProxy<W: io::Writer>(&self, w: &mut W) -> error {
        // Go: return r.write(w, true, nil, nil)
        self.write_to(w, true)
    }

    fn write_to<W: io::Writer>(&self, w: &mut W, using_proxy: bool) -> error {
        let host = if self.Host.Len() != 0 {
            self.Host.clone()
        } else {
            self.URL.Host.clone()
        };
        // `serialize_request_proxy` already appends the body. This
        // used to append it a SECOND time, so every request with a
        // body put it on the wire twice while Content-Length still
        // announced one copy. On a keep-alive connection the surplus
        // bytes are read as the start of the next request — a
        // request-smuggling desync, self-inflicted on every POST.
        let out = super::client::serialize_request_proxy(self, &host, using_proxy);
        let (_, e) = w.Write(out);
        return e;
    }

    // go: sdk 1.25.5 net/http/request.go:417-420 Request.ProtoAtLeast
    /// `r.ProtoAtLeast(major, minor)` (request.go:417) — reports whether
    /// the request's HTTP protocol is at least major.minor.
    pub fn ProtoAtLeast(&self, major: int, minor: int) -> bool {
        // Go: return r.ProtoMajor > major ||
        //         r.ProtoMajor == major && r.ProtoMinor >= minor
        self.ProtoMajor > major || self.ProtoMajor == major && self.ProtoMinor >= minor
    }

    // go: sdk 1.25.5 net/http/request.go:423-425 Request.UserAgent
    /// `r.UserAgent()` (request.go:423) — convenience for the
    /// `User-Agent` request header.
    pub fn UserAgent(&self) -> string {
        self.Header.Get(string("User-Agent"))
    }

    // go: sdk 1.25.5 net/http/request.go:481-483 Request.Referer
    /// `r.Referer()` (request.go:481) — convenience for the
    /// `Referer` request header. Note the historical misspelling.
    pub fn Referer(&self) -> string {
        self.Header.Get(string("Referer"))
    }

    // go: sdk 1.25.5 net/http/request.go:973-979 Request.BasicAuth
    /// `r.BasicAuth()` (request.go:973) — return `(user, pass, ok)`
    /// from a HTTP Basic `Authorization` header.
    pub fn BasicAuth(&self) -> (string, string, bool) {
        let auth = self.Header.Get(string("Authorization"));
        if auth.Len() == 0 {
            return (string::new(), string::new(), false);
        }
        parseBasicAuth(auth)
    }

    // go: sdk 1.25.5 net/http/request.go:1022-1024 Request.SetBasicAuth
    /// `r.SetBasicAuth(user, pass)` (request.go:1022) — set the
    /// `Authorization` header to "Basic " + base64(user:pass).
    pub fn SetBasicAuth<U: Into<string>, P: Into<string>>(&mut self, username: U, password: P){
        let username: string = username.into();
        let password: string = password.into();
        let mut creds = crate::strings::Builder::new();
        let _ = creds.WriteString(username);
        let _ = creds.WriteByte(b':');
        let _ = creds.WriteString(password);
        let combined = creds.String();
        let encoded = crate::encoding::base64::StdEncoding
            .EncodeToString(crate::convert::bytes(combined).as_ref());
        let mut hv = crate::strings::Builder::new();
        let _ = hv.WriteString("Basic ");
        let _ = hv.WriteString(encoded);
        self.Header.Set(string("Authorization"), hv.String());
    }

    // go: sdk 1.25.5 net/http/request.go:464-471 Request.AddCookie
    /// `r.AddCookie(c)` — append a cookie to the `Cookie:` request
    /// header. Mirrors `(*Request).AddCookie(c)` (request.go:434);
    /// per RFC 6265 the request only has a single `Cookie:` line, so
    /// repeat calls fold into one space+`; `-separated value.
    pub fn AddCookie(&mut self, c: &super::cookie::Cookie) {
        // Go: fmt.Sprintf("%s=%s", sanitizeCookieName(c.Name),
        //                          sanitizeCookieValue(c.Value, c.Quoted))
        //
        // NAME=VALUE and nothing else. This used to call c.String(),
        // which is the Set-Cookie serialisation: it appends Path,
        // Domain, Expires, Max-Age, HttpOnly, Secure and SameSite, so a
        // request carrying an attribute-bearing Cookie sent
        //   Cookie: sid=abc; Path=/admin; HttpOnly
        // where Go sends `Cookie: sid=abc`, and the server on the other
        // end parses phantom cookies named Path and HttpOnly.
        // c.String() also returns "" for a name that is not a token, so
        // AddCookie silently dropped such cookies; Go rewrites \n and
        // \r to '-' and sends them.
        let name = super::cookie::sanitizeCookieName(c.Name.clone());
        let value = super::cookie::sanitizeCookieValue(c.Value.clone(), c.Quoted);
        let mut s: Vec<u8> = Vec::with_capacity((name.Len() + value.Len()) as usize + 1);
        s.extend_from_slice(name.as_bytes());
        s.push(b'=');
        s.extend_from_slice(value.as_bytes());
        let s = string::from_bytes(&s);

        let existing = self.Header.Get(string("Cookie"));
        if existing.Len() == 0 {
            self.Header.Set(string("Cookie"), s);
        } else {
            let mut buf: Vec<u8> = Vec::with_capacity((existing.Len() + s.Len()) as usize + 2);
            buf.extend_from_slice(existing.as_bytes());
            buf.extend_from_slice(b"; ");
            buf.extend_from_slice(s.as_bytes());
            self.Header.Set(string("Cookie"), string::from_bytes(&buf));
        }
    }

    // go: sdk 1.25.5 net/http/request.go:529-531 Request.isH2Upgrade
    pub fn isH2Upgrade(&self) -> bool {
        return self.Method == "PRI"
            && self.Header.Len() == 0
            && self.URL.Path == "*"
            && self.Proto == "HTTP/2.0";
    }

    // go: sdk 1.25.5 net/http/request.go:1509-1511 Request.expectsContinue
    //
    // Go calls the unexported `Header.get`, a raw map read that skips
    // canonicalization. "Expect" is already canonical, so goish's
    // canonicalizing `Get` returns the same value here.
    pub fn expectsContinue(&self) -> bool {
        return hasToken(self.Header.Get(string("Expect")), string("100-continue"));
    }

    // go: sdk 1.25.5 net/http/request.go:1520-1525 Request.wantsClose
    //
    /// Reports whether the request wants the connection closed after
    /// the reply — either the `Close` field is set, or the Connection
    /// header carries the "close" token.
    ///
    /// Go reads the header through the unexported `get`, a raw map
    /// lookup; "Connection" is already canonical so goish's `Get`
    /// returns the same value.
    pub fn wantsClose(&self) -> bool {
        if self.Close {
            return true;
        }
        return hasToken(self.Header.Get(string("Connection")), string("close"));
    }

    // go: sdk 1.25.5 net/http/request.go:1513-1518 Request.wantsHttp10KeepAlive
    pub fn wantsHttp10KeepAlive(&self) -> bool {
        if self.ProtoMajor != 1 || self.ProtoMinor != 0 {
            return false;
        }
        return hasToken(self.Header.Get(string("Connection")), string("keep-alive"));
    }

    // go: sdk 1.25.5 net/http/request.go:1579-1582 Request.requiresHTTP1
    // go: sdk 1.25.5 net/http/request.go:1534-1548 Request.isReplayable
    /// Go: whether this request may be re-sent on a fresh connection
    /// after a connection failure.
    ///
    /// GET/HEAD/OPTIONS/TRACE are replayable because they are
    /// idempotent. The two Idempotency-Key headers are non-standard
    /// but "widely used to mean a POST or other request is idempotent"
    /// (golang/go#19943) — a server that honours them opts its POSTs
    /// into retry, so dropping the check would silently stop retrying
    /// requests the caller expected to be retried.
    ///
    /// Go also requires `Body == nil || Body == NoBody || GetBody !=
    /// nil`; goish's Request owns its body as a `slice<byte>`, which
    /// is always replayable, so that guard is always satisfied.
    // go: sdk 1.25.5 net/http/request.go:1550-1560 Request.outgoingLength
    /// Go: "reports the Content-Length of this outgoing (Client)
    /// request. It maps 0 into -1 (unknown) when the Body is non-nil."
    ///
    /// The 0 -> -1 mapping is the point: a non-empty body whose length
    /// nobody set must be framed as UNKNOWN (chunked), not as
    /// zero-length, or the body silently never reaches the wire.
    pub fn outgoingLength(&self) -> i64 {
        if self.Body.Len() == 0 {
            return 0;
        }
        if self.ContentLength != 0 {
            return crate::int64(self.ContentLength);
        }
        return -1;
    }

    pub fn isReplayable(&self) -> bool {
        let m = if self.Method.Len() == 0 {
            string("GET")
        } else {
            self.Method.clone()
        };
        if m == "GET" || m == "HEAD" || m == "OPTIONS" || m == "TRACE" {
            return true;
        }
        if self.Header.has(string("Idempotency-Key"))
            || self.Header.has(string("X-Idempotency-Key"))
        {
            return true;
        }
        return false;
    }

    pub fn requiresHTTP1(&self) -> bool {
        return hasToken(self.Header.Get(string("Connection")), string("upgrade"))
            && crate::net::http::internal::ascii::EqualFold(
                self.Header.Get(string("Upgrade")),
                string("websocket"),
            );
    }
}

// go: sdk 1.25.5 net/http/request.go:35-37 defaultMaxMemory
pub const defaultMaxMemory: int = 32 << 20; // 32 MB

// go: sdk 1.25.5 net/http/request.go:1027-1034 parseRequestLine
//
/// Split "GET /path HTTP/1.1" into its three fields. Both separators
/// must be present, and each cut takes the FIRST space, so a URI
/// containing a space makes the remainder the proto and the line is
/// rejected downstream rather than silently mis-split.
pub fn parseRequestLine<L: Into<string>>(line: L) -> (string, string, string, bool) {
    let line: string = line.into();
    let (method, rest, ok1) = crate::strings::Cut(line, string(" "));
    let (requestURI, proto, ok2) = crate::strings::Cut(rest, string(" "));
    if !ok1 || !ok2 {
        return (string(""), string(""), string(""), false);
    }
    return (method, requestURI, proto, true);
}

// go: sdk 1.25.5 net/http/request.go:781-795 idnaASCII
//
/// Convert a host to its ASCII (punycode) form.
///
/// Go returns `v` unchanged when it is already ASCII and otherwise
/// calls `idna.Lookup.ToASCII`. goish has no `idna`, so a non-ASCII
/// host is an error rather than being punycoded. That is a REJECTION,
/// not a silent pass-through: returning the UTF-8 host would put
/// non-ASCII bytes in a Host header, which is what the conversion
/// exists to prevent. The ASCII fast path — every host a Go program
/// realistically dials — is exact.
pub fn idnaASCII<V: Into<string>>(v: V) -> (string, error) {
    let v: string = v.into();
    if super::internal::ascii::Is(v.clone()) {
        return (v, crate::errors::nil);
    }
    return (
        string(""),
        crate::errors::New(string(
            "http: internationalized host requires idna, which goish does not port",
        )),
    );
}

// go: sdk 1.25.5 net/http/request.go:96-96 badStringError
pub fn badStringError<W: Into<string>, V: Into<string>>(what: W, val: V) -> error {
    return crate::fmt::Errorf!("%s %q", what.into(), val.into());
}

// go: sdk 1.25.5 net/http/request.go:98-105 reqWriteExcludeHeader
//
// Headers that Request.Write emits from the Request's own fields
// rather than from the Header map, so writing them twice would
// duplicate them on the wire.
pub fn reqWriteExcludeHeader() -> crate::gomap::map<string, bool> {
    let mut m: crate::gomap::map<string, bool> = crate::gomap::map::new();
    m.Set(string("Host"), true); // not in Header map anyway
    m.Set(string("User-Agent"), true);
    m.Set(string("Content-Length"), true);
    m.Set(string("Transfer-Encoding"), true);
    m.Set(string("Trailer"), true);
    return m;
}

// go: sdk 1.25.5 net/http/request.go:486-491 multipartByReader
//
// A sentinel value. Its presence in Request.MultipartForm indicates
// that parsing of the request body has been handed off to a
// MultipartReader instead of ParseMultipartForm.
//
// Go compares it by POINTER identity (`r.MultipartForm ==
// multipartByReader`). goish rebuilds the value per call, so identity
// is not available and a caller must compare some other way — which is
// why this is a function rather than a `var!`: `var!` would look like
// a singleton and silently not be one.
pub fn multipartByReader() -> crate::mime::multipart::Form {
    return crate::mime::multipart::Form::default();
}

// go: sdk 1.25.5 net/http/request.go:545-545 defaultUserAgent
pub const defaultUserAgent: &str = "Go-http-client/1.1";

// go: sdk 1.25.5 net/http/request.go:577-577 errMissingHost
crate::var! {
    pub errMissingHost: error = "http: Request.Write on Request with no Host or URL set";
}

// go: sdk 1.25.5 net/http/request.go:794-812 removeZone
//
// Strip an IPv6 zone identifier from a bracketed host: `[fe80::1%en0]`
// becomes `[fe80::1]`. A zone is meaningful only on the local machine
// and must not appear in a Host header.
pub fn removeZone<H: Into<string>>(host: H) -> string {
    let host: string = host.into();
    if !crate::strings::HasPrefix(host.clone(), string("[")) {
        return host;
    }
    let i = crate::strings::LastIndex(host.clone(), string("]"));
    if i < 0 {
        return host;
    }
    let j = crate::strings::LastIndex(host.slice(0, i), string("%"));
    if j < 0 {
        return host;
    }
    return host.slice(0, j) + host.slice(i, host.Len());
}

// go: sdk 1.25.5 net/http/request.go:1566-1575 requestMethodUsuallyLacksBody
//
// Reports whether the given request method is one that typically has
// no body. Used only as a heuristic.
pub fn requestMethodUsuallyLacksBody<M: Into<string>>(method: M) -> bool {
    let method: string = method.into();
    if method == "GET"
        || method == "HEAD"
        || method == "DELETE"
        || method == "OPTIONS"
        || method == "PROPFIND"
        || method == "SEARCH"
    {
        return true;
    }
    return false;
}

// go: sdk 1.25.5 net/http/request.go:534-539 valueOrDefault
pub fn valueOrDefault<V: Into<string>, D: Into<string>>(value: V, def: D) -> string {
    let value: string = value.into();
    if value != "" {
        return value;
    }
    return def.into();
}

// ─── ReadRequest ─────────────────────────────────────────────────────

const DEFAULT_MAX_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 100;
const MAX_BODY: usize = 16 * 1024 * 1024; // 16 MiB safety cap

/// `http.ReadRequest(b *bufio.Reader)` — parse an HTTP/1.x request
/// using the default 8 KiB max-header-line. Mirrors
/// `func ReadRequest(b *bufio.Reader) (*Request, error)`
/// (request.go:1058).
///
/// For server use with a configurable limit, prefer
/// `ReadRequestWithLimit` (called by `http::Server` with
/// `srv.MaxHeaderBytes`).
pub fn ReadRequest<R: io::Reader>(
    br: &mut bufio::Reader<R>,
) -> (Request, error) {
    ReadRequestWithLimit(br, DEFAULT_MAX_LINE as int)
}

/// Variant of `ReadRequest` that honors the caller-provided
/// `max_header_bytes` — the maximum length of the request line and of
/// each individual header line. `<= 0` means "use the default".
///
/// On success the reader is positioned at the first byte after the
/// final CRLF of the request body (or after the headers if no body).
pub fn ReadRequestWithLimit<R: io::Reader>(
    br: &mut bufio::Reader<R>,
    max_header_bytes: int,
) -> (Request, error) {
    __read_request_server(br, max_header_bytes, -1)
}

/// Server-side variant carrying the raw conn fd so the parser can
/// emit the `HTTP/1.1 100 Continue` interim response between header
/// parse and the (eager) body read â Go defers this to the first
/// body `Read` via `expectContinueReader` (server.go:1022); goish
/// reads bodies eagerly, so "just before the body read" is the same
/// linearization point. `interim_fd < 0` disables Expect handling
/// (client-side response parsing paths).
// go: none — goish-only: Go writes `new(http.Request)` or
// `&http.Request{…}` for the zero value; Request has unexported fields
// (ctx, form state, path values) so goish needs a named constructor.
// Matches Go's zero value field for field.
impl Default for Request {
    fn default() -> Request {
        return Request {
            Close: false,
            Trailer: Header::new(),
            TLS: None,
            RequestURI: string::new(),
            Method: string::new(),
            URL: URL::empty(),
            Proto: string::new(),
            ProtoMajor: 0,
            ProtoMinor: 0,
            Header: Header::new(),
            Host: string::new(),
            ContentLength: 0,
            Body: slice::<byte>::__from_vec(Vec::new()),
            RemoteAddr: string::new(),
            path_values: crate::gomap::map::<string, string>::new(),
            form_state: alloc::sync::Arc::new(crate::sync::Mutex::new(FormCell::default())),
            ctx: None,
        };
    }
}

pub(crate) fn __read_request_server<R: io::Reader>(
    br: &mut bufio::Reader<R>,
    max_header_bytes: int,
    interim_fd: i32,
) -> (Request, error) {
    let max_line = if max_header_bytes > 0 {
        max_header_bytes as usize
    } else {
        DEFAULT_MAX_LINE
    };
    let mut req = Request {
        Close: false,
        Trailer: Header::new(),
        TLS: None,
        RequestURI: string::new(),
        Method: string::new(),
        URL: URL::empty(),
        Proto: string::new(),
        ProtoMajor: 0,
        ProtoMinor: 0,
        Header: Header::new(),
        Host: string::new(),
        ContentLength: 0,
        Body: slice::<byte>::__from_vec(Vec::new()),
        RemoteAddr: string::new(),
        path_values: crate::gomap::map::<string, string>::new(),
        form_state: alloc::sync::Arc::new(crate::sync::Mutex::new(FormCell::default())),
        ctx: None,
    };

    // Request-line: METHOD SP request-target SP HTTP-version CRLF —
    // parsed from a borrowed view of the bufio buffer; only the
    // three kept substrings are materialized (method/proto interned).
    let (method, target, proto) = match read_line_with(br, max_line, parse_request_line) {
        Ok(Some(t)) => t,
        Ok(None) => return (req, errors::New(string("net/http: malformed request line"))),
        Err(e) => return (req, e),
    };

    // Go: req.RequestURI = rawurl — the UNMODIFIED request-target,
    // captured before any URL parsing, because "*" and an absolute-URI
    // target do not survive it (readRequest, request.go:1105).
    req.RequestURI = target.clone();

    if !validMethod(method.clone()) {
        return (req, errors::New(string("net/http: invalid method")));
    }
    let (major, minor) = match parse_http_version(proto.as_bytes()) {
        Some(v) => v,
        None => return (req, errors::New(string("net/http: malformed HTTP version"))),
    };

    let url = match parse_request_uri(&target) {
        Ok(u) => u,
        Err(msg) => return (req, errors::New(msg)),
    };

    req.Method = method;
    req.URL = url;
    req.Proto = proto;
    req.ProtoMajor = major;
    req.ProtoMinor = minor;

    // Headers: lines of `Name: value` ending with an empty line.
    // Each line is parsed from a borrowed buffer view; the name
    // comes back pre-canonicalized (interned for common names), so
    // no canonicalization happens on the Add path.
    enum HeaderLine {
        End,
        Malformed,
        Field(string, string),
    }
    let mut count = 0;
    loop {
        let item = match read_line_with(br, max_line, |line| {
            if line.is_empty() {
                return HeaderLine::End;
            }
            match parse_header_line(line) {
                Some((n, v)) => HeaderLine::Field(n, v),
                None => HeaderLine::Malformed,
            }
        }) {
            Ok(v) => v,
            Err(e) => return (req, e),
        };
        match item {
            HeaderLine::End => break,
            HeaderLine::Malformed => {
                return (req, errors::New(string("net/http: malformed header")))
            }
            HeaderLine::Field(name, value) => {
                count += 1;
                if count > MAX_HEADERS {
                    return (req, errors::New(string("net/http: too many headers")));
                }
                // Special-case Host: into req.Host, not into Header.
                if name.as_bytes() == b"Host" {
                    req.Host = value;
                } else {
                    req.Header.__add_canonical(name, value);
                }
            }
        }
    }

    // `Expect` (RFC 9110 §10.1.1) — server path only. Mirrors Go's
    // readRequest/expectContinueReader split (server.go:1096, :1022):
    // a 100-continue expectation on a request with a body gets the
    // interim response now, right before the body read below; any
    // other Expect value is a 417 (the caller maps the sentinel).
    if interim_fd >= 0 {
        let expect = req.Header.Get(string("Expect"));
        if !expect.as_bytes().is_empty() {
            if crate::strings::EqualFold(expect.clone(), string("100-continue")) {
                let has_body = is_chunked(
                    req.Header.Get(string("Transfer-Encoding")).as_bytes(),
                ) || !req.Header.Get(string("Content-Length")).as_bytes().is_empty();
                if req.ProtoMajor > 1 || (req.ProtoMajor == 1 && req.ProtoMinor >= 1) {
                    if has_body {
                        write_interim_100(interim_fd);
                    }
                }
            } else {
                return (req, ErrUnsupportedExpect.into());
            }
        }
    }

    // Body framing — Transfer-Encoding: chunked takes precedence over
    // Content-Length per RFC 7230 §3.3.3.
    let te = req.Header.Get(string("Transfer-Encoding"));
    let chunked = is_chunked(te.as_bytes());
    if chunked {
        // Decode chunked body into a Vec, then drop into req.Body.
        // ContentLength = -1 ("unknown") matches Go's convention.
        req.ContentLength = -1;
        let mut buf: Vec<u8> = Vec::new();
        // ChunkedReader sits over `br` directly via a small adapter:
        // we hand it ownership of a &mut bufio::Reader-like surface.
        // Simplest: drain the bufio::Reader's Buffered() bytes plus
        // any future reads through the chunked decoder. Since
        // `ChunkedReader<R>` wraps its own bufio::Reader, we feed it
        // a thin `BufioPassthrough` that delegates to the existing
        // `br`.
        let mut cr = super::internal::chunked::NewChunkedReader(BufioPassthrough { inner: br });
        loop {
            let mut tmp = slice::<byte>::__from_vec(alloc::vec![0u8; 4096]);
            let (n_read, err) = cr.Read(&mut tmp);
            if n_read > 0 {
                let n_us = n_read as usize;
                if buf.len() + n_us > MAX_BODY {
                    return (req, errors::New(string("net/http: chunked body too large")));
                }
                for i in 0..n_us {
                    buf.push(tmp[i as int]);
                }
            }
            if !err.IsNil() {
                if errors::Is(err.clone(), io::EOF) {
                    break;
                }
                return (req, err);
            }
            if n_read == 0 {
                break;
            }
        }
        req.Body = slice::<byte>::__from_vec(buf);
        return (req, errors::nil);
    }

    // Content-Length → bounded body.
    let cl_str = req.Header.Get(string("Content-Length"));
    let n: int = if cl_str.as_bytes().is_empty() {
        0
    } else {
        match parse_dec(cl_str.as_bytes()) {
            Some(n) if n >= 0 && (n as usize) <= MAX_BODY => n,
            _ => return (req, errors::New(string("net/http: invalid Content-Length"))),
        }
    };
    req.ContentLength = n;

    if n > 0 {
        let want = n as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(want);
        let mut got: usize = 0;
        while got < want {
            let chunk = (want - got).min(4096);
            let scratch_vec: Vec<u8> = alloc::vec![0u8; chunk];
            let mut scratch = slice::<byte>::__from_vec(scratch_vec);
            let (n_read, err) = br.Read(&mut scratch);
            if n_read > 0 {
                let n_us = n_read as usize;
                let v: Vec<u8> = scratch.__into_vec();
                buf.extend_from_slice(&v[..n_us]);
                got += n_us;
            } else if !err.IsNil() {
                return (req, err);
            } else {
                return (req, errors::New(string("net/http: read returned 0 bytes")));
            }
        }
        req.Body = slice::<byte>::__from_vec(buf);
    }

    (req, errors::nil)
}

/// Adapter so ChunkedReader (which builds its *own* bufio::Reader)
/// can pull bytes from the request parser's existing bufio::Reader
/// without double-buffering. ChunkedReader wraps this in a fresh
/// bufio of its own — that's a small extra buffer, but the alternative
/// would require ChunkedReader to take a borrowed bufio which clashes
/// with its current `R: Reader` API shape.
struct BufioPassthrough<'a, R: io::Reader> {
    inner: &'a mut bufio::Reader<R>,
}
impl<'a, R: io::Reader> io::Reader for BufioPassthrough<'a, R> {
    fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        self.inner.Read(b)
    }
}

/// Match RFC 7230 `Transfer-Encoding: chunked` (case-insensitive,
/// possibly part of a comma-separated list — we accept any list whose
/// last item is `chunked`).
fn is_chunked(value: &[u8]) -> bool {
    // Trim and lowercase walk; check trailing token == "chunked".
    let mut end = value.len();
    while end > 0 && (value[end - 1] == b' ' || value[end - 1] == b'\t') {
        end -= 1;
    }
    let mut start = end;
    while start > 0 {
        let prev = value[start - 1];
        if prev == b',' || prev == b' ' || prev == b'\t' {
            break;
        }
        start -= 1;
    }
    let last = &value[start..end];
    last.len() == 7
        && (last[0] | 0x20) == b'c'
        && (last[1] | 0x20) == b'h'
        && (last[2] | 0x20) == b'u'
        && (last[3] | 0x20) == b'n'
        && (last[4] | 0x20) == b'k'
        && (last[5] | 0x20) == b'e'
        && (last[6] | 0x20) == b'd'
}

// ─── parsers ─────────────────────────────────────────────────────────

crate::var! {
    /// Sentinel returned by the server-side request parser when the
    /// request carries an `Expect` header other than `100-continue`.
    /// The serve loop maps it to `417 Expectation Failed` + close
    /// (Go `sendExpectationFailed`, server.go:2103).
    pub(crate) ErrUnsupportedExpect: error = "net/http: unsupported Expect header";
}

/// Blast the `100 Continue` interim response onto the raw conn fd.
/// 25 bytes into an (empty at this point — no response has started)
/// socket buffer; EAGAIN is retried with a yield, everything else is
/// abandoned (the real response write will surface the error).
fn write_interim_100(fd: i32) {
    const INTERIM: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
    let mut off = 0usize;
    while off < INTERIM.len() {
        let r = crate::syscall::Write(fd, INTERIM[off..].as_ptr(), INTERIM.len() - off);
        if r > 0 {
            off += r as usize;
            continue;
        }
        let errno = -(r as i32);
        if errno == 11 || errno == 4 {
            // EAGAIN / EINTR — tiny write, yield and retry.
            crate::runtime::sched::Gosched();
            continue;
        }
        return;
    }
}

/// Read one header/request line into an OWNED Vec — the slow path,
/// used only when the line doesn't fit the bufio buffer whole (rare:
/// requires a header line > 4 KiB). The hot path is the zero-copy
/// `__read_line_view` inside `read_line_with`.
fn read_line_owned<R: io::Reader>(
    br: &mut bufio::Reader<R>,
    max: usize,
) -> Result<Vec<u8>, error> {
    let (line_bytes, err) = br.ReadBytes(b'\n');
    if !err.IsNil() {
        return Err(err);
    }
    let mut bs: Vec<u8> = line_bytes.__into_vec();
    if bs.len() > max {
        return Err(errors::New(string("net/http: header line too long")));
    }
    // Strip trailing \n and optional \r.
    if bs.last() == Some(&b'\n') {
        bs.pop();
    }
    if bs.last() == Some(&b'\r') {
        bs.pop();
    }
    Ok(bs)
}

/// Read the next line and run `f` over its bytes without copying the
/// line itself — the view borrows the bufio buffer (valid for the
/// duration of `f`, invalidated by the next read; same contract as
/// Go's ReadSlice-based textproto reading). `f` copies out only the
/// substrings it keeps. Falls back to an owned read for
/// buffer-spanning lines.
fn read_line_with<R: io::Reader, T>(
    br: &mut bufio::Reader<R>,
    max: usize,
    f: impl FnOnce(&[u8]) -> T,
) -> Result<T, error> {
    match br.__read_line_view() {
        Ok(Some(line)) => {
            if line.len() > max {
                return Err(errors::New(string("net/http: header line too long")));
            }
            Ok(f(line))
        }
        Ok(None) => {
            let owned = read_line_owned(br, max)?;
            Ok(f(&owned))
        }
        Err(e) => Err(e),
    }
}

/// Intern the method token for the requests that dominate real
/// traffic — `from_static` is zero-alloc. Mirrors the effect of Go's
/// method-name string constants staying shared.
fn intern_method(b: &[u8]) -> string {
    string::from_static(match b {
        b"GET" => "GET",
        b"POST" => "POST",
        b"PUT" => "PUT",
        b"DELETE" => "DELETE",
        b"HEAD" => "HEAD",
        b"OPTIONS" => "OPTIONS",
        b"PATCH" => "PATCH",
        b"CONNECT" => "CONNECT",
        b"TRACE" => "TRACE",
        _ => return string::from_bytes(b),
    })
}

/// Intern the protocol token (all real traffic is one of two).
fn intern_proto(b: &[u8]) -> string {
    string::from_static(match b {
        b"HTTP/1.1" => "HTTP/1.1",
        b"HTTP/1.0" => "HTTP/1.0",
        _ => return string::from_bytes(b),
    })
}

/// `parseRequestLine` (request.go:961) — split "METHOD SP target SP
/// proto" on the two spaces. Byte-view in; owned strings out (method
/// and proto interned).
fn parse_request_line(bytes: &[u8]) -> Option<(string, string, string)> {
    let s1 = bytes.iter().position(|&b| b == b' ')?;
    let s2 = bytes[s1 + 1..].iter().position(|&b| b == b' ')? + s1 + 1;
    Some((
        intern_method(&bytes[..s1]),
        string::from_bytes(&bytes[s1 + 1..s2]),
        intern_proto(&bytes[s2 + 1..]),
    ))
}

/// `parseHeaderLine` — split "Name: value" on the first colon and
/// trim optional whitespace around `value`. Byte-view in; the name
/// comes back ALREADY canonicalized (interned for the common header
/// names — zero-alloc), so the caller skips `canonical_key`.
fn parse_header_line(bytes: &[u8]) -> Option<(string, string)> {
    let colon = bytes.iter().position(|&b| b == b':')?;
    let name = &bytes[..colon];
    if name.is_empty() {
        return None;
    }
    let mut start = colon + 1;
    while start < bytes.len() && (bytes[start] == b' ' || bytes[start] == b'\t') {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }
    Some((
        super::header::canonical_key_bytes(name),
        string::from_bytes(&bytes[start..end]),
    ))
}

// go: sdk 1.25.5 net/http/request.go:817-842 ParseHTTPVersion
/// `http.ParseHTTPVersion(vers)` — parse an HTTP
/// version string per RFC 7230 §2.6. `"HTTP/1.0"` → `(1, 0, true)`.
/// Note: strings without a minor version (e.g. `"HTTP/2"`) are
/// rejected.
pub fn ParseHTTPVersion<V: Into<string>>(vers: V) -> (int, int, bool) {
    let vers: string = vers.into();
    // Go: switch vers { case "HTTP/1.1": return 1, 1, true; case "HTTP/1.0": return 1, 0, true }
    if vers == "HTTP/1.1" {
        return (1, 1, true);
    }
    if vers == "HTTP/1.0" {
        return (1, 0, true);
    }
    // Go: if !strings.HasPrefix(vers, "HTTP/") || len(vers) != len("HTTP/X.Y") { return 0,0,false }
    if !crate::strings::HasPrefix(vers.clone(), string("HTTP/")) || vers.Len() != 8 {
        return (0, 0, false);
    }
    // Go: if vers[6] != '.' { return 0,0,false }
    if vers[6] != b'.' {
        return (0, 0, false);
    }
    // Go: maj, err := strconv.ParseUint(vers[5:6], 10, 0)
    let mb: byte = vers[5];
    let nb: byte = vers[7];
    if !mb.is_ascii_digit() || !nb.is_ascii_digit() {
        return (0, 0, false);
    }
    ((mb - b'0') as int, (nb - b'0') as int, true)
}

fn parse_http_version(b: &[u8]) -> Option<(int, int)> {
    if !b.starts_with(b"HTTP/") {
        return None;
    }
    let rest = &b[5..];
    let dot = rest.iter().position(|&c| c == b'.')?;
    let major = parse_dec(&rest[..dot])?;
    let minor = parse_dec(&rest[dot + 1..])?;
    if !(0..1000).contains(&major) || !(0..1000).contains(&minor) {
        return None;
    }
    Some((major, minor))
}

fn parse_dec(b: &[u8]) -> Option<int> {
    if b.is_empty() {
        return None;
    }
    let mut acc: i64 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as i64)?;
    }
    Some(acc)
}

// go: sdk 1.25.5 net/http/request.go:844-859 validMethod
//
/// RFC 7230 §3.2.6 token chars — what's legal in a method name.
///
/// Reports whether `m` is a valid HTTP method — RFC 7230 §3.1.1's
/// `token`, i.e. one or more `tchar`. Note this ACCEPTS lowercase and
/// arbitrary tokens: Go validates the grammar, not a method list, so
/// `validMethod("get")` and `validMethod("a!b")` are both true.
pub fn validMethod<M: Into<string>>(m: M) -> bool {
    let m: string = m.into();
    if m.Len() == 0 {
        return false;
    }
    for &b in m.as_bytes() {
        let ok = matches!(b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' |
            b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' |
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
        );
        if !ok {
            return false;
        }
    }
    return true;
}

// go: sdk 1.25.5 net/http/request.go:993-1009 parseBasicAuth
/// Line-by-line port of `parseBasicAuth` (request.go:993).
pub fn parseBasicAuth(auth: string) -> (string, string, bool) {
    // Go: const prefix = "Basic "
    // Go: if len(auth) < len(prefix) || !ascii.EqualFold(auth[:len(prefix)], prefix) { return "","",false }
    if auth.Len() < 6 {
        return (string::new(), string::new(), false);
    }
    let head_bytes = &auth.as_bytes()[..6];
    let head = string::from_bytes(head_bytes);
    if !crate::strings::EqualFold(head, string("Basic ")) {
        return (string::new(), string::new(), false);
    }
    // Go: c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
    let payload_bytes = &auth.as_bytes()[6..];
    let payload_str = match core::str::from_utf8(payload_bytes) {
        Ok(s) => s,
        Err(_) => return (string::new(), string::new(), false),
    };
    let (decoded, derr) = crate::encoding::base64::StdEncoding.DecodeString(payload_str);
    if !derr.IsNil() {
        return (string::new(), string::new(), false);
    }
    // Go: cs := string(c); username, password, ok := strings.Cut(cs, ":")
    let cs = crate::convert::string(decoded);
    let (user, pass, ok) = crate::strings::Cut(cs, string(":"));
    if !ok {
        return (string::new(), string::new(), false);
    }
    (user, pass, true)
}

// go: sdk 1.25.5 net/http/request.go:1203-1209 maxBytesReader
//
/// `http.MaxBytesReader(w, r, n)` — returns a `Reader` that stops
/// reading from `r` after `n` bytes, returning `MaxBytesError` once
/// the limit is exceeded.
///
/// `w` was previously DROPPED from the signature, with a note calling
/// it a slim port. It is not cosmetic: `w` is how Go reaches
/// `requestTooLarge`, which forces the connection closed. Without it
/// the client keeps sending a body nobody reads, and the remainder is
/// parsed as the next keep-alive request. Still Reader-only rather
/// than io.ReadCloser.
///
/// `w` is a BORROW with a lifetime, not an owned handle. That is the
/// whole trick: the reader is created and consumed inside the
/// handler's body, so `&dyn ResponseWriter` — which is all
/// `ServeHTTP` hands out — outlives it comfortably. I first wrote
/// this taking an `Arc`, concluded a handler could never supply one,
/// and documented it as a known gap; the gap was my choice of
/// ownership, not the signature.
pub struct maxBytesReader<'w, R: io::Reader> {
    w: Option<&'w (dyn super::responsewriter::ResponseWriter + Send + Sync + 'static)>,
    r: R,
    i: int,
    n: int,
    err: error,
}

impl __ErrNotSupported {
    // go: sdk 1.25.5 net/http/request.go:52-55 ProtocolError.Is
    /// Go: "Is lets http.ErrNotSupported match errors.ErrUnsupported."
    ///
    /// Go's receiver is `*ProtocolError` and the body is
    /// `pe == ErrNotSupported && err == errors.ErrUnsupported` — an
    /// identity test on the sentinel, not a type test, so only THAT
    /// one ProtocolError matches. goish reaches the same result
    /// through the Unwrap chain already on this type; `Is` is spelled
    /// out so the rule is greppable under its Go name.
    #[allow(dead_code)]
    pub fn Is(&self, err: crate::errors::error) -> bool {
        return crate::errors::Is(err, crate::errors::ErrUnsupported);
    }
}

crate::var! {
    /// `http.ErrNoCookie` (request.go:442).
    pub ErrNoCookie: error        = "http: named cookie not present";

    /// `http.ErrMissingFile` (request.go:41).
    pub ErrMissingFile: error     = "http: no such file";

    /// `http.ErrNotMultipart` (request.go:78).
    pub ErrNotMultipart: error    = "request Content-Type isn't multipart/form-data";

    /// `http.ErrMissingBoundary` (request.go:74).
    pub ErrMissingBoundary: error = "no multipart boundary param in Content-Type";
}

// ─── ProtocolError + sentinels (line-by-line port of request.go:43-94) ─

/// `http.ProtocolError` (request.go:47) — typed HTTP protocol error.
/// Mirrors:
///
/// ```ignore
/// type ProtocolError struct { ErrorString string }
/// func (pe *ProtocolError) Error() string { return pe.ErrorString }
/// ```
///
/// User code can construct one directly: `errors::Wrap(ProtocolError{
/// ErrorString: string("...") })`. Sentinel instances live in cached
/// SpinLocks below so identity-comparison via Arc::ptr_eq works.
#[derive(Clone)]
pub struct ProtocolError {
    pub ErrorString: string,
}

impl errors::ErrorTrait for ProtocolError {
    // Go: func (pe *ProtocolError) Error() string { return pe.ErrorString }
    fn Error(&self) -> string {
        self.ErrorString.clone()
    }
}

/// Internal: ErrNotSupported's pointee. Wraps ProtocolError but
/// chains `Unwrap()` to `errors::ErrUnsupported()`, so
/// `errors::Is(http::ErrNotSupported, errors::ErrUnsupported())`
/// returns true. Mirrors Go's:
///
/// ```ignore
/// func (pe *ProtocolError) Is(err error) bool {
///     return pe == ErrNotSupported && err == errors.ErrUnsupported
/// }
/// ```
///
/// Goish has no `errors.As`, so the sentinel's identity is encoded in
/// the type itself — only the cached `ErrNotSupported()` instance is
/// of this internal type, all other ProtocolError values are not.
struct __ErrNotSupported;

impl errors::ErrorTrait for __ErrNotSupported {
    fn Error(&self) -> string {
        // Go: ErrNotSupported = &ProtocolError{"feature not supported"}
        string("feature not supported")
    }
    fn Unwrap(&self) -> error {
        // Goish chain: walk to errors.ErrUnsupported so callers using
        // `errors::Is(err, errors::ErrUnsupported)` succeed.
        crate::errors::ErrUnsupported.into()
    }
}

crate::var! {
    /// `http.ErrNotSupported` (request.go:65) — sentinel returned by
    /// ResponseController methods and Pusher.Push when a feature is not
    /// supported. `errors::Is(_, errors::ErrUnsupported)` succeeds via
    /// the Unwrap chain.
    pub ErrNotSupported: error = { __ErrNotSupported };

    /// `http.ErrUnexpectedTrailer` (request.go:70) — deprecated sentinel.
    pub ErrUnexpectedTrailer: error = {
        ProtocolError { ErrorString: string("trailer header without chunked transfer encoding") }
    };

    /// `http.ErrHeaderTooLong` (request.go:83) — deprecated sentinel.
    pub ErrHeaderTooLong: error = {
        ProtocolError { ErrorString: string("header too long") }
    };

    /// `http.ErrShortBody` (request.go:88) — deprecated sentinel.
    pub ErrShortBody: error = {
        ProtocolError { ErrorString: string("entity body too short") }
    };

    /// `http.ErrMissingContentLength` (request.go:93) — deprecated sentinel.
    pub ErrMissingContentLength: error = {
        ProtocolError { ErrorString: string("missing ContentLength in HEAD response") }
    };
}

/// Internal helper to construct a degenerate Reader for the
/// MultipartReader error paths.
fn empty_multipart_reader() -> crate::mime::multipart::Reader {
    crate::mime::multipart::NewReader(
        slice::<byte>::__from_vec(Vec::new()),
        string::new(),
    )
}

/// `http.MaxBytesError` (request.go:1193) — typed error returned by
/// MaxBytesReader when its read limit is exceeded. Carries the
/// configured byte limit so callers can introspect it. Mirrors:
///
/// ```ignore
/// type MaxBytesError struct { Limit int64 }
/// func (e *MaxBytesError) Error() string { return "http: request body too large" }
/// ```
// go: sdk 1.25.5 net/http/request.go:1194-1196 MaxBytesError
#[derive(Clone)]
pub struct MaxBytesError {
    pub Limit: int,
}

impl errors::ErrorTrait for MaxBytesError {
    fn Error(&self) -> string {
        // Go: "Due to Hyrum's law, this text cannot be changed."
        string("http: request body too large")
    }

    /// Walks to the legacy sentinel so callers using the older
    /// `errors::Is(err, ErrMaxBytes.into())` form continue to match. Go's
    /// type uses `errors.As(*MaxBytesError)` instead, but goish lacks
    /// errors.As; chaining through Unwrap is the closest analogue.
    fn Unwrap(&self) -> error {
        ErrMaxBytes.into()
    }
}

/// Build a `MaxBytesError` wrapped as a goish `error`.
pub fn NewMaxBytesError(limit: int) -> error {
    errors::Wrap(MaxBytesError { Limit: limit })
}

crate::var! {
    /// `http.MaxBytesReader` legacy sentinel — kept for callers that
    /// match against a single error value rather than the typed
    /// MaxBytesError. Prefer the typed form when you need the limit.
    pub ErrMaxBytes: error = "http: request body too large";
}

// go: sdk 1.25.5 net/http/request.go:1186-1191 MaxBytesReader
//
// Go has the exported FUNC `MaxBytesReader` and the unexported TYPE
// `maxBytesReader`. goish had them the wrong way round — the struct
// took the exported name and the constructor became
// `NewMaxBytesReader`, which matches nothing in Go and hid the
// function from the coverage check. Now spelled as Go spells them.
pub fn MaxBytesReader<'w, R: io::Reader>(
    w: Option<&'w (dyn super::responsewriter::ResponseWriter + Send + Sync + 'static)>,
    r: R,
    n: int,
) -> maxBytesReader<'w, R> {
    // Go: if n < 0 { n = 0 }
    let n = if n < 0 { 0 } else { n };
    maxBytesReader {
        w,
        r,
        i: n,
        n,
        err: errors::nil,
    }
}

impl<'w, R: io::Reader> io::Reader for maxBytesReader<'w, R> {
    // go: sdk 1.25.5 net/http/request.go:1211-1251 maxBytesReader.Read
    //
    /// Verified against goref across the boundary that matters. Go
    /// shrinks the read to `remaining+1`, not `remaining`, so ONE
    /// extra byte answers "did we go over?":
    ///
    ///   body exactly at the limit -> full read, then a plain EOF
    ///   body one byte over        -> full read, then MaxBytesError
    ///   limit 0                   -> MaxBytesError on the first read
    ///
    /// A port shrinking to `remaining` passes the exact case and
    /// reports EOF for the over case — silently accepting an
    /// oversized body. The error is also STICKY: every later Read
    /// returns it with n=0.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: if l.err != nil { return 0, l.err }
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }
        // Go: if len(p) == 0 { return 0, nil }
        if p.Len() == 0 {
            return (0, errors::nil);
        }
        // Go: if int64(len(p))-1 > l.n { p = p[:l.n+1] }
        // We can't shrink the caller's slice; instead read into a tmp.
        let cap = if p.Len() - 1 > self.n {
            self.n + 1
        } else {
            p.Len()
        };
        let mut tmp = crate::make!([]byte, cap);
        let (n, err) = self.r.Read(&mut tmp);
        // Copy what we read into p.
        for i in 0..n {
            p[i] = tmp[i];
        }
        // Go: if int64(n) <= l.n { l.n -= int64(n); l.err = err; return n, err }
        if n <= self.n {
            self.n -= n;
            self.err = err.clone();
            return (n, err);
        }
        // Go: n = int(l.n); l.n = 0; … return n, &MaxBytesError{l.i}
        let limited_n = self.n;
        self.n = 0;
        // Go: `l.w.requestTooLarge()` BEFORE building the error
        // (request.go:1241). This is what closes the connection so the
        // unread remainder of the body cannot be read as the next
        // keep-alive request.
        if let Some(w) = self.w {
            if let (r, true) = crate::cast!(w, super::responsewriter::__RequestTooLarge) {
                r.requestTooLarge();
            }
        }
        self.err = NewMaxBytesError(self.i);
        return (limited_n, self.err.clone());
    }
}

// ─── Form helpers (line-by-line port of request.go:1245-1306) ────────

// go: sdk 1.25.5 net/http/request.go:1263-1307 parsePostForm
//
/// `parsePostForm(r)` (request.go:1245). Reads body when content type
/// is application/x-www-form-urlencoded; otherwise returns empty.
fn parsePostForm(r: &Request) -> (crate::gomap::map<string, slice<string>>, error) {
    use crate::gomap::map;
    // Go: if r.Body == nil { return … }
    if r.Body.Len() == 0 && r.ContentLength <= 0 {
        return (map::<string, slice<string>>::new(), errors::nil);
    }
    // Go: ct := r.Header.Get("Content-Type")
    let ct = r.Header.Get(string("Content-Type"));
    // Strip parameters: "application/x-www-form-urlencoded; charset=utf-8" → base
    let (base, _, _) = crate::strings::Cut(ct, string(";"));
    let base = crate::strings::TrimSpace(base);
    // Go: switch ct { case "application/x-www-form-urlencoded": … }
    if !crate::strings::EqualFold(base, string("application/x-www-form-urlencoded")) {
        return (map::<string, slice<string>>::new(), errors::nil);
    }
    // Go: b, e := io.ReadAll(reader)
    // We already have r.Body fully buffered; just decode it as a string.
    let body_bytes = r.Body.clone();
    let body_str = crate::convert::string(body_bytes);
    super::url::ParseQuery(body_str)
}

// go: sdk 1.25.5 net/http/request.go:1257-1261 copyValues
/// Merge `src` into `dst`, appending values under each key.
pub fn copyValues(
    dst: &mut crate::gomap::map<string, slice<string>>,
    src: &crate::gomap::map<string, slice<string>>,
) {
    for (k, v) in src.__iter() {
        let (existing, _) = dst.Get(k.clone());
        let mut merged = existing;
        for i in 0..v.Len() {
            merged = crate::append!(merged, v[i].clone());
        }
        dst.Set(k.clone(), merged);
    }
}

