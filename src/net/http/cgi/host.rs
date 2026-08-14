// net/http/cgi/host — the CGI host side (running a child process as
// a Handler).
//
// Port of Go 1.25.5 net/http/cgi/host.go: `Handler` and its ServeHTTP,
// which runs the CGI executable as a child process, plus the pure
// helpers that shape its environment.
//
// NOT ported: `osDefaultInheritEnv`, a GOOS switch whose linux arm is
// the only reachable one — inlined as LD_LIBRARY_PATH below.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::error;
use crate::goslice::slice;
use crate::string;
use crate::strings;
use crate::types::{int, rune};

use super::super::request::Request;
use super::super::responsewriter::ResponseWriter;
use super::super::server::Handler as HTTPHandler;

// go: sdk 1.25.5 net/http/cgi/host.go:393-407 upperCaseAndUnderscore
/// Map one rune of an HTTP header name into its CGI environment form:
/// lowercase to uppercase, `-` to `_`, and `=` to `_`.
///
/// The `=` case is the one worth keeping the comment for. Go: "Maybe
/// not part of the CGI 'spec' but would mess up the environment in any
/// case, as Go represents the environment as a slice of 'key=value'
/// strings." A header named `X=Y` would otherwise inject a second
/// `=` into the env entry and split it in the wrong place.
pub fn upperCaseAndUnderscore(r: rune) -> rune {
    if r >= crate::rune('a') && r <= crate::rune('z') {
        return r - (crate::rune('a') - crate::rune('A'));
    }
    if r == crate::rune('-') {
        return crate::rune('_');
    }
    if r == crate::rune('=') {
        return crate::rune('_');
    }
    // Go: "TODO: other transformations in spec or practice?"
    return r;
}

// go: sdk 1.25.5 net/http/cgi/host.go:98-115 removeLeadingDuplicates
/// Drop every `key=value` entry that a LATER entry with the same key
/// overrides, keeping the last occurrence.
///
/// Order matters and the direction is easy to invert: Go scans forward
/// and drops entry `i` if any entry AFTER it shares its `key=` prefix,
/// so the SURVIVOR is the last one. An environment is applied
/// last-wins, so keeping the first instead would silently hand the
/// child the value it was meant to override.
///
/// An entry with no `=` at all is never treated as a duplicate — Go
/// only compares when `IndexByte(e, '=')` finds one.
pub fn removeLeadingDuplicates(env: slice<string>) -> slice<string> {
    let mut ret: Vec<string> = Vec::new();
    for i in 0..env.Len() {
        let e = env[i].clone();
        let mut found = false;
        let eq = crate::strings::IndexByte(e.clone(), b'=');
        if eq != -1 {
            // Go: `keq := e[:eq+1]` — the key INCLUDING its '=', so
            // "PATH=" cannot match "PATH_EXTRA=".
            let eb = e.as_bytes();
            let keq = string::from_bytes(
                &eb[..crate::builtin::__make_size(eq) + 1],
            );
            for j in (i + 1)..env.Len() {
                if crate::strings::HasPrefix(env[j].clone(), keq.clone()) {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            ret.push(e);
        }
    }
    return slice::<string>::__from_vec(ret);
}

// go: sdk 1.25.5 net/http/cgi/host.go:36-36 trailingPort
/// Go: `regexp.MustCompile(`:([0-9]+)$`)`, used to lift the port out
/// of `Host`. goish builds it on demand rather than at package init —
/// a `var!` with a compiled Regexp would be rebuilt per use anyway.
fn trailingPort() -> crate::regexp::Regexp {
    return crate::regexp::MustCompile(string(":([0-9]+)$"));
}

// go: sdk 1.25.5 net/http/cgi/host.go:37-54 osDefaultInheritEnv
/// Go switches on GOOS; goish targets linux only, where the list is
/// `LD_LIBRARY_PATH`. Kept as a function so the shape survives if a
/// second target ever appears.
fn osDefaultInheritEnv() -> slice<string> {
    let mut out: slice<string> = slice::new();
    out = crate::append!(out, string("LD_LIBRARY_PATH"));
    return out;
}

// go: sdk 1.25.5 net/http/cgi/host.go:409-409 testHookStartProcess
/// Go: "nil except for some tests" — a hook the package's own tests
/// use to reach the child `*os.Process` right after Start. goish has
/// no `os.Process` to hand it (see `exec::Cmd::Kill`), and nothing in
/// the tree sets it, so the slot exists to keep the declaration
/// present rather than to be called.
pub static testHookStartProcess: Option<fn(int)> = None;

// go: sdk 1.25.5 net/http/cgi/host.go:56-82 Handler
/// Go: "Handler runs an executable in a subprocess with a CGI
/// environment."
#[derive(Default)]
pub struct Handler {
    /// Go: "path to the CGI executable".
    pub Path: string,
    /// Go: "root URI prefix of handler or empty for '/'".
    pub Root: string,
    /// Go: "Dir specifies the CGI executable's working directory. If
    /// Dir is empty, the base directory of Path is used. If Path has
    /// no base directory, the current working directory is used."
    pub Dir: string,
    /// Go: "extra environment variables to set, if any, as
    /// 'key=value'".
    pub Env: slice<string>,
    /// Go: "environment variables to inherit from host, as 'key'".
    pub InheritEnv: slice<string>,
    /// Go: "optional log for errors or nil to use log.Print".
    pub Logger: Option<Arc<crate::log::Logger>>,
    /// Go: "optional arguments to pass to child process".
    pub Args: slice<string>,
    /// Go: "optional stderr for the child process; nil means
    /// os.Stderr".
    pub Stderr: Option<Arc<crate::sync::Mutex<alloc::boxed::Box<dyn crate::io::Writer + Send>>>>,
    /// Go: "PathLocationHandler specifies the root http Handler that
    /// should handle internal redirects when the CGI process returns a
    /// Location header value starting with a '/' […] If nil, a CGI
    /// response with a local URI path is instead sent back to the
    /// client and not redirected internally."
    pub PathLocationHandler: Option<Arc<dyn HTTPHandler>>,
}

impl Handler {
    // go: sdk 1.25.5 net/http/cgi/host.go:84-89 Handler.stderr
    /// Where the child's stderr goes. Go returns an `io.Writer`;
    /// goish returns the optional handle and the caller falls back to
    /// `os.Stderr`, because the two have no common owned type.
    pub fn stderr(
        &self,
    ) -> Option<Arc<crate::sync::Mutex<alloc::boxed::Box<dyn crate::io::Writer + Send>>>> {
        if self.Stderr.is_some() {
            return self.Stderr.clone();
        }
        return None;
    }

    // go: sdk 1.25.5 net/http/cgi/host.go:355-361 Handler.printf
    /// Go's `printf(format string, v ...any)`. goish has no variadic
    /// `any`, so callers format with `fmt::Sprintf!` and pass the
    /// finished string — the shape `Server.logf` and
    /// `ReverseProxy.logf` already use.
    pub fn printf(&self, format: string, args: slice<string>) {
        let _ = &args;
        match self.Logger.as_ref() {
            Some(l) => {
                let _ = l.Output(2, format);
            }
            None => {
                crate::log::Printf!("%s", format);
            }
        }
        return;
    }

    // go: sdk 1.25.5 net/http/cgi/host.go:363-391 Handler.handleInternalRedirect
    /// RFC 3875 §6.3.2: a `Location:` starting with `/` is resolved by
    /// the host, not sent to the client.
    ///
    /// The synthesized request is deliberately spare — Go's comment
    /// notes RFC 3875 is unclear on whether anything but GET is
    /// supported, so the method is forced to GET and NO headers carry
    /// over. Copying the inbound headers here would forward the
    /// client's Cookie/Authorization into a request it never made.
    pub fn handleInternalRedirect(
        &self,
        rw: &(dyn ResponseWriter + Send + Sync + 'static),
        req: &Request,
        path: string,
    ) {
        let (url, err) = req.URL.Parse(path.clone());
        if !err.IsNil() {
            rw.WriteHeader(super::super::status::StatusInternalServerError);
            self.printf(
                crate::fmt::Sprintf!(
                    "cgi: error resolving local URI path %q: %v",
                    path,
                    err
                ),
                slice::new(),
            );
            return;
        }
        let mut newReq = Request::default();
        newReq.Method = string("GET");
        newReq.Proto = string("HTTP/1.1");
        newReq.ProtoMajor = 1;
        newReq.ProtoMinor = 1;
        newReq.Header = super::super::header::Header::new();
        newReq.Host = url.Host.clone();
        newReq.RemoteAddr = req.RemoteAddr.clone();
        newReq.TLS = req.TLS.clone();
        newReq.URL = url;
        match self.PathLocationHandler.as_ref() {
            Some(h) => {
                h.ServeHTTP(rw, &newReq);
            }
            None => {
                // Go dereferences a nil PathLocationHandler here and
                // panics; the field doc says the caller must set it
                // before a CGI script can return a local Location. A
                // nil deref is not a behaviour worth reproducing.
                rw.WriteHeader(super::super::status::StatusInternalServerError);
                self.printf(
                    string("cgi: local Location with no PathLocationHandler set"),
                    slice::new(),
                );
            }
        }
        return;
    }
}

impl HTTPHandler for Handler {
    // go: sdk 1.25.5 net/http/cgi/host.go:117-353 Handler.ServeHTTP
    /// Run the CGI executable for one request: build the environment
    /// per RFC 3875, spawn the child, parse the CGI head off its
    /// stdout, then stream the rest to the client.
    ///
    /// Three details are load-bearing and easy to lose:
    ///
    ///   * a chunked request body is refused with 400. CGI has no way
    ///     to express "length unknown" to the child, so guessing would
    ///     hand the script a truncated body.
    ///   * the `Proxy` header is dropped (Go issue 16405, "httpoxy").
    ///     `Proxy: …` from a client would otherwise arrive as
    ///     HTTP_PROXY and redirect the script's own outbound requests.
    ///   * headers are joined with ", " except Cookie, which uses "; ".
    fn ServeHTTP(&self, rw: &(dyn ResponseWriter + Send + Sync + 'static), req: &Request) {
        let te = req.Header.Values(string("Transfer-Encoding"));
        if crate::len(&te) > 0 && te[0] == "chunked" {
            rw.WriteHeader(super::super::status::StatusBadRequest);
            let _ = rw.Write(crate::convert::bytes(
                "Chunked request bodies are not supported by CGI.",
            ));
            return;
        }

        let root = strings::TrimRight(self.Root.clone(), string("/"));
        let pathInfo = strings::TrimPrefix(req.URL.Path.clone(), root.clone());

        let mut port = string("80");
        if req.TLS.is_some() {
            port = string("443");
        }
        let matches = trailingPort().FindStringSubmatch(req.Host.clone());
        if crate::len(&matches) != 0 {
            port = matches[1].clone();
        }

        let mut env: slice<string> = slice::new();
        env = crate::append!(env, string("SERVER_SOFTWARE=go"));
        env = crate::append!(env, string("SERVER_PROTOCOL=HTTP/1.1"));
        env = crate::append!(env, string("HTTP_HOST=") + req.Host.clone());
        env = crate::append!(env, string("GATEWAY_INTERFACE=CGI/1.1"));
        env = crate::append!(env, string("REQUEST_METHOD=") + req.Method.clone());
        env = crate::append!(env, string("QUERY_STRING=") + req.URL.RawQuery.clone());
        env = crate::append!(env, string("REQUEST_URI=") + req.URL.RequestURI());
        env = crate::append!(env, string("PATH_INFO=") + pathInfo);
        env = crate::append!(env, string("SCRIPT_NAME=") + root);
        env = crate::append!(env, string("SCRIPT_FILENAME=") + self.Path.clone());
        env = crate::append!(env, string("SERVER_PORT=") + port);

        let (remoteIP, remotePort, err) = crate::net::SplitHostPort(req.RemoteAddr.clone());
        if err.IsNil() {
            env = crate::append!(env, string("REMOTE_ADDR=") + remoteIP.clone());
            env = crate::append!(env, string("REMOTE_HOST=") + remoteIP);
            env = crate::append!(env, string("REMOTE_PORT=") + remotePort);
        } else {
            // Go: "could not parse ip:port, let's use whole RemoteAddr
            // and leave REMOTE_PORT undefined".
            env = crate::append!(env, string("REMOTE_ADDR=") + req.RemoteAddr.clone());
            env = crate::append!(env, string("REMOTE_HOST=") + req.RemoteAddr.clone());
        }

        let (hostDomain, _, herr) = crate::net::SplitHostPort(req.Host.clone());
        if herr.IsNil() {
            env = crate::append!(env, string("SERVER_NAME=") + hostDomain);
        } else {
            env = crate::append!(env, string("SERVER_NAME=") + req.Host.clone());
        }

        if req.TLS.is_some() {
            env = crate::append!(env, string("HTTPS=on"));
        }

        for (k, v) in req.Header.__inner().__iter() {
            let k = strings::Map(upperCaseAndUnderscore, k);
            if k == "PROXY" {
                // Go: "See Issue 16405" — the httpoxy vulnerability.
                continue;
            }
            let joinStr = if k == "COOKIE" {
                string("; ")
            } else {
                string(", ")
            };
            env = crate::append!(
                env,
                string("HTTP_") + k + string("=") + strings::Join(v.clone(), joinStr)
            );
        }

        if req.ContentLength > 0 {
            env = crate::append!(
                env,
                crate::fmt::Sprintf!("CONTENT_LENGTH=%d", req.ContentLength)
            );
        }
        let ctype = req.Header.Get(string("Content-Type"));
        if ctype.Len() != 0 {
            env = crate::append!(env, string("CONTENT_TYPE=") + ctype);
        }

        let mut envPath = crate::os::Getenv("PATH");
        if envPath.Len() == 0 {
            envPath = string("/bin:/usr/bin:/usr/ucb:/usr/bsd:/usr/local/bin");
        }
        env = crate::append!(env, string("PATH=") + envPath);

        for i in 0..crate::len(&self.InheritEnv) {
            let e = self.InheritEnv[i].clone();
            let v = crate::os::Getenv(e.clone());
            if v.Len() != 0 {
                env = crate::append!(env, e + string("=") + v);
            }
        }
        let dflt = osDefaultInheritEnv();
        for i in 0..crate::len(&dflt) {
            let e = dflt[i].clone();
            let v = crate::os::Getenv(e.clone());
            if v.Len() != 0 {
                env = crate::append!(env, e + string("=") + v);
            }
        }

        for i in 0..crate::len(&self.Env) {
            env = crate::append!(env, self.Env[i].clone());
        }

        env = removeLeadingDuplicates(env);

        // Go: `filepath.Split(h.Path)` when Dir is empty. goish's
        // path::Split is the slash-only form, which on the only target
        // (linux) is the same function.
        let (cwd, path) = if self.Dir.Len() != 0 {
            (self.Dir.clone(), self.Path.clone())
        } else {
            let (d, f) = crate::path::Split(self.Path.clone());
            (d, f)
        };
        let cwd = if cwd.Len() == 0 { string(".") } else { cwd };

        let mut args: slice<string> = slice::new();
        args = crate::append!(args, self.Path.clone());
        for i in 0..crate::len(&self.Args) {
            args = crate::append!(args, self.Args[i].clone());
        }

        // Go builds the Cmd as a struct literal: `Path` is the name
        // relative to `Dir` and `Args[0]` is the FULL h.Path. goish's
        // `Command` prepends its own argv[0] and runs LookPath, so
        // both fields are overwritten with Go's values — LookPath here
        // could otherwise pick a same-named binary off $PATH instead
        // of the script the caller named.
        let mut cmd = crate::os::exec::Command(path.clone(), slice::new());
        cmd.Path = path;
        cmd.Args = args;
        cmd.Dir = cwd;
        cmd.Env = env;
        if let Some(w) = self.stderr() {
            cmd.Stderr = Some(alloc::sync::Arc::new(crate::sync::Mutex::new(
                core::cell::UnsafeCell::new(alloc::boxed::Box::new(__sharedWriter { w })
                    as alloc::boxed::Box<dyn crate::io::Writer + Send>),
            )));
        }
        if req.ContentLength != 0 {
            cmd.SetStdin(crate::bytes::NewReader(req.Body.__materialize().0));
        }
        let (stdoutRead, perr) = cmd.StdoutPipe();
        if !perr.IsNil() {
            self.__internalError(rw, perr);
            return;
        }
        let serr = cmd.Start();
        if !serr.IsNil() {
            self.__internalError(rw, serr);
            return;
        }

        let mut linebody = crate::bufio::NewReaderSize(stdoutRead, 1024);
        let mut headers = super::super::header::Header::new();
        let mut statusCode: int = 0;
        let mut headerLines: int = 0;
        let mut sawBlankLine = false;
        loop {
            let (line, isPrefix, lerr) = linebody.ReadLine();
            if isPrefix {
                rw.WriteHeader(super::super::status::StatusInternalServerError);
                self.printf(string("cgi: long header line from subprocess."), slice::new());
                let _ = cmd.Kill();
                let _ = cmd.Wait();
                return;
            }
            if crate::errors::Is(lerr.clone(), crate::io::EOF) {
                break;
            }
            if !lerr.IsNil() {
                rw.WriteHeader(super::super::status::StatusInternalServerError);
                self.printf(
                    crate::fmt::Sprintf!("cgi: error reading headers: %v", lerr),
                    slice::new(),
                );
                let _ = cmd.Kill();
                let _ = cmd.Wait();
                return;
            }
            if crate::len(&line) == 0 {
                sawBlankLine = true;
                break;
            }
            headerLines += 1;
            let text = crate::string::from_bytes(&line);
            let (header, val, ok) = strings::Cut(text.clone(), string(":"));
            if !ok {
                self.printf(
                    crate::fmt::Sprintf!("cgi: bogus header line: %s", text),
                    slice::new(),
                );
                continue;
            }
            // Go calls httpguts.ValidHeaderFieldName; goish's `isToken`
            // IS that function, as http.rs records.
            if !super::super::http::isToken(&header) {
                self.printf(
                    crate::fmt::Sprintf!("cgi: invalid header name: %q", header),
                    slice::new(),
                );
                continue;
            }
            let val = crate::net::textproto::TrimString(val);
            if header == "Status" {
                if val.Len() < 3 {
                    self.printf(
                        crate::fmt::Sprintf!("cgi: bogus status (short): %q", val),
                        slice::new(),
                    );
                    let _ = cmd.Kill();
                    let _ = cmd.Wait();
                    return;
                }
                let (code, cerr) = crate::strconv::Atoi(val.slice(0, 3));
                if !cerr.IsNil() {
                    self.printf(
                        crate::fmt::Sprintf!("cgi: bogus status: %q", val),
                        slice::new(),
                    );
                    self.printf(
                        crate::fmt::Sprintf!("cgi: line was %q", text),
                        slice::new(),
                    );
                    let _ = cmd.Kill();
                    let _ = cmd.Wait();
                    return;
                }
                statusCode = code;
            } else {
                headers.Add(header, val);
            }
        }
        if headerLines == 0 || !sawBlankLine {
            rw.WriteHeader(super::super::status::StatusInternalServerError);
            self.printf(string("cgi: no headers"), slice::new());
            let _ = cmd.Kill();
            let _ = cmd.Wait();
            return;
        }

        let loc = headers.Get(string("Location"));
        if loc.Len() != 0 {
            if strings::HasPrefix(loc.clone(), string("/")) && self.PathLocationHandler.is_some()
            {
                self.handleInternalRedirect(rw, req, loc);
                let _ = cmd.Wait();
                return;
            }
            if statusCode == 0 {
                statusCode = super::super::status::StatusFound;
            }
        }

        if statusCode == 0 && headers.Get(string("Content-Type")).Len() == 0 {
            rw.WriteHeader(super::super::status::StatusInternalServerError);
            self.printf(
                string("cgi: missing required Content-Type in headers"),
                slice::new(),
            );
            let _ = cmd.Kill();
            let _ = cmd.Wait();
            return;
        }

        if statusCode == 0 {
            statusCode = super::super::status::StatusOK;
        }

        // Go: "Copy headers to rw's headers, after we've decided not to
        // go into handleInternalRedirect, which won't want its rw
        // headers to have been touched."
        for (k, vv) in headers.__inner().__iter() {
            for i in 0..crate::len(&vv) {
                rw.Header().Add(k.clone(), vv[i].clone());
            }
        }

        rw.WriteHeader(statusCode);

        let (_, cerr) = __copyToResponse(rw, &mut linebody);
        if !cerr.IsNil() {
            self.printf(
                crate::fmt::Sprintf!("cgi: copy error: %v", cerr),
                slice::new(),
            );
            // Go: "kill the child CGI process so we don't hang on the
            // deferred cmd.Wait above if the error was just the client
            // (rw) going away."
            let _ = cmd.Kill();
        }
        let _ = cmd.Wait();
        return;
    }
}

impl Handler {
    // go: none — goish-only: Go declares `internalError` as a closure
    // inside ServeHTTP; a closure capturing `rw` and `self` cannot be
    // spelled there without fighting the borrow checker for nothing.
    fn __internalError(
        &self,
        rw: &(dyn ResponseWriter + Send + Sync + 'static),
        err: error,
    ) {
        rw.WriteHeader(super::super::status::StatusInternalServerError);
        self.printf(
            crate::fmt::Sprintf!("CGI error: %v", err),
            slice::new(),
        );
        return;
    }
}

// go: none — goish-only: Go assigns `cmd.Stderr = h.stderr()` directly
// because both sides are io.Writer. goish's Cmd wants an owned
// `Box<dyn Writer + Send>`, so the shared handle is wrapped.
struct __sharedWriter {
    w: Arc<crate::sync::Mutex<alloc::boxed::Box<dyn crate::io::Writer + Send>>>,
}

impl crate::io::Writer for __sharedWriter {
    // go: none — goish-only: see __sharedWriter above.
    fn Write(&mut self, p: slice<crate::types::byte>) -> (int, error) {
        let mut g = self.w.Lock();
        return g.Write(p);
    }
}

// go: none — goish-only: Go writes `io.Copy(rw, linebody)` because its
// ResponseWriter IS an io.Writer. goish's is not, so the loop is here.
fn __copyToResponse<R: crate::io::Reader>(
    rw: &(dyn ResponseWriter + Send + Sync + 'static),
    src: &mut R,
) -> (crate::types::int64, error) {
    let mut buf = crate::make!([]crate::types::byte, 32 * 1024);
    let mut written: crate::types::int64 = 0;
    let out = loop {
        let (nr, rerr) = src.Read(&mut buf);
        if nr > 0 {
            let (nw, werr) = rw.Write(buf.slice(0, nr));
            written += crate::types::int64::from(nw);
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

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registry for this module's Handler, the way every other module with
// an unexported Handler does.
pub(crate) fn register_cgi_impls() {
    super::super::server::__goish_register_Handler_impl::<Handler>();
}

// ── cgi_main.go ──────────────────────────────────────────────────────
//
// Go compiles cgi_main.go into the package, but every declaration in
// it is a CGI CHILD PROGRAM: `cgiMain` dispatches on SCRIPT_NAME,
// `testCGI` and `childCGIProcess` are the two child binaries the
// package's own host_test/integration_test re-exec themselves as, and
// `neverEnding.Read` is the infinite body one of them streams.
//
// goish has no test binary to re-exec — its tests are examples, and
// `examples/http_cgi_serve_smoke.rs` spawns `/bin/sh -c` as the child
// instead, which exercises the same host-side code paths (env, header
// parse, Status/Location handling, body copy) without needing a Go
// test harness to impersonate. Porting these four would produce four
// functions that nothing in the tree can call.
//
// go: waived cgiMain — CGI child program for the package's own tests; goish spawns /bin/sh instead.
// go: waived testCGI — CGI child program for the package's own tests; see cgiMain.
// go: waived childCGIProcess — CGI child program for the package's own tests; see cgiMain.
// go: waived Read — `neverEnding.Read`, the infinite body childCGIProcess streams; no caller without it.
