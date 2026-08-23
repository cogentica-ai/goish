// go: file net/http/pprof/pprof.go decls: Cmdline, sleep, configureWriteDeadline, serveError, Profile, Trace, Symbol, Handler, handler.ServeHTTP, handler.serveDeltaProfile, collectProfile, Index, indexTmplExecute, init, profileSupportsDelta, profileDescriptions
//
// net/http/pprof — the HTTP surface of the runtime profiler.
//
// PARTIAL, and the split is by DEPENDENCY, not by difficulty. What
// lands here is everything that needs only net/http itself:
//
//   * `Cmdline` — the process argv, NUL-separated.
//   * `serveError` — the package's error response shape.
//   * `sleep` — the profile duration wait, cancellable by the request.
//   * `configureWriteDeadline` — the reason a 30-second profile is not
//     cut off by the server's WriteTimeout. It reads the *Server back
//     out of the request context, which only became possible when
//     `ServerContextKey` was ported.
//
// The rest of the package rides on runtime/pprof's registry slice
// and the honest unsupported arms of StartCPUProfile / trace.Start
// (both the error-returning shapes Go itself ships on platforms
// without profiling): Handler/Index/ServeHTTP serve REAL registry
// profiles with live-symbolized stacks; Symbol resolves PCs through
// runtime::FuncForPC; Profile and Trace flow Go's exact error path;
// the delta pair ports verbatim and reports through collectProfile's
// error (WriteTo's protobuf arm awaits the profileBuilder). The old
// html/template claim on indexTmplExecute was wrong twice over — Go
// itself hand-renders the page into a bytes.Buffer.

#![allow(non_snake_case)]

extern crate alloc;

use crate::errors::error;
use crate::goslice::slice;
use crate::string;
use crate::types::{float64, int};

use super::super::request::Request;
use super::super::responsewriter::ResponseWriter;

// go: sdk 1.25.5 net/http/pprof/pprof.go:110-114 Cmdline
/// Go: "Cmdline responds with the running program's command line,
/// with arguments separated by NUL bytes."
///
/// `X-Content-Type-Options: nosniff` is on every handler in this
/// package and is not decoration — profile output is attacker-
/// influenced in the sense that it contains program data, and a
/// browser sniffing it as HTML would run it.
pub fn Cmdline(w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request) {
    w.Header()
        .Set(string("X-Content-Type-Options"), string("nosniff"));
    w.Header()
        .Set(string("Content-Type"), string("text/plain; charset=utf-8"));
    let _ = w.Write(crate::convert::bytes(crate::strings::Join(
        crate::os::Args(),
        string("\x00"),
    )));
    return;
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:116-121 sleep
/// Wait `d`, or until the request is cancelled — whichever comes
/// first. A profile that ignored the second half would keep running
/// after the client hung up.
pub fn sleep(r: &Request, d: crate::time::Duration) {
    let done = r.Context().Done();
    let after = crate::time::After(d);
    crate::select! {
        let _ = after.Recv() => {},
        let _ = done.Recv() => {},
    }
    return;
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:123-131 configureWriteDeadline
/// Extend this response's write deadline to cover the profile.
///
/// Without it a `Server.WriteTimeout` of, say, 10 seconds truncates
/// every 30-second profile at 10 — the handler is not stuck, it is
/// working as asked, and the timeout cannot tell the difference. The
/// server is reached through `ServerContextKey`, which is why this
/// could not be ported before that key existed.
pub fn configureWriteDeadline(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: &Request,
    seconds: float64,
) {
    let v = match r.Context().Value(super::super::server::ServerContextKey) {
        None => {
            return;
        }
        Some(v) => v,
    };
    let srv = match v.downcast_ref::<alloc::sync::Arc<super::super::server::Server>>() {
        None => {
            return;
        }
        Some(s) => s.clone(),
    };
    if srv.WriteTimeout.0 > 0 {
        // Go: `srv.WriteTimeout + time.Duration(seconds*float64(time.Second))`
        let extra = crate::int64(seconds * crate::float64(crate::time::Second.0));
        let timeout = crate::time::Duration(srv.WriteTimeout.0 + extra);
        let rc = super::super::responsecontroller::NewResponseController(__rw_arc(w));
        let _ = rc.SetWriteDeadline(crate::time::Now().Add(timeout));
    }
    return;
}

// go: none — goish-only: `NewResponseController` takes an owned
// `Arc<dyn ResponseWriter>` because a ResponseController outlives the
// call that built it. A handler is handed a borrow, so the borrow is
// re-wrapped in a non-owning Arc whose only job is to satisfy that
// signature for the duration of this call.
fn __rw_arc(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
) -> alloc::sync::Arc<dyn ResponseWriter + Send + Sync + 'static> {
    struct Borrowed(*const (dyn ResponseWriter + Send + Sync + 'static));
    // SAFETY: the Arc never escapes `configureWriteDeadline`, which
    // borrows `w` for its whole body, so the pointer cannot dangle.
    unsafe impl Send for Borrowed {}
    unsafe impl Sync for Borrowed {}
    impl ResponseWriter for Borrowed {
        // go: none — goish-only: forwarding shim, see __rw_arc.
        fn Header(&self) -> super::super::responsewriter::HeaderHandle {
            return unsafe { (*self.0).Header() };
        }
        // go: none — goish-only: forwarding shim, see __rw_arc.
        fn Write(&self, p: slice<crate::types::byte>) -> (int, error) {
            return unsafe { (*self.0).Write(p) };
        }
        // go: none — goish-only: forwarding shim, see __rw_arc.
        fn WriteHeader(&self, statusCode: int) {
            unsafe { (*self.0).WriteHeader(statusCode) }
        }
        // go: none — goish-only: forwarding shim, see __rw_arc.
        fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
            // The controller's capability walk must see through to the
            // real writer, not to this shim.
            return unsafe { (*self.0).__goish_as_dyn_any() };
        }
    }
    return alloc::sync::Arc::new(Borrowed(w as *const _));
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:133-139 serveError
/// The package's error shape. `X-Go-Pprof: 1` is how the pprof CLIENT
/// recognises an error coming from this handler rather than from a
/// proxy in between, and the `Content-Disposition` DELETE matters
/// because the success path sets one — leaving it on an error would
/// have the browser save the error text as a .pprof file.
pub fn serveError(w: &(dyn ResponseWriter + Send + Sync + 'static), status: int, txt: string) {
    w.Header()
        .Set(string("Content-Type"), string("text/plain; charset=utf-8"));
    w.Header().Set(string("X-Go-Pprof"), string("1"));
    w.Header().Del(string("Content-Disposition"));
    w.WriteHeader(status);
    // Go: fmt.Fprintln — the newline is part of the response.
    let _ = w.Write(crate::convert::bytes(txt + string("\n")));
    return;
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:95-106 init
/// Go registers the five handlers on the DefaultServeMux at import
/// time (method-prefixed "GET " unless the httpmuxgo121 godebug opts
/// out; goish has no godebug, so the modern prefix is unconditional).
/// goish packages have no import-time hook — call this once (any
/// number of calls is safe: pkg_init_once) before serving the
/// DefaultServeMux, the same way expvar-style ports surface their
/// init.
pub fn init() {
    crate::pkg_init_once!("net_http_pprof", {
        super::super::HandleFunc(string("GET /debug/pprof/"), |w, r| Index(w, r));
        super::super::HandleFunc(string("GET /debug/pprof/cmdline"), |w, r| Cmdline(w, r));
        super::super::HandleFunc(string("GET /debug/pprof/profile"), |w, r| Profile(w, r));
        super::super::HandleFunc(string("GET /debug/pprof/symbol"), |w, r| Symbol(w, r));
        super::super::HandleFunc(string("GET /debug/pprof/trace"), |w, r| Trace(w, r));
    });
    return;
}

// go: none — goish-only: io::Writer over the borrowed
// ResponseWriter (Go passes `w` straight to StartCPUProfile /
// WriteTo; goish's shared-handle writer needs the &mut shim).
struct __RwSink<'a> {
    w: &'a (dyn ResponseWriter + Send + Sync + 'static),
}

impl crate::io::Writer for __RwSink<'_> {
    // go: none — goish-only forwarding shim, see __RwSink.
    fn Write(&mut self, p: slice<crate::types::byte>) -> (int, error) {
        return self.w.Write(p);
    }
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:144-165 Profile
/// Go: "Profile responds with the pprof-formatted cpu profile." The
/// Content-Type is set optimistically because a successful
/// StartCPUProfile begins writing immediately; the goish runtime's
/// StartCPUProfile reports its unsupported error, so this serves
/// Go's exact profiler-failure arm (500, "Could not enable CPU
/// profiling: …").
pub fn Profile(w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
    w.Header()
        .Set(string("X-Content-Type-Options"), string("nosniff"));
    let (mut sec, err) = crate::strconv::Atoi(r.FormValue(string("seconds")));
    if sec <= 0 || !err.IsNil() {
        sec = 30;
    }

    configureWriteDeadline(w, r, crate::float64(sec));

    // Go: "Set Content Type assuming StartCPUProfile will work,
    // because if it does it starts writing."
    w.Header()
        .Set(string("Content-Type"), string("application/octet-stream"));
    w.Header().Set(
        string("Content-Disposition"),
        string("attachment; filename=\"profile\""),
    );
    let mut sink = __RwSink { w };
    let serr = crate::runtime::pprof::StartCPUProfile(&mut sink);
    if !serr.IsNil() {
        // Go: "StartCPUProfile failed, so no writes yet."
        serveError(
            w,
            super::super::status::StatusInternalServerError,
            crate::fmt::Sprintf!("Could not enable CPU profiling: %v", serr),
        );
        return;
    }
    sleep(r, crate::time::Duration(sec * 1_000_000_000));
    crate::runtime::pprof::StopCPUProfile();
    return;
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:170-191 Trace
/// Go: "Trace responds with the execution trace in binary form." As
/// with Profile, the goish tracer's Start reports unsupported and
/// this serves Go's failure arm verbatim.
pub fn Trace(w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
    w.Header()
        .Set(string("X-Content-Type-Options"), string("nosniff"));
    let (mut sec, err) = crate::strconv::Atoi(r.FormValue(string("seconds")));
    if sec <= 0 || !err.IsNil() {
        sec = 1;
    }

    configureWriteDeadline(w, r, crate::float64(sec));

    w.Header()
        .Set(string("Content-Type"), string("application/octet-stream"));
    w.Header().Set(
        string("Content-Disposition"),
        string("attachment; filename=\"trace\""),
    );
    let mut sink = __RwSink { w };
    let serr = crate::runtime::trace::Start(&mut sink);
    if !serr.IsNil() {
        // Go: "trace.Start failed, so no writes yet."
        serveError(
            w,
            super::super::status::StatusInternalServerError,
            crate::fmt::Sprintf!("Could not enable tracing: %v", serr),
        );
        return;
    }
    sleep(r, crate::time::Duration(sec * 1_000_000_000));
    crate::runtime::trace::Stop();
    return;
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:196-240 Symbol
/// Go: "Symbol looks up the program counters listed in the request,
/// responding with a table mapping program counters to function
/// names." PCs arrive '+'-separated in the POST body or the raw
/// query; resolution is LIVE through runtime::FuncForPC (the
/// symbolizer that also feeds panic backtraces).
pub fn Symbol(w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
    w.Header()
        .Set(string("X-Content-Type-Options"), string("nosniff"));
    w.Header()
        .Set(string("Content-Type"), string("text/plain; charset=utf-8"));

    // Go: "We have to read the whole POST body before writing any
    // output. Buffer the output here."
    let mut buf = crate::strings::Builder::new();
    // Go: "Pprof only cares whether this number is 0 (no symbols
    // available) or > 0."
    let _ = buf.WriteString(string("num_symbols: 1\n"));

    let raw: slice<crate::types::byte> = if r.Method == "POST" {
        let (b, _) = crate::io::ReadAll(&mut r.Body.clone());
        b
    } else {
        crate::convert::bytes(r.URL.RawQuery.clone())
    };

    // Go reads '+'-separated words off a bufio; the whole input is in
    // hand here, so the split is direct.
    let text = crate::gostring::string::from_bytes(&raw);
    for word in (text.as_ref() as &str).split('+') {
        let word = word.trim();
        if word.is_empty() {
            continue;
        }
        // Go: strconv.ParseUint(word, 0, 64) — base 0: 0x-prefixed
        // hex or decimal.
        let pc: u64 = if let Some(hex) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16).unwrap_or(0)
        } else {
            word.parse().unwrap_or(0)
        };
        if pc != 0 {
            if let Some(f) = crate::runtime::FuncForPC(pc as crate::types::uintptr) {
                let _ = buf.WriteString(crate::fmt::Sprintf!("0x%x %s\n", pc, f.Name()));
            }
        }
    }

    let _ = w.Write(crate::convert::bytes(buf.String()));
    return;
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:244-246 Handler
/// Go: "Handler returns an HTTP handler that serves the named
/// profile. Available profiles can be found in runtime/pprof.Profile."
pub fn Handler(
    name: crate::gostring::string,
) -> alloc::sync::Arc<dyn super::super::server::Handler> {
    return alloc::sync::Arc::new(handler(name));
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:248-248 handler
pub struct handler(pub crate::gostring::string);

impl super::super::server::Handler for handler {
    // go: sdk 1.25.5 net/http/pprof/pprof.go:250-273 handler.ServeHTTP
    /// The named-profile server: unknown names 404 ("Unknown
    /// profile"), a `seconds` param routes to the delta path, and the
    /// profile renders as text (debug!=0) or attachment.
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
        w.Header()
            .Set(string("X-Content-Type-Options"), string("nosniff"));
        let p = match crate::runtime::pprof::Lookup(self.0.clone()) {
            None => {
                serveError(
                    w,
                    super::super::status::StatusNotFound,
                    string("Unknown profile"),
                );
                return;
            }
            Some(p) => p,
        };
        let sec = r.FormValue(string("seconds"));
        if sec.Len() != 0 {
            self.serveDeltaProfile(w, r, &p, sec);
            return;
        }
        // Go: if name == "heap" && gc > 0 { runtime.GC() } — the
        // goish runtime has no collector to kick.
        let (debug, _) = crate::strconv::Atoi(r.FormValue(string("debug")));
        if debug != 0 {
            w.Header()
                .Set(string("Content-Type"), string("text/plain; charset=utf-8"));
        } else {
            w.Header()
                .Set(string("Content-Type"), string("application/octet-stream"));
            w.Header().Set(
                string("Content-Disposition"),
                crate::fmt::Sprintf!("attachment; filename=\"%s\"", self.0.clone()),
            );
        }
        let mut sink = __RwSink { w };
        let werr = p.WriteTo(&mut sink, debug);
        if !werr.IsNil() && debug == 0 {
            // The protobuf arm reported unsupported before writing;
            // surface it the way Go surfaces WriteTo failures.
            serveError(
                w,
                super::super::status::StatusInternalServerError,
                werr.Error(),
            );
        }
        return;
    }
}

impl handler {
    // go: sdk 1.25.5 net/http/pprof/pprof.go:275-338 handler.serveDeltaProfile
    /// Go: diff two collections of the profile `seconds` apart. The
    /// parameter validation and pacing are verbatim; collectProfile's
    /// protobuf dependency reports through the same "failed to
    /// collect profile" arm Go uses for any collection failure.
    fn serveDeltaProfile(
        &self,
        w: &(dyn ResponseWriter + Send + Sync + 'static),
        r: &Request,
        p: &alloc::sync::Arc<crate::runtime::pprof::Profile>,
        secStr: crate::gostring::string,
    ) {
        let (sec, err) = crate::strconv::Atoi(secStr);
        if !err.IsNil() || sec <= 0 {
            serveError(
                w,
                super::super::status::StatusBadRequest,
                string("invalid value for \"seconds\" - must be a positive integer"),
            );
            return;
        }
        // Go: 'name' should be a key in profileSupportsDelta.
        if !profileSupportsDelta(self.0.clone()) {
            serveError(
                w,
                super::super::status::StatusBadRequest,
                string("\"seconds\" parameter is not supported for this profile type"),
            );
            return;
        }

        configureWriteDeadline(w, r, crate::float64(sec));

        let (debug, _) = crate::strconv::Atoi(r.FormValue(string("debug")));
        if debug != 0 {
            serveError(
                w,
                super::super::status::StatusBadRequest,
                string("seconds and debug params are incompatible"),
            );
            return;
        }
        let (p0, cerr) = collectProfile(p);
        let _ = p0;
        if !cerr.IsNil() {
            serveError(
                w,
                super::super::status::StatusInternalServerError,
                string("failed to collect profile"),
            );
            return;
        }
        // The second collection, the Scale(-1) + Merge delta and the
        // protobuf Write ride on internal/profile, which arrives with
        // the profileBuilder; collectProfile above reports before any
        // of it can run today.
        serveError(
            w,
            super::super::status::StatusInternalServerError,
            string("failed to compute delta"),
        );
        return;
    }
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:339-350 collectProfile
/// Go: WriteTo(debug=0) into a buffer, then internal/profile.Parse.
/// The registry WriteTo's protobuf arm reports unsupported, so this
/// returns that error — the delta path then serves Go's collection-
/// failure response.
fn collectProfile(
    p: &alloc::sync::Arc<crate::runtime::pprof::Profile>,
) -> (crate::goslice::slice<crate::types::byte>, error) {
    let mut buf = crate::bytes::Buffer::new();
    let werr = p.WriteTo(&mut buf, 0);
    if !werr.IsNil() {
        return (
            crate::goslice::slice::__from_vec(alloc::vec::Vec::new()),
            werr,
        );
    }
    return (buf.Bytes(), crate::errors::nil);
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:353-360 profileSupportsDelta
// goishlint:ignore GOISH020 profileSupportsDelta — Go's is a map var
// consulted by key; the lookup is the function form of the same set.
/// The builtin profiles whose ?seconds= delta makes sense.
fn profileSupportsDelta(name: crate::gostring::string) -> bool {
    let n: &str = name.as_ref();
    return n == "allocs"
        || n == "block"
        || n == "goroutine"
        || n == "heap"
        || n == "mutex"
        || n == "threadcreate";
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:362-373 profileDescriptions
/// The Index page's per-profile blurbs, verbatim.
fn profileDescriptions(name: crate::gostring::string) -> crate::gostring::string {
    let n: &str = name.as_ref();
    let d = match n {
        "allocs" => "A sampling of all past memory allocations",
        "block" => "Stack traces that led to blocking on synchronization primitives",
        "cmdline" => "The command line invocation of the current program",
        "goroutine" => "Stack traces of all current goroutines. Use debug=2 as a query parameter to export in the same format as an unrecovered panic.",
        "heap" => "A sampling of memory allocations of live objects. You can specify the gc GET parameter to run GC before taking the heap sample.",
        "mutex" => "Stack traces of holders of contended mutexes",
        "profile" => "CPU profile. You can specify the duration in the seconds GET parameter. After you get the profile file, use the go tool pprof command to investigate the profile.",
        "symbol" => "Maps given program counters to function names. Counters can be specified in a GET raw query or POST body, multiple counters are separated by '+'.",
        "threadcreate" => "Stack traces that led to the creation of new OS threads",
        "trace" => "A trace of execution of the current program. You can specify the duration in the seconds GET parameter. After you get the trace file, use the go tool trace command to investigate the trace.",
        _ => "",
    };
    return string(d);
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:375-380 profileEntry
pub struct profileEntry {
    pub Name: crate::gostring::string,
    pub Href: crate::gostring::string,
    pub Desc: crate::gostring::string,
    pub Count: int,
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:386-423 Index
/// Go: "/debug/pprof/" serves the HTML listing; a trailing name
/// dispatches to that profile's handler.
pub fn Index(w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
    let name_owned = {
        let path: &str = r.URL.Path.as_ref();
        path.strip_prefix("/debug/pprof/")
            .filter(|n| !n.is_empty())
            .map(|n| crate::gostring::string::from_bytes(n.as_bytes()))
    };
    if let Some(name) = name_owned {
        let h = handler(name);
        return super::super::server::Handler::ServeHTTP(&h, w, r);
    }

    w.Header()
        .Set(string("X-Content-Type-Options"), string("nosniff"));
    w.Header()
        .Set(string("Content-Type"), string("text/html; charset=utf-8"));

    let mut profiles: alloc::vec::Vec<profileEntry> = alloc::vec::Vec::new();
    let ps = crate::runtime::pprof::Profiles();
    for i in 0..ps.Len() {
        let p = &ps[i];
        profiles.push(profileEntry {
            Name: p.Name(),
            Href: p.Name(),
            Desc: profileDescriptions(p.Name()),
            Count: p.Count(),
        });
    }
    // Go: "Adding other profiles exposed from within this package"
    for name in ["cmdline", "profile", "symbol", "trace"] {
        profiles.push(profileEntry {
            Name: string(name),
            Href: string(name),
            Desc: profileDescriptions(string(name)),
            Count: 0,
        });
    }
    profiles.sort_by(|a, b| a.Name.as_bytes().cmp(b.Name.as_bytes()));

    let mut sink = __RwSink { w };
    let _ = indexTmplExecute(&mut sink, &profiles);
    return;
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:425-469 indexTmplExecute
/// Go hand-renders the page into a bytes.Buffer (no template package
/// involved — an earlier note here claimed html/template and was
/// wrong). Names and descriptions are HTML-escaped.
pub fn indexTmplExecute(
    w: &mut dyn crate::io::Writer,
    profiles: &alloc::vec::Vec<profileEntry>,
) -> error {
    let mut b = crate::strings::Builder::new();
    let _ = b.WriteString(string(
        "<html>\n<head>\n<title>/debug/pprof/</title>\n<style>\n.profile-name{\n\tdisplay:inline-block;\n\twidth:6rem;\n}\n</style>\n</head>\n<body>\n/debug/pprof/\n<br>\n<p>Set debug=1 as a query parameter to export in legacy text format</p>\n<br>\nTypes of profiles available:\n<table>\n<thead><td>Count</td><td>Profile</td></thead>\n",
    ));
    for p in profiles.iter() {
        let _ = b.WriteString(crate::fmt::Sprintf!(
            "<tr><td>%d</td><td><a href='%s?debug=1'>%s</a></td></tr>\n",
            p.Count,
            p.Href.clone(),
            crate::html::EscapeString(p.Name.clone())
        ));
    }
    let _ = b.WriteString(string(
        "</table>\n<a href=\"goroutine?debug=2\">full goroutine stack dump</a>\n<br>\n<p>\nProfile Descriptions:\n<ul>\n",
    ));
    for p in profiles.iter() {
        let _ = b.WriteString(crate::fmt::Sprintf!(
            "<li><div class=profile-name>%s: </div> %s</li>\n",
            crate::html::EscapeString(p.Name.clone()),
            crate::html::EscapeString(p.Desc.clone())
        ));
    }
    let _ = b.WriteString(string("</ul>\n</p>\n</body>\n</html>"));
    let (_, err) = w.Write(crate::convert::bytes(b.String()));
    return err;
}
