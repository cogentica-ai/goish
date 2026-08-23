// http_pprof_smoke — the four net/http/pprof declarations that need
// nothing but net/http itself.
//
// The package as a whole is blocked on runtime/pprof, runtime/trace
// and internal/profile. These four are not, and each has a property
// worth pinning:
//
//   * serveError DELETES Content-Disposition. The success path sets
//     one (profiles download as files); leaving it on an error would
//     have the browser save the error text as a .pprof.
//   * X-Go-Pprof: 1 is how the pprof CLIENT tells an error from this
//     handler apart from one injected by a proxy.
//   * Cmdline separates arguments with NUL, not spaces — an argument
//     containing a space would otherwise be indistinguishable from
//     two arguments.
//   * configureWriteDeadline reads the *Server back out of the
//     request context. Without it, a Server.WriteTimeout shorter than
//     the profile duration truncates every profile, and the handler
//     cannot tell that it happened.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::Closer;
use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::pprof::pprof;
use goish::runtime::pprof as rpprof;
use goish::time;
use goish::{context, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

static DEADLINES: AtomicUsize = AtomicUsize::new(0);
static LAST_DEADLINE: goish::sync::Mutex<i64> = goish::sync::Mutex::new(0);

/// A ResponseWriter that can set a write deadline, and remembers it.
struct deadlineWriter;

impl http::ResponseWriter for deadlineWriter {
    fn Header(&self) -> goish::net::http::responsewriter::HeaderHandle {
        return goish::net::http::responsewriter::HeaderHandle::new(http::Header::new());
    }
    fn Write(&self, p: goish::goslice::slice<goish::byte>) -> (goish::types::int, goish::error) {
        return (goish::builtin::len(&p), goish::errors::nil);
    }
    fn WriteHeader(&self, _statusCode: goish::types::int) {}
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl goish::net::http::responsecontroller::WriteDeadliner for deadlineWriter {
    fn SetWriteDeadline(&self, deadline: time::Time) -> goish::error {
        DEADLINES.fetch_add(1, Ordering::Relaxed);
        // Unix seconds is plenty to place a deadline ~40s out.
        *LAST_DEADLINE.Lock() = deadline.Unix() as i64;
        return goish::errors::nil;
    }
}

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

fn get(client: &http::Client, url: goish::string) -> (goish::int, goish::string) {
    let (mut resp, err) = client.Do(&{
        let (r, _) = http::NewRequest(string("GET"), url, goish::nil);
        r
    });
    if !err.IsNil() {
        return (0, fmt::Sprintf!("err=%v", err));
    }
    let (b, _) = goish::io::ReadAll(&mut resp.Body);
    let _ = resp.Body.Close();
    (resp.StatusCode, goish::string::from_bytes(&b))
}

/// A named function whose PC the Symbol test resolves, and inside
/// which the profile stack is captured so debug=1 output must name it.
#[inline(never)]
fn capture_site(p: &Arc<rpprof::Profile>, value: usize) {
    p.Add(value, 0);
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() -> ! {
    goish::net::http::responsewriter::__goish_register_ResponseWriter_impl::<deadlineWriter>();
    goish::net::http::responsecontroller::__goish_register_WriteDeadliner_impl::<deadlineWriter>();

    // ── serveError ──
    {
        let w = httptest::NewRecorder();
        // The success path would have set this; the error path must
        // not leave it behind.
        http::ResponseWriter::Header(&w).Set(
            string("Content-Disposition"),
            string("attachment; filename=\"profile\""),
        );
        pprof::serveError(
            &w,
            400,
            string("profile duration exceeds server's WriteTimeout"),
        );
        let body = goish::string::from_bytes(&w.Body());
        check(
            "serveError writes the status, the marker header and a trailing newline",
            w.Code() == 400
                && w.HeaderMap().Get(string("X-Go-Pprof")) == "1"
                && w.HeaderMap().Get(string("Content-Type")) == "text/plain; charset=utf-8"
                && body == "profile duration exceeds server's WriteTimeout\n",
            fmt::Sprintf!("code=%d body=%q", w.Code(), body),
        );
        check(
            "serveError deletes Content-Disposition",
            w.HeaderMap().Get(string("Content-Disposition")).Len() == 0,
            w.HeaderMap().Get(string("Content-Disposition")),
        );
    }

    // ── Cmdline ──
    {
        let w = httptest::NewRecorder();
        let (r, _) = http::NewRequest(
            string("GET"),
            string("http://x/debug/pprof/cmdline"),
            goish::goslice::slice::new(),
        );
        pprof::Cmdline(&w, &r);
        let body = goish::string::from_bytes(&w.Body());
        let b: &str = body.as_ref();
        check(
            "Cmdline is nosniff text and carries argv[0]",
            w.HeaderMap().Get(string("X-Content-Type-Options")) == "nosniff"
                && w.HeaderMap().Get(string("Content-Type")) == "text/plain; charset=utf-8"
                && b.contains("http_pprof_smoke"),
            body.clone(),
        );
        check(
            "arguments are NUL-separated, never space-separated",
            !b.contains(' ') || b.contains('\u{0}'),
            body,
        );
    }

    // ── sleep returns early when the request is cancelled ──
    {
        let (r, _) = http::NewRequest(
            string("GET"),
            string("http://x/debug/pprof/profile"),
            goish::goslice::slice::new(),
        );
        let (ctx, cancel) = context::WithCancel(context::Background());
        let r = r.WithContext(ctx);
        goish::go!(stack(256 * 1024), move || {
            time::Sleep(time::Duration(120 * 1_000_000));
            cancel();
        });
        let start = time::Now();
        // Ask for 30 seconds; the cancel must cut it short.
        pprof::sleep(&r, time::Duration(30 * 1_000_000_000));
        let elapsed = time::Since(start);
        check(
            "sleep returns as soon as the request is cancelled",
            elapsed < time::Duration(5 * 1_000_000_000),
            fmt::Sprintf!("elapsed=%dms", elapsed.0 / 1_000_000),
        );
    }

    // ── sleep returns on its own deadline when nothing cancels ──
    {
        let (r, _) = http::NewRequest(
            string("GET"),
            string("http://x/debug/pprof/profile"),
            goish::goslice::slice::new(),
        );
        let start = time::Now();
        pprof::sleep(&r, time::Duration(150 * 1_000_000));
        let elapsed = time::Since(start);
        check(
            "sleep waits out its duration when nothing cancels",
            elapsed >= time::Duration(150 * 1_000_000)
                && elapsed < time::Duration(5 * 1_000_000_000),
            fmt::Sprintf!("elapsed=%dms", elapsed.0 / 1_000_000),
        );
    }

    // ── configureWriteDeadline needs the Server in the context ──
    //
    // `deadlineWriter` records what it is asked for, so all three
    // cases are observable: no Server, a Server with no WriteTimeout,
    // and a Server with one.
    {
        let w = deadlineWriter;
        let (r, _) = http::NewRequest(
            string("GET"),
            string("http://x/debug/pprof/profile"),
            goish::goslice::slice::new(),
        );

        DEADLINES.store(0, Ordering::Relaxed);
        pprof::configureWriteDeadline(&w, &r, 30.0);
        check(
            "no Server in the context: nothing is asked for",
            DEADLINES.load(Ordering::Relaxed) == 0,
            fmt::Sprintf!("calls=%d", DEADLINES.load(Ordering::Relaxed) as i64),
        );

        // Go guards on `srv.WriteTimeout > 0` — the zero value means
        // no write timeout at all, and extending a deadline that does
        // not exist would IMPOSE one.
        let no_timeout = Arc::new(http::Server::default());
        let r_nt = r.WithContext(context::WithValue(
            context::Background(),
            http::server::ServerContextKey,
            no_timeout,
        ));
        pprof::configureWriteDeadline(&w, &r_nt, 30.0);
        check(
            "a Server with no WriteTimeout is left alone",
            DEADLINES.load(Ordering::Relaxed) == 0,
            fmt::Sprintf!("calls=%d", DEADLINES.load(Ordering::Relaxed) as i64),
        );

        let srv = Arc::new(http::Server {
            WriteTimeout: time::Duration(10 * 1_000_000_000),
            ..Default::default()
        });
        let r2 = r.WithContext(context::WithValue(
            context::Background(),
            http::server::ServerContextKey,
            srv,
        ));
        let before = time::Now().Unix() as i64;
        pprof::configureWriteDeadline(&w, &r2, 30.0);
        let got = *LAST_DEADLINE.Lock();
        // Go: WriteTimeout + seconds, i.e. 10s + 30s from now.
        check(
            "the deadline becomes WriteTimeout + the profile duration",
            DEADLINES.load(Ordering::Relaxed) == 1 && got >= before + 39 && got <= before + 41,
            fmt::Sprintf!(
                "calls=%d delta=%d",
                DEADLINES.load(Ordering::Relaxed) as i64,
                got - before
            ),
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    // ── registry: a profile with two real stacks ──
    let prof = rpprof::NewProfile(string("goish_conns"));
    let v1: usize = 0x1001;
    let v2: usize = 0x1002;
    capture_site(&prof, v1);
    capture_site(&prof, v2);
    check(
        "registry Count sees both stacks",
        prof.Count() == 2 && rpprof::Lookup(string("goish_conns")).is_some(),
        fmt::Sprintf!("count=%d", prof.Count()),
    );

    // ── the HTTP surface ──
    let mux = http::ServeMux::new();
    mux.HandleFunc(string("/debug/pprof/"), |w, r| http::pprof::Index(w, r));
    mux.HandleFunc(string("/debug/pprof/symbol"), |w, r| {
        http::pprof::Symbol(w, r)
    });
    mux.HandleFunc(string("/debug/pprof/profile"), |w, r| {
        http::pprof::Profile(w, r)
    });
    mux.HandleFunc(string("/debug/pprof/trace"), |w, r| {
        http::pprof::Trace(w, r)
    });
    mux.HandleFunc(string("/debug/pprof/cmdline"), |w, r| {
        http::pprof::Cmdline(w, r)
    });
    let ts = http::httptest::NewServer(Arc::new(mux));
    let client = http::Client::default();
    let base = ts.URL();

    // 1. Handler?debug=1: Go text format + live-symbolized frame.
    {
        let (code, body) = get(
            &client,
            base.clone() + string("/debug/pprof/goish_conns?debug=1"),
        );
        let bv: &str = body.as_ref();
        check(
            "profile renders in Go's text format with a symbolized frame",
            code == 200
                && bv.contains("goish_conns profile: total 2")
                && bv.contains("@ 0x")
                && bv.contains("capture_site"),
            fmt::Sprintf!("code=%d body=%q", code, body.clone()),
        );
    }

    // 2. Index lists it (count included) + the package-local four.
    {
        let (code, body) = get(&client, base.clone() + string("/debug/pprof/"));
        let bv: &str = body.as_ref();
        check(
            "Index lists the registered profile and the built-in four",
            code == 200
                && bv.contains("goish_conns")
                && bv.contains("<td>2</td>")
                && bv.contains("cmdline")
                && bv.contains("symbol")
                && bv.contains("full goroutine stack dump"),
            fmt::Sprintf!("code=%d", code),
        );
    }

    // 3. Symbol resolves this binary's own PC.
    {
        // An in-function PC (entry+1): pprof clients send sampled PCs
        // from inside function bodies, and the symbolizer's pc-1
        // return-address convention expects that.
        let pc = capture_site as fn(&Arc<rpprof::Profile>, usize) as usize + 1;
        let (code, body) = get(
            &client,
            fmt::Sprintf!("%s/debug/pprof/symbol?0x%x", base, pc as u64),
        );
        let bv: &str = body.as_ref();
        check(
            "Symbol maps a live PC to its function name",
            code == 200 && bv.starts_with("num_symbols: 1") && bv.contains("capture_site"),
            fmt::Sprintf!("code=%d body=%q", code, body.clone()),
        );
    }

    // 4. Unknown profile → Go's 404.
    {
        let (code, body) = get(&client, base.clone() + string("/debug/pprof/nonesuch"));
        check(
            "unknown profile 404s with Go's message",
            code == 404 && (body.as_ref() as &str).contains("Unknown profile"),
            fmt::Sprintf!("code=%d body=%q", code, body),
        );
    }

    // 5. Profile / Trace: the honest unsupported arms.
    {
        let (code, body) = get(
            &client,
            base.clone() + string("/debug/pprof/profile?seconds=1"),
        );
        check(
            "CPU profile serves Go's could-not-enable arm",
            code == 500 && (body.as_ref() as &str).contains("Could not enable CPU profiling"),
            fmt::Sprintf!("code=%d body=%q", code, body),
        );
        let (code, body) = get(
            &client,
            base.clone() + string("/debug/pprof/trace?seconds=1"),
        );
        check(
            "trace serves Go's could-not-enable arm",
            code == 500 && (body.as_ref() as &str).contains("Could not enable tracing"),
            fmt::Sprintf!("code=%d body=%q", code, body),
        );
    }

    // 6. ?seconds= on a registry profile → Go's delta validation.
    {
        let (code, body) = get(
            &client,
            base.clone() + string("/debug/pprof/goish_conns?seconds=1"),
        );
        check(
            "delta on a non-builtin profile takes Go's 400 arm",
            code == 400 && (body.as_ref() as &str).contains("not supported for this profile type"),
            fmt::Sprintf!("code=%d body=%q", code, body),
        );
    }

    // 7. Remove drains it.
    {
        prof.Remove(v1);
        prof.Remove(v2);
        let (code, body) = get(
            &client,
            base.clone() + string("/debug/pprof/goish_conns?debug=1"),
        );
        check(
            "Remove empties the profile",
            code == 200 && (body.as_ref() as &str).contains("goish_conns profile: total 0"),
            fmt::Sprintf!("code=%d body=%q", code, body),
        );
    }

    // 8. Cmdline still serves (the original four's representative).
    {
        let (code, _body) = get(&client, base.clone() + string("/debug/pprof/cmdline"));
        check(
            "cmdline serves 200",
            code == 200,
            fmt::Sprintf!("code=%d", code),
        );
    }

    ts.Close();

    // ── init registers the five on the DefaultServeMux ──
    {
        http::pprof::pprof::init();
        let ts2 = httptest::NewServer(http::DefaultServeMux());
        let (code, _b) = get(&client, ts2.URL() + string("/debug/pprof/cmdline"));
        let (code2, body2) = get(&client, ts2.URL() + string("/debug/pprof/"));
        check(
            "init wires the handlers into the DefaultServeMux",
            code == 200 && code2 == 200 && (body2.as_ref() as &str).contains("goish_conns"),
            fmt::Sprintf!("cmdline=%d index=%d", code, code2),
        );
        ts2.Close();
    }

    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_PPROF_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_PPROF_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
