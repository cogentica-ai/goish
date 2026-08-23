// http_proxyrequest_smoke — httputil.ProxyRequest's two rewrite
// helpers. Values from scripts/goref.sh against the real package.
//
// Both have a half that is easy to drop and dangerous to drop:
// SetURL CLEARS Out.Host (or the backend sees the client's Host), and
// SetXForwarded DELETES X-Forwarded-For when RemoteAddr cannot be
// split (or a stale value is forwarded as if observed).

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::httputil::reverseproxy::{ProxyRequest, ReverseProxy};
use goish::net::http::{NewRequest, ParseURL};
use goish::{slice, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let mk = |remote: &'static str, xff: &[&'static str]| {
        let (r, _) = NewRequest(string("GET"), string("http://in.example/p"), slice::new());
        let mut inr = r.clone();
        inr.RemoteAddr = string(remote);
        inr.Host = string("front.example");
        let mut out = inr.clone();
        for v in xff {
            out.Header.Add(string("X-Forwarded-For"), string(*v));
        }
        (inr, out)
    };

    // X-Forwarded-For appends to the OUTBOUND chain.
    {
        let cases: &[(&'static str, &[&'static str], &'static str)] = &[
            ("1.2.3.4:5678", &[], "1.2.3.4"),
            ("1.2.3.4:5678", &["9.9.9.9"], "9.9.9.9, 1.2.3.4"),
            (
                "1.2.3.4:5678",
                &["9.9.9.9", "8.8.8.8"],
                "9.9.9.9, 8.8.8.8, 1.2.3.4",
            ),
            // Unsplittable RemoteAddr: the header is DELETED, not kept.
            ("no-port", &["9.9.9.9"], ""),
        ];
        let mut bad = string("");
        for (remote, xff, want) in cases {
            let (inr, mut out) = mk(remote, xff);
            {
                let mut pr = ProxyRequest {
                    In: &inr,
                    Out: &mut out,
                };
                pr.SetXForwarded();
            }
            let got = out.Header.Get(string("X-Forwarded-For"));
            if got != *want {
                bad = fmt::Sprintf!("%s -> %q want %q", string(*remote), got, string(*want));
            }
        }
        check(
            "SetXForwarded appends to the outbound chain, and deletes on a bad RemoteAddr",
            bad.Len() == 0,
            bad,
        );
    }
    // Host and Proto.
    {
        let (inr, mut out) = mk("1.2.3.4:5678", &[]);
        {
            let mut pr = ProxyRequest {
                In: &inr,
                Out: &mut out,
            };
            pr.SetXForwarded();
        }
        check(
            "X-Forwarded-Host is the client's Host, Proto is http without TLS",
            out.Header.Get(string("X-Forwarded-Host")) == "front.example"
                && out.Header.Get(string("X-Forwarded-Proto")) == "http",
            out.Header.Get(string("X-Forwarded-Proto")),
        );
    }
    // SetURL rewrites the path onto the target AND clears Host.
    {
        let (inr, mut out) = mk("1.2.3.4:5678", &[]);
        out.Host = string("front.example");
        let (target, _) = ParseURL(string("http://backend.internal/base"));
        {
            let mut pr = ProxyRequest {
                In: &inr,
                Out: &mut out,
            };
            pr.SetURL(&target);
        }
        check(
            "SetURL joins the paths and CLEARS Out.Host",
            out.URL.String() == "http://backend.internal/base/p" && out.Host.Len() == 0,
            fmt::Sprintf!("URL=%q Host=%q", out.URL.String(), out.Host.clone()),
        );
    }

    // ── ReverseProxy.flushInterval ──
    // Two cases force immediate flushing regardless of the configured
    // interval, and both are streams that never end.
    {
        let rp = ReverseProxy {
            FlushInterval: goish::time::Duration(250 * 1_000_000),
            ..Default::default()
        };
        let mut sse = goish::net::http::Response::default();
        sse.Header
            .Set(string("Content-Type"), string("text/event-stream"));
        sse.ContentLength = 100;
        let mut unknown = goish::net::http::Response::default();
        unknown
            .Header
            .Set(string("Content-Type"), string("text/plain"));
        unknown.ContentLength = -1;
        let mut plain = goish::net::http::Response::default();
        plain
            .Header
            .Set(string("Content-Type"), string("text/plain; charset=utf-8"));
        plain.ContentLength = 100;
        check(
            "flushInterval: SSE and unknown-length flush immediately, others use the setting",
            rp.flushInterval(&sse) == goish::time::Duration(-1)
                && rp.flushInterval(&unknown) == goish::time::Duration(-1)
                && rp.flushInterval(&plain) == goish::time::Duration(250 * 1_000_000),
            fmt::Sprintf!(
                "sse=%d unknown=%d plain=%d",
                rp.flushInterval(&sse).Nanoseconds(),
                rp.flushInterval(&unknown).Nanoseconds(),
                rp.flushInterval(&plain).Nanoseconds()
            ),
        );
        // The media-type parse must ignore parameters: SSE with a
        // charset is still SSE.
        let mut sse2 = goish::net::http::Response::default();
        sse2.Header.Set(
            string("Content-Type"),
            string("text/event-stream; charset=utf-8"),
        );
        sse2.ContentLength = 100;
        check(
            "and a charset parameter does not hide text/event-stream",
            rp.flushInterval(&sse2) == goish::time::Duration(-1),
            string(""),
        );
    }

    // ── modifyResponse / getErrorHandler ──
    {
        use core::sync::atomic::AtomicUsize as AU;
        static CLOSED_OK: AU = AU::new(0);
        // No hook: proxying continues untouched.
        let plain = ReverseProxy::default();
        let mut res = goish::net::http::Response::default();
        let (req, _) =
            goish::net::http::NewRequest(string("GET"), string("http://x/"), slice::new());
        let w = goish::net::http::httptest::NewRecorder();
        check(
            "modifyResponse with no hook continues",
            plain.modifyResponse(&w, &mut res, &req),
            string(""),
        );

        // A hook that succeeds also continues, and can mutate.
        let ok_rp = ReverseProxy {
            ModifyResponse: Some(alloc::sync::Arc::new(
                |r: &mut goish::net::http::Response| {
                    r.Header.Set(string("X-Touched"), string("1"));
                    goish::errors::nil
                },
            )),
            ..Default::default()
        };
        let mut res2 = goish::net::http::Response::default();
        let cont = ok_rp.modifyResponse(&w, &mut res2, &req);
        check(
            "a successful hook continues and its mutation sticks",
            cont && res2.Header.Get(string("X-Touched")) == "1",
            string(""),
        );

        // A failing hook STOPS proxying and routes to the error
        // handler — which must be the custom one when set.
        let fail_rp = ReverseProxy {
            ModifyResponse: Some(alloc::sync::Arc::new(
                |_r: &mut goish::net::http::Response| goish::errors::New(string("nope")),
            )),
            ErrorHandler: Some(alloc::sync::Arc::new(
                |_w: &(dyn goish::net::http::ResponseWriter + Send + Sync + 'static),
                 _r: &goish::net::http::Request,
                 _e: goish::error| {
                    CLOSED_OK.fetch_add(1, Ordering::Relaxed);
                },
            )),
            ..Default::default()
        };
        // The body is PIPE-backed, like a real backend conn: Close
        // must reach the underlying stream. (An in-memory body's
        // Close is a NopCloser no-op — Go's shape — so it could not
        // witness the close.)
        let (pr3, mut pw3) = goish::io::Pipe();
        goish::go!(stack(256 * 1024), move || {
            let _ = pw3.Write(goish::bytes("payload"));
        });
        let mut res3 = goish::net::http::Response {
            Body: goish::net::http::Body::from_reader(alloc::boxed::Box::new(pr3)),
            ..Default::default()
        };
        let cont3 = fail_rp.modifyResponse(&w, &mut res3, &req);
        check(
            "a failing hook stops proxying and calls the CUSTOM error handler",
            !cont3 && CLOSED_OK.load(Ordering::Relaxed) == 1,
            fmt::Sprintf!(
                "cont=%v calls=%d",
                cont3,
                CLOSED_OK.load(Ordering::Relaxed) as i64
            ),
        );

        // Go closes the body BEFORE the error handler runs; the
        // backend conn is finished with either way. A body left open
        // here leaks one conn per rejected response, so read it back:
        // the closed pipe reports so rather than returning bytes.
        let mut sink = goish::make!([]goish::byte, 16);
        let (n3, e3) = goish::io::Reader::Read(&mut res3.Body, &mut sink);
        check(
            "the rejected response's Body is closed, not leaked",
            n3 == 0 && !e3.IsNil(),
            fmt::Sprintf!("n=%d err=%v", n3 as i64, e3),
        );

        // With no ErrorHandler set, getErrorHandler reports none and
        // handleError falls back to the 502 default.
        let w2 = goish::net::http::httptest::NewRecorder();
        let mut res4 = goish::net::http::Response::default();
        let fail_default = ReverseProxy {
            ModifyResponse: Some(alloc::sync::Arc::new(
                |_r: &mut goish::net::http::Response| goish::errors::New(string("nope")),
            )),
            ..Default::default()
        };
        let _ = fail_default.modifyResponse(&w2, &mut res4, &req);
        check(
            "with no ErrorHandler the default answers 502",
            fail_default.getErrorHandler().is_none() && w2.Code() == 502,
            fmt::Sprintf!("code=%d", w2.Code()),
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_PROXYREQUEST_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_PROXYREQUEST_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
