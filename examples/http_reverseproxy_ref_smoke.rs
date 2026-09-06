// http_reverseproxy_ref_smoke — httputil.ReverseProxy as a Handler,
// against Go 1.25.5.
//
// Until this landed, `ReverseProxy` had every hook Go has — Director,
// Rewrite, ModifyResponse, ErrorHandler, FlushInterval, BufferPool,
// ErrorLog — and NO ServeHTTP, so the compiler rejected mounting one:
//
//     the trait bound `ReverseProxy: net::http::Handler` is not satisfied
//
// The hooks were not unwired; the type could not be invoked at all
// (ROADMAP 2m). Its own doc called ServeHTTP "staged" because it
// "needs the streaming response copy, which needs Body as
// io.ReadCloser" — a reason that had gone stale, since the slim
// handler had been streaming through `Response.Body` as an io::Reader
// for some time.
//
// What each row is for:
//
//   director        the Director path appends the real peer to
//                   X-Forwarded-For, so the LAST entry is trustworthy
//                   whatever the client claimed. `secret=""` is the
//                   other half: the backend answers
//                   `Connection: X-Secret` alongside `X-Secret`, and
//                   RFC 7230 §6.1 says a Connection-named header is
//                   hop-by-hop and must not reach the client.
//   rewrite         the Rewrite path STRIPS client forwarding headers
//                   instead — `xff=""` where director has an address —
//                   which is the reason Go prefers it.
//   modifyresponse  the hook runs and its header reaches the client.
//   modify-error    a hook returning an error gives 502, not the
//                   backend's 200.
//   errorhandler    ErrorHandler overrides that 502 with its own code.
//   relays-3xx      the proxy RELAYS a 302 rather than following it.
//                   Go calls Transport.RoundTrip, which performs
//                   exactly one exchange; a proxy that followed would
//                   fetch a URL the backend chose.
//   both-set        Director and Rewrite both set is Go's documented
//                   error, not a silent precedence rule.
//
// `relays-3xx` also found a second, unrelated defect while this was
// being written: the body came back EMPTY because Client.do closed the
// hop's body before consulting CheckRedirect, so ErrUseLastResponse
// returned a response whose body had already gone. Both are fixed; the
// row would go red again if either regressed.
//
// FlushInterval is NOT exercised because it is not honoured — see the
// deviation note on the struct and ROADMAP 2m.
//
// Reference: tools/gen_reverseproxy_ref.go via scripts/goref.sh.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use goish::gostring::string;
use goish::io::{Closer, Writer};
use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::httputil::reverseproxy::{ProxyRequest, ReverseProxy};
use goish::net::http::{Handler, HandlerFunc, ResponseWriter};
use goish::{errors, fmt, go, strings};

fn s(x: &str) -> string { string::from_bytes(x.as_bytes()) }

const GO: [&str; 7] = [
    "director         code=200 backend=\"yes\" secret=\"\" mod=\"\" body=xff=\"127.0.0.1\" ua=\"\" up=\"\"",
    "rewrite          code=200 backend=\"yes\" secret=\"\" mod=\"\" body=xff=\"\" ua=\"\" up=\"1\"",
    "modifyresponse   code=200 backend=\"yes\" secret=\"\" mod=\"yes\" body=xff=\"127.0.0.1\" ua=\"\" up=\"\"",
    "modify-error     code=502 backend=\"\" secret=\"\" mod=\"\" body=",
    "errorhandler     code=418 backend=\"\" secret=\"\" mod=\"\" body=",
    "relays-3xx       code=302 backend=\"yes\" secret=\"\" mod=\"\" body=<a href=\"http://elsewhere.invalid/\">Found</a>.",
    "both-set         code=502 backend=\"\" secret=\"\" mod=\"\" body=",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    go!(stack(2 * 1024 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn run() {
    let back = httptest::NewServer(Arc::new(HandlerFunc(
        |w: &(dyn ResponseWriter + Send + Sync + 'static), r: &http::Request| {
            w.Header().Set(s("X-Backend"), s("yes"));
            w.Header().Set(s("Connection"), s("X-Secret"));
            w.Header().Set(s("X-Secret"), s("leak"));
            if r.URL.Path == s("/redir") {
                http::Redirect(w, r, s("http://elsewhere.invalid/"), 302);
                return;
            }
            let body = fmt::Sprintf!(
                "xff=%q ua=%q up=%q",
                r.Header.Get(s("X-Forwarded-For")),
                r.Header.Get(s("User-Agent")),
                r.Header.Get(s("X-Rewritten"))
            );
            let _ = w.Write(goish::convert::bytes(body));
        },
    )) as Arc<dyn Handler>);
    let (tgt, _) = http::url::Parse(back.URL());

    let ln = core::cell::Cell::new(0usize);
    let probe = |label: &str, rp: ReverseProxy, path: &str| {
        let front = httptest::NewServer(Arc::new(rp) as Arc<dyn Handler>);
        let mut c = http::Client::default();
        c.CheckRedirect = Some(Arc::new(|_r: &http::Request, _v: &[http::Request]| {
            http::ErrUseLastResponse.into()
        }));
        let (mut req, _) = http::NewRequest(s("GET"), front.URL() + s(path),
            goish::slice::<goish::byte>::new());
        req.Header.Set(s("User-Agent"), s(""));
        let (mut resp, err) = c.Do(&req);
        if !err.IsNil() {
            let mut n = ln.get();
            chk(&mut n, &fmt::Sprintf!("%-16s err=%v", s(label), err));
            ln.set(n);
        } else {
            let (bb, _) = goish::io::ReadAll(&mut resp.Body);
            let _ = goish::io::Closer::Close(&mut resp.Body);
            let body = string::from_bytes(bb.as_ref());
            let mut n = ln.get();
            chk(&mut n, &fmt::Sprintf!(
                "%-16s code=%d backend=%q secret=%q mod=%q body=%s",
                s(label), resp.StatusCode as i64,
                resp.Header.Get(s("X-Backend")), resp.Header.Get(s("X-Secret")),
                resp.Header.Get(s("X-Modified")),
                strings::TrimSpace(body)
            ));
            ln.set(n);
        }
        front.clone().Close();
    };

    let t1 = tgt.clone();
    probe("director", ReverseProxy {
        Director: Some(Arc::new(move |r: &mut http::Request| {
            r.URL.Scheme = t1.Scheme.clone();
            r.URL.Host = t1.Host.clone();
        })),
        ..Default::default()
    }, "/");

    let t2 = tgt.clone();
    probe("rewrite", ReverseProxy {
        Rewrite: Some(Arc::new(move |pr: &mut ProxyRequest| {
            pr.SetURL(&t2);
            pr.Out.Header.Set(s("X-Rewritten"), s("1"));
        })),
        ..Default::default()
    }, "/");

    let t3 = tgt.clone();
    probe("modifyresponse", ReverseProxy {
        Director: Some(Arc::new(move |r: &mut http::Request| {
            r.URL.Scheme = t3.Scheme.clone(); r.URL.Host = t3.Host.clone();
        })),
        ModifyResponse: Some(Arc::new(|res: &mut http::Response| {
            res.Header.Set(s("X-Modified"), s("yes"));
            errors::nil
        })),
        ..Default::default()
    }, "/");

    let t4 = tgt.clone();
    probe("modify-error", ReverseProxy {
        Director: Some(Arc::new(move |r: &mut http::Request| {
            r.URL.Scheme = t4.Scheme.clone(); r.URL.Host = t4.Host.clone();
        })),
        ModifyResponse: Some(Arc::new(|_res: &mut http::Response| {
            errors::New(s("nope"))
        })),
        ..Default::default()
    }, "/");

    let t5 = tgt.clone();
    probe("errorhandler", ReverseProxy {
        Director: Some(Arc::new(move |r: &mut http::Request| {
            r.URL.Scheme = t5.Scheme.clone(); r.URL.Host = t5.Host.clone();
        })),
        ModifyResponse: Some(Arc::new(|_res: &mut http::Response| errors::New(s("nope")))),
        ErrorHandler: Some(Arc::new(
            |w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &http::Request, _e: errors::error| {
                w.WriteHeader(418);
            },
        )),
        ..Default::default()
    }, "/");

    let t6 = tgt.clone();
    probe("relays-3xx", ReverseProxy {
        Director: Some(Arc::new(move |r: &mut http::Request| {
            r.URL.Scheme = t6.Scheme.clone(); r.URL.Host = t6.Host.clone();
        })),
        ..Default::default()
    }, "/redir");

    probe("both-set", ReverseProxy {
        Director: Some(Arc::new(|_r: &mut http::Request| {})),
        Rewrite: Some(Arc::new(|_pr: &mut ProxyRequest| {})),
        ..Default::default()
    }, "/");

    back.clone().Close();
    if ln.get() != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
    }
    goish::os::Exit(0);
}
