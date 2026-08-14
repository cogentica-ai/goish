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
use goish::net::http::httputil::reverseproxy::ProxyRequest;
use goish::net::http::{NewRequest, ParseURL};
use goish::{slice, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok { PASSED.fetch_add(1, Ordering::Relaxed); fmt::Printf!("PASS: %s\n", name); }
    else { FAILED.fetch_add(1, Ordering::Relaxed); fmt::Printf!("FAIL: %s — %s\n", name, detail); }
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn run() {
    let mk = |remote: &'static str, xff: &[&'static str]| {
        let (r, _) = NewRequest(string("GET"), string("http://in.example/p"), slice::new());
        let mut inr = r.clone();
        inr.RemoteAddr = string(remote);
        inr.Host = string("front.example");
        let mut out = inr.clone();
        for v in xff { out.Header.Add(string("X-Forwarded-For"), string(*v)); }
        (inr, out)
    };

    // X-Forwarded-For appends to the OUTBOUND chain.
    {
        let cases: &[(&'static str, &[&'static str], &'static str)] = &[
            ("1.2.3.4:5678", &[], "1.2.3.4"),
            ("1.2.3.4:5678", &["9.9.9.9"], "9.9.9.9, 1.2.3.4"),
            ("1.2.3.4:5678", &["9.9.9.9", "8.8.8.8"], "9.9.9.9, 8.8.8.8, 1.2.3.4"),
            // Unsplittable RemoteAddr: the header is DELETED, not kept.
            ("no-port", &["9.9.9.9"], ""),
        ];
        let mut bad = string("");
        for (remote, xff, want) in cases {
            let (inr, mut out) = mk(remote, xff);
            {
                let mut pr = ProxyRequest { In: &inr, Out: &mut out };
                pr.SetXForwarded();
            }
            let got = out.Header.Get(string("X-Forwarded-For"));
            if got != *want {
                bad = fmt::Sprintf!("%s -> %q want %q", string(*remote), got, string(*want));
            }
        }
        check("SetXForwarded appends to the outbound chain, and deletes on a bad RemoteAddr",
              bad.Len() == 0, bad);
    }
    // Host and Proto.
    {
        let (inr, mut out) = mk("1.2.3.4:5678", &[]);
        {
            let mut pr = ProxyRequest { In: &inr, Out: &mut out };
            pr.SetXForwarded();
        }
        check("X-Forwarded-Host is the client's Host, Proto is http without TLS",
              out.Header.Get(string("X-Forwarded-Host")) == "front.example"
                  && out.Header.Get(string("X-Forwarded-Proto")) == "http",
              out.Header.Get(string("X-Forwarded-Proto")));
    }
    // SetURL rewrites the path onto the target AND clears Host.
    {
        let (inr, mut out) = mk("1.2.3.4:5678", &[]);
        out.Host = string("front.example");
        let (target, _) = ParseURL(string("http://backend.internal/base"));
        {
            let mut pr = ProxyRequest { In: &inr, Out: &mut out };
            pr.SetURL(&target);
        }
        check("SetURL joins the paths and CLEARS Out.Host",
              out.URL.String() == "http://backend.internal/base/p" && out.Host.Len() == 0,
              fmt::Sprintf!("URL=%q Host=%q", out.URL.String(), out.Host.clone()));
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 { fmt::Printf!("HTTP_PROXYREQUEST_SMOKE_OK\n"); goish::os::Exit(0); }
    fmt::Printf!("HTTP_PROXYREQUEST_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
