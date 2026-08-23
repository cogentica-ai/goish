// http_connectmethod_smoke — net/http/transport.go's pool key.
//
// The connection-pool key decides which requests may share a socket.
// Getting it wrong either shares a socket that must not be shared
// (an https/CONNECT tunnel) or refuses to share one that should be.
// Every expectation is Go 1.25.5's, via scripts/goref.sh.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::transport::{canonicalAddr, connectMethod, schemePort};
use goish::net::http::ParseURL;
use goish::string;

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
    // ── schemePort ──
    {
        let cases: &[(&str, &str)] = &[
            ("http", "80"),
            ("https", "443"),
            ("socks5", "1080"),
            ("socks5h", "1080"),
            ("ftp", ""),
            ("", ""),
        ];
        let mut bad = string("");
        for (s, want) in cases {
            let got = schemePort(string(*s));
            if got != *want {
                bad = fmt::Sprintf!("%s -> %q", string(*s), got);
            }
        }
        check("schemePort over 6 schemes", bad.Len() == 0, bad);
    }

    // ── canonicalAddr ── note ftp yields a trailing colon, as in Go
    {
        let cases: &[(&str, &str)] = &[
            ("http://foo.com/x", "foo.com:80"),
            ("https://foo.com/x", "foo.com:443"),
            ("http://foo.com:8080/x", "foo.com:8080"),
            ("socks5://p.com/", "p.com:1080"),
            ("ftp://foo.com/", "foo.com:"),
        ];
        let mut bad = string("");
        for (u, want) in cases {
            let (url, _) = ParseURL(string(*u));
            let got = canonicalAddr(&url);
            if got != *want {
                bad = fmt::Sprintf!("%s -> %q want %q", string(*u), got, string(*want));
            }
        }
        check("canonicalAddr over 5 URLs", bad.Len() == 0, bad);
    }

    // ── connectMethod.key ── (proxy, targetScheme, targetAddr, onlyH1, key)
    {
        let cases: &[(&str, &str, &str, bool, &str)] = &[
            ("", "http", "foo.com:80", false, "|http|foo.com:80"),
            ("", "https", "foo.com:443", false, "|https|foo.com:443"),
            ("", "https", "foo.com:443", true, "|https,h1|foo.com:443"),
            (
                "http://proxy.com",
                "https",
                "foo.com:443",
                false,
                "http://proxy.com|https|foo.com:443",
            ),
            // THE case: http proxy + http target drops the destination,
            // because one socket serves every destination.
            (
                "http://proxy.com",
                "http",
                "foo.com:80",
                false,
                "http://proxy.com|http|",
            ),
            (
                "https://proxy.com",
                "http",
                "foo.com:80",
                false,
                "https://proxy.com|http|",
            ),
            // socks5 does NOT drop it — the proxy dials the target.
            (
                "socks5://proxy.com",
                "http",
                "foo.com:80",
                false,
                "socks5://proxy.com|http|foo.com:80",
            ),
            (
                "socks5://proxy.com",
                "https",
                "foo.com:443",
                false,
                "socks5://proxy.com|https|foo.com:443",
            ),
        ];
        let mut bad = string("");
        for (proxy, target, addr, h1, want) in cases {
            let mut cm = connectMethod {
                proxyURL: None,
                targetScheme: string(*target),
                targetAddr: string(*addr),
                onlyH1: *h1,
            };
            if !proxy.is_empty() {
                let (pu, _) = ParseURL(string(*proxy));
                cm.proxyURL = Some(Arc::new(pu));
            }
            let got = cm.key().String();
            if got != *want {
                bad = fmt::Sprintf!("%q -> %q want %q", string(*proxy), got, string(*want));
            }
        }
        check("connectMethod.key over 8 shapes", bad.Len() == 0, bad);
    }

    // ── scheme / addr / tlsHost ──
    {
        let (pu, _) = ParseURL(string("socks5://proxy.com"));
        let cm = connectMethod {
            proxyURL: Some(Arc::new(pu)),
            targetScheme: string("https"),
            targetAddr: string("foo.com:443"),
            onlyH1: false,
        };
        check(
            "first-hop scheme/addr come from the proxy, tlsHost from the target",
            cm.scheme() == "socks5" && cm.addr() == "proxy.com:1080" && cm.tlsHost() == "foo.com",
            fmt::Sprintf!("%q %q %q", cm.scheme(), cm.addr(), cm.tlsHost()),
        );
        let direct = connectMethod {
            proxyURL: None,
            targetScheme: string("http"),
            targetAddr: string("foo.com:80"),
            onlyH1: false,
        };
        check(
            "with no proxy the first hop IS the target",
            direct.scheme() == "http" && direct.addr() == "foo.com:80",
            string(""),
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_CONNECTMETHOD_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_CONNECTMETHOD_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
