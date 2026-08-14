// http_proxyenv_smoke — ProxyFromEnvironment over the httpproxy port.
//
// Every expected value is a verbatim goref capture from Go 1.25.5
// (t.Setenv + resetProxyConfig between vectors, exactly what this
// test does). The discriminating cases:
//
//   * a bare "host:port" proxy value gets "http://" prepended;
//   * an https request uses HTTPS_PROXY and IGNORES HTTP_PROXY;
//   * NO_PROXY "target.com" matches the host AND its subdomains,
//     while ".target.com" matches ONLY subdomains — the leading-dot
//     asymmetry is the classic implementation mistake;
//   * "*" disables proxying entirely; CIDR entries match by network;
//   * localhost and loopback literals never proxy, even with no
//     NO_PROXY at all;
//   * "host:port" NO_PROXY entries match only that port;
//   * resetProxyConfig really resets — without it every vector after
//     the first would see the first vector's cached environment.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http;
use goish::os;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(label: &'static str, got: goish::string, want: &'static str) {
    if (got.as_ref() as &str) == want {
        fmt::Printf!("PASS: %s\n", label);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — got %q want %q\n", label, got, string(want));
    }
}

fn resolve(
    label: &'static str,
    http_proxy: &'static str,
    https_proxy: &'static str,
    no_proxy: &'static str,
    req_url: &'static str,
    want: &'static str,
) {
    let _ = os::Setenv("HTTP_PROXY", http_proxy);
    let _ = os::Setenv("HTTPS_PROXY", https_proxy);
    let _ = os::Setenv("NO_PROXY", no_proxy);
    let _ = os::Setenv("REQUEST_METHOD", "");
    http::transport::resetProxyConfig();
    let (req, _) = http::NewRequest(string("GET"), string(req_url), goish::nil);
    let resolver = http::ProxyFromEnvironment();
    let (u, err) = resolver(&req);
    let got = if !err.IsNil() {
        fmt::Sprintf!("err=%v", err)
    } else if u.Host.Len() == 0 && u.Scheme.Len() == 0 {
        string("<nil>")
    } else {
        u.String()
    };
    check(label, got, want);
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

fn run() -> ! {
    resolve("plain", "http://proxy.example:3128", "", "", "http://target.com/x",
            "http://proxy.example:3128");
    resolve("bare-host-proxy", "proxy.example:3128", "", "", "http://target.com/x",
            "http://proxy.example:3128");
    resolve("https-req-uses-https-proxy", "http://hp:1", "http://sp:2", "",
            "https://target.com/x", "http://sp:2");
    resolve("https-req-no-https-proxy", "http://hp:1", "", "", "https://target.com/x",
            "<nil>");
    resolve("noproxy-exact", "http://p:1", "", "target.com", "http://target.com/x",
            "<nil>");
    resolve("noproxy-subdomain", "http://p:1", "", "target.com",
            "http://sub.target.com/x", "<nil>");
    resolve("noproxy-dot-no-parent", "http://p:1", "", ".target.com",
            "http://target.com/x", "http://p:1");
    resolve("noproxy-dot-subdomain", "http://p:1", "", ".target.com",
            "http://sub.target.com/x", "<nil>");
    resolve("noproxy-star", "http://p:1", "", "*", "http://target.com/x", "<nil>");
    resolve("noproxy-cidr", "http://p:1", "", "10.0.0.0/8", "http://10.1.2.3/x",
            "<nil>");
    resolve("noproxy-ip-other", "http://p:1", "", "10.0.0.0/8", "http://11.1.2.3/x",
            "http://p:1");
    resolve("localhost", "http://p:1", "", "", "http://localhost:8080/x", "<nil>");
    resolve("loopback", "http://p:1", "", "", "http://127.0.0.1:9/x", "<nil>");
    resolve("noproxy-port-match", "http://p:1", "", "target.com:80",
            "http://target.com/x", "<nil>");
    resolve("noproxy-port-miss", "http://p:1", "", "target.com:81",
            "http://target.com/x", "http://p:1");

    // The cache is real: WITHOUT reset, a changed environment must
    // NOT be observed (this is what envProxyOnce means).
    let _ = os::Setenv("HTTP_PROXY", "http://p:1");
    let _ = os::Setenv("NO_PROXY", "");
    http::transport::resetProxyConfig();
    let (req, _) = http::NewRequest(string("GET"), string("http://target.com/x"), goish::nil);
    let r1 = http::ProxyFromEnvironment();
    let (u1, _) = r1(&req);
    let _ = os::Setenv("HTTP_PROXY", "http://changed:2");
    let r2 = http::ProxyFromEnvironment();
    let (u2, _) = r2(&req);
    check(
        "environment is read once and cached",
        fmt::Sprintf!("%s/%s", u1.String(), u2.String()),
        "http://p:1/http://p:1",
    );

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("HTTP_PROXYENV_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_PROXYENV_FAIL (%d)\n", f as i64);
    goish::os::Exit(1);
}
