// httpproxy_ref_smoke — NO_PROXY matching, against a running Go 1.25.5.
//
// `net/http/httpproxy` is 465 lines that no example touched. It decides
// whether every outbound request in a goish program goes through a
// proxy, and its rules are the kind that look obvious and are not:
//
//   NO_PROXY=x.com     bypasses x.com AND sub.x.com
//   NO_PROXY=.x.com    bypasses sub.x.com but PROXIES x.com
//   NO_PROXY=x.com:80  bypasses only that port; x.com on 9090 is proxied
//   NO_PROXY=*         bypasses everything
//   localhost, 127.0.0.1 and [::1] are always direct, proxy or not
//
// Getting the leading-dot rule backwards sends internal traffic through
// a proxy, or company traffic around one, and nothing errors either
// way. All 32 lines matched Go on the first run; this pins them.
//
// Both sides go through the ENVIRONMENT rather than a Config literal,
// so `FromEnvironment`'s mapping of HTTP_PROXY / HTTPS_PROXY /
// NO_PROXY is measured too, not assumed. Checked against a
// Config-literal reference as well: same 32 lines.
//
// goish's resolver returns the EMPTY url where Go returns nil, which
// is why "direct" is spelled as an empty String() here rather than a
// None — a documented divergence in `ProxyFromEnvironment`, not a
// difference in the matching.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string;
use goish::net::http;
use goish::net::url;
use goish::os;
use goish::types::int;

const CASES: [(&str, &str, &str, &str, &[&str]); 15] = [
    ("plain", "http://p:8080", "", "", &["http://x.com/a", "https://x.com/a"]),
    ("https-only", "", "http://s:8443", "", &["http://x.com", "https://x.com"]),
    ("noproxy-exact", "http://p:8080", "", "x.com", &["http://x.com", "http://y.com", "http://sub.x.com"]),
    ("noproxy-dot", "http://p:8080", "", ".x.com", &["http://x.com", "http://sub.x.com", "http://xx.com"]),
    ("noproxy-star", "http://p:8080", "", "*", &["http://x.com", "https://y.com"]),
    ("noproxy-list", "http://p:8080", "", "a.com, b.com", &["http://a.com", "http://b.com", "http://c.com"]),
    ("noproxy-port", "http://p:8080", "", "x.com:8080", &["http://x.com:8080", "http://x.com:9090", "http://x.com"]),
    ("noproxy-cidr", "http://p:8080", "", "10.0.0.0/8", &["http://10.1.2.3", "http://11.1.2.3"]),
    ("noproxy-ip", "http://p:8080", "", "1.2.3.4", &["http://1.2.3.4", "http://1.2.3.5"]),
    ("noproxy-v6", "http://p:8080", "", "[::1]", &["http://[::1]:80", "http://[::2]:80"]),
    ("localhost", "http://p:8080", "", "", &["http://localhost/a", "http://127.0.0.1/a", "http://[::1]/a", "http://127.0.0.1:8080/"]),
    ("noproxy-space", "http://p:8080", "", " x.com ", &["http://x.com"]),
    ("noproxy-upper", "http://p:8080", "", "X.COM", &["http://x.com"]),
    ("scheme-relative", "http://p:8080", "", "", &["//x.com/a"]),
    ("bad-scheme", "http://p:8080", "", "", &["ftp://x.com/a"]),
];

const GO: [&str; 32] = [
    "plain            http://x.com/a             http://p:8080",
    "plain            https://x.com/a            direct",
    "https-only       http://x.com               direct",
    "https-only       https://x.com              http://s:8443",
    "noproxy-exact    http://x.com               direct",
    "noproxy-exact    http://y.com               http://p:8080",
    "noproxy-exact    http://sub.x.com           direct",
    "noproxy-dot      http://x.com               http://p:8080",
    "noproxy-dot      http://sub.x.com           direct",
    "noproxy-dot      http://xx.com              http://p:8080",
    "noproxy-star     http://x.com               direct",
    "noproxy-star     https://y.com              direct",
    "noproxy-list     http://a.com               direct",
    "noproxy-list     http://b.com               direct",
    "noproxy-list     http://c.com               http://p:8080",
    "noproxy-port     http://x.com:8080          direct",
    "noproxy-port     http://x.com:9090          http://p:8080",
    "noproxy-port     http://x.com               http://p:8080",
    "noproxy-cidr     http://10.1.2.3            direct",
    "noproxy-cidr     http://11.1.2.3            http://p:8080",
    "noproxy-ip       http://1.2.3.4             direct",
    "noproxy-ip       http://1.2.3.5             http://p:8080",
    "noproxy-v6       http://[::1]:80            direct",
    "noproxy-v6       http://[::2]:80            http://p:8080",
    "localhost        http://localhost/a         direct",
    "localhost        http://127.0.0.1/a         direct",
    "localhost        http://[::1]/a             direct",
    "localhost        http://127.0.0.1:8080/     direct",
    "noproxy-space    http://x.com               direct",
    "noproxy-upper    http://x.com               direct",
    "scheme-relative  //x.com/a                  direct",
    "bad-scheme       ftp://x.com/a              direct",
];

static mut BAD: usize = 0;

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        unsafe { BAD += 1 };
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        unsafe { BAD += 1 };
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    for (name, http_p, https_p, no_p, urls) in CASES.iter() {
        let _ = os::Setenv("HTTP_PROXY", *http_p);
        let _ = os::Setenv("HTTPS_PROXY", *https_p);
        let _ = os::Setenv("NO_PROXY", *no_p);
        let _ = os::Unsetenv("REQUEST_METHOD");
        http::transport::resetProxyConfig();
        let f = http::ProxyFromEnvironment();

        for raw in urls.iter() {
            let (u, err) = url::Parse(*raw);
            if !err.IsNil() {
                chk(&mut ln, &fmt::Sprintf!("%-16s %-26s PARSE-ERR", *name, *raw));
                continue;
            }
            let (req, err) = http::NewRequest("GET", *raw, goish::nil);
            if !err.IsNil() {
                chk(&mut ln, &fmt::Sprintf!("%-16s %-26s REQ-ERR %v", *name, *raw, err));
                continue;
            }
            let mut req = req;
            req.URL = u;
            let (p, err) = f(&req);
            if !err.IsNil() {
                chk(&mut ln, &fmt::Sprintf!("%-16s %-26s err=%v", *name, *raw, err));
            } else if p.String() == "" {
                chk(&mut ln, &fmt::Sprintf!("%-16s %-26s direct", *name, *raw));
            } else {
                chk(&mut ln, &fmt::Sprintf!("%-16s %-26s %s", *name, *raw, p.String()));
            }
        }
    }
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        unsafe { BAD += 1 };
    }
    let bad = unsafe { BAD };
    if bad != 0 {
        // e2e_runner.sh: "rc=0 wins regardless of stdout content",
        // so printing the mismatch is not enough to fail CI.
        fmt::Printf!("[!!] %d row(s) diverge from Go\n", bad as i64);
        goish::os::Exit(1);
    }
}
