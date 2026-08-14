// go: file vendor/golang.org/x/net/http/httpproxy/proxy.go decls: FromEnvironment, getEnvAny, Config.ProxyFunc, config.proxyForURL, parseProxy, config.useProxy, config.init, portMap, canonicalAddr, hasPort, idnaASCII, isASCII, allMatch.match, cidrMatch.match, ipMatch.match, domainMatch.match
// vendor/golang.org/x/net/http/httpproxy — proxy determination from
// HTTP_PROXY / HTTPS_PROXY / NO_PROXY, exactly as net/http's
// ProxyFromEnvironment consumes it. Ported from the copy Go vendors
// into GOROOT (src/vendor/...), which is the code net/http actually
// links.
//
// Adaptations, each stated at its site:
//   * Go's `*url.URL` returns are `Option<URL>` (nil pointer ⇔ None).
//   * `netip.ParseAddr` is replaced by `net::ParseIP` (goish has no
//     netip); the loopback test is the same predicate.
//   * `matcher` is a #[goish::interface]-free plain trait with three
//     impls held as `MatcherKind` enum entries — goish needs the
//     closed set spelled somewhere, and a Box<dyn> per NO_PROXY entry
//     buys nothing here.

// goishlint:ignore GOISH019 — one finding, on `config`: Go EMBEDS
// Config anonymously and the parser records no name for an embedded
// field, so goish's necessarily-named `Config` field reads as an
// addition (the onceCloseListener situation; this rule has no
// line-scoped form). The other four structs in this file pass the
// field check and stay covered by review, not by the rule.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::string;
use crate::strings;

use super::super::url::URL;

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:28-62 Config
/// Go: "Config holds configuration for HTTP proxy settings. See
/// FromEnvironment for details."
#[derive(Clone, Default)]
pub struct Config {
    /// Go: "the value of the HTTP_PROXY or http_proxy environment
    /// variable … used as the proxy URL for HTTP requests unless
    /// overridden by NoProxy."
    pub HTTPProxy: string,
    /// Go: "the HTTPS_PROXY or https_proxy environment variable …
    /// used as the proxy URL for HTTPS requests unless overridden by
    /// NoProxy."
    pub HTTPSProxy: string,
    /// Go: "comma-separated values specifying hosts that should be
    /// excluded from proxying" — IP, CIDR, domain (leading '.' for
    /// subdomains-only), optional :port, or `*` for everything.
    pub NoProxy: string,
    /// Go: "whether the current process is running as a CGI handler …
    /// When this is set, ProxyForURL will return an error when
    /// HTTPProxy applies, because a client could be setting
    /// HTTP_PROXY maliciously. See https://golang.org/s/cgihttpproxy."
    pub CGI: bool,
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:64-88 config
/// Go: "config holds the parsed configuration for HTTP proxy
/// settings" — the Config plus its preprocessed matchers.
struct config {
    Config: Config,
    /// Parsed HTTPSProxy, if any (Go: `httpsProxy *url.URL`).
    httpsProxy: Option<URL>,
    /// Parsed HTTPProxy, if any.
    httpProxy: Option<URL>,
    /// NO_PROXY entries that match by IP (prefix or CIDR).
    ipMatchers: Vec<MatcherKind>,
    /// NO_PROXY entries that match by domain name.
    domainMatchers: Vec<MatcherKind>,
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:90-97 FromEnvironment
/// Go: "returns a Config instance populated from the environment
/// variables HTTP_PROXY, HTTPS_PROXY and NO_PROXY (or the lowercase
/// versions thereof)."
pub fn FromEnvironment() -> Config {
    return Config {
        HTTPProxy: getEnvAny(&["HTTP_PROXY", "http_proxy"]),
        HTTPSProxy: getEnvAny(&["HTTPS_PROXY", "https_proxy"]),
        NoProxy: getEnvAny(&["NO_PROXY", "no_proxy"]),
        CGI: crate::os::Getenv("REQUEST_METHOD") != "",
    };
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:99-106 getEnvAny
fn getEnvAny(names: &[&str]) -> string {
    for n in names {
        let val = crate::os::Getenv(*n);
        if val != "" {
            return val;
        }
    }
    return string::new();
}

impl Config {
    // go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:118-125 Config.ProxyFunc
    // goishlint:ignore GOISH006 ProxyFunc — Go returns a closure; the
    // Arc<dyn Fn> is that closure's only spellable Rust carrier.
    /// Go: "returns a function that determines the proxy URL to use
    /// for a given request URL. Changing the contents of cfg will not
    /// affect proxy functions created earlier." A None URL with nil
    /// error means "no proxy" — including the localhost/loopback
    /// special case.
    pub fn ProxyFunc(
        &self,
    ) -> alloc::sync::Arc<dyn Fn(&URL) -> (Option<URL>, error) + Send + Sync> {
        // Go: preprocess the Config for more efficient evaluation.
        let mut cfg1 = config {
            Config: self.clone(),
            httpsProxy: None,
            httpProxy: None,
            ipMatchers: Vec::new(),
            domainMatchers: Vec::new(),
        };
        cfg1.init();
        return alloc::sync::Arc::new(move |req_url: &URL| cfg1.proxyForURL(req_url));
    }
}

impl config {
    // go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:127-145 config.proxyForURL
    fn proxyForURL(&self, reqURL: &URL) -> (Option<URL>, error) {
        let mut proxy: Option<&URL> = None;
        if reqURL.Scheme == "https" {
            proxy = self.httpsProxy.as_ref();
        } else if reqURL.Scheme == "http" {
            proxy = self.httpProxy.as_ref();
            if proxy.is_some() && self.Config.CGI {
                return (
                    None,
                    errors::New(string(
                        "refusing to use HTTP_PROXY value in CGI environment; see golang.org/s/cgihttpproxy",
                    )),
                );
            }
        }
        let proxy = match proxy {
            Some(p) => p,
            None => return (None, errors::nil),
        };
        if !self.useProxy(canonicalAddr(reqURL)) {
            return (None, errors::nil);
        }
        return (Some(proxy.clone()), errors::nil);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:170-205 config.useProxy
    /// Go: "reports whether requests to addr should use a proxy,
    /// according to the NO_PROXY or no_proxy environment variable.
    /// addr is always a canonicalAddr with a host and port."
    fn useProxy(&self, addr: string) -> bool {
        if addr.Len() == 0 {
            return true;
        }
        let (host, port, err) = crate::net::SplitHostPort(addr);
        if !err.IsNil() {
            return false;
        }
        if host == "localhost" {
            return false;
        }
        // Go parses via netip.ParseAddr then converts; goish's
        // ParseIP returns a nil (empty) IP on failure — the same
        // comma-ok, spelled by length.
        let ip = crate::net::ParseIP(host.clone());
        let has_ip = !ip.IsNil();
        if has_ip && ip.IsLoopback() {
            return false;
        }

        let addr = strings::ToLower(strings::TrimSpace(host));

        if has_ip {
            for m in &self.ipMatchers {
                if m.r#match(&addr, &port, Some(&ip)) {
                    return false;
                }
            }
        }
        for m in &self.domainMatchers {
            if m.r#match(&addr, &port, if has_ip { Some(&ip) } else { None }) {
                return false;
            }
        }
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:207-274 config.init
    fn init(&mut self) {
        let (parsed, perr) = parseProxy(self.Config.HTTPProxy.clone());
        if perr.IsNil() {
            self.httpProxy = parsed;
        }
        let (parsed, perr) = parseProxy(self.Config.HTTPSProxy.clone());
        if perr.IsNil() {
            self.httpsProxy = parsed;
        }

        let parts = strings::Split(self.Config.NoProxy.clone(), string(","));
        for pi in 0..parts.Len() {
            let p = strings::ToLower(strings::TrimSpace(parts[pi].clone()));
            if p.Len() == 0 {
                continue;
            }
            if p == "*" {
                self.ipMatchers = alloc::vec![MatcherKind::All(allMatch)];
                self.domainMatchers = alloc::vec![MatcherKind::All(allMatch)];
                return;
            }
            // Go: IPv4/CIDR, IPv6/CIDR
            let (_, pnet, cerr) = crate::net::ParseCIDR(p.clone());
            if cerr.IsNil() {
                self.ipMatchers.push(MatcherKind::Cidr(cidrMatch { cidr: pnet }));
                continue;
            }
            // Go: IPv4:port, [IPv6]:port
            let (mut phost, pport, sperr) = crate::net::SplitHostPort(p.clone());
            if sperr.IsNil() {
                if phost.Len() == 0 {
                    // Go: "no host part, likely malformed; ignore."
                    continue;
                }
                let pb = phost.as_bytes();
                if pb[0] == b'[' && pb[pb.len() - 1] == b']' {
                    phost = string::from_bytes(&pb[1..pb.len() - 1]);
                }
            } else {
                phost = p.clone();
            }
            // Go: IPv4, IPv6
            let pip = crate::net::ParseIP(phost.clone());
            if !pip.IsNil() {
                self.ipMatchers.push(MatcherKind::Ip(ipMatch {
                    ip: pip,
                    port: pport,
                }));
                continue;
            }
            if phost.Len() == 0 {
                continue;
            }
            // Go: "domain.com or domain.com:80 … foo.com matches
            // bar.foo.com … .domain.com, *.domain.com" (+ :port).
            if strings::HasPrefix(phost.clone(), string("*.")) {
                phost = string::from_bytes(&phost.as_bytes()[1..]);
            }
            let mut matchHost = false;
            if phost.as_bytes()[0] != b'.' {
                matchHost = true;
                phost = string(".") + phost;
            }
            let (v, ierr) = idnaASCII(phost.clone());
            if ierr.IsNil() {
                phost = v;
            }
            self.domainMatchers.push(MatcherKind::Domain(domainMatch {
                host: phost,
                port: pport,
                matchHost,
            }));
        }
        return;
    }
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:147-165 parseProxy
fn parseProxy(proxy: string) -> (Option<URL>, error) {
    if proxy.Len() == 0 {
        return (None, errors::nil);
    }
    let (proxyURL, err) = super::super::url::Parse(proxy.clone());
    if !err.IsNil() || proxyURL.Scheme.Len() == 0 || proxyURL.Host.Len() == 0 {
        // Go: "proxy was bogus. Try prepending 'http://' … If not, we
        // fall through and complain about the original one."
        let (retryURL, rerr) = super::super::url::Parse(string("http://") + proxy.clone());
        if rerr.IsNil() {
            return (Some(retryURL), errors::nil);
        }
    }
    if !err.IsNil() {
        return (
            None,
            crate::fmt::Errorf!("invalid proxy address %q: %v", proxy, err),
        );
    }
    return (Some(proxyURL), errors::nil);
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:276-280 portMap
fn portMap(scheme: &string) -> string {
    if *scheme == "http" {
        return string("80");
    }
    if *scheme == "https" {
        return string("443");
    }
    if *scheme == "socks5" {
        return string("1080");
    }
    return string::new();
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:282-294 canonicalAddr
/// Go: "returns url.Host but always with a ':port' suffix".
fn canonicalAddr(url: &URL) -> string {
    let mut addr = url.Hostname();
    let (v, err) = idnaASCII(addr.clone());
    if err.IsNil() {
        addr = v;
    }
    let mut port = url.Port();
    if port.Len() == 0 {
        port = portMap(&url.Scheme);
    }
    return crate::net::JoinHostPort(addr, port);
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:296-297 hasPort
/// Go: 'return true if the string includes a port' — for "host",
/// "host:port", or "[ipv6::address]:port".
#[allow(dead_code)]
fn hasPort(s: string) -> bool {
    return strings::LastIndex(s.clone(), string(":")) > strings::LastIndex(s, string("]"));
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:299-313 idnaASCII
/// Same fast-path-then-punycode shape as net/http's own copy; the
/// heavy half delegates to it rather than re-porting idna.
fn idnaASCII(v: string) -> (string, error) {
    if isASCII(v.clone()) {
        return (v, errors::nil);
    }
    return super::super::request::idnaASCII(v);
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:315-322 isASCII
fn isASCII(s: string) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] >= 0x80 {
            return false;
        }
        i += 1;
    }
    return true;
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:325-330 matcher
/// Go: "the matching rule for a given value in the NO_PROXY list".
/// goish carries the closed set as `MatcherKind` (Go's interface
/// values live in `[]matcher` slices; a Box<dyn> per entry buys
/// nothing over an enum here).
trait matcher {
    fn r#match(&self, host: &string, port: &string, ip: Option<&crate::net::IP>) -> bool;
}

// go: none — goish-only closed-set carrier for the matcher impls.
enum MatcherKind {
    All(allMatch),
    Cidr(cidrMatch),
    Ip(ipMatch),
    Domain(domainMatch),
}

impl MatcherKind {
    // go: none — dispatch over the closed set.
    fn r#match(&self, host: &string, port: &string, ip: Option<&crate::net::IP>) -> bool {
        let out = match self {
            MatcherKind::All(m) => m.r#match(host, port, ip),
            MatcherKind::Cidr(m) => m.r#match(host, port, ip),
            MatcherKind::Ip(m) => m.r#match(host, port, ip),
            MatcherKind::Domain(m) => m.r#match(host, port, ip),
        };
        return out;
    }
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:332-332 allMatch
/// Go: "allMatch matches on all possible inputs" — the `*` entry.
struct allMatch;

impl matcher for allMatch {
    // go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:334-336 allMatch.match
    // goishlint:ignore GOISH014 - `match` is a Rust keyword; the only
    // spelling is the raw identifier `r#match` (routing_tree precedent).
    fn r#match(&self, _host: &string, _port: &string, _ip: Option<&crate::net::IP>) -> bool {
        return true;
    }
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:338-340 cidrMatch
struct cidrMatch {
    cidr: crate::net::IPNet,
}

impl matcher for cidrMatch {
    // go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:342-344 cidrMatch.match
    // goishlint:ignore GOISH014 - `match` is a Rust keyword; the only
    // spelling is the raw identifier `r#match` (routing_tree precedent).
    fn r#match(&self, _host: &string, _port: &string, ip: Option<&crate::net::IP>) -> bool {
        let out = match ip {
            Some(ip) => self.cidr.Contains(ip.clone()),
            None => false,
        };
        return out;
    }
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:346-349 ipMatch
struct ipMatch {
    ip: crate::net::IP,
    port: string,
}

impl matcher for ipMatch {
    // go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:351-356 ipMatch.match
    // goishlint:ignore GOISH014 - `match` is a Rust keyword; the only
    // spelling is the raw identifier `r#match` (routing_tree precedent).
    fn r#match(&self, _host: &string, port: &string, ip: Option<&crate::net::IP>) -> bool {
        if let Some(ip) = ip {
            if self.ip.Equal(ip) {
                return self.port.Len() == 0 || self.port == *port;
            }
        }
        return false;
    }
}

// go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:358-363 domainMatch
struct domainMatch {
    host: string,
    port: string,
    matchHost: bool,
}

impl matcher for domainMatch {
    // go: sdk 1.25.5 vendor/golang.org/x/net/http/httpproxy/proxy.go:365-372 domainMatch.match
    // goishlint:ignore GOISH014 - `match` is a Rust keyword; the only
    // spelling is the raw identifier `r#match` (routing_tree precedent).
    fn r#match(&self, host: &string, port: &string, ip: Option<&crate::net::IP>) -> bool {
        if ip.is_some() {
            return false;
        }
        let stripped = string::from_bytes(&self.host.as_bytes()[1..]);
        if strings::HasSuffix(host.clone(), self.host.clone())
            || (self.matchHost && *host == stripped)
        {
            return self.port.Len() == 0 || self.port == *port;
        }
        return false;
    }
}
