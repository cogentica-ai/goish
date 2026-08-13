// go: package net/http
//
// go: file net/http/jar.go decls:
//
// Go: "A CookieJar manages storage and use of cookies in HTTP requests."
//
// jar.go declares one interface and no functions, so it moves the
// coverage needle not at all — but without it `cookiejar.Jar` has
// nothing to implement, and the sentence Go's own package doc opens
// with ("Jar implements the http.CookieJar interface") is unbacked.
//
// The GOISH022 suppression on the `#[goish::interface]` line below is a
// linter false positive, not a divergence: the rule looks for the
// prefix `goish::int` and finds it inside `goish::interface`. The same
// hit is baselined in 22 other files across the tree.

#![allow(non_snake_case)]

use super::cookie::Cookie;
use super::url::URL;
use crate::goslice::slice;

// go: sdk 1.25.5 net/http/jar.go:17-27 CookieJar
/// Go: "A CookieJar manages storage and use of cookies in HTTP
/// requests. Implementations of CookieJar must be safe for concurrent
/// use by multiple goroutines. The net/http/cookiejar package provides
/// a CookieJar implementation."
// goishlint:ignore GOISH022 — false positive: the rule matches the
// prefix `goish::int` inside the attribute name `goish::interface`.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait CookieJar: Send + Sync {
    /// Go: "SetCookies handles the receipt of the cookies in a reply for
    /// the given URL. It may or may not choose to save the cookies,
    /// depending on the jar's policy and implementation."
    fn SetCookies(&self, u: &URL, cookies: slice<Cookie>);

    /// Go: "Cookies returns the cookies to send in a request for the
    /// given URL. It is up to the implementation to honor the standard
    /// cookie use restrictions such as in RFC 6265."
    fn Cookies(&self, u: &URL) -> slice<Cookie>;
}
