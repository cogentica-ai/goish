// net/http/cookiejar — in-memory RFC 6265-compliant http.CookieJar.
//
//   Go                                       goish
//   ──────────────────────────────────────   ─────────────────────────────────
//   cookiejar.New(nil)                       cookiejar::New(None)
//   jar.SetCookies(u, cookies)               jar.SetCookies(&u, cookies)
//   jar.Cookies(u)                           jar.Cookies(&u)
//
// The code lives in jar.rs and punycode.rs, mirroring Go's two files,
// because anchored code may not sit in a module root (GOISH015).

#![allow(non_snake_case)]

mod jar;
pub mod punycode;

pub use jar::{Jar, New, Options, PublicSuffixList};
