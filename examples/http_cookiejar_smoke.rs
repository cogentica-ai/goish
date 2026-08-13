// http_cookiejar_smoke — exercise net/http/cookiejar.
// (net/http/cookiejar/jar.go + punycode.go)
//
// Mirrors the headline behaviors from jar_test.go: domain matching,
// path matching, host-only vs. domain cookies, MaxAge expiry,
// scheme filtering, and round-trip Cookies after SetCookies.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http::cookiejar::{self, New, Options};
use goish::net::http::{Cookie, CookieJar, ParseURL};
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. New with nil options returns a usable jar.
    {
        let (jar, err) = New(None);
        if err.IsNil() {
            let _ = jar; // jar is Arc<Jar>
            fmt::Println!("[ 1] New(nil) returns jar      PASS");
        } else {
            fmt::Println!("[ 1] New(nil) returns jar      FAIL");
            failed += 1;
        }
    }

    // 2. SetCookies on http URL stores; Cookies returns them.
    {
        let (jar, _) = New(None);
        let (u, _) = ParseURL(string("http://example.com/"));
        let mut c = Cookie::new(string("k"), string("v"));
        c.Path = string("/");
        let cookies = goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![c]);
        jar.SetCookies(&u, cookies);
        let got = jar.Cookies(&u);
        if got.len() == 1 && got[0].Name == "k" && got[0].Value == "v" {
            fmt::Println!("[ 2] Set then Cookies          PASS");
        } else {
            fmt::Println!("[ 2] Set then Cookies          FAIL n={}", got.len());
            failed += 1;
        }
    }

    // 3. Non-http(s) scheme is ignored on Set.
    {
        let (jar, _) = New(None);
        let (u, _) = ParseURL(string("ftp://example.com/"));
        let mut c = Cookie::new(string("k"), string("v"));
        c.Path = string("/");
        let cookies = goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![c]);
        jar.SetCookies(&u, cookies);
        let (u2, _) = ParseURL(string("http://example.com/"));
        let got = jar.Cookies(&u2);
        if got.is_empty() {
            fmt::Println!("[ 3] non-http(s) ignored       PASS");
        } else {
            fmt::Println!("[ 3] non-http(s) ignored       FAIL n={}", got.len());
            failed += 1;
        }
    }

    // 4. Cross-host cookie not returned.
    {
        let (jar, _) = New(None);
        let (u1, _) = ParseURL(string("http://example.com/"));
        let mut c = Cookie::new(string("k"), string("v"));
        c.Path = string("/");
        let cookies = goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![c]);
        jar.SetCookies(&u1, cookies);
        let (u2, _) = ParseURL(string("http://other.com/"));
        let got = jar.Cookies(&u2);
        if got.is_empty() {
            fmt::Println!("[ 4] host-only stays put       PASS");
        } else {
            fmt::Println!("[ 4] host-only stays put       FAIL n={}", got.len());
            failed += 1;
        }
    }

    // 5. Domain cookie covers subdomain.
    {
        let (jar, _) = New(None);
        let (u_set, _) = ParseURL(string("http://www.example.com/"));
        let mut c = Cookie::new(string("k"), string("v"));
        c.Path = string("/");
        c.Domain = string("example.com");
        let cookies = goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![c]);
        jar.SetCookies(&u_set, cookies);

        // Same-host (www.example.com) should match.
        let (u_get, _) = ParseURL(string("http://www.example.com/"));
        let got = jar.Cookies(&u_get);
        if got.len() == 1 {
            fmt::Println!("[ 5] domain cookie matches     PASS");
        } else {
            fmt::Println!("[ 5] domain cookie matches     FAIL n={}", got.len());
            failed += 1;
        }
    }

    // 6. Path match: /foo cookie goes to /foo/bar but not to /baz.
    {
        let (jar, _) = New(None);
        let (u_set, _) = ParseURL(string("http://example.com/foo"));
        let mut c = Cookie::new(string("k"), string("v"));
        c.Path = string("/foo");
        let cookies = goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![c]);
        jar.SetCookies(&u_set, cookies);

        let (u_in, _) = ParseURL(string("http://example.com/foo/bar"));
        let in_got = jar.Cookies(&u_in);

        let (u_out, _) = ParseURL(string("http://example.com/baz"));
        let out_got = jar.Cookies(&u_out);

        if in_got.len() == 1 && out_got.is_empty() {
            fmt::Println!("[ 6] path match /foo ⊂ /foo/.. PASS");
        } else {
            fmt::Println!(
                "[ 6] path match /foo ⊂ /foo/.. FAIL in={} out={}",
                in_got.len(),
                out_got.len()
            );
            failed += 1;
        }
    }

    // 7. MaxAge < 0 deletes any prior cookie with same id.
    {
        let (jar, _) = New(None);
        let (u, _) = ParseURL(string("http://example.com/"));
        let mut c1 = Cookie::new(string("k"), string("v"));
        c1.Path = string("/");
        jar.SetCookies(&u, goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![c1]));

        let mut c2 = Cookie::new(string("k"), string("ignored"));
        c2.Path = string("/");
        c2.MaxAge = -1;
        jar.SetCookies(&u, goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![c2]));

        let got = jar.Cookies(&u);
        if got.is_empty() {
            fmt::Println!("[ 7] MaxAge<0 deletes          PASS");
        } else {
            fmt::Println!("[ 7] MaxAge<0 deletes          FAIL n={}", got.len());
            failed += 1;
        }
    }

    // 8. Secure cookie not sent over http.
    {
        let (jar, _) = New(None);
        let (u_set, _) = ParseURL(string("https://example.com/"));
        let mut c = Cookie::new(string("k"), string("v"));
        c.Path = string("/");
        c.Secure = true;
        jar.SetCookies(&u_set, goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![c]));

        let (u_http, _) = ParseURL(string("http://example.com/"));
        let http_got = jar.Cookies(&u_http);

        let (u_https, _) = ParseURL(string("https://example.com/"));
        let https_got = jar.Cookies(&u_https);

        if http_got.is_empty() && https_got.len() == 1 {
            fmt::Println!("[ 8] Secure http filter        PASS");
        } else {
            fmt::Println!(
                "[ 8] Secure http filter        FAIL http={} https={}",
                http_got.len(),
                https_got.len()
            );
            failed += 1;
        }
    }

    // 9. Multi-cookie sort: longer path first.
    {
        let (jar, _) = New(None);
        let (u, _) = ParseURL(string("http://example.com/a/b"));
        let mut c1 = Cookie::new(string("short"), string("1"));
        c1.Path = string("/");
        let mut c2 = Cookie::new(string("long"), string("2"));
        c2.Path = string("/a");
        let mut c3 = Cookie::new(string("longest"), string("3"));
        c3.Path = string("/a/b");
        jar.SetCookies(&u, goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![c1, c2, c3]));

        let got = jar.Cookies(&u);
        if got.len() == 3 && got[0].Name == "longest" && got[1].Name == "long" && got[2].Name == "short" {
            fmt::Println!("[ 9] sort by path length       PASS");
        } else {
            fmt::Println!("[ 9] sort by path length       FAIL n={}", got.len());
            failed += 1;
        }
    }

    // 10. Empty cookies slice is a no-op.
    {
        let (jar, _) = New(None);
        let (u, _) = ParseURL(string("http://example.com/"));
        jar.SetCookies(&u, goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![]));
        let got = jar.Cookies(&u);
        if got.is_empty() {
            fmt::Println!("[10] empty Set noop            PASS");
        } else {
            fmt::Println!("[10] empty Set noop            FAIL n={}", got.len());
            failed += 1;
        }
    }

    // 11. punycode toASCII: ASCII passthrough.
    {
        let (s, err) = cookiejar::punycode::toASCII(string("golang"));
        if err.IsNil() && s == "golang" {
            fmt::Println!("[11] toASCII ASCII             PASS");
        } else {
            fmt::Println!("[11] toASCII ASCII             FAIL");
            failed += 1;
        }
    }

    // 12. punycode toASCII: bücher.example.com -> xn--bcher-kva.example.com.
    {
        let (s, err) = cookiejar::punycode::toASCII(string("bücher.example.com"));
        if err.IsNil() && s == "xn--bcher-kva.example.com" {
            fmt::Println!("[12] toASCII IDN encode        PASS");
        } else {
            fmt::Println!("[12] toASCII IDN encode        FAIL got ", s);
            failed += 1;
        }
    }

    // 13. Options::default + New round trip.
    {
        let opts = Options::default();
        let (jar, err) = New(Some(&opts));
        let _ = jar;
        if err.IsNil() {
            fmt::Println!("[13] New(Options::default)     PASS");
        } else {
            fmt::Println!("[13] New(Options::default)     FAIL");
            failed += 1;
        }
    }

    // 14. A Jar is usable through http.CookieJar. Go's package doc
    //     opens by saying Jar implements that interface, and goish had
    //     neither the interface nor the impl — so the sentence was
    //     unbacked and Client could never have been handed a jar.
    {
        let (jar, _) = New(None);
        let asJar: alloc::sync::Arc<dyn CookieJar> = jar;
        let (u, _) = ParseURL(string("http://example.com/"));
        let mut c = Cookie::new(string("via"), string("iface"));
        c.Path = string("/");
        asJar.SetCookies(
            &u,
            goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![c]),
        );
        let got = asJar.Cookies(&u);
        if goish::builtin::len(&got) == 1 && got[0].Value == "iface" {
            fmt::Println!("[14] usable as http.CookieJar  PASS");
        } else {
            fmt::Println!("[14] usable as http.CookieJar  FAIL");
            failed += 1;
        }
    }

    // 15. A cookie whose Domain does not domain-match the host is
    //     dropped (errIllegalDomain). This is the security property the
    //     package exists for: evil.example.net must not be able to set
    //     a cookie for bank.example.com.
    {
        let (jar, _) = New(None);
        let (u, _) = ParseURL(string("http://evil.example.net/"));
        let mut c = Cookie::new(string("stolen"), string("1"));
        c.Path = string("/");
        c.Domain = string("bank.example.com");
        jar.SetCookies(
            &u,
            goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![c]),
        );
        let (victim, _) = ParseURL(string("http://bank.example.com/"));
        let at_victim = jar.Cookies(&victim);
        let at_self = jar.Cookies(&u);
        if goish::builtin::len(&at_victim) == 0 && goish::builtin::len(&at_self) == 0 {
            fmt::Println!("[15] cross-domain set refused  PASS");
        } else {
            fmt::Println!("[15] cross-domain set refused  FAIL");
            failed += 1;
        }
    }

    // 16. A trailing dot in the domain attribute is malformed and
    //     rejected (errMalformedDomain), where the SAME name without
    //     the dot is accepted. Asserting both halves is what separates
    //     "rejects the dot" from "rejects everything".
    {
        let (jar, _) = New(None);
        let (u, _) = ParseURL(string("http://example.com/"));

        let mut bad = Cookie::new(string("bad"), string("1"));
        bad.Path = string("/");
        bad.Domain = string("example.com.");
        jar.SetCookies(
            &u,
            goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![bad]),
        );
        let after_bad = goish::builtin::len(&jar.Cookies(&u));

        let mut good = Cookie::new(string("good"), string("1"));
        good.Path = string("/");
        good.Domain = string("example.com");
        jar.SetCookies(
            &u,
            goish::goslice::slice::<Cookie>::__from_vec(alloc::vec![good]),
        );
        let after_good = goish::builtin::len(&jar.Cookies(&u));

        if after_bad == 0 && after_good == 1 {
            fmt::Println!("[16] trailing-dot domain bad   PASS");
        } else {
            fmt::Println!(
                "[16] trailing-dot domain bad   FAIL",
                after_bad,
                after_good
            );
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 16/16");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 16");
        syscall::Exit(1);
    }
}
