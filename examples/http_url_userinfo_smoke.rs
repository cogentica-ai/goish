// http_url_userinfo_smoke — URL.User end to end.
//
// Every expected value below is a VERBATIM capture from Go 1.25.5 via
// scripts/goref.sh (net/url for Parse/String/Redacted, net/http for
// the unexported stripPassword/refererForURL) — not transcribed from
// documentation. The cases that discriminate:
//
//   * "u:p@ss@host" — the split is at the LAST '@' (go.dev/issue/3439);
//     a first-@ split would make the host "ss@example.com".
//   * "u:@host" — an EMPTY password still counts as SET: Redacted and
//     stripPassword must mask it, and String keeps the ':'.
//   * "%20"/"%2F" — userinfo is percent-DECODED at Parse and
//     re-encoded by String, round-tripping byte-identically.
//   * "bad^user" — invalid userinfo is a PARSE ERROR, not a silent
//     pass-through into Host.
//   * Host stays clean in all cases — Request.Host feeds the Host:
//     header, which must never carry credentials.
//   * refererForURL strips only the userinfo, keeps query, and
//     returns "" on an https→http downgrade.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::client::{refererForURL, stripPassword};
use goish::net::http::url::{Parse, UserPassword};
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, got: goish::string, want: &'static str) {
    if (got.as_ref() as &str) == want {
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — got %q want %q\n", name, got, string(want));
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

fn run() -> ! {
    // ── plain user:pass ──
    let (u, e) = Parse("http://user:pw@example.com/p");
    check("parse ok", fmt::Sprintf!("%v", e), "<nil>");
    check("host is clean", u.Host.clone(), "example.com");
    let ui = u.User.clone();
    check("username", ui.Username(), "user");
    let (pw, set) = ui.Password();
    check("password", pw, "pw");
    check(
        "password set",
        string(if set { "true" } else { "false" }),
        "true",
    );
    check(
        "String round-trips",
        u.String(),
        "http://user:pw@example.com/p",
    );
    check(
        "Redacted masks",
        u.Redacted(),
        "http://user:xxxxx@example.com/p",
    );
    check(
        "stripPassword",
        stripPassword(&u),
        "http://user:***@example.com/p",
    );

    // ── '@' inside the password: split at the LAST '@' ──
    let (u2, _) = Parse("http://u:p@ss@example.com/p");
    check("last-@ host", u2.Host.clone(), "example.com");
    let ui2 = u2.User.clone();
    let (pw2, _) = ui2.Password();
    check("last-@ password", pw2, "p@ss");
    check(
        "last-@ String re-encodes",
        u2.String(),
        "http://u:p%40ss@example.com/p",
    );

    // ── username only: password NOT set ──
    let (u3, _) = Parse("http://justuser@example.com/p");
    let ui3 = u3.User.clone();
    let (_, set3) = ui3.Password();
    check(
        "user-only not set",
        string(if set3 { "true" } else { "false" }),
        "false",
    );
    check(
        "user-only Redacted unchanged",
        u3.Redacted(),
        "http://justuser@example.com/p",
    );
    check(
        "user-only strip unchanged",
        stripPassword(&u3),
        "http://justuser@example.com/p",
    );

    // ── empty password still counts as set ──
    let (u4, _) = Parse("http://u:@example.com/p");
    let ui4 = u4.User.clone();
    let (_, set4) = ui4.Password();
    check(
        "empty pw is set",
        string(if set4 { "true" } else { "false" }),
        "true",
    );
    check(
        "empty pw String keeps colon",
        u4.String(),
        "http://u:@example.com/p",
    );
    check(
        "empty pw Redacted masks",
        u4.Redacted(),
        "http://u:xxxxx@example.com/p",
    );
    check(
        "empty pw strip masks",
        stripPassword(&u4),
        "http://u:***@example.com/p",
    );

    // ── percent-decoding at Parse, re-encoding at String ──
    let (u5, _) = Parse("http://a%20b:c%2Fd@example.com/");
    let ui5 = u5.User.clone();
    check("decoded username", ui5.Username(), "a b");
    let (pw5, _) = ui5.Password();
    check("decoded password", pw5, "c/d");
    check(
        "re-encoded String",
        u5.String(),
        "http://a%20b:c%2Fd@example.com/",
    );

    // ── invalid userinfo is a parse error ──
    let (_, e6) = Parse("http://bad^user@example.com/");
    check(
        "invalid userinfo rejected",
        string(if e6.IsNil() { "nil" } else { "err" }),
        "err",
    );

    // ── Userinfo.String escapes '@' '/' '?' ':' (UserPassword mode) ──
    check(
        "Userinfo.String escaping",
        UserPassword("a@b", "c:d/e?f").String(),
        "a%40b:c%3Ad%2Fe%3Ff",
    );

    // ── no userinfo at all: User is None ──
    let (u7, _) = Parse("http://example.com/p");
    check(
        "no userinfo → None",
        string(if u7.User == goish::nil {
            "none"
        } else {
            "some"
        }),
        "none",
    );

    // ── refererForURL: strips auth, keeps query, blocks downgrade ──
    let (last, _) = Parse("https://user:pw@last.com/from?q=1");
    let (next_https, _) = Parse("https://next.com/");
    let (next_http, _) = Parse("http://next.com/");
    check(
        "referer strips userinfo, keeps query",
        refererForURL(&last, &next_https, string("")),
        "https://last.com/from?q=1",
    );
    check(
        "referer empty on https→http downgrade",
        refererForURL(&last, &next_http, string("")),
        "",
    );
    check(
        "explicit referer wins",
        refererForURL(&last, &next_https, string("keepme")),
        "keepme",
    );

    // ── live: URL userinfo becomes Authorization: Basic on the wire ──
    // (client.go `send`: u := req.URL.User; "Basic " + basicAuth —
    // goref: base64("user:pa ss") == "dXNlcjpwYSBzcw==".) A caller-set
    // Authorization header must win over the URL's credentials.
    {
        use alloc::sync::Arc;
        let seen = Arc::new(goish::sync::Mutex::new(goish::string::new()));
        let mux = goish::net::http::ServeMux::new();
        {
            let seen = seen.clone();
            mux.HandleFunc(string("/auth"), move |w, r| {
                *seen.Lock() = r.Header.Get(string("Authorization"));
                let _ = w.Write(goish::bytes("ok"));
            });
        }
        let ts = goish::net::http::httptest::NewServer(Arc::new(mux));
        let base = goish::strings::TrimPrefix(ts.URL(), string("http://"));

        let url1 = fmt::Sprintf!("http://user:pa%%20ss@%s/auth", base);
        let (mut resp, err) = goish::net::http::Get(url1);
        if err.IsNil() {
            let _ = goish::io::Closer::Close(&mut resp.Body);
        }
        check(
            "URL userinfo arrives as Authorization: Basic",
            (*seen.Lock()).clone(),
            "Basic dXNlcjpwYSBzcw==",
        );

        let url2 = fmt::Sprintf!("http://user:pw@%s/auth", base);
        let (mut req, _) = goish::net::http::NewRequest(string("GET"), url2, goish::nil);
        req.Header
            .Set(string("Authorization"), string("Bearer mine"));
        let client = goish::net::http::Client::default();
        let (mut resp, err) = client.Do(&req);
        if err.IsNil() {
            let _ = goish::io::Closer::Close(&mut resp.Body);
        }
        check(
            "a caller-set Authorization wins over URL credentials",
            (*seen.Lock()).clone(),
            "Bearer mine",
        );

        // Go send: a set RequestURI is refused client-side.
        let (mut req, _) = goish::net::http::NewRequest(
            string("GET"),
            fmt::Sprintf!("http://%s/auth", base),
            goish::nil,
        );
        req.RequestURI = string("/auth");
        let (_, err) = client.Do(&req);
        check(
            "a set RequestURI is refused in client requests",
            fmt::Sprintf!("%v", err),
            "http: Request.RequestURI can't be set in client requests",
        );
        ts.Close();
    }

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("HTTP_URL_USERINFO_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_URL_USERINFO_FAIL (%d)\n", f as i64);
    goish::os::Exit(1);
}
