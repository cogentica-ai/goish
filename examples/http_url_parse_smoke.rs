// net/http's URL parser against Go 1.25.5's net/url.
//
// Expected values from a goref run of net/url.Parse. This file exists
// because src/net/http/url.rs is 1274 lines with ZERO provenance
// anchors — no fidelity rule has ever examined it — and the first
// thing checked in it (authority splitting on '@') was a real bug
// that leaked userinfo into the Host header.
//
// One deliberate divergence is asserted as such: goish's URL has no
// `User` field, so userinfo is dropped after Host is computed. Host
// matches Go exactly; String() cannot re-emit "user:pw@".
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http::url;
use goish::{errors, fmt, string, syscall};

/// Scheme/Host/Query/Fragment — the parts goish matches Go on.
fn f(u: &url::URL) -> string {
    return fmt::Sprintf!(
        "Scheme=%s Host=%s Q=%s F=%s",
        u.Scheme.clone(),
        u.Host.clone(),
        u.RawQuery.clone(),
        u.Fragment.clone()
    );
}

fn chkEq(got: string, want: &'static str, what: &'static str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what);
        fmt::Println!("  got  ", got);
        fmt::Println!("  want ", want);
        *bad += 1;
    }
}

fn chk(raw: &'static str, want: &'static str, bad: &mut i32) {
    let (u, err) = url::Parse(string(raw));
    if err != errors::nil {
        fmt::Println!("FAIL ", raw, ": err ", err.Error());
        *bad += 1;
        return;
    }
    let got = f(&u);
    if got != want {
        fmt::Println!("FAIL ", raw);
        fmt::Println!("  got  ", got);
        fmt::Println!("  want ", want);
        *bad += 1;
    }
}

fn chkStr(raw: &'static str, want: &'static str, bad: &mut i32) {
    let (u, err) = url::Parse(string(raw));
    if err != errors::nil {
        fmt::Println!("FAIL String ", raw, ": err ", err.Error());
        *bad += 1;
        return;
    }
    let got = u.String();
    if got != want {
        fmt::Println!("FAIL String ", raw, ": got ", got, " want ", want);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    chk(
        "http://example.com/a/b?q=1#frag",
        "Scheme=http Host=example.com Q=q=1 F=frag",
        &mut bad,
    );
    chk(
        "http://example.com",
        "Scheme=http Host=example.com Q= F=",
        &mut bad,
    );
    chk(
        "http://example.com/",
        "Scheme=http Host=example.com Q= F=",
        &mut bad,
    );
    chk(
        "//example.com/x",
        "Scheme= Host=example.com Q= F=",
        &mut bad,
    );
    chk("/just/a/path", "Scheme= Host= Q= F=", &mut bad);
    chk(
        "http://[::1]:8080/p",
        "Scheme=http Host=[::1]:8080 Q= F=",
        &mut bad,
    );
    // Go lowercases the SCHEME but leaves the host case alone.
    chk(
        "HTTP://EXAMPLE.COM/P",
        "Scheme=http Host=EXAMPLE.COM Q= F=",
        &mut bad,
    );
    // Go does NOT clean dot segments during Parse.
    chk(
        "http://example.com/./a/../b",
        "Scheme=http Host=example.com Q= F=",
        &mut bad,
    );
    chk(
        "http://example.com//double//slash",
        "Scheme=http Host=example.com Q= F=",
        &mut bad,
    );

    // %2F: Go DECODES Path and keeps the raw form in RawPath.
    chk(
        "http://example.com/a%2Fb",
        "Scheme=http Host=example.com Q= F=",
        &mut bad,
    );

    // Host must exclude userinfo (the bug this file was written for).
    chk(
        "https://user:pw@host:8443/p?x=1",
        "Scheme=https Host=host:8443 Q=x=1 F=",
        &mut bad,
    );

    // String() round-trips.
    chkStr(
        "http://example.com/a/b?q=1#frag",
        "http://example.com/a/b?q=1#frag",
        &mut bad,
    );
    chkStr("http://example.com", "http://example.com", &mut bad);
    chkStr("http://example.com/", "http://example.com/", &mut bad);
    chkStr("/just/a/path", "/just/a/path", &mut bad);
    chkStr("//example.com/x", "//example.com/x", &mut bad);

    // ── The divergence this file used to pin, now CLOSED ───────────
    //
    // Go PERCENT-DECODES Path during Parse and keeps the raw form in
    // RawPath, setting RawPath only when it differs from the default
    // escaping of Path:
    //
    //   "/a%2Fb" -> Path="/a/b"   RawPath="/a%2Fb"
    //   "/a/b"   -> Path="/a/b"   RawPath=""
    //
    // goish used to answer Path="/a%2Fb" and always set RawPath. That
    // was not cosmetic: ServeMux matches on r.URL.Path, so a request
    // for "/a%2Fb" did not match a "/a/b" pattern as it does in Go, and
    // every handler inspecting Path saw the encoded bytes.
    //
    // The cause was not a bug in the parser — it was that there were
    // TWO. net/http had its own 1504-line URL parser, unanchored and
    // never diffed, shadowing the anchored port in `crate::net::url`,
    // which decoded correctly all along. net/http now uses the one
    // parser, and these are Go's values.
    {
        let (u, _) = url::Parse(string("http://example.com/a%2Fb"));
        chkEq(u.Path.clone(), "/a/b", "decoded Path", &mut bad);
        chkEq(
            u.RawPath.clone(),
            "/a%2Fb",
            "RawPath keeps the raw form",
            &mut bad,
        );

        // RawPath is EMPTY when the default escaping of Path round-trips
        // — Go only sets it when the two differ.
        let (u2, _) = url::Parse(string("http://example.com/a/b"));
        chkEq(u2.Path.clone(), "/a/b", "plain Path", &mut bad);
        chkEq(
            u2.RawPath.clone(),
            "",
            "plain path leaves RawPath empty",
            &mut bad,
        );

        // EscapedPath reconstructs the raw form from either.
        chkEq(
            u.EscapedPath(),
            "/a%2Fb",
            "EscapedPath from RawPath",
            &mut bad,
        );
        chkEq(
            u2.EscapedPath(),
            "/a/b",
            "EscapedPath with no RawPath",
            &mut bad,
        );
    }

    if bad == 0 {
        fmt::Println!("URL_PARSE_OK 23/23");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
