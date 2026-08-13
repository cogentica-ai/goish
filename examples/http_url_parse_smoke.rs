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

    chk("http://example.com/a/b?q=1#frag",
        "Scheme=http Host=example.com Q=q=1 F=frag", &mut bad);
    chk("http://example.com",
        "Scheme=http Host=example.com Q= F=", &mut bad);
    chk("http://example.com/",
        "Scheme=http Host=example.com Q= F=", &mut bad);
    chk("//example.com/x",
        "Scheme= Host=example.com Q= F=", &mut bad);
    chk("/just/a/path",
        "Scheme= Host= Q= F=", &mut bad);
    chk("http://[::1]:8080/p",
        "Scheme=http Host=[::1]:8080 Q= F=", &mut bad);
    // Go lowercases the SCHEME but leaves the host case alone.
    chk("HTTP://EXAMPLE.COM/P",
        "Scheme=http Host=EXAMPLE.COM Q= F=", &mut bad);
    // Go does NOT clean dot segments during Parse.
    chk("http://example.com/./a/../b",
        "Scheme=http Host=example.com Q= F=", &mut bad);
    chk("http://example.com//double//slash",
        "Scheme=http Host=example.com Q= F=", &mut bad);

    // %2F: Go DECODES Path and keeps the raw form in RawPath.
    chk("http://example.com/a%2Fb",
        "Scheme=http Host=example.com Q= F=", &mut bad);

    // Host must exclude userinfo (the bug this file was written for).
    chk("https://user:pw@host:8443/p?x=1",
        "Scheme=https Host=host:8443 Q=x=1 F=", &mut bad);

    // String() round-trips.
    chkStr("http://example.com/a/b?q=1#frag", "http://example.com/a/b?q=1#frag", &mut bad);
    chkStr("http://example.com", "http://example.com", &mut bad);
    chkStr("http://example.com/", "http://example.com/", &mut bad);
    chkStr("/just/a/path", "/just/a/path", &mut bad);
    chkStr("//example.com/x", "//example.com/x", &mut bad);

    // ── KNOWN DIVERGENCE, pinned so a fix trips this test ──────────
    //
    // Go PERCENT-DECODES Path during Parse and keeps the raw form in
    // RawPath, setting RawPath only when it differs from the default
    // escaping of Path:
    //
    //   Go:    "/a%2Fb" -> Path="/a/b"   RawPath="/a%2Fb"
    //          "/a/b"   -> Path="/a/b"   RawPath=""
    //   goish: "/a%2Fb" -> Path="/a%2Fb" RawPath="/a%2Fb"
    //          "/a/b"   -> Path="/a/b"   RawPath="/a/b"
    //
    // goish never decodes and always sets RawPath. This is not
    // cosmetic: ServeMux matches on r.URL.Path, so a request for
    // "/a%2Fb" does NOT match a "/a/b" pattern here as it would in
    // Go, and any handler inspecting Path sees the encoded bytes.
    // Fixing it changes what EVERY handler observes, so it wants its
    // own session and a full suite run — it is recorded here rather
    // than bodged.
    {
        let (u, _) = url::Parse(string("http://example.com/a%2Fb"));
        if u.Path != "/a%2Fb" || u.RawPath != "/a%2Fb" {
            fmt::Println!(
                "KNOWN DIVERGENCE CHANGED — Path/RawPath now ",
                u.Path.clone(),
                " / ",
                u.RawPath.clone(),
                " (Go: /a/b and /a%2Fb). Update this test and the note above."
            );
            bad += 1;
        }
        let (u2, _) = url::Parse(string("http://example.com/a/b"));
        if u2.RawPath != "/a/b" {
            fmt::Println!("KNOWN DIVERGENCE CHANGED — RawPath for a plain path");
            bad += 1;
        }
    }

    if bad == 0 {
        fmt::Println!("URL_PARSE_OK 17/17");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
