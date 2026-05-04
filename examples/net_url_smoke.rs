// net/url smoke — Parse, field access, escape/unescape, query values.

#![no_std]
#![no_main]

extern crate alloc;

use goish::{nil, string, syscall};
use goish::net::url;

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond { die(msg); }
}

#[goish::main]
fn main() {
    // ── Parse a full URL ──────────────────────────────────────────────
    let (u, err) = url::Parse("https://alice:secret@example.com:8080/the/path?q=1&r=2#frag");
    check(err == nil, b"url: Parse error\n");

    check(u.Scheme   == string::from_static("https"),              b"url: Scheme wrong\n");
    check(u.Host     == string::from_static("example.com:8080"),   b"url: Host wrong\n");
    check(u.Path     == string::from_static("/the/path"),          b"url: Path wrong\n");
    check(u.RawQuery == string::from_static("q=1&r=2"),            b"url: RawQuery wrong\n");
    check(u.Fragment == string::from_static("frag"),               b"url: Fragment wrong\n");
    check(u.Hostname() == string::from_static("example.com"),      b"url: Hostname() wrong\n");
    check(u.Port()     == string::from_static("8080"),             b"url: Port() wrong\n");

    // Userinfo
    let uname = u.User.Username();
    check(uname == string::from_static("alice"), b"url: Username wrong\n");
    let (pwd, ok) = u.User.Password();
    check(ok,                                       b"url: Password ok wrong\n");
    check(pwd == string::from_static("secret"),     b"url: Password wrong\n");

    // IsAbs
    check(u.IsAbs(), b"url: IsAbs should be true\n");

    // String round-trip (scheme+host+path only; query+frag preserved)
    let s = u.String();
    check(s.Len() > 0, b"url: String() empty\n");

    // ── Parse a relative URL ─────────────────────────────────────────
    let (r, err) = url::Parse("/just/a/path");
    check(err == nil,                                          b"url: relative Parse error\n");
    check(r.Path == string::from_static("/just/a/path"),      b"url: relative Path wrong\n");
    check(!r.IsAbs(),                                          b"url: relative IsAbs should be false\n");

    // ── QueryEscape / QueryUnescape ──────────────────────────────────
    let esc = url::QueryEscape("hello world & more");
    check(esc == string::from_static("hello+world+%26+more"), b"url: QueryEscape wrong\n");

    let (unesc, err) = url::QueryUnescape("hello+world+%26+more");
    check(err == nil,                                          b"url: QueryUnescape error\n");
    check(unesc == string::from_static("hello world & more"), b"url: QueryUnescape wrong\n");

    // ── PathEscape / PathUnescape ────────────────────────────────────
    let pesc = url::PathEscape("a b/c");
    // space → %20, / → %2F
    check(pesc == string::from_static("a%20b%2Fc"), b"url: PathEscape wrong\n");

    let (punesc, err) = url::PathUnescape("a%20b%2Fc");
    check(err == nil,                                b"url: PathUnescape error\n");
    check(punesc == string::from_static("a b/c"),   b"url: PathUnescape wrong\n");

    // ── ParseQuery → Values ──────────────────────────────────────────
    let (vals, err) = url::ParseQuery("key=val&foo=bar&foo=baz");
    check(err == nil, b"url: ParseQuery error\n");

    let v = url::ValuesGet(&vals, string::from_static("key"));
    check(v == string::from_static("val"), b"url: ValuesGet key wrong\n");

    let v2 = url::ValuesGet(&vals, string::from_static("foo"));
    check(v2 == string::from_static("bar"), b"url: ValuesGet foo first wrong\n");

    check(url::ValuesHas(&vals, string::from_static("key")), b"url: ValuesHas key wrong\n");
    check(!url::ValuesHas(&vals, string::from_static("missing")), b"url: ValuesHas missing wrong\n");

    // ValuesSet / ValuesAdd / ValuesEncode
    let mut mv: url::Values = url::Values::new();
    url::ValuesSet(&mut mv, string::from_static("a"), string::from_static("1"));
    url::ValuesAdd(&mut mv, string::from_static("b"), string::from_static("2"));
    let enc = url::ValuesEncode(&mv);
    check(enc.Len() > 0, b"url: ValuesEncode empty\n");

    const OK: &[u8] = b"net/url: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
