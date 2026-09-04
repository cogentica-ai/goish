// preconditions_ref_smoke — conditional requests through ServeContent.
//
// Reference: Go 1.25.5 net/http, measured by
// tools/gen_preconditions_ref.go. Every GO[] line is Go's verbatim
// output for the same request against the same content.
//
// checkPreconditions decides whether a client is told "here it is",
// "you already have it", or "someone changed it under you". Getting
// the ORDER wrong is the interesting failure, because every individual
// header still looks like it works: RFC 9110 13.2.2 fixes the
// evaluation order as If-Match, If-Unmodified-Since, If-None-Match,
// If-Modified-Since, If-Range, and a server that evaluates them in a
// different order answers 200 where 304 is required, or serves content
// that a lost-update check was supposed to block.
//
// goish matched Go on all 25 lines, which for this surface is the
// result worth holding. None of it had ever been diffed against a
// running Go — no generator covered these headers at all.
//
// The cases that would catch a re-ordering or a sloppy comparison:
//
//   inm-wins — If-None-Match says "not mine" while If-Modified-Since
//   says "not modified". If-None-Match is evaluated first AND its
//   answer is final, so the response is 200. A server that let
//   If-Modified-Since have the last word would send a 304 for content
//   the client does not have.
//
//   inm-weak — W/"v1" matches "v1". ETag comparison for If-None-Match
//   is WEAK, so the W/ prefix must be stripped before comparing; for
//   If-Match it is strong. Same syntax, two comparison rules.
//
//   inm-list — a comma-separated list, matching on the middle entry.
//
//   ifrange-etag-bad and ifrange-date-bad — a Range request whose
//   If-Range does not match is answered with the FULL body and 200,
//   not 416 and not a range. Silently serving the range anyway would
//   hand a client bytes from a different version of the resource,
//   spliced into the copy it already holds.
//
//   ims-junk — an unparseable date is IGNORED, not an error.
//
//   inm-empty — an empty If-None-Match is not a match.
//
// The header side is pinned too, because it is where 304 differs from
// 200 in more than the status line: a 304 carries NO Content-Type and
// NO Last-Modified, while a 412 keeps Last-Modified. Both are easy to
// get wrong by writing the headers before evaluating the conditions.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::{go, string, strings, time};

// Go's verbatim output.
const GO: [&str; 25] = [
    "plain              200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=11 body=\"hello world\"",
    "inm-match          304 ct=\"\"                       cr=\"\"               etag=\"\\\"v1\\\"\" lm=false len=0 body=\"\"",
    "inm-star           304 ct=\"\"                       cr=\"\"               etag=\"\\\"v1\\\"\" lm=false len=0 body=\"\"",
    "inm-nomatch        200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=11 body=\"hello world\"",
    "inm-weak           304 ct=\"\"                       cr=\"\"               etag=\"\\\"v1\\\"\" lm=false len=0 body=\"\"",
    "inm-list           304 ct=\"\"                       cr=\"\"               etag=\"\\\"v1\\\"\" lm=false len=0 body=\"\"",
    "ims-after          304 ct=\"\"                       cr=\"\"               etag=\"\\\"v1\\\"\" lm=false len=0 body=\"\"",
    "ims-exact          304 ct=\"\"                       cr=\"\"               etag=\"\\\"v1\\\"\" lm=false len=0 body=\"\"",
    "ims-before         200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=11 body=\"hello world\"",
    "ims-junk           200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=11 body=\"hello world\"",
    "inm-wins           200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=11 body=\"hello world\"",
    "im-match           200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=11 body=\"hello world\"",
    "im-nomatch         412 ct=\"\"                       cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=0 body=\"\"",
    "im-star            200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=11 body=\"hello world\"",
    "ium-before         412 ct=\"\"                       cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=0 body=\"\"",
    "ium-after          200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=11 body=\"hello world\"",
    "range              206 ct=\"text/plain; charset=utf-8\" cr=\"bytes 0-4/11\"   etag=\"\\\"v1\\\"\" lm=true len=5 body=\"hello\"",
    "ifrange-etag-ok    206 ct=\"text/plain; charset=utf-8\" cr=\"bytes 0-4/11\"   etag=\"\\\"v1\\\"\" lm=true len=5 body=\"hello\"",
    "ifrange-etag-bad   200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=11 body=\"hello world\"",
    "ifrange-date-ok    206 ct=\"text/plain; charset=utf-8\" cr=\"bytes 0-4/11\"   etag=\"\\\"v1\\\"\" lm=true len=5 body=\"hello\"",
    "ifrange-date-bad   200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=11 body=\"hello world\"",
    "head-inm           304 ct=\"\"                       cr=\"\"               etag=\"\\\"v1\\\"\" lm=false len=0 body=\"\"",
    "head-plain         200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=0 body=\"\"",
    "post-im-nomatch    412 ct=\"\"                       cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=0 body=\"\"",
    "inm-empty          200 ct=\"text/plain; charset=utf-8\" cr=\"\"               etag=\"\\\"v1\\\"\" lm=true len=11 body=\"hello world\"",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            goish::string(GO[i])
        );
    }
}

fn ascii(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for &c in b.iter() {
        s.push(c as char);
    }
    s
}

fn itoa(mut n: i64) -> String {
    if n == 0 {
        return String::from("0");
    }
    let neg = n < 0;
    if neg {
        n = -n;
    }
    let mut d: Vec<u8> = Vec::new();
    while n > 0 {
        d.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    d.reverse();
    let mut s = ascii(&d);
    if neg {
        s.insert(0, '-');
    }
    s
}

fn hdr(raw: &str, name: &str) -> goish::string {
    for ln in raw.split("\r\n") {
        if ln.is_empty() {
            break;
        }
        let mut want = name.to_ascii_lowercase();
        want.push(':');
        if ln.to_ascii_lowercase().starts_with(&want) {
            return goish::string::from_bytes(ln[name.len() + 1..].trim().as_bytes());
        }
    }
    string("")
}

fn req_raw(port: goish::int, req: &str) -> goish::string {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        return string("");
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(700 * 1_000_000)));
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
        req.as_bytes().to_vec(),
    ));
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    while out.len() < 8192 {
        let (n, re) = c.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if !re.IsNil() || n == 0 {
            break;
        }
    }
    let _ = c.Close();
    goish::string::from_bytes(&out)
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

const ETAG: &str = "\"v1\"";
const BODY: &str = "hello world";

fn run() {
    let modtime = time::Date(2024, time::January, 2, 3, 4, 5, 0, time::UTC);
    let mt = modtime.clone();
    let mux = http::ServeMux::new();
    mux.HandleFunc("/f.txt", move |w, r| {
        w.Header()
            .Set(string("ETag"), goish::string::from_bytes(ETAG.as_bytes()));
        let mut content = strings::NewReader(goish::string::from_bytes(BODY.as_bytes()));
        http::ServeContent(
            w,
            goish::gonilable_ref::nilable_ref::new(r),
            string("f.txt"),
            mt.clone(),
            &mut content,
        );
    });

    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ..Default::default()
    });
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("listen: %v\n", le);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    {
        let s2 = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s2.Serve(ln);
        });
    }
    time::Sleep(time::Duration(150 * 1_000_000));

    let tf = goish::string::from_bytes(http::TimeFormat.as_bytes());
    let before = modtime
        .Add(time::Duration(-3600i64 * 1_000_000_000))
        .UTC()
        .Format(tf.clone());
    let after = modtime
        .Add(time::Duration(3600i64 * 1_000_000_000))
        .UTC()
        .Format(tf.clone());
    let exact = modtime.UTC().Format(tf);

    let mut cases: Vec<(&'static str, &'static str, String)> = Vec::new();
    let add =
        |v: &mut Vec<(&'static str, &'static str, String)>, n, m, h: String| v.push((n, m, h));
    add(&mut cases, "plain", "GET", String::new());
    add(
        &mut cases,
        "inm-match",
        "GET",
        String::from("If-None-Match: \"v1\"\r\n"),
    );
    add(
        &mut cases,
        "inm-star",
        "GET",
        String::from("If-None-Match: *\r\n"),
    );
    add(
        &mut cases,
        "inm-nomatch",
        "GET",
        String::from("If-None-Match: \"other\"\r\n"),
    );
    add(
        &mut cases,
        "inm-weak",
        "GET",
        String::from("If-None-Match: W/\"v1\"\r\n"),
    );
    add(
        &mut cases,
        "inm-list",
        "GET",
        String::from("If-None-Match: \"a\", \"v1\", \"b\"\r\n"),
    );
    let mut s = String::from("If-Modified-Since: ");
    s.push_str(after.as_ref());
    s.push_str("\r\n");
    add(&mut cases, "ims-after", "GET", s);
    let mut s = String::from("If-Modified-Since: ");
    s.push_str(exact.as_ref());
    s.push_str("\r\n");
    add(&mut cases, "ims-exact", "GET", s);
    let mut s = String::from("If-Modified-Since: ");
    s.push_str(before.as_ref());
    s.push_str("\r\n");
    add(&mut cases, "ims-before", "GET", s);
    add(
        &mut cases,
        "ims-junk",
        "GET",
        String::from("If-Modified-Since: not a date\r\n"),
    );
    let mut s = String::from("If-None-Match: \"other\"\r\nIf-Modified-Since: ");
    s.push_str(after.as_ref());
    s.push_str("\r\n");
    add(&mut cases, "inm-wins", "GET", s);
    add(
        &mut cases,
        "im-match",
        "GET",
        String::from("If-Match: \"v1\"\r\n"),
    );
    add(
        &mut cases,
        "im-nomatch",
        "GET",
        String::from("If-Match: \"other\"\r\n"),
    );
    add(
        &mut cases,
        "im-star",
        "GET",
        String::from("If-Match: *\r\n"),
    );
    let mut s = String::from("If-Unmodified-Since: ");
    s.push_str(before.as_ref());
    s.push_str("\r\n");
    add(&mut cases, "ium-before", "GET", s);
    let mut s = String::from("If-Unmodified-Since: ");
    s.push_str(after.as_ref());
    s.push_str("\r\n");
    add(&mut cases, "ium-after", "GET", s);
    add(
        &mut cases,
        "range",
        "GET",
        String::from("Range: bytes=0-4\r\n"),
    );
    add(
        &mut cases,
        "ifrange-etag-ok",
        "GET",
        String::from("Range: bytes=0-4\r\nIf-Range: \"v1\"\r\n"),
    );
    add(
        &mut cases,
        "ifrange-etag-bad",
        "GET",
        String::from("Range: bytes=0-4\r\nIf-Range: \"other\"\r\n"),
    );
    let mut s = String::from("Range: bytes=0-4\r\nIf-Range: ");
    s.push_str(exact.as_ref());
    s.push_str("\r\n");
    add(&mut cases, "ifrange-date-ok", "GET", s);
    let mut s = String::from("Range: bytes=0-4\r\nIf-Range: ");
    s.push_str(before.as_ref());
    s.push_str("\r\n");
    add(&mut cases, "ifrange-date-bad", "GET", s);
    add(
        &mut cases,
        "head-inm",
        "HEAD",
        String::from("If-None-Match: \"v1\"\r\n"),
    );
    add(&mut cases, "head-plain", "HEAD", String::new());
    add(
        &mut cases,
        "post-im-nomatch",
        "POST",
        String::from("If-Match: \"other\"\r\nContent-Length: 0\r\n"),
    );
    add(
        &mut cases,
        "inm-empty",
        "GET",
        String::from("If-None-Match: \r\n"),
    );

    for (name, method, extra) in cases.iter() {
        let mut r = String::from(*method);
        r.push_str(" /f.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
        r.push_str(extra);
        r.push_str("\r\n");
        let raw = req_raw(port, &r);
        let rs: &str = raw.as_ref();
        let code = match rs.find(' ') {
            Some(i) if rs.len() > i + 4 => &rs[i + 1..i + 4],
            _ => "000",
        };
        let body = match rs.find("\r\n\r\n") {
            Some(i) => &rs[i + 4..],
            None => "",
        };
        chk(fmt::Sprintf!(
            "%-18s %s ct=%-24q cr=%-16q etag=%-6q lm=%v len=%d body=%q",
            goish::string::from_bytes(name.as_bytes()),
            goish::string::from_bytes(code.as_bytes()),
            hdr(rs, "Content-Type"),
            hdr(rs, "Content-Range"),
            hdr(rs, "ETag"),
            hdr(rs, "Last-Modified").Len() != 0,
            body.len() as i64,
            goish::string::from_bytes(body.as_bytes())
        ));
    }

    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
