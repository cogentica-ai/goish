// http_cgi_smoke — net/http/cgi/child.go's envMap (:39) and
// RequestFromMap (:50), the pair that turns a CGI environment into an
// http.Request. net/http/fcgi's child.go calls RequestFromMap, so this
// is what unblocks it.
//
// Every expectation is Go 1.25.5 output via scripts/goref.sh
// net/http/cgi. The environment is attacker-adjacent — a CGI child
// reads whatever the front-end server puts there — so the edges are
// the point:
//
//   * A missing REQUEST_METHOD and an unparseable SERVER_PROTOCOL are
//     ERRORS, not defaults. So is a non-numeric CONTENT_LENGTH.
//   * HTTP_* variables become "Foo-Bar" headers with underscores
//     turned into hyphens; HTTP_HOST is skipped because it is already
//     r.Host, and would otherwise appear as a "Host" header too.
//   * The scheme comes from the de-facto HTTPS variable, and Go
//     accepts exactly "on", "ON" and "1" — "off" leaves TLS nil and
//     the URL http://.
//   * REMOTE_PORT is parsed with the error DROPPED, so an unset or
//     invalid port becomes 0 and RemoteAddr is "addr:0" — never
//     absent. With no REMOTE_ADDR either it is ":0".
//   * Without a Host the URL is built from REQUEST_URI alone, or from
//     SCRIPT_NAME + PATH_INFO + "?" + QUERY_STRING when the server
//     did not supply one.
//
// envMap keeps the LAST duplicate key and splits on the FIRST "=",
// so "B=x=y" maps B to "x=y".

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gomap::map;
use goish::goslice::slice;
use goish::net::http::cgi::{envMap, RequestFromMap};
use goish::{fmt, string, syscall};

fn params(kv: &[(&'static str, &'static str)]) -> map<string, string> {
    let mut m: map<string, string> = map::new();
    let mut i = 0;
    while i < kv.len() {
        m.Set(string(kv[i].0), string(kv[i].1));
        i += 1;
    }
    return m;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Minimal environment.
    {
        let p = params(&[("REQUEST_METHOD", "GET"), ("SERVER_PROTOCOL", "HTTP/1.1")]);
        let (r, err) = RequestFromMap(&p);
        if err == goish::nil
            && r.Method == "GET"
            && r.ProtoMajor == 1
            && r.ProtoMinor == 1
            && r.Close
            && r.TLS.is_none()
            && r.RemoteAddr == ":0"
        {
            fmt::Println!("[1] minimal env  PASS");
        } else {
            fmt::Println!("[1] minimal env  FAIL remote=", r.RemoteAddr, " err=", err);
            failed += 1;
        }
    }

    // 2. The three error paths.
    {
        let (_a, e1) = RequestFromMap(&params(&[("SERVER_PROTOCOL", "HTTP/1.1")]));
        let (_b, e2) = RequestFromMap(&params(&[
            ("REQUEST_METHOD", "GET"),
            ("SERVER_PROTOCOL", "HTTP/9"),
        ]));
        let (_c, e3) = RequestFromMap(&params(&[
            ("REQUEST_METHOD", "GET"),
            ("SERVER_PROTOCOL", "HTTP/1.1"),
            ("CONTENT_LENGTH", "abc"),
        ]));
        if e1.Error() == "cgi: no REQUEST_METHOD in environment"
            && e2.Error() == "cgi: invalid SERVER_PROTOCOL version"
            && e3.Error() == "cgi: bad CONTENT_LENGTH in environment: abc"
        {
            fmt::Println!("[2] missing method / bad proto / bad length all error  PASS");
        } else {
            fmt::Println!("[2] error paths  FAIL: ", e1, " | ", e2, " | ", e3);
            failed += 1;
        }
    }

    // 3. A full environment: URL assembly, HTTP_* headers, RemoteAddr.
    {
        let p = params(&[
            ("REQUEST_METHOD", "POST"),
            ("SERVER_PROTOCOL", "HTTP/1.1"),
            ("HTTP_HOST", "example.com"),
            ("REQUEST_URI", "/a/b?q=1"),
            ("CONTENT_LENGTH", "42"),
            ("CONTENT_TYPE", "text/plain"),
            ("REMOTE_ADDR", "1.2.3.4"),
            ("REMOTE_PORT", "5678"),
            ("HTTP_X_FOO_BAR", "v"),
        ]);
        let (r, err) = RequestFromMap(&p);
        if err == goish::nil
            && r.URL.String() == "http://example.com/a/b?q=1"
            && r.Host == "example.com"
            && r.ContentLength == 42
            && r.Header.Get(string("Content-Type")) == "text/plain"
            && r.Header.Get(string("X-Foo-Bar")) == "v"
            && r.RemoteAddr == "1.2.3.4:5678"
            && r.Header.Get(string("Host")) == ""
        {
            fmt::Println!("[3] full env: URL, HTTP_* headers, RemoteAddr  PASS");
        } else {
            fmt::Println!("[3] full env  FAIL url=", r.URL.String(), " remote=", r.RemoteAddr);
            failed += 1;
        }
    }

    // 4. HTTPS accepts "on", "ON" and "1"; anything else is plaintext.
    {
        let mk = |v: &'static str| {
            let p = params(&[
                ("REQUEST_METHOD", "GET"),
                ("SERVER_PROTOCOL", "HTTP/1.1"),
                ("HTTP_HOST", "e.com"),
                ("REQUEST_URI", "/"),
                ("HTTPS", v),
            ]);
            let (r, _) = RequestFromMap(&p);
            return (r.URL.String(), r.TLS.is_some());
        };
        let (u1, t1) = mk("on");
        let (u2, t2) = mk("ON");
        let (u3, t3) = mk("1");
        let (u4, t4) = mk("off");
        if u1 == "https://e.com/" && t1
            && u2 == "https://e.com/" && t2
            && u3 == "https://e.com/" && t3
            && u4 == "http://e.com/" && !t4
        {
            fmt::Println!("[4] HTTPS on/ON/1 -> TLS, off -> plaintext  PASS");
        } else {
            fmt::Println!("[4] HTTPS  FAIL ", u1, " ", u2, " ", u3, " ", u4);
            failed += 1;
        }
    }

    // 5. No REQUEST_URI: SCRIPT_NAME + PATH_INFO + "?" + QUERY_STRING.
    {
        let p = params(&[
            ("REQUEST_METHOD", "GET"),
            ("SERVER_PROTOCOL", "HTTP/1.1"),
            ("SCRIPT_NAME", "/cgi"),
            ("PATH_INFO", "/x"),
            ("QUERY_STRING", "a=1"),
        ]);
        let (r, err) = RequestFromMap(&p);
        if err == goish::nil && r.URL.String() == "/cgi/x?a=1" {
            fmt::Println!("[5] REQUEST_URI fallback  PASS");
        } else {
            fmt::Println!("[5] REQUEST_URI fallback  FAIL url=", r.URL.String());
            failed += 1;
        }
    }

    // 6. envMap: first "=" splits, last duplicate wins, no "=" skipped.
    {
        let e = slice::__from_vec(alloc::vec![
            string("A=1"),
            string("B=x=y"),
            string("noequals"),
            string("A=2"),
        ]);
        let m = envMap(e);
        let (a, _) = m.Get(string("A"));
        let (b, _) = m.Get(string("B"));
        if m.Len() == 2 && a == "2" && b == "x=y" {
            fmt::Println!("[6] envMap  PASS");
        } else {
            fmt::Println!("[6] envMap  FAIL len=", m.Len() as i64, " A=", a, " B=", b);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 6");
        syscall::Exit(1);
    }
}
